# SAPE d-MCP - Windows build: PyInstaller bundle + Inno Setup installer, optionally signed.
#
# Usage (from any directory, Windows PowerShell 5.1 or PowerShell 7):
#
#   powershell -ExecutionPolicy Bypass -File _distro\Windows\build_windows.ps1
#
# Options:
#   -Python <exe>      Interpreter used to create the build venv (default: python).
#   -BuildRoot <dir>   Where the venv, PyInstaller work and dist folders go. Defaults to a
#                      folder under %TEMP%, deliberately NOT inside the project: the project
#                      may sit on a synced drive, and the sync client locks files mid-write.
#   -Iscc <exe>        Path to ISCC.exe if it is not in a standard location.
#   -SignTool <exe>    Path to signtool.exe if it is not in the Windows SDK's standard location.
#   -Clean             Delete the build root first (fresh venv, fresh PyInstaller cache).
#   -SkipInstaller     Build and smoke-test the bundle only; do not run Inno Setup.
#
# Code signing (optional; unsigned when neither variable is set):
#   SIGN_PFX_PATH         Path to a .pfx/.p12 code-signing certificate.
#   SIGN_PFX_PASSWORD     Its password. Read from the environment only - never pass it as an
#                         argument, and never put it in this file.
#   SIGN_CERT_THUMBPRINT  Alternative to the .pfx: a certificate already in the current
#                         user's certificate store (e.g. from a USB token).
#   SIGN_TIMESTAMP_URL    RFC 3161 timestamp server (default: http://timestamp.digicert.com).
#
# With a .pfx, the certificate is imported into Cert:\CurrentUser\My for the duration of the
# build and removed afterwards (unless it was already there), so signtool and Inno Setup sign
# by thumbprint and the password never appears on any command line or in any log.
# Signed: sape-d-mcp.exe, the installer and the uninstaller.
#
# Output: _distro\Windows\output\sape-d-mcp-<version>-windows-x64-setup.exe
#
# This file is ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less script as ANSI.

[CmdletBinding()]
param(
    [string]$Python = "python",
    [string]$BuildRoot = (Join-Path ([IO.Path]::GetTempPath()) "sape-d-mcp-build\windows"),
    [string]$Iscc = "",
    [string]$SignTool = "",
    [switch]$Clean,
    [switch]$SkipInstaller
)

$ErrorActionPreference = "Stop"

function Invoke-Checked {
    param([string]$Exe, [string[]]$Arguments)
    # pip and PyInstaller log to stderr; under "Stop", PowerShell 5.1 can turn that into a
    # terminating error when the output is captured. The exit code is the real signal.
    $previous = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try { & $Exe @Arguments } finally { $ErrorActionPreference = $previous }
    if ($LASTEXITCODE -ne 0) { throw "'$(Split-Path $Exe -Leaf)' failed with exit code $LASTEXITCODE" }
}

$DistroDir   = $PSScriptRoot
$ProjectRoot = (Resolve-Path (Join-Path $DistroDir "..\..")).Path
$RootSpec    = Join-Path $ProjectRoot "sape-d-mcp.spec"
$OutputDir   = Join-Path $DistroDir "output"

# --- Version (single source of truth: src/sape_d_mcp/_version.py) -------------------------
$versionFile = Get-Content (Join-Path $ProjectRoot "src\sape_d_mcp\_version.py") -Encoding UTF8 -Raw
if ($versionFile -notmatch '(?m)^__version__\s*=\s*"([^"]+)"') { throw "Could not read __version__ from _version.py" }
$Version = $Matches[1]
$Stage = ""
if ($versionFile -match '(?m)^RELEASE_STAGE\s*=\s*"([^"]*)"') { $Stage = $Matches[1] }
$VersionDisplay = if ($Stage) { "$Version $Stage" } else { $Version }
Write-Host "==> SAPE d-MCP $VersionDisplay"

# --- Signing setup (before any build work, so a bad certificate fails fast) ---------------
$Thumbprint = $env:SIGN_CERT_THUMBPRINT
$TimestampUrl = if ($env:SIGN_TIMESTAMP_URL) { $env:SIGN_TIMESTAMP_URL } else { "http://timestamp.digicert.com" }
$RemoveCertAfterwards = $false

if ($env:SIGN_PFX_PATH) {
    if (-not (Test-Path $env:SIGN_PFX_PATH)) { throw "SIGN_PFX_PATH points to a file that does not exist: $($env:SIGN_PFX_PATH)" }
    if (-not $env:SIGN_PFX_PASSWORD) { throw "SIGN_PFX_PATH is set but SIGN_PFX_PASSWORD is not." }
    $securePassword = ConvertTo-SecureString $env:SIGN_PFX_PASSWORD -AsPlainText -Force
    $pfx = Get-PfxData -FilePath $env:SIGN_PFX_PATH -Password $securePassword
    $Thumbprint = $pfx.EndEntityCertificates[0].Thumbprint
    if (-not (Test-Path "Cert:\CurrentUser\My\$Thumbprint")) {
        Import-PfxCertificate -FilePath $env:SIGN_PFX_PATH -CertStoreLocation Cert:\CurrentUser\My -Password $securePassword | Out-Null
        $RemoveCertAfterwards = $true
    }
}

$Signing = [bool]$Thumbprint
if ($Signing) {
    $cert = Get-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
    if (-not $cert) { throw "Signing certificate $Thumbprint is not in Cert:\CurrentUser\My." }
    if (-not $cert.HasPrivateKey) { throw "Signing certificate $Thumbprint has no private key." }
    Write-Host "==> Signing as: $($cert.Subject) (expires $($cert.NotAfter.ToString('yyyy-MM-dd')))"
    if (-not $SignTool) {
        $SignTool = Get-ChildItem (Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin") -Recurse -Filter signtool.exe -ErrorAction SilentlyContinue |
            Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    }
    if (-not $SignTool) { throw "signtool.exe not found. Install the Windows SDK or pass -SignTool." }
} else {
    Write-Host "==> Code signing: OFF (set SIGN_PFX_PATH + SIGN_PFX_PASSWORD, or SIGN_CERT_THUMBPRINT)"
}

function Invoke-Sign([string]$File) {
    Invoke-Checked $SignTool @("sign", "/sha1", $Thumbprint, "/fd", "sha256", "/tr", $TimestampUrl, "/td", "sha256", "/d", "SAPE d-MCP", $File)
}

try {
    # --- Build venv -----------------------------------------------------------------------
    if ($Clean -and (Test-Path $BuildRoot)) { Remove-Item -Recurse -Force $BuildRoot }
    New-Item -ItemType Directory -Force $BuildRoot | Out-Null
    $Venv = Join-Path $BuildRoot "venv"
    $VenvPython = Join-Path $Venv "Scripts\python.exe"
    if (-not (Test-Path $VenvPython)) {
        Write-Host "==> Creating build venv in $Venv"
        Invoke-Checked $Python @("-m", "venv", $Venv)
    }
    Write-Host "==> Installing runtime requirements and PyInstaller"
    Invoke-Checked $VenvPython @("-m", "pip", "install", "--disable-pip-version-check", "--upgrade", "pip")
    Invoke-Checked $VenvPython @("-m", "pip", "install", "--disable-pip-version-check", "-r", (Join-Path $ProjectRoot "requirements.txt"), "pyinstaller>=6.0")

    # --- PyInstaller bundle (the project's own spec, unchanged) ---------------------------
    $DistPath = Join-Path $BuildRoot "dist"
    $WorkPath = Join-Path $BuildRoot "build"
    Write-Host "==> Running PyInstaller"
    Invoke-Checked $VenvPython @("-m", "PyInstaller", "--noconfirm", "--clean", "--distpath", $DistPath, "--workpath", $WorkPath, $RootSpec)

    $Bundle = Join-Path $DistPath "sape-d-mcp"
    $Exe = Join-Path $Bundle "sape-d-mcp.exe"
    if (-not (Test-Path $Exe)) { throw "PyInstaller finished but $Exe does not exist" }

    if ($Signing) { Write-Host "==> Signing sape-d-mcp.exe"; Invoke-Sign $Exe }

    # --- Smoke test (runs the signed exe when signing is on) ------------------------------
    # --cli keeps main.py from hiding the console window it was started from; --version then
    # exits before anything else runs.
    Write-Host "==> Smoke test: sape-d-mcp.exe --cli --version"
    $reported = & $Exe --cli --version
    if ($LASTEXITCODE -ne 0) { throw "Smoke test failed with exit code $LASTEXITCODE" }
    Write-Host "    $reported"
    if ("$reported" -notmatch [regex]::Escape($Version)) { throw "Smoke test reported '$reported', expected version $Version" }

    if ($SkipInstaller) { Write-Host "==> Bundle ready at $Bundle (installer skipped)"; return }

    # --- Inno Setup -----------------------------------------------------------------------
    if (-not $Iscc) {
        $candidates = @(
            (Join-Path ${env:ProgramFiles(x86)} "Inno Setup 6\ISCC.exe"),
            (Join-Path $env:ProgramFiles "Inno Setup 6\ISCC.exe"),
            (Join-Path $env:LOCALAPPDATA "Programs\Inno Setup 6\ISCC.exe")
        )
        $Iscc = $candidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
        if (-not $Iscc) {
            $cmd = Get-Command iscc -ErrorAction SilentlyContinue
            if ($cmd) { $Iscc = $cmd.Source }
        }
    }
    if (-not $Iscc) { throw "ISCC.exe (Inno Setup 6) not found. Install it (winget install JRSoftware.InnoSetup) or pass -Iscc." }

    New-Item -ItemType Directory -Force $OutputDir | Out-Null
    $isccArgs = @(
        "/Q",
        "/DAppVersion=$Version",
        "/DAppVersionDisplay=$VersionDisplay",
        "/DSourceDir=$Bundle",
        "/O$OutputDir"
    )
    if ($Signing) {
        # Inno Setup substitutes $q with a double quote and $f with the file to sign. It signs
        # the installer and the uninstaller (SignedUninstaller=yes in the .iss).
        $isccArgs += "/Ssapesign=`$q$SignTool`$q sign /sha1 $Thumbprint /fd sha256 /tr $TimestampUrl /td sha256 /d `$qSAPE d-MCP`$q `$f"
        $isccArgs += "/DSignToolName=sapesign"
    }
    $isccArgs += (Join-Path $DistroDir "sape-d-mcp.iss")
    Write-Host "==> Compiling installer with $Iscc"
    Invoke-Checked $Iscc $isccArgs

    $Setup = Join-Path $OutputDir "sape-d-mcp-$Version-windows-x64-setup.exe"
    if (-not (Test-Path $Setup)) { throw "ISCC finished but $Setup does not exist" }

    if ($Signing) {
        foreach ($f in @($Exe, $Setup)) {
            $sig = Get-AuthenticodeSignature $f
            if ($sig.Status -eq "NotSigned") { throw "$f is not signed" }
            Write-Host "    Signature on $(Split-Path $f -Leaf): $($sig.Status) ($($sig.SignerCertificate.Subject))"
        }
    }

    $hash = (Get-FileHash -Algorithm SHA256 $Setup).Hash.ToLower()
    Set-Content -Path "$Setup.sha256" -Value "$hash  $(Split-Path $Setup -Leaf)" -Encoding Ascii
    Write-Host "==> Installer: $Setup"
    Write-Host "    SHA-256:   $hash"
}
finally {
    if ($RemoveCertAfterwards) {
        Remove-Item "Cert:\CurrentUser\My\$Thumbprint" -ErrorAction SilentlyContinue
        Write-Host "==> Removed the temporarily imported signing certificate from the store"
    }
}
