# SAPE d-MCP - install-and-run test of the built Linux packages, each in a clean container.
#
# Usage (after build_linux_docker.ps1, Docker Desktop running):
#
#   powershell -ExecutionPolicy Bypass -File _distro\Linux\test_linux_docker.ps1
#
# This file is ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less script as ANSI.

$ErrorActionPreference = "Continue"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$cases = @(
    @{ Kind = "deb";      Image = "ubuntu:22.04" },
    @{ Kind = "deb";      Image = "debian:12" },
    @{ Kind = "rpm";      Image = "fedora:40" },
    @{ Kind = "appimage"; Image = "ubuntu:22.04" }
)
$failed = 0
foreach ($c in $cases) {
    Write-Host "==> $($c.Kind) on $($c.Image)"
    & docker run --rm -v "${ProjectRoot}:/src" $c.Image bash /src/_distro/Linux/test_packages_inside.sh $c.Kind
    if ($LASTEXITCODE -ne 0) { $failed++ }
}
if ($failed) { Write-Host "==> $failed configuration(s) FAILED"; exit 1 }
Write-Host "==> All configurations passed"
