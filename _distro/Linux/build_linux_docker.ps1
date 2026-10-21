# SAPE d-MCP - build the Linux packages from Windows, inside a Docker container.
#
# Usage (Docker Desktop running, Linux engine):
#
#   powershell -ExecutionPolicy Bypass -File _distro\Linux\build_linux_docker.ps1 [appimage] [deb] [rpm]
#
# Runs build_linux.sh unchanged in a throwaway container, so the Windows machine needs no
# Linux toolchain and no sudo. The image decides which distributions can run the result:
# a PyInstaller bundle needs a glibc at least as new as the build system's, so the default
# ubuntu:22.04 (glibc 2.35) produces packages for Ubuntu 22.04+, Debian 12+, Fedora 36+
# and RHEL 10. Pass -Image for an older or newer base.
#
# The project folder must be on a drive Docker can mount (a local disk, not a virtual
# cloud-sync drive). Output: _distro\Linux\output\
#
# This file is ASCII-only on purpose: Windows PowerShell 5.1 reads a BOM-less script as ANSI.

# PositionalBinding off: bare words are formats (appimage, deb, rpm), never the -Image value.
[CmdletBinding(PositionalBinding = $false)]
param(
    [string]$Image = "ubuntu:22.04",
    [Parameter(ValueFromRemainingArguments = $true)][string[]]$Formats = @()
)

$ErrorActionPreference = "Stop"
$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

$packages = @(
    # libpython3-dev pulls in libpython3.X.so, which PyInstaller bundles; system Python on
    # Debian/Ubuntu does not ship it by default.
    "python3", "python3-venv", "python3-pip", "libpython3-dev", "ca-certificates", "curl", "file",
    "dpkg-dev", "rpm",
    # pyodbc links libodbc.so.2; without it the MS-SQL pyodbc driver is left out.
    "unixodbc",
    # Imported by PyInstaller's Qt hooks while it analyses PyQt6.
    "libglib2.0-0", "libgl1", "libegl1", "libfontconfig1", "libxkbcommon0", "libdbus-1-3",
    # Needed by Qt's xcb platform plugin; present here so PyInstaller can resolve them.
    "libxcb-cursor0", "libxcb-icccm4", "libxcb-image0", "libxcb-keysyms1", "libxcb-randr0",
    "libxcb-render-util0", "libxcb-shape0", "libxcb-xinerama0", "libxcb-xkb1", "libxkbcommon-x11-0"
) -join " "

$inner = "set -e; export DEBIAN_FRONTEND=noninteractive; " +
         "apt-get update -qq && apt-get install -y -qq --no-install-recommends $packages >/dev/null; " +
         "bash /src/_distro/Linux/build_linux.sh $($Formats -join ' ')"

Write-Host "==> Building Linux packages in $Image from $ProjectRoot"
$previous = $ErrorActionPreference
$ErrorActionPreference = "Continue"
try {
    & docker run --rm -v "${ProjectRoot}:/src" -e BUILD_ROOT=/build $Image bash -c $inner
} finally { $ErrorActionPreference = $previous }
if ($LASTEXITCODE -ne 0) { throw "Container build failed with exit code $LASTEXITCODE" }
Write-Host "==> Artifacts in $(Join-Path $ProjectRoot '_distro\Linux\output')"
