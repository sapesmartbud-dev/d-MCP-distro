#!/usr/bin/env bash
# SAPÉ d-MCP — Linux build: PyInstaller bundle, then AppImage, .deb and .rpm.
#
# Usage (run with bash; files written on Windows carry no executable bit):
#
#   bash _distro/Linux/build_linux.sh [appimage] [deb] [rpm]
#
# With no format named, all three are attempted. A format whose packaging tool is missing
# is skipped with a warning rather than failing the whole run.
#
# Environment:
#   PYTHON          Interpreter for the build venv (default: python3; needs >= 3.10).
#   BUILD_ROOT      venv + PyInstaller work/dist (default: ${TMPDIR:-/tmp}/sape-d-mcp-build/linux).
#   APPIMAGETOOL    Path to appimagetool. If unset and not on PATH, it is downloaded.
#   CLEAN=1         Delete BUILD_ROOT first.
#
# Build-host prerequisites (Debian/Ubuntu names):
#   python3-venv, dpkg-dev (deb), rpm (rpmbuild), file, and unixodbc — without unixODBC the
#   pyodbc MS-SQL driver cannot be imported at build time and is left OUT of the bundle
#   (sape-d-mcp.spec prints a WARNING when that happens). Build on the oldest distro you
#   intend to support: the bundle only runs on systems with the same or newer glibc.
#
# Output: _distro/Linux/output/

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$HERE/../.." && pwd)"
OUTPUT_DIR="$HERE/output"
PYTHON="${PYTHON:-python3}"
BUILD_ROOT="${BUILD_ROOT:-${TMPDIR:-/tmp}/sape-d-mcp-build/linux}"

FORMATS=("$@")
[ ${#FORMATS[@]} -eq 0 ] && FORMATS=(appimage deb rpm)

log()  { printf '==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; }

# --- Version ------------------------------------------------------------------------------
VERSION="$(sed -n 's/^__version__ *= *"\([^"]*\)".*/\1/p' "$PROJECT_ROOT/src/sape_d_mcp/_version.py")"
[ -n "$VERSION" ] || { echo "Could not read __version__" >&2; exit 1; }
MACHINE="$(uname -m)"
log "SAPÉ d-MCP $VERSION ($MACHINE)"

if ! ldconfig -p 2>/dev/null | grep -q 'libodbc\.so\.2'; then
    warn "libodbc.so.2 (unixODBC) not found: the pyodbc MS-SQL driver will be missing from this build."
fi

# --- Build venv + PyInstaller ---------------------------------------------------------------
[ "${CLEAN:-0}" = "1" ] && rm -rf "$BUILD_ROOT"
mkdir -p "$BUILD_ROOT" "$OUTPUT_DIR"
VENV="$BUILD_ROOT/venv"
[ -x "$VENV/bin/python" ] || { log "Creating build venv"; "$PYTHON" -m venv "$VENV"; }
log "Installing runtime requirements and PyInstaller"
"$VENV/bin/python" -m pip install --disable-pip-version-check --upgrade pip
"$VENV/bin/python" -m pip install --disable-pip-version-check -r "$PROJECT_ROOT/requirements.txt" "pyinstaller>=6.0"

log "Running PyInstaller"
"$VENV/bin/python" -m PyInstaller --noconfirm --clean \
    --distpath "$BUILD_ROOT/dist" --workpath "$BUILD_ROOT/build" "$PROJECT_ROOT/sape-d-mcp.spec"
BUNDLE="$BUILD_ROOT/dist/sape-d-mcp"
[ -x "$BUNDLE/sape-d-mcp" ] || { echo "PyInstaller produced no executable" >&2; exit 1; }

log "Smoke test: sape-d-mcp --cli --version"
"$BUNDLE/sape-d-mcp" --cli --version

ICON_SIZES=(16 24 32 48 64 96 128 256 512)
ICONS="$PROJECT_ROOT/gui_resources/icons"

# Stage the /opt + /usr tree shared by the .deb and the .rpm.
stage_system_tree() {
    local root="$1"
    rm -rf "$root"
    mkdir -p "$root/opt" "$root/usr/bin" "$root/usr/share/applications"
    cp -a "$BUNDLE" "$root/opt/sape-d-mcp"
    cp "$PROJECT_ROOT/LICENSE" "$root/opt/sape-d-mcp/LICENSE"
    ln -s /opt/sape-d-mcp/sape-d-mcp "$root/usr/bin/sape-d-mcp"
    install -m 0755 "$HERE/sape-d-mcp-gui" "$root/usr/bin/sape-d-mcp-gui"
    sed 's|@EXEC@|/usr/bin/sape-d-mcp-gui|' "$HERE/sape-d-mcp.desktop" \
        > "$root/usr/share/applications/sape-d-mcp.desktop"
    for s in "${ICON_SIZES[@]}"; do
        install -D -m 0644 "$ICONS/dark-$s.png" "$root/usr/share/icons/hicolor/${s}x${s}/apps/sape-d-mcp.png"
    done
}

build_appimage() {
    local tool="${APPIMAGETOOL:-$(command -v appimagetool || true)}"
    if [ -z "$tool" ]; then
        tool="$BUILD_ROOT/appimagetool-$MACHINE.AppImage"
        if [ ! -x "$tool" ]; then
            log "Downloading appimagetool"
            curl -fsSL -o "$tool" \
                "https://github.com/AppImage/appimagetool/releases/download/continuous/appimagetool-$MACHINE.AppImage" \
                || { warn "appimagetool download failed; skipping AppImage"; return 0; }
            chmod +x "$tool"
        fi
    fi
    local appdir="$BUILD_ROOT/AppDir"
    rm -rf "$appdir"
    mkdir -p "$appdir/usr/lib"
    cp -a "$BUNDLE" "$appdir/usr/lib/sape-d-mcp"
    install -m 0755 "$HERE/AppRun" "$appdir/AppRun"
    sed 's|@EXEC@|sape-d-mcp|' "$HERE/sape-d-mcp.desktop" > "$appdir/sape-d-mcp.desktop"
    cp "$ICONS/dark-256.png" "$appdir/sape-d-mcp.png"
    for s in "${ICON_SIZES[@]}"; do
        install -D -m 0644 "$ICONS/dark-$s.png" "$appdir/usr/share/icons/hicolor/${s}x${s}/apps/sape-d-mcp.png"
    done
    local out="$OUTPUT_DIR/sape-d-mcp-$VERSION-$MACHINE.AppImage"
    log "Building AppImage"
    # Extract-and-run avoids needing FUSE on the build host.
    APPIMAGE_EXTRACT_AND_RUN=1 ARCH="$MACHINE" "$tool" "$appdir" "$out"
    log "AppImage: $out"
}

build_deb() {
    command -v dpkg-deb >/dev/null || { warn "dpkg-deb not found; skipping .deb"; return 0; }
    local arch; arch="$(dpkg --print-architecture)"
    local root="$BUILD_ROOT/deb-root"
    stage_system_tree "$root"
    mkdir -p "$root/DEBIAN"
    local size; size="$(du -sk "$root" | cut -f1)"
    cat > "$root/DEBIAN/control" <<EOF
Package: sape-d-mcp
Version: $VERSION
Section: database
Priority: optional
Architecture: $arch
Installed-Size: $size
Maintainer: SAPÉ smart bud <info@sapebud.com>
Homepage: https://sapebud.com
Depends: libxcb-cursor0, libxcb-icccm4, libxcb-image0, libxcb-keysyms1, libxcb-randr0, libxcb-render-util0, libxcb-shape0, libxcb-xinerama0, libxcb-xkb1, libxkbcommon-x11-0, libx11-xcb1, libglib2.0-0, libfontconfig1, libdbus-1-3, libegl1, libgl1
Recommends: unixodbc
Description: Controlled database access with granular permissions for LLMs
 SAPÉ d-MCP is an MCP server with a desktop GUI that gives LLMs controlled
 access to databases (SQLite, MS-SQL, PostgreSQL, MySQL/MariaDB) under
 granular, default-deny permissions, with an audit trail of every tool call.
EOF
    local out="$OUTPUT_DIR/sape-d-mcp_${VERSION}_${arch}.deb"
    log "Building .deb"
    dpkg-deb --root-owner-group --build "$root" "$out"
    log ".deb: $out"
}

build_rpm() {
    command -v rpmbuild >/dev/null || { warn "rpmbuild not found; skipping .rpm"; return 0; }
    local root="$BUILD_ROOT/rpm-root"
    stage_system_tree "$root"
    local top="$BUILD_ROOT/rpmbuild"
    rm -rf "$top"
    mkdir -p "$top"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    log "Building .rpm"
    rpmbuild -bb \
        --define "_topdir $top" \
        --define "app_version $VERSION" \
        --define "staging_dir $root" \
        "$HERE/sape-d-mcp.rpm.spec"
    find "$top/RPMS" -name '*.rpm' -exec cp {} "$OUTPUT_DIR/" \;
    log ".rpm: $(ls "$OUTPUT_DIR"/*.rpm)"
}

for f in "${FORMATS[@]}"; do
    case "$f" in
        appimage) build_appimage ;;
        deb)      build_deb ;;
        rpm)      build_rpm ;;
        *) echo "Unknown format: $f (use appimage, deb, rpm)" >&2; exit 2 ;;
    esac
done

(cd "$OUTPUT_DIR" && sha256sum -- *.AppImage *.deb *.rpm 2>/dev/null > SHA256SUMS || true)
log "Done. Artifacts in $OUTPUT_DIR"
