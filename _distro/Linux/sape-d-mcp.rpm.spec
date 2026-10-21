# SAPÉ d-MCP — RPM spec for repackaging the prebuilt PyInstaller bundle.
#
# Not meant to be run by hand: build_linux.sh stages the files and calls rpmbuild with
# --define for app_version and staging_dir.

# The payload is an already-frozen PyInstaller bundle: no compilation, no stripping (it
# would corrupt the bundled archive), no Python byte-compiling, no debuginfo.
%global debug_package %{nil}
%global __strip /bin/true
%global __os_install_post %{nil}
%global _build_id_links none
# Automatic dependency scanning would demand every library bundled inside the package
# (Qt, OpenSSL, ...) from the system. Real system dependencies are listed by hand below.
AutoReqProv: no

Name:           sape-d-mcp
Version:        %{app_version}
Release:        1
Summary:        Controlled database access with granular permissions for LLMs
License:        GPL-3.0-only
URL:            https://sapebud.com
ExclusiveArch:  x86_64 aarch64

# Qt 6's xcb platform plugin needs these from the system.
Requires:       xcb-util-cursor
Requires:       xcb-util-image
Requires:       xcb-util-keysyms
Requires:       xcb-util-renderutil
Requires:       xcb-util-wm
Requires:       libxkbcommon-x11
Requires:       libX11-xcb
Requires:       mesa-libGL
Requires:       mesa-libEGL
Requires:       glib2
Requires:       fontconfig
Requires:       dbus-libs
Requires:       hicolor-icon-theme
# The pyodbc MS-SQL driver links libodbc.so.2; without it only that driver is unavailable.
Recommends:     unixODBC

%description
SAPÉ d-MCP is an MCP server with a desktop GUI that gives LLMs controlled access to
databases (SQLite, MS-SQL, PostgreSQL, MySQL/MariaDB) under granular, default-deny
permissions, with an audit trail of every tool call.

%install
cp -a %{staging_dir}/. %{buildroot}/

%files
# /opt/sape-d-mcp/LICENSE ships inside the directory below.
/opt/sape-d-mcp
/usr/bin/sape-d-mcp
/usr/bin/sape-d-mcp-gui
/usr/share/applications/sape-d-mcp.desktop
/usr/share/icons/hicolor/*/apps/sape-d-mcp.png
