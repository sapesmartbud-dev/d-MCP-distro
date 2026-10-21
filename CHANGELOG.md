# Changelog

All notable changes to SAPÉ d-MCP are recorded in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). The version
number is kept in `src/sape_d_mcp/_version.py`. For the stage-by-stage development history up
to 0.1.0.8, see [`HISTORY.md`](HISTORY.md).

## [Unreleased]

### Added

- `_distro/`: installer builds per operating system, each built from the unchanged
  `sape-d-mcp.spec`. `Windows/` builds a per-user Inno Setup installer. `Linux/` builds an
  AppImage, a `.deb` and an `.rpm`. `Mac_OS/` builds an `.app` in a `.dmg`, with optional
  signing and notarization. See [`_distro/README.md`](_distro/README.md).
- Each installer sets the working directory for desktop launches, so the databases land in
  a writable per-user folder instead of the install directory (or `/` on macOS).
- `_distro/Linux/build_linux_docker.ps1` builds the Linux packages on Windows in an Ubuntu
  22.04 container. `test_linux_docker.ps1` installs and runs them on clean Ubuntu 22.04,
  Debian 12 and Fedora 40 containers.
- Optional code signing of the Windows build (executable, installer and uninstaller) from a
  `.pfx` or a certificate in the store, driven by environment variables.

### Changed

- `sape-d-mcp.exe` now uses the dark desktop icon (`app.ico`) instead of `trans.ico`, matching
  the window icon and the icon guidelines in `gui_resources/icons/README.md`.

## [0.1.0.9] — 2026-09-24 (Beta)

### Added

- `CONTRIBUTING.md`: forking and contribution guidelines under GPL-3.0-only.
- `CHANGELOG.md` (this file), updated with each change from now on.

### Changed

- Version set to 0.1.0.9 Beta in the application, README and legal documents.
- The development history up to 0.1.0.8 moved from `CHANGELOG.md` to `HISTORY.md`.
- README, `Stack.md` and `HISTORY.md` now record 0.1.0.8 Beta as released on 2026-09-14.

## [0.1.0.8] — 2026-09-14 (Beta)

- First release: stages 0–9 complete. See [`HISTORY.md`](HISTORY.md) for the full record.
