# SAPÉ d-MCP — controlled database access with granular permissions for LLMs
# Copyright (C) 2026 Luciano Arrezze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only

"""PyInstaller build spec for the SAPÉ d-MCP desktop application.

Build with::

    pyinstaller sape-d-mcp.spec

from the project root (the same directory this file lives in — every path
below is relative to it). Produces a one-directory bundle under
``dist/sape-d-mcp/`` whose executable is ``dist/sape-d-mcp/sape-d-mcp``
(``.exe`` on Windows).

Two data trees are carried in verbatim, wherever ``sys._MEIPASS`` points,
because that is where ``src/sape_d_mcp/gui/resources.py`` looks for them
first (see that module's docstring for the three-shape lookup — frozen,
development checkout, installed prefix). Confirmed against a real build:
with PyInstaller >=6.0's onedir layout, ``sys._MEIPASS`` is
``dist/sape-d-mcp/_internal/``, not the top-level ``dist/sape-d-mcp/``
directory the executable itself sits in — the two data trees below land at
``dist/sape-d-mcp/_internal/gui_resources/`` and
``.../_internal/legal-documents/`` accordingly, and ``resources.py`` finds
them there without any change on its part, because it only ever asks
``sys._MEIPASS`` rather than assuming a fixed layout.

* ``gui_resources/`` — the 18 flags, the icon set and the logos.
* ``legal-documents/`` — the English-only legal document bodies
  (``legal_document_loader.py`` reads these at runtime; they are not baked
  into the package the way the QSS files under ``src/sape_d_mcp/gui/styles/``
  are, so PyInstaller has to be told about them explicitly, same as
  ``pyproject.toml``'s ``[tool.setuptools.data-files]`` has to be for a
  wheel install).

One-directory rather than one-file: a one-file build re-extracts the whole
payload to a fresh temporary directory on every launch, which is slower and
also means ``sys._MEIPASS`` points at a different throwaway path each run —
harmless for ``resources.py`` itself (it only reads from there), but it
adds startup latency for no benefit this application needs, since it is
installed once and launched repeatedly rather than distributed as a single
email attachment.
"""

from __future__ import annotations

from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

# `spec` files are exec'd by PyInstaller with `__file__` unset in some
# versions, but `SPECPATH` is always injected into the exec namespace — the
# documented, version-stable way to recover "the directory this .spec lives
# in" (PyInstaller's own spec-file templates use it for exactly this).
PROJECT_ROOT = Path(SPECPATH)  # noqa: F821 — injected by PyInstaller

block_cipher = None


def _collect_driver(package_name: str) -> list[str]:
    """``collect_submodules(package_name)``, but honest about a silent failure.

    For a single-file compiled extension (``pyodbc``, ``pymssql``, ...) —
    anything that is not itself a package — ``collect_submodules`` has to
    *import* it to confirm it has no further submodules, and if that import
    fails it returns ``[]``: no exception, no warning, nothing. Built this
    way, a build log gives no sign that a driver went missing; the bundle
    simply lacks it, discovered later at the worst possible time — the first
    time a user picks that engine.

    That is precisely what happens to ``pyodbc`` on this project's Linux
    build VM: it installs, but its compiled extension links against
    ``libodbc.so.2``, which only unixODBC provides, unixODBC is not
    installed, and installing it needs sudo this environment does not have.
    On the user's actual Windows target ``pyodbc`` links the OS's own
    ``odbc32.dll`` instead and imports cleanly, so this is a gap specific to
    *building* here, not a defect in the driver list below — but reporting
    it loudly costs nothing, and papering over it (e.g. by hardcoding the
    module name into ``hiddenimports`` regardless of whether it imports) was
    tried and turns this from a silent skip into a hard build failure
    instead, because the post-graph ``hook-pyodbc.py`` then tries the same
    import again via ``get_pyextension_imports`` and raises. Reporting is
    the only option that is honest without also being fragile.
    """
    modules = collect_submodules(package_name)
    if not modules:
        print(
            f"sape-d-mcp.spec: WARNING — '{package_name}' could not be imported in "
            "this build environment, so it collected no submodules and is EXCLUDED "
            "from this bundle. On Windows or macOS this would be a real defect worth "
            "investigating before shipping. On this project's Linux build VM it is "
            "the known pyodbc/libodbc.so.2 gap (no unixODBC, no sudo to install it); "
            "pymssql remains available there as the self-contained MS-SQL driver."
        )
    return modules


# db/discovery.py, db/targets.py and db/auth_modes.py (connection auto-detection and the
# system-authentication support matrix) need NO entry here. All three were checked by hand
# for anything a static import-graph walk could miss:
#
# - targets.py and auth_modes.py import only stdlib modules that exist on every platform
#   (re, dataclasses, platform, logging) — nothing conditional, nothing deferred.
# - discovery.py imports `winreg` — Windows-only stdlib, never third-party — but always as
#   a literal `import winreg` statement inside a function body, several of them additionally
#   guarded by `if sys.platform != "win32": return`. PyInstaller's modulegraph disassembles
#   bytecode for IMPORT_NAME opcodes wherever they sit, including inside a guarded function,
#   so it finds this import on any platform without needing it named in hiddenimports — and
#   because `winreg` is a *builtin* extension module frozen into `python3.dll` on Windows
#   (not a file PyInstaller has to locate and copy), there is nothing further to bundle for
#   it there either. Verified against a real build on this Linux VM: the generated
#   `build/sape-d-mcp/warn-sape-d-mcp.txt` reports "missing module named winreg - imported
#   by ... sape_d_mcp.db.discovery (delayed)" — the same "missing, delayed, harmless" shape
#   already logged there for `platform`, `mimetypes` and `importlib._bootstrap_external`,
#   which have carried an optional `winreg` import for years. That is expected on Linux,
#   where the module genuinely does not exist and every call site that would touch it is
#   unreachable; a Windows build should show no such line for `sape_d_mcp.db.discovery` at
#   all, because there `winreg` resolves. If a future Windows build ever prints a *different*
#   missing-module line naming this package, that is the regression to chase — not this one.
#
# `gui/dialogs/discovery_dialog.py` itself needs no entry either. `connections_page.py`
# imports it at module level, so PyInstaller's analysis reaches it automatically once it
# walks `main.py`. Its worker thread then imports `db.discovery`'s two entry points
# (`discover_local`/`discover_network`) *inside* `run()` rather than at module level — a
# deliberate lazy import so the dialog can be constructed without the discovery module doing
# any work first — but that is still a literal `from ... import ...` statement, which the
# same bytecode scan finds regardless of the indentation it sits at; "lazy" and "dynamic"
# are not the same thing, and only the latter would need a hiddenimports entry.

# The four DB driver packages are imported lazily, per connection profile,
# from src/sape_d_mcp/db/dialects/*.py — PyInstaller's static import graph
# walk never sees those call sites, so each driver has to be named here or
# the frozen build works until the first time a user picks that engine.
hidden_imports = [
    *_collect_driver("pyodbc"),
    *_collect_driver("pymssql"),
    *_collect_driver("psycopg"),
    "psycopg_binary",
    *_collect_driver("pymysql"),
    *_collect_driver("mysql.connector"),
    "keyring.backends",
    *_collect_driver("keyring.backends"),
]

a = Analysis(
    ["main.py"],
    pathex=[str(PROJECT_ROOT / "src")],
    binaries=[],
    datas=[
        (str(PROJECT_ROOT / "gui_resources"), "gui_resources"),
        (str(PROJECT_ROOT / "legal-documents"), "legal-documents"),
    ],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="sape-d-mcp",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    # Console-subsystem, not windowed: main.py's own top-level code hides the
    # console window itself on Windows, and only when --cli is *not* given
    # ("there the process is a server, it inherits the console of whoever
    # launched it, and hiding that would take the user's own terminal window
    # with it" — see main.py). That logic assumes a console exists to hide;
    # building windowed (console=False) would make GetConsoleWindow() return
    # a null handle unconditionally, and — worse — leave a --cli build with
    # no inherited stdio at all when a human runs it directly from a shell
    # rather than through a client that redirects the pipes itself.
    console=True,
    icon=str(PROJECT_ROOT / "gui_resources" / "icons" / "trans.ico"),
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="sape-d-mcp",
)
