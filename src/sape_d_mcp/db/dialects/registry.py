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

"""Turns the `(engine, driver)` pair stored in `connections.db` into a `Dialect`."""

from __future__ import annotations

import importlib
import importlib.util
import logging
import sys
from types import ModuleType

from .base import Dialect, DriverNotInstalledError, UnknownDriverError
from .types import Engine, ParamStyle

logger = logging.getLogger(__name__)

__all__ = [
    "available_drivers",
    "dialect_for",
    "driver_requirement",
    "drivers_for",
    "import_driver",
    "is_driver_available",
]


#: `(engine, driver) -> (module, class name, paramstyle)`.  The two MS-SQL rows point at the
#: same class with two different `ParamStyle` values — decision D4 made concrete: one dialect,
#: two drivers, two placeholder grammars, selected at construction and never guessed from the
#: SQL text at build time.
_DIALECT_REGISTRY: dict[tuple[Engine, str], tuple[str, str, ParamStyle]] = {
    (Engine.MSSQL, "pyodbc"): ("sape_d_mcp.db.dialects.mssql", "MSSQLDialect", ParamStyle.QMARK),
    (Engine.MSSQL, "pymssql"): ("sape_d_mcp.db.dialects.mssql", "MSSQLDialect", ParamStyle.PYFORMAT),
    (Engine.POSTGRESQL, "psycopg"): (
        "sape_d_mcp.db.dialects.postgres",
        "PostgreSQLDialect",
        ParamStyle.PYFORMAT,
    ),
    (Engine.MYSQL, "pymysql"): ("sape_d_mcp.db.dialects.mysql", "MySQLDialect", ParamStyle.PYFORMAT),
    (Engine.MYSQL, "mysql-connector-python"): (
        "sape_d_mcp.db.dialects.mysql",
        "MySQLDialect",
        ParamStyle.PYFORMAT,
    ),
    (Engine.SQLITE, "sqlite3"): ("sape_d_mcp.db.dialects.sqlite", "SQLiteDialect", ParamStyle.QMARK),
}

#: The pip requirement each driver key needs, verbatim, so the error message can be pasted
#: into a terminal.  `None` means the standard library, which is never missing.
_DRIVER_PACKAGES: dict[str, str | None] = {
    "pyodbc": "pyodbc>=5.0",
    "pymssql": "pymssql>=2.3",
    "psycopg": "psycopg[binary]>=3.1",
    "pymysql": "PyMySQL>=1.1",
    "mysql-connector-python": "mysql-connector-python>=8.3",
    "sqlite3": None,
}

#: The importable module name, which is not always the pip name.
_DRIVER_MODULES: dict[str, str] = {
    "pyodbc": "pyodbc",
    "pymssql": "pymssql",
    "psycopg": "psycopg",
    "pymysql": "pymysql",
    "mysql-connector-python": "mysql.connector",
    "sqlite3": "sqlite3",
}

#: pyodbc is the one driver whose pip install is not the whole story: it links against the
#: platform's ODBC driver manager and needs Microsoft's Driver 18 installed separately, with
#: administrator rights on Windows.  A user who sees only "pip install pyodbc" will install
#: it, try again, and get an entirely different and much less legible error from unixODBC.
_ODBC_DRIVER_HINTS: dict[str, str] = {
    "win32": (
        "It also needs the Microsoft ODBC Driver 18 for SQL Server, which is a separate "
        "install requiring administrator rights:\n"
        "    winget install --id Microsoft.msodbcsql.18 -e\n"
        "Where administrator rights are unavailable, select the 'pymssql' driver on this "
        "connection profile instead: it needs nothing beyond pip."
    ),
    "darwin": (
        "It also needs the Microsoft ODBC Driver 18 for SQL Server:\n"
        "    brew tap microsoft/mssql-release "
        "https://github.com/Microsoft/homebrew-mssql-release\n"
        "    brew update && HOMEBREW_ACCEPT_EULA=Y brew install msodbcsql18\n"
        "Or select the 'pymssql' driver on this connection profile, which needs nothing "
        "beyond pip."
    ),
    "linux": (
        "It also needs unixODBC and the Microsoft ODBC Driver 18 for SQL Server:\n"
        "    curl https://packages.microsoft.com/keys/microsoft.asc | sudo tee "
        "/etc/apt/trusted.gpg.d/microsoft.asc\n"
        "    curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list | sudo tee "
        "/etc/apt/sources.list.d/mssql-release.list\n"
        "    sudo apt-get update && sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18 "
        "unixodbc\n"
        "Or select the 'pymssql' driver on this connection profile, which needs nothing "
        "beyond pip."
    ),
}


def _coerce_engine(engine: Engine | str) -> Engine:
    """Accept the `Engine` member or the plain text `connections.engine` stores."""

    if isinstance(engine, Engine):
        return engine
    try:
        return Engine(str(engine).strip().lower())
    except ValueError as exc:
        known = ", ".join(sorted(member.value for member in Engine))
        raise UnknownDriverError(f"unknown engine {engine!r}; d-MCP supports {known}") from exc


def _coerce_driver(driver: str) -> str:
    """Normalise the driver key's spelling without inventing aliases.

    Case and surrounding whitespace are forgiven because they are transcription noise from a
    hand-edited `connections.db`.  Nothing else is: an alias table here would let a profile
    name a driver d-MCP has never tested against.
    """

    return str(driver or "").strip().lower()


def dialect_for(engine: Engine | str, driver: str) -> Dialect:
    """Return an unconfigured `Dialect` instance for `(engine, driver)`.

    Imports only the dialect module, never the third-party DB-API package a `Dialect` never
    touches (decision D1) — so this call succeeds even when that package is not installed.
    The Connections page needs to show a fully built profile, with a clear "driver not
    installed" state on the test-connection button, rather than failing before the user has
    even attempted to connect.

    Raises `UnknownDriverError` for a pair absent from the registry: a corrupt or hand-edited
    `connections.db` row, not a missing package.
    """

    resolved_engine = _coerce_engine(engine)
    key = (resolved_engine, _coerce_driver(driver))
    try:
        module_name, class_name, param_style = _DIALECT_REGISTRY[key]
    except KeyError as exc:
        supported = ", ".join(drivers_for(resolved_engine)) or "none"
        raise UnknownDriverError(
            f"{driver!r} is not a driver d-MCP knows for {resolved_engine}. "
            f"Supported drivers for that engine: {supported}."
        ) from exc

    module = importlib.import_module(module_name)
    dialect_class = getattr(module, class_name)
    return dialect_class(param_style, key[1])


def drivers_for(engine: Engine | str) -> tuple[str, ...]:
    """Every driver key registered for one engine, in the order the GUI should offer them.

    Registration order is deliberate: `pyodbc` before `pymssql`, because pyodbc is the
    default and the pairing exists so the multi-platform promise never depends on Microsoft's
    installer being reachable — not because the fallback is second-rate.
    """

    resolved = _coerce_engine(engine)
    return tuple(driver for (eng, driver) in _DIALECT_REGISTRY if eng is resolved)


def driver_requirement(driver: str) -> str | None:
    """The pip requirement for a driver key, or `None` for the standard library."""

    key = _coerce_driver(driver)
    if key not in _DRIVER_PACKAGES:
        raise UnknownDriverError(f"{driver!r} is not a driver d-MCP knows")
    return _DRIVER_PACKAGES[key]


def is_driver_available(driver: str) -> bool:
    """Whether the driver's package is *installed*, decided without importing it.

    The Connections page calls this to decide whether the test button is live, and it must
    not import the package to find out: importing pyodbc loads the ODBC driver manager, which
    on a misconfigured Linux host is slow and can abort the process.

    Note the exact claim.  This says the package is present, not that it will load: a pyodbc
    installed without `unixODBC` answers `True` here and still fails at `import_driver()`,
    with `libodbc.so.2: cannot open shared object file`.  That second failure is the one the
    user needs the install instructions for, so it is `import_driver()` that explains it, and
    this function stays cheap.
    """

    key = _coerce_driver(driver)
    if key not in _DRIVER_MODULES:
        raise UnknownDriverError(f"{driver!r} is not a driver d-MCP knows")
    module_name = _DRIVER_MODULES[key]
    if module_name in sys.modules:
        return True
    try:
        return importlib.util.find_spec(module_name) is not None
    except (ImportError, ValueError):
        # find_spec imports the parent package for a dotted name, so a broken
        # mysql.connector installation raises here rather than returning None.
        return False


def available_drivers(engine: Engine | str | None = None) -> tuple[str, ...]:
    """The installed subset of the registered drivers, optionally for one engine."""

    keys = drivers_for(engine) if engine is not None else tuple(_DRIVER_MODULES)
    return tuple(driver for driver in keys if is_driver_available(driver))


def import_driver(driver: str) -> ModuleType:
    """Import the DB-API driver module named by `driver`.  Called only from
    `engine.py.connect()`, at the one moment the driver is actually needed.

    Turns a bare `ImportError` into `DriverNotInstalledError`, whose message names the exact
    pip requirement — with an additional paragraph for `pyodbc` giving the Microsoft ODBC
    Driver 18 install command for the current platform, because `pip install pyodbc` alone
    does not make a pyodbc connection work.  The MCP tool boundary and the GUI's
    connection-test handler both catch `DriverNotInstalledError` specifically and show its
    message verbatim; neither ever lets a bare `ImportError` or its traceback reach the user.
    """

    key = _coerce_driver(driver)
    if key not in _DRIVER_MODULES:
        raise UnknownDriverError(
            f"{driver!r} is not a driver d-MCP knows. Registered drivers: "
            + ", ".join(sorted(_DRIVER_MODULES))
        )
    module_name = _DRIVER_MODULES[key]
    try:
        return importlib.import_module(module_name)
    except ImportError as exc:
        requirement = _DRIVER_PACKAGES[key]
        if requirement is None:
            # sqlite3 is the standard library.  If it is missing, the Python build itself is
            # broken and no pip command will help, so say that instead of a useless one.
            raise DriverNotInstalledError(
                "the standard library's sqlite3 module could not be imported, which means "
                "this Python was built without SQLite support. Reinstall Python from "
                "python.org or your distribution's packages."
            ) from exc

        # Two genuinely different failures wearing one exception class.  A
        # ModuleNotFoundError means the package is absent and pip will fix it.  Any other
        # ImportError means the package is there but its native library would not load —
        # pyodbc without unixODBC is the classic, and it reports
        # "libodbc.so.2: cannot open shared object file", which tells a user nothing about
        # what to install.  Telling them to `pip install pyodbc` in that state is worse than
        # useless: it succeeds, changes nothing, and sends them looking in the wrong place.
        absent = isinstance(exc, ModuleNotFoundError) and (
            exc.name is None
            or module_name == exc.name
            or module_name.startswith(f"{exc.name}.")
        )
        if absent:
            message = f"The {key!r} driver is not installed. Run: pip install {requirement}"
        else:
            message = (
                f"The {key!r} driver is installed but could not be loaded: {exc}. "
                "The Python package is present; a library it links against is not."
            )
        hint = _install_hint(key)
        if hint:
            message = f"{message}\n{hint}"
        logger.debug("driver %s is not importable: %s", key, exc)
        raise DriverNotInstalledError(message) from exc


def _install_hint(key: str) -> str | None:
    """The platform-specific extra install step for a driver that needs one.

    Only pyodbc does.  Everything else in the matrix is pure Python or ships its client
    library inside the wheel, which is the whole reason `pymssql` is shipped alongside
    `pyodbc` rather than as an afterthought.
    """

    if key != "pyodbc":
        return None
    if sys.platform.startswith("win"):
        return _ODBC_DRIVER_HINTS["win32"]
    if sys.platform == "darwin":
        return _ODBC_DRIVER_HINTS["darwin"]
    return _ODBC_DRIVER_HINTS["linux"]
