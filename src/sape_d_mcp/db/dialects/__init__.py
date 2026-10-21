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

"""Per-engine SQL dialects (MS-SQL, PostgreSQL, MySQL/MariaDB, SQLite) behind one registry.

Nothing outside `src/sape_d_mcp/db/` imports a concrete dialect: everything goes through
`dialect_for()`, which is also the only place that knows a `(engine, driver)` pair maps onto
a class and a paramstyle.  Importing this package pulls in no database driver — that happens
in `import_driver()`, at the one moment `engine.py` actually needs one.
"""

from __future__ import annotations

from .base import (
    MAX_WRITE_ROWS,
    RESERVED_PARAM_NAMES,
    CapabilityError,
    DeferredSurface,
    Dialect,
    DialectError,
    DialectNotConfiguredError,
    DriverNotInstalledError,
    InvalidIdentifierError,
    UnknownDriverError,
    fold_ascii_lower,
    rewrite_placeholders,
)
from .mssql import MSSQLDialect
from .mysql import MySQLDialect
from .postgres import PostgreSQLDialect
from .registry import (
    available_drivers,
    dialect_for,
    driver_requirement,
    drivers_for,
    import_driver,
    is_driver_available,
)
from .sqlite import SQLiteDialect
from .types import (
    Capabilities,
    CaseFolding,
    ColumnInfo,
    ColumnSpec,
    ConnectionProfile,
    Engine,
    ForeignKeyInfo,
    GuardTraits,
    KeyInfo,
    NormalisedRef,
    ObjectRef,
    ObjectType,
    Operator,
    ParameterInfo,
    ParamStyle,
    Predicate,
    PrincipalInfo,
    Query,
    RawPredicate,
    ReadOnlyEnforcement,
    ReadOnlyScope,
    ReadOnlySession,
    RoutineInfo,
    Script,
    SecretStr,
    ServerTraits,
    StatementKind,
    TableInfo,
    WritingCTEShape,
    reads_as_read_only,
)

__all__ = [
    # Vocabulary
    "Capabilities",
    "CaseFolding",
    "ColumnInfo",
    "ColumnSpec",
    "ConnectionProfile",
    "Engine",
    "ForeignKeyInfo",
    "GuardTraits",
    "KeyInfo",
    "NormalisedRef",
    "ObjectRef",
    "ObjectType",
    "Operator",
    "ParamStyle",
    "ParameterInfo",
    "Predicate",
    "PrincipalInfo",
    "Query",
    "RawPredicate",
    "ReadOnlyEnforcement",
    "ReadOnlyScope",
    "ReadOnlySession",
    "RoutineInfo",
    "Script",
    "SecretStr",
    "ServerTraits",
    "StatementKind",
    "TableInfo",
    "WritingCTEShape",
    "reads_as_read_only",
    # Interface
    "DeferredSurface",
    "Dialect",
    "MAX_WRITE_ROWS",
    "RESERVED_PARAM_NAMES",
    "fold_ascii_lower",
    "rewrite_placeholders",
    # Concrete dialects — reachable for typing and tests; production code uses dialect_for()
    "MSSQLDialect",
    "MySQLDialect",
    "PostgreSQLDialect",
    "SQLiteDialect",
    # Registry
    "available_drivers",
    "dialect_for",
    "driver_requirement",
    "drivers_for",
    "import_driver",
    "is_driver_available",
    # Exceptions
    "CapabilityError",
    "DialectError",
    "DialectNotConfiguredError",
    "DriverNotInstalledError",
    "InvalidIdentifierError",
    "UnknownDriverError",
]
