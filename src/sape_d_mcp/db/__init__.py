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

"""Database access layer: dialects, connection profiles, credentials, introspection and the SQL guard."""

from __future__ import annotations

from typing import Any

__all__ = [
    # connection_store
    "ConnectionStore",
    "DEFAULT_STATEMENT_TIMEOUT_S",
    "DRIVERS_BY_ENGINE",
    "ENGINES",
    "canonical_driver",
    "canonical_engine",
    "current_user",
    "default_db_path",
    "known_drivers",
    # credential_store
    "CredentialError",
    "CredentialStore",
    "SERVICE_NAME",
    "VaultLocked",
    "account_for",
    "config_dir",
    # engine
    "ConnectionTestResult",
    "DatabaseConnection",
    "ERROR_KINDS",
    "ReadOnlySessionError",
    "apply_statement_timeout",
    "classify_error",
    "connect",
    "connection",
    "read_only_session",
    "resolve_dialect",
    "statement_timeout_for",
    "test_connection",
]

# Which submodule owns each public name.  Resolved lazily through the PEP 562
# module __getattr__ below rather than imported here, for two reasons: importing
# engine.py pulls in the whole dialect layer, and the Connections page must be
# able to list and edit profiles on a machine where not one database driver is
# installed; and `main.py --cli` should not pay for the dialect import until it
# actually opens a connection.
_EXPORTS: dict[str, str] = {
    "ConnectionStore": "connection_store",
    "DEFAULT_STATEMENT_TIMEOUT_S": "connection_store",
    "DRIVERS_BY_ENGINE": "connection_store",
    "ENGINES": "connection_store",
    "canonical_driver": "connection_store",
    "canonical_engine": "connection_store",
    "current_user": "connection_store",
    "default_db_path": "connection_store",
    "known_drivers": "connection_store",
    "CredentialError": "credential_store",
    "CredentialStore": "credential_store",
    "SERVICE_NAME": "credential_store",
    "VaultLocked": "credential_store",
    "account_for": "credential_store",
    "config_dir": "credential_store",
    "ConnectionTestResult": "engine",
    "DatabaseConnection": "engine",
    "ERROR_KINDS": "engine",
    "ReadOnlySessionError": "engine",
    "apply_statement_timeout": "engine",
    "classify_error": "engine",
    "connect": "engine",
    "connection": "engine",
    "read_only_session": "engine",
    "resolve_dialect": "engine",
    "statement_timeout_for": "engine",
    "test_connection": "engine",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORTS.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module

    module = import_module(f"{__name__}.{module_name}")
    value = getattr(module, name)
    globals()[name] = value  # cache, so the lookup happens once
    return value


def __dir__() -> list[str]:
    return sorted(__all__)
