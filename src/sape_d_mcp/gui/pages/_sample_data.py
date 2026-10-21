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

"""Mockup fixtures for the stage-3 GUI pages, as far as they still exist.

Nothing left in this module is real. Every page that reads from here also
reads ``app.config_manager.get_show_sample_data()`` and renders its genuine
empty state when that flag is False, because the empty state is what every
first-run user actually sees and it must look as finished as the populated
one.

Delete the rest of this module, and every remaining import of it, once the
real stores land for the pages that still use it. Stage 8 has already retired
the audit-log fixture: ``logs_page.py`` reads ``audit.db`` through
``LogStore`` and no longer imports anything from here.
"""

from __future__ import annotations

# ---------------------------------------------------------------------------
# Connections (stage 4 retires this)
# ---------------------------------------------------------------------------

SAMPLE_CONNECTIONS: list[dict] = [
    {
        "id": 1,
        "display_name": "BD1",
        "engine": "mssql",
        "driver": "pyodbc",
        "host": "db.example.com",
        "port": 1433,
        "database": "Sales",
        "username": "svc_reports",
        "status": "success",  # display-only mock status dot, not a live health check
    },
    {
        "id": 2,
        "display_name": "BD2",
        "engine": "postgresql",
        "driver": "psycopg",
        "host": "localhost",
        "port": 5432,
        "database": "analytics",
        "username": "analytics_ro",
        "status": "warning",
    },
    {
        "id": 3,
        "display_name": "BD3",
        "engine": "sqlite",
        "driver": "sqlite3",
        "host": "",
        "port": None,
        "database": "./local/inventory.db",
        "username": "",
        "status": "error",
    },
]

# ---------------------------------------------------------------------------
# Schema browser — BD1 only, as the mockup brief asks for (stage 5 retires this)
# ---------------------------------------------------------------------------

# {connection_id: {schema_name: {object_type: [object_name, ...]}}}
SAMPLE_SCHEMA_TREE: dict[int, dict[str, dict[str, list[str]]]] = {
    1: {
        "dbo": {
            "table": ["Customers", "Orders", "OrderLines", "rpt_SalesSummary"],
            "view": ["vw_ActiveCustomers"],
            "function": ["fn_FullName"],
            "procedure": ["usp_CreateOrder"],
        },
        "sales": {
            "table": ["Invoices", "Payments"],
            "view": ["vw_MonthlySales"],
            "function": ["fn_TaxRate"],
            "procedure": ["usp_ClosePeriod"],
        },
    },
}

# ---------------------------------------------------------------------------
# Permission rules (stage 5 retires this)
# ---------------------------------------------------------------------------

_TABLE_ACTIONS = ("list", "read_structure", "select", "insert", "update", "delete",
                   "create", "drop")
_VIEW_ACTIONS = ("list", "read_definition", "select", "create", "drop")

SAMPLE_PERMISSION_RULES: list[dict] = [
    {
        "id": 1, "connection_id": 1, "object_type": "table", "is_deny": False,
        "rule_name": "Reporting read-only",
        "targets": [{"schema_pattern": "dbo", "name_pattern": "*"}],
        "actions": {a: a in ("list", "read_structure", "select") for a in _TABLE_ACTIONS},
        "created_at": "2026-08-04T09:12:00", "user_created": "luciano",
        "updated_at": "2026-08-04T09:12:00", "user_updated": "luciano",
    },
    {
        # A collection: one rule over three named tables, which is what schema
        # version 2 exists for and what the Objects column's "(+n)" renders.
        "id": 2, "connection_id": 1, "object_type": "table", "is_deny": False,
        "rule_name": "Order processing team",
        "targets": [{"schema_pattern": "dbo", "name_pattern": "Orders"},
                    {"schema_pattern": "dbo", "name_pattern": "OrderLines"},
                    {"schema_pattern": "dbo", "name_pattern": "Invoices"}],
        "actions": {a: a in ("list", "read_structure", "select", "insert", "update")
                    for a in _TABLE_ACTIONS},
        "created_at": "2026-08-10T14:30:00", "user_created": "luciano",
        "updated_at": "2026-08-10T14:30:00", "user_updated": "luciano",
    },
    {
        # Deliberately left unnamed: schema version 3 makes ``rule_name`` optional, and
        # the sample data is where an operator first sees what an unnamed rule looks
        # like -- the Objects column's "—", not a blank cell that reads as broken.
        "id": 3, "connection_id": 1, "object_type": "table", "is_deny": True,
        "rule_name": None,
        "targets": [{"schema_pattern": "sales", "name_pattern": "Payments"}],
        "actions": dict.fromkeys(_TABLE_ACTIONS, False),
        "created_at": "2026-08-12T08:00:00", "user_created": "luciano",
        "updated_at": "2026-08-12T08:00:00", "user_updated": "luciano",
    },
    {
        # A prefix pattern, deliberately included per the mockup brief.
        "id": 4, "connection_id": 1, "object_type": "table", "is_deny": False,
        "rule_name": "Report tables (rpt_*)",
        "targets": [{"schema_pattern": "*", "name_pattern": "rpt_*"}],
        "actions": {a: a in ("list", "read_structure", "select") for a in _TABLE_ACTIONS},
        "created_at": "2026-08-15T11:45:00", "user_created": "maria",
        "updated_at": "2026-08-15T11:45:00", "user_updated": "maria",
    },
    {
        "id": 5, "connection_id": 1, "object_type": "view", "is_deny": False,
        "rule_name": "dbo views read-only",
        "targets": [{"schema_pattern": "dbo", "name_pattern": "*"}],
        "actions": {a: a in ("list", "read_definition", "select") for a in _VIEW_ACTIONS},
        "created_at": "2026-08-16T09:00:00", "user_created": "luciano",
        "updated_at": "2026-08-16T09:00:00", "user_updated": "luciano",
    },
]
