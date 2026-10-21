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

"""Connection profiles in ``connections.db`` — everything needed to reach a server, never the password."""

from __future__ import annotations

import getpass
import json
import logging
import os
import re
import sqlite3
from collections.abc import Callable, Iterable, Mapping
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any, Protocol

from sape_d_mcp.db.auth_modes import (
    AUTH_MODES,
    canonical_auth_mode,
    default_auth_mode,
    message_for,
    support_for,
)
from sape_d_mcp.db_location import resolve_db_directory
from sape_d_mcp.db_migrations import MigrationRecord, backup_before_rebuild

logger = logging.getLogger(__name__)

#: What an upgrade of this file rewrote, as it reads in a sentence.  Passed to every
#: :class:`MigrationRecord` raised here so the record's heading names profiles rather
#: than the permission rules the same machinery serves in ``permissions.py``.
_MIGRATION_SUBJECT = "your connection profiles"

#: The one thing a reader of a ``connections.db`` record most needs told plainly.
_MIGRATION_NOTES = (
    "There is no password here, and there is none in the backup either: the\n"
    "connections database has no column that can hold one.",
)

# ---------------------------------------------------------------------------
# Domains — the single source of truth
# ---------------------------------------------------------------------------
# These two tuples drive the DDL's CHECK constraints, the runtime validation and
# the parametrised tests.  DESIGN-DATA-MODEL.md §3.4 names them ENGINES and
# DRIVERS_BY_ENGINE and sites them in dialects/base.py.  They are restated here
# rather than imported because connection_store must remain usable — and
# testable — with the dialect layer absent: the Connections page has to be able
# to list and edit profiles on a machine where no driver at all is installed.
# A conformance test asserts these agree with the dialect registry.
#
# SPELLING NOTE, needs a ruling.  DESIGN-DATA-MODEL.md §3.3 spells the
# PostgreSQL engine 'postgres' and the Oracle MySQL driver 'mysqlconnector';
# DESIGN-DIALECTS.md §2 (Engine.POSTGRESQL = "postgresql") and §7 (the registry
# key "mysql-connector-python") spell them differently, and the stage-3 GUI
# mockup already emits the DESIGN-DIALECTS spelling.  Three of the four
# artefacts agree, and only the DESIGN-DIALECTS spelling can be handed straight
# to dialect_for(), so that is what this file stores.  _ENGINE_ALIASES below
# accepts the DESIGN-DATA-MODEL spelling on input and canonicalises it, so
# either spelling may be written and only one is ever stored.
ENGINES: tuple[str, ...] = ("mssql", "postgresql", "mysql", "sqlite")

DRIVERS_BY_ENGINE: dict[str, tuple[str, ...]] = {
    "mssql": ("pyodbc", "pymssql"),
    "postgresql": ("psycopg",),
    "mysql": ("pymysql", "mysql-connector-python"),
    "sqlite": ("sqlite3",),
}

_ENGINE_ALIASES: dict[str, str] = {
    "postgres": "postgresql",
    "postgresql": "postgresql",
    "pg": "postgresql",
    "mariadb": "mysql",
    "sql server": "mssql",
    "sqlserver": "mssql",
    "mssql": "mssql",
    "mysql": "mysql",
    "sqlite": "sqlite",
    "sqlite3": "sqlite",
}

_DRIVER_ALIASES: dict[str, str] = {
    "mysqlconnector": "mysql-connector-python",
    "mysql_connector_python": "mysql-connector-python",
    "mysql-connector": "mysql-connector-python",
    "psycopg3": "psycopg",
}

# The engine that needs no host, port or username — the tagged union's odd member.
FILE_ENGINE = "sqlite"

DEFAULT_STATEMENT_TIMEOUT_S = 30
MAX_STATEMENT_TIMEOUT_S = 86_400  # 24 h; above this the value is a typo, not a policy

# Keys that must never appear in a profile or in options_json.  This table is the
# reason connections.db cannot hold a secret even by accident: a caller that
# hands us a password gets a ValueError, not a silently persisted credential.
# The check is on the key, not the value, because we cannot recognise a password
# by looking at it.
_FORBIDDEN_PROFILE_KEYS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "secret",
        "credential",
        "credentials",
        "token",
        "api_key",
        "apikey",
        "master_password",
        "connection_string",  # a DSN is the classic smuggling route for PWD=
        "dsn",
    }
)

SCHEMA_VERSION = 2

# Columns the store reads and writes, in DDL order.  Drives the INSERT, the
# UPDATE, the row -> dict mapping and _migrate_schema().
_PROFILE_COLUMNS: tuple[str, ...] = (
    "display_name",
    "engine",
    "driver",
    "host",
    "port",
    "instance",
    "database",
    "username",
    "auth_mode",
    "options_json",
    "colour_tag",
    "statement_timeout_s",
)

# An MS-SQL named instance, deliberately wider than Microsoft's own rule (16
# characters, no leading digit).  The regex exists to keep a delimiter — a
# backslash, a comma, a colon, a semicolon, a space, a control character — out of
# a connection string, not to second-guess the server about what it will accept.
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_$#][A-Za-z0-9_$#\-]{0,127}$")

_AUDIT_COLUMNS: tuple[str, ...] = ("created_at", "user_created", "updated_at", "user_updated")


def _engine_driver_check() -> str:
    """Render the engine/driver CHECK from DRIVERS_BY_ENGINE.

    Generated rather than typed out so the tuple above genuinely is the single
    source of truth: adding a driver is one edit, and the constraint cannot
    drift away from the validation that runs before the INSERT.
    """
    clauses = []
    for engine in ENGINES:
        drivers = DRIVERS_BY_ENGINE[engine]
        if len(drivers) == 1:
            rendered = f"driver  = '{drivers[0]}'"
        else:
            rendered = "driver IN (" + ", ".join(f"'{d}'" for d in drivers) + ")"
        clauses.append(f"(engine = '{engine}' AND {rendered})")
    return "\n     OR ".join(clauses)


def _auth_mode_check() -> str:
    """Render the auth_mode CHECK from AUTH_MODES, for the reason above.

    Adding a fourth mode must be one edit in ``auth_modes.py``, and the constraint
    must not be able to drift from the validator that runs before the INSERT.
    """
    return "auth_mode IN (" + ", ".join(f"'{mode}'" for mode in AUTH_MODES) + ")"


def _connections_ddl(table: str, *, if_not_exists: bool) -> str:
    """The `connections` table body, under a caller-chosen name.

    Parameterised on the name for one reason only: the version 1 -> 2 migration
    builds the same table as ``connections_v2`` before renaming it, and a schema
    the migration retypes by hand is a schema whose two copies drift.  ``table``
    is always a literal written in this module — never anything that arrived from
    outside — which is why it may be formatted into the statement text.
    """
    exists_clause = "IF NOT EXISTS " if if_not_exists else ""
    return f"""
CREATE TABLE {exists_clause}{table} (
    -- NO password column, and no column that could hold one. Repeated inside the
    -- CREATE TABLE and not only above it, because this is the text sqlite_master
    -- keeps: it is what anyone opening the file in a SQLite browser will read.
    id            INTEGER PRIMARY KEY AUTOINCREMENT,   -- AUTOINCREMENT: ids are never
                                                       -- recycled, so an orphan rule in
                                                       -- permissions.db can never be adopted
                                                       -- by a different connection (§3.2)
    display_name  TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    engine        TEXT    NOT NULL,
    driver        TEXT    NOT NULL,
    host          TEXT,            -- NULL iff engine = 'sqlite'
    port          INTEGER,         -- NULL iff engine = 'sqlite', or an MS-SQL named
                                   --   instance supplies the port through the Browser
    instance      TEXT,            -- MS-SQL named instance ('SQLEXPRESS'); NULL elsewhere
    database      TEXT    NOT NULL,-- database name, or the absolute file path for sqlite
    username      TEXT,            -- NULL iff auth_mode <> 'password'

    -- How the connection proves who it is: 'password', 'integrated' (the operating
    -- system supplies the identity — SSPI, Kerberos/GSSAPI, PostgreSQL peer) or
    -- 'none' (SQLite, where the file's own permissions are the access control).
    -- The default keeps every profile written before version 2 behaving exactly as
    -- it did.
    auth_mode     TEXT    NOT NULL DEFAULT 'password',

    options_json  TEXT    NOT NULL DEFAULT '{{}}',
    colour_tag    TEXT,            -- '#RRGGBB' shown as the tab and sidebar accent, or NULL

    -- Per-connection statement timeout (DESIGN-MCP-TOOLS.md §6.1, §13.2). It is a
    -- property of the connection and not of the call: the model gets no lever
    -- over how long its own statement may tie up the server.
    statement_timeout_s INTEGER NOT NULL DEFAULT {DEFAULT_STATEMENT_TIMEOUT_S},

    created_at    TEXT    NOT NULL,
    user_created  TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    user_updated  TEXT    NOT NULL,

    -- The engine is the discriminator of a tagged union and auth_mode is a second,
    -- narrower one. Exactly one null pattern is legal per (engine, auth_mode) pair,
    -- so a NULL here always means "structurally absent", never "not filled in yet".
    --
    -- Renamed from ck_connections_sqlite_shape: it no longer governs only the SQLite
    -- row shape, and a constraint whose name says less than it does is a constraint
    -- someone will relax for the wrong reason. Two guarantees of the old constraint
    -- survive intact: a 'password' profile still cannot be saved without a user
    -- name, and every non-SQLite profile is still addressable — 'port IS NOT NULL'
    -- becomes 'port IS NOT NULL OR instance IS NOT NULL', and since instance is NULL
    -- on every engine but MS-SQL, PostgreSQL and MySQL still require a port.
    CONSTRAINT ck_connections_shape CHECK (
        (engine =  'sqlite'
            AND host     IS NULL AND port     IS NULL
            AND username IS NULL AND instance IS NULL
            AND auth_mode = 'none')
     OR (engine <> 'sqlite'
            AND host IS NOT NULL
            AND (port IS NOT NULL OR instance IS NOT NULL)
            AND ( (auth_mode = 'password'   AND username IS NOT NULL)
               OR (auth_mode = 'integrated' AND username IS     NULL) ))
    ),

    CONSTRAINT ck_connections_auth_mode CHECK (
        {_auth_mode_check()}
    ),

    -- An instance name belongs to MS-SQL alone. Without this, a PostgreSQL row
    -- could carry one and would then satisfy ck_connections_shape with no port,
    -- which is a profile nothing can reach.
    CONSTRAINT ck_connections_instance CHECK (
        instance IS NULL
        OR (engine = 'mssql' AND length(trim(instance)) > 0)
    ),

    -- The engine/driver pairing is a closed product decision, not routine schema
    -- evolution, so it is safe to pin in a CHECK: adding a fifth engine is a
    -- user_version bump with a full table rebuild, which is proportionate.
    CONSTRAINT ck_connections_engine_driver CHECK (
        {_engine_driver_check()}
    ),

    CONSTRAINT ck_connections_port      CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    CONSTRAINT ck_connections_options   CHECK (json_valid(options_json)),
    CONSTRAINT ck_connections_name      CHECK (length(trim(display_name)) > 0),
    CONSTRAINT ck_connections_database  CHECK (length(trim(database)) > 0),
    CONSTRAINT ck_connections_colour    CHECK (
        colour_tag IS NULL
        OR colour_tag GLOB '#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]'
    ),
    CONSTRAINT ck_connections_timeout   CHECK (
        statement_timeout_s BETWEEN 1 AND {MAX_STATEMENT_TIMEOUT_S}
    ),
    CONSTRAINT ck_connections_audit     CHECK (
        length(created_at) >= 19 AND length(updated_at) >= 19
        AND length(user_created) > 0 AND length(user_updated) > 0
    )
);
"""


# DESIGN-DATA-MODEL.md §3.3 as revised by DESIGN-CONNECTION-SETUP.md §3.2, verbatim
# but for the generated engine/driver and auth_mode clauses, the engine spelling
# noted above and the statement_timeout_s column that DESIGN-MCP-TOOLS.md §13.2 adds.
SCHEMA = f"""
-- connections.db
--
-- Connection profiles. There is deliberately NO password column, and no column
-- that could hold one: credentials go to the OS keyring under service
-- "SAPE-d-MCP", account "conn:<id>", with the AES vault as the fallback where no
-- keyring backend exists. A password must never reach this file, an error
-- message, a log line or a generated MCP client config. If a future change
-- appears to need a secret here, the change is wrong.
--
-- Only "SQL-standard" values are stored: options_json carries every
-- engine-specific extra, so this table never grows a column for one driver.

{_connections_ddl('connections', if_not_exists=True).strip()}

-- display_name is already UNIQUE (implicit index). This second index serves the
-- Connections page's default ordering and the Logs page's tab construction.
CREATE INDEX IF NOT EXISTS idx_connections_engine ON connections(engine, display_name);
"""

# Columns whose absence _migrate_schema() repairs in place.  Only columns that can
# be added by ALTER TABLE (no UNIQUE, no CHECK that references another column)
# belong here; anything else needs a versioned table rebuild.
#
# auth_mode and instance are deliberately NOT here, and must never be added.
# SQLite would accept both by ALTER TABLE quite happily — and the resulting table
# would keep the version 1 constraints, including the `username IS NOT NULL` that
# makes a trusted connection unrepresentable, which is the exact failure the
# version 2 rebuild exists to correct.  Only _migrate_1_to_2() may introduce them.
_MIGRATABLE_COLUMNS: dict[str, str] = {
    "statement_timeout_s": f"INTEGER NOT NULL DEFAULT {DEFAULT_STATEMENT_TIMEOUT_S}",
    "colour_tag": "TEXT",
}


class _PermissionSweeper(Protocol):
    """The one method ConnectionStore.delete() needs from the permission store.

    Typed as a Protocol so connection_store never imports permissions.py — the
    module boundary DESIGN-DATA-MODEL.md §7.2 relies on to keep the permission
    engine testable with no connections database present at all.
    """

    def revoke_connection(self, connection_id: int) -> int: ...


class _SecretPurger(Protocol):
    """The one method ConnectionStore.delete() needs from the credential store."""

    def delete_password(self, connection_id: int) -> None: ...


def current_user() -> str:
    """Best-effort login name of the user running the application.

    Ported from f-MCP's ``permissions.current_user`` with its documented
    fallbacks: ``getpass.getuser()`` raises where there is no password entry and
    no LOGNAME, which happens inside slim containers and some service accounts.
    """
    try:
        return getpass.getuser()
    except Exception:  # no password entry / no LOGNAME in some containers
        fallback = os.environ.get("USER") or os.environ.get("USERNAME")
        if fallback:
            return fallback
        getuid = getattr(os, "getuid", None)
        return f"uid:{getuid()}" if getuid is not None else "unknown"


def _now() -> str:
    """ISO 8601 with the local offset, seconds precision — f-MCP's audit format."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def default_db_path() -> Path:
    """Resolve ``connections.db`` from the environment, else the current working directory.

    Precedence: ``DMCP_CONNECTIONS_DB`` (this file, exactly), then ``DMCP_DB_DIR``
    (all three files, one directory), then whatever :func:`resolve_db_directory`
    falls back to — see that module for why the fallback is the *current working
    directory* and not a hard-coded ``.parent`` count off ``__file__`` (the defect
    this replaced: an installed wheel's ``__file__`` lives under
    ``site-packages/``, and a fixed hop count from there lands inside the
    interpreter's own ``lib/`` directory, not the project).

    Overridable so the test suite can point at a ``tmp_path`` without touching
    the developer's real databases (DESIGN-DATA-MODEL.md §1).
    """
    explicit = os.environ.get("DMCP_CONNECTIONS_DB")
    if explicit:
        return Path(explicit).expanduser()
    return resolve_db_directory() / "connections.db"


def canonical_engine(value: str) -> str:
    """Map an engine spelling to the one canonical form, or raise.

    Accepts the DESIGN-DATA-MODEL.md §3.3 spellings as aliases; see the note on
    ENGINES above.
    """
    if not isinstance(value, str):
        raise ValueError(f"engine must be a string, got {type(value).__name__}")
    key = value.strip().lower()
    engine = _ENGINE_ALIASES.get(key)
    if engine is None:
        raise ValueError(f"unknown engine {value!r}; expected one of {', '.join(ENGINES)}")
    return engine


def canonical_driver(engine: str, value: str) -> str:
    """Map a driver spelling to the one canonical form for ``engine``, or raise."""
    if not isinstance(value, str):
        raise ValueError(f"driver must be a string, got {type(value).__name__}")
    key = value.strip().lower()
    driver = _DRIVER_ALIASES.get(key, key)
    allowed = DRIVERS_BY_ENGINE[engine]
    if driver not in allowed:
        raise ValueError(
            f"driver {value!r} cannot be used with engine {engine!r}; "
            f"expected one of {', '.join(allowed)}"
        )
    return driver


def _parse_mssql_target(raw: str):
    """`targets.parse_mssql_target()`, imported at the call rather than at module scope.

    ``targets`` is a leaf module with no dialect and no driver import, so importing
    it here costs nothing — but this module's stated property is that it stays
    usable on a machine where the rest of the database layer is absent, and the
    late import is what keeps that true of the import statement as well as of the
    behaviour.  It parses or it raises; it never repairs.
    """
    from sape_d_mcp.db.targets import parse_mssql_target

    return parse_mssql_target(raw)


def _reconcile_mssql_profile(profile):
    """`targets.reconcile_mssql_profile()`, imported at the call for the same reason."""
    from sape_d_mcp.db.targets import reconcile_mssql_profile

    return reconcile_mssql_profile(profile)


def _split_compound_hosts(
    conn: sqlite3.Connection, table: str, record: MigrationRecord | None = None
) -> None:
    """Separate an MS-SQL ``host`` that carries a server, an instance and a port.

    A version 1 row may hold ``PC-ARR\\SQLEXPRESS:56879`` in ``host``, because
    ``host`` was free text and there was nowhere else to put the other two values.
    That row reaches FreeTDS verbatim and fails with DB-Lib 20009, which reads like
    a network fault and is not one.

    The user ruled that the migration splits such a host automatically rather than
    only flagging it, and the safeguards on that ruling are these:

    * the ``VACUUM INTO`` backup has already been taken, unconditionally;
    * every split is recorded with the original value and the three results, one
      per line, so it is auditable afterwards exactly what changed — and recorded
      to the file beside that backup as well as to the logger, because the
      application's own logging configuration silences the logger (see
      :class:`MigrationRecord`);
    * a host ``parse_mssql_target()`` will not accept — two backslashes, a comma
      *and* a colon, ``np:``, ``(localdb)\\NAME`` — is copied **verbatim** and left
      for :meth:`ConnectionStore.needs_review` to flag.  Nothing is invented; the
      automatic split applies only to what the parser accepts unambiguously.
    """
    record = record if record is not None else MigrationRecord(_MIGRATION_SUBJECT)
    rows = conn.execute(
        f"SELECT id, display_name, host, port FROM {table} "
        "WHERE engine = 'mssql' AND host IS NOT NULL"
    ).fetchall()

    for row in rows:
        connection_id, display_name, host, port = row[0], row[1], str(row[2]), row[3]
        try:
            target = _parse_mssql_target(host)
        except Exception as exc:  # ValueError from the parser, or the module absent
            record.note(
                "Connection %s (%s) keeps its host %r verbatim: it cannot be split "
                "unambiguously (%s). Open the profile and set Host, Instance and Port "
                "by hand.",
                connection_id,
                display_name,
                host,
                exc,
            )
            continue
        if not getattr(target, "compound", False):
            continue

        new_port = target.port if target.port is not None else port
        conn.execute(
            f"UPDATE {table} SET host = ?, instance = ?, port = ? "
            "WHERE id = ?",
            (target.server, target.instance, new_port, connection_id),
        )
        # One line per resulting value, as the ruling requires: a migration that
        # rewrites user data has to leave a record a human can check field by field.
        record.note("Connection %s (%s): the host was split.", connection_id, display_name)
        record.note("    host     was    %r", host)
        record.note("    host     is now %r", target.server)
        record.note("    instance is now %r", target.instance)
        record.note("    port     was %r, is now %r", port, new_port)
        if target.port is not None and port is not None and int(target.port) != int(port):
            record.note(
                "    the port %r that was typed into the host field supersedes the "
                "port column's %r; check the profile if that is not what you meant.",
                target.port,
                port,
            )


def _migrate_1_to_2(conn: sqlite3.Connection) -> None:
    """Rebuild ``connections`` with ``auth_mode``, ``instance`` and ``ck_connections_shape``.

    SQLite has no ``ALTER TABLE ... DROP CONSTRAINT``, and version 2 *replaces* a
    CHECK, so SQLite's own twelve-step table rebuild is the only honest route.
    ``pragma writable_schema = 1`` is rejected: it edits ``sqlite_master`` text
    under a live schema cache, it is documented as a foot-gun, and a corrupted
    ``connections.db`` costs every profile and strands every keyring entry.

    Idempotent, because the migration chain must be safe to re-enter: a database
    that already has the two columns is left alone, and so is a brand-new file,
    whose table ``SCHEMA`` has just created in the version 2 shape.

    Everything it reports goes to a :class:`MigrationRecord`, which writes it to a
    file beside the backup as well as to the logger: this runs once, unattended, at
    start-up, under a logging configuration that discards it.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(connections)")}
    if not columns or {"auth_mode", "instance"} <= columns:
        return

    record = MigrationRecord(
        _MIGRATION_SUBJECT, user=current_user(), notes=_MIGRATION_NOTES
    )
    backup_before_rebuild(conn, 2, record, subject=_MIGRATION_SUBJECT)

    # connections.db holds no foreign key of its own — the rules in permissions.db
    # are a different file and are swept by _revoke_rules(), not by SQLite — so this
    # is procedure rather than necessity.  It is done anyway, because the next
    # maintainer will not know that.  Both pragmas are no-ops inside a transaction,
    # which is why they sit outside one.
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute("BEGIN IMMEDIATE")
        conn.execute(_connections_ddl("connections_v2", if_not_exists=False))
        # `colour_tag` and `statement_timeout_s` both arrived after the first
        # pre-release build, and `_migrate_schema()` — which repairs them by ALTER —
        # runs *after* this chain.  So a genuine old file may not have them yet, and
        # naming them unconditionally in the SELECT fails with "no such column",
        # taking the whole upgrade down on exactly the oldest file it exists to
        # rescue.  Each is therefore read where it is present and defaulted where it
        # is not, which is what `_migrate_schema()` would have done anyway.
        colour = "colour_tag" if "colour_tag" in columns else "NULL"
        timeout = (
            "statement_timeout_s"
            if "statement_timeout_s" in columns
            else str(DEFAULT_STATEMENT_TIMEOUT_S)
        )
        # Every version 1 row satisfies the version 2 constraint by construction: a
        # v1 SQLite row has the three NULLs the 'none' branch demands, and every v1
        # non-SQLite row has a non-NULL username and port, which is exactly the
        # 'password' branch.  The migration therefore cannot fail on data.
        conn.execute(
            f"""
            INSERT INTO connections_v2
                  (id, display_name, engine, driver, host, port, instance, database,
                   username, auth_mode, options_json, colour_tag, statement_timeout_s,
                   created_at, user_created, updated_at, user_updated)
            SELECT id, display_name, engine, driver, host, port, NULL,     database,
                   username,
                   CASE WHEN engine = 'sqlite' THEN 'none' ELSE 'password' END,
                   options_json, {colour}, {timeout},
                   created_at, user_created, updated_at, user_updated
              FROM connections
            """
        )
        _split_compound_hosts(conn, "connections_v2", record)
        conn.execute("DROP TABLE connections")
        conn.execute("ALTER TABLE connections_v2 RENAME TO connections")
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_connections_engine "
            "ON connections(engine, display_name)"
        )
        broken = conn.execute("PRAGMA foreign_key_check").fetchall()
        if broken:  # pragma: no cover - this file declares no foreign key
            raise RuntimeError(
                "The schema version 2 rebuild left a broken foreign key reference; "
                "the change has been rolled back."
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        # Written even here.  A rolled-back rebuild changed nothing, but the run
        # that failed is exactly the one whose account someone will want, and the
        # record already names the backup it should be restored from if the
        # rollback itself is in doubt.
        outcome = (
            f"The upgrade FAILED ({exc}) and was rolled back. Nothing above was kept; "
            "the database is as it was, and the backup named at the top is a copy of it."
        )
        record.write(outcome)
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")

    record.note("connections.db is now at schema version 2.", level=logging.INFO)
    record.write("The upgrade completed and every change it made is listed above.")


#: One entry per version step, applied in ascending order, each idempotent and each
#: committed before the next.  The key is the version the step *produces*.
_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    2: _migrate_1_to_2,
}


class ConnectionStore:
    """CRUD over ``connections.db``.  Holds no secret and opens no database server.

    Every write goes through :meth:`_validate`, which enforces in Python exactly
    what the DDL's CHECK constraints enforce in SQLite.  Both layers are kept
    because they fail differently and usefully: the Python layer produces a
    sentence the Connections page can show beside the offending field, and the
    SQLite layer is the backstop that also covers a hand-edited file.
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str] | None = None,
        user: str | None = None,
        credential_store: _SecretPurger | None = None,
        permission_store: _PermissionSweeper | None = None,
    ) -> None:
        self.db_path = Path(db_path).expanduser() if db_path is not None else default_db_path()
        self.user = user or current_user()
        self._credentials = credential_store
        self._permissions = permission_store

        # Nothing is created at import time; the file appears here, on the first
        # construction of a store, which is what the first-run sequence in
        # DESIGN-DATA-MODEL.md §8 step 3 prescribes.
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._apply_pragmas()

        # Read the version *before* the schema runs: after executescript a fresh
        # file is indistinguishable from a current one.
        existing_version = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate(existing_version)
        self._migrate_schema()

    # -- lifecycle -------------------------------------------------------

    def _apply_pragmas(self) -> None:
        """DESIGN-DATA-MODEL.md §6, applied on every open and before the first CREATE."""
        self.conn.execute("PRAGMA busy_timeout = 5000")
        mode = self.conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            # Some network mounts have no shared-memory locking and silently fall
            # back to 'delete', which would quietly break the GUI/server
            # cross-process design rather than fail.
            raise RuntimeError(
                f"Cannot enable WAL journalling on {self.db_path}: SQLite reported "
                f"journal_mode={mode!r}. The d-MCP GUI and MCP server read this file "
                "concurrently and need WAL. Move the databases off the network share, "
                "or set DMCP_DB_DIR to a local directory."
            )
        # FULL, not NORMAL: losing a profile strands a keyring entry that nothing
        # can now address, because the account name is derived from the row's id.
        self.conn.execute("PRAGMA synchronous = FULL")
        self.conn.execute("PRAGMA foreign_keys = ON")

    def _migrate(self, existing_version: int) -> None:
        """The ``user_version`` hook: run the step chain, bump a fresh file, refuse a newer one.

        The version is read in ``__init__`` *before* ``executescript(SCHEMA)``,
        which is the ordering that makes this possible at all: after the script has
        run, a fresh file is indistinguishable from a current one, and
        ``CREATE TABLE IF NOT EXISTS`` is a silent no-op against the version 1
        table.
        """
        if existing_version > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.db_path} was written by a newer version of SAPÉ d-MCP "
                f"(schema {existing_version}, this build understands {SCHEMA_VERSION}). "
                "Upgrade the application rather than letting an older build mis-read it."
            )
        if existing_version >= SCHEMA_VERSION:
            return

        for version in sorted(_MIGRATIONS):
            if version <= existing_version:
                continue
            _MIGRATIONS[version](self.conn)
            self.conn.execute(f"PRAGMA user_version = {version}")
            self.conn.commit()

        # A fresh file, or one whose remaining steps were all no-ops: the version is
        # still set, so the next open takes the early return above.
        self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.conn.commit()

    def _migrate_schema(self) -> None:
        """Add any column missing from an older file, sorted for determinism.

        f-MCP's ``PRAGMA table_info`` diff, applied to the fixed column list
        rather than to an action tuple.  It covers a pre-release file written
        before ``statement_timeout_s`` existed, which is not hypothetical: the
        column arrived after the data-model document was signed off.
        """
        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(connections)")}
        missing = sorted(set(_MIGRATABLE_COLUMNS) - existing)
        for column in missing:
            try:
                self.conn.execute(
                    f"ALTER TABLE connections ADD COLUMN {column} {_MIGRATABLE_COLUMNS[column]}"
                )
                self.conn.commit()
            except sqlite3.OperationalError as exc:
                # SQLite says "attempt to write a readonly database" — no hyphen — so a
                # literal "read-only" search never fires and the raw OperationalError
                # leaks instead of this message. Strip hyphens before comparing.
                if "readonly" in str(exc).lower().replace("-", ""):
                    raise RuntimeError(
                        f"Cannot migrate {self.db_path}: the database is read-only. "
                        "Check the file permissions."
                    ) from exc
                raise
            logger.info("Added missing column %s to connections", column)

    def close(self) -> None:
        """Close the SQLite handle.  Safe to call twice."""
        try:
            self.conn.close()
        except Exception:  # pragma: no cover - closing twice, or already gone
            logger.debug("connections.db was already closed", exc_info=True)

    def __enter__(self) -> ConnectionStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- validation ------------------------------------------------------

    def _validate(self, profile: Mapping[str, Any]) -> dict[str, Any]:
        """Normalise and check a profile, returning the exact column values to store.

        Raises ``ValueError`` with a sentence the Connections page can show; the
        DDL's CHECK constraints then say the same thing again in SQLite, for a
        file that was written by something other than this method.
        """
        if not isinstance(profile, Mapping):
            raise ValueError(f"profile must be a mapping, got {type(profile).__name__}")

        smuggled = sorted(k for k in profile if str(k).strip().lower() in _FORBIDDEN_PROFILE_KEYS)
        if smuggled:
            raise ValueError(
                f"a connection profile must not carry {', '.join(smuggled)}: "
                "connections.db never stores a secret. Pass the password to "
                "CredentialStore.set_password() instead."
            )

        known = set(_PROFILE_COLUMNS) | {"id", "options"} | set(_AUDIT_COLUMNS)
        unknown = sorted(set(map(str, profile)) - known)
        if unknown:
            raise ValueError(
                f"unknown profile field(s): {', '.join(unknown)}. "
                f"Engine-specific settings belong in options."
            )

        display_name = str(profile.get("display_name") or "").strip()
        if not display_name:
            raise ValueError("display_name is required and cannot be blank.")

        engine = canonical_engine(profile.get("engine") or "")
        driver_value = profile.get("driver")
        if not driver_value:
            raise ValueError(
                f"driver is required for engine {engine!r}; "
                f"expected one of {', '.join(DRIVERS_BY_ENGINE[engine])}"
            )
        driver = canonical_driver(engine, str(driver_value))

        database = str(profile.get("database") or "").strip()
        if not database:
            label = "the database file path" if engine == FILE_ENGINE else "the database name"
            raise ValueError(f"database is required: give {label}.")
        if engine == FILE_ENGINE:
            # Stored resolved and expanduser-ed (§3.4) so two profiles cannot
            # disagree about which file they mean, and so the MCP server started
            # from a different working directory opens the same file.
            database = str(Path(database).expanduser().resolve())

        host = profile.get("host")
        port = profile.get("port")
        username = profile.get("username")
        instance = profile.get("instance")
        auth_mode = profile.get("auth_mode")

        if engine == FILE_ENGINE:
            # The tagged union: for SQLite these four are structurally absent,
            # not merely unknown, so a blank string is normalised to NULL and a
            # real value is an error rather than something we quietly discard.
            for field, value in (
                ("host", host),
                ("port", port),
                ("username", username),
                ("instance", instance),
            ):
                if value not in (None, "", 0):
                    raise ValueError(
                        f"{field} does not apply to a SQLite connection; leave it empty."
                    )
            if auth_mode not in (None, "") and canonical_auth_mode(auth_mode) != "none":
                raise ValueError(
                    "a SQLite database is a file: access is controlled by the file's own "
                    "permissions, so a SQLite connection authenticates with 'none' and "
                    "takes no user name and no password."
                )
            host = port = username = instance = None
            auth_mode = "none"
        else:
            auth_mode = (
                default_auth_mode(engine)
                if auth_mode in (None, "")
                else canonical_auth_mode(auth_mode)
            )
            if auth_mode == "none":
                raise ValueError(
                    f"auth_mode 'none' means there is no authentication step at all, which "
                    f"is true of a SQLite file and of nothing else; a {engine} connection "
                    "uses 'password' or 'integrated'."
                )

            host = str(host or "").strip()
            if not host:
                raise ValueError(f"host is required for a {engine} connection.")

            if instance in (None, ""):
                instance = None
            else:
                if engine != "mssql":
                    raise ValueError(
                        f"instance is a Microsoft SQL Server named instance and does not "
                        f"apply to a {engine} connection; leave it empty."
                    )
                instance = str(instance).strip()
                if not _INSTANCE_RE.match(instance):
                    raise ValueError(
                        f"instance {instance!r} is not a valid SQL Server instance name: "
                        "letters, digits, underscore, $, # and - only, starting with "
                        "anything but a hyphen."
                    )

            if engine == "mssql":
                # A host of 'PC-ARR\SQLEXPRESS:56879' carries three values in one field,
                # which no driver can be given as it stands. It is split into the three
                # columns here, on the same ruling (section 13 D6) under which the version 2
                # migration splits a stored one; only a piece that contradicts a column the
                # user also filled in is refused.
                target = _reconcile_mssql_profile(
                    {"host": host, "instance": instance, "port": port}
                )
                host = target.server
                instance = target.instance
                port = target.port

            username = str(username or "").strip()
            if auth_mode == "password":
                if not username:
                    raise ValueError(f"username is required for a {engine} connection.")
            else:
                # 'integrated' means the operating system supplies the identity, and
                # ODBC ignores UID entirely under Trusted_Connection. A profile that
                # stored a name while connecting as whoever launched the process
                # would display one identity and hand the server another, and the
                # audit trail would inherit the wrong one.  If the value cannot be
                # used, it is not kept — and the mistake is corrected on screen
                # rather than dropped silently.
                if username:
                    raise ValueError(
                        "this profile authenticates through the operating system, so it "
                        "does not take a user name — remove it, or switch Authentication "
                        "to 'User name and password'."
                    )
                username = None
                support = support_for(engine, driver)
                if not support.supported:
                    raise ValueError(message_for(support))

            if port in (None, "") and engine == "mssql" and instance:
                # A named instance is addressable without a port: the SQL Server
                # Browser resolves it, which is the whole reason the instance column
                # exists — a dynamic port moves at every service restart.
                port = None
            else:
                try:
                    port = int(port)  # type: ignore[arg-type]
                except (TypeError, ValueError):
                    hint = (
                        " Give a port, or a named instance for the SQL Server Browser to "
                        "resolve."
                        if engine == "mssql"
                        else ""
                    )
                    raise ValueError(
                        f"port is required for a {engine} connection and must be a whole "
                        f"number between 1 and 65535.{hint}"
                    ) from None
                if not 1 <= port <= 65535:
                    raise ValueError(f"port must be between 1 and 65535, got {port}.")

        options_json = self._normalise_options(profile)

        colour_tag = profile.get("colour_tag")
        if colour_tag in ("", None):
            colour_tag = None
        else:
            colour_tag = str(colour_tag).strip()
            if len(colour_tag) != 7 or not colour_tag.startswith("#") or any(
                c not in "0123456789abcdefABCDEF" for c in colour_tag[1:]
            ):
                raise ValueError(
                    f"colour_tag must be '#RRGGBB', got {colour_tag!r}."
                )

        timeout = profile.get("statement_timeout_s", DEFAULT_STATEMENT_TIMEOUT_S)
        if timeout in ("", None):
            timeout = DEFAULT_STATEMENT_TIMEOUT_S
        try:
            timeout = int(timeout)
        except (TypeError, ValueError):
            raise ValueError(
                f"statement_timeout_s must be a whole number of seconds, got {timeout!r}."
            ) from None
        if not 1 <= timeout <= MAX_STATEMENT_TIMEOUT_S:
            raise ValueError(
                f"statement_timeout_s must be between 1 and {MAX_STATEMENT_TIMEOUT_S} seconds, "
                f"got {timeout}."
            )

        return {
            "display_name": display_name,
            "engine": engine,
            "driver": driver,
            "host": host,
            "port": port,
            "instance": instance,
            "database": database,
            "username": username,
            "auth_mode": auth_mode,
            "options_json": options_json,
            "colour_tag": colour_tag,
            "statement_timeout_s": timeout,
        }

    @staticmethod
    def _normalise_options(profile: Mapping[str, Any]) -> str:
        """Accept ``options`` (a mapping) or ``options_json`` (text) and return text.

        Per-dialect allow-listing of the keys (§3.4) belongs to the dialect and
        happens at connect time; what is enforced here is the structural
        invariant the CHECK also enforces — valid JSON, and an object rather than
        a list or a scalar — plus the no-secrets rule.
        """
        if "options" in profile and "options_json" in profile:
            # Silent precedence between the two spellings is how a caller ends up
            # persisting settings it never intended; make it say which it meant.
            raise ValueError(
                "give either options (a mapping) or options_json (text), not both."
            )
        if "options" in profile and profile["options"] not in (None, ""):
            options = profile["options"]
            if not isinstance(options, Mapping):
                raise ValueError(
                    f"options must be a mapping, got {type(options).__name__}."
                )
            parsed: dict[str, Any] = dict(options)
        elif profile.get("options_json"):
            try:
                parsed = json.loads(str(profile["options_json"]))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"options_json is not valid JSON: {exc}") from None
            if not isinstance(parsed, dict):
                raise ValueError("options_json must be a JSON object, not a list or a scalar.")
        else:
            parsed = {}

        smuggled = sorted(k for k in parsed if str(k).strip().lower() in _FORBIDDEN_PROFILE_KEYS)
        if smuggled:
            raise ValueError(
                f"options must not carry {', '.join(smuggled)}: connections.db never "
                "stores a secret. Pass the password to CredentialStore.set_password()."
            )
        # sort_keys so an unchanged profile produces an identical string and the
        # updated_* pair does not move for a no-op save.
        return json.dumps(parsed, sort_keys=True, separators=(",", ":"))

    # -- reads -----------------------------------------------------------

    @staticmethod
    def _to_dict(row: sqlite3.Row) -> dict[str, Any]:
        profile = dict(row)
        try:
            profile["options"] = json.loads(profile.get("options_json") or "{}")
        except ValueError:  # a hand-edited file; the CHECK should have stopped it
            logger.warning(
                "connection %s has unreadable options_json; treating it as empty",
                profile.get("id"),
            )
            profile["options"] = {}
        return profile

    def get(self, connection_id: int) -> dict[str, Any] | None:
        """One profile by id, or ``None``.  Never contains a password."""
        row = self.conn.execute(
            "SELECT * FROM connections WHERE id = ?", (int(connection_id),)
        ).fetchone()
        return self._to_dict(row) if row else None

    def get_by_name(self, display_name: str) -> dict[str, Any] | None:
        """One profile by display name, case-insensitively — the column is NOCASE.

        The MCP layer resolves its ``connection`` enum through this.
        """
        row = self.conn.execute(
            "SELECT * FROM connections WHERE display_name = ?", (str(display_name),)
        ).fetchone()
        return self._to_dict(row) if row else None

    def all(self) -> list[dict[str, Any]]:
        """Every profile, ordered as the Connections page lists them."""
        rows = self.conn.execute(
            "SELECT * FROM connections ORDER BY engine, display_name COLLATE NOCASE"
        ).fetchall()
        return [self._to_dict(r) for r in rows]

    def all_ids(self) -> list[int]:
        """Every id, for ``PermissionStore.reconcile()`` (§7.2 step 3)."""
        return [int(r[0]) for r in self.conn.execute("SELECT id FROM connections ORDER BY id")]

    @staticmethod
    def needs_review(profile: Mapping[str, Any]) -> str | None:
        """A sentence when a stored profile still carries an address nobody can act on.

        The Connections page shows an amber marker on the row and this sentence as
        its tooltip.  It is computed rather than stored, so a profile repaired by
        hand — or by the version 2 migration's automatic split — stops being flagged
        the moment it is correct, with no second piece of state to keep in step.

        Returns ``None`` when there is nothing to say, which is the normal case.
        """
        if str(profile.get("engine") or "").strip().lower() != "mssql":
            return None
        host = str(profile.get("host") or "").strip()
        if not host:
            return None
        try:
            target = _parse_mssql_target(host)
        except ValueError as exc:
            return (
                f"The host {host!r} cannot be read as a server address ({exc}). Open the "
                "profile and set Host, Instance and Port separately."
            )
        except ImportError:  # pragma: no cover - the leaf module is part of the package
            return None
        if not target.compound:
            return None
        pieces = [f"Host to {target.server!r}"]
        if target.instance:
            pieces.append(f"Instance to {target.instance!r}")
        if target.port:
            pieces.append(f"Port to {target.port}")
        return (
            f"The host {host!r} carries a server, an instance and/or a port in one field, "
            f"which no driver can be given as it stands. Set " + ", ".join(pieces) + "."
        )

    def data_version(self) -> int:
        """SQLite's ``data_version``, which changes when another process commits.

        The MCP server polls this to notice that the GUI added or removed a
        connection, and refreshes its tool enum (DESIGN-MCP-TOOLS.md §2.6).
        """
        return int(self.conn.execute("PRAGMA data_version").fetchone()[0])

    # -- writes ----------------------------------------------------------

    def add(self, profile: Mapping[str, Any]) -> int:
        """Insert a profile and return its new id.

        The id is the credential account name, so the caller stores the password
        only after this returns.
        """
        values = self._validate(profile)
        now = _now()
        columns = ", ".join(_PROFILE_COLUMNS) + ", created_at, user_created, updated_at, user_updated"
        placeholders = ", ".join("?" for _ in _PROFILE_COLUMNS) + ", ?, ?, ?, ?"
        params = [values[c] for c in _PROFILE_COLUMNS] + [now, self.user, now, self.user]
        try:
            cursor = self.conn.execute(
                f"INSERT INTO connections ({columns}) VALUES ({placeholders})", params
            )
        except sqlite3.IntegrityError as exc:
            raise self._friendly_integrity_error(exc, values) from None
        self.conn.commit()
        connection_id = int(cursor.lastrowid or 0)
        logger.info(
            "Added connection %s (%s/%s) as id %s",
            values["display_name"], values["engine"], values["driver"], connection_id,
        )
        return connection_id

    def update(self, connection_id: int, profile: Mapping[str, Any]) -> None:
        """Replace every editable field of an existing profile.

        ``created_at``/``user_created`` are preserved and only the ``updated_*``
        pair moves — f-MCP's upsert discipline.

        A profile that stops authenticating with a password has its keyring entry
        deleted here (§5.1).  An orphaned credential is not a leak in itself — it
        sits in the same OS keyring it always did — but it is a credential nothing
        can now address, kept alive by an application that has stopped needing it,
        and removing it is the discipline :meth:`delete` already applies.
        """
        connection_id = int(connection_id)
        existing = self.get(connection_id)
        if existing is None:
            raise KeyError(f"no connection with id {connection_id}")
        values = self._validate(profile)
        assignments = ", ".join(f"{c} = ?" for c in _PROFILE_COLUMNS)
        params = [values[c] for c in _PROFILE_COLUMNS] + [_now(), self.user, connection_id]
        try:
            self.conn.execute(
                f"UPDATE connections SET {assignments}, updated_at = ?, user_updated = ? "
                "WHERE id = ?",
                params,
            )
        except sqlite3.IntegrityError as exc:
            raise self._friendly_integrity_error(exc, values) from None
        self.conn.commit()
        logger.info("Updated connection %s (%s)", connection_id, values["display_name"])

        was = str(existing.get("auth_mode") or "password")
        now = values["auth_mode"]
        if was == "password" and now != "password":
            # Never with any part of the value, and never conditional on the purge
            # succeeding: a locked vault must not be able to veto a change of
            # authentication mode, and engine.connect() refuses to use a password
            # for a non-'password' profile in any case, so a survivor is inert.
            logger.info(
                "Removed the stored password for connection %s: it no longer "
                "authenticates with one.",
                connection_id,
            )
            self._purge_secret(connection_id)

    def upsert(self, profile: Mapping[str, Any]) -> int:
        """Insert by ``display_name``, or update the row that already holds it.

        Returns the id either way.  Used by the CLI, where there is no row id to
        hand: the name is the natural key the operator typed.
        """
        values = self._validate(profile)
        existing = self.get_by_name(values["display_name"])
        if existing is None:
            return self.add(profile)
        self.update(int(existing["id"]), profile)
        return int(existing["id"])

    def delete(self, connection_id: int) -> bool:
        """Remove a profile, its secret and its permission rules, in that order.

        SQLite cannot enforce a foreign key across separate database files
        (DESIGN-DATA-MODEL.md §7.1), so the referential integrity between
        ``connections.db``, the credential vault and ``permissions.db`` is this
        method's job.  §7.2 fixes the order, and it is chosen so that every
        interruption leaves a fail-closed state:

        1. the secret goes first — it is the only step needing data the later
           steps destroy, and a stranded secret is the one residue with a
           security cost;
        2. then the rules, so a surviving profile authorises nothing;
        3. then the profile itself.

        ``audit.db`` is deliberately untouched (§5.3): the history of a deleted
        connection is exactly what an audit trail is for.

        Returns ``False`` if there was no such connection.
        """
        connection_id = int(connection_id)
        if self.get(connection_id) is None:
            return False

        self._purge_secret(connection_id)
        self._revoke_rules(connection_id)

        self.conn.execute("DELETE FROM connections WHERE id = ?", (connection_id,))
        self.conn.commit()
        logger.info("Deleted connection %s", connection_id)
        return True

    def _purge_secret(self, connection_id: int) -> None:
        """Step 1 of the §7.2 cascade."""
        store = self._credentials
        if store is None:
            # Import late and only here: the GUI passes its own instance, and a
            # ConnectionStore used purely for listing must not construct a
            # credential backend (which may prompt for a master password).
            try:
                from sape_d_mcp.db.credential_store import CredentialStore

                store = CredentialStore()
            except Exception:
                logger.error(
                    "Could not open the credential store while deleting connection %s; "
                    "its stored password may survive as an orphan. It can never be "
                    "handed to another connection, because ids are never recycled.",
                    connection_id,
                    exc_info=True,
                )
                return
        try:
            store.delete_password(connection_id)
        except Exception:
            # Deliberately not fatal.  Blocking profile deletion on a broken
            # keyring would leave the user unable to remove a connection at all,
            # and AUTOINCREMENT guarantees the orphaned account name "conn:<id>"
            # can never be reused by a different connection (§3.2).
            logger.error(
                "Could not delete the stored password for connection %s; it survives "
                "as an unreachable orphan. Remove it from the OS credential store by "
                "hand if that matters to you.",
                connection_id,
                exc_info=True,
            )

    def _revoke_rules(self, connection_id: int) -> None:
        """Step 2 of the §7.2 cascade — delegated to the permission store.

        §7.2 assigns the deletion of the rules to
        ``PermissionStore.revoke_connection()``, so that is what is called; this
        module never opens ``permissions.db`` itself.  Where the permission store
        does not exist yet (it arrives in stage 5), the omission is logged at
        WARNING and repaired by ``PermissionStore.reconcile()`` at the next
        start-up, which §7.2 step 3 provides for exactly this case.  It is not a
        security hole in the meantime: the resolver never consults
        ``connections.db``, and no caller can produce an orphan id, because
        producing one means opening a profile that no longer exists (§7.2 step 4).
        """
        store = self._permissions
        if store is None:
            try:
                from sape_d_mcp.permissions import PermissionStore  # type: ignore[attr-defined]

                store = PermissionStore()
            except Exception:
                logger.warning(
                    "Permission store unavailable while deleting connection %s; its rules "
                    "were not swept and will be removed by the start-up reconciliation.",
                    connection_id,
                )
                return
        try:
            removed = store.revoke_connection(connection_id)
        except Exception:
            logger.warning(
                "Could not revoke the rules of connection %s; the start-up reconciliation "
                "will remove them.",
                connection_id,
                exc_info=True,
            )
            return
        if removed:
            logger.info("Revoked %s rule(s) belonging to connection %s", removed, connection_id)

    # -- errors ----------------------------------------------------------

    @staticmethod
    def _friendly_integrity_error(
        exc: sqlite3.IntegrityError, values: Mapping[str, Any]
    ) -> ValueError:
        """Turn a SQLite constraint name into a sentence the Connections page shows."""
        text = str(exc)
        if "display_name" in text or "UNIQUE" in text.upper():
            return ValueError(
                f"a connection called {values['display_name']!r} already exists; "
                "names are compared case-insensitively."
            )
        for constraint, message in (
            (
                "ck_connections_shape",
                (
                    "host and either a port or a named instance apply to every engine "
                    "except SQLite; a user name belongs to a 'password' profile and to no "
                    "other."
                ),
            ),
            (
                "ck_connections_auth_mode",
                f"auth_mode must be one of {', '.join(AUTH_MODES)}.",
            ),
            (
                "ck_connections_instance",
                (
                    "instance is a Microsoft SQL Server named instance and belongs to no "
                    "other engine."
                ),
            ),
            ("ck_connections_engine_driver", "that driver cannot be used with that engine."),
            ("ck_connections_port", "port must be between 1 and 65535."),
            ("ck_connections_options", "options must be a valid JSON object."),
            ("ck_connections_colour", "colour_tag must be '#RRGGBB'."),
            ("ck_connections_timeout", f"statement_timeout_s must be between 1 and {MAX_STATEMENT_TIMEOUT_S}."),
        ):
            if constraint in text:
                return ValueError(message)
        return ValueError(f"the connection profile was rejected by the database: {text}")


def known_drivers() -> Iterable[tuple[str, str]]:
    """Every legal ``(engine, driver)`` pair, for the GUI's combo boxes and the tests."""
    for engine in ENGINES:
        for driver in DRIVERS_BY_ENGINE[engine]:
            yield engine, driver
