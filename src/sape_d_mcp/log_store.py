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

"""SQLite-backed audit store over ``audit.db`` — one row per MCP tool call.

``tool_calls`` is the durable half of the dual-logging pair DESIGN-DATA-MODEL.md §5
mandates; :mod:`sape_d_mcp.tool_logger` supplies the other half, an append-only JSONL
file beside this database that keeps working when the server is spawned as a
subprocess and nothing else about the process survives.

Ported from f-MCP's ``log_store.py``, with three differences that matter:

* a ``connection_id`` column (nullable — ``NULL`` for tools that touch no connection,
  DESIGN-DATA-MODEL.md §5.2) so the Logs page can filter one ``QTabWidget`` tab per
  connection over a single table instead of opening N files;
* a ``decision`` column with a closed domain (``allowed`` / ``denied`` / ``refused`` /
  ``error``) rather than f-MCP's bare result-or-error pair, because "the rules say no"
  and "a human declined the confirmation dialog" are different findings and the
  security review needs to tell them apart (DESIGN-DATA-MODEL.md §5.2);
* rotation also runs every 1 000 inserts, tracked by a process-local counter, and not
  only at start-up as f-MCP does — f-MCP's start-up-only trim lets a long-running
  server grow without bound between restarts (DESIGN-DATA-MODEL.md §5.5).

Default-deny lives in ``permissions.py``; this module has no such policy of its own —
an audit row records a decision, it never makes one. A logging failure must never
propagate into a tool result, so every write and read is wrapped in a bare
``try/except sqlite3.Error`` and degrades to a logged warning, never a raised
exception — the same contract as f-MCP's ``LogStore``, extended to also cover the
``CHECK`` constraints below (f-MCP's schema had none to violate).
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any

from sape_d_mcp.db_location import resolve_db_directory

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Domains — the single source of truth
# ---------------------------------------------------------------------------
# DESIGN-DATA-MODEL.md §5.2's ck_tool_calls_decision, restated here so the CHECK
# text, the docstring table and _validate_decision() can never drift apart.
DECISIONS: tuple[str, ...] = ("allowed", "denied", "refused", "error")

SCHEMA_VERSION = 1

# Columns after `id`, in DDL order. Drives the INSERT column list, the ALTER TABLE
# migration below and a parametrised round-trip test — the same discipline
# connection_store.py applies to _PROFILE_COLUMNS, kept separate from permissions.py's
# ACTIONS_BY_TYPE pattern because audit.db's columns are not per-object-type: there is
# exactly one shape for every tool call, defined once in DESIGN-DATA-MODEL.md §5.2.
_TOOL_CALL_COLUMNS: tuple[str, ...] = (
    "connection_id",
    "session_id",
    "timestamp",
    "tool_name",
    "params_json",
    "rows_affected",
    "duration_ms",
    "result",
    "error",
    "decision",
    "matched_rule_id",
)

# The subset PRAGMA table_info() can repair with a plain ADD COLUMN: nullable, with
# no UNIQUE and no cross-column CHECK. session_id/timestamp/tool_name/params_json/
# decision are NOT NULL in the original CREATE TABLE and are never missing from a
# file this module created; they are excluded here for the same reason
# connection_store.py excludes display_name from _MIGRATABLE_COLUMNS — an ALTER TABLE
# ADD COLUMN cannot add a NOT NULL column with no DEFAULT to a table that already
# holds rows, and a stale audit.db predates connection_id, matched_rule_id and the
# other three nullable additions this dict exists to catch up.
_MIGRATABLE_COLUMNS: dict[str, str] = {
    "connection_id": "INTEGER",
    "rows_affected": "INTEGER",
    "duration_ms": "INTEGER",
    "result": "TEXT",
    "error": "TEXT",
    "matched_rule_id": "INTEGER",
}

# DESIGN-DATA-MODEL.md §5.2, verbatim but for the PRAGMAs (applied in Python, before
# this script runs, so a hand-copied or restored file behaves the same way a freshly
# created one does — see _apply_pragmas()).
SCHEMA = """
-- audit.db
--
-- One row per MCP tool call, whether it succeeded, failed or was denied. The
-- Logs page renders one QTabWidget tab per connection over this single table,
-- filtered on connection_id.
--
-- This is the durable half of the dual-logging pair; the other is the
-- append-only JSONL sink beside it, which survives being spawned as a Claude
-- Desktop subprocess. A logging failure NEVER propagates into a tool result.

CREATE TABLE IF NOT EXISTS tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id   INTEGER,            -- logical FK -> connections.db connections(id).
                                        -- NULL for tools that touch no connection
                                        -- (list_connections, server status): those
                                        -- render under the Logs page's "System" tab.
    session_id      TEXT    NOT NULL,   -- 'cli' is the well-known id for an externally
                                        -- spawned server, as in f-MCP
    timestamp       TEXT    NOT NULL,   -- ISO 8601 with offset
    tool_name       TEXT    NOT NULL,
    params_json     TEXT    NOT NULL,   -- sanitised, size-capped; see §5.4
    rows_affected   INTEGER,            -- NULL where the verb has no row count
    duration_ms     INTEGER,            -- NULL if the call never started
    result          TEXT,               -- truncated at 1000 chars, as f-MCP
    error           TEXT,               -- truncated at 1000 chars
    decision        TEXT    NOT NULL,
    matched_rule_id INTEGER,            -- logical FK -> permissions.db rules(id); the rule
                                        -- CITED in the outcome. NULL on default-deny and on
                                        -- a multi-object allow, where no single rule decides.

    CONSTRAINT ck_tool_calls_decision CHECK (
        decision IN ('allowed', 'denied', 'refused', 'error')
    ),
    CONSTRAINT ck_tool_calls_params CHECK (json_valid(params_json)),
    CONSTRAINT ck_tool_calls_rows   CHECK (rows_affected IS NULL OR rows_affected >= 0),
    CONSTRAINT ck_tool_calls_ms     CHECK (duration_ms   IS NULL OR duration_ms   >= 0)
);

-- The Logs page's only query shape: one connection's tail, newest first.
CREATE INDEX IF NOT EXISTS idx_tool_calls_conn_ts ON tool_calls(connection_id, timestamp);

-- Clearing one session's rows, as f-MCP's clear_session does.
CREATE INDEX IF NOT EXISTS idx_tool_calls_session ON tool_calls(session_id);

-- The Logs page's "denied only" filter, and the security review's first query.
CREATE INDEX IF NOT EXISTS idx_tool_calls_decision ON tool_calls(decision, timestamp);
"""

# Rotation thresholds (DESIGN-DATA-MODEL.md §5.5). Not module-private constants named
# with a leading underscore: a future CLI "how close to rotation are we" diagnostic
# reads them, same as f-MCP's equivalents were treated as part of the public shape.
ROTATE_ABOVE_ROWS = 10_000
ROTATE_DELETE_ROWS = 1_000
# Checked at start-up (cheap, once) and then only every this many inserts, so the
# common path never pays for a COUNT(*) on every single tool call.
ROTATE_CHECK_EVERY = 1_000

# ---------------------------------------------------------------------------
# Parameter sanitisation
# ---------------------------------------------------------------------------
# f-MCP's fields were filesystem-shaped (path, target, mode, recursive); d-MCP's are
# database-shaped. Kept as a tuple, not scattered literals, so a reviewer can see the
# whole allow-list in one place.
_IMPORTANT_PARAM_KEYS: frozenset[str] = frozenset(
    {"connection", "schema", "object_type", "name", "table", "action", "tool_name"}
)

# DESIGN-DATA-MODEL.md §5.4's three reserved params_json keys. Underscore-prefixed so
# they cannot collide with a tool's own argument names; always kept whole rather than
# subjected to the important-keys trimming below, because they ARE the audit record
# (which connection, which objects, which statement) rather than incidental context
# that can be dropped under size pressure.
_RESERVED_PARAM_KEYS: tuple[str, ...] = ("_connection", "_objects", "_sql")

# §5.4: "_sql carries placeholders; bound parameter values are not logged at all." The
# statement text itself can still be long (a generated multi-join view definition), so
# it gets its own, more generous cap rather than sharing the 500-char budget below.
_SQL_MAX_CHARS = 2000

# Key markers that mean "never let the value reach the log", checked as a
# case-and-separator-insensitive substring so 'DB_PASSWORD', 'pwd', 'auth-token' and
# 'connectionString' are all caught by one entry each. This is deliberately broader
# than an exact-match set: a credential is security-relevant here (DATA-PROTECTION.md
# — "the audit log may therefore contain personal data"), and a false-positive
# redaction of an innocuous field is a cosmetic cost, whereas a false negative is a
# leaked secret. Matches connection_store.py's _FORBIDDEN_PROFILE_KEYS in spirit, but
# is not the same set: that module rejects a profile write outright, this one merely
# must never let a value that slipped past that check reach a log line.
_CREDENTIAL_KEY_MARKERS: tuple[str, ...] = (
    "password",
    "pwd",
    "secret",
    "token",
    "dsn",
    "connection_string",
)

_REDACTED = "***REDACTED***"


def _looks_like_credential_key(key: Any) -> bool:
    """True if ``key`` names something that must never be logged verbatim."""
    normalised = str(key).strip().lower().replace("-", "_").replace(" ", "_")
    return any(marker in normalised for marker in _CREDENTIAL_KEY_MARKERS)


def _scrub_credentials(value: Any) -> Any:
    """Recursively replace credential-shaped values with a redaction marker.

    Walks nested dicts and lists — not just the top level — because a tool's own
    ``options`` argument can carry an engine-specific dict (DESIGN-DATA-MODEL.md
    §3.4's ``options_json`` shape) that itself holds a key like ``sslrootcert`` or a
    driver-specific ``connection_string``. Returns a new structure; the caller's
    ``params`` dict is never mutated, because the same dict may still be in use by
    the tool that is being logged.
    """
    if isinstance(value, dict):
        return {
            k: (_REDACTED if _looks_like_credential_key(k) else _scrub_credentials(v))
            for k, v in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_scrub_credentials(v) for v in value]
    return value


def _sanitize_body(params: dict[str, Any], max_chars: int) -> dict[str, Any]:
    """f-MCP's ``_sanitize_params``, ported verbatim bar the renamed important keys.

    If the serialised JSON is too large, keeps only the important fields to prevent
    huge log entries — the bug this guards against is a single verbose tool call (a
    large ``IN (...)`` list, a wide row echoed back in an error) blowing out a log
    line that a human or the Logs page then has to scroll past.
    """
    try:
        test_json = json.dumps(params, default=str)
    except (TypeError, ValueError):
        return {"_error": "unable to serialise params"}

    if len(test_json) <= max_chars:
        return params

    result = {k: v for k, v in params.items() if k in _IMPORTANT_PARAM_KEYS}

    for k, v in params.items():
        if k not in _IMPORTANT_PARAM_KEYS:
            try:
                v_json = json.dumps(v, default=str)
                if len(v_json) < 50:  # only keep small non-important fields
                    result[k] = v
            except (TypeError, ValueError):
                pass

    try:
        still_too_large = len(json.dumps(result, default=str)) > max_chars
    except (TypeError, ValueError):
        still_too_large = True
    if still_too_large:
        result = {
            "action": params.get("action", "?"),
            "_truncated": True,
        }

    return result


def _sanitize_params(params: dict[str, Any] | None, max_chars: int = 500) -> dict[str, Any]:
    """Scrub credentials, then apply f-MCP's size-capped important-keys trimming.

    Order matters: credentials are scrubbed *before* the size check, so a password
    that happens to be short enough to survive the 500-char budget is still never
    written — the size cap is about log hygiene, not security, and must not be the
    only thing standing between a secret and the log file.

    The three DESIGN-DATA-MODEL.md §5.4 reserved keys (``_connection``, ``_objects``,
    ``_sql``) are pulled out first and always kept whole (bar ``_sql``'s own 2000-char
    cap), so they cannot be discarded by the important-keys trim applied to the rest.
    """
    if not isinstance(params, dict):
        return {"_error": "params was not a dict"}

    scrubbed = _scrub_credentials(params)

    reserved = {k: scrubbed.pop(k) for k in list(scrubbed) if k in _RESERVED_PARAM_KEYS}
    sql = reserved.get("_sql")
    if isinstance(sql, str) and len(sql) > _SQL_MAX_CHARS:
        reserved["_sql"] = sql[:_SQL_MAX_CHARS] + "... (truncated)"

    body = _sanitize_body(scrubbed, max_chars)
    body.update(reserved)
    return body


def _now() -> str:
    """ISO 8601 with the local offset, seconds precision — f-MCP's audit format."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def default_db_path() -> Path:
    """Resolve ``audit.db`` from the environment, else the current working directory.

    Precedence: ``DMCP_AUDIT_DB`` (this file, exactly), then ``DMCP_DB_DIR`` (all
    three files, one directory), then whatever :func:`resolve_db_directory` falls
    back to — see that module for why the fallback is the *current working
    directory* rather than a hard-coded ``.parent`` count off ``__file__``.

    Unlike ``permissions.db``'s fail-closed fallback, a wrongly-located
    ``audit.db`` has no safety valve of its own: it is simply a second, disjoint
    audit trail, indistinguishable from a complete one to anyone who opens it,
    which is worse for forensics than no file at all — a missing file at least
    announces itself. That is the real cost of choosing the current working
    directory over a fixed location, and it falls on this store specifically.

    Overridable so the test suite can point at a ``tmp_path`` without touching the
    developer's real databases (DESIGN-DATA-MODEL.md §1).
    """
    explicit = os.environ.get("DMCP_AUDIT_DB")
    if explicit:
        return Path(explicit).expanduser()
    return resolve_db_directory() / "audit.db"


class LogStore:
    """WAL SQLite store over ``audit.db``, keyed by ``session_id`` and ``connection_id``.

    ``"cli"`` is the well-known ``session_id`` for a server spawned headless by an MCP
    client (a Claude Desktop subprocess, say), exactly as in f-MCP, so the GUI can
    show those calls alongside its own interactive sessions rather than inventing a
    fresh UUID no human ever typed.

    Every public method that touches the database is wrapped in
    ``try/except sqlite3.Error`` and degrades to a logged warning rather than raising:
    a logging failure must never break the caller, whether the cause is a locked
    file, a read-only filesystem, or a row that would violate one of the ``CHECK``
    constraints above (a malformed ``decision``, say — a programmer error, but still
    not one that should crash a tool call that otherwise succeeded).
    """

    def __init__(self, db_path: str | os.PathLike[str] | None = None) -> None:
        self.db_path = Path(db_path).expanduser() if db_path is not None else default_db_path()

        # Nothing is created at import time; the file appears here, on the first
        # construction of a store (DESIGN-DATA-MODEL.md §8).
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

        # Serialises writes within this process; WAL plus check_same_thread=False
        # handles cross-process concurrency (the GUI and the MCP server), but two
        # threads in the same process racing an INSERT and a rotation DELETE is still
        # our own problem to solve.
        self._write_lock = threading.Lock()
        self._writes_since_rotation_check = 0

        self.conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._apply_pragmas()

        # Read the version *before* the schema runs: after executescript a fresh
        # file is indistinguishable from a current one.
        existing_version = int(self.conn.execute("PRAGMA user_version").fetchone()[0])
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate(existing_version)
        self._migrate_schema()

        # Start-up trim, per DESIGN-DATA-MODEL.md §5.5 — f-MCP only trims here, which
        # lets a long-running server grow unbounded between restarts; log_tool() below
        # also re-checks every ROTATE_CHECK_EVERY inserts to close that gap.
        self.trim_if_needed()

    # -- lifecycle -----------------------------------------------------------

    def _apply_pragmas(self) -> None:
        """DESIGN-DATA-MODEL.md §6, applied on every open and before the first CREATE."""
        self.conn.execute("PRAGMA busy_timeout = 5000")
        mode = self.conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            # Some network mounts have no shared-memory locking and silently fall
            # back to 'delete', which would quietly break the GUI/server
            # cross-process design rather than fail (DESIGN-DATA-MODEL.md §6).
            raise RuntimeError(
                f"Cannot enable WAL journalling on {self.db_path}: SQLite reported "
                f"journal_mode={mode!r}. The d-MCP GUI and MCP server read this file "
                "concurrently and need WAL. Move the databases off the network share, "
                "or set DMCP_DB_DIR to a local directory."
            )
        # NORMAL, not FULL: audit.db can lose its most recent transactions on a power
        # failure without corrupting the file, and the lost tail is a handful of log
        # rows the JSONL sink holds anyway. Unlike permissions.db, there is no
        # asymmetric fail-open risk here — a lost audit row is just a lost audit row
        # (DESIGN-DATA-MODEL.md §6).
        self.conn.execute("PRAGMA synchronous = NORMAL")
        self.conn.execute("PRAGMA foreign_keys = ON")

    def _migrate(self, existing_version: int) -> None:
        """The ``user_version`` hook: bump a fresh file, refuse a newer one."""
        if existing_version > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.db_path} was written by a newer version of SAPÉ d-MCP "
                f"(schema {existing_version}, this build understands {SCHEMA_VERSION}). "
                "Upgrade the application rather than letting an older build mis-read it."
            )
        if existing_version < SCHEMA_VERSION:
            # No structural migration exists yet — version 1 is the first shipped
            # schema. When version 2 arrives, the chain goes here, one step per
            # version, each idempotent, each committed before the next.
            self.conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.conn.commit()

    def _migrate_schema(self) -> None:
        """Add any column in ``_MIGRATABLE_COLUMNS`` that an older ``audit.db`` lacks.

        ``PRAGMA table_info`` diffed against the tuple, the same discipline
        ``permissions.py`` and ``connection_store.py`` apply to their own column
        sets. There is no shipped schema older than this one yet, so today this is a
        no-op on every real file; it exists so the *next* additive column is a data
        edit here rather than a hand-written ``ALTER TABLE`` someone has to remember
        to run against every operator's existing ``audit.db``.
        """
        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(tool_calls)")}
        missing = sorted(name for name in _MIGRATABLE_COLUMNS if name not in existing)
        for column in missing:
            sql_type = _MIGRATABLE_COLUMNS[column]
            try:
                self.conn.execute(f"ALTER TABLE tool_calls ADD COLUMN {column} {sql_type}")
                self.conn.commit()
            except sqlite3.OperationalError as exc:
                # See permissions.py's identical check: SQLite's own wording has no
                # hyphen ("attempt to write a readonly database"), so a literal
                # "read-only" search would silently miss it.
                if "readonly" in str(exc).lower().replace("-", ""):
                    raise RuntimeError(
                        f"Cannot migrate {self.db_path}: the database is read-only. "
                        "Check the file permissions."
                    ) from exc
                raise
            logger.info("Added missing column %s to tool_calls", column)

    def close(self) -> None:
        """Close the SQLite handle. Safe to call twice."""
        try:
            self.conn.close()
        except Exception:  # pragma: no cover - closing twice, or already gone
            logger.debug("audit.db was already closed", exc_info=True)

    def __enter__(self) -> LogStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- writes ----------------------------------------------------------------

    def log_tool(
        self,
        connection_id: int | None,
        session_id: str,
        tool_name: str,
        params: dict[str, Any],
        *,
        result: str | None = None,
        error: str | None = None,
        decision: str,
        rows_affected: int | None = None,
        duration_ms: int | None = None,
        matched_rule_id: int | None = None,
    ) -> None:
        """Record one tool call. Never raises — see the class docstring.

        Args:
            connection_id: The connection the call was made against, or ``None`` for
                a tool that touches no connection (DESIGN-DATA-MODEL.md §5.2).
            session_id: ``"cli"`` for a headless subprocess server, else the GUI
                session's own id.
            tool_name: The MCP tool name.
            params: The tool's own arguments, sanitised and size-capped by
                ``_sanitize_params`` before being written — see that function and
                DESIGN-DATA-MODEL.md §5.4 for the reserved ``_connection``,
                ``_objects`` and ``_sql`` keys.
            result: Free-text outcome, truncated at 1000 characters like f-MCP.
            error: Free-text failure detail, truncated at 1000 characters.
            decision: One of ``allowed``, ``denied``, ``refused``, ``error``
                (DESIGN-DATA-MODEL.md §5.2) — required, not inferred, because the
                caller is the only one who knows whether a denial came from a
                permission rule or from a declined confirmation dialog.
            rows_affected: Row count, or ``None`` where the verb has none.
            duration_ms: Wall-clock duration, or ``None`` if the call never started.
            matched_rule_id: The single rule that decided the outcome, or ``None`` on
                default-deny or a multi-object allow where no one rule decides.
        """
        if result and len(result) > 1000:
            result = result[:1000] + "... (truncated)"
        if error and len(error) > 1000:
            error = error[:1000] + "... (truncated)"

        sanitised_params = _sanitize_params(params)
        try:
            params_json = json.dumps(sanitised_params, default=str)
        except (TypeError, ValueError):
            params_json = json.dumps({"_error": "unable to serialise params"})

        row = (
            connection_id,
            session_id,
            _now(),
            tool_name,
            params_json,
            rows_affected,
            duration_ms,
            result,
            error,
            decision,
            matched_rule_id,
        )

        with self._write_lock:
            try:
                self.conn.execute(
                    f"""
                    INSERT INTO tool_calls ({', '.join(_TOOL_CALL_COLUMNS)})
                    VALUES ({', '.join('?' for _ in _TOOL_CALL_COLUMNS)})
                    """,
                    row,
                )
                self.conn.commit()
            except sqlite3.Error as exc:
                # Covers a locked/read-only file (OperationalError) as much as a
                # malformed decision tripping ck_tool_calls_decision
                # (IntegrityError) — both must degrade to the JSONL sink, never to a
                # raised exception reaching the tool caller.
                logger.warning("Failed to insert audit row into %s: %s", self.db_path, exc)
                return

            self._writes_since_rotation_check += 1
            if self._writes_since_rotation_check >= ROTATE_CHECK_EVERY:
                self._writes_since_rotation_check = 0
                self._trim_locked()

    def delete_all(self) -> None:
        """Delete every row. Does not ``VACUUM`` — see :meth:`trim_if_needed`."""
        with self._write_lock:
            try:
                self.conn.execute("DELETE FROM tool_calls")
                self.conn.commit()
            except sqlite3.Error as exc:
                logger.warning("Failed to delete all audit rows in %s: %s", self.db_path, exc)

    def clear_session(self, session_id: str) -> None:
        """Delete only ``session_id``'s rows, leaving other sessions for rotation."""
        with self._write_lock:
            try:
                self.conn.execute("DELETE FROM tool_calls WHERE session_id = ?", (session_id,))
                self.conn.commit()
            except sqlite3.Error as exc:
                logger.warning(
                    "Failed to clear session %s in %s: %s", session_id, self.db_path, exc
                )

    def _trim_locked(self) -> None:
        """The rotation body. Caller must already hold ``_write_lock``."""
        try:
            count = self.conn.execute("SELECT COUNT(*) FROM tool_calls").fetchone()[0]
            if count > ROTATE_ABOVE_ROWS:
                # By id, not by timestamp: id is monotonic and a clock is not
                # (DESIGN-DATA-MODEL.md §5.5). No VACUUM — it takes an exclusive
                # lock and would defeat the cross-process access WAL exists to give.
                self.conn.execute(
                    "DELETE FROM tool_calls WHERE id IN "
                    "(SELECT id FROM tool_calls ORDER BY id LIMIT ?)",
                    (ROTATE_DELETE_ROWS,),
                )
                self.conn.commit()
        except sqlite3.Error as exc:
            logger.warning("Failed to rotate audit rows in %s: %s", self.db_path, exc)

    def trim_if_needed(self) -> None:
        """Delete the oldest 1 000 rows if the table exceeds 10 000.

        Called at start-up (see ``__init__``) and, internally, every
        ``ROTATE_CHECK_EVERY`` inserts, so a long-running server does not grow
        unbounded between restarts the way f-MCP's start-up-only trim does.
        """
        with self._write_lock:
            self._trim_locked()

    # -- reads -------------------------------------------------------------

    def get_logs(
        self,
        session_id: str | None = None,
        connection_id: int | None = None,
        limit: int | None = None,
    ) -> list[dict]:
        """Fetch rows, optionally filtered by session and/or connection.

        Args:
            session_id: Restrict to one session, or ``None`` for every session.
            connection_id: Restrict to one connection (``NULL`` rows are matched by
                passing ``None`` here only combined with no other filter — there is
                deliberately no separate "system tools only" flag, since the Logs
                page can express that as ``connection_id=None`` with no session
                filter and then discard rows whose ``connection_id`` is not
                ``NULL`` client-side, exactly as f-MCP's single-table page does).
            limit: If given, the most recent ``limit`` rows, returned oldest-first —
                the "one connection's tail" shape ``idx_tool_calls_conn_ts`` exists
                for. ``None`` returns every matching row.

        Returns:
            One dict per row, oldest first, or ``[]`` on any database error —
            degraded gracefully rather than raised, like every other method here.
        """
        clauses: list[str] = []
        args: list[Any] = []
        if session_id is not None:
            clauses.append("session_id = ?")
            args.append(session_id)
        if connection_id is not None:
            clauses.append("connection_id = ?")
            args.append(connection_id)
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""

        try:
            # Commit first to clear any stale read snapshot left by a previous
            # SELECT under Python's default isolation level — without this a
            # long-lived connection can keep returning a pre-INSERT view of the
            # table, exactly the bug f-MCP's get_logs() documents and works around.
            self.conn.commit()

            if limit is not None:
                query = (
                    f"SELECT * FROM (SELECT * FROM tool_calls {where} "
                    "ORDER BY id DESC LIMIT ?) ORDER BY id ASC"
                )
                rows = self.conn.execute(query, (*args, limit)).fetchall()
            else:
                query = f"SELECT * FROM tool_calls {where} ORDER BY id ASC"
                rows = self.conn.execute(query, args).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.warning("Failed to retrieve audit rows from %s: %s", self.db_path, exc)
            return []

    def get_system_logs(self, limit: int | None = None) -> list[dict]:
        """Rows whose ``connection_id`` is ``NULL`` — the Logs page's System tab.

        DESIGN-DATA-MODEL.md §5.2: tools that touch no connection (``list-connections``,
        a server status check) still get an audit row, and it would otherwise be invisible
        to every per-connection tab. ``get_logs(connection_id=None)`` cannot express this —
        that call means "no connection filter at all", not "only the NULL rows" — so this
        is a separate method rather than an overload of an existing parameter.

        Args:
            limit: If given, the most recent ``limit`` rows, returned oldest-first, the
                same shape ``get_logs`` uses for its "one tail" query.

        Returns:
            One dict per row, oldest first, or ``[]`` on any database error.
        """
        try:
            self.conn.commit()  # see get_logs()'s identical comment on stale read snapshots
            if limit is not None:
                query = (
                    "SELECT * FROM (SELECT * FROM tool_calls WHERE connection_id IS NULL "
                    "ORDER BY id DESC LIMIT ?) ORDER BY id ASC"
                )
                rows = self.conn.execute(query, (limit,)).fetchall()
            else:
                query = "SELECT * FROM tool_calls WHERE connection_id IS NULL ORDER BY id ASC"
                rows = self.conn.execute(query).fetchall()
            return [dict(row) for row in rows]
        except sqlite3.Error as exc:
            logger.warning("Failed to retrieve system audit rows from %s: %s", self.db_path, exc)
            return []

    def has_system_rows(self) -> bool:
        """Whether at least one row carries a ``NULL`` ``connection_id``.

        The Logs page uses this to decide whether its System tab should exist at all —
        DESIGN-DATA-MODEL.md's "correct and calm on first run" requirement means a fresh
        ``audit.db`` with no rows must not grow a System tab nobody asked for.
        """
        try:
            self.conn.commit()
            row = self.conn.execute(
                "SELECT EXISTS(SELECT 1 FROM tool_calls WHERE connection_id IS NULL)"
            ).fetchone()
            return bool(row[0]) if row is not None else False
        except sqlite3.Error as exc:
            logger.warning("Failed to check for system audit rows in %s: %s", self.db_path, exc)
            return False

    def distinct_connection_ids(self) -> list[int]:
        """Every non-``NULL`` ``connection_id`` this file holds a row for, ascending.

        The Logs page unions this with ``ConnectionStore.all_ids()`` to find the
        connections that no longer have a profile — DESIGN-DATA-MODEL.md §5.3's "a tab may
        need to exist for a connection that no longer has a profile" — because a deleted
        connection's audit rows are retained and the id can therefore appear here without
        appearing there.
        """
        try:
            self.conn.commit()
            rows = self.conn.execute(
                "SELECT DISTINCT connection_id FROM tool_calls "
                "WHERE connection_id IS NOT NULL ORDER BY connection_id"
            ).fetchall()
            return [int(row[0]) for row in rows]
        except sqlite3.Error as exc:
            logger.warning("Failed to list distinct connection ids in %s: %s", self.db_path, exc)
            return []

    def latest_connection_name(self, connection_id: int) -> str | None:
        """The ``_connection`` display name recorded on the most recent row for
        ``connection_id``, or ``None`` if there is no such row or it carries no name.

        DESIGN-DATA-MODEL.md §5.3: a deleted connection's tab still needs a label, and
        this file cannot join to a row in ``connections.db`` that is gone. The fix is the
        denormalised ``_connection`` reserved key every row's ``params_json`` carries
        (§5.4), read back out here rather than joined.
        """
        try:
            self.conn.commit()
            row = self.conn.execute(
                "SELECT params_json FROM tool_calls WHERE connection_id = ? "
                "ORDER BY id DESC LIMIT 1",
                (int(connection_id),),
            ).fetchone()
            if row is None:
                return None
            params = json.loads(row[0])
            name = params.get("_connection") if isinstance(params, dict) else None
            return str(name) if name else None
        except (sqlite3.Error, ValueError) as exc:
            logger.warning(
                "Failed to read the denormalised connection name for %s in %s: %s",
                connection_id, self.db_path, exc,
            )
            return None
