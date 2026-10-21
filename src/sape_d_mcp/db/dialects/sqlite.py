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

"""The SQLite dialect, driven by the standard library's `sqlite3`."""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Sequence
from typing import Any, ClassVar

from .base import (
    DeferredSurface,
    Dialect,
    DialectError,
    InvalidIdentifierError,
    fold_ascii_lower,
)
from .types import (
    Capabilities,
    CaseFolding,
    ColumnSpec,
    ConnectionProfile,
    Engine,
    GuardTraits,
    NormalisedRef,
    ObjectRef,
    ObjectType,
    Predicate,
    Query,
    RawPredicate,
    ReadOnlyEnforcement,
    ReadOnlyScope,
    ReadOnlySession,
    Script,
    SecretStr,
    ServerTraits,
    StatementKind,
    WritingCTEShape,
)

logger = logging.getLogger(__name__)

__all__ = ["SQLiteDialect"]


#: `RETURNING` landed in SQLite 3.35.0 (2021-03-12), and the version that matters is the one
#: the interpreter's `sqlite3` module was *linked* against, not the Python version.  Ubuntu
#: 20.04's system Python 3.8 links libsqlite3 3.31; the python.org Windows and macOS
#: installers bundle something current.  Two hosts running the same Python can therefore
#: disagree about this flag, which is why it is probed rather than assumed.
_RETURNING_FLOOR = (3, 35)

#: An in-memory database has no file to be absolute about.  Allowed by name so tests and the
#: GUI's "try it out" path have a target, and spelled out rather than pattern-matched so a
#: `file::memory:?cache=shared` URI — which reaches the filesystem URI parser and can name a
#: real path — does not slip through with it.
_MEMORY_PATH = ":memory:"

#: The one sentence every routine refusal on this engine gives, written once so the three
#: methods that raise it cannot drift into three different explanations of the same fact.
_NO_ROUTINES = (
    "SQLite has no stored functions or procedures; an application-defined function lives in "
    "the connecting process, not in the database file, so there is nothing to create and "
    "nothing a permission rule could be written against"
)

#: The same, for the twelve security builders.  SQLite has no server and therefore no
#: server-side principal of any kind: there is no `GRANT`, no `CREATE USER` and no catalogue
#: of who may do what, because whoever can open the file can already do everything.
#:
#: All twelve raise rather than returning an empty result, and the distinction is the whole
#: point.  An empty list reads as "this database has no roles", which is a claim about the
#: database; the truth is that the question does not apply to it, which is a claim about the
#: engine, and the two would lead a reader to opposite conclusions about how much has been
#: locked down.  `DESIGN-MCP-TOOLS.md` §11.2 requires the refusal in exactly those terms.
_NO_PRINCIPALS = (
    "SQLite has no server and no server-side principals: there is no role, user or group to "
    "create, list or grant to, and file permissions plus d-MCP's own rule table are the only "
    "access boundary a SQLite connection has"
)


def _linked_version() -> tuple[int, ...]:
    """The linked SQLite version, read from the module at call time.

    Read through a function rather than captured at import so a test can monkeypatch
    `sqlite3.sqlite_version_info` and see the capability flag move, which is exactly the
    conformance check the design document asks for.
    """

    return tuple(int(part) for part in sqlite3.sqlite_version_info)


class SQLiteDialect(DeferredSurface, Dialect):
    """Authors SQLite SQL.

    The engine with no server, and therefore no server-side principal of any kind: whoever
    can open the file has full DML and DDL rights inherent in filesystem access.  That makes
    d-MCP's own rule table the **only** access boundary a SQLite connection has, with file
    permissions as the sole other line of defence, and they sit outside this application
    entirely.
    """

    engine: ClassVar[Engine] = Engine.SQLITE
    display_name: ClassVar[str] = "SQLite"
    default_port: ClassVar[int | None] = None
    #: No schema layer at all.  `main` is the only schema d-MCP will address (decision D9),
    #: and `None` here is what makes `quote_ref()` emit a bare, unqualified name.
    default_schema: ClassVar[str | None] = None
    #: But `main` is what a permission rule matches against — see base.Dialect.
    addressable_schema: ClassVar[str | None] = "main"

    #: SQLite imposes no identifier length limit of its own; d-MCP caps it for sanity and for
    #: consistency with the GUI's identifier field.
    max_identifier_length: ClassVar[int] = 1024

    quote_open: ClassVar[str] = '"'
    quote_close: ClassVar[str] = '"'

    # -- the write side's per-engine constants -----------------------------------------

    #: Every spelling of "replace what is already there" refused in a `create_*` body and in
    #: the DDL `create_*` generates (DESIGN-MCP-TOOLS.md §8.1).
    #:
    #: SQLite has **no** `CREATE OR REPLACE` of any kind — the grammar simply does not admit
    #: it — so every entry here is a refusal of something the server would reject anyway, and
    #: the value of listing them is the message: a model that writes `CREATE OR REPLACE VIEW`
    #: is told that d-MCP replaces no object that already exists (docs/adr/0005) rather than
    #: handed `near "OR": syntax error`.
    #:
    #: What SQLite *does* have is `INSERT OR REPLACE` and the bare `REPLACE INTO`, both of
    #: which delete the conflicting row and insert a new one.  They are not create clauses and
    #: cannot appear in a `CREATE TABLE`, but they are listed because a view body is arbitrary
    #: SQL and this is the engine where "replace" means a silent delete.  The real replacement
    #: route here is `DROP` followed by `CREATE`, which is two statements and is refused by the
    #: trailing-statement check before this list is consulted.
    or_replace_spellings: ClassVar[tuple[str, ...]] = (
        "CREATE OR REPLACE",
        "CREATE OR ALTER",
        "INSERT OR REPLACE",
        "REPLACE INTO",
        "ALTER TABLE",
        "ALTER VIEW",
    )

    #: There is no boolean type; SQLite recognises `TRUE`/`FALSE` as the integer literals 1
    #: and 0 from 3.23 and stores them as integers either way, so the integers are emitted and
    #: the DDL stays valid on a file opened by an older library.
    boolean_literals: ClassVar[tuple[str, str]] = ("1", "0")

    #: `CURRENT_DATE`, `CURRENT_TIME` and `CURRENT_TIMESTAMP` are all available.
    unsupported_default_keywords: ClassVar[frozenset[str]] = frozenset()

    #: The type names `create_table()` will emit.  SQLite has type *affinity* rather than
    #: types and would accept `BANANA` as a column type, resolving it to NUMERIC affinity —
    #: which is exactly why an allow-list is worth having here even though the server enforces
    #: nothing: a typo that another engine would reject would otherwise create a column whose
    #: affinity nobody intended.  The list is the one in SQLite's own affinity-determination
    #: rules plus the aliases that documentation names.
    column_types: ClassVar[frozenset[str]] = frozenset(
        {
            "int", "integer", "tinyint", "smallint", "mediumint", "bigint",
            "unsigned big int", "int2", "int8",
            "character", "varchar", "varying character", "nchar", "native character",
            "nvarchar", "text", "clob",
            "blob",
            "real", "double", "double precision", "float",
            "numeric", "decimal", "boolean", "date", "datetime",
        }
    )

    # -- capabilities ------------------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        """Every flag is a constant except `supports_returning`.

        Spelled out because SQLite is where nearly every capability is absent at once:
        no schemas, no stored procedures, no table-valued functions, no roles, no users, no
        groups, no `CREATE OR REPLACE` of anything, no `ALTER COLUMN`, no cross-database
        reference (decision D9 refuses `ATTACH`, whose argument is a file path and therefore
        outside the permission model), and no data-modifying CTE — a SQLite CTE body is a
        `SELECT`, always.  DDL *is* transactional here, which is the one place SQLite is more
        capable than MySQL.
        """

        probed = self.probed
        version = self._traits.version if probed else ()
        return Capabilities(
            engine=Engine.SQLITE,
            supports_schemas=False,
            supports_stored_procedures=False,
            supports_table_valued_functions=False,
            supports_roles=False,
            supports_users=False,
            supports_groups=False,
            supports_create_or_replace_view=False,
            supports_create_or_replace_routine=False,
            supports_transactional_ddl=True,
            supports_alter_column=False,
            supports_returning=probed and version >= _RETURNING_FLOOR,
            supports_cross_database_reference=False,
            supports_data_modifying_cte=False,
            max_identifier_length=self.max_identifier_length,
            param_style=self.param_style,
            probed=probed,
        )

    @property
    def case_folding(self) -> CaseFolding:
        """Stored as written, compared ASCII-insensitively.  Constant — nothing to probe."""

        return CaseFolding.PRESERVE_CASE_INSENSITIVE

    # -- quoting and normalisation -----------------------------------------------------

    def quote_identifier(self, name: str) -> str:
        """`"name"`, with any inner double quote doubled.

        Double quotes rather than SQLite's tolerated `[name]` or `` `name` ``: those two exist
        only as compatibility affordances for MS-SQL and MySQL syntax, and SQLite will also
        silently reinterpret a double-quoted string that matches no column as a *string
        literal* — the infamous "double-quoted string misfeature".  Quoting an identifier that
        does exist is unaffected by it, and every identifier this layer emits has been
        validated against the catalogue first.
        """

        return self._quote(name)

    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str:
        """Verbatim.  SQLite stores an identifier exactly as it was typed, quoted or not.

        Works immediately: no probe is involved, because there is no server whose collation or
        configuration could change the answer.
        """

        if not isinstance(raw, str) or raw == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        if "\x00" in raw:
            raise InvalidIdentifierError("the identifier contains an embedded NUL")
        return raw

    def identifier_match_key(self, name: str) -> str:
        """ASCII-lower.  SQLite's identifier comparison is case-insensitive over ASCII only —
        `LIKE`-style Unicode folding is not applied to identifiers — so `Salaries` and
        `SALARIES` are one table while `café` and `CAFÉ` are two, and decision D6 refuses to
        pretend otherwise."""

        return fold_ascii_lower(self.normalise_identifier(name), engine=self.engine)

    # -- what the guard borrows --------------------------------------------------------

    def guard_traits(self) -> GuardTraits:
        """SQLite grammar facts, transcribed from §6 of `DESIGN-DIALECTS.md`.

        Two omissions are the document's, recorded here rather than silently corrected.
        SQLite does accept `REPLACE INTO`, an alias for `INSERT OR REPLACE`, yet §6 lists
        `REPLACE` for MySQL only; and decision D9 refuses `ATTACH`, for which `GuardTraits`
        has no field, so `sql_guard.py` must carry that refusal itself.  Both fail closed as
        the document stands — an unclassifiable statement is refused, not run — but both are
        worth closing explicitly in stage 7.
        """

        return GuardTraits(
            write_keywords=frozenset({"INSERT", "UPDATE", "DELETE"}),
            ddl_keywords=frozenset({"CREATE", "ALTER", "DROP"}),
            # SQLite has no GRANT, no login and no principal of any kind: there is nothing
            # for the guard to recognise as a security statement.
            security_keywords=frozenset(),
            line_comment_prefixes=("--",),
            block_comment_delimiters=("/*", "*/"),
            executable_comment_pattern=None,
            batch_separator_pattern=None,
            # A SQLite CTE body is a SELECT.  A data-modifying statement may carry a leading
            # `WITH`, but the CTE itself never writes, so there is no writing CTE to detect.
            writing_cte_shape=WritingCTEShape.NONE,
        )

    # -- connection --------------------------------------------------------------------

    def build_dsn(self, profile: ConnectionProfile) -> str:
        """The absolute database file path, taken from the profile's `database` column.

        `DESIGN-DATA-MODEL.md` §3.1 puts the path in `database`, and
        `ck_connections_shape` forces `host`, `port` and `username` to be NULL for a
        SQLite row — so `database` is the only column that can carry it.  The path must be
        absolute or the literal
        `:memory:`: a relative path resolves against the process working directory, which is
        the project root under the GUI and whatever the MCP client happened to be in when it
        spawned `--cli`, so the same profile would open two different files — or create an
        empty third one, since `sqlite3.connect()` never refuses a missing file.

        A `file:` URI is refused for the same reason `ATTACH` is (decision D9): its query
        string can turn on shared cache, immutable mode or a different VFS, none of which the
        permission model can see.
        """

        # A SQLite row is pinned to auth_mode 'none' by `ck_connections_shape`, and an
        # absent value means the same thing here — so only a hand-edited file can reach
        # this, and it must say why rather than open the file and let the user believe a
        # password protected it.
        auth_mode = self._profile_auth_mode(profile, default="none")
        if auth_mode != "none":
            raise DialectError(
                f"a SQLite database is a file, so it cannot authenticate with "
                f"{auth_mode!r}: access is controlled by the file's own permissions."
            )

        path = self._require(profile, "database").strip()
        if path == _MEMORY_PATH:
            return path
        if path.lower().startswith("file:"):
            raise DialectError(
                "a SQLite 'file:' URI is not accepted: its query string can change the VFS, "
                "the cache mode and the read-only flag, none of which d-MCP's permission "
                "model can see. Give a plain absolute path."
            )
        if not os.path.isabs(path):
            raise DialectError(
                f"the SQLite database path {path!r} is not absolute. A relative path resolves "
                "against the working directory, which differs between the GUI and an "
                "MCP-spawned --cli process, so the same profile would open two different "
                "files."
            )
        return path

    def with_password(self, dsn: str | dict[str, Any], password: SecretStr | str) -> str | dict[str, Any]:
        """SQLite has no credential.  A supplied password is a misconfigured profile.

        Returning the DSN unchanged for an empty secret keeps `engine.py`'s connect path
        uniform across the four engines; refusing a non-empty one stops a profile that the
        user believes is password-protected from connecting anyway and silently proving it
        never was.
        """

        secret = password.get_secret_value() if isinstance(password, SecretStr) else password
        if secret:
            raise DialectError(
                "SQLite connections carry no password: access is governed by the file's own "
                "permissions and by d-MCP's rules. Clear the stored credential for this "
                "profile."
            )
        return dsn

    def health_check_sql(self, *, first_check: bool = False) -> str:
        """`SELECT 1`, or `PRAGMA quick_check(1)` on the first check of a session.

        The keyword is an addition to §3.7, which describes the two-phase behaviour without
        saying who remembers which phase we are in.  A dialect holds no connection (decision
        D1) and so cannot know: `engine.py` owns the session and passes `first_check=True`
        once per pooled connection.  Called with no arguments — the shape `engine.py`'s
        contract names — it returns `SELECT 1`, so forgetting the flag costs a corruption
        check, not a broken connection.

        `quick_check(1)` rather than `integrity_check`: it stops after one error and skips
        the index-content pass, so it is seconds rather than minutes on a large file, and a
        corrupt SQLite database is silent until it is not.
        """

        return "PRAGMA quick_check(1)" if first_check else "SELECT 1"

    def version_probe_sql(self) -> str:
        """`SELECT sqlite_version()` — a cross-check, not the authority.

        `parse_traits()` takes the version from `sqlite3.sqlite_version_info` in this process,
        because that is the library that will actually run the statements.  The statement is
        still issued so `engine.py` has a uniform probe across the four engines and so a
        mismatch between the linked library and the one answering the query — which would
        mean something very odd about the environment — shows up in the log.
        """

        return "SELECT sqlite_version()"

    @classmethod
    def parse_traits(cls, rows: Sequence[Sequence[Any]]) -> ServerTraits:
        """Traits from the linked `sqlite3` library, cross-checked against the probe row.

        `rows` may be empty: there is nothing to ask a server about, so a caller that has not
        run the probe still gets usable traits.
        """

        version = _linked_version()
        raw_version = sqlite3.sqlite_version
        if rows:
            row = tuple(rows[0])
            reported = None if not row or row[0] is None else str(row[0])
            if reported and reported != raw_version:
                logger.warning(
                    "SQLite reports version %s from SQL but the linked library is %s; "
                    "capability flags follow the linked library",
                    reported,
                    raw_version,
                )
        return ServerTraits(
            raw_version=raw_version,
            version=version,
            variant="sqlite",
            collation=None,
            # Identifier comparison is ASCII case-insensitive, so the canonical form and the
            # match key genuinely differ here — see `identifier_match_key()`.
            case_sensitive_collation=False,
            lower_case_table_names=None,
            default_schema=None,
            current_user=None,
        )

    # -- session hardening --------------------------------------------------------------

    def read_only_session(self) -> ReadOnlySession:
        """`PRAGMA query_only = ON`, which SQLite enforces in the pager itself.

        The strongest of the four: with `query_only` set, every attempt to change the
        database file — DML, DDL, `VACUUM`, a journal write — fails with
        `SQLITE_READONLY: attempt to write a readonly database`, whatever the statement
        looked like to the guard.

        **It is connection state, not transaction state** (`ReadOnlyScope.CONNECTION`), and
        that is the fact `mcp_server.py` has to care about.  Its sessions are cached per
        `(connection_id, thread)` and reused across tool calls, so a `query_only` left on
        would not end with the read that set it: it would make every later write tool on that
        thread fail with a message about a read-only database and nothing to explain it.  The
        release is therefore mandatory and `engine.read_only_session()` closes the connection
        outright if it cannot be performed — a closed session is reopened transparently by
        `_resolve_connection()`, whereas a silently read-only one is a bug that would be
        blamed on the write tool.

        `PRAGMA query_only = OFF` is itself allowed while `query_only` is on: the pragma
        changes a connection flag and never touches the file, so the release cannot be
        locked out by the hardening it is undoing.
        """

        return ReadOnlySession(
            harden=(self._session_statement("PRAGMA query_only = ON"),),
            release=(self._session_statement("PRAGMA query_only = OFF"),),
            verify=self._session_statement("PRAGMA query_only"),
            verify_released=self._session_statement("PRAGMA query_only"),
            scope=ReadOnlyScope.CONNECTION,
            enforcement=ReadOnlyEnforcement.REFUSES,
            note="SQLite PRAGMA query_only, enforced by the pager for the whole connection",
        )

    def statement_timeout_statements(self, seconds: int) -> tuple[Query, ...]:
        """`PRAGMA busy_timeout`, which is the only clock SQLite exposes — and not a statement
        timeout.

        SQLite has no way to interrupt a long-running statement from SQL; the only interrupt
        is `sqlite3_interrupt()` from another thread, and a progress handler installed by the
        driver.  Neither is a session setting and neither is this dialect's to install, so
        rather than pretend, this bounds the one thing a SQLite statement can genuinely block
        on for an unbounded time: waiting for a writer's lock.  The profile's
        `statement_timeout_s` is the budget the operator gave this connection, so it is the
        right number to wait for a lock, and `engine.py` documents that a CPU-bound scan on a
        very large file is not covered.
        """

        return (self._session_statement(f"PRAGMA busy_timeout = {self._timeout_literal(seconds) * 1000}"),)

    # -- catalogue introspection -------------------------------------------------------

    def _is_addressable_schema(self, schema: str | None) -> bool:
        """Whether a schema argument names the one schema d-MCP addresses on this engine.

        `None` and `main` are the same thing here.  Anything else — `temp`, or an `ATTACH`ed
        alias — answers `False`, and the caller returns an empty result rather than raising:
        a refusal that distinguished "no such schema" from "schema you may not see" would be
        an existence oracle, and `list`-style operations hide rather than refuse.  Decision D9
        already refuses `ATTACH`, so no other schema can come into existence through d-MCP.
        """

        if schema is None:
            return True
        # Compared through the match key, not raw: SQLite's identifier comparison is ASCII
        # case-insensitive, so `MAIN` is `main`.
        return self.identifier_match_key(schema) == "main"

    def _empty_result(self, columns: int) -> str:
        """A statement of the right shape that returns no rows.

        SQLite accepts a `SELECT` with a `WHERE` and no `FROM`, so this needs no dummy table.
        The column count matters and the names do not: `introspection.py` unpacks catalogue
        rows positionally, and a caller that iterates zero rows never reads either.
        """

        return "SELECT " + ", ".join(f"NULL AS c{i}" for i in range(columns)) + " WHERE 0"

    #: `sqlite_master` under its historical name rather than `sqlite_schema`, which arrived
    #: in 3.33; the old spelling works on every version and is what §3.3 names.
    _MASTER = ObjectRef(schema=None, name="sqlite_master", object_type=ObjectType.TABLE)

    @staticmethod
    def _pragma(name: str) -> ObjectRef:
        """A pragma table-valued function, as an `ObjectRef` for `Query.touches`.

        Recorded as a `FUNCTION` because that is what it is — SQLite exposes the pragmas as
        table-valued functions from 3.16 — even though `capabilities.supports_table_valued_
        functions` is `False`, which is about *user-definable* ones.  `touches` has to say
        what the statement reads; a catalogue query that claimed to touch nothing would be
        the one lie `sql_guard`'s agreement test exists to catch.
        """

        return ObjectRef(schema=None, name=name, object_type=ObjectType.FUNCTION)

    def list_databases(self, *, include_system: bool = False) -> Query:
        """One synthetic row, `main`.  The GUI never calls it.

        A SQLite profile has exactly one database and it is the file, so there is nothing to
        enumerate and the Find-databases button is hidden — the Browse button already does
        the job.  `PRAGMA database_list` is deliberately **not** used: it reports `temp` and
        anything `ATTACH`ed, neither of which a profile may name (decision D9), so it would
        offer the user something unusable.

        The method exists all the same, because every caller above this one is written
        against four engines and an implementation that raised would put an engine test in
        the connection dialog.
        """

        return self._catalogue_query("SELECT 'main' AS database_name, 0 AS is_system")

    @property
    def bootstrap_database(self) -> str | None:
        """`None`: the file *is* the database, so there is nothing to connect to first."""

        return None

    def list_schemas(self) -> Query:
        """One synthetic row, `main`.

        SQLite has no schema layer, but every caller above this one is written against four
        engines that do, and a `list_schemas()` that raised here would put an engine test in
        the Explorer page, the rule editor and the MCP tool alike.  `capabilities.
        supports_schemas` stays `False`, which is what a caller checks before *offering* to
        create one.
        """

        return self._catalogue_query("SELECT 'main' AS schema_name")

    def list_tables(self, schema: str | None = None) -> Query:
        """Base tables from `sqlite_master`, internal `sqlite_*` tables excluded.

        `substr(name, 1, 7) <> 'sqlite_'` rather than `NOT LIKE 'sqlite_%'` for two reasons:
        `_` is a LIKE wildcard, so the pattern would also match `sqliteX`, and a literal `%`
        in a statement is a hazard on any driver with a `pyformat` paramstyle.  SQLite is
        `qmark`, so the second does not bite here — but the habit is the point, since the
        same query shape is written four times in this layer.

        Shadow tables belonging to a virtual table (`fts_content` and friends) are *not*
        filtered: they are ordinary tables to SQLite, they are addressable, and hiding them
        would hide something a rule can still be written against.
        """

        if not self._is_addressable_schema(schema):
            return self._catalogue_query(self._empty_result(3))
        return self._catalogue_query(
            "SELECT NULL AS schema_name, m.name AS table_name, NULL AS table_comment "
            "FROM sqlite_master AS m "
            "WHERE m.type = 'table' AND substr(m.name, 1, 7) <> 'sqlite_' "
            "ORDER BY m.name",
            touches=(self._MASTER,),
        )

    def list_views(self, schema: str | None = None) -> Query:
        """Views from `sqlite_master`.  SQLite has no materialised view, so the flag is 0."""

        if not self._is_addressable_schema(schema):
            return self._catalogue_query(self._empty_result(4))
        return self._catalogue_query(
            "SELECT NULL AS schema_name, m.name AS view_name, 0 AS is_materialised, "
            "NULL AS view_comment "
            "FROM sqlite_master AS m "
            "WHERE m.type = 'view' AND substr(m.name, 1, 7) <> 'sqlite_' "
            "ORDER BY m.name",
            touches=(self._MASTER,),
        )

    def list_functions(self, schema: str | None = None) -> Query:
        """Empty, never an error.

        SQLite has application-defined functions, but they live in the *process* that opened
        the file, not in the database, so there is nothing in the file to enumerate and
        nothing a permission rule could be written against.  `capabilities.
        supports_table_valued_functions` is `False`; the honest rendering is an empty list,
        which is the "hide rather than refuse" rule for `list`-style operations.
        """

        return self._catalogue_query(self._empty_result(6))

    def list_procedures(self, schema: str | None = None) -> Query:
        """Empty, never an error.  SQLite has no stored procedure of any kind."""

        return self._catalogue_query(self._empty_result(6))

    def describe_table(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Columns, primary key, unique keys, foreign keys — four pragma queries.

        The table name is a **bound parameter** in every one of them: SQLite's pragma
        functions take their argument in the ordinary value position, so nothing here needs
        the name spliced into the text.  That is worth saying out loud because the obvious
        alternative — `PRAGMA table_info("<name>")` — has no parameter position at all, and
        writing it that way would put an interpolated identifier in the security-critical
        layer for no gain.
        """

        name = ref.canonical_name
        columns = self._catalogue_query(
            "SELECT x.name AS column_name, "
            "x.type AS data_type, "
            'CASE WHEN x."notnull" = 0 THEN 1 ELSE 0 END AS is_nullable, '
            "x.dflt_value AS column_default, "
            # A single-column INTEGER PRIMARY KEY is a rowid alias: SQLite assigns it for
            # you and it is the closest thing the engine has to an identity column.  Any
            # other primary key is not, however INTEGER it looks, so the test carries the
            # count of key columns with it rather than trusting `pk = 1` alone.
            "CASE WHEN x.pk = 1 AND upper(x.type) = 'INTEGER' "
            f"          AND (SELECT count(*) FROM pragma_table_info({self.placeholder(0, 't0')}) AS p "
            "               WHERE p.pk > 0) = 1 "
            "     THEN 1 ELSE 0 END AS is_identity, "
            "CASE WHEN x.hidden IN (2, 3) THEN 1 ELSE 0 END AS is_generated, "
            "x.cid + 1 AS ordinal_position, "
            "NULL AS column_comment "
            f"FROM pragma_table_xinfo({self.placeholder(1, 't1')}) AS x "
            # hidden = 1 is a virtual table's hidden column: not selectable through
            # `SELECT *`, so listing it would describe a table the caller cannot query.
            "WHERE x.hidden <> 1 "
            "ORDER BY x.cid",
            (name, name),
            ("t0", "t1"),
            touches=(self._pragma("pragma_table_info"), self._pragma("pragma_table_xinfo")),
        )
        primary_key = self._catalogue_query(
            # SQLite gives the primary key no name of its own.  `'PRIMARY'` is MySQL's name
            # for the same thing and is what the GUI shows; inventing a per-table name would
            # imply the server holds one.
            "SELECT 'PRIMARY' AS constraint_name, p.name AS column_name, p.pk AS key_ordinal "
            f"FROM pragma_table_info({self.placeholder(0, 't0')}) AS p "
            "WHERE p.pk > 0 "
            "ORDER BY p.pk",
            (name,),
            ("t0",),
            touches=(self._pragma("pragma_table_info"),),
        )
        unique_keys = self._catalogue_query(
            'SELECT il.name AS constraint_name, ii.name AS column_name, '
            "ii.seqno + 1 AS key_ordinal "
            f"FROM pragma_index_list({self.placeholder(0, 't0')}) AS il, "
            "     pragma_index_info(il.name) AS ii "
            # origin 'pk' is the primary key's own index, already reported above; 'u' is a
            # UNIQUE constraint and 'c' a CREATE UNIQUE INDEX, and both are genuine unique
            # keys as far as a caller reasoning about row identity is concerned.
            'WHERE il."unique" = 1 AND il.origin <> \'pk\' '
            # An index over an expression reports a NULL column name.  Dropping the row
            # would report a *partial* key, which is worse than not reporting it: the whole
            # index is excluded instead.
            "  AND NOT EXISTS (SELECT 1 FROM pragma_index_info(il.name) AS z "
            "                  WHERE z.name IS NULL) "
            "ORDER BY il.name, ii.seqno",
            (name,),
            ("t0",),
            touches=(self._pragma("pragma_index_list"), self._pragma("pragma_index_info")),
        )
        foreign_keys = self._catalogue_query(
            "SELECT 'fk_' || CAST(fk.id AS TEXT) AS constraint_name, "
            'fk."from" AS column_name, '
            "fk.seq + 1 AS key_ordinal, "
            "NULL AS referenced_schema, "
            'fk."table" AS referenced_table, '
            # A parent key omitted from the REFERENCES clause means "the parent's primary
            # key", and SQLite reports NULL for it rather than resolving it.  Resolving it
            # here keeps every consumer from having to know that.
            'COALESCE(fk."to", (SELECT p.name FROM pragma_table_info(fk."table") AS p '
            "                   WHERE p.pk = fk.seq + 1)) AS referenced_column, "
            "fk.on_delete AS on_delete, "
            "fk.on_update AS on_update "
            f"FROM pragma_foreign_key_list({self.placeholder(0, 't0')}) AS fk "
            "ORDER BY fk.id, fk.seq",
            (name,),
            ("t0",),
            touches=(
                self._pragma("pragma_foreign_key_list"),
                self._pragma("pragma_table_info"),
            ),
        )
        return (columns, primary_key, unique_keys, foreign_keys)

    def describe_routine(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Two empty results, in the shape the other three engines fill.

        Not a `CapabilityError`: `describe_routine()` is reached from the Explorer page's
        object tree, which on this engine never offers a routine to describe, and from
        `introspection.py`, which returns "no such routine" for an empty header row.  Both
        are better served by an empty answer than by an exception they would have to catch
        to render an empty panel.
        """

        return (self._catalogue_query(self._empty_result(7)), self._catalogue_query(self._empty_result(6)))

    def object_definition(self, ref: NormalisedRef) -> Query:
        """The `CREATE` text `sqlite_master` stored for a view or a table.

        SQLite keeps the statement it was given, verbatim, comments and all — so this is the
        one engine where the definition read back is byte-for-byte what was written.  A
        routine has no definition to read because it has no existence, and that is a
        `CapabilityError` rather than an empty row: the caller asked for a specific object's
        source, and answering "NULL" would read as "encrypted or withheld", which is a
        different and much more confusing thing.
        """

        if ref.object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE):
            raise self._unsupported(
                "object_definition",
                "SQLite has no stored functions or procedures; application-defined functions "
                "live in the connecting process, not in the database file",
            )
        return self._catalogue_query(
            "SELECT m.sql AS definition "
            "FROM sqlite_master AS m "
            f"WHERE m.name = {self.placeholder(0, 'name')} "
            "  AND m.type IN ('view', 'table')",
            (ref.canonical_name,),
            ("name",),
            touches=(self._MASTER,),
        )

    # -- row operations (DESIGN-DIALECTS.md §3.6) --------------------------------------

    def _check_select(self, ref: NormalisedRef, row_cap: int, offset: int) -> None:
        """Everything `select()` refuses before it writes a single character of SQL.

        `row_cap` is deliberately validated rather than clamped (decision D7): a caller that
        asked for zero rows, or for a boolean by accident, has a bug, and quietly returning
        the "sensible" number of rows hides it until the day the number matters.  `True` is
        an `int` in Python and is rejected explicitly for the same reason.
        """

        if ref.object_type not in (ObjectType.TABLE, ObjectType.VIEW):
            raise ValueError(
                f"select() reads a table or a view; {ref.object_type} is neither"
            )
        if isinstance(row_cap, bool) or not isinstance(row_cap, int) or row_cap < 1:
            raise ValueError(f"row_cap must be a positive integer, not {row_cap!r}")
        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError(f"offset must be a non-negative integer, not {offset!r}")

    def _select_list(self, columns: Sequence[str] | None) -> str:
        """The quoted column list, refusing the `*` shortcut.

        `columns=None` means "every column" and is the caller's job to expand from the
        introspected catalogue, not this layer's: a dialect holds no connection and cannot
        read a catalogue (decision D1).  Emitting `*` instead would hand the LLM whatever
        columns exist at execution time — including one added by an `ALTER TABLE` after the
        permission rule was written — so it is refused with a message naming the fix rather
        than substituted silently.
        """

        if columns is None:
            raise ValueError(
                "select() will not emit '*': pass the column list, which the caller expands "
                "from Introspector.describe_table() so the result shape cannot change under "
                "a later ALTER TABLE"
            )
        quoted = [self.quote_identifier(column) for column in columns]
        if not quoted:
            raise ValueError("select() needs at least one column")
        return ", ".join(quoted)

    # `_bind()` and `_where_clause()` used to stand here, byte for byte identical in all four
    # dialects.  They moved to `base.Dialect` when the write builders needed them too: the
    # routine that decides what a parameter marker is numbered must have exactly one
    # implementation, because a positional paramstyle pairs values to markers by that number
    # and by nothing else.

    def _order_clause(self, order_by: Sequence[tuple[str, bool]]) -> str:
        """`ORDER BY`, each column validated and quoted, the flag reading "ascending"."""

        if not order_by:
            return ""
        parts = [
            f"{self.quote_identifier(column)} {'ASC' if ascending else 'DESC'}"
            for column, ascending in order_by
        ]
        return " ORDER BY " + ", ".join(parts)

    def select(
        self,
        ref: NormalisedRef,
        columns: Sequence[str] | None = None,
        *,
        predicates: Sequence[Predicate] = (),
        where: RawPredicate | None = None,
        order_by: Sequence[tuple[str, bool]] = (),
        row_cap: int,
        offset: int = 0,
    ) -> Query:
        """A parameterised `SELECT` capped with `LIMIT ... OFFSET`.

        The emitted name is unqualified — SQLite has no schema layer and `quote_ref()`
        omits the part it does not have — while `touches` reports the schema as `main`,
        which is what a permission rule matches against (DESIGN-PERMISSIONS.md §5.5)
        and what `sql_guard` resolves the unqualified name to.  The two must agree or
        the structured path and the free-form path would authorise different keys.

        `row_cap` is keyword-only and has no default anywhere in the chain, so omitting it is
        a `TypeError` at the call site rather than a silent default (decision D7).  Values are
        bound — the cap and the offset included — and every identifier is validated and then
        quoted with this engine's own delimiters.


        `predicates` carries the structured form; `where` carries the free-form fragment the
        user has ruled `select-rows` must accept.  The two are alternatives, not a pair, and
        passing both raises.  The fragment is emitted parenthesised and its values are bound
        into exactly the slots the structured predicates would have used, which is what keeps
        the cap and offset paired with their own markers.
        `touches` carries exactly the one object the statement reads, and deliberately not
        whatever a `where` fragment reaches: enumerating the fragment's references is the
        guard's job, done against the composed text by the tool layer.  For the structured
        path the two enumerations must agree, and a test asserts they do — that agreement is
        what makes the structured path and the free-form path answer to the same
        authorisation.
        """

        self._check_one_where(predicates, where)
        self._check_select(ref, row_cap, offset)
        values: list[Any] = []
        names: list[str] = []
        column_list = self._select_list(columns)
        target = self.quote_ref(ref)
        condition = (
            self._where_clause(predicates, values, names)
            if where is None
            else self._raw_where_clause(where, values, names)
        )
        order = self._order_clause(order_by)
        # Bound after the condition because they appear after it in the text, and a
        # positional paramstyle pairs values to markers by position alone.
        cap = self._bind(row_cap, values, names, "row_cap")
        skip = self._bind(offset, values, names, "row_offset")
        sql = f"SELECT {column_list} FROM {target}{condition}{order} LIMIT {cap} OFFSET {skip}"

        return Query(
            sql=sql,
            params=self.parameters(
                values, names if self.param_style.is_mapping_style else None
            ),
            kind=StatementKind.READ,
            touches=(
                ObjectRef(
                    schema=ref.canonical_schema or self.addressable_schema,
                    name=ref.canonical_name,
                    object_type=ref.object_type,
                ),
            ),
            row_cap=row_cap,
        )

    # -- the write side (DESIGN-DIALECTS.md §3.4 and §3.6) -----------------------------

    #: `SQLITE_MAX_VARIABLE_NUMBER` was 999 until 3.32 and 32 766 from it.  Read from the
    #: *linked* library rather than assumed, for the same reason `supports_returning` is: two
    #: hosts running the same Python can link different SQLite versions, and a batch that fits
    #: on one would fail on the other with `too many SQL variables`.
    _VARIABLE_LIMIT_FLOOR = (3, 32)

    @property
    def max_bound_parameters(self) -> int | None:  # type: ignore[override]
        """The linked library's parameter ceiling.

        A property overriding a class attribute, which is unusual and is the point: the answer
        is a property of the shared library this process happens to have loaded, not of the
        engine, so it cannot be a constant the way SQL Server's 2 100 can.
        """

        return 32766 if _linked_version() >= self._VARIABLE_LIMIT_FLOOR else 999

    def _identity_clause(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """`PRIMARY KEY AUTOINCREMENT`, which is only spellable one way and only on one shape.

        SQLite has no identity attribute.  What it has is the rowid alias: a column declared
        exactly `INTEGER PRIMARY KEY` *is* the rowid and the server assigns it, and adding
        `AUTOINCREMENT` further promises the value is never reused after a delete.  Both
        require the column to be the whole primary key and to be spelled `INTEGER` — not
        `INT`, not `BIGINT`, which are different affinity keywords and produce an ordinary
        indexed column that SQLite will not populate.

        So this refuses anything else rather than emitting DDL the server accepts and then
        behaves differently from every other engine under.  The primary key is emitted inline
        here, which is why `_primary_key_clause()` below has to know to stay silent.
        """

        if self._validate_type(spec.data_type) != "INTEGER":
            raise ValueError(
                f"column {spec.name!r} is an identity column, and SQLite only assigns values "
                "for a column declared exactly INTEGER: INT and BIGINT are different "
                "affinities and the server will leave them NULL"
            )
        keys = [self.identifier_match_key(column) for column in primary_key]
        if keys != [self.identifier_match_key(spec.name)]:
            raise ValueError(
                f"column {spec.name!r} is an identity column, and SQLite only assigns values "
                "for the rowid alias: it must be the whole primary key"
            )
        return " PRIMARY KEY AUTOINCREMENT"

    def _primary_key_clause(
        self, primary_key: Sequence[str], columns: Sequence[ColumnSpec]
    ) -> str:
        """The table-level constraint, unless the key is the identity column's own.

        `INTEGER PRIMARY KEY AUTOINCREMENT` already declares the key inline, and adding a
        second `PRIMARY KEY (...)` beside it is a syntax error rather than a redundancy.
        """

        if not primary_key:
            return ""
        keys = {self.identifier_match_key(column) for column in primary_key}
        for spec in columns:
            if spec.is_identity and {self.identifier_match_key(spec.name)} == keys:
                return ""
        return super()._primary_key_clause(primary_key, columns)

    def create_routine(
        self, ref: NormalisedRef, body: str, object_type: ObjectType, or_replace: bool = False
    ) -> Script:
        """`CapabilityError`.  SQLite has no stored routine of any kind.

        Refused here rather than left to `_routine_keyword()`'s stored-procedure check,
        because that check would let a *function* through: SQLite does have functions, they
        are just registered by the connecting process and live in it, so there is nothing in
        the file to create and nothing a permission rule could be written against.
        """

        raise self._unsupported("create_routine", _NO_ROUTINES)

    def edit_routine(
        self,
        ref: NormalisedRef,
        body: str,
        object_type: ObjectType,
        previous_definition: str | None = None,
    ) -> Script:
        """`CapabilityError`.  There is no routine to edit."""

        raise self._unsupported("edit_routine", _NO_ROUTINES)

    def drop_routine(
        self,
        ref: NormalisedRef,
        object_type: ObjectType,
        signature: str | None = None,
        if_exists: bool = True,
    ) -> Script:
        """`CapabilityError`.  There is no routine to drop."""

        raise self._unsupported("drop_routine", _NO_ROUTINES)

    def resolve_overload(
        self, ref: NormalisedRef, signature: str | None, overloads: Sequence[str]
    ) -> str | None:
        """`CapabilityError`, and not the base class's `ValueError`.

        The base answer — "SQLite does not overload routines" — is true and misleading: it
        reads as a remark about one engine's routines, and there are none to overload or to
        address at all.  The distinction is the one the whole routine surface here makes: a
        `CapabilityError` is a permanent answer the GUI greys a control out for, while a
        `ValueError` invites the model to try again with different arguments, and nothing it
        could pass would work.
        """

        raise self._unsupported("resolve_overload", _NO_ROUTINES)

    def estimate_row_count(self, ref: NormalisedRef) -> Query:
        """An exact `COUNT(*)`, and the docstring says so rather than the name implying
        otherwise.

        SQLite keeps no row-count statistic.  `sqlite_stat1` exists only after an `ANALYZE`,
        holds a *string* whose first field is the row count as of that analysis, and is absent
        on the overwhelming majority of databases — so reading it would give a wrong answer
        most of the time and no answer the rest.  The honest alternative is to count, which on
        this engine is a scan of the smallest index.

        The consequence belongs on the record: this is the one engine where the confirmation
        dialog's "estimated rows" line costs a full table scan, bounded by the connection's
        `statement_timeout_s` — which on SQLite is `PRAGMA busy_timeout`, a lock wait rather
        than a CPU budget, so a very large file can make the dialog slow to appear.  Slow and
        right was preferred to instant and invented.
        """

        if ref.object_type not in (ObjectType.TABLE, ObjectType.VIEW):
            raise ValueError(
                f"estimate_row_count() counts rows of a table or a view; {ref.object_type} "
                "is neither"
            )
        return self._catalogue_query(
            f"SELECT COUNT(*) AS estimated_rows FROM {self.quote_ref(ref)}",
            touches=(
                ObjectRef(
                    schema=self.addressable_schema,
                    name=ref.canonical_name,
                    object_type=ref.object_type,
                ),
            ),
        )

    # -- 3.5 security ------------------------------------------------------------------
    #
    # Twelve refusals, each a `CapabilityError` and never an empty result.  They are written
    # out one by one rather than generated in a loop or funnelled through `__getattr__`,
    # because a reader auditing this layer must be able to see that every one of the twelve is
    # accounted for by reading the file — and because a generated refusal would go on being
    # correct if a thirteenth builder were added to `Dialect` and never noticed here.
    #
    # `capabilities.supports_roles`, `supports_users` and `supports_groups` are all `False`, so
    # the MCP tool layer refuses before it ever reaches these.  They are the second line: the
    # GUI, `db/security.py` and any later caller reach the dialect directly.

    def list_principals(self) -> Query:
        """`CapabilityError`.  There is no principal to list — not zero of them."""

        raise self._unsupported("list_principals", _NO_PRINCIPALS)

    def list_group_members(self, group: str) -> Query:
        """`CapabilityError`.  There is no group to have members."""

        raise self._unsupported("list_group_members", _NO_PRINCIPALS)

    def list_grants(self, ref: NormalisedRef | None = None) -> Query:
        """`CapabilityError`.  There is no server-side privilege system to report on.

        Worth separating from the others: the Explorer page shows this listing *beside* the
        d-MCP rules so a human can see where the two disagree.  On SQLite there is no second
        system to disagree with, and an empty grant list would suggest that the file is
        locked down when in fact everything is permitted to anyone holding it.
        """

        raise self._unsupported("list_grants", _NO_PRINCIPALS)

    def create_role(self, name: str) -> Script:
        """`CapabilityError`.  No roles."""

        raise self._unsupported("create_role", _NO_PRINCIPALS)

    def create_user(
        self,
        name: str,
        *,
        host: str | None = None,
        login: str | None = None,
        default_schema: str | None = None,
    ) -> Script:
        """`CapabilityError`.  No users, and no credential to withhold from one either."""

        raise self._unsupported("create_user", _NO_PRINCIPALS)

    def create_group(self, name: str) -> Script:
        """`CapabilityError`.  No groups."""

        raise self._unsupported("create_group", _NO_PRINCIPALS)

    def add_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`CapabilityError`.  No groups to join."""

        raise self._unsupported("add_group_member", _NO_PRINCIPALS)

    def remove_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`CapabilityError`.  No groups to leave."""

        raise self._unsupported("remove_group_member", _NO_PRINCIPALS)

    def assign_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`CapabilityError`.  No roles to assign."""

        raise self._unsupported("assign_role", _NO_PRINCIPALS)

    def revoke_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`CapabilityError`.  No roles to revoke."""

        raise self._unsupported("revoke_role", _NO_PRINCIPALS)

    def grant(
        self,
        privileges: Sequence[str],
        ref: NormalisedRef | None,
        principal: str,
        with_grant_option: bool = False,
        *,
        host: str | None = None,
        signature: str | None = None,
    ) -> Script:
        """`CapabilityError`.  SQLite's grammar has no `GRANT`.

        Refused before the privilege words are looked at, so the message names the engine's
        absent feature rather than complaining about a privilege spelling on an engine that
        would have nothing to do with a correctly spelled one either.
        """

        raise self._unsupported("grant", _NO_PRINCIPALS)

    def revoke(
        self,
        privileges: Sequence[str],
        ref: NormalisedRef | None,
        principal: str,
        *,
        host: str | None = None,
        signature: str | None = None,
    ) -> Script:
        """`CapabilityError`.  SQLite's grammar has no `REVOKE`."""

        raise self._unsupported("revoke", _NO_PRINCIPALS)
