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

"""The MySQL/MariaDB dialect, driven by PyMySQL or mysql-connector-python."""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Any, ClassVar

from .base import (
    DeferredSurface,
    Dialect,
    DialectError,
    DialectNotConfiguredError,
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
    ServerTraits,
    StatementKind,
    WritingCTEShape,
)

logger = logging.getLogger(__name__)

__all__ = ["MySQLDialect"]

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")

#: MariaDB prefixes its `VERSION()` with `5.5.5-` on the classic protocol — a compatibility
#: hack for replication clients that predate two-digit major versions.  Left in place it
#: parses as MariaDB 5.5.5, which is below every capability floor below, so every flag would
#: read `False` on a perfectly capable 10.x or 11.x server.
_MARIADB_LEGACY_PREFIX = "5.5.5-"

#: Roles arrived in MySQL 8.0 and MariaDB 10.0.5.  Below those, a "user" — the `'name'@'host'`
#: pair — is the only principal there is, and d-MCP refuses to approximate a group with a
#: dummy user: that would put an unlogged, un-auditable principal into the server's own
#: catalogue purely to make a GUI button work.
_ROLES_FLOOR_MYSQL = (8, 0)
_ROLES_FLOOR_MARIADB = (10, 0, 5)

_OR_REPLACE_VIEW_FLOOR_MYSQL = (5, 7)
_OR_REPLACE_VIEW_FLOOR_MARIADB = (10, 1)

#: `INSERT ... RETURNING` is a MariaDB extension (10.5) that MySQL has never had.
_RETURNING_FLOOR_MARIADB = (10, 5)

#: `ACCOUNT LOCK` — the only clause on this engine that makes an account genuinely unable to
#: connect — arrived in MySQL 5.7.6 and MariaDB 10.4.2.  Below those, a user created without a
#: password is a user with an **empty** password, which is a password it can log in with, so
#: `create_user()` refuses rather than emitting something that reads safe and is not.
_ACCOUNT_LOCK_FLOOR_MYSQL = (5, 7, 6)
_ACCOUNT_LOCK_FLOOR_MARIADB = (10, 4, 2)

#: `mysql.user.account_locked` exists from the same releases, and `list_principals()` reads it
#: only where it is there: naming a missing column is `ERROR 1054` and takes the whole listing
#: out rather than one column of it.
_ACCOUNT_LOCKED_COLUMN_FLOOR_MARIADB = _ACCOUNT_LOCK_FLOOR_MARIADB

#: The most characters MySQL 8.0 and MariaDB allow in the two halves of an account name.  The
#: user half was 16 before MySQL 5.7.8 and the host half 60 before 8.0.17; both older limits are
#: enforced by the server, which refuses the name rather than truncating it.
_MAX_ACCOUNT_USER_LENGTH = 32
_MAX_ACCOUNT_HOST_LENGTH = 255

#: `@@transaction_read_only` replaced `@@tx_read_only` in MySQL 5.7.20 and the old spelling
#: was *removed* in 8.0.3, so neither name works everywhere and the choice has to be made
#: from the probe.  MariaDB kept `tx_read_only` far longer and only added the new spelling in
#: 11.1.  Reading the wrong one is not a cosmetic error: it is `ERROR 1193: Unknown system
#: variable`, and since a failed verify refuses the read, that would take the connection out.
_READ_ONLY_VARIABLE_FLOOR_MYSQL = (5, 7, 20)
_READ_ONLY_VARIABLE_FLOOR_MARIADB = (11, 1)

#: `max_execution_time` (milliseconds, MySQL 5.7.8+) applies to read-only `SELECT` only.
#: MariaDB never implemented it and offers `max_statement_time` (seconds, as a float, from
#: 10.1) instead, which applies to more than `SELECT`.
_MAX_EXECUTION_TIME_FLOOR_MYSQL = (5, 7, 8)
_MAX_STATEMENT_TIME_FLOOR_MARIADB = (10, 1)


class MySQLDialect(DeferredSurface, Dialect):
    """Authors MySQL and MariaDB SQL.

    One class for both, because they share a grammar for almost everything this layer emits;
    where they genuinely diverge — role assignment, `RETURNING` — the branch is on
    `traits.variant` inside the method rather than in a second class, so the two paths sit
    next to each other and neither can be updated while the other is forgotten.
    """

    engine: ClassVar[Engine] = Engine.MYSQL
    display_name: ClassVar[str] = "MySQL/MariaDB"
    default_port: ClassVar[int | None] = 3306
    #: MySQL's "database" and "schema" are the same object; the profile's database is the
    #: schema, so there is no engine-wide default to fall back on.
    default_schema: ClassVar[str | None] = None

    max_identifier_length: ClassVar[int] = 64

    quote_open: ClassVar[str] = "`"
    quote_close: ClassVar[str] = "`"

    # -- the write side's per-engine constants -----------------------------------------

    #: Every spelling of "replace what is already there" this engine has, refused in a
    #: `create_*` body and in the DDL `create_*` generates (DESIGN-MCP-TOOLS.md §8.1).
    #:
    #: `CREATE OR REPLACE VIEW` is MySQL's from 5.7 and MariaDB's from earlier.  MariaDB adds
    #: `CREATE OR REPLACE TABLE`, which is not a merge or an upsert — it **drops** the
    #: existing table first, data included, and is the single most destructive thing on this
    #: list; it is also why `CREATE OR REPLACE` is listed as a two-word phrase rather than
    #: enumerated per object kind.  MariaDB has `CREATE OR REPLACE PROCEDURE`/`FUNCTION` too.
    #: `CREATE OR ALTER` is T-SQL and listed so a model writing the wrong dialect gets the
    #: message that names the right tool.  The `ALTER <object>` forms replace a definition
    #: wholesale.  `RENAME TABLE` is here because on this engine it is how a table is moved
    #: out from under the rule that authorised it — the very act `rename_object()` was deleted
    #: rather than shipped for.
    or_replace_spellings: ClassVar[tuple[str, ...]] = (
        "CREATE OR REPLACE",
        "CREATE OR ALTER",
        "ALTER VIEW",
        "ALTER FUNCTION",
        "ALTER PROCEDURE",
        "ALTER EVENT",
        "ALTER TABLE",
        "RENAME TABLE",
    )

    #: A backslash escapes the next character inside a string literal unless
    #: `NO_BACKSLASH_ESCAPES` is set.  The default is the escaping one, and reading a body the
    #: other way would let `'\''` close a literal the server would leave open — handing the
    #: scanner text where the server sees code.
    backslash_escapes_strings: ClassVar[bool] = True

    #: There is no boolean type: `BOOLEAN` is an alias for `TINYINT(1)`, and `TRUE`/`FALSE`
    #: are accepted as the integer literals 1 and 0.  Emitting the words would work; emitting
    #: the integers works on MariaDB with a strict SQL mode too.
    boolean_literals: ClassVar[tuple[str, str]] = ("1", "0")

    #: `UNSIGNED` and `ZEROFILL` are attributes of the type rather than of the column, so they
    #: have to be admitted by the type validator or half the integer columns in a MySQL schema
    #: become unspellable.
    type_modifiers: ClassVar[frozenset[str]] = frozenset({"UNSIGNED", "ZEROFILL"})

    #: The types `create_table()` will emit.  `ENUM` and `SET` are absent and that is not an
    #: oversight: their argument list is a list of *string literals*, so admitting them would
    #: mean interpolating caller text into a type name, which is the one thing this layer does
    #: not do outside `_default_literal()` — the only interpolation point left in it since
    #: stage 8 deleted `_password_literal()` rather than implementing it.
    column_types: ClassVar[frozenset[str]] = frozenset(
        {
            "tinyint", "smallint", "mediumint", "int", "integer", "bigint", "bit",
            "decimal", "dec", "numeric", "fixed", "float", "double", "double precision",
            "real", "boolean", "bool",
            "date", "datetime", "timestamp", "time", "year",
            "char", "varchar", "binary", "varbinary",
            "tinyblob", "blob", "mediumblob", "longblob",
            "tinytext", "text", "mediumtext", "longtext",
            "json",
            "geometry", "point", "linestring", "polygon",
            "multipoint", "multilinestring", "multipolygon", "geometrycollection",
        }
    )

    # -- capabilities ------------------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        """Four flags are version- or variant-dependent and read `False` unprobed.

        Roles and groups — a group maps onto a MySQL 8 role, so the two flags move together.
        `CREATE OR REPLACE VIEW`, which §4.3 floors at 5.7.  And `RETURNING`, which only
        MariaDB 10.5+ has.  `supports_create_or_replace_routine` is `False` on this engine
        unconditionally and at every version: MySQL has never had `CREATE OR REPLACE
        PROCEDURE`, so `edit_routine()` here is always a real drop-then-create, never
        version-gated the way MS-SQL's `CREATE OR ALTER` is.
        """

        probed = self.probed
        version = self._traits.version if probed else ()
        mariadb = probed and self._traits.variant == "mariadb"

        roles = probed and version >= (_ROLES_FLOOR_MARIADB if mariadb else _ROLES_FLOOR_MYSQL)
        or_replace_view = probed and version >= (
            _OR_REPLACE_VIEW_FLOOR_MARIADB if mariadb else _OR_REPLACE_VIEW_FLOOR_MYSQL
        )
        return Capabilities(
            engine=Engine.MYSQL,
            supports_schemas=True,
            supports_stored_procedures=True,
            # MySQL has no table-valued function of any kind: a stored function returns a
            # scalar, full stop.
            supports_table_valued_functions=False,
            supports_roles=roles,
            supports_users=True,
            supports_groups=roles,
            supports_create_or_replace_view=or_replace_view,
            supports_create_or_replace_routine=False,
            # Every CREATE, ALTER and DROP commits the open transaction implicitly, asked to
            # or not.  Script.atomic is therefore False for every DDL-bearing script here.
            supports_transactional_ddl=False,
            supports_alter_column=True,
            supports_returning=probed and mariadb and version >= _RETURNING_FLOOR_MARIADB,
            supports_cross_database_reference=True,
            # `WITH`, at every supported version of MySQL and MariaDB, introduces a read-only
            # common table expression.  There is no MERGE and no data-modifying CTE.
            supports_data_modifying_cte=False,
            max_identifier_length=self.max_identifier_length,
            param_style=self.param_style,
            probed=probed,
        )

    @property
    def case_folding(self) -> CaseFolding:
        """Governed by `lower_case_table_names`, which is a server setting and a host
        filesystem consequence, so it must be probed.

        `0` stores as given and compares case-**sensitively** (the Linux default); `1`
        lower-cases on creation and compares insensitively (the Windows default, and mandated
        on macOS from 8.0); `2` stores as given and compares insensitively (macOS on a
        case-preserving filesystem).  MySQL 8.0 rejects a change to the setting after
        initialisation, so the probed value is stable for the life of the server and may be
        cached with the pool.
        """

        lctn = self._lower_case_table_names()
        if lctn == 0:
            return CaseFolding.PRESERVE_CASE_SENSITIVE
        if lctn == 1:
            return CaseFolding.FOLD_LOWER
        return CaseFolding.PRESERVE_CASE_INSENSITIVE

    def _lower_case_table_names(self) -> int:
        """The probed setting, refusing to guess.

        A default of 0 would make every rule case-sensitive on a Windows server where the
        engine is not, so a rule for `salaries` would stop matching `Salaries` — the deny
        direction, but the *wrong* deny, and impossible to debug from the GUI.
        """

        lctn = self.traits.lower_case_table_names
        if lctn is None:
            raise DialectNotConfiguredError(
                "the MySQL probe did not return @@lower_case_table_names, so identifier "
                "folding is unknown. d-MCP will not guess it: on this engine the setting "
                "decides whether two names are one object or two."
            )
        if lctn not in (0, 1, 2):
            raise DialectError(f"unexpected @@lower_case_table_names value {lctn!r}")
        return lctn

    # -- quoting and normalisation -----------------------------------------------------

    def quote_identifier(self, name: str) -> str:
        """`` `name` ``, with any inner backtick doubled.

        Two prohibitions beyond the shared ones.  A trailing space is refused because MySQL
        refuses it too — but only sometimes, depending on `sql_mode` and version, and where
        it is accepted the name is silently stripped, so `` `sales ` `` and `` `sales` ``
        become one object.  A `/` or `\\` is refused because database and table names become
        directory and file names on disk, and those two characters escape the data directory.
        """

        if isinstance(name, str):
            if name.endswith(" "):
                raise InvalidIdentifierError(
                    "a MySQL identifier cannot end with a space: the server strips it, and "
                    "the stripped name may already belong to a different object"
                )
            if "/" in name or "\\" in name:
                raise InvalidIdentifierError(
                    "a MySQL database or table name maps onto a directory or file name; "
                    "'/' and '\\\\' are refused because they escape the data directory"
                )
        return self._quote(name)

    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str:
        """The stored form: lower-cased under `lower_case_table_names = 1`, verbatim under
        `0` and `2`.  Quoting makes no difference on this engine — the setting applies either
        way — so `quoted` is accepted for interface symmetry and ignored.

        Raises `DialectNotConfiguredError` before `configure()`: the answer is a property of
        the server, not of the engine.
        """

        if not isinstance(raw, str) or raw == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        if self._lower_case_table_names() == 1:
            return fold_ascii_lower(raw, engine=self.engine)
        return raw

    def identifier_match_key(self, name: str) -> str:
        """ASCII-lower, except under `lower_case_table_names = 0` where names are compared
        case-sensitively and the key is the canonical form.

        This answers for *database, table and alias* names only.  Column, index,
        stored-routine and event names are case-insensitive on every platform regardless of
        the setting — see `column_match_key()` — and trigger names are case-*sensitive*, a
        MySQL deviation from the standard rather than a slip here.  `normalise_ref()` is the
        supported entrance precisely because this method cannot tell which kind it was handed.
        """

        if not isinstance(name, str) or name == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        if self._lower_case_table_names() == 0:
            return name
        return fold_ascii_lower(name, engine=self.engine)

    def column_match_key(self, name: str) -> str:
        """Always ASCII-lower, and answerable without a probe.

        Column names are case-insensitive on every MySQL and MariaDB platform whatever
        `lower_case_table_names` says, so this is the one identifier question on this engine
        the server cannot change the answer to.
        """

        if not isinstance(name, str) or name == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        return fold_ascii_lower(name, engine=self.engine)

    # -- what the guard borrows --------------------------------------------------------

    def guard_traits(self) -> GuardTraits:
        """MySQL grammar facts, including the one genuine injection vector in the set.

        `/*! ... */` is an *executable* comment: MySQL runs what is inside it while every
        other engine, every generic tokeniser and every human skimming the query treats it as
        inert.  `SELECT 1 /*!50000 ; DROP TABLE users */;` drops the table on 5.0 and above
        and is dead text everywhere else.  The pattern here only detects the opening
        sequence; the guard's rule is to refuse the statement outright the moment it matches,
        never to parse what follows, because that content obeys the same grammar and can hide
        another layer of the same trick.

        `--` is listed as a line-comment prefix even though MySQL requires a following space
        or control character to treat it as one; the distinction belongs to the tokeniser,
        and the safe direction for the guard is to over-recognise a comment start, not under.
        """

        return GuardTraits(
            write_keywords=frozenset({"INSERT", "UPDATE", "DELETE", "REPLACE", "TRUNCATE"}),
            ddl_keywords=frozenset({"CREATE", "ALTER", "DROP"}),
            security_keywords=frozenset(
                {
                    "GRANT",
                    "REVOKE",
                    "CREATE USER",
                    "ALTER USER",
                    "DROP USER",
                    "RENAME USER",
                    "CREATE ROLE",
                    "DROP ROLE",
                    "SET ROLE",
                    "SET DEFAULT ROLE",
                    "SET PASSWORD",
                    "FLUSH PRIVILEGES",
                }
            ),
            line_comment_prefixes=("--", "#"),
            block_comment_delimiters=("/*", "*/"),
            executable_comment_pattern=re.compile(r"/\*!"),
            batch_separator_pattern=None,
            writing_cte_shape=WritingCTEShape.NONE,
        )

    # -- connection --------------------------------------------------------------------

    def build_dsn(self, profile: ConnectionProfile) -> dict[str, Any]:
        """Keyword arguments for the bound driver, never the password.

        The two drivers take the same engine and the same `ParamStyle` but different keyword
        spellings for the timeouts — `connect_timeout`/`read_timeout` for PyMySQL,
        `connection_timeout` for mysql-connector-python — which is why the dialect is told
        which driver it is serving at construction.

        `charset` is always sent explicitly.  PyMySQL's own default is `latin1`, a silent
        mojibake trap for anything outside ASCII that has caught out more than one
        integration: the data arrives, it is simply wrong, and nothing errors.
        """

        auth_mode = self._profile_auth_mode(profile)
        if auth_mode == "none":
            raise DialectError(
                "auth_mode 'none' means there is no authentication step at all, which is "
                "true of a SQLite file and of nothing else."
            )
        # Neither driver is ever asked to try: `auth_socket` needs a Unix domain socket and
        # an account name equal to the operating-system account, and the Windows plugin
        # ships only with MySQL Enterprise.  Refusing here with the matrix's own sentence is
        # more useful than a timeout the user reads as a network fault.
        self._refuse_integrated(profile, self.driver or "pymysql")

        dsn: dict[str, Any] = {
            "host": self._require(profile, "host"),
            "port": self._profile_port(profile),
            "database": self._require(profile, "database"),
            "charset": "utf8mb4",
        }
        username = profile.get("username")
        if username:
            dsn["user"] = str(username)

        timeout = self._profile_timeout(profile)
        if timeout:
            if self.driver == "mysql-connector-python":
                dsn["connection_timeout"] = timeout
            else:
                # PyMySQL has no statement timeout; a read timeout is the closest thing it
                # offers, and it is honest to say so rather than to pretend the profile's
                # statement_timeout_s is being enforced server-side.  Where a real one is
                # needed, engine.py can additionally issue SET SESSION MAX_EXECUTION_TIME,
                # which MySQL applies to SELECT only.
                dsn["connect_timeout"] = timeout
                dsn["read_timeout"] = timeout
                dsn["write_timeout"] = timeout

        dsn.update(self._profile_options(profile))
        if "password" in dsn or "passwd" in dsn:
            raise DialectError("options_json must not carry a password; use the credential store")
        return dsn

    def health_check_sql(self) -> str:
        """`SELECT 1`."""

        return "SELECT 1"

    def version_probe_sql(self) -> str:
        """One row: version, server banner, folding setting, collation, database, user.

        `@@lower_case_table_names` is the column that matters most — without it
        `normalise_identifier()` refuses to answer at all — and it is a session-readable
        system variable, so no privilege beyond CONNECT is needed for the probe.
        """

        return (
            "SELECT VERSION(), @@version_comment, @@lower_case_table_names, "
            "@@collation_database, DATABASE(), CURRENT_USER()"
        )

    @classmethod
    def parse_traits(cls, rows: Sequence[Sequence[Any]]) -> ServerTraits:
        """Build `ServerTraits`, separating MariaDB from MySQL and stripping the `5.5.5-` lie."""

        if not rows:
            raise DialectError("the MySQL version probe returned no rows")
        row = tuple(rows[0])
        if len(row) < 6:
            raise DialectError(f"the MySQL version probe returned {len(row)} columns, expected 6")

        raw_version = "" if row[0] is None else str(row[0])
        banner = "" if row[1] is None else str(row[1])
        haystack = f"{raw_version} {banner}".lower()

        if "mariadb" in haystack:
            variant = "mariadb"
        elif "tidb" in haystack:
            variant = "tidb"
        elif "percona" in haystack:
            variant = "percona"
        else:
            variant = "mysql"

        numeric = raw_version
        if variant == "mariadb" and numeric.startswith(_MARIADB_LEGACY_PREFIX):
            numeric = numeric[len(_MARIADB_LEGACY_PREFIX) :]
        match = _VERSION_RE.search(numeric)
        if match is None:
            raise DialectError(f"cannot parse a MySQL version out of {raw_version!r}")
        version = tuple(int(part) for part in match.group(1).split("."))

        lctn: int | None
        try:
            lctn = None if row[2] is None else int(row[2])
        except (TypeError, ValueError):
            lctn = None

        return ServerTraits(
            raw_version=raw_version,
            version=version,
            variant=variant,
            collation=None if row[3] is None else str(row[3]),
            # Deliberately None: on MySQL the collation governs *data* comparison, while
            # identifier case sensitivity comes from lower_case_table_names below.  Filling
            # this in from the collation name would invite a reader to key folding on the
            # wrong field, which is the mistake this whole section exists to prevent.
            case_sensitive_collation=None,
            lower_case_table_names=lctn,
            default_schema=None if row[4] is None else str(row[4]),
            current_user=None if row[5] is None else str(row[5]),
        )

    # -- session hardening --------------------------------------------------------------

    def _is_mariadb(self) -> bool:
        return self.probed and self.traits.variant == "mariadb"

    def _read_only_variable(self) -> str:
        """The session variable that reports whether this transaction may write.

        Named from the probe because the two families renamed it in opposite decades — see
        the floors above.  Unprobed, the modern spelling is returned: `engine.py` probes
        before it hardens anything, so an unprobed dialect here means a caller that opened a
        session with `probe=False`, and MySQL 8 is the server it will most often be against.
        """

        if not self.probed:
            return "@@session.transaction_read_only"
        floor = _READ_ONLY_VARIABLE_FLOOR_MARIADB if self._is_mariadb() else _READ_ONLY_VARIABLE_FLOOR_MYSQL
        if self.traits.version >= floor:
            return "@@session.transaction_read_only"
        return "@@session.tx_read_only"

    def read_only_session(self) -> ReadOnlySession:
        """`SET SESSION TRANSACTION READ ONLY`, preceded by the `ROLLBACK` that gives it effect.

        The statement DESIGN-MCP-TOOLS.md §9.1 step 11 names sets the *default* mode for
        transactions started from now on; it does not convert a transaction that is already
        open.  Both MySQL drivers d-MCP ships default to `autocommit=0`, and InnoDB opens a
        transaction on the first statement of a session and keeps it open until something
        commits, so on a pooled session the transaction carrying the read would have been
        started before the hardening and would still be read-write.  The `ROLLBACK` closes it,
        so the transaction the read runs in is one that started after the mode changed.

        As on PostgreSQL, entering therefore discards uncommitted work on this connection, and
        as on PostgreSQL the read path never has any.

        A write in a read-only transaction fails with `ERROR 1792
        (25006): Cannot execute statement in a READ ONLY transaction`.  DDL is the honest
        caveat: it commits implicitly, and whether the implicit commit or the read-only check
        wins has varied between MySQL versions, so the guard — which refuses DDL outright on a
        read path — remains the primary defence against `CREATE`/`DROP` and this is the
        secondary one against `INSERT`/`UPDATE`/`DELETE`.

        The release restores the session default explicitly, because `SESSION` scope outlives
        the transaction that the `ROLLBACK` before it ends.
        """

        return ReadOnlySession(
            harden=(
                self._session_statement("ROLLBACK"),
                self._session_statement("SET SESSION TRANSACTION READ ONLY"),
            ),
            release=(
                self._session_statement("ROLLBACK"),
                self._session_statement("SET SESSION TRANSACTION READ WRITE"),
            ),
            verify=self._session_statement(f"SELECT {self._read_only_variable()}"),
            verify_released=self._session_statement(f"SELECT {self._read_only_variable()}"),
            scope=ReadOnlyScope.SESSION,
            enforcement=ReadOnlyEnforcement.REFUSES,
            note="MySQL read-only transaction mode; a write raises 1792 in SQLSTATE 25006",
        )

    def statement_timeout_statements(self, seconds: int) -> tuple[Query, ...]:
        """`max_execution_time` on MySQL, `max_statement_time` on MariaDB.

        Neither is quite PostgreSQL's `statement_timeout`: MySQL's applies to read-only
        `SELECT` statements only — which is, at least, exactly the statement class this
        matters for on a read path — and MariaDB's is a float in seconds rather than an
        integer in milliseconds.  Applying the wrong one is `ERROR 1193: Unknown system
        variable`, so this refuses to guess before the probe rather than take the connection
        out with a `SET` it cannot know the server understands.
        """

        budget = self._timeout_literal(seconds)
        if not self.probed:
            raise DialectNotConfiguredError(
                "the MySQL statement timeout cannot be set before the version probe: "
                "MySQL and MariaDB spell the variable differently and the wrong one is a "
                "fatal 'Unknown system variable'"
            )
        version = self.traits.version
        if self._is_mariadb():
            if version < _MAX_STATEMENT_TIME_FLOOR_MARIADB:
                return ()
            return (self._session_statement(f"SET SESSION max_statement_time = {budget}"),)
        if version < _MAX_EXECUTION_TIME_FLOOR_MYSQL:
            return ()
        return (self._session_statement(f"SET SESSION max_execution_time = {budget * 1000}"),)

    # -- catalogue introspection -------------------------------------------------------

    #: `INFORMATION_SCHEMA` relations the builders below read, as `Query.touches` entries.
    #: They are views on this engine (temporary tables before 8.0, which changes nothing a
    #: caller can observe from here).
    _IS_SCHEMATA = ObjectRef(schema="information_schema", name="SCHEMATA", object_type=ObjectType.VIEW)
    _IS_TABLES = ObjectRef(schema="information_schema", name="TABLES", object_type=ObjectType.VIEW)
    _IS_VIEWS = ObjectRef(schema="information_schema", name="VIEWS", object_type=ObjectType.VIEW)
    _IS_COLUMNS = ObjectRef(schema="information_schema", name="COLUMNS", object_type=ObjectType.VIEW)
    _IS_ROUTINES = ObjectRef(schema="information_schema", name="ROUTINES", object_type=ObjectType.VIEW)
    _IS_PARAMETERS = ObjectRef(schema="information_schema", name="PARAMETERS", object_type=ObjectType.VIEW)
    _IS_KCU = ObjectRef(
        schema="information_schema", name="KEY_COLUMN_USAGE", object_type=ObjectType.VIEW
    )
    _IS_TC = ObjectRef(
        schema="information_schema", name="TABLE_CONSTRAINTS", object_type=ObjectType.VIEW
    )
    _IS_RC = ObjectRef(
        schema="information_schema", name="REFERENTIAL_CONSTRAINTS", object_type=ObjectType.VIEW
    )
    _IS_TABLE_PRIVILEGES = ObjectRef(
        schema="information_schema", name="TABLE_PRIVILEGES", object_type=ObjectType.VIEW
    )
    #: The grant tables themselves.  Ordinary tables in the `mysql` database rather than
    #: information_schema views, and readable only by a principal with `SELECT` on that
    #: database — which is stated in the docstrings of the two builders that read them.
    _MYSQL_USER = ObjectRef(schema="mysql", name="user", object_type=ObjectType.TABLE)
    _MYSQL_ROLE_EDGES = ObjectRef(schema="mysql", name="role_edges", object_type=ObjectType.TABLE)
    _MYSQL_ROLES_MAPPING = ObjectRef(
        schema="mysql", name="roles_mapping", object_type=ObjectType.TABLE
    )

    #: The four schemas the server owns.  `sys` is MySQL 5.7+ and MariaDB 10.6+; naming it on
    #: a server that has none costs nothing, which is why the list is a constant rather than
    #: another version branch.
    _SYSTEM_SCHEMAS = "('mysql', 'information_schema', 'performance_schema', 'sys')"

    #: The same four as a Python set, for a caller that wants to mark a name it already
    #: holds rather than to filter in SQL.  Rendered from one source in both directions
    #: would need a tuple and a join at import time; the pair is kept in step by a test
    #: instead, which is cheaper to read than the generator would be.
    SYSTEM_DATABASES: ClassVar[frozenset[str]] = frozenset(
        {"mysql", "information_schema", "performance_schema", "sys"}
    )

    #: The routine signature, assembled from `INFORMATION_SCHEMA.PARAMETERS`.  MySQL has no
    #: overloading, so this is display text rather than an identity — but it is the text the
    #: Explorer page shows beside the routine name, and reading `IN qty INT` there is the
    #: difference between a usable list and a list of bare names.
    _SIGNATURE_SUBQUERY = (
        "(SELECT GROUP_CONCAT(CONCAT_WS(' ', NULLIF(sp.PARAMETER_MODE, ''), "
        "                     sp.PARAMETER_NAME, sp.DTD_IDENTIFIER) "
        "        ORDER BY sp.ORDINAL_POSITION SEPARATOR ', ') "
        " FROM INFORMATION_SCHEMA.PARAMETERS AS sp "
        " WHERE sp.SPECIFIC_SCHEMA = r.ROUTINE_SCHEMA "
        "   AND sp.SPECIFIC_NAME = r.ROUTINE_NAME "
        "   AND sp.ROUTINE_TYPE = r.ROUTINE_TYPE "
        # Position 0 is a function's return type, not a parameter, and putting it in the
        # signature would read as an unnamed first argument.
        "   AND sp.ORDINAL_POSITION > 0)"
    )

    def list_databases(self, *, include_system: bool = False) -> Query:
        """The schemas this account holds some privilege on, the server's own four marked.

        On this engine a database and a schema are the same object, so this differs from
        `list_schemas()` only in what it returns about each one and in offering to keep the
        system four.

        **Not `SHOW DATABASES`.**  `SHOW` is a dialect statement the guard has no reason to
        learn to classify, and teaching a security chokepoint a new statement family to
        fill a combo box is a bad trade.  `information_schema.schemata` is ordinary SQL,
        already classified as a read, and the server filters it to what the account may see
        — which means an unprivileged login gets a *short list*, frequently just
        `information_schema`, and never an error.  That is a correctly configured account,
        not a broken one.
        """

        clause = (
            "" if include_system else f"WHERE s.SCHEMA_NAME NOT IN {self._SYSTEM_SCHEMAS} "
        )
        return self._catalogue_query(
            "SELECT s.SCHEMA_NAME AS database_name, "
            "s.DEFAULT_CHARACTER_SET_NAME, "
            "s.DEFAULT_COLLATION_NAME, "
            f"(s.SCHEMA_NAME IN {self._SYSTEM_SCHEMAS}) AS is_system "
            "FROM INFORMATION_SCHEMA.SCHEMATA AS s "
            f"{clause}"
            "ORDER BY is_system, s.SCHEMA_NAME",
            touches=(self._IS_SCHEMATA,),
        )

    @property
    def bootstrap_database(self) -> str | None:
        """`information_schema` — every account may see it.

        MySQL is also happy with no default schema at all, and `engine.py` may omit the
        database entirely; naming `information_schema` keeps the bootstrap profile the same
        shape as the other engines' rather than making one of the four special.
        """

        return "information_schema"

    def list_schemas(self) -> Query:
        """The databases this login can see, the server's own four excluded.

        `INFORMATION_SCHEMA.SCHEMATA` is already filtered by the server to the databases the
        current user holds some privilege on, so no explicit privilege test is needed here —
        unlike PostgreSQL, whose catalogue is world-readable.
        """

        return self._catalogue_query(
            "SELECT s.SCHEMA_NAME AS schema_name "
            "FROM INFORMATION_SCHEMA.SCHEMATA AS s "
            f"WHERE s.SCHEMA_NAME NOT IN {self._SYSTEM_SCHEMAS} "
            "ORDER BY s.SCHEMA_NAME",
            touches=(self._IS_SCHEMATA,),
        )

    def list_tables(self, schema: str | None = None) -> Query:
        """Base tables.  `TABLE_TYPE` separates them from views and from `SYSTEM VIEW`."""

        clause, values, names = self._schema_filter(schema, "t.TABLE_SCHEMA")
        return self._catalogue_query(
            "SELECT t.TABLE_SCHEMA AS schema_name, t.TABLE_NAME AS table_name, "
            # An InnoDB table with no comment reports the empty string, and older servers
            # put "InnoDB free: ..." here; the empty case is normalised away so the GUI
            # shows nothing rather than a blank tooltip.
            "NULLIF(t.TABLE_COMMENT, '') AS table_comment "
            "FROM INFORMATION_SCHEMA.TABLES AS t "
            "WHERE t.TABLE_TYPE = 'BASE TABLE' "
            f"  AND t.TABLE_SCHEMA NOT IN {self._SYSTEM_SCHEMAS}"
            f"{clause} "
            "ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME",
            values,
            names,
            touches=(self._IS_TABLES,),
        )

    def list_views(self, schema: str | None = None) -> Query:
        """Views.  Neither MySQL nor MariaDB has a materialised view, so the flag is always 0
        — and it is emitted anyway, so the row shape does not change between engines."""

        clause, values, names = self._schema_filter(schema, "t.TABLE_SCHEMA")
        return self._catalogue_query(
            "SELECT t.TABLE_SCHEMA AS schema_name, t.TABLE_NAME AS view_name, "
            "0 AS is_materialised, NULLIF(t.TABLE_COMMENT, '') AS view_comment "
            "FROM INFORMATION_SCHEMA.TABLES AS t "
            "WHERE t.TABLE_TYPE = 'VIEW' "
            f"  AND t.TABLE_SCHEMA NOT IN {self._SYSTEM_SCHEMAS}"
            f"{clause} "
            "ORDER BY t.TABLE_SCHEMA, t.TABLE_NAME",
            values,
            names,
            touches=(self._IS_TABLES,),
        )

    def _list_routines(self, schema: str | None, *, procedure: bool) -> Query:
        """The shared body of `list_functions()` and `list_procedures()`."""

        routine_type = "PROCEDURE" if procedure else "FUNCTION"
        clause, values, names = self._schema_filter(schema, "r.ROUTINE_SCHEMA")
        return self._catalogue_query(
            "SELECT r.ROUTINE_SCHEMA AS schema_name, r.ROUTINE_NAME AS routine_name, "
            f"{self._SIGNATURE_SUBQUERY} AS signature, "
            # DTD_IDENTIFIER is the declared return type of a function and NULL for a
            # procedure, which is exactly the distinction the row shape wants.
            "NULLIF(r.DTD_IDENTIFIER, '') AS `returns`, "
            "r.ROUTINE_BODY AS `language`, "
            "CASE WHEN r.IS_DETERMINISTIC = 'YES' THEN 1 ELSE 0 END AS is_deterministic "
            "FROM INFORMATION_SCHEMA.ROUTINES AS r "
            # A literal this module writes, never caller input: the two values are the only
            # two ROUTINE_TYPE the server stores.
            f"WHERE r.ROUTINE_TYPE = '{routine_type}' "
            f"  AND r.ROUTINE_SCHEMA NOT IN {self._SYSTEM_SCHEMAS}"
            f"{clause} "
            "ORDER BY r.ROUTINE_SCHEMA, r.ROUTINE_NAME",
            values,
            names,
            touches=(self._IS_ROUTINES, self._IS_PARAMETERS),
        )

    def list_functions(self, schema: str | None = None) -> Query:
        """Stored functions.  MySQL has no table-valued function and no aggregate a user can
        define in SQL, so `ROUTINE_TYPE = 'FUNCTION'` is the whole of it."""

        return self._list_routines(schema, procedure=False)

    def list_procedures(self, schema: str | None = None) -> Query:
        """Stored procedures."""

        return self._list_routines(schema, procedure=True)

    def _object_where(self, ref: NormalisedRef, schema_column: str, name_column: str) -> str:
        """`WHERE <schema> = COALESCE(?, DATABASE()) AND <name> = ?`, in that parameter order.

        The `COALESCE` is not defensive padding.  `normalise_ref()` fills an absent schema
        from `effective_default_schema()`, which on this engine is only known once the probe
        has read it, so a reference minted before `configure()` still carries
        `canonical_schema=None`.  Comparing a column to `NULL` is never true, so without this
        such a `describe_table()` would return an empty description and look like a missing
        table.  `DATABASE()` is the connection's own database, which is precisely the schema
        an unqualified reference means.
        """

        return (
            f"WHERE {schema_column} = COALESCE({self.placeholder(0, 'schema')}, DATABASE()) "
            f"  AND {name_column} = {self.placeholder(1, 'name')}"
        )

    def _column_default_expression(self) -> str:
        """`COLUMN_DEFAULT`, with MariaDB's literal string `NULL` normalised away.

        From 10.2, MariaDB reports `COLUMN_DEFAULT` as a quoted *expression* rather than a
        value, and a column with no default reports the four characters `NULL` instead of SQL
        NULL.  Taken at face value that becomes "this column defaults to the string NULL" in
        the GUI and in the MCP tool result, on every nullable column in the database.  MySQL
        reports a real NULL, so the rewrite is confined to the MariaDB branch: on MySQL a
        column genuinely declared `DEFAULT 'NULL'` reports the bare word too, and there the
        `NULLIF` would erase a real default.
        """

        if self.probed and self.traits.variant == "mariadb":
            return "NULLIF(c.COLUMN_DEFAULT, 'NULL')"
        return "c.COLUMN_DEFAULT"

    def describe_table(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Columns, primary key, unique keys, foreign keys, from `INFORMATION_SCHEMA`.

        A caveat that belongs on the record rather than in a bug report later: MariaDB 10.2+
        quotes a string default (`'abc'`) where MySQL does not (`abc`).  Both are passed
        through as the engine reported them, because `ColumnInfo.data_type` and
        `ColumnInfo.default` are documented as the engine's own spelling and normalising one
        of the two would make the pair inconsistent.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        columns = self._catalogue_query(
            "SELECT c.COLUMN_NAME AS column_name, "
            # COLUMN_TYPE, not DATA_TYPE: the former is `varchar(50)` and the latter is
            # `varchar`, and a caller told only the second cannot know what it may store.
            "c.COLUMN_TYPE AS data_type, "
            "CASE WHEN c.IS_NULLABLE = 'YES' THEN 1 ELSE 0 END AS is_nullable, "
            f"{self._column_default_expression()} AS column_default, "
            "CASE WHEN LOCATE('auto_increment', LOWER(c.EXTRA)) > 0 THEN 1 ELSE 0 END "
            "     AS is_identity, "
            # Tested against the two full phrases, not against 'GENERATED' alone: MySQL
            # 8.0.13 writes 'DEFAULT_GENERATED' in EXTRA for an expression *default*, which
            # a substring test would report as a generated column.
            "CASE WHEN LOCATE('VIRTUAL GENERATED', UPPER(c.EXTRA)) > 0 "
            "       OR LOCATE('STORED GENERATED', UPPER(c.EXTRA)) > 0 THEN 1 ELSE 0 END "
            "     AS is_generated, "
            "c.ORDINAL_POSITION AS ordinal_position, "
            "NULLIF(c.COLUMN_COMMENT, '') AS column_comment "
            "FROM INFORMATION_SCHEMA.COLUMNS AS c "
            f"{self._object_where(ref, 'c.TABLE_SCHEMA', 'c.TABLE_NAME')} "
            "ORDER BY c.ORDINAL_POSITION",
            values,
            names,
            touches=(self._IS_COLUMNS,),
        )

        def key_query(constraint_type: str) -> Query:
            return self._catalogue_query(
                "SELECT k.CONSTRAINT_NAME AS constraint_name, k.COLUMN_NAME AS column_name, "
                "k.ORDINAL_POSITION AS key_ordinal "
                "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS k "
                "JOIN INFORMATION_SCHEMA.TABLE_CONSTRAINTS AS tc "
                "     ON tc.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA "
                "    AND tc.CONSTRAINT_NAME = k.CONSTRAINT_NAME "
                "    AND tc.TABLE_SCHEMA = k.TABLE_SCHEMA "
                "    AND tc.TABLE_NAME = k.TABLE_NAME "
                f"{self._object_where(ref, 'k.TABLE_SCHEMA', 'k.TABLE_NAME')} "
                # A literal written here, never input: the two values are the only two this
                # method is ever called with.
                f"  AND tc.CONSTRAINT_TYPE = '{constraint_type}' "
                "ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION",
                values,
                names,
                touches=(self._IS_KCU, self._IS_TC),
            )

        primary_key = key_query("PRIMARY KEY")
        unique_keys = key_query("UNIQUE")

        foreign_keys = self._catalogue_query(
            "SELECT k.CONSTRAINT_NAME AS constraint_name, k.COLUMN_NAME AS column_name, "
            "k.ORDINAL_POSITION AS key_ordinal, "
            "k.REFERENCED_TABLE_SCHEMA AS referenced_schema, "
            "k.REFERENCED_TABLE_NAME AS referenced_table, "
            "k.REFERENCED_COLUMN_NAME AS referenced_column, "
            "rc.DELETE_RULE AS on_delete, rc.UPDATE_RULE AS on_update "
            "FROM INFORMATION_SCHEMA.KEY_COLUMN_USAGE AS k "
            "JOIN INFORMATION_SCHEMA.REFERENTIAL_CONSTRAINTS AS rc "
            "     ON rc.CONSTRAINT_SCHEMA = k.CONSTRAINT_SCHEMA "
            "    AND rc.CONSTRAINT_NAME = k.CONSTRAINT_NAME "
            "    AND rc.TABLE_NAME = k.TABLE_NAME "
            f"{self._object_where(ref, 'k.TABLE_SCHEMA', 'k.TABLE_NAME')} "
            "  AND k.REFERENCED_TABLE_NAME IS NOT NULL "
            "ORDER BY k.CONSTRAINT_NAME, k.ORDINAL_POSITION",
            values,
            names,
            touches=(self._IS_KCU, self._IS_RC),
        )
        return (columns, primary_key, unique_keys, foreign_keys)

    def describe_routine(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """The routine header, then its parameters.

        Both `ROUTINE_TYPE` values are returned rather than filtered on `ref.object_type`: a
        function and a procedure may share a name on this engine, and showing the caller both
        rows is more useful than silently answering about the one d-MCP guessed at.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        header = self._catalogue_query(
            "SELECT r.ROUTINE_SCHEMA AS schema_name, r.ROUTINE_NAME AS routine_name, "
            "LOWER(r.ROUTINE_TYPE) AS routine_type, "
            f"{self._SIGNATURE_SUBQUERY} AS signature, "
            "NULLIF(r.DTD_IDENTIFIER, '') AS `returns`, "
            "r.ROUTINE_BODY AS `language`, "
            "CASE WHEN r.IS_DETERMINISTIC = 'YES' THEN 1 ELSE 0 END AS is_deterministic "
            "FROM INFORMATION_SCHEMA.ROUTINES AS r "
            f"{self._object_where(ref, 'r.ROUTINE_SCHEMA', 'r.ROUTINE_NAME')} "
            "ORDER BY r.ROUTINE_TYPE",
            values,
            names,
            touches=(self._IS_ROUTINES, self._IS_PARAMETERS),
        )
        parameters = self._catalogue_query(
            # No signature to key on: MySQL cannot overload, so every parameter row belongs
            # to the single routine the header returned.
            "SELECT NULL AS routine_signature, "
            "p.PARAMETER_NAME AS parameter_name, "
            "p.DTD_IDENTIFIER AS data_type, "
            # Ordinal 0 is the function's return type rather than a parameter, and it is
            # reported as such instead of being dropped: a caller reading the parameter list
            # of a function wants to see what comes back.
            "CASE WHEN p.ORDINAL_POSITION = 0 THEN 'RETURN' "
            "     ELSE COALESCE(NULLIF(p.PARAMETER_MODE, ''), 'IN') END AS parameter_mode, "
            "p.ORDINAL_POSITION AS ordinal_position, "
            # MySQL routine parameters cannot have defaults.  Emitted as a constant so the
            # row shape matches PostgreSQL's, where they can.
            "0 AS has_default "
            "FROM INFORMATION_SCHEMA.PARAMETERS AS p "
            f"{self._object_where(ref, 'p.SPECIFIC_SCHEMA', 'p.SPECIFIC_NAME')} "
            "ORDER BY p.ROUTINE_TYPE, p.ORDINAL_POSITION",
            values,
            names,
            touches=(self._IS_PARAMETERS,),
        )
        return (header, parameters)

    def object_definition(self, ref: NormalisedRef) -> Query:
        """`VIEW_DEFINITION` for a view, `ROUTINE_DEFINITION` for a routine.

        Both come back **empty rather than absent** when the current login lacks the
        privilege to read them — `SHOW VIEW` for a view, `SHOW_ROUTINE` (or `SELECT` on
        `mysql.proc` before 8.0) for a routine.  `NULLIF(..., '')` turns that into a NULL so
        `introspection.py` sees one "no text" case instead of two, and reports it as withheld
        rather than as an empty body: a caller shown a blank editor with no explanation will
        assume the routine is empty and try to write it.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        if ref.object_type is ObjectType.VIEW:
            return self._catalogue_query(
                "SELECT NULLIF(v.VIEW_DEFINITION, '') AS definition "
                "FROM INFORMATION_SCHEMA.VIEWS AS v "
                f"{self._object_where(ref, 'v.TABLE_SCHEMA', 'v.TABLE_NAME')}",
                values,
                names,
                touches=(self._IS_VIEWS,),
            )
        if ref.object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE):
            return self._catalogue_query(
                "SELECT NULLIF(r.ROUTINE_DEFINITION, '') AS definition "
                "FROM INFORMATION_SCHEMA.ROUTINES AS r "
                f"{self._object_where(ref, 'r.ROUTINE_SCHEMA', 'r.ROUTINE_NAME')} "
                # A function and a procedure can share a name; the caller asked about one.
                f"  AND r.ROUTINE_TYPE = '{ref.object_type.value.upper()}'",
                values,
                names,
                touches=(self._IS_ROUTINES,),
            )
        raise self._unsupported(
            "object_definition",
            f"MySQL stores no source text for a {ref.object_type}; only views, functions and "
            "procedures have a definition to read",
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

        The target goes through `quote_ref()`, which now keys off
        `capabilities.supports_schemas` and so qualifies the name on this engine.  It used
        to key off `default_schema`, `None` here because a MySQL "database" *is* its schema
        and the answer is the session's, not the engine's; that emitted a bare name and let
        the server resolve it against whatever database the session happened to be using
        rather than the one the permission check authorised.

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
                    schema=ref.canonical_schema,
                    name=ref.canonical_name,
                    object_type=ref.object_type,
                ),
            ),
            row_cap=row_cap,
        )

    # -- the write side (DESIGN-DIALECTS.md §3.4 and §3.6) -----------------------------

    def _identity_clause(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """`AUTO_INCREMENT`, which the server insists is indexed.

        Checked here rather than left to the server, because "there can be only one auto
        column and it must be defined as a key" is an error message that arrives with no
        indication of which column it means on a twelve-column `CREATE TABLE`.  The column
        must be in the primary key this call is also creating; an auto-increment column keyed
        by some other index is a table shape §11.3 puts out of reach on purpose.
        """

        keys = {self.column_match_key(column) for column in primary_key}
        if self.column_match_key(spec.name) not in keys:
            raise ValueError(
                f"column {spec.name!r} is an identity column, and MySQL requires an "
                "AUTO_INCREMENT column to be indexed: name it in the primary key"
            )
        return " AUTO_INCREMENT"

    def _column_ddl(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """The base assembly with `AUTO_INCREMENT` moved to the end.

        MySQL's `column_definition` grammar puts the attribute after `NOT NULL` and after
        `DEFAULT`, and the shared order — which suits the other three engines — would put it
        before both.  Overridden rather than made configurable with a flag, because the whole
        of the difference is where one token goes and a flag would hide that.
        """

        self._reject_column_comment(spec)
        piece = f"{self.quote_identifier(spec.name)} {self._validate_type(spec.data_type)}"
        piece += self._collate_clause(spec.collation)
        if spec.is_identity and spec.default is not None:
            raise ValueError(
                f"column {spec.name!r} is both an identity column and has a default; the "
                "server assigns one or the other, and no engine accepts both"
            )
        if not spec.nullable:
            piece += " NOT NULL"
        if spec.default is not None:
            piece += " DEFAULT " + self._default_literal(spec.default)
        if spec.is_identity:
            piece += self._identity_clause(spec, primary_key=primary_key)
        return piece

    def estimate_row_count(self, ref: NormalisedRef) -> Query:
        """`INFORMATION_SCHEMA.TABLES.TABLE_ROWS`, which is an estimate on InnoDB and exact on
        MyISAM — and the caller is told it is an estimate either way.

        InnoDB derives the number by sampling index pages, so it can be out by a wide margin
        on a table under write load and is documented by MySQL as possibly off by 40-50 %.
        That is the trade §3.3 asks for: the exact number for a predicated write comes from
        `count_matching()`, which is small by construction, and this is only ever the "and the
        table has roughly this many rows" line beside it.

        A view reports `NULL` here rather than a number, which is honest: MySQL does not
        materialise views and there is nothing stored to count.
        """

        if ref.object_type not in (ObjectType.TABLE, ObjectType.VIEW):
            raise ValueError(
                f"estimate_row_count() counts rows of a table or a view; {ref.object_type} "
                "is neither"
            )
        return self._catalogue_query(
            "SELECT t.TABLE_ROWS AS estimated_rows "
            "FROM INFORMATION_SCHEMA.TABLES AS t "
            + self._object_where(ref, "t.TABLE_SCHEMA", "t.TABLE_NAME"),
            (ref.canonical_schema, ref.canonical_name),
            ("schema", "name"),
            touches=(self._IS_TABLES,),
        )

    # -- 3.5 security ------------------------------------------------------------------
    #
    # The engine where a principal is not a name.  Identity here is the **pair**
    # `'user'@'host'`, the two halves are quoted separately, and `bob@localhost` and `bob@%`
    # are two different accounts with two different privilege sets that a listing showing only
    # the user half would present as one.  Every builder below therefore takes the host as its
    # own argument and never parses it out of the name: splitting on `@` would be a parser
    # applied to hostile text in the one layer that must not contain one, and it would be wrong
    # anyway — `@` is legal inside a quoted user name.
    #
    # A role is an account too.  `CREATE ROLE r` makes a row in `mysql.user` that is locked and
    # password-expired, with an empty host that MySQL reads as `%`; that is the whole of the
    # difference between a role and a user here, and `list_principals()` reads it back out.

    #: The privileges d-MCP will grant on a table or a view.
    #:
    #: `CREATE`, `DROP`, `ALTER`, `INDEX` and `CREATE VIEW` are absent for the reason SQL
    #: Server's `ALTER` and `CONTROL` are: at table scope each of them redefines or removes the
    #: object rather than using it, which is a change to the permission surface and belongs in
    #: a human's hands.  `TRIGGER` is absent for a reason peculiar to this engine — a MySQL
    #: trigger executes with its **definer's** privileges, so granting `TRIGGER` on a table is
    #: granting the ability to run arbitrary SQL as whoever defines the trigger.  `LOCK TABLES`
    #: and `EVENT` are absent as denial-of-service surface with no read or write value.
    relation_privileges: ClassVar[frozenset[str]] = frozenset(
        {"SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES", "SHOW VIEW"}
    )

    #: `EXECUTE` calls the routine.  `ALTER ROUTINE` would let the grantee replace its body,
    #: which destroys the previous one — an act d-MCP never performs through any tool of its
    #: own (docs/adr/0005).  Granting it would hand out as a privilege exactly what the
    #: product refuses by design.
    routine_privileges: ClassVar[frozenset[str]] = frozenset({"EXECUTE"})

    def _at_least(self, mysql: tuple[int, ...], mariadb: tuple[int, ...]) -> bool:
        """Whether the probed server is at or above its family's floor.

        Two floors rather than one because the two families version independently and a single
        number is wrong for one of them by several years.  Refuses to answer unprobed — every
        caller of this decides either what a statement will contain or whether it may be
        emitted at all, and both are worse guessed than refused.
        """

        floor = mariadb if self._is_mariadb() else mysql
        return self.traits.version >= floor

    def _require_roles(self, feature: str) -> None:
        """Refuse a role operation on a server that has no roles.

        Distinguishes "this server cannot" from "we have not asked it yet": unprobed,
        `capabilities.supports_roles` reads `False` by decision D2, and reporting that as
        "MySQL/MariaDB does not support roles" would be a lie about an 8.0 server.  Touching
        `traits` first raises `DialectNotConfiguredError` in that case, which is the truthful
        answer.
        """

        raw = self.traits.raw_version
        if not self.capabilities.supports_roles:
            raise self._unsupported(
                feature,
                "roles arrived in MySQL 8.0 and MariaDB 10.0.5, and this server reports "
                f"{raw}. d-MCP will not approximate a role with a dummy user account",
            )

    def _quote_account_part(self, part: str, *, limit: int, what: str) -> str:
        """Backtick-quote one half of an account name.

        MySQL accepts backticks, single quotes or double quotes around either half, and
        backticks are the one spelling whose meaning does not move with `sql_mode`:
        `ANSI_QUOTES` turns `"..."` into an identifier and `''` is a string literal whose
        escaping rules depend on `NO_BACKSLASH_ESCAPES`.  Backticks are an identifier delimiter
        under every mode, and the escape is the same doubling `quote_identifier()` applies.

        Not `quote_identifier()` itself, for two reasons that are both about the limit.  A user
        name is capped at 32 characters and a host name at 255, neither of which is the 64 that
        governs a table name; using the table rule would admit a user name the server refuses
        and refuse a host name the server accepts.  The rest of `quote_identifier()`'s
        prohibitions are reproduced here deliberately — a trailing space is stripped by the
        server, and `/` and `\\` have no business in either half.
        """

        if not isinstance(part, str) or part == "":
            raise InvalidIdentifierError(f"an account {what} must be a non-empty str")
        if part.endswith(" "):
            raise InvalidIdentifierError(
                f"an account {what} cannot end with a space: the server strips it, and the "
                "stripped name may already belong to a different account"
            )
        if "/" in part or "\\" in part:
            raise InvalidIdentifierError(
                f"'/' and '\\\\' are refused in an account {what}"
            )
        return self._quote(part, max_length=limit)

    def quote_principal(self, name: str, *, host: str | None = None) -> str:
        """`` `user`@`host` ``, or `` `name` `` where no host is given.

        The two halves are quoted **separately** and are never assembled by the caller, because
        they are separately escaped: a backtick in the user half is doubled inside the user
        half's delimiters and does not affect the host half at all.  Handing this method a
        pre-joined `bob@localhost` would quote the whole thing as one user name, producing the
        account `` `bob@localhost`@`%` `` — a different, and new, account.

        `host=None` means the principal is named without one.  MySQL resolves that as `name@%`,
        which is exactly right for a role — `CREATE ROLE r` creates `r` with an empty host —
        and is the caller's responsibility for a user account: a user is created here with a
        mandatory host, so anything that names one afterwards knows what it is.  `create_user()`
        is the one builder that refuses `host=None`, because there the default would not resolve
        an existing account but **create** a new one reachable from every address on the network.
        """

        user = self._quote_account_part(name, limit=_MAX_ACCOUNT_USER_LENGTH, what="user name")
        if host is None:
            return user
        return (
            user
            + "@"
            + self._quote_account_part(host, limit=_MAX_ACCOUNT_HOST_LENGTH, what="host name")
        )

    #: `mysql.user.Host` is the empty string for a role and a real pattern for an account, so
    #: the displayed name is the bare role name in the first case and `user@host` in the second.
    #: `CONCAT` is used rather than `||`, which on this engine is a logical OR unless
    #: `PIPES_AS_CONCAT` is set.
    _ACCOUNT_NAME = (
        "CASE WHEN u.Host = '' THEN u.User ELSE CONCAT(u.User, '@', u.Host) END"
    )

    def list_principals(self) -> Query:
        """Every account in `mysql.user`, with roles told apart from users by the columns the
        two families use for it.

        The name reported is the **pair**, `bob@localhost`, and not the user half alone.  On
        this engine the pair is the identity: `bob@localhost` and `bob@10.0.0.%` are two
        accounts with two privilege sets, and reporting them both as "bob" would show one
        principal where there are two and attribute one's grants to the other.

        Telling a role from a user needs a different column in each family.  MariaDB has
        `is_role`, which is unambiguous.  MySQL has none, and marks a role by locking the
        account *and* expiring its password — which is exactly what `CREATE ROLE` does and what
        nothing else does, since `create_user()` here locks the account but leaves the password
        unexpired.  That asymmetry is the reason `create_user()` does not add `PASSWORD EXPIRE`
        for tidiness: doing so would make every user d-MCP creates indistinguishable from a role
        in this listing.

        `mysql.user` needs `SELECT` on the `mysql` database, which an administrative connection
        has and an application connection does not.  There is no weaker source that answers the
        same question: `information_schema.USER_PRIVILEGES` lists grantees rather than accounts,
        so an account holding no global privilege is simply absent from it.  A connection
        without the privilege gets the server's own error, which says so plainly.
        """

        if self._is_mariadb():
            kind = "CASE WHEN u.is_role = 'Y' THEN 'role' ELSE 'user' END"
            native = "CASE WHEN u.is_role = 'Y' THEN 'role' ELSE 'user_account' END"
            if self.traits.version >= _ACCOUNT_LOCKED_COLUMN_FLOOR_MARIADB:
                can_login = (
                    "CASE WHEN u.is_role = 'Y' OR u.account_locked = 'Y' THEN 0 ELSE 1 END"
                )
            else:
                # No `account_locked` column before 10.4.2, and naming it would be ERROR 1054
                # against the whole statement rather than one column of it.
                can_login = "CASE WHEN u.is_role = 'Y' THEN 0 ELSE 1 END"
        else:
            role = "u.account_locked = 'Y' AND u.password_expired = 'Y'"
            kind = f"CASE WHEN {role} THEN 'role' ELSE 'user' END"
            native = f"CASE WHEN {role} THEN 'role' ELSE 'user_account' END"
            can_login = "CASE WHEN u.account_locked = 'Y' THEN 0 ELSE 1 END"
        return self._catalogue_query(
            f"SELECT {self._ACCOUNT_NAME} AS principal_name, "
            f"{kind} AS principal_kind, "
            f"{native} AS native_kind, "
            f"{can_login} AS can_login, "
            "CASE WHEN u.Super_priv = 'Y' THEN 1 ELSE 0 END AS is_superuser "
            "FROM mysql.user AS u "
            "ORDER BY u.User, u.Host",
            touches=(self._MYSQL_USER,),
        )

    def list_group_members(self, group: str) -> Query:
        """The accounts a role has been granted to, out of whichever grant table holds them.

        MySQL keeps role grants in `mysql.role_edges` and MariaDB in `mysql.roles_mapping`.
        Neither is an information_schema view and neither has an equivalent that is, so this
        needs `SELECT` on the `mysql` database exactly as `list_principals()` does.

        `group` is bound rather than quoted, and it is matched against the **user half** of the
        role's own account name: a role created as `CREATE ROLE r` is stored with an empty host,
        so comparing against a joined `r@%` would match nothing.
        """

        self._require_roles("list_group_members")
        canonical = self.normalise_identifier(group)
        self._quote_account_part(canonical, limit=_MAX_ACCOUNT_USER_LENGTH, what="user name")
        placeholder = self.placeholder(0, "group_name")
        if self._is_mariadb():
            sql = (
                "SELECT CASE WHEN m.Host = '' THEN m.User "
                "            ELSE CONCAT(m.User, '@', m.Host) END AS member_name, "
                "'user_account' AS member_native_kind, "
                "CASE WHEN m.Admin_option = 'Y' THEN 1 ELSE 0 END AS has_admin_option "
                "FROM mysql.roles_mapping AS m "
                f"WHERE m.Role = {placeholder} "
                "ORDER BY m.User, m.Host"
            )
            touches: tuple[ObjectRef, ...] = (self._MYSQL_ROLES_MAPPING,)
        else:
            sql = (
                "SELECT CASE WHEN e.TO_HOST = '' THEN e.TO_USER "
                "            ELSE CONCAT(e.TO_USER, '@', e.TO_HOST) END AS member_name, "
                "'user_account' AS member_native_kind, "
                "CASE WHEN e.WITH_ADMIN_OPTION = 'Y' THEN 1 ELSE 0 END AS has_admin_option "
                "FROM mysql.role_edges AS e "
                f"WHERE e.FROM_USER = {placeholder} "
                "ORDER BY e.TO_USER, e.TO_HOST"
            )
            touches = (self._MYSQL_ROLE_EDGES,)
        return self._catalogue_query(sql, (canonical,), ("group_name",), touches=touches)

    def list_grants(self, ref: NormalisedRef | None = None) -> Query:
        """Table and view privileges, out of `INFORMATION_SCHEMA.TABLE_PRIVILEGES`.

        The information_schema view rather than `mysql.tables_priv`, because it is readable by
        an ordinary connection and shows that connection what it is entitled to see, while the
        grant table behind it needs `SELECT` on the `mysql` database.  `list_principals()` has
        no such choice and says so; this one does, and takes it.

        Two kinds of grant are **not** reported, and the omissions are stated rather than left
        to be discovered.  Column-level privileges live in `COLUMN_PRIVILEGES` and would need a
        second query whose rows have no object of their own to sit against.  Routine privileges
        live in `mysql.procs_priv`, which has no information_schema equivalent at all — joining
        it in would take the whole listing out on any connection that cannot read the `mysql`
        database, so the readable answer is preferred to the complete one that usually fails.

        `state` is the constant `'GRANT'`: this engine has no `DENY`, and returning the column
        keeps the row shape identical across the four dialects.
        """

        clause = ""
        values: tuple[Any, ...] = ()
        names: tuple[str, ...] = ()
        if ref is None:
            clause = f"WHERE tp.TABLE_SCHEMA NOT IN {self._SYSTEM_SCHEMAS} "
        else:
            clause = self._object_where(ref, "tp.TABLE_SCHEMA", "tp.TABLE_NAME") + " "
            values = (ref.canonical_schema, ref.canonical_name)
            names = ("schema", "name")
        return self._catalogue_query(
            "SELECT tp.GRANTEE AS grantee, tp.PRIVILEGE_TYPE AS privilege, "
            "tp.TABLE_SCHEMA AS schema_name, tp.TABLE_NAME AS object_name, "
            "CASE WHEN tp.IS_GRANTABLE = 'YES' THEN 1 ELSE 0 END AS grantable, "
            "'GRANT' AS state "
            "FROM INFORMATION_SCHEMA.TABLE_PRIVILEGES AS tp "
            f"{clause}"
            "ORDER BY tp.TABLE_SCHEMA, tp.TABLE_NAME, tp.GRANTEE, tp.PRIVILEGE_TYPE",
            values,
            names,
            touches=(self._IS_TABLE_PRIVILEGES,),
        )

    def create_role(self, name: str) -> Script:
        """`CREATE ROLE `r``, on a server new enough to have roles.

        No host: a role created without one is stored with an empty host and resolves as `r@%`,
        which is what every subsequent `GRANT ... TO r` will name it by.  Giving a role a host
        is legal and would make it addressable only as `r@h`, which is a distinction nothing in
        d-MCP's vocabulary can express and every later call would have to remember.
        """

        self._require_roles("create_role")
        return self._security_script(f"CREATE ROLE {self.quote_principal(name)}")

    def create_user(
        self,
        name: str,
        *,
        host: str | None = None,
        login: str | None = None,
        default_schema: str | None = None,
    ) -> Script:
        """`CREATE USER `bob`@`localhost` ACCOUNT LOCK` — an account that cannot connect.

        `ACCOUNT LOCK` is the whole of the safety here and it is not optional.  A bare
        `CREATE USER bob@localhost` does not create an account without a password; it creates
        one whose authentication string is **empty**, and an empty authentication string is a
        password that `caching_sha2_password` and `mysql_native_password` will both accept from
        anyone who types nothing.  A locked account is refused at authentication with
        `ER_ACCOUNT_HAS_BEEN_LOCKED` before any credential is considered at all.

        The follow-up a human must perform is therefore *two* changes, not one, and the tool
        summary should say so: `ALTER USER ... IDENTIFIED BY '<password>' ACCOUNT UNLOCK`.
        Unlocking alone would leave the empty password in place.

        There is no `PASSWORD EXPIRE`, deliberately: on MySQL a locked *and* password-expired
        account is precisely how `CREATE ROLE` records a role, so adding it would make every
        user this tool creates read back as a role in `list_principals()`.

        `host` is mandatory, per §3.5, and a **wildcard** host is refused outright.  `%` and `_`
        are patterns rather than literals in this position, so `db_server.local` matches
        `dbXserver.local` whether or not the caller meant it to; and an account created for `%`
        is reachable from every address on the network, which is the widest thing this whole
        surface can author.  Neither is something d-MCP will create on a model's say-so.  A
        human can widen an account at the server, where the act is visible as what it is.

        `login` and `default_schema` are refused: MySQL has no login object separate from the
        account, and no per-account default database — the session's database is chosen at
        connect time or by `USE`, neither of which is a property of the user.
        """

        if login is not None:
            raise ValueError(
                "MySQL has no login object separate from the account: create_user() creates "
                "the account itself"
            )
        if default_schema is not None:
            raise ValueError(
                "MySQL has no per-account default database; the session's database is chosen "
                "at connect time or with USE, and is not a property of the user"
            )
        if host is None:
            raise ValueError(
                "MySQL identity is the pair 'user'@'host' and create_user() has no default "
                "host: defaulting to '%' would create an account reachable from anywhere on "
                "the network"
            )
        if "%" in host or "_" in host:
            raise ValueError(
                f"{host!r} is a host *pattern*, not a host: '%' and '_' are wildcards in this "
                "position, and d-MCP will not create an account whose reachable set it cannot "
                "state. Name one host, or widen the account by hand at the server."
            )
        if not self._at_least(_ACCOUNT_LOCK_FLOOR_MYSQL, _ACCOUNT_LOCK_FLOOR_MARIADB):
            raise self._unsupported(
                "create_user",
                "ACCOUNT LOCK arrived in MySQL 5.7.6 and MariaDB 10.4.2, and without it every "
                "account this layer could create would have an empty password; "
                f"{self.traits.raw_version} is below that floor, so the account must be "
                "created by a human at the server",
            )
        return self._security_script(
            f"CREATE USER {self.quote_principal(name, host=host)} ACCOUNT LOCK"
        )

    def create_group(self, name: str) -> Script:
        """`CREATE ROLE `g`` — a group is a role here, and there is no other object for it.

        Written out rather than delegating to `create_role()`, so that a later change to either
        cannot silently change the other.
        """

        self._require_roles("create_group")
        return self._security_script(f"CREATE ROLE {self.quote_principal(name)}")

    def _grant_role_script(self, role: str, principal: str, host: str | None) -> Script:
        """`GRANT `r` TO `u`@`h``, followed on MySQL by `SET DEFAULT ROLE ALL`.

        The second statement is what §3.5 asks for and it is not tidying: a role granted to an
        account on MySQL is **inert** until it is activated, so stopping at the `GRANT` leaves
        the human believing access was given and the next connection proving otherwise.  `ALL`
        rather than the role just granted, because `SET DEFAULT ROLE` replaces the whole default
        list and naming one role would silently deactivate every role the account already had.

        MariaDB gets the `GRANT` alone, which is also what §3.5 says — it scopes the extra
        statement to MySQL 8 — and here is why that is right rather than an oversight.  MariaDB
        allows an account exactly **one** default role, so `SET DEFAULT ROLE r FOR u` would
        replace whatever default the account already had with the role just granted, taking away
        an activation nobody asked to remove.  A MariaDB user activates a role with `SET ROLE`,
        which is a session act and not this layer's to perform.

        `Script.atomic` is `False` on this engine, so the two-statement form genuinely has a
        window between its steps.  It fails in the safe direction: a `GRANT` that succeeds
        without its `SET DEFAULT ROLE` leaves the role granted but inactive, which is less
        access than was asked for rather than more.
        """

        self._require_roles("assign_role")
        granted = (
            f"GRANT {self.quote_principal(role)} TO "
            f"{self.quote_principal(principal, host=host)}"
        )
        if self._is_mariadb():
            return self._security_script(granted)
        return self._security_script(
            granted,
            f"SET DEFAULT ROLE ALL TO {self.quote_principal(principal, host=host)}",
        )

    def _revoke_role_script(self, role: str, principal: str, host: str | None) -> Script:
        """`REVOKE `r` FROM `u`@`h``.

        One statement on both families: revoking a role removes it from the account's default
        role list as part of the same act, so there is no second statement to undo the one
        `_grant_role_script()` may have emitted.
        """

        self._require_roles("revoke_role")
        return self._security_script(
            f"REVOKE {self.quote_principal(role)} FROM "
            f"{self.quote_principal(principal, host=host)}"
        )

    def add_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`GRANT `g` TO `m`@`h`` — joining a group is being granted the role that is the group.

        `host` is the host half of the **member's** account name, not the group's: a group is a
        role and a role is named without a host.
        """

        return self._grant_role_script(group, member, host)

    def remove_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`REVOKE `g` FROM `m`@`h``."""

        return self._revoke_role_script(group, member, host)

    def assign_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`GRANT `r` TO `u`@`h``, plus `SET DEFAULT ROLE ALL` on MySQL."""

        return self._grant_role_script(role, principal, host)

    def revoke_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`REVOKE `r` FROM `u`@`h``."""

        return self._revoke_role_script(role, principal, host)

    def _grant_object(self, ref: NormalisedRef, arguments: str = "") -> str:
        """`` `db`.`t` ``, or `FUNCTION`/`PROCEDURE` where the object is a routine.

        `arguments` is always empty here and the parameter exists only so the four dialects
        answer one shape: MySQL permits no overloading, so `_routine_arguments_for()` has
        already refused any signature before this is reached.

        A routine grant must name its kind: `ON db.f` is a *table* grant on this engine even
        when `db.f` is a function, so omitting the keyword would compose a grant on a table
        that does not exist rather than on the routine the caller named.
        """

        quoted = self.quote_ref(ref)
        if ref.object_type in (ObjectType.TABLE, ObjectType.VIEW):
            return quoted
        if ref.object_type is ObjectType.FUNCTION:
            return f"FUNCTION {quoted}{arguments}"
        if ref.object_type is ObjectType.PROCEDURE:
            return f"PROCEDURE {quoted}{arguments}"
        raise ValueError(
            f"a grant on {ref.object_type} is not composable here: d-MCP grants on a table, "
            "a view, a function or a procedure"
        )

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
        """``GRANT SELECT, INSERT ON `db`.`t` TO `bob`@`localhost` [WITH GRANT OPTION]``.

        A `signature` is refused rather than ignored: MySQL has no overloading, so a caller
        passing one has a different object in mind from the one being permissioned.
        """

        target = self._check_grant_ref(ref)
        words = self._validated_privileges(privileges, target, what="grant")
        arguments = self._routine_arguments_for(target, signature, method="grant")
        option = " WITH GRANT OPTION" if with_grant_option else ""
        return self._security_script(
            f"GRANT {', '.join(words)} ON {self._grant_object(target, arguments)} TO "
            f"{self.quote_principal(principal, host=host)}{option}",
            touches=self._grant_touches(target),
        )

    def revoke(
        self,
        privileges: Sequence[str],
        ref: NormalisedRef | None,
        principal: str,
        *,
        host: str | None = None,
        signature: str | None = None,
    ) -> Script:
        """``REVOKE SELECT ON `db`.`t` FROM `bob`@`localhost```.

        A wildcard host is accepted here and refused by `create_user()`, and the asymmetry is
        deliberate: this statement names an account that already exists and takes access away
        from it.  Refusing `bob@%` would leave a d-MCP operator unable to narrow the very
        account whose breadth the refusal was worried about.
        """

        target = self._check_grant_ref(ref)
        words = self._validated_privileges(privileges, target, what="revoke")
        arguments = self._routine_arguments_for(target, signature, method="revoke")
        return self._security_script(
            f"REVOKE {', '.join(words)} ON {self._grant_object(target, arguments)} FROM "
            f"{self.quote_principal(principal, host=host)}",
            touches=self._grant_touches(target),
        )
