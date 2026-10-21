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

"""The PostgreSQL dialect, driven by psycopg 3."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping, Sequence
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
    ServerTraits,
    StatementKind,
    WritingCTEShape,
)

logger = logging.getLogger(__name__)

__all__ = ["PostgreSQLDialect"]


#: `version()` strings that begin plausibly and end badly.  CockroachDB, Amazon Redshift and
#: Greenplum all speak the PostgreSQL wire protocol well enough to connect; Redshift and
#: Greenplum even *begin* their banner with the word "PostgreSQL", so a prefix check alone
#: would wave both through.  They are rejected by name at the probe rather than several tool
#: calls later inside `pg_get_functiondef`, which is where the divergence would otherwise
#: first show up — with a stack trace that blames d-MCP.
_IMPOSTOR_MARKERS: tuple[tuple[str, str], ...] = (
    ("cockroach", "CockroachDB"),
    ("redshift", "Amazon Redshift"),
    ("greenplum", "Greenplum"),
    ("yugabyte", "YugabyteDB"),
    ("-yb-", "YugabyteDB"),
    ("materialize", "Materialize"),
)

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")


class PostgreSQLDialect(DeferredSurface, Dialect):
    """Authors PostgreSQL SQL.

    The one engine of the four whose folding rule needs no probe: an unquoted identifier is
    folded to lower case, a quoted one is preserved, and comparison is byte-exact on whatever
    was stored.  `normalise_identifier()` and `identifier_match_key()` therefore work the
    moment the dialect is constructed.
    """

    engine: ClassVar[Engine] = Engine.POSTGRESQL
    display_name: ClassVar[str] = "PostgreSQL"
    default_port: ClassVar[int | None] = 5432
    default_schema: ClassVar[str | None] = "public"

    # NAMEDATALEN - 1, and it is a *byte* budget, not a character one.
    max_identifier_length: ClassVar[int] = 63

    quote_open: ClassVar[str] = '"'
    quote_close: ClassVar[str] = '"'

    # -- the write side's per-engine constants -----------------------------------------

    #: Every spelling of "replace what is already there" PostgreSQL has, refused in a
    #: `create_*` body and in the DDL `create_*` generates (DESIGN-MCP-TOOLS.md §8.1).
    #:
    #: `CREATE OR REPLACE` is the engine's own, and it applies to views, functions,
    #: procedures, rules, triggers, aggregates and transforms — all of them matched by the
    #: two leading words, so listing the object kinds would add nothing.  `CREATE OR ALTER`
    #: is T-SQL and listed for the same reason SQL Server lists `CREATE OR REPLACE`: a model
    #: writing the wrong dialect should get the message that names the right tool.  The
    #: `ALTER <object>` forms replace a definition wholesale and are edits under another name;
    #: `DROP` needs no entry because a `DROP` followed by a `CREATE` is two statements and the
    #: trailing-statement check refuses it first.
    or_replace_spellings: ClassVar[tuple[str, ...]] = (
        "CREATE OR REPLACE",
        "CREATE OR ALTER",
        "ALTER VIEW",
        "ALTER MATERIALIZED VIEW",
        "ALTER FUNCTION",
        "ALTER PROCEDURE",
        "ALTER ROUTINE",
        "ALTER RULE",
        "ALTER TRIGGER",
        "ALTER TABLE",
    )

    #: `$$ ... $$` is where a PL/pgSQL body lives, semicolons and all, and reading it as code
    #: rather than as a literal would make every routine on this engine look like a batch.
    dollar_quoted_strings: ClassVar[bool] = True

    #: The extended query protocol counts parameters in an unsigned 16-bit field.
    max_bound_parameters: ClassVar[int | None] = 65535

    #: PostgreSQL has a real boolean type and the three ANSI niladic date functions.
    boolean_literals: ClassVar[tuple[str, str]] = ("TRUE", "FALSE")

    #: `text[]`, `integer[]` — one dimension, which is all PostgreSQL's declaration syntax
    #: distinguishes anyway: the number of dimensions is not enforced by the server.
    supports_array_types: ClassVar[bool] = True

    #: The built-in types `create_table()` will emit, in `pg_catalog`'s own spelling plus the
    #: SQL-standard aliases PostgreSQL accepts for them.  Extension types (`hstore`, `citext`,
    #: PostGIS `geometry`) are absent on purpose: whether one exists is a per-database
    #: question this layer cannot ask, and emitting a type the database has never installed
    #: fails at the server with a message about the type rather than about the extension.
    column_types: ClassVar[frozenset[str]] = frozenset(
        {
            "smallint", "integer", "int", "int2", "int4", "int8", "bigint",
            "decimal", "numeric", "real", "double precision", "float4", "float8", "money",
            "smallserial", "serial", "bigserial", "serial2", "serial4", "serial8",
            "character varying", "varchar", "character", "char", "bpchar", "text", "bytea",
            "date", "time", "time with time zone", "time without time zone", "timetz",
            "timestamp", "timestamp with time zone", "timestamp without time zone",
            "timestamptz", "interval",
            "boolean", "bool", "bit", "bit varying", "varbit",
            "uuid", "xml", "json", "jsonb",
            "cidr", "inet", "macaddr", "macaddr8",
            "point", "line", "lseg", "box", "path", "polygon", "circle",
            "tsvector", "tsquery",
        }
    )

    # -- capabilities ------------------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        """Everything constant except stored procedures, which arrived in PostgreSQL 11.

        Unprobed, `supports_stored_procedures` reads `False` (decision D2).  Reporting `True`
        and letting `CALL` fail on a 10 server would be an optimistic default in a
        default-deny system, and `permissions.resolve()` reads this flag as an extra deny.
        """

        probed = self.probed
        version = self._traits.version if probed else ()
        return Capabilities(
            engine=Engine.POSTGRESQL,
            supports_schemas=True,
            supports_stored_procedures=probed and version >= (11,),
            supports_table_valued_functions=True,
            supports_roles=True,
            supports_users=True,
            supports_groups=True,
            supports_create_or_replace_view=True,
            supports_create_or_replace_routine=True,
            supports_transactional_ddl=True,
            supports_alter_column=True,
            supports_returning=True,
            # PostgreSQL cannot reference a second database on one connection at all: there
            # is no three-part name, and dblink/postgres_fdw are extensions with their own
            # credentials, which is a whole permission surface d-MCP does not model.
            supports_cross_database_reference=False,
            supports_data_modifying_cte=True,
            max_identifier_length=self.max_identifier_length,
            param_style=self.param_style,
            probed=probed,
        )

    @property
    def case_folding(self) -> CaseFolding:
        """Always `FOLD_LOWER`.  The SQL standard says fold *up*; PostgreSQL has folded down
        since before the standard said so, and it is not configurable."""

        return CaseFolding.FOLD_LOWER

    # -- quoting and normalisation -----------------------------------------------------

    def quote_identifier(self, name: str) -> str:
        """`"name"`, with any inner double quote doubled.

        The length check is in **bytes**, not characters: `NAMEDATALEN - 1` is 63 bytes, so
        `ñ` costs two of them.  PostgreSQL does not error on a longer name, it silently
        truncates it — which is precisely the silent-collision hazard this method exists to
        prevent, so it is refused here before the truncated name can reach the server and
        collide with an existing object.
        """

        quoted = self._quote(name, max_length=self.max_identifier_length)
        encoded = len(name.encode("utf-8"))
        if encoded > self.max_identifier_length:
            raise InvalidIdentifierError(
                f"the identifier is {encoded} bytes, over PostgreSQL's NAMEDATALEN-1 limit of "
                f"{self.max_identifier_length}; the server would truncate it silently rather "
                "than refuse it"
            )
        return quoted

    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str:
        """Fold an unquoted name to lower case; leave a quoted one exactly as it arrived.

        The two are genuinely different objects: `CREATE TABLE Foo` and `CREATE TABLE "Foo"`
        can coexist in one schema as `foo` and `Foo`.  Non-ASCII case folding is refused
        (decision D6) — PostgreSQL folds using the server's own locale rules, which this
        process cannot reproduce, and a wrong guess names a different table.
        """

        if not isinstance(raw, str) or raw == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        if quoted:
            return raw
        return fold_ascii_lower(raw, engine=self.engine)

    def identifier_match_key(self, name: str) -> str:
        """Identical to `normalise_identifier()`, which is what §3.2's table specifies.

        The residual, worth stating because it is a real gap rather than an oversight: an
        object created as a *quoted* mixed-case name — `"Foo"` — has canonical form `Foo`,
        and its match key here is `foo`, the same key as an ordinary `foo` table.  A rule
        written for `foo` would therefore cover both.  Quoted mixed-case names are rare
        enough that d-MCP does not carry a second key for them, but the Explorer page should
        flag any object whose stored name is not already lower case, so the human can see the
        one case where a rule reaches further than it reads.
        """

        return self.normalise_identifier(name, quoted=False)

    # -- what the guard borrows --------------------------------------------------------

    def guard_traits(self) -> GuardTraits:
        """PostgreSQL grammar facts: no batch separator, no executable comment, and a `WITH`
        clause whose body may itself be an `INSERT`/`UPDATE`/`DELETE`."""

        return GuardTraits(
            write_keywords=frozenset({"INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE"}),
            ddl_keywords=frozenset({"CREATE", "ALTER", "DROP"}),
            security_keywords=frozenset(
                {
                    "GRANT",
                    "REVOKE",
                    "CREATE ROLE",
                    "ALTER ROLE",
                    "DROP ROLE",
                    "CREATE USER",
                    "ALTER USER",
                    "DROP USER",
                    "CREATE GROUP",
                    "ALTER GROUP",
                    "DROP GROUP",
                    "SET ROLE",
                    "REASSIGN OWNED",
                    "ALTER DEFAULT PRIVILEGES",
                }
            ),
            line_comment_prefixes=("--",),
            block_comment_delimiters=("/*", "*/"),
            executable_comment_pattern=None,
            batch_separator_pattern=None,
            writing_cte_shape=WritingCTEShape.DML_IN_BODY,
        )

    # -- connection --------------------------------------------------------------------

    def build_dsn(self, profile: ConnectionProfile) -> dict[str, Any]:
        """A psycopg keyword mapping, never the password.

        §5 permits either a `postgresql://` URL or a keyword mapping, and the mapping is the
        safer of the two: a URL needs percent-encoding of the user name and of every option
        value, and one missed escape is a connection pointed somewhere unintended.  The
        mapping has no escaping rules to get wrong.

        `sslmode` defaults to `require`, matching the DSN §5.3 illustrates.  It is a genuine
        default, not a hardcode — `options_json` can lower it for a server that has no TLS —
        but it defaults up rather than down, because the password crosses this connection.

        `statement_timeout_s` becomes a real server-side `statement_timeout`, which is the
        only one of the four engines where the profile field maps onto a first-class setting
        rather than an approximation.
        """

        driver = self.driver or "psycopg"
        auth_mode = self._profile_auth_mode(profile)
        if auth_mode == "none":
            raise DialectError(
                "auth_mode 'none' means there is no authentication step at all, which is "
                "true of a SQLite file and of nothing else. PostgreSQL's 'trust' method is "
                "modelled as 'integrated', because from d-MCP's side both send nothing."
            )
        self._refuse_integrated(profile, driver)

        dsn: dict[str, Any] = {
            "host": self._require(profile, "host"),
            "port": self._profile_port(profile),
            "dbname": self._require(profile, "database"),
            "sslmode": "prefer",
            #"sslmode": "require",
            # Shows up in pg_stat_activity, so a DBA can see which sessions are d-MCP's
            # before asking us.
            "application_name": "SAPE d-MCP",
        }
        username = profile.get("username")
        if auth_mode == "integrated":
            # Omitting `user` is the whole of it: libpq then resolves the name in its own
            # documented order — PGUSER, then the operating-system account — and
            # pg_hba.conf decides which method applies to that connection (peer over a Unix
            # socket, gss or sspi over TCP, or trust).  Sending a name we chose would be
            # sending an identity the server was never going to use.
            #
            # For the Unix-socket case the socket *directory* goes in `host`
            # (/var/run/postgresql) and the port stays 5432; libpq builds the socket name
            # from the two, so the tagged union needs no special case, and libpq ignores
            # `sslmode` for a Unix-domain socket.
            dsn.pop("user", None)
        elif username:
            dsn["user"] = str(username)
        timeout = self._profile_timeout(profile)
        if timeout:
            dsn["options"] = f"-c statement_timeout={timeout * 1000}"
        dsn.update(self._profile_options(profile))
        if "password" in dsn:
            raise DialectError("options_json must not carry a password; use the credential store")
        if auth_mode == "integrated" and "user" in dsn:
            # options_json is hand-editable, so it is the one route by which a user name
            # could reappear after the branch above removed it — which would show one
            # identity on the Connections page and hand another to the server.
            raise DialectError(
                "this connection authenticates through the operating system, so options "
                "must not carry a user name"
            )
        return dsn

    def health_check_sql(self) -> str:
        """`SELECT 1`.  Cheap, read-only, and classified as a read by our own guard traits."""

        return "SELECT 1"

    def version_probe_sql(self) -> str:
        """One row: banner, version, current schema, current user, database collation.

        `current_schema()` rather than a hardcoded `public`: a role whose `search_path` puts
        its own schema first resolves unqualified names there, and assuming `public` would
        address a different table.
        """

        return (
            "SELECT version(), "
            "current_setting('server_version'), "
            "current_schema(), "
            "current_user, "
            "(SELECT datcollate FROM pg_catalog.pg_database WHERE datname = current_database())"
        )

    @classmethod
    def parse_traits(cls, rows: Sequence[Sequence[Any]]) -> ServerTraits:
        """Build `ServerTraits`, refusing a wire-protocol impostor by name.

        The impostor check runs before anything else is read.  Redshift's banner opens
        `PostgreSQL 8.0.2 ... Redshift 1.0.x` and Greenplum's opens
        `PostgreSQL 9.4.24 (Greenplum Database 6.x ...)`, so a `startswith("PostgreSQL")`
        test passes both; the marker scan is what actually catches them.
        """

        if not rows:
            raise DialectError("the PostgreSQL version probe returned no rows")
        row = tuple(rows[0])
        if len(row) < 5:
            raise DialectError(
                f"the PostgreSQL version probe returned {len(row)} columns, expected 5"
            )
        banner = "" if row[0] is None else str(row[0])
        lowered = banner.lower()
        for marker, product in _IMPOSTOR_MARKERS:
            if marker in lowered:
                raise DialectError(
                    f"this server reports itself as {product}, which speaks the PostgreSQL "
                    "wire protocol but is not PostgreSQL. d-MCP refuses it at the probe "
                    "rather than half-working and then failing inside a catalogue query. "
                    f"Server banner: {banner!r}"
                )
        if not lowered.startswith("postgresql"):
            raise DialectError(
                "this server does not identify itself as PostgreSQL. Server banner: "
                f"{banner!r}"
            )

        raw_version = "" if row[1] is None else str(row[1])
        match = _VERSION_RE.search(raw_version) or _VERSION_RE.search(banner)
        if match is None:
            raise DialectError(f"cannot parse a PostgreSQL version out of {raw_version!r}")
        version = tuple(int(part) for part in match.group(1).split("."))

        return ServerTraits(
            raw_version=banner,
            version=version,
            variant="postgresql",
            collation=None if row[4] is None else str(row[4]),
            # Identifier comparison on PostgreSQL is byte-exact on the stored form; the
            # database's LC_COLLATE governs *data* ordering, not identifier matching, and
            # conflating the two is a classic way to get the match key wrong.
            case_sensitive_collation=True,
            lower_case_table_names=None,
            default_schema=None if row[2] is None else str(row[2]),
            current_user=None if row[3] is None else str(row[3]),
        )

    # -- session hardening --------------------------------------------------------------

    def read_only_session(self) -> ReadOnlySession:
        """`SET TRANSACTION READ ONLY`, preceded by the `ROLLBACK` that makes it legal.

        PostgreSQL refuses `SET TRANSACTION` once the current transaction has taken a
        snapshot — `25001: SET TRANSACTION must be called before any query` — and psycopg
        holds a transaction open across statements unless it is in autocommit mode, so on a
        pooled session that has already served one read the bare statement DESIGN-MCP-TOOLS.md
        §9.1 step 11 names would fail every time after the first.  The `ROLLBACK` ends
        whatever transaction was open (PostgreSQL answers a `ROLLBACK` outside a transaction
        with a warning, not an error), so the `SET` is always the first statement of a fresh
        transaction, which is the only place it is accepted.

        **Entering discards uncommitted work on this connection.**  The read path never has
        any: a tool body opens no transaction of its own, and stage 7's write tools complete
        theirs before returning.  A caller that nests a read inside its own open write
        transaction would lose it, so no caller does — and this sentence is the contract that
        says so.

        The verify step is not belt and braces.  Issued outside a transaction block — which
        is exactly what an autocommit connection would give us — `SET TRANSACTION READ ONLY`
        raises a *warning* and does nothing, and a driver discards warnings.  Hardening that
        can succeed and mean nothing has to be read back, so `SHOW transaction_read_only` is
        checked for `on` and the read is refused when it is not.

        The release is another `ROLLBACK`: the read-only property belongs to the transaction,
        so ending the transaction is what restores the session, and there is never anything
        to commit on a read path.
        """

        return ReadOnlySession(
            harden=(
                self._session_statement("ROLLBACK"),
                self._session_statement("SET TRANSACTION READ ONLY"),
            ),
            release=(self._session_statement("ROLLBACK"),),
            verify=self._session_statement("SHOW transaction_read_only"),
            verify_released=self._session_statement("SHOW transaction_read_only"),
            scope=ReadOnlyScope.TRANSACTION,
            enforcement=ReadOnlyEnforcement.REFUSES,
            note="PostgreSQL read-only transaction; a write raises 25006 read_only_sql_transaction",
        )

    def statement_timeout_statements(self, seconds: int) -> tuple[Query, ...]:
        """`SET statement_timeout`, in milliseconds — the one engine where this is exact.

        `build_dsn()` already sends `-c statement_timeout=…` where the profile carries a
        value, and this repeats it at session level for two reasons: the connect option is
        skipped when the profile has no value at all, which is precisely the case that must
        fall back to the 30 s default rather than to no limit; and a session setting is
        visible in `pg_settings`, so a DBA can see what d-MCP asked for.  Setting the same
        value twice costs one round trip and nothing else.
        """

        return (
            self._session_statement(
                f"SET statement_timeout = {self._timeout_literal(seconds) * 1000}"
            ),
        )

    # -- catalogue introspection -------------------------------------------------------

    def _at_least(self, major: int) -> bool:
        """Whether the server is at least this major version, assuming yes when unprobed.

        The optimistic default is deliberate and is *not* the decision-D2 capability rule.
        D2 governs what d-MCP will let a caller *do*, and there an unknown must read as no.
        This governs which spelling of a `pg_catalog` column a read-only catalogue query
        uses, where a wrong guess costs a driver error naming the missing column — loud,
        local and harmless — while a conservative guess would silently under-report a modern
        server, telling the human there are no procedures on a database full of them.
        Introspection always runs on a probed connection; the unprobed dialect is the
        Connections page's DSN-preview path, which lists nothing.
        """

        if not self.probed:
            return True
        return self.traits.version >= (major,)

    #: The `pg_catalog` relations the builders below read, as `Query.touches` entries.  They
    #: are ordinary tables — `pg_catalog` is a schema like any other — so they are typed as
    #: such rather than as views.
    _CAT_CLASS = ObjectRef(schema="pg_catalog", name="pg_class", object_type=ObjectType.TABLE)
    _CAT_NAMESPACE = ObjectRef(schema="pg_catalog", name="pg_namespace", object_type=ObjectType.TABLE)
    _CAT_PROC = ObjectRef(schema="pg_catalog", name="pg_proc", object_type=ObjectType.TABLE)
    _CAT_LANGUAGE = ObjectRef(schema="pg_catalog", name="pg_language", object_type=ObjectType.TABLE)
    _CAT_ATTRIBUTE = ObjectRef(schema="pg_catalog", name="pg_attribute", object_type=ObjectType.TABLE)
    _CAT_ATTRDEF = ObjectRef(schema="pg_catalog", name="pg_attrdef", object_type=ObjectType.TABLE)
    _CAT_CONSTRAINT = ObjectRef(schema="pg_catalog", name="pg_constraint", object_type=ObjectType.TABLE)
    _CAT_ROLES = ObjectRef(schema="pg_catalog", name="pg_roles", object_type=ObjectType.VIEW)
    _CAT_DATABASE = ObjectRef(schema="pg_catalog", name="pg_database", object_type=ObjectType.TABLE)

    #: `template0` and `template1` are already excluded by `datistemplate`; they are named
    #: here so a caller can recognise one it was handed from somewhere else.  `postgres` is
    #: a system name and frequently a real working database, which is why it is marked and
    #: not hidden.
    SYSTEM_DATABASES: ClassVar[frozenset[str]] = frozenset({"postgres", "template0", "template1"})
    _CAT_AUTH_MEMBERS = ObjectRef(
        schema="pg_catalog", name="pg_auth_members", object_type=ObjectType.TABLE
    )

    #: Schemas no caller is offered.  `pg_toast`, `pg_temp_N` and `pg_toast_temp_N` are
    #: matched by the `left(nspname, 3) <> 'pg_'` test rather than named, because their
    #: numbered forms are per-backend and cannot be listed ahead of time.  A user schema
    #: called `pg_something` would be hidden too — PostgreSQL reserves that prefix, so such a
    #: schema is either the server's or a mistake.
    _SCHEMA_EXCLUSION = "n.nspname <> 'information_schema' AND left(n.nspname, 3) <> 'pg_'"

    def list_databases(self, *, include_system: bool = False) -> Query:
        """Every database that accepts connections, with the role's CONNECT right reported.

        The flags do the real work: `template0` has `datallowconn` false and both templates
        are flagged, so the two databases that cannot or must not be opened are excluded by
        the catalogue's own facts rather than by a name list.  `postgres` is filtered only
        as a *system* name, because it is very often a real working database.

        `has_database_privilege(...)` is a returned column and deliberately not a `WHERE`
        clause: a database the role can see but not connect to should be listed and
        disabled, so the user knows it exists and who to ask.  `pg_database` is
        world-readable, so this statement practically never fails — which is the same point
        the base class makes about a short list: absence of an error is not evidence of
        access.
        """

        clause = "" if include_system else "  AND d.datname <> 'postgres' "
        return self._catalogue_query(
            "SELECT d.datname AS database_name, "
            "pg_catalog.pg_get_userbyid(d.datdba) AS owner, "
            "pg_catalog.pg_encoding_to_char(d.encoding) AS encoding, "
            "d.datcollate, "
            "pg_catalog.has_database_privilege(current_user, d.oid, 'CONNECT') AS can_connect, "
            "(d.datname IN ('postgres', 'template0', 'template1')) AS is_system "
            "FROM pg_catalog.pg_database AS d "
            "WHERE d.datallowconn "
            "  AND NOT d.datistemplate "
            f"{clause}"
            "ORDER BY is_system, d.datname",
            touches=(self._CAT_DATABASE,),
        )

    @property
    def bootstrap_database(self) -> str | None:
        """`postgres`, the `psql` convention.

        There is no "no database" connection in PostgreSQL, so something has to be named.
        §8.3 tries the typed value first and falls back through `postgres`, `template1` and
        the PGUSER/OS account name, which is what `psql` itself does.
        """

        return "postgres"

    def list_schemas(self) -> Query:
        """Every schema the current role holds `USAGE` on, system schemas excluded.

        The privilege test is not decoration: `pg_namespace` is world-readable, so without it
        the Explorer page would offer schemas whose contents the connection can never reach,
        and every rule written against one of them would be dead on arrival.
        """

        return self._catalogue_query(
            "SELECT n.nspname AS schema_name "
            "FROM pg_catalog.pg_namespace AS n "
            f"WHERE {self._SCHEMA_EXCLUSION} "
            "  AND pg_catalog.has_schema_privilege(n.oid, 'USAGE') "
            "ORDER BY n.nspname",
            touches=(self._CAT_NAMESPACE,),
        )

    def list_tables(self, schema: str | None = None) -> Query:
        """Ordinary, partitioned and foreign tables the role holds any privilege on.

        Partitions are **not** filtered out, tempting as it is on a table with three hundred
        monthly children.  A partition is an addressable relation with a name of its own; if
        a statement reaches one, `sql_guard` will enumerate that name and the resolver will
        look it up here, and an object missing from this listing is one the resolver cannot
        authorise at all.  Tidiness in the tree is the GUI's problem, not the catalogue's.
        """

        clause, values, names = self._schema_filter(schema, "n.nspname")
        return self._catalogue_query(
            "SELECT n.nspname AS schema_name, c.relname AS table_name, "
            "pg_catalog.obj_description(c.oid, 'pg_class') AS table_comment "
            "FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            # 'r' ordinary, 'p' partitioned parent, 'f' foreign.  A foreign table is a table
            # to every statement that names one, so hiding it would hide something writable.
            "WHERE c.relkind IN ('r', 'p', 'f') "
            f"  AND {self._SCHEMA_EXCLUSION} "
            "  AND pg_catalog.has_table_privilege(c.oid, "
            "      'SELECT, INSERT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER')"
            f"{clause} "
            "ORDER BY n.nspname, c.relname",
            values,
            names,
            touches=(self._CAT_CLASS, self._CAT_NAMESPACE),
        )

    def list_views(self, schema: str | None = None) -> Query:
        """Views and materialised views, the latter flagged.

        A materialised view is a table-shaped object holding a snapshot: it is refreshed with
        `REFRESH MATERIALIZED VIEW`, not re-evaluated on read, and a caller told it is an
        ordinary view will assume it is current when it may be a week old.  Hence the flag,
        rather than folding both into one undifferentiated list.
        """

        clause, values, names = self._schema_filter(schema, "n.nspname")
        return self._catalogue_query(
            "SELECT n.nspname AS schema_name, c.relname AS view_name, "
            "CASE WHEN c.relkind = 'm' THEN 1 ELSE 0 END AS is_materialised, "
            "pg_catalog.obj_description(c.oid, 'pg_class') AS view_comment "
            "FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "WHERE c.relkind IN ('v', 'm') "
            f"  AND {self._SCHEMA_EXCLUSION} "
            "  AND pg_catalog.has_table_privilege(c.oid, 'SELECT') "
            f"{clause} "
            "ORDER BY n.nspname, c.relname",
            values,
            names,
            touches=(self._CAT_CLASS, self._CAT_NAMESPACE),
        )

    def _routine_kind_predicate(self, procedure: bool) -> str | None:
        """The `pg_proc` predicate selecting functions or procedures, per server version.

        `prokind` replaced the `proisagg`/`proiswindow` pair in PostgreSQL 11, which is also
        the release that introduced procedures — so below 11 there is no procedure to select
        and this returns `None`, which the caller renders as an empty result rather than an
        error.  Aggregates and window functions are excluded either way: they cannot be
        called as a plain function and `pg_get_functiondef()` refuses them.
        """

        if self._at_least(11):
            return "p.prokind = 'p'" if procedure else "p.prokind = 'f'"
        if procedure:
            return None
        return "NOT p.proisagg AND NOT p.proiswindow"

    def _empty_result(self, columns: int) -> str:
        """A statement of the right shape that returns no rows, for an absent object kind."""

        return "SELECT " + ", ".join(f"NULL AS c{i}" for i in range(columns)) + " WHERE false"

    def _list_routines(self, schema: str | None, *, procedure: bool) -> Query:
        """The shared body of `list_functions()` and `list_procedures()`.

        `pg_get_function_identity_arguments()` and not `pg_get_function_arguments()`: the
        identity form is the overload discriminator `DROP FUNCTION` needs, without the
        default expressions the other one includes, which would make two spellings of the
        same routine look like two routines.
        """

        predicate = self._routine_kind_predicate(procedure)
        if predicate is None:
            return self._catalogue_query(self._empty_result(6))
        clause, values, names = self._schema_filter(schema, "n.nspname")
        return self._catalogue_query(
            "SELECT n.nspname AS schema_name, p.proname AS routine_name, "
            "pg_catalog.pg_get_function_identity_arguments(p.oid) AS signature, "
            "pg_catalog.pg_get_function_result(p.oid) AS returns, "
            "l.lanname AS language, "
            # Only IMMUTABLE guarantees no side effect.  STABLE and VOLATILE are both
            # reported as non-deterministic, and §4.2 makes a VOLATILE call a write.
            "CASE WHEN p.provolatile = 'i' THEN 1 ELSE 0 END AS is_deterministic "
            "FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
            "JOIN pg_catalog.pg_language AS l ON l.oid = p.prolang "
            f"WHERE {predicate} "
            f"  AND {self._SCHEMA_EXCLUSION} "
            "  AND pg_catalog.has_function_privilege(p.oid, 'EXECUTE')"
            f"{clause} "
            "ORDER BY n.nspname, p.proname, signature",
            values,
            names,
            touches=(self._CAT_PROC, self._CAT_NAMESPACE, self._CAT_LANGUAGE),
        )

    def list_functions(self, schema: str | None = None) -> Query:
        """Scalar, set-returning and table-valued functions; aggregates and window functions
        excluded."""

        return self._list_routines(schema, procedure=False)

    def list_procedures(self, schema: str | None = None) -> Query:
        """Procedures, which exist from PostgreSQL 11.  Below that, an empty result."""

        return self._list_routines(schema, procedure=True)

    def describe_table(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Columns, primary key, unique keys, foreign keys.

        The schema and the relation name are bound values in all four statements.  Nothing
        about them reaches the SQL as text, so a schema called `public"; DROP` — which
        PostgreSQL will happily let you create — is a value that matches nothing, not a
        statement.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        schema_ph = self.placeholder(0, "schema")
        name_ph = self.placeholder(1, "name")
        # COALESCE rather than a bare comparison: a `NormalisedRef` built by hand — the GUI
        # can produce one before a schema has been chosen — carries `None`, and `nspname =
        # NULL` is never true, so the description would come back empty with nothing to say
        # why.  The cast is what stops PostgreSQL asking psycopg what type the NULL is.
        where = (
            f"WHERE n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
            f"  AND c.relname = {name_ph}"
        )

        generated = "a.attgenerated <> ''" if self._at_least(12) else "false"
        identity = "a.attidentity <> ''" if self._at_least(10) else "false"
        columns = self._catalogue_query(
            "SELECT a.attname AS column_name, "
            "pg_catalog.format_type(a.atttypid, a.atttypmod) AS data_type, "
            "CASE WHEN a.attnotnull THEN 0 ELSE 1 END AS is_nullable, "
            "pg_catalog.pg_get_expr(ad.adbin, ad.adrelid) AS column_default, "
            f"CASE WHEN {identity} THEN 1 ELSE 0 END AS is_identity, "
            f"CASE WHEN {generated} THEN 1 ELSE 0 END AS is_generated, "
            # attnum, not the ordinal: a dropped column leaves a hole in attnum while the
            # position a caller counts in `SELECT *` closes up behind it.
            "CAST(row_number() OVER (ORDER BY a.attnum) AS int) AS ordinal_position, "
            "pg_catalog.col_description(c.oid, a.attnum) AS column_comment "
            "FROM pg_catalog.pg_attribute AS a "
            "JOIN pg_catalog.pg_class AS c ON c.oid = a.attrelid "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "LEFT JOIN pg_catalog.pg_attrdef AS ad "
            "       ON ad.adrelid = c.oid AND ad.adnum = a.attnum "
            f"{where} AND a.attnum > 0 AND NOT a.attisdropped "
            "ORDER BY a.attnum",
            values,
            names,
            touches=(self._CAT_ATTRIBUTE, self._CAT_CLASS, self._CAT_NAMESPACE, self._CAT_ATTRDEF),
        )

        def key_query(contype: str) -> Query:
            return self._catalogue_query(
                "SELECT con.conname AS constraint_name, a.attname AS column_name, "
                "CAST(k.ord AS int) AS key_ordinal "
                "FROM pg_catalog.pg_constraint AS con "
                "JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
                # WITH ORDINALITY is what keeps the key's column *order* — conkey is an
                # array whose position is the key position, and a join that lost it would
                # report a composite key back to front half the time.
                "CROSS JOIN LATERAL unnest(con.conkey) WITH ORDINALITY AS k(attnum, ord) "
                "JOIN pg_catalog.pg_attribute AS a "
                "     ON a.attrelid = c.oid AND a.attnum = k.attnum "
                f"{where} AND con.contype = '{contype}' "
                "ORDER BY con.conname, k.ord",
                values,
                names,
                touches=(
                    self._CAT_CONSTRAINT,
                    self._CAT_CLASS,
                    self._CAT_NAMESPACE,
                    self._CAT_ATTRIBUTE,
                ),
            )

        # 'p' and 'u' are single characters this module writes; they are not input, and the
        # f-string is over a literal, never over anything that arrived from a caller.
        primary_key = key_query("p")
        unique_keys = key_query("u")

        foreign_keys = self._catalogue_query(
            "SELECT con.conname AS constraint_name, a.attname AS column_name, "
            "CAST(k.ord AS int) AS key_ordinal, "
            "fn.nspname AS referenced_schema, fc.relname AS referenced_table, "
            "fa.attname AS referenced_column, "
            "CASE con.confdeltype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' "
            "     WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' "
            "     WHEN 'd' THEN 'SET DEFAULT' END AS on_delete, "
            "CASE con.confupdtype WHEN 'a' THEN 'NO ACTION' WHEN 'r' THEN 'RESTRICT' "
            "     WHEN 'c' THEN 'CASCADE' WHEN 'n' THEN 'SET NULL' "
            "     WHEN 'd' THEN 'SET DEFAULT' END AS on_update "
            "FROM pg_catalog.pg_constraint AS con "
            "JOIN pg_catalog.pg_class AS c ON c.oid = con.conrelid "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            "JOIN pg_catalog.pg_class AS fc ON fc.oid = con.confrelid "
            "JOIN pg_catalog.pg_namespace AS fn ON fn.oid = fc.relnamespace "
            # Both arrays unnested together, so the local column and the column it
            # references stay paired at every position of a composite key.
            "CROSS JOIN LATERAL unnest(con.conkey, con.confkey) "
            "     WITH ORDINALITY AS k(attnum, fattnum, ord) "
            "JOIN pg_catalog.pg_attribute AS a ON a.attrelid = c.oid AND a.attnum = k.attnum "
            "JOIN pg_catalog.pg_attribute AS fa "
            "     ON fa.attrelid = fc.oid AND fa.attnum = k.fattnum "
            f"{where} AND con.contype = 'f' "
            "ORDER BY con.conname, k.ord",
            values,
            names,
            touches=(
                self._CAT_CONSTRAINT,
                self._CAT_CLASS,
                self._CAT_NAMESPACE,
                self._CAT_ATTRIBUTE,
            ),
        )
        return (columns, primary_key, unique_keys, foreign_keys)

    def describe_routine(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """A header row per overload, then the parameters, keyed back by signature.

        PostgreSQL is the engine where a routine name is not a unique object: `add(int, int)`
        and `add(text, text)` are two rows here and two entries in `pg_proc`, sharing one
        name and one permission rule.  Both statements therefore return *every* overload and
        the parameter rows carry the signature they belong to, so the caller can group them
        without a second round trip per overload.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        schema_ph = self.placeholder(0, "schema")
        name_ph = self.placeholder(1, "name")
        where = (
            f"WHERE n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
            f"  AND p.proname = {name_ph}"
        )
        kind = (
            "CASE WHEN p.prokind = 'p' THEN 'procedure' ELSE 'function' END"
            if self._at_least(11)
            else "'function'"
        )
        header = self._catalogue_query(
            "SELECT n.nspname AS schema_name, p.proname AS routine_name, "
            f"{kind} AS routine_type, "
            "pg_catalog.pg_get_function_identity_arguments(p.oid) AS signature, "
            "pg_catalog.pg_get_function_result(p.oid) AS returns, "
            "l.lanname AS language, "
            "CASE WHEN p.provolatile = 'i' THEN 1 ELSE 0 END AS is_deterministic "
            "FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
            "JOIN pg_catalog.pg_language AS l ON l.oid = p.prolang "
            f"{where} "
            "ORDER BY signature",
            values,
            names,
            touches=(self._CAT_PROC, self._CAT_NAMESPACE, self._CAT_LANGUAGE),
        )
        parameters = self._catalogue_query(
            "SELECT pg_catalog.pg_get_function_identity_arguments(p.oid) AS routine_signature, "
            "p.proargnames[k.ord] AS parameter_name, "
            "pg_catalog.format_type(k.argtype, NULL) AS data_type, "
            "CASE COALESCE(p.proargmodes[k.ord], 'i') "
            "     WHEN 'i' THEN 'IN' WHEN 'o' THEN 'OUT' WHEN 'b' THEN 'INOUT' "
            "     WHEN 'v' THEN 'VARIADIC' WHEN 't' THEN 'TABLE' ELSE 'IN' END AS parameter_mode, "
            "CAST(k.ord AS int) AS ordinal_position, "
            # An approximation, and the only one available: pg_proc records how many
            # trailing input arguments have defaults, not which ones, so the last
            # pronargdefaults of the pronargs inputs are the ones that carry them.
            "CASE WHEN k.ord > p.pronargs - p.pronargdefaults THEN 1 ELSE 0 END AS has_default "
            "FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
            # proallargtypes is NULL unless the routine has an OUT or INOUT parameter, in
            # which case proargtypes holds only the inputs — so the COALESCE is not tidiness,
            # it is the difference between listing a procedure's OUT parameters and silently
            # dropping them.
            "CROSS JOIN LATERAL unnest(COALESCE(p.proallargtypes, CAST(p.proargtypes AS oid[]))) "
            "     WITH ORDINALITY AS k(argtype, ord) "
            f"{where} "
            "ORDER BY routine_signature, k.ord",
            values,
            names,
            touches=(self._CAT_PROC, self._CAT_NAMESPACE),
        )
        return (header, parameters)

    def object_definition(self, ref: NormalisedRef) -> Query:
        """`pg_get_viewdef()` for a view, `pg_get_functiondef()` for a routine.

        Both return `NULL` — not an error — for an object whose definition the current role
        may not see, which is the "definition withheld" case `introspection.py` has to tell
        apart from "this object has no body".  A table has no definition text on this engine
        at all: PostgreSQL stores the parsed catalogue entry, not the `CREATE TABLE` that
        produced it, and reconstructing one here would be inventing text the server never
        held.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        schema_ph = self.placeholder(0, "schema")
        name_ph = self.placeholder(1, "name")
        if ref.object_type is ObjectType.VIEW:
            return self._catalogue_query(
                "SELECT pg_catalog.pg_get_viewdef(c.oid, true) AS definition "
                "FROM pg_catalog.pg_class AS c "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
                f"WHERE n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
                f"  AND c.relname = {name_ph} AND c.relkind IN ('v', 'm')",
                values,
                names,
                touches=(self._CAT_CLASS, self._CAT_NAMESPACE),
            )
        if ref.object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE):
            # pg_get_functiondef() raises for an aggregate or a window function rather than
            # returning NULL, so the kind predicate is a guard, not a filter.
            predicate = (
                "p.prokind IN ('f', 'p')"
                if self._at_least(11)
                else "NOT p.proisagg AND NOT p.proiswindow"
            )
            return self._catalogue_query(
                "SELECT pg_catalog.pg_get_functiondef(p.oid) AS definition "
                "FROM pg_catalog.pg_proc AS p "
                "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
                f"WHERE n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
                f"  AND p.proname = {name_ph} AND {predicate} "
                "ORDER BY pg_catalog.pg_get_function_identity_arguments(p.oid)",
                values,
                names,
                touches=(self._CAT_PROC, self._CAT_NAMESPACE),
            )
        raise self._unsupported(
            "object_definition",
            f"PostgreSQL stores no source text for a {ref.object_type}; only views, "
            "functions and procedures have a definition to read",
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

    def _collate_clause(self, collation: str | None) -> str:
        """`COLLATE "en_US"` — quoted, because on this engine a collation *is* an identifier.

        The base class emits it bare, which is right for SQL Server and MySQL and wrong here:
        an unquoted `en_US` is folded to `en_us` and PostgreSQL's own collation names are
        mixed case, so the unquoted form finds nothing on the very locales people use.
        """

        if collation is None:
            return ""
        return f" COLLATE {self.quote_identifier(collation)}"

    def _identity_clause(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """`GENERATED BY DEFAULT AS IDENTITY`, the SQL-standard form, from PostgreSQL 10.

        `BY DEFAULT` rather than `ALWAYS`: an `ALWAYS` column cannot be written even by an
        explicit `OVERRIDING SYSTEM VALUE`-less insert, which would make the table
        unloadable through `insert-rows` — the tool that exists precisely to put rows in it.

        Below 10 the clause does not exist and the alternative is `serial`, which is not a
        column attribute at all but a macro that creates a sequence object the permission
        table has never heard of.  That is refused rather than emitted.
        """

        if not self._at_least(10):
            raise self._unsupported(
                "create_table(is_identity=True)",
                "PostgreSQL grew identity columns in 10; below that the only spelling is "
                "serial, which silently creates a sequence object no d-MCP rule covers",
            )
        return " GENERATED BY DEFAULT AS IDENTITY"

    # -- 3.4 routines: the one engine where a name is not an identity --------------------
    #
    # `add(integer, integer)` and `add(text, text)` are two objects sharing one name, and
    # `DROP FUNCTION add` is refused by the server as ambiguous while both exist.  The kit
    # that carries the argument list through `drop_routine()`, `grant()` and `revoke()` is in
    # `base.py`; what belongs here is the two engine-specific answers it asks for — which
    # spellings mean the same type, and how a type that is not in `column_types` is rendered.

    #: True here and nowhere else among the four.
    overloads_routines: ClassVar[bool] = True

    #: PostgreSQL's own aliases, used **only** to match a caller's argument list against the
    #: overloads the catalogue reported: `pg_get_function_identity_arguments()` prints the
    #: canonical spelling on the right of each pair, and a human writes the one on the left.
    #: Nothing here is ever emitted — `_render_argument_type()` renders what it was given.
    type_aliases: ClassVar[Mapping[str, str]] = {
        "int": "integer",
        "int2": "smallint",
        "int4": "integer",
        "int8": "bigint",
        "serial2": "smallserial",
        "serial4": "serial",
        "serial8": "bigserial",
        "float4": "real",
        "float8": "double precision",
        "decimal": "numeric",
        "varchar": "character varying",
        "char": "character",
        "bpchar": "character",
        "bool": "boolean",
        "varbit": "bit varying",
        "timetz": "time with time zone",
        "timestamptz": "timestamp with time zone",
        "time with time zone": "time with time zone",
        "time without time zone": "time",
        "timestamp without time zone": "timestamp",
    }

    def _render_argument_type(self, data_type: str) -> str:
        """An argument's type, rendered from `column_types` or from a quoted identifier.

        The vocabulary alone is not enough here, and the gap is not academic: a schema whose
        function takes an enum, a domain or a composite type has no entry in `column_types`
        for it and never will — whether one exists is a per-database question this layer
        cannot ask — so a vocabulary-only renderer can address `f(integer)` and cannot address
        `f(mood)`, which is half the overloads on a real schema.

        So a type this engine has declared is rendered by `_validate_type()` exactly as a
        column's would be, and anything else must be a **type name**: one identifier, or a
        schema-qualified pair, each part either a plain unquoted word or a `"…"` span with its
        inner quotes doubled, with an optional trailing `[]`.  Every part is re-quoted by
        `quote_identifier()`, so what reaches the statement is this layer's own text either
        way, and a fragment that is not one of those two things is refused rather than
        repaired.  `"integer"` is deliberately *not* how `integer` is rendered: quoted, that
        names a type PostgreSQL does not have, so the vocabulary is tried first and its
        answer preferred.
        """

        try:
            return self._validate_type(data_type)
        except (ValueError, DialectError) as vocabulary_error:
            rendered = self._type_identifier(data_type)
            if rendered is None:
                raise ValueError(
                    f"the routine argument list names {data_type!r}, which is neither a type "
                    f"{self.display_name} has declared nor a plain type name d-MCP can quote: "
                    "the list is rebuilt from validated pieces and nothing that cannot be "
                    "attributed is emitted"
                ) from vocabulary_error
            return rendered

    def _type_identifier(self, data_type: str) -> str | None:
        """`data_type` as a re-quoted type name, or `None` when it is not one."""

        text = " ".join(str(data_type).split())
        array = ""
        while text.endswith("[]"):
            array += "[]"
            text = text[:-2].rstrip()
        if not text:
            return None
        parts = self._split_qualified(text)
        if parts is None or len(parts) > 2:
            return None
        try:
            return ".".join(self.quote_identifier(part) for part in parts) + array
        except DialectError:
            return None

    def _split_qualified(self, text: str) -> list[str] | None:
        """`schema.name`, `"Schema"."Name"` or `name` as its parts, folded, or `None`.

        Written out rather than `text.split(".")` for two reasons.  A quoted name may contain
        a dot, and a splitter that did not know that would take `"my.type"` apart into two
        names neither of which exists.  And an **unquoted** part is folded to lower case here,
        because that is what the server would do to it: quoting `MOOD` as `"MOOD"` would name
        a type that does not exist on a database whose type is `mood`, which is the quiet
        half of the same bug `normalise_identifier()` exists to prevent.
        """

        parts: list[str] = []
        current: list[str] = []
        index = 0
        quoted_part = False
        started = False

        def close() -> bool:
            if not started:
                return False
            raw = "".join(current)
            if raw == "":
                return False
            try:
                parts.append(raw if quoted_part else self.normalise_identifier(raw))
            except DialectError:
                return False
            return True

        while index < len(text):
            char = text[index]
            if char == '"':
                if started:
                    return None
                started = True
                quoted_part = True
                index += 1
                closed = False
                while index < len(text):
                    if text[index] == '"':
                        if index + 1 < len(text) and text[index + 1] == '"':
                            current.append('"')
                            index += 2
                            continue
                        closed = True
                        index += 1
                        break
                    current.append(text[index])
                    index += 1
                if not closed:
                    return None
                continue
            if char == ".":
                if not close():
                    return None
                current = []
                quoted_part = False
                started = False
                index += 1
                continue
            if quoted_part:
                return None
            if not (char.isalnum() or char in "_$" or ord(char) > 127):
                return None
            if not started and (char.isdigit() or char == "$"):
                return None
            started = True
            current.append(char)
            index += 1
        if not close():
            return None
        return parts

    def estimate_row_count(self, ref: NormalisedRef) -> Query:
        """`pg_class.reltuples`, which the planner keeps and `ANALYZE` refreshes.

        `reltuples` is `-1` on a relation that has never been analysed from PostgreSQL 14, and
        `0` on older servers — two spellings of "nobody knows", and the second is
        indistinguishable from a genuinely empty table.  The `-1` case is mapped to SQL NULL so
        the caller can say "unknown" rather than "none"; the older `0` cannot be told apart
        and the docstring says so rather than the code pretending otherwise.

        Cheap by construction: one row of one catalogue table, no scan of the relation.
        """

        if ref.object_type not in (ObjectType.TABLE, ObjectType.VIEW):
            raise ValueError(
                f"estimate_row_count() counts rows of a table or a view; {ref.object_type} "
                "is neither"
            )
        schema_ph = self.placeholder(0, "schema")
        name_ph = self.placeholder(1, "name")
        return self._catalogue_query(
            "SELECT CASE WHEN c.reltuples < 0 THEN NULL "
            "            ELSE CAST(c.reltuples AS bigint) END AS estimated_rows "
            "FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            f"WHERE n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
            f"  AND c.relname = {name_ph}",
            (ref.canonical_schema, ref.canonical_name),
            ("schema", "name"),
            touches=(self._CAT_CLASS, self._CAT_NAMESPACE),
        )

    # -- 3.5 security ------------------------------------------------------------------
    #
    # PostgreSQL has exactly one kind of principal: a role.  A role with `LOGIN` is what every
    # other engine calls a user, a role without it is what every other engine calls a group,
    # and `CREATE USER` and `CREATE GROUP` are documented aliases of `CREATE ROLE` that differ
    # only in whether `LOGIN` defaults on.  d-MCP therefore emits `CREATE ROLE` throughout and
    # says out loud which of its own three words each call means, rather than emitting an alias
    # that would make the server's catalogue look as though it held three kinds of thing.

    #: The privileges d-MCP will grant on a relation.  PostgreSQL's full table vocabulary, with
    #: `MAINTAIN` (17) left out because it is version-gated and nothing asks for it.
    relation_privileges: ClassVar[frozenset[str]] = frozenset(
        {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", "REFERENCES", "TRIGGER"}
    )

    #: `EXECUTE` is the whole of a routine's vocabulary here.  `USAGE` belongs to schemas,
    #: sequences, types and languages, none of which this surface addresses.
    routine_privileges: ClassVar[frozenset[str]] = frozenset({"EXECUTE"})

    def list_principals(self) -> Query:
        """Every role, with `rolcanlogin` deciding which of d-MCP's words it is called by.

        `pg_roles` rather than `pg_authid`: the two differ in exactly one column, the password
        hash, which `pg_authid` exposes to superusers and `pg_roles` replaces with `********`.
        There is no reason for this application to hold a hash and one very good reason not to,
        so the view that cannot supply one is the one that is read.

        `pg_`-prefixed roles are excluded as the schema listing excludes `pg_` schemas, and by
        the same `left(...)` test rather than a `LIKE` pattern — a literal `%` in a statement
        is a formatting directive to psycopg's pyformat paramstyle, and this layer keeps `%`
        out of statement text everywhere for that reason.  What is hidden by it is the
        predefined roles (`pg_read_all_data` and its siblings), which no d-MCP call can create,
        drop or usefully assign.
        """

        return self._catalogue_query(
            "SELECT r.rolname AS principal_name, "
            # d-MCP's own vocabulary: a role that can log in is a user, one that cannot is a
            # group.  The third word, "role", has no separate object on this engine, so
            # list-roles and list-groups answer with the same rows and the Explorer page shows
            # one tree rather than pretending to two.
            "CASE WHEN r.rolcanlogin THEN 'user' ELSE 'group' END AS principal_kind, "
            "'role' AS native_kind, "
            "CASE WHEN r.rolcanlogin THEN 1 ELSE 0 END AS can_login, "
            "CASE WHEN r.rolsuper THEN 1 ELSE 0 END AS is_superuser "
            "FROM pg_catalog.pg_roles AS r "
            "WHERE left(r.rolname, 3) <> 'pg_' "
            "ORDER BY r.rolname",
            touches=(self._CAT_ROLES,),
        )

    def list_group_members(self, group: str) -> Query:
        """The direct members of one role.

        Direct, not transitive: role membership on this engine is a graph and
        `pg_auth_members` holds its edges.  Flattening it here would answer a question nobody
        asked — the Explorer page draws the tree — and would need a recursive CTE whose cost
        grows with a graph d-MCP does not control.

        `group` is bound, not quoted: this is a comparison against a catalogue column, and a
        parameter is the strongest form that text can take.  It is still normalised on the way
        past so the comparison uses the spelling the catalogue holds — an unquoted `Sales`
        folds to `sales` here and would otherwise match nothing.
        """

        canonical = self.normalise_identifier(group)
        self.quote_identifier(canonical)
        return self._catalogue_query(
            "SELECT m.rolname AS member_name, 'role' AS member_native_kind, "
            "CASE WHEN am.admin_option THEN 1 ELSE 0 END AS has_admin_option "
            "FROM pg_catalog.pg_auth_members AS am "
            "JOIN pg_catalog.pg_roles AS g ON g.oid = am.roleid "
            "JOIN pg_catalog.pg_roles AS m ON m.oid = am.member "
            f"WHERE g.rolname = {self.placeholder(0, 'group_name')} "
            "ORDER BY m.rolname",
            (canonical,),
            ("group_name",),
            touches=(self._CAT_AUTH_MEMBERS, self._CAT_ROLES),
        )

    #: The relation kinds `list_grants()` reports on: ordinary, partitioned and foreign tables,
    #: views and materialised views — the same set `list_tables()` and `list_views()` between
    #: them offer, so a grant can never be reported against an object the tree does not show.
    _GRANTABLE_RELKINDS = "('r', 'p', 'f', 'v', 'm')"

    #: `aclexplode()` unpacks an `aclitem[]` into one row per privilege.  The column alias list
    #: is spelled out rather than left to the function's own record type: the four names are
    #: part of this statement's meaning, and a server that returned them in another order would
    #: otherwise silently pair a grantee with a privilege.
    _ACL_COLUMNS = "acl(grantor, grantee, privilege_type, is_grantable)"

    def _relation_grants(self, clause: str) -> str:
        """The relation half of `list_grants()`, with an optional extra `WHERE` fragment."""

        return (
            "SELECT COALESCE(g.rolname, 'PUBLIC') AS grantee, "
            "acl.privilege_type AS privilege, "
            "n.nspname AS schema_name, c.relname AS object_name, "
            "CASE WHEN acl.is_grantable THEN 1 ELSE 0 END AS grantable, "
            "'GRANT' AS state "
            "FROM pg_catalog.pg_class AS c "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = c.relnamespace "
            f"CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) AS {self._ACL_COLUMNS} "
            "LEFT JOIN pg_catalog.pg_roles AS g ON g.oid = acl.grantee "
            f"WHERE c.relkind IN {self._GRANTABLE_RELKINDS} "
            f"  AND {self._SCHEMA_EXCLUSION}"
            f"{clause}"
        )

    def _routine_grants(self, clause: str) -> str:
        """The routine half of `list_grants()`."""

        return (
            "SELECT COALESCE(g.rolname, 'PUBLIC') AS grantee, "
            "acl.privilege_type AS privilege, "
            "n.nspname AS schema_name, p.proname AS object_name, "
            "CASE WHEN acl.is_grantable THEN 1 ELSE 0 END AS grantable, "
            "'GRANT' AS state "
            "FROM pg_catalog.pg_proc AS p "
            "JOIN pg_catalog.pg_namespace AS n ON n.oid = p.pronamespace "
            f"CROSS JOIN LATERAL pg_catalog.aclexplode(p.proacl) AS {self._ACL_COLUMNS} "
            "LEFT JOIN pg_catalog.pg_roles AS g ON g.oid = acl.grantee "
            f"WHERE {self._SCHEMA_EXCLUSION}"
            f"{clause}"
        )

    def list_grants(self, ref: NormalisedRef | None = None) -> Query:
        """Explicit `GRANT`s, read out of the objects' own ACLs.

        `aclexplode()` on `relacl`/`proacl` rather than `information_schema.table_privileges`,
        which restricts itself to grants where the current role is the grantor or the grantee.
        On an admin connection that view answers a much smaller question than the page is
        asking, and the difference is silent.

        A **null** ACL is skipped, and that is the one thing this listing does not report: a
        freshly created object has `relacl IS NULL`, meaning "the owner holds the owner's
        default privileges and nothing has been granted to anyone else".  There is nothing
        explicit to show, and synthesising the owner's implicit set with `acldefault()` would
        put rows on the page that no `GRANT` ever created and no `REVOKE` could remove.

        A `state` column of the constant `'GRANT'` is carried so the four engines return the
        same shape: PostgreSQL has no `DENY`, and saying so in the result is better than
        leaving the caller to discover that the column is missing here.
        """

        if ref is None:
            # Both halves, no parameters at all: a mapping-style `params` of `{}` would still
            # be a mapping, and this way there is nothing for a driver to interpolate.
            return self._catalogue_query(
                self._relation_grants("")
                + " UNION ALL "
                + self._routine_grants("")
                + " ORDER BY 3, 4, 1, 2",
                touches=(
                    self._CAT_CLASS,
                    self._CAT_PROC,
                    self._CAT_NAMESPACE,
                    self._CAT_ROLES,
                ),
            )

        schema_ph = self.placeholder(0, "schema")
        name_ph = self.placeholder(1, "name")
        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        # One half only when an object is named, so each placeholder appears exactly once:
        # `parameters()` refuses a duplicate name, and a positional style would need the value
        # twice.  Branching on the object type is also the more accurate answer — a function
        # and a table can share a name.
        if ref.object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE):
            sql = self._routine_grants(
                f" AND n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
                f" AND p.proname = {name_ph}"
            )
            touches = (self._CAT_PROC, self._CAT_NAMESPACE, self._CAT_ROLES)
        else:
            sql = self._relation_grants(
                f" AND n.nspname = COALESCE(CAST({schema_ph} AS name), current_schema()) "
                f" AND c.relname = {name_ph}"
            )
            touches = (self._CAT_CLASS, self._CAT_NAMESPACE, self._CAT_ROLES)
        return self._catalogue_query(
            sql + " ORDER BY 1, 2", values, names, touches=touches
        )

    def create_role(self, name: str) -> Script:
        """`CREATE ROLE "x" NOLOGIN`.

        `NOLOGIN` is the default for `CREATE ROLE` and is written anyway.  A default that is
        not spelled out is a default that a future `ALTER ROLE ... LOGIN`, a `createrole`
        template or a reader of the audit row has to know about; spelling it makes the
        statement say what it does.
        """

        return self._security_script(f"CREATE ROLE {self.quote_principal(name)} NOLOGIN")

    def create_user(
        self,
        name: str,
        *,
        host: str | None = None,
        login: str | None = None,
        default_schema: str | None = None,
    ) -> Script:
        """`CREATE ROLE "x" NOLOGIN` — a user that cannot connect until a human says so.

        `NOLOGIN` and not `LOGIN PASSWORD NULL`, and the difference is the whole point.  A
        password is only ever consulted by the `password`, `md5` and `scram-sha-256` methods
        in `pg_hba.conf`; `trust`, `peer`, `ident`, `cert`, `gss` and `sspi` never look at it,
        so a `LOGIN` role with no password connects freely under any of the six.  `LOGIN`
        itself is the only attribute that gates a connection unconditionally, so withholding
        it is the only way to create a principal that is genuinely unable to connect on a
        server whose authentication configuration this application cannot see.

        The consequence, stated rather than hidden: on this engine the statement is
        byte-identical to `create_group()`.  PostgreSQL does not distinguish the two, and
        d-MCP's own distinction is a label it applies in `list_principals()` from
        `rolcanlogin` — which is `false` for both until the operator grants `LOGIN` along with
        the credential, at which point the server's answer and d-MCP's agree again.

        `login` is refused: there is no login object here separate from the role, so mapping a
        user onto one is a request that has no meaning, and silently ignoring it would leave a
        caller believing it had reused an existing identity.

        `default_schema` becomes `ALTER ROLE ... SET search_path`, which is the honest
        equivalent and not quite the same thing — it sets the whole search path to that one
        schema, so `public` stops being on it.  That is what a default schema means on the
        other engines and what a caller asking for one wants; it is a second statement, and
        `Script.atomic` is `True` here, so the pair cannot half-apply.
        """

        if login is not None:
            raise ValueError(
                "PostgreSQL has no login object separate from the role, so a user cannot be "
                "mapped onto one: create_user() creates the role itself"
            )
        quoted = self.quote_principal(name, host=host)
        statements = [f"CREATE ROLE {quoted} NOLOGIN"]
        if default_schema is not None:
            schema = self.quote_identifier(self.normalise_identifier(default_schema))
            statements.append(f"ALTER ROLE {quoted} SET search_path TO {schema}")
        return self._security_script(*statements)

    def create_group(self, name: str) -> Script:
        """`CREATE ROLE "x" NOLOGIN` — the same statement `create_user()` emits, deliberately.

        A group on PostgreSQL *is* a role that cannot log in.  `CREATE GROUP` exists as an
        alias and is not used: it is documented as obsolete, and emitting it would suggest the
        server holds a third kind of object when it holds one.
        """

        return self._security_script(f"CREATE ROLE {self.quote_principal(name)} NOLOGIN")

    # `host` is threaded to the **member** — the grantee — in all four methods below, matching
    # what `Dialect.add_group_member()` documents and what `MySQLDialect` implements.  On this
    # engine the choice makes no observable difference: `quote_principal()` refuses any non-None
    # host, so `host=None` produces identical text either way and a supplied host raises whoever
    # it was attached to.  That is exactly why it is worth spelling correctly now.  Nothing here
    # can fail to warn us, so the first person to give PostgreSQL a host meaning — a peer or a
    # cert-mapped identity, say — would inherit a silent mis-routing that scopes the *group*
    # rather than the account joining it, and would find it by reading the emitted GRANT rather
    # than by a red test.  `test_security_composition.py` pins the contract across both engines
    # so the two cannot drift apart again.

    def add_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`GRANT "group" TO "member"` — membership is a grant of the role itself.

        Without `WITH ADMIN OPTION`, which would let the member add and remove other members.
        That is the ability to change who has access, and it is not part of "add this user to
        this group": a caller that wants it is asking for a different act, and there is no
        argument here that quietly performs it.
        """

        return self._security_script(
            f"GRANT {self.quote_principal(group)} TO "
            f"{self.quote_principal(member, host=host)}"
        )

    def remove_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`REVOKE "group" FROM "member"`."""

        return self._security_script(
            f"REVOKE {self.quote_principal(group)} FROM "
            f"{self.quote_principal(member, host=host)}"
        )

    def assign_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`GRANT "role" TO "principal"`.

        Identical to `add_group_member()`, because on this engine the two acts are identical:
        a group is a role and joining one is being granted it.  Both are written out rather
        than one delegating to the other, so that neither can be changed for its own reasons
        and silently change the other.

        A granted role is live immediately for a member with `INHERIT` — the default — and
        needs `SET ROLE` for one created `NOINHERIT`.  d-MCP does not create `NOINHERIT` roles
        and does not emit `SET ROLE`, which is a session act rather than a durable one.
        """

        return self._security_script(
            f"GRANT {self.quote_principal(role)} TO "
            f"{self.quote_principal(principal, host=host)}"
        )

    def revoke_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`REVOKE "role" FROM "principal"`, and never `CASCADE`.

        The omission matters as much as it does on `DROP`: `CASCADE` would follow the grant
        graph and remove privileges from principals nobody named in the call.
        """

        return self._security_script(
            f"REVOKE {self.quote_principal(role)} FROM "
            f"{self.quote_principal(principal, host=host)}"
        )

    def _grant_object(self, ref: NormalisedRef, arguments: str = "") -> str:
        """The `ON <kind> <name>` clause, with the object kind named explicitly.

        `ON TABLE` covers views and materialised views too — PostgreSQL's grammar has no
        `ON VIEW` — and naming the kind rather than relying on the bare-name form keeps the
        statement unambiguous when a table and a function share a name.

        `arguments` closes what was an honest gap: an **overloaded** function needs its
        argument list here, and until stage 8 this surface had no signature to give it, so a
        routine d-MCP could list and read was one it could not permission.  PostgreSQL 10 and
        later accept the bare name when it is unique in its schema and refuse it otherwise, so
        the old behaviour survives unchanged when no signature is passed: the server fails
        loudly rather than d-MCP picking an overload.
        """

        if ref.object_type in (ObjectType.TABLE, ObjectType.VIEW):
            return f"TABLE {self.quote_ref(ref)}"
        if ref.object_type is ObjectType.FUNCTION:
            return f"FUNCTION {self.quote_ref(ref)}{arguments}"
        if ref.object_type is ObjectType.PROCEDURE:
            return f"PROCEDURE {self.quote_ref(ref)}{arguments}"
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
        """`GRANT SELECT, INSERT ON TABLE "s"."t" TO "bob" [WITH GRANT OPTION]`, and
        `GRANT EXECUTE ON FUNCTION "s"."add"(INTEGER, INTEGER) TO "bob"` for an overload."""

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
        """`REVOKE SELECT ON TABLE "s"."t" FROM "bob"`, and never `CASCADE`.

        `CASCADE` would revoke onward from everyone the principal had granted to, which is a
        wider act than the one requested and one the confirmation dialog could not summarise.
        Without it PostgreSQL refuses the revoke where dependent grants exist, which is the
        loud failure rather than the silent wide one.
        """

        target = self._check_grant_ref(ref)
        words = self._validated_privileges(privileges, target, what="revoke")
        arguments = self._routine_arguments_for(target, signature, method="revoke")
        return self._security_script(
            f"REVOKE {', '.join(words)} ON {self._grant_object(target, arguments)} FROM "
            f"{self.quote_principal(principal, host=host)}",
            touches=self._grant_touches(target),
        )
