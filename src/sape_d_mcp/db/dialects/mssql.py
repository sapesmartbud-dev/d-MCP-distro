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

"""The MS-SQL dialect, driven by either pyodbc or pymssql."""

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
    ParamStyle,
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

__all__ = ["MSSQLDialect"]

_VERSION_RE = re.compile(r"(\d+(?:\.\d+)*)")

#: `CREATE OR ALTER` arrived in SQL Server 2016 SP1, which reports 13.0.4001.0.  Below it the
#: dialect falls back to `DROP ... IF EXISTS` then `CREATE`; the pair still runs inside one
#: transaction, so unlike MySQL's equivalent fallback it needs no warning key.
_CREATE_OR_ALTER_FLOOR = (13, 0, 4001)

#: `SERVERPROPERTY('EngineEdition')`.  5 is the one that changes the security model outright:
#: Azure SQL Database has no server-level principal, so a login cannot be created and a
#: three-part cross-database name is not legal.
_ENGINE_EDITIONS: dict[int, str] = {
    1: "sql_server",  # Personal/Desktop
    2: "sql_server",  # Standard
    3: "sql_server",  # Enterprise
    4: "sql_server",  # Express
    5: "azure_sql_database",
    6: "azure_synapse_analytics",
    8: "azure_sql_managed_instance",
    9: "azure_sql_edge",
    11: "azure_synapse_serverless",
}

#: Variants that behave like a boxed instance for cross-database naming.  Azure SQL Database
#: is the exception, not the rule, and Synapse is neither — it is listed nowhere here so it
#: gets the conservative answer.
_CROSS_DATABASE_VARIANTS = frozenset({"sql_server", "azure_sql_managed_instance"})

#: ODBC's own quoting rule: a value containing any of these must be brace-wrapped, and an
#: inner `}` doubled.  A password with a semicolon in it is otherwise a connection-string
#: keyword injection, which is why `with_password()` and not `engine.py` owns this.
_ODBC_NEEDS_BRACES = set("[]{}(),;?*=!@ ")


def _odbc_value(value: Any) -> str:
    """Render one ODBC connection-string value, brace-wrapping and escaping as required."""

    text = str(value)
    if "\x00" in text or "\n" in text or "\r" in text:
        raise DialectError("an ODBC connection value cannot contain a NUL or a line break")
    if text == "" or any(ch in _ODBC_NEEDS_BRACES for ch in text):
        return "{" + text.replace("}", "}}") + "}"
    return text


class MSSQLDialect(DeferredSurface, Dialect):
    """Authors Microsoft SQL Server SQL, for pyodbc or for pymssql.

    One class, two drivers, two placeholder grammars (`?` and `%s`) selected at construction
    — the concrete illustration of decision D4.  A dialect that hardcoded `?` would emit
    broken SQL for half of its own connections.
    """

    engine: ClassVar[Engine] = Engine.MSSQL
    display_name: ClassVar[str] = "Microsoft SQL Server"
    default_port: ClassVar[int | None] = 1433
    default_schema: ClassVar[str | None] = "dbo"

    #: `sysname` is `nvarchar(128)`, so the limit is 128 characters, not bytes.
    max_identifier_length: ClassVar[int] = 128

    quote_open: ClassVar[str] = "["
    quote_close: ClassVar[str] = "]"

    #: Driver 18 and not 17: it defaults `Encrypt=yes`, which is what Azure SQL Database and
    #: any modern on-premises instance under a TLS-enforcing policy already require.  Naming
    #: a floor is the whole reason §5.1 says "Driver 18" rather than "the ODBC driver".
    default_odbc_driver: ClassVar[str] = "ODBC Driver 18 for SQL Server"

    # -- the write side's per-engine constants -----------------------------------------

    #: Every spelling of "replace what is already there" T-SQL has, refused in a `create_*`
    #: body and in the DDL `create_*` generates (DESIGN-MCP-TOOLS.md §8.1).
    #:
    #: `CREATE OR ALTER` is the real one — 2016 SP1 onwards, and the clause `edit_routine()`
    #: itself splices in.  `CREATE OR REPLACE` is not T-SQL at all and is listed anyway,
    #: because a model that has written PostgreSQL all morning will try it and deserves the
    #: message that names the right tool rather than a syntax error from the server.  The four
    #: `ALTER <object>` forms are the same act under the other name: `ALTER VIEW` replaces a
    #: view's whole definition, and a body starting with one is an edit wearing a create's
    #: label.  `ALTER TABLE` joins them because on this engine it is how a column is dropped.
    or_replace_spellings: ClassVar[tuple[str, ...]] = (
        "CREATE OR ALTER",
        "CREATE OR REPLACE",
        "ALTER VIEW",
        "ALTER FUNCTION",
        "ALTER PROCEDURE",
        "ALTER PROC",
        "ALTER TRIGGER",
        "ALTER TABLE",
    )

    #: SQL Server's atomic replacement is spelled `CREATE OR ALTER`, not `CREATE OR REPLACE`.
    create_or_replace_clause: ClassVar[str] = "OR ALTER"

    #: `sp_executesql` and the TDS protocol stop at 2 100 parameters per statement, of which
    #: one is spoken for.  This is the binding constraint on a batch insert long before
    #: `MAX_WRITE_ROWS` is: 1 000 rows of three columns already exceeds it.
    max_bound_parameters: ClassVar[int | None] = 2100

    #: A `VALUES` clause on this engine lists at most 1 000 row tuples.
    max_insert_value_rows: ClassVar[int | None] = 1000

    #: There is no boolean type: `bit` takes 1 and 0, and `DEFAULT TRUE` is a syntax error.
    boolean_literals: ClassVar[tuple[str, str]] = ("1", "0")

    #: T-SQL has `CURRENT_TIMESTAMP` and neither of the other two ANSI niladic functions.
    unsupported_default_keywords: ClassVar[frozenset[str]] = frozenset(
        {"CURRENT_DATE", "CURRENT_TIME"}
    )

    #: `nvarchar(max)` and friends.
    supports_max_length_argument: ClassVar[bool] = True

    #: The system types `create_table()` will emit.  Deliberately the *system* types only:
    #: an alias type (`CREATE TYPE dbo.Postcode FROM nvarchar(10)`) is a schema-scoped object
    #: with its own permissions, and emitting one would be naming an object the rule table
    #: never authorised.  `timestamp` is absent and `rowversion` present because the first is
    #: a deprecated synonym for the second and has nothing to do with time.
    column_types: ClassVar[frozenset[str]] = frozenset(
        {
            "bigint", "int", "smallint", "tinyint", "bit",
            "decimal", "numeric", "money", "smallmoney", "float", "real",
            "date", "datetime", "datetime2", "datetimeoffset", "smalldatetime", "time",
            "char", "varchar", "text", "nchar", "nvarchar", "ntext",
            "binary", "varbinary", "image",
            "uniqueidentifier", "xml", "sql_variant", "rowversion", "hierarchyid",
            "geography", "geometry",
        }
    )

    # -- capabilities ------------------------------------------------------------------

    @property
    def capabilities(self) -> Capabilities:
        """Three flags depend on the probe: the two `CREATE OR ALTER` flags, which need
        2016 SP1, and cross-database reference, which Azure SQL Database removes.

        `supports_returning` is `True` on this engine at every supported version even though
        the keyword is `OUTPUT` rather than `RETURNING`: the flag asks whether a DML statement
        can hand rows back, and here it can.  The spelling difference belongs to the builder,
        not to the capability.
        """

        probed = self.probed
        version = self._traits.version if probed else ()
        variant = self._traits.variant if probed else ""
        # Azure SQL Database and Managed Instance both have CREATE OR ALTER regardless of the
        # ProductVersion they report — Azure SQL Database still says 12.0.x, which would fail
        # the boxed-server floor below and turn the flag off on a server that has the feature.
        azure = variant.startswith("azure_")
        or_alter = probed and (azure or version >= _CREATE_OR_ALTER_FLOOR)
        return Capabilities(
            engine=Engine.MSSQL,
            supports_schemas=True,
            supports_stored_procedures=True,
            supports_table_valued_functions=True,
            supports_roles=True,
            supports_users=True,
            # A "group" on this engine is a database role; there is no separate object.
            supports_groups=True,
            supports_create_or_replace_view=or_alter,
            supports_create_or_replace_routine=or_alter,
            supports_transactional_ddl=True,
            supports_alter_column=True,
            supports_returning=True,
            supports_cross_database_reference=probed and variant in _CROSS_DATABASE_VARIANTS,
            supports_data_modifying_cte=True,
            max_identifier_length=self.max_identifier_length,
            param_style=self.param_style,
            probed=probed,
        )

    @property
    def case_folding(self) -> CaseFolding:
        """Preserve-and-compare-by-collation, with the sensitivity read from the probe.

        The **database** collation, never the server collation: `SERVERPROPERTY('Collation')`
        gives the instance default, and a database restored from elsewhere routinely differs
        from it.  Getting this from the instance would make every identifier comparison on
        that database wrong in one direction or the other.
        """

        return (
            CaseFolding.PRESERVE_CASE_SENSITIVE
            if self._collation_is_case_sensitive()
            else CaseFolding.PRESERVE_CASE_INSENSITIVE
        )

    def _collation_is_case_sensitive(self) -> bool:
        """Whether the database collation compares identifiers case-sensitively.

        Refuses to answer when the probe could not read the collation.  Both guesses are
        wrong in a way that matters: assuming case-insensitive folds the match key and widens
        every rule to cover names it was not written for, and assuming case-sensitive stops a
        *deny* rule from covering a name the server treats as the same object.
        """

        sensitive = self.traits.case_sensitive_collation
        if sensitive is None:
            raise DialectNotConfiguredError(
                "the MS-SQL probe could not read the database collation, so identifier "
                "comparison is unknown. d-MCP will not guess it: the collation decides "
                "whether a rule for 'salaries' covers the table 'Salaries'."
            )
        return sensitive

    # -- quoting and normalisation -----------------------------------------------------

    def quote_identifier(self, name: str) -> str:
        """`[name]`, with any inner `]` doubled.

        Brackets rather than double quotes: `"..."` is an identifier delimiter only while
        `QUOTED_IDENTIFIER` is `ON`, and a session that turned it off would reinterpret every
        quoted name as a string literal.  Brackets mean the same thing whatever the session
        setting is.

        A name that is entirely whitespace is refused: SQL Server accepts `[ ]` as an
        identifier, and an object called "one space" is indistinguishable from one called
        "two spaces" anywhere a human has to read it.
        """

        if isinstance(name, str) and name != "" and name.strip() == "":
            raise InvalidIdentifierError(
                "an MS-SQL identifier consisting only of whitespace is refused: the server "
                "accepts it, but no human can tell two of them apart"
            )
        return self._quote(name)

    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str:
        """Verbatim — SQL Server stores an identifier exactly as it was written, quoted or not.

        It still raises before `configure()`.  That is not pedantry: the canonical form is
        only half the answer, the match key is the other half, and a caller that can get a
        canonical name out of an unprobed dialect will pair it with a match key it could not
        have got, or worse, skip the match key entirely.  One gate, on both.
        """

        if not isinstance(raw, str) or raw == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        if "\x00" in raw:
            raise InvalidIdentifierError("the identifier contains an embedded NUL")
        # Raises unless probed; the value itself is not needed to canonicalise.
        self._collation_is_case_sensitive()
        return raw

    def identifier_match_key(self, name: str) -> str:
        """ASCII-lower under a `_CI_` collation; the canonical form under `_CS_`, `_BIN` or
        `_BIN2`.

        This is the pair decision D5 exists for.  Under the usual `..._CI_AS` the canonical
        form of the table is `Salaries` and its key is `salaries`, so a rule written for
        `salaries` matches.  Under `..._CS_AS` the key is `Salaries` and that same rule
        correctly fails to match, because on that server the two names are two objects.
        """

        if not isinstance(name, str) or name == "":
            raise InvalidIdentifierError("an identifier must be a non-empty str")
        if self._collation_is_case_sensitive():
            return name
        return fold_ascii_lower(name, engine=self.engine)

    # -- what the guard borrows --------------------------------------------------------

    def guard_traits(self) -> GuardTraits:
        """MS-SQL grammar facts, including the batch separator `sqlparse` cannot see.

        `GO` is not T-SQL: it is a convention of `sqlcmd` and SSMS, handled entirely
        client-side, so no SQL tokeniser will ever report it as a statement boundary.  A
        batch that reads as one harmless statement to `sqlparse` can therefore be two, which
        is exactly the smuggling case the guard exists to stop — hence the regex is supplied
        here rather than left to be discovered.

        `DENY` is in `security_keywords` alongside `GRANT`/`REVOKE`; it is MS-SQL's third
        privilege verb and has no counterpart on the other three engines.
        """

        return GuardTraits(
            write_keywords=frozenset({"INSERT", "UPDATE", "DELETE", "MERGE", "TRUNCATE"}),
            ddl_keywords=frozenset({"CREATE", "ALTER", "DROP"}),
            security_keywords=frozenset(
                {
                    "GRANT",
                    "REVOKE",
                    "DENY",
                    "CREATE LOGIN",
                    "ALTER LOGIN",
                    "DROP LOGIN",
                    "CREATE USER",
                    "ALTER USER",
                    "DROP USER",
                    "CREATE ROLE",
                    "ALTER ROLE",
                    "DROP ROLE",
                    "ALTER SERVER ROLE",
                    "EXECUTE AS",
                }
            ),
            line_comment_prefixes=("--",),
            block_comment_delimiters=("/*", "*/"),
            executable_comment_pattern=None,
            # `GO` alone on a line, optionally followed by a repeat count and a trailing
            # line comment, case-insensitively.
            batch_separator_pattern=re.compile(r"(?im)^[ \t]*GO(?:[ \t]+\d+)?[ \t]*(?:--[^\n]*)?$"),
            writing_cte_shape=WritingCTEShape.DML_THROUGH_REFERENCE,
        )

    # -- connection --------------------------------------------------------------------

    def _uses_odbc(self) -> bool:
        """Whether this instance is serving pyodbc.

        Keyed on the driver name where the registry supplied one, and on the paramstyle
        otherwise, because pyodbc is the only MS-SQL driver of the two that is `qmark`.
        """

        if self.driver is not None:
            return self.driver == "pyodbc"
        return self.param_style is ParamStyle.QMARK

    def _connection_target(self, profile: ConnectionProfile):
        """The server, instance and port to dial, whichever field each one was typed into.

        A profile may hold `PC-ARR\\SQLEXPRESS:56879` in `host`, because that is the form an
        environment file uses and the form a version 1 profile was stored in.  Passed through
        as `Server=` it reaches FreeTDS, which guesses, and reports DB-Lib 20009 - a
        *transport* error naming none of this.  `reconcile_mssql_profile()` splits it into the
        three values instead, and refuses only a piece that contradicts a column the profile
        also fills.

        It then applies the one documented precedence - when a port is present the port is
        used and the instance name is not used to reach the server - for both drivers from
        one place, so pyodbc and pymssql cannot come to disagree.
        """

        from ..targets import reconcile_mssql_profile

        host = self._require(profile, "host")
        try:
            target = reconcile_mssql_profile(profile)
        except ValueError as exc:
            raise ValueError(f"the host {host!r} cannot be used as a server address: {exc}") from None

        if target.port is None and not target.instance:
            # No instance to resolve through the Browser, so the engine default applies —
            # the same value `_profile_port()` has always supplied.
            from ..targets import MsSqlTarget

            target = MsSqlTarget(
                server=target.server,
                instance=None,
                port=self._profile_port(profile),
                compound=False,
            )
        return target

    def build_dsn(self, profile: ConnectionProfile) -> str | dict[str, Any]:
        """An ODBC connection string for pyodbc, a keyword mapping for pymssql — no password.

        The pyodbc string carries no `PWD` field at all rather than a placeholder to be
        string-substituted later: a placeholder invites `str.format()` or a `replace()`, and
        a password containing a `{`, a `}` or a `;` then either crashes the substitution or
        injects a connection-string keyword.  `with_password()` appends the field properly
        escaped, at the `connect()` call and nowhere else.

        Under `auth_mode = 'integrated'` the ODBC string carries `Trusted_Connection=yes`
        and no `UID` field at all, and pymssql refuses the mode outright (§4.2).
        """

        driver = "pyodbc" if self._uses_odbc() else "pymssql"
        auth_mode = self._profile_auth_mode(profile)
        if auth_mode == "none":
            raise DialectError(
                "auth_mode 'none' means there is no authentication step at all, which is "
                "true of a SQLite file and of nothing else. A SQL Server connection uses "
                "'password' or 'integrated'."
            )
        # pymssql + integrated is unrepresentable, and this is the third of the three
        # layers that say so.  FreeTDS has no SSPI path, so the attempt could never work;
        # left to fail at connect time it reports DB-Lib 20009, "Adaptive Server is
        # unavailable or does not exist" — a transport error that sends the user hunting a
        # firewall problem that is not there.  That is the reported defect.
        self._refuse_integrated(profile, driver)
        integrated = auth_mode == "integrated"

        target = self._connection_target(profile)
        database = self._require(profile, "database")
        username = profile.get("username")
        timeout = self._profile_timeout(profile)
        options = self._profile_options(profile)

        if not self._uses_odbc():
            # §6.3: `server="PC-ARR", port=1433` for the port form, and
            # `server="PC-ARR\\SQLEXPRESS"` with no port keyword at all for the instance
            # form — FreeTDS must reach the SQL Server Browser to learn the port, and a
            # port keyword beside an instance name is what made it guess before.
            if target.port is not None:
                dsn: dict[str, Any] = {"server": target.server, "port": target.port}
            else:
                dsn = {"server": f"{target.server}\\{target.instance}"}
            dsn.update(
                {
                    "database": database,
                    # Shows in sys.dm_exec_sessions.program_name, so a DBA can identify
                    # d-MCP's sessions without asking.
                    "appname": "SAPE d-MCP",
                }
            )
            if username:
                dsn["user"] = str(username)
            if timeout:
                # pymssql's `timeout` really is a query timeout, the only one of the four
                # drivers where the profile's statement_timeout_s maps onto exactly that.
                dsn["timeout"] = timeout
                dsn["login_timeout"] = timeout
            dsn.update(options)
            if "password" in dsn:
                raise DialectError(
                    "options_json must not carry a password; use the credential store"
                )
            return dsn

        odbc_driver = str(options.pop("odbc_driver", self.default_odbc_driver))
        # The `tcp:` prefix is emitted in the port form only.  With a named instance the
        # driver must reach the SQL Server Browser on UDP 1434 to learn the port, and
        # pinning a protocol prefix in front of an instance name behaves differently
        # between driver versions; leaving it off is the documented form.
        server = (
            f"tcp:{target.server},{target.port}"
            if target.port is not None
            else f"{target.server}\\{target.instance}"
        )
        fields: list[tuple[str, Any]] = [
            ("Driver", "{" + odbc_driver.replace("}", "}}") + "}"),
            ("Server", server),
            ("Database", database),
        ]
        if integrated:
            # No `UID` field at all rather than an empty one: an empty `UID=` is a
            # different thing to ODBC and has been known to defeat the trusted path.  No
            # `PWD` either, ever — `engine.connect()` refuses to hold a password for a
            # profile that does not authenticate with one, so `with_password()` is never
            # reached here.
            fields.append(("Trusted_Connection", "yes"))
        elif username:
            fields.append(("UID", str(username)))
        # A trusted connection is not an encrypted one; both stay as they were. These are
        # defaults, not fixtures: an on-premises server with a self-signed certificate needs
        # `TrustServerCertificate=yes`, and options_json is where that is said. Appending the
        # default anyway would put the key in the string twice, and which of the two the
        # driver honours is not something to leave to the driver.
        overridden = {key.lower() for key in options}
        fields.extend(
            (key, value)
            for key, value in (("Encrypt", "yes"), ("TrustServerCertificate", "no"))
            if key.lower() not in overridden
        )
        fields.append(("APP", "SAPE d-MCP"))
        for key, value in options.items():
            if key.lower() in ("pwd", "password"):
                raise DialectError(
                    "options_json must not carry a password; use the credential store"
                )
            fields.append((key, value))

        parts = []
        for key, value in fields:
            # The Driver field is pre-wrapped above; everything else goes through the
            # escaper, including anything that arrived from options_json.
            rendered = value if key == "Driver" else _odbc_value(value)
            parts.append(f"{key}={rendered}")
        return ";".join(parts) + ";"

    def with_password(
        self, dsn: str | dict[str, Any], password: SecretStr | str
    ) -> str | dict[str, Any]:
        """Append `PWD` to the ODBC string, or `password` to the pymssql mapping.

        The result is the secret and must never be logged, stored or put in an exception
        message.  `engine.py` calls this inside the `try/finally` that clears the local name
        immediately after `connect()` returns.
        """

        secret = password.get_secret_value() if isinstance(password, SecretStr) else password
        if isinstance(dsn, dict):
            return {**dsn, "password": secret}
        separator = "" if dsn.endswith(";") or dsn == "" else ";"
        return f"{dsn}{separator}PWD={_odbc_value(secret)};"

    def health_check_sql(self) -> str:
        """`SELECT 1`."""

        return "SELECT 1"

    def version_probe_sql(self) -> str:
        """One row of seven columns: banner, version, edition code, edition name, database
        collation, default schema and login name.

        `DATABASEPROPERTYEX(DB_NAME(), 'Collation')` rather than `sys.databases`: it returns
        the same value for the current database and needs no `VIEW ANY DATABASE`, which a
        least-privilege application login will not have — and a probe that fails on a
        correctly restricted account is a probe that pushes people to over-privilege it.

        `SCHEMA_NAME()` gives the login's *own* default schema, which is frequently not `dbo`
        and decides what an unqualified name resolves to.
        """

        return (
            "SELECT CONVERT(nvarchar(4000), @@VERSION), "
            "CONVERT(nvarchar(128), SERVERPROPERTY('ProductVersion')), "
            "CONVERT(int, SERVERPROPERTY('EngineEdition')), "
            "CONVERT(nvarchar(128), SERVERPROPERTY('Edition')), "
            "CONVERT(nvarchar(128), DATABASEPROPERTYEX(DB_NAME(), 'Collation')), "
            "CONVERT(nvarchar(128), SCHEMA_NAME()), "
            "CONVERT(nvarchar(128), SUSER_SNAME())"
        )

    @classmethod
    def parse_traits(cls, rows: Sequence[Sequence[Any]]) -> ServerTraits:
        """Build `ServerTraits`, deriving the variant from `EngineEdition` and the identifier
        case sensitivity from the database collation name."""

        if not rows:
            raise DialectError("the MS-SQL version probe returned no rows")
        row = tuple(rows[0])
        if len(row) < 7:
            raise DialectError(f"the MS-SQL version probe returned {len(row)} columns, expected 7")

        banner = "" if row[0] is None else str(row[0])
        product = "" if row[1] is None else str(row[1])
        match = _VERSION_RE.search(product) or _VERSION_RE.search(banner)
        if match is None:
            raise DialectError(f"cannot parse an MS-SQL version out of {product!r}")
        version = tuple(int(part) for part in match.group(1).split("."))

        edition_code: int | None
        try:
            edition_code = None if row[2] is None else int(row[2])
        except (TypeError, ValueError):
            edition_code = None
        variant = _ENGINE_EDITIONS.get(edition_code, "sql_server") if edition_code else "sql_server"

        collation = None if row[4] is None else str(row[4])
        return ServerTraits(
            raw_version=banner,
            version=version,
            variant=variant,
            collation=collation,
            case_sensitive_collation=cls.collation_is_case_sensitive(collation),
            lower_case_table_names=None,
            default_schema=None if row[5] is None else str(row[5]),
            current_user=None if row[6] is None else str(row[6]),
        )

    @staticmethod
    def collation_is_case_sensitive(collation: str | None) -> bool | None:
        """Classify a SQL Server collation name, returning `None` when it cannot be classified.

        `_CI_` is case-insensitive, `_CS_` case-sensitive, and any `_BIN`/`_BIN2` collation
        compares by code point and is therefore case-sensitive.  A UTF-8 collation carries the
        same `_CI_`/`_CS_` token followed by `_SC_UTF8`, so the token test still holds; a name
        with neither token — which should not exist — returns `None` and the dialect refuses
        to fold rather than picking the common case.
        """

        if not collation:
            return None
        upper = collation.upper()
        if "_BIN" in upper:
            return True
        if "_CS_" in upper or upper.endswith("_CS"):
            return True
        if "_CI_" in upper or upper.endswith("_CI"):
            return False
        return None

    # -- session hardening --------------------------------------------------------------

    def read_only_session(self) -> ReadOnlySession:
        """An explicit transaction that is always rolled back — the weakest of the four, and
        the docstring says so rather than letting the name imply otherwise.

        **SQL Server has no read-only session or transaction mode.**  There is no
        `SET TRANSACTION READ ONLY`, no session flag equivalent to PostgreSQL's
        `transaction_read_only`, and `SET LOCK_TIMEOUT`/`SET QUERY_GOVERNOR_COST_LIMIT` bound
        other things entirely.  The mechanisms that would genuinely refuse a write are all
        outside a session: a database in `READ_ONLY` state, an Availability Group secondary
        reached with `ApplicationIntent=ReadOnly`, or — the one DESIGN-MCP-TOOLS.md §9.1 step
        11 gestures at — a login that simply has no write permission.  The last of those is
        the right answer and it is an operator's to give: the connection profile has no
        read-only-login column today, and adding one is a Connections-page change, not this
        one.  Until it exists, this is what the session layer can do by itself.

        So what is promised here is narrower than on the other three engines and is recorded
        as `ReadOnlyEnforcement.DISCARDS`: a write that got past the guard would *run*, inside
        an explicit transaction that `engine.read_only_session()` unconditionally rolls back,
        so it can never be made durable.  SQL Server's DDL is transactional too, so a `CREATE`
        or `DROP` is undone by the same rollback; what is not undone is anything outside the
        transaction's reach — a side effect through `xp_cmdshell`, a linked server, or the
        identity-value consumption of a rolled-back `INSERT`.  Those the guard's denylist and
        classification remain the only defence against, which is the honest statement of where
        the defence in depth stops on this engine.

        `@@TRANCOUNT` is the verify: it is the only observable that says whether the
        transaction actually opened.  It is compared as "greater than zero" rather than as
        "equal to one" because ODBC in its default, non-autocommit mode has already opened one
        of its own, and our `BEGIN TRANSACTION` nests inside it.  For the same reason the
        release is guarded with `IF @@TRANCOUNT > 0`: a bare `ROLLBACK TRANSACTION` with no
        transaction open is error 3903, and the release must never itself raise.

        `verify_released` is deliberately `None`, and this is where the design's instruction
        stops surviving contact with the driver.  Under ODBC's default implicit-transaction
        mode the verifying `SELECT` opens a transaction of its own *before* it can report
        `@@TRANCOUNT`, so after a successful rollback it would still answer `1`.  Checking it
        would therefore close a perfectly healthy connection after every single read.  The
        release is judged here by whether `ROLLBACK TRANSACTION` raised, and by the fact that
        `engine.py` closes the connection if it did — and closing a SQL Server connection
        rolls back whatever it was holding, which is the guarantee that actually matters.
        """

        return ReadOnlySession(
            harden=(self._session_statement("BEGIN TRANSACTION"),),
            release=(self._session_statement("IF @@TRANCOUNT > 0 ROLLBACK TRANSACTION"),),
            verify=self._session_statement(
                "SELECT CASE WHEN @@TRANCOUNT > 0 THEN 1 ELSE 0 END"
            ),
            scope=ReadOnlyScope.TRANSACTION,
            enforcement=ReadOnlyEnforcement.DISCARDS,
            note=(
                "SQL Server explicit transaction, always rolled back: a write cannot be "
                "committed, but it is not refused"
            ),
        )

    def statement_timeout_statements(self, seconds: int) -> tuple[Query, ...]:
        """None: SQL Server has no session-level statement timeout, so `engine.py` sets the
        driver's.

        `SET LOCK_TIMEOUT` bounds waiting for a lock, not running; `SET
        QUERY_GOVERNOR_COST_LIMIT` bounds the optimiser's *estimated* cost, which is not
        seconds and refuses the statement before it starts rather than after a real budget is
        spent.  Neither is the profile's `statement_timeout_s`, and issuing one under that
        name would be a false claim in `pg_settings`' absence.

        The timeout is therefore a client-side one on this engine: pyodbc's
        `Connection.timeout` and pymssql's query timeout, both applied by `engine.py`
        immediately after connecting.  The difference matters and is documented rather than
        papered over — a client-side timeout abandons the statement and the server may go on
        running it until it notices the connection is gone.
        """

        self._timeout_literal(seconds)
        return ()

    # -- catalogue introspection -------------------------------------------------------

    #: The `sys` catalogue views the builders below read, as `Query.touches` entries.  SQL
    #: Server applies metadata visibility rules to these views — a principal sees only what
    #: it owns or holds a permission on — so no explicit privilege predicate is needed on
    #: this engine, unlike PostgreSQL's world-readable `pg_catalog`.
    _SYS_SCHEMAS = ObjectRef(schema="sys", name="schemas", object_type=ObjectType.VIEW)
    _SYS_DATABASES = ObjectRef(schema="sys", name="databases", object_type=ObjectType.VIEW)

    #: The four the server installs, which are exactly `database_id <= 4`.
    SYSTEM_DATABASES: ClassVar[frozenset[str]] = frozenset({"master", "model", "msdb", "tempdb"})

    #: Databases that are not system databases by id but are by convention: replication's
    #: distribution database and the ones the SQL Server feature packs install.  Rendered
    #: into the statement rather than bound because it is a fixed list this module wrote —
    #: no value from outside ever reaches it — and `IN (?, ?, ...)` cannot be built from a
    #: constant without inventing a parameter count.
    _CONVENTIONAL_SYSTEM_DATABASES = (
        "('distribution', 'SSISDB', 'ReportServer', 'ReportServerTempDB')"
    )
    _SYS_TABLES = ObjectRef(schema="sys", name="tables", object_type=ObjectType.VIEW)
    _SYS_VIEWS = ObjectRef(schema="sys", name="views", object_type=ObjectType.VIEW)
    _SYS_OBJECTS = ObjectRef(schema="sys", name="objects", object_type=ObjectType.VIEW)
    _SYS_COLUMNS = ObjectRef(schema="sys", name="columns", object_type=ObjectType.VIEW)
    _SYS_TYPES = ObjectRef(schema="sys", name="types", object_type=ObjectType.VIEW)
    _SYS_PARAMETERS = ObjectRef(schema="sys", name="parameters", object_type=ObjectType.VIEW)
    _SYS_DEFAULTS = ObjectRef(
        schema="sys", name="default_constraints", object_type=ObjectType.VIEW
    )
    _SYS_EXTENDED = ObjectRef(
        schema="sys", name="extended_properties", object_type=ObjectType.VIEW
    )
    _SYS_KEY_CONSTRAINTS = ObjectRef(
        schema="sys", name="key_constraints", object_type=ObjectType.VIEW
    )
    _SYS_INDEXES = ObjectRef(schema="sys", name="indexes", object_type=ObjectType.VIEW)
    _SYS_INDEX_COLUMNS = ObjectRef(
        schema="sys", name="index_columns", object_type=ObjectType.VIEW
    )
    _SYS_FOREIGN_KEYS = ObjectRef(schema="sys", name="foreign_keys", object_type=ObjectType.VIEW)
    _SYS_FOREIGN_KEY_COLUMNS = ObjectRef(
        schema="sys", name="foreign_key_columns", object_type=ObjectType.VIEW
    )
    _SYS_SQL_MODULES = ObjectRef(schema="sys", name="sql_modules", object_type=ObjectType.VIEW)
    _SYS_DATABASE_PRINCIPALS = ObjectRef(
        schema="sys", name="database_principals", object_type=ObjectType.VIEW
    )
    _SYS_SERVER_PRINCIPALS = ObjectRef(
        schema="sys", name="server_principals", object_type=ObjectType.VIEW
    )
    _SYS_DATABASE_ROLE_MEMBERS = ObjectRef(
        schema="sys", name="database_role_members", object_type=ObjectType.VIEW
    )
    _SYS_DATABASE_PERMISSIONS = ObjectRef(
        schema="sys", name="database_permissions", object_type=ObjectType.VIEW
    )

    #: `sys.objects.type` for the two routine families.  `FS`/`FT`/`PC` are the CLR forms:
    #: they are listed because they are callable and permissionable, even though their body
    #: is an assembly and `sys.sql_modules` holds no text for them.
    _FUNCTION_TYPES = "('FN', 'IF', 'TF', 'FS', 'FT')"
    _PROCEDURE_TYPES = "('P', 'PC')"
    #: Both families at once, for `describe_routine()`, which is called with an object type
    #: the caller may have guessed wrong.
    _ROUTINE_TYPES = "('FN', 'IF', 'TF', 'FS', 'FT', 'P', 'PC')"

    #: The MS_Description extended property is where SSMS puts a description, and it is the
    #: only thing on this engine that answers to "comment".
    _COMMENT_JOIN = (
        "LEFT JOIN sys.extended_properties AS ep "
        "       ON ep.class = 1 AND ep.major_id = {major} AND ep.minor_id = {minor} "
        "      AND ep.name = 'MS_Description'"
    )

    #: Built with `+` rather than `CONCAT()` so it works back to SQL Server 2008, and with no
    #: `%` anywhere: a literal percent sign in a statement is a formatting directive to
    #: pymssql, whose paramstyle is `pyformat`.
    _TYPE_EXPRESSION = (
        "CASE "
        "WHEN t.name IN ('varchar', 'char', 'varbinary', 'binary') "
        "     THEN t.name + '(' + CASE WHEN c.max_length = -1 THEN 'max' "
        "                              ELSE CAST(c.max_length AS varchar(11)) END + ')' "
        # max_length is in bytes, and these three are two bytes a character, so the declared
        # length is half of it — reporting nvarchar(100) for an nvarchar(50) would tell a
        # caller it may store twice what it can.
        "WHEN t.name IN ('nvarchar', 'nchar') "
        "     THEN t.name + '(' + CASE WHEN c.max_length = -1 THEN 'max' "
        "                              ELSE CAST(c.max_length / 2 AS varchar(11)) END + ')' "
        "WHEN t.name IN ('decimal', 'numeric') "
        "     THEN t.name + '(' + CAST(c.precision AS varchar(11)) + ', ' "
        "                       + CAST(c.scale AS varchar(11)) + ')' "
        "WHEN t.name IN ('datetime2', 'datetimeoffset', 'time') "
        "     THEN t.name + '(' + CAST(c.scale AS varchar(11)) + ')' "
        "ELSE t.name END"
    )

    def _object_where(self, schema_column: str, name_column: str) -> str:
        """`WHERE <schema> = COALESCE(?, SCHEMA_NAME()) AND <name> = ?`, in parameter order.

        `SCHEMA_NAME()` is the *login's* default schema, which is not always `dbo` and is
        exactly what an unqualified name would have resolved to had the caller written one.
        A reference with no schema is therefore described against the same object the same
        session would have reached, rather than silently returning nothing.
        """

        return (
            f"WHERE {schema_column} = COALESCE({self.placeholder(0, 'schema')}, SCHEMA_NAME()) "
            f"  AND {name_column} = {self.placeholder(1, 'name')}"
        )

    def list_databases(self, *, include_system: bool = False) -> Query:
        """Databases this login can actually open, system ones marked rather than hidden.

        Two filters, and they do different jobs.  `sys.databases` is already
        permission-filtered — a login without `VIEW ANY DATABASE` sees only `master`,
        `tempdb` and the databases it owns or is a user in — so the short list a restricted
        account gets is *not* an error and must not be presented as one.  What the
        catalogue does not do is say whether the connection would be accepted, which is
        what `HAS_DBACCESS` answers.

        `state_desc = 'ONLINE'` comes first because `HAS_DBACCESS` returns `NULL` for a
        database that is offline or restoring; `NULL = 1` is not true, so the two together
        are belt and braces, and the explicit state test is what lets the GUI explain an
        absence rather than silently drop a name the user expected to see.
        """

        clause = (
            ""
            if include_system
            else f"  AND d.database_id > 4 AND d.name NOT IN {self._CONVENTIONAL_SYSTEM_DATABASES} "
        )
        return self._catalogue_query(
            "SELECT d.name AS database_name, "
            "d.state_desc, "
            "d.collation_name, "
            "d.is_read_only, "
            "CASE WHEN d.database_id <= 4 "
            f"       OR d.name IN {self._CONVENTIONAL_SYSTEM_DATABASES} "
            "     THEN 1 ELSE 0 END AS is_system "
            "FROM sys.databases AS d "
            "WHERE d.state_desc = 'ONLINE' "
            "  AND HAS_DBACCESS(d.name) = 1 "
            f"{clause}"
            "ORDER BY is_system, d.name",
            touches=(self._SYS_DATABASES,),
        )

    @property
    def bootstrap_database(self) -> str | None:
        """`master` — but the caller tries the profile's own database first.

        A *contained* database user cannot open `master` at all and can open only its own
        database, which is why §8.3 makes this the second link of a chain rather than the
        only one, and why the Database field always stays hand-editable.
        """

        return "master"

    def list_schemas(self) -> Query:
        """User schemas, with the server's own and the fixed database roles' excluded.

        The `schema_id` range is not a magic number pulled from nowhere: SQL Server creates
        one schema per fixed database role (`db_owner`, `db_datareader` and the rest) and
        gives them ids 16384-16399.  Listing them would offer the operator sixteen schemas
        that can never contain an object.
        """

        return self._catalogue_query(
            "SELECT s.name AS schema_name "
            "FROM sys.schemas AS s "
            "WHERE s.name NOT IN ('sys', 'INFORMATION_SCHEMA', 'guest') "
            "  AND s.schema_id NOT BETWEEN 16384 AND 16399 "
            "ORDER BY s.name",
            touches=(self._SYS_SCHEMAS,),
        )

    def list_tables(self, schema: str | None = None) -> Query:
        """User tables.  `is_ms_shipped` excludes the ones the server installed itself."""

        clause, values, names = self._schema_filter(schema, "s.name")
        return self._catalogue_query(
            "SELECT s.name AS schema_name, t.name AS table_name, "
            "CAST(ep.value AS nvarchar(4000)) AS table_comment "
            "FROM sys.tables AS t "
            "JOIN sys.schemas AS s ON s.schema_id = t.schema_id "
            + self._COMMENT_JOIN.format(major="t.object_id", minor="0")
            + " WHERE t.is_ms_shipped = 0"
            f"{clause} "
            "ORDER BY s.name, t.name",
            values,
            names,
            touches=(self._SYS_TABLES, self._SYS_SCHEMAS, self._SYS_EXTENDED),
        )

    def list_views(self, schema: str | None = None) -> Query:
        """Views.  SQL Server has no materialised view — an indexed view is still evaluated
        against live data — so the flag is always 0 and the row shape stays uniform."""

        clause, values, names = self._schema_filter(schema, "s.name")
        return self._catalogue_query(
            "SELECT s.name AS schema_name, v.name AS view_name, "
            "0 AS is_materialised, CAST(ep.value AS nvarchar(4000)) AS view_comment "
            "FROM sys.views AS v "
            "JOIN sys.schemas AS s ON s.schema_id = v.schema_id "
            + self._COMMENT_JOIN.format(major="v.object_id", minor="0")
            + " WHERE v.is_ms_shipped = 0"
            f"{clause} "
            "ORDER BY s.name, v.name",
            values,
            names,
            touches=(self._SYS_VIEWS, self._SYS_SCHEMAS, self._SYS_EXTENDED),
        )

    def _list_routines(self, schema: str | None, types: str) -> Query:
        """The shared body of `list_functions()` and `list_procedures()`.

        `types` is one of the two class constants above — a literal this module owns, never
        anything that arrived from a caller.
        """

        clause, values, names = self._schema_filter(schema, "s.name")
        return self._catalogue_query(
            "SELECT s.name AS schema_name, o.name AS routine_name, "
            # No overloading on this engine: one name is one routine, so there is no
            # discriminator to report and NULL is the honest answer rather than an empty
            # string pretending to be a signature.
            "NULL AS signature, "
            "COALESCE((SELECT TYPE_NAME(rp.user_type_id) FROM sys.parameters AS rp "
            "          WHERE rp.object_id = o.object_id AND rp.parameter_id = 0), "
            "         CASE WHEN o.type IN ('IF', 'TF', 'FT') THEN 'TABLE' END) AS returns, "
            "CASE WHEN o.type IN ('FS', 'FT', 'PC') THEN 'CLR' ELSE 'SQL' END AS language, "
            "CAST(OBJECTPROPERTY(o.object_id, 'IsDeterministic') AS int) AS is_deterministic "
            "FROM sys.objects AS o "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            f"WHERE o.type IN {types} AND o.is_ms_shipped = 0"
            f"{clause} "
            "ORDER BY s.name, o.name",
            values,
            names,
            touches=(self._SYS_OBJECTS, self._SYS_SCHEMAS, self._SYS_PARAMETERS),
        )

    def list_functions(self, schema: str | None = None) -> Query:
        """Scalar, inline table-valued, multi-statement table-valued and CLR functions.
        Aggregates (`AF`) are excluded: they are usable only inside a query."""

        return self._list_routines(schema, self._FUNCTION_TYPES)

    def list_procedures(self, schema: str | None = None) -> Query:
        """Stored procedures, T-SQL and CLR."""

        return self._list_routines(schema, self._PROCEDURE_TYPES)

    def describe_table(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Columns, primary key, unique keys, foreign keys.

        Every one of the four binds the schema and the object name; nothing is spliced.
        `sys.objects` rather than `sys.tables` for the columns query, so a view can be
        described with the same statement — the Explorer page shows a view's columns beside
        its definition, and a second near-identical query would be a second thing to get
        wrong.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        where = self._object_where("s.name", "o.name")

        columns = self._catalogue_query(
            "SELECT c.name AS column_name, "
            f"{self._TYPE_EXPRESSION} AS data_type, "
            "CAST(c.is_nullable AS int) AS is_nullable, "
            "dc.definition AS column_default, "
            "CAST(c.is_identity AS int) AS is_identity, "
            "CAST(c.is_computed AS int) AS is_generated, "
            # column_id has gaps once a column has been dropped; the position a caller
            # counts in `SELECT *` does not.
            "CAST(ROW_NUMBER() OVER (ORDER BY c.column_id) AS int) AS ordinal_position, "
            "CAST(ep.value AS nvarchar(4000)) AS column_comment "
            "FROM sys.columns AS c "
            "JOIN sys.objects AS o ON o.object_id = c.object_id "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            "JOIN sys.types AS t ON t.user_type_id = c.user_type_id "
            "LEFT JOIN sys.default_constraints AS dc ON dc.object_id = c.default_object_id "
            + self._COMMENT_JOIN.format(major="c.object_id", minor="c.column_id")
            + f" {where} "
            "ORDER BY c.column_id",
            values,
            names,
            touches=(
                self._SYS_COLUMNS,
                self._SYS_OBJECTS,
                self._SYS_SCHEMAS,
                self._SYS_TYPES,
                self._SYS_DEFAULTS,
                self._SYS_EXTENDED,
            ),
        )

        def key_query(constraint_type: str) -> Query:
            return self._catalogue_query(
                "SELECT kc.name AS constraint_name, col.name AS column_name, "
                "CAST(ic.key_ordinal AS int) AS key_ordinal "
                "FROM sys.key_constraints AS kc "
                "JOIN sys.objects AS o ON o.object_id = kc.parent_object_id "
                "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
                "JOIN sys.indexes AS i "
                "     ON i.object_id = kc.parent_object_id AND i.index_id = kc.unique_index_id "
                "JOIN sys.index_columns AS ic "
                "     ON ic.object_id = i.object_id AND ic.index_id = i.index_id "
                "JOIN sys.columns AS col "
                "     ON col.object_id = ic.object_id AND col.column_id = ic.column_id "
                f"{where} AND kc.type = '{constraint_type}' "
                # An INCLUDE column is carried by the index but is not part of the key, and
                # reporting one would describe a key the server does not enforce.
                "  AND ic.is_included_column = 0 "
                "ORDER BY kc.name, ic.key_ordinal",
                values,
                names,
                touches=(
                    self._SYS_KEY_CONSTRAINTS,
                    self._SYS_OBJECTS,
                    self._SYS_SCHEMAS,
                    self._SYS_INDEXES,
                    self._SYS_INDEX_COLUMNS,
                    self._SYS_COLUMNS,
                ),
            )

        primary_key = key_query("PK")
        unique_keys = key_query("UQ")

        foreign_keys = self._catalogue_query(
            "SELECT fk.name AS constraint_name, pc.name AS column_name, "
            "CAST(fkc.constraint_column_id AS int) AS key_ordinal, "
            "rs.name AS referenced_schema, rt.name AS referenced_table, "
            "rc.name AS referenced_column, "
            "REPLACE(fk.delete_referential_action_desc, '_', ' ') AS on_delete, "
            "REPLACE(fk.update_referential_action_desc, '_', ' ') AS on_update "
            "FROM sys.foreign_keys AS fk "
            "JOIN sys.foreign_key_columns AS fkc ON fkc.constraint_object_id = fk.object_id "
            "JOIN sys.objects AS o ON o.object_id = fk.parent_object_id "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            "JOIN sys.columns AS pc "
            "     ON pc.object_id = fkc.parent_object_id AND pc.column_id = fkc.parent_column_id "
            "JOIN sys.objects AS rt ON rt.object_id = fk.referenced_object_id "
            "JOIN sys.schemas AS rs ON rs.schema_id = rt.schema_id "
            "JOIN sys.columns AS rc "
            "     ON rc.object_id = fkc.referenced_object_id "
            "    AND rc.column_id = fkc.referenced_column_id "
            f"{where} "
            "ORDER BY fk.name, fkc.constraint_column_id",
            values,
            names,
            touches=(
                self._SYS_FOREIGN_KEYS,
                self._SYS_FOREIGN_KEY_COLUMNS,
                self._SYS_OBJECTS,
                self._SYS_SCHEMAS,
                self._SYS_COLUMNS,
            ),
        )
        return (columns, primary_key, unique_keys, foreign_keys)

    def describe_routine(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """The routine header, then its parameters.

        `parameter_id = 0` is a scalar function's return value rather than a parameter, and
        it is reported with mode `RETURN` instead of being dropped — the caller reading a
        function's parameter list wants to know what comes back out of it.
        """

        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        where = self._object_where("s.name", "o.name")
        routine_types = self._ROUTINE_TYPES

        header = self._catalogue_query(
            "SELECT s.name AS schema_name, o.name AS routine_name, "
            "CASE WHEN o.type IN ('P', 'PC') THEN 'procedure' ELSE 'function' END "
            "     AS routine_type, "
            "NULL AS signature, "
            "COALESCE((SELECT TYPE_NAME(rp.user_type_id) FROM sys.parameters AS rp "
            "          WHERE rp.object_id = o.object_id AND rp.parameter_id = 0), "
            "         CASE WHEN o.type IN ('IF', 'TF', 'FT') THEN 'TABLE' END) AS returns, "
            "CASE WHEN o.type IN ('FS', 'FT', 'PC') THEN 'CLR' ELSE 'SQL' END AS language, "
            "CAST(OBJECTPROPERTY(o.object_id, 'IsDeterministic') AS int) AS is_deterministic "
            "FROM sys.objects AS o "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            f"{where} AND o.type IN {routine_types} "
            "ORDER BY o.type",
            values,
            names,
            touches=(self._SYS_OBJECTS, self._SYS_SCHEMAS, self._SYS_PARAMETERS),
        )
        parameters = self._catalogue_query(
            # No overloading, so no signature to key the rows back to.
            "SELECT NULL AS routine_signature, "
            "NULLIF(p.name, '') AS parameter_name, "
            "TYPE_NAME(p.user_type_id) AS data_type, "
            "CASE WHEN p.parameter_id = 0 THEN 'RETURN' "
            "     WHEN p.is_output = 1 THEN 'OUT' ELSE 'IN' END AS parameter_mode, "
            "CAST(p.parameter_id AS int) AS ordinal_position, "
            # Only a CLR routine can carry a parameter default that the catalogue records;
            # a T-SQL default lives in the module text and is not readable from here.
            "CAST(p.has_default_value AS int) AS has_default "
            "FROM sys.parameters AS p "
            "JOIN sys.objects AS o ON o.object_id = p.object_id "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            f"{where} AND o.type IN {routine_types} "
            "ORDER BY o.type, p.parameter_id",
            values,
            names,
            touches=(self._SYS_PARAMETERS, self._SYS_OBJECTS, self._SYS_SCHEMAS),
        )
        return (header, parameters)

    def object_definition(self, ref: NormalisedRef) -> Query:
        """The module text from `sys.sql_modules`, which is `NULL` where it is withheld.

        Two cases produce that NULL and neither is an error: a module created `WITH
        ENCRYPTION`, and a CLR object whose body is an assembly rather than text.  There is
        also a third, quieter one — a principal without `VIEW DEFINITION` sees no row at all,
        because the catalogue views are visibility-filtered — so the caller must distinguish
        "one row holding NULL" from "no rows", and `introspection.py` does.

        `sys.sql_modules` and not `OBJECT_DEFINITION(OBJECT_ID(...))`: the latter takes the
        object as a *string* to be parsed as a name, so a name containing a dot or a bracket
        would have to be quoted into that string, and building an identifier inside a value
        is the one shape this layer refuses to have anywhere.
        """

        if ref.object_type is ObjectType.DATABASE:
            raise self._unsupported(
                "object_definition",
                "a database is not a module and has no source text",
            )
        values = (ref.canonical_schema, ref.canonical_name)
        names = ("schema", "name")
        return self._catalogue_query(
            "SELECT sm.definition AS definition "
            "FROM sys.objects AS o "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            "LEFT JOIN sys.sql_modules AS sm ON sm.object_id = o.object_id "
            f"{self._object_where('s.name', 'o.name')}",
            values,
            names,
            touches=(self._SYS_OBJECTS, self._SYS_SCHEMAS, self._SYS_SQL_MODULES),
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
        """A parameterised `SELECT` capped with `TOP`, or with `OFFSET ... FETCH` when a
        page is asked for.

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
        if offset:
            if not order_by:
                # OFFSET/FETCH is grammatically part of the ORDER BY clause on this engine,
                # so there is no unordered page to take. Refused rather than ordered by
                # something arbitrary: `ORDER BY (SELECT NULL)` would let a caller page
                # through a result whose row order the server is free to change between
                # pages, which returns duplicates and skips rows without ever erroring.
                raise ValueError(
                    "SQL Server pages with OFFSET ... FETCH, which is part of the ORDER BY "
                    "clause: pass order_by when offset is non-zero"
                )
            condition = (
                self._where_clause(predicates, values, names)
                if where is None
                else self._raw_where_clause(where, values, names)
            )
            order = self._order_clause(order_by)
            skip = self._bind(offset, values, names, "row_offset")
            cap = self._bind(row_cap, values, names, "row_cap")
            sql = (
                f"SELECT {column_list} FROM {target}{condition}{order} "
                f"OFFSET {skip} ROWS FETCH NEXT {cap} ROWS ONLY"
            )
        else:
            # `TOP (expression)` accepts a parameter marker as long as the parentheses are
            # there — they are not optional here for that reason — and binding the cap keeps
            # the promise that nothing but a validated identifier is ever formatted into the
            # statement text.
            cap = self._bind(row_cap, values, names, "row_cap")
            # The cap is bound *first* here and last in the paging branch above, because
            # `TOP` precedes the WHERE clause in the text while `FETCH NEXT` follows it.  A
            # free-form fragment therefore has to be composed by this method rather than by
            # its caller: on a positional paramstyle, binding it in the wrong order would put
            # the row cap inside the predicate with nothing to show that it had happened.
            condition = (
                self._where_clause(predicates, values, names)
                if where is None
                else self._raw_where_clause(where, values, names)
            )
            order = self._order_clause(order_by)
            sql = f"SELECT TOP ({cap}) {column_list} FROM {target}{condition}{order}"

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

    def _supports_drop_if_exists(self) -> bool:
        """`DROP ... IF EXISTS` arrived in SQL Server 2016 (13.0); Azure SQL Database has it
        whatever `ProductVersion` it reports.

        Unprobed answers `False`, which is the conservative direction: the script then omits
        the clause and carries a warning key saying so, rather than emitting a clause an older
        server would reject with a syntax error the operator has to decode.
        """

        if not self.probed:
            return False
        return self.traits.variant.startswith("azure_") or self.traits.version >= (13,)

    def _identity_clause(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """`IDENTITY(1,1)` — seed one, increment one, and neither is configurable from here.

        The seed and increment are not exposed because `ColumnSpec` has no field for them and
        inventing one would put two more numbers into the DDL that nothing validates.  A table
        that needs a different seed is one of the exotic shapes §11.3 puts out of reach on
        purpose.
        """

        return " IDENTITY(1,1)"

    def _returning_clauses(self, returning: Sequence[str]) -> tuple[str, str]:
        """`OUTPUT INSERTED.<column>`, which sits between the column list and `VALUES`.

        The one place the two halves of the hook earn their keep: PostgreSQL and SQLite put
        `RETURNING` at the end of the statement and SQL Server puts `OUTPUT` in the middle, so
        a single trailing clause would have been a syntax error here and nowhere else.
        """

        if not returning:
            return "", ""
        if not self.capabilities.supports_returning:  # pragma: no cover - always true here
            raise self._unsupported(
                "insert(returning=...)", "this server cannot return rows from an INSERT"
            )
        quoted = self._quoted_columns(returning, what="returning")
        return " OUTPUT " + ", ".join(f"INSERTED.{column}" for column in quoted), ""

    def estimate_row_count(self, ref: NormalisedRef) -> Query:
        """`sys.partitions`, summed over the heap or clustered index.

        `sys.partitions` rather than `sys.dm_db_partition_stats`: the dynamic management view
        is more precise and needs `VIEW DATABASE STATE`, which a least-privilege d-MCP login
        will not have, and an impact estimate that fails for want of a server-wide permission
        is an estimate the operator never sees.  `index_id IN (0, 1)` is the heap or the
        clustered index — every other row in that view is a non-clustered index over the same
        rows, and summing them all would multiply the answer by the index count.

        Approximate on purpose: the number comes from the storage engine's own counter, which
        is maintained rather than computed, so this is cheap on a table of any size.  §3.3
        says the exact number for a predicated write comes from `count_matching()` instead.
        """

        if ref.object_type not in (ObjectType.TABLE, ObjectType.VIEW):
            raise ValueError(
                f"estimate_row_count() counts rows of a table or a view; {ref.object_type} "
                "is neither"
            )
        return self._catalogue_query(
            "SELECT SUM(p.rows) AS estimated_rows "
            "FROM sys.partitions AS p "
            "JOIN sys.objects AS o ON o.object_id = p.object_id "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            "WHERE p.index_id IN (0, 1) "
            f"  AND s.name = COALESCE({self.placeholder(0, 'schema')}, SCHEMA_NAME()) "
            f"  AND o.name = {self.placeholder(1, 'name')}",
            (ref.canonical_schema, ref.canonical_name),
            ("schema", "name"),
            touches=(self._SYS_PARTITIONS, self._SYS_OBJECTS, self._SYS_SCHEMAS),
        )

    #: The one catalogue view `estimate_row_count()` adds to the set §3.3 already reads.
    _SYS_PARTITIONS = ObjectRef(schema="sys", name="partitions", object_type=ObjectType.VIEW)

    # -- 3.5 security ------------------------------------------------------------------
    #
    # This is the engine with two principal classes rather than one: a **login** lives on the
    # instance and is what authenticates a connection, a **user** lives in a database and is
    # what a permission is granted to, and the two are joined by a SID rather than by a name.
    # §4.1 wrote `create_user()` as emitting both.  It no longer can — a `CREATE LOGIN` needs a
    # password, and `DESIGN-MCP-TOOLS.md` §11.2 forbids this application from ever handling one
    # — so what it emits instead is the half that carries the permissions, and the login half
    # is either named by the caller or left for a human.
    #
    # A "group" here is a database role.  There is no separate object, so `create_group()` and
    # `create_role()` emit the same statement and `assign_role()` and `add_group_member()` emit
    # the same statement, each written out in full rather than delegating to its twin.

    #: The variants whose user databases can see `sys.server_principals`.  Azure SQL Database
    #: and both Synapse forms expose it in `master` only, and a query naming it from a user
    #: database fails with "Invalid object name" — which would take the whole principal listing
    #: out rather than the server half of it.
    _SERVER_PRINCIPAL_VARIANTS = frozenset({"sql_server", "azure_sql_managed_instance"})

    #: The privileges d-MCP will grant on a table or a view.
    #:
    #: `ALTER`, `CONTROL`, `TAKE OWNERSHIP` and `IMPERSONATE` are deliberately absent, and the
    #: absence is policy rather than vocabulary: each of them confers the ability to redefine
    #: the object or to re-grant on it, which is a change to the permission surface itself
    #: rather than a use of it.  A human can make those at the server, where the act is visible
    #: as an administrative one; through d-MCP they would arrive inside a list of six ordinary
    #: words and read like one of them.
    relation_privileges: ClassVar[frozenset[str]] = frozenset(
        {"SELECT", "INSERT", "UPDATE", "DELETE", "REFERENCES", "VIEW DEFINITION"}
    )

    #: `EXECUTE` runs the routine; `VIEW DEFINITION` reads its text and is in both sets because
    #: SQL Server puts it on every securable class.
    routine_privileges: ClassVar[frozenset[str]] = frozenset({"EXECUTE", "VIEW DEFINITION"})

    def _at_least(self, major: int) -> bool:
        """Whether the instance is at least this major version, assuming yes when unprobed.

        The same optimistic default `PostgreSQLDialect._at_least()` documents, and for the same
        narrow purpose: choosing which spelling of a catalogue column a read-only query uses,
        where a wrong guess is a driver error naming the missing column — loud, local and
        harmless — rather than a capability answer, where decision D2 requires the pessimistic
        default.  Azure's variants all report a version at or above every floor tested here.
        """

        if not self.probed:
            return True
        return self.traits.version >= (major,)

    def _sees_server_principals(self) -> bool:
        """Whether this connection's database can read `sys.server_principals`.

        Conservative when unprobed: the database half of the listing works on every variant, so
        omitting the server half costs rows on a connection that has not been probed and a
        wrong "yes" costs the entire statement on Azure SQL Database.
        """

        return self.probed and self.traits.variant in self._SERVER_PRINCIPAL_VARIANTS

    def _database_principal_login(self) -> str:
        """The `can_login` expression for a database principal, per server version.

        From SQL Server 2012 `authentication_type` answers it exactly: `0` is `NONE`, which is
        what `CREATE USER ... WITHOUT LOGIN` produces, and anything else means the user
        authenticates through a login, through a contained-database password or through
        Windows.

        Before 2012 there is no such column and the honest fallback over-reports: a user with a
        SID and a login-shaped type is called login-capable even where it is a `WITHOUT LOGIN`
        user.  That is the right direction for this particular number.  It is read by a human
        auditing who can reach the database, and a security display that lists a principal
        which turns out to be harmless is a nuisance, while one that omits a principal which
        turns out not to be is a hole.
        """

        if self._at_least(11):
            return "CASE WHEN dp.authentication_type = 0 THEN 0 ELSE 1 END"
        return "CASE WHEN dp.sid IS NOT NULL AND dp.type IN ('S', 'U', 'G') THEN 1 ELSE 0 END"

    def list_principals(self) -> Query:
        """Database principals, and instance logins where the variant exposes them.

        Both halves, because on this engine either alone is misleading.  A login with no user
        in this database can authenticate and then see nothing; a user with no login cannot
        authenticate at all and may still hold every permission in the schema.  §4.1 asks for
        `native_kind` to tell them apart, and `type_desc` — `SQL_USER`, `SQL_LOGIN`,
        `WINDOWS_GROUP`, `DATABASE_ROLE` — is the server's own word for it.

        The fixed database roles (`db_owner`, `db_datareader` and the rest) are **not**
        filtered out.  They can neither be created nor dropped through d-MCP, but membership of
        them is most of what there is to know about who can do what here, and a principal tree
        that hid them would show an empty answer for the commonest way access is actually
        granted on this engine.

        `is_superuser` is `dbo` and the `sysadmin` server role.  For a database principal it is
        a name test rather than `IS_ROLEMEMBER('db_owner', ...)`, which arrived in 2012;
        `IS_SRVROLEMEMBER` has been available far longer and answers accurately for a login.
        """

        database_half = (
            "SELECT dp.name AS principal_name, "
            "CASE WHEN dp.type IN ('R', 'A') THEN 'role' "
            "     WHEN dp.type IN ('G', 'X') THEN 'group' "
            "     ELSE 'user' END AS principal_kind, "
            "dp.type_desc AS native_kind, "
            f"{self._database_principal_login()} AS can_login, "
            "CASE WHEN dp.name = 'dbo' THEN 1 ELSE 0 END AS is_superuser, "
            "'database' AS scope "
            "FROM sys.database_principals AS dp "
            # `sys` and `INFORMATION_SCHEMA` are schema owners the server installed, not
            # principals anyone administers.  `##`-prefixed names are the certificate-backed
            # internal principals; the LEFT() test avoids a LIKE pattern, because a literal
            # `%` in statement text is a formatting directive to pymssql's pyformat paramstyle.
            "WHERE dp.name NOT IN ('sys', 'INFORMATION_SCHEMA') "
            "  AND LEFT(dp.name, 2) <> '##'"
        )
        touches: tuple[ObjectRef, ...] = (self._SYS_DATABASE_PRINCIPALS,)
        sql = database_half
        if self._sees_server_principals():
            sql += (
                " UNION ALL "
                "SELECT sp.name, "
                "CASE WHEN sp.type = 'R' THEN 'role' "
                "     WHEN sp.type IN ('G', 'X') THEN 'group' "
                "     ELSE 'user' END, "
                "sp.type_desc, "
                # A server role is not something anything logs in as, and a disabled login is
                # something nothing logs in as.
                "CASE WHEN sp.type = 'R' THEN 0 WHEN sp.is_disabled = 1 THEN 0 ELSE 1 END, "
                "COALESCE(IS_SRVROLEMEMBER('sysadmin', sp.name), 0), "
                "'server' "
                "FROM sys.server_principals AS sp "
                "WHERE LEFT(sp.name, 2) <> '##'"
            )
            touches += (self._SYS_SERVER_PRINCIPALS,)
        return self._catalogue_query(sql + " ORDER BY 1, 6", touches=touches)

    def list_group_members(self, group: str) -> Query:
        """The direct members of one database role.

        Direct rather than transitive, as on every engine: a role can be a member of a role,
        and flattening the graph here would answer a question the Explorer page did not ask.

        `group` is bound rather than quoted — a catalogue comparison needs a value, not an
        identifier — and normalised first so the comparison uses the spelling the catalogue
        holds under this database's collation.
        """

        canonical = self.normalise_identifier(group)
        self.quote_identifier(canonical)
        return self._catalogue_query(
            "SELECT m.name AS member_name, m.type_desc AS member_native_kind, "
            "0 AS has_admin_option "
            "FROM sys.database_role_members AS rm "
            "JOIN sys.database_principals AS r ON r.principal_id = rm.role_principal_id "
            "JOIN sys.database_principals AS m ON m.principal_id = rm.member_principal_id "
            f"WHERE r.name = {self.placeholder(0, 'group_name')} "
            "ORDER BY m.name",
            (canonical,),
            ("group_name",),
            touches=(self._SYS_DATABASE_ROLE_MEMBERS, self._SYS_DATABASE_PRINCIPALS),
        )

    def list_grants(self, ref: NormalisedRef | None = None) -> Query:
        """Object-level permissions out of `sys.database_permissions`.

        `state_desc` is reported and is why this engine needed a `state` column in the shared
        row shape at all: SQL Server has `DENY` as well as `GRANT`, a `DENY` beats every grant
        at the same scope, and a listing that showed only the grants would tell a human that
        access exists where the server refuses it.  `GRANT_WITH_GRANT_OPTION` is state `W` and
        is reported as grantable.

        A **column-level** permission is reported against `table(column)` rather than against
        the table, because either simplification is a lie in one direction: showing it as a
        grant on the table over-reports, and dropping the row under-reports.  It costs one join
        and a concatenation, and `+` rather than `CONCAT()` because this statement has to work
        back to 2008 like the rest of this module's catalogue SQL.
        """

        object_name = (
            "CASE WHEN perm.minor_id = 0 THEN o.name "
            "     ELSE o.name + '(' + ISNULL(c.name, '') + ')' END AS object_name"
        )
        clause = ""
        values: tuple[Any, ...] = ()
        names: tuple[str, ...] = ()
        if ref is not None:
            clause = (
                f"  AND s.name = COALESCE({self.placeholder(0, 'schema')}, SCHEMA_NAME()) "
                f"  AND o.name = {self.placeholder(1, 'name')} "
            )
            values = (ref.canonical_schema, ref.canonical_name)
            names = ("schema", "name")
        return self._catalogue_query(
            "SELECT gp.name AS grantee, perm.permission_name AS privilege, "
            f"s.name AS schema_name, {object_name}, "
            "CASE WHEN perm.state = 'W' THEN 1 ELSE 0 END AS grantable, "
            "perm.state_desc AS state "
            "FROM sys.database_permissions AS perm "
            "JOIN sys.database_principals AS gp "
            "  ON gp.principal_id = perm.grantee_principal_id "
            "JOIN sys.objects AS o ON o.object_id = perm.major_id "
            "JOIN sys.schemas AS s ON s.schema_id = o.schema_id "
            "LEFT JOIN sys.columns AS c "
            "  ON c.object_id = perm.major_id AND c.column_id = perm.minor_id "
            # class 1 is OBJECT_OR_COLUMN.  Database-, schema- and assembly-scoped permissions
            # are real and are not shown here: this listing sits beside the object tree, and a
            # row with no object to sit against would have nowhere to appear.
            "WHERE perm.class = 1 "
            f"{clause}"
            "ORDER BY s.name, o.name, gp.name, perm.permission_name",
            values,
            names,
            touches=(
                self._SYS_DATABASE_PERMISSIONS,
                self._SYS_DATABASE_PRINCIPALS,
                self._SYS_OBJECTS,
                self._SYS_SCHEMAS,
                self._SYS_COLUMNS,
            ),
        )

    def create_role(self, name: str) -> Script:
        """`CREATE ROLE [x]` — a database role, owned by the caller.

        No `AUTHORIZATION` clause.  Omitting it makes the creating principal the owner, which
        is the caller d-MCP connected as; naming an owner instead would hand the ability to
        alter and drop the role to a principal that took no part in the request.
        """

        return self._security_script(f"CREATE ROLE {self.quote_principal(name)}")

    def create_user(
        self,
        name: str,
        *,
        host: str | None = None,
        login: str | None = None,
        default_schema: str | None = None,
    ) -> Script:
        """`CREATE USER [x] WITHOUT LOGIN`, or `FOR LOGIN [y]` where a login is named.

        `WITHOUT LOGIN` is the form that is genuinely unable to connect: the user exists in the
        database, holds no SID mapping to any login and carries no password of its own, so
        there is no authentication path to it at all.  It is what SQL Server itself
        recommends for a principal that exists to hold permissions and to be impersonated.

        §11.2 calls this "a contained user", and the distinction is worth keeping straight: a
        *contained* user in the strict sense is `CREATE USER [x] WITH PASSWORD = ...`, which
        authenticates against the database rather than the instance — and needs a password,
        which this tool will not accept.  What is emitted is the credential-free member of the
        same family.

        `FOR LOGIN` maps the new user onto an **existing** login, which is the case §4.1 was
        really describing.  The login is quoted as a principal like any other name: it arrives
        from a caller and is not looked up first, so it is hostile until quoted.

        `host` is refused: identity here is one name, and a host half would be a MySQL notion.
        `default_schema` becomes `WITH DEFAULT_SCHEMA = [s]`, which is native and needs no
        second statement.
        """

        quoted = self.quote_principal(name, host=host)
        mapping = (
            f" FOR LOGIN {self.quote_principal(login)}"
            if login is not None
            else " WITHOUT LOGIN"
        )
        options = ""
        if default_schema is not None:
            schema = self.quote_identifier(self.normalise_identifier(default_schema))
            options = f" WITH DEFAULT_SCHEMA = {schema}"
        return self._security_script(f"CREATE USER {quoted}{mapping}{options}")

    def create_group(self, name: str) -> Script:
        """`CREATE ROLE [x]` — a database role, used as a group.

        The same statement `create_role()` emits, because SQL Server has one object for both
        and inventing a distinction it does not hold would make the server's catalogue
        disagree with d-MCP's vocabulary at the first `list_principals()`.
        """

        return self._security_script(f"CREATE ROLE {self.quote_principal(name)}")

    def _alter_role_membership(
        self, role: str, principal: str, verb: str, host: str | None
    ) -> Script:
        """`ALTER ROLE [role] ADD|DROP MEMBER [principal]`, refused before SQL Server 2012.

        `host` is threaded to the **principal** — the member being added or dropped — and not
        to the role, which is what `Dialect.add_group_member()` documents and what MySQL
        implements.  It is refused here by `quote_principal()`, the shared rule, rather than by
        a check of this dialect's own: routing it through the same call the other engines use
        is what makes "which principal does the host belong to" an observable fact on an engine
        that has no hosts, instead of a convention that only a reader of this file can check.

        The pre-2012 spelling is `EXEC sp_addrolemember`, a deprecated stored procedure that
        Microsoft has documented as removable since 2012 and which d-MCP does not emit: a
        second, differently shaped code path through the one statement class that changes who
        can do what is not worth carrying for a version that left extended support in 2019.
        The refusal names the alternative so the human can run it themselves.
        """

        if not self._at_least(11):
            raise self._unsupported(
                "assign_role",
                "ALTER ROLE ... ADD MEMBER arrived in SQL Server 2012; on an older instance "
                "use sp_addrolemember / sp_droprolemember at the server",
            )
        return self._security_script(
            f"ALTER ROLE {self.quote_principal(role)} {verb} MEMBER "
            f"{self.quote_principal(principal, host=host)}"
        )

    def add_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`ALTER ROLE [group] ADD MEMBER [member]`."""

        return self._alter_role_membership(group, member, "ADD", host)

    def remove_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """`ALTER ROLE [group] DROP MEMBER [member]`."""

        return self._alter_role_membership(group, member, "DROP", host)

    def assign_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`ALTER ROLE [role] ADD MEMBER [principal]` — the same act as joining a group.

        Nothing further is needed: unlike MySQL, a role here is active for its members from the
        moment it is granted, with no default-role step to forget.
        """

        return self._alter_role_membership(role, principal, "ADD", host)

    def revoke_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """`ALTER ROLE [role] DROP MEMBER [principal]`."""

        return self._alter_role_membership(role, principal, "DROP", host)

    def _grant_object(self, ref: NormalisedRef, arguments: str = "") -> str:
        """`OBJECT::[s].[t]`, with the securable class named.

        `arguments` is always empty here and the parameter exists only so the four dialects
        answer one shape: SQL Server permits no overloading of a user function, so
        `_routine_arguments_for()` has already refused any signature before this is reached.

        The class prefix is not optional decoration.  `GRANT SELECT ON [sales]` is a grant on
        an *object* called `sales` if one exists and a syntax error otherwise, while
        `ON SCHEMA::[sales]` is a grant on the schema — two very different scopes distinguished
        by four characters.  Naming `OBJECT::` makes the emitted statement mean the narrow one
        whatever else exists on the server under that name.
        """

        if ref.object_type not in (
            ObjectType.TABLE,
            ObjectType.VIEW,
            ObjectType.FUNCTION,
            ObjectType.PROCEDURE,
        ):
            raise ValueError(
                f"a grant on {ref.object_type} is not composable here: d-MCP grants on a "
                "table, a view, a function or a procedure"
            )
        return f"OBJECT::{self.quote_ref(ref)}{arguments}"

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
        """`GRANT SELECT, INSERT ON OBJECT::[s].[t] TO [bob] [WITH GRANT OPTION]`.

        A `signature` is refused rather than ignored: SQL Server has no overloading, so a
        caller passing one has a different object in mind from the one being permissioned.
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
        """`REVOKE SELECT ON OBJECT::[s].[t] FROM [bob]`, and never `CASCADE`.

        A permission that was granted `WITH GRANT OPTION` and then passed on cannot be revoked
        without `GRANT OPTION FOR ... CASCADE`, and SQL Server refuses this statement rather
        than half-applying it.  That refusal is the right outcome: cascading would revoke from
        principals nobody named, and the human who wants it can say so at the server.

        `REVOKE` removes a grant; it does not create a `DENY`.  The two are distinct states in
        `sys.database_permissions` and `list_grants()` reports which is which.
        """

        target = self._check_grant_ref(ref)
        words = self._validated_privileges(privileges, target, what="revoke")
        arguments = self._routine_arguments_for(target, signature, method="revoke")
        return self._security_script(
            f"REVOKE {', '.join(words)} ON {self._grant_object(target, arguments)} FROM "
            f"{self.quote_principal(principal, host=host)}",
            touches=self._grant_touches(target),
        )
