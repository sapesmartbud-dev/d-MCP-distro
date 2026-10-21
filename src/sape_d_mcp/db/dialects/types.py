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

"""The vocabulary every dialect, the guard and the permission resolver share."""

from __future__ import annotations

import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

# `enum.StrEnum` arrived in 3.11 and the project floor is 3.10, so the shim below is not
# optional politeness: without it every `Engine.MSSQL` written into `connections.db` on a
# 3.10 host would serialise as "Engine.MSSQL" instead of "mssql", and the profile would be
# unreadable by the same application running on 3.11.  Pinning `__str__` to `str.__str__`
# is what CPython's own StrEnum does.
if sys.version_info >= (3, 11):  # pragma: no cover - version dependent
    from enum import StrEnum
else:  # pragma: no cover - version dependent

    class StrEnum(str, Enum):  # type: ignore[no-redef]
        """Minimal 3.10 stand-in for `enum.StrEnum`."""

        __str__ = str.__str__

        def _generate_next_value_(name, start, count, last_values):
            return name.lower()


__all__ = [
    "READ_ONLY_OFF_VALUES",
    "READ_ONLY_ON_VALUES",
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
]


# --------------------------------------------------------------------------------------
# Enumerations
# --------------------------------------------------------------------------------------


class Engine(StrEnum):
    """The four engines d-MCP addresses.  The value is what `connections.engine` stores."""

    MSSQL = "mssql"
    POSTGRESQL = "postgresql"
    MYSQL = "mysql"
    SQLITE = "sqlite"


class ParamStyle(StrEnum):
    """PEP 249 `paramstyle`, taken from the driver rather than from the engine.

    Injected into the dialect at construction (decision D4).  `NAMED` is reachable only
    through `sqlite3`, which accepts both `?` and `:name`; d-MCP uses `QMARK` there so one
    code path serves both MS-SQL/pyodbc and SQLite.
    """

    QMARK = "qmark"
    NUMERIC = "numeric"
    NAMED = "named"
    FORMAT = "format"
    PYFORMAT = "pyformat"

    @property
    def is_mapping_style(self) -> bool:
        """True where the driver wants a mapping of parameters rather than a sequence."""

        return self in (ParamStyle.PYFORMAT, ParamStyle.NAMED)


class ObjectType(StrEnum):
    """The permission model's object types, verbatim from `dmcp-permissions`.

    `DATABASE` is the pseudo-type carrying the catalogue and security actions; it never
    names a concrete object.
    """

    TABLE = "table"
    VIEW = "view"
    FUNCTION = "function"
    PROCEDURE = "procedure"
    DATABASE = "database"


class StatementKind(StrEnum):
    """What a statement does, as the guard classifies it and the resolver authorises it.

    `UNKNOWN` exists so the guard has something to return that is *not* a lie.  It is never
    executed: the contract is refuse-what-you-cannot-classify.
    """

    READ = "read"
    WRITE = "write"
    DDL = "ddl"
    SECURITY = "security"
    DESTRUCTIVE = "destructive"
    UNKNOWN = "unknown"


class CaseFolding(StrEnum):
    """How an engine treats the case of an unquoted identifier.

    PostgreSQL folds down (the SQL standard says up; PostgreSQL has deviated since forever).
    MS-SQL preserves and defers comparison to the collation.  MySQL depends on
    `lower_case_table_names` *and* on the host filesystem.  SQLite is ASCII-insensitive.
    """

    FOLD_LOWER = "fold_lower"
    FOLD_UPPER = "fold_upper"
    PRESERVE_CASE_SENSITIVE = "preserve_cs"
    PRESERVE_CASE_INSENSITIVE = "preserve_ci"


class Operator(StrEnum):
    """The closed set of predicate operators a structured row operation may use (D3).

    Anything outside this set is a request for free-form SQL and must go through the guard.
    """

    EQ = "="
    NE = "<>"
    LT = "<"
    LE = "<="
    GT = ">"
    GE = ">="
    LIKE = "like"
    NOT_LIKE = "not like"
    IN = "in"
    NOT_IN = "not in"
    IS_NULL = "is null"
    IS_NOT_NULL = "is not null"
    BETWEEN = "between"


class WritingCTEShape(StrEnum):
    """How this engine's grammar allows a `WITH` clause to write, if at all.

    `NONE`: `WITH` is read-only end to end (MySQL/MariaDB, SQLite).  `DML_IN_BODY`: a
    data-modifying statement can itself be the body of a CTE, typically paired with
    `RETURNING` so the outer query has something to select from (PostgreSQL).
    `DML_THROUGH_REFERENCE`: the CTE body stays a `SELECT`, but a following `UPDATE`/`DELETE`
    targets the CTE's name directly (MS-SQL) — syntactically an `UPDATE`/`DELETE` statement,
    not a `WITH` statement, but one the guard must still connect back to the CTE's row set to
    authorise correctly.
    """

    NONE = "none"
    DML_IN_BODY = "dml_in_body"
    DML_THROUGH_REFERENCE = "dml_through_reference"


# --------------------------------------------------------------------------------------
# Secret handling
# --------------------------------------------------------------------------------------


class SecretStr:
    """A string that refuses to reveal itself through `repr()`, `str()` or a format spec.

    Deliberately hand-rolled rather than borrowed from pydantic: `src/sape_d_mcp/db/` must
    stay importable with nothing installed beyond the standard library and the one driver in
    use, and this is thirty lines.  The point is not cryptographic — the value is in memory in
    clear — it is that a password cannot reach a log line, a traceback frame repr or an audit
    row by accident, which is how credentials actually leak.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        if not isinstance(value, str):
            raise TypeError("SecretStr wraps a str")
        self._value = value

    def get_secret_value(self) -> str:
        """The clear value.  Every call site of this is worth reviewing."""

        return self._value

    def __len__(self) -> int:
        return len(self._value)

    def __bool__(self) -> bool:
        return bool(self._value)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, SecretStr) and other._value == self._value

    def __hash__(self) -> int:
        return hash(("SecretStr", self._value))

    def __repr__(self) -> str:
        return "SecretStr('***')"

    def __str__(self) -> str:
        return "***"

    def __format__(self, spec: str) -> str:
        return "***"


# --------------------------------------------------------------------------------------
# Object references
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, order=True)
class ObjectRef:
    """A schema-qualified object name exactly as it arrived, before normalisation.

    `schema` is `None` only for SQLite, which has no schema layer; every other engine
    requires it, because an unqualified name resolves against a server-side search path
    that the LLM does not control and the resolver cannot see.
    """

    schema: str | None
    name: str
    object_type: ObjectType


@dataclass(frozen=True, slots=True, order=True)
class NormalisedRef:
    """An `ObjectRef` after the dialect has canonicalised it, plus its comparison key.

    `canonical_*` is what the server's catalogue holds and what d-MCP emits in SQL.
    `key_*` is what `permissions.resolve()` compares against a rule pattern (decision D5).
    They differ on MS-SQL under a case-insensitive collation, on MySQL under
    `lower_case_table_names = 1` or `2`, and on SQLite, whose comparison is ASCII-insensitive
    while its storage preserves what was typed.
    """

    canonical_schema: str | None
    canonical_name: str
    key_schema: str | None
    key_name: str
    object_type: ObjectType


@dataclass(frozen=True, slots=True)
class Predicate:
    """One structured `WHERE` term.  The column is validated against the introspected
    catalogue and then quoted; the value is always a bound parameter, never text."""

    column: str
    operator: Operator
    value: Any = None
    values: tuple[Any, ...] = ()


@dataclass(frozen=True, slots=True)
class RawPredicate:
    """A free-form `WHERE` fragment written by the model, with its values kept out of it.

    Decision D3 originally admitted structured predicates only, and free-form SQL only
    through the guard.  The user has since ruled that `select-rows` and `select-view-rows`
    take a `where` string, as `DESIGN-MCP-TOOLS.md` §5 always specified: the tool composes
    the statement, then re-parses the composed text through `SqlGuard`, so a subquery in the
    fragment is authorised object by object exactly as `run-read-query` is.  The fragment
    therefore buys expressiveness without buying an unauthorised read — but only because
    the composition happens here, where the dialect knows where its own cap and offset bind.

    `text` spells its placeholders `:name` whatever the engine, because the model writes one
    statement and the driver's paramstyle is the operator's choice, not the model's;
    `Dialect.select()` rewrites them through `rewrite_placeholders()`.  `values` never
    reaches the statement text.
    """

    text: str
    values: Mapping[str, Any]


# --------------------------------------------------------------------------------------
# Statements
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Query:
    """One statement plus its bound parameters, ready for `engine.py` to execute.

    `params` is a tuple for `qmark`/`format` styles and a mapping for `pyformat`/`named`;
    the dialect produces whichever matches the `ParamStyle` it was built with.  `touches`
    lists every object the statement reads or writes so the caller can re-check that the
    resolver authorised all of them — the guard and the dialect must agree, and a test
    asserts they do.
    """

    sql: str
    params: tuple[Any, ...] | Mapping[str, Any] = ()
    kind: StatementKind = StatementKind.READ
    touches: tuple[ObjectRef, ...] = ()
    row_cap: int | None = None


@dataclass(frozen=True, slots=True)
class Script:
    """An ordered sequence of `Query` objects that must be run as one logical operation.

    `atomic` is `False` where the engine cannot wrap the sequence in a transaction — MySQL
    commits implicitly on every DDL statement, so "edit a stored procedure" is genuinely a
    drop followed by a create with a window in between where the routine does not exist.
    `rollback` holds the best-effort compensating statements for that case and
    `warning_key` is the i18n key the confirmation dialog must show before proceeding.
    """

    steps: tuple[Query, ...]
    atomic: bool
    rollback: tuple[Query, ...] = ()
    warning_key: str | None = None


# --------------------------------------------------------------------------------------
# The read-only session
# --------------------------------------------------------------------------------------


class ReadOnlyScope(StrEnum):
    """How long an engine's read-only state lasts once it has been set.

    The distinction is not academic: it decides what "restore it afterwards" has to do.
    `TRANSACTION` state disappears of its own accord at the next `COMMIT`/`ROLLBACK`, so the
    release is that boundary.  `SESSION` and `CONNECTION` state outlive every statement and
    must be turned off by hand — and if that fails, the connection is no longer fit to be
    handed to a write tool and must be discarded rather than pooled.
    """

    TRANSACTION = "transaction"
    SESSION = "session"
    CONNECTION = "connection"


class ReadOnlyEnforcement(StrEnum):
    """What the engine actually does to a write that reaches a hardened session.

    `REFUSES` is real prevention: the server raises and nothing happens.  `DISCARDS` is the
    weaker guarantee SQL Server leaves us with — the write executes inside a transaction that
    d-MCP always rolls back, so it cannot be made durable, but it does run.  The difference is
    stated here rather than buried in a comment because it is the difference between "cannot
    write" and "cannot commit a write", and only one of them is worth promising to a user.
    """

    REFUSES = "refuses"
    DISCARDS = "discards"


@dataclass(frozen=True, slots=True)
class ReadOnlySession:
    """The statements that make one session refuse to write, and undo that again.

    A dialect authors this and executes none of it (decision D1); `engine.read_only_session()`
    is the context manager that runs it.  Every field is a plain statement so the whole plan
    can be asserted in a test without a server.

    Attributes:
        harden: Run in order before the read.  If any of them raises, the read is refused —
            there is no fall-through to an unhardened session.
        release: Run in order afterwards, on the success path and the exception path alike.
        verify: A statement whose single cell proves the hardening took: `on`/`1`/`true` means
            hardened, `off`/`0`/`false` means it did not.  It exists because two of the four
            engines have a way of accepting the hardening statement and doing nothing (a
            PostgreSQL `SET TRANSACTION` outside a transaction block is a warning, not an
            error), and a control that can silently no-op is not a control.
        verify_released: The mirror image, run after `release`, whose cell must *not* read as
            read-only.  A separate field rather than a second use of `verify` because the two
            questions are not the same one asked twice: SQL Server's only observable is
            `@@TRANCOUNT`, and under ODBC's default implicit-transaction mode the verifying
            `SELECT` opens a transaction of its own before it can answer, so a post-release
            reading of `1` would mean nothing.  `None` means "this engine cannot be asked",
            and the release is then judged by whether its statements raised.
        scope: How long the state lasts, which decides whether the release is mandatory.
        enforcement: Whether the engine refuses a write or merely cannot keep it.
        note: One sentence naming the engine mechanism, for the log and for the report.
    """

    harden: tuple[Query, ...]
    release: tuple[Query, ...]
    verify: Query | None = None
    verify_released: Query | None = None
    scope: ReadOnlyScope = ReadOnlyScope.TRANSACTION
    enforcement: ReadOnlyEnforcement = ReadOnlyEnforcement.REFUSES
    note: str = ""


#: Values a `ReadOnlySession.verify` cell may take to mean "hardened".  Compared against
#: `str(cell).strip().lower()` so `1`, `True`, `'on'` and `'ON'` all read alike across four
#: drivers that each return a different type for the same question.
READ_ONLY_ON_VALUES: frozenset[str] = frozenset({"1", "on", "true", "yes"})

#: And the values that mean "not hardened".  Anything in neither set is unrecognised, and an
#: unrecognised answer is treated as "not hardened" — the only safe direction.
READ_ONLY_OFF_VALUES: frozenset[str] = frozenset({"0", "off", "false", "no", "none", ""})


def reads_as_read_only(cell: Any) -> bool:
    """Whether a `ReadOnlySession.verify` cell says the session is hardened.

    Unrecognised is `False`.  A verify statement that returns something nobody anticipated is
    exactly the case where assuming success would turn a broken control into an invisible one.
    """

    return str(cell).strip().lower() in READ_ONLY_ON_VALUES


# --------------------------------------------------------------------------------------
# Catalogue shapes
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ColumnInfo:
    """One column as the catalogue describes it, normalised across the four engines.

    `data_type` is the engine's own spelling (`nvarchar(50)`, `character varying(50)`,
    `varchar(50)`, `TEXT`) because a lossy common type vocabulary would mislead the LLM
    about what it may store.  `position` is 1-based.
    """

    name: str
    data_type: str
    nullable: bool
    default: str | None
    is_identity: bool
    is_generated: bool
    position: int
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class ColumnSpec:
    """A column as the *caller* asks for it in `create_table()`.

    Distinct from `ColumnInfo`, which is what the catalogue reports back: a spec has no
    position and no generated-column flag, and its `data_type` is validated against the
    engine's own type vocabulary before emission rather than trusted.  `DESIGN-DIALECTS.md`
    names this type in §3.4 without defining it in §2; the shape here is the minimum §3.4
    needs and is recorded in the stage-4 report as a documentation gap.
    """

    name: str
    data_type: str
    nullable: bool = True
    default: str | None = None
    is_identity: bool = False
    collation: str | None = None
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class KeyInfo:
    """A primary or unique key: the constraint name and its columns in key order."""

    name: str
    columns: tuple[str, ...]
    is_primary: bool


@dataclass(frozen=True, slots=True)
class ForeignKeyInfo:
    """A foreign key, with the referential actions spelled as the engine reports them."""

    name: str
    columns: tuple[str, ...]
    referenced_schema: str | None
    referenced_table: str
    referenced_columns: tuple[str, ...]
    on_delete: str | None
    on_update: str | None


@dataclass(frozen=True, slots=True)
class TableInfo:
    """A table or view and everything `read_structure` is permitted to disclose."""

    ref: ObjectRef
    columns: tuple[ColumnInfo, ...]
    primary_key: KeyInfo | None
    unique_keys: tuple[KeyInfo, ...]
    foreign_keys: tuple[ForeignKeyInfo, ...]
    estimated_rows: int | None
    comment: str | None = None


@dataclass(frozen=True, slots=True)
class ParameterInfo:
    """One routine parameter.  `mode` is `IN`, `OUT`, `INOUT` or `RETURN`."""

    name: str | None
    data_type: str
    mode: str
    position: int
    has_default: bool = False


@dataclass(frozen=True, slots=True)
class RoutineInfo:
    """A function or stored procedure.

    `signature` is the overload discriminator: PostgreSQL keys routines by name *and*
    argument types, so `add(int, int)` and `add(text, text)` are two objects sharing one
    name.  The permission rule matches on the bare name — a rule cannot sensibly discriminate
    overloads — but `DROP` needs the full signature, hence both fields.
    """

    ref: ObjectRef
    signature: str
    parameters: tuple[ParameterInfo, ...]
    returns: str | None
    language: str | None
    is_deterministic: bool | None
    definition_available: bool
    definition_withheld_reason: str | None = None


@dataclass(frozen=True, slots=True)
class PrincipalInfo:
    """A role, user or group as the engine understands it.

    The three are not distinct object classes everywhere: on PostgreSQL a role with
    `LOGIN` is a user and one without is a group; on MS-SQL a database role is the group;
    on MySQL before 8.0 there is no role at all.  `kind` records how d-MCP is presenting
    it, `native_kind` records what the server actually stores.
    """

    name: str
    kind: str
    native_kind: str
    can_login: bool
    is_superuser: bool
    members: tuple[str, ...] = ()


# `GrantInfo(grantee, privilege, object_ref, grantable)` stood here until stage 8 and is
# deleted rather than fixed.  `db/security.py` shapes a server privilege as a plain dictionary
# and argues in `list_grants()`'s docstring that this dataclass was wrong in two independent
# ways, both of which under-report or misreport access:
#
#   * `object_ref` is an `ObjectRef`, whose `object_type` is the permission model's five-member
#     vocabulary, and a server privilege can be held on a sequence, a schema or the database
#     itself — none of which fits, so a real grant would be shown unattributed in the one panel
#     whose job is to show access the rule table cannot see;
#   * there is no `state`, which is how SQL Server tells a `DENY` from a `GRANT`.  A `DENY`
#     rendered through this shape would read as a grant.
#
# Both hold, and a shape that is wrong in two ways is not an incomplete one.  Kept exported and
# constructed nowhere, it was a trap for whoever next assumed it was the canonical answer, so
# what stands is the dictionary `SecurityManager.list_grants()` actually builds, whose keys are
# `(grantee, privilege, schema, object, grantable, state)` — the column order
# `Dialect.list_grants()` contracts for, and nothing invented on top of it.


# --------------------------------------------------------------------------------------
# Probe results and capabilities
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class ServerTraits:
    """What the version probe learned.  Every version-dependent capability derives from it.

    `raw_version` is kept verbatim for the log; `version` is the parsed tuple; `variant`
    separates MariaDB from MySQL and Azure SQL Database from a boxed SQL Server, both of
    which change the capability answers materially.

    `case_sensitive_collation` is deliberately tri-state.  `None` means the probe could not
    read the collation, and a dialect that cannot read it must **raise** rather than assume:
    guessing case-insensitive silently widens a rule to objects it was not written for, and
    guessing case-sensitive silently narrows a *deny* rule so it stops covering the object it
    was written for.  Both directions are wrong, so neither is guessed.
    """

    raw_version: str
    version: tuple[int, ...]
    variant: str
    collation: str | None = None
    case_sensitive_collation: bool | None = None
    lower_case_table_names: int | None = None
    default_schema: str | None = None
    current_user: str | None = None


@dataclass(frozen=True, slots=True)
class Capabilities:
    """What this connection can actually be asked to do.

    Computed from `ServerTraits`, never hardcoded per class (decision D2).  The MCP layer
    publishes it through `describe_connection` so the LLM can avoid impossible calls, the
    GUI greys out the corresponding action tick-boxes, and `permissions.resolve()` treats a
    `False` as an additional deny (decision D10).
    """

    engine: Engine
    supports_schemas: bool
    supports_stored_procedures: bool
    supports_table_valued_functions: bool
    supports_roles: bool
    supports_users: bool
    supports_groups: bool
    supports_create_or_replace_view: bool
    supports_create_or_replace_routine: bool
    supports_transactional_ddl: bool
    supports_alter_column: bool
    supports_returning: bool
    supports_cross_database_reference: bool
    supports_data_modifying_cte: bool
    max_identifier_length: int
    param_style: ParamStyle
    probed: bool


# --------------------------------------------------------------------------------------
# What the guard borrows from the dialect
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class GuardTraits:
    """Everything `sql_guard.py` borrows from the dialect layer (decision D8).

    Constant per engine and never derived from `ServerTraits`, so it is answerable before
    `configure()`.  Where a keyword exists only from a given server version — PostgreSQL's
    `MERGE`, added in 16 — it is listed unconditionally: a keyword in `write_keywords` can
    only ever cause a statement to be classified as a write, and classifying a write as a
    write on a server that would have rejected the syntax anyway costs nothing, whereas
    omitting it on a server that does support it is a write executed as a read.
    """

    write_keywords: frozenset[str]
    ddl_keywords: frozenset[str]
    security_keywords: frozenset[str]
    line_comment_prefixes: tuple[str, ...]
    block_comment_delimiters: tuple[str, str]
    executable_comment_pattern: re.Pattern[str] | None
    batch_separator_pattern: re.Pattern[str] | None
    writing_cte_shape: WritingCTEShape


# A connection profile as `ConnectionStore` yields it: `display_name, engine, driver, host,
# port, database, username, options_json, statement_timeout_s`.  Typed as a plain mapping so
# the dialect layer never imports `connection_store`, which would make the two modules
# mutually dependent and the dialects untestable without the store.
ConnectionProfile = Mapping[str, Any]
