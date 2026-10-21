# SAPÉ d-MCP — Dialect layer, logical design

Stage 1 deliverable. Owner: DB-Specialist. Status: proposed, awaiting the stage-1 gate.

This document specifies `src/sape_d_mcp/db/dialects/` — the abstraction that lets one MCP tool surface,
one permission resolver and one GUI work against MS-SQL, PostgreSQL, MySQL/MariaDB and SQLite
without any of them learning a second engine's grammar. Nothing here is production code. Every
interface is given as a type-hinted Python signature with a docstring and no body, so stage 4
is a transcription exercise rather than a design exercise.

Related stage-1 documents: the ER model of the three `.db` files, the permission-resolution
algorithm and the MCP tool catalogue. Where this document names a column or an action it is
quoting `DEVELOPMENT-PLAN.md`, which is the contract.

---

## 1. What the dialect layer is, and what it deliberately is not

A `Dialect` is a **pure SQL author**. It answers "what is the text of the statement, and what
are its bound parameters" for one engine. It does not own a connection, does not execute
anything, and holds no cursor.

```
             ┌──────────────────────────────────────────────┐
 MCP tool ──▶│ permissions.py   resolve(connection, ref, …)  │  deny ⇒ stop
             └──────────────────┬───────────────────────────┘
                                │ allow
             ┌──────────────────▼───────────────────────────┐
             │ sql_guard.py     classify + enumerate objects │  unknown ⇒ stop
             └──────────────────┬───────────────────────────┘
                                │
             ┌──────────────────▼───────────────────────────┐
             │ Dialect          build Query / Script         │  ← this document
             └──────────────────┬───────────────────────────┘
                                │
             ┌──────────────────▼───────────────────────────┐
             │ engine.py        pool, execute, cap rows      │
             └──────────────────────────────────────────────┘
```

The separation is not decoration. It is what makes the dialects testable: every catalogue
query, every piece of generated DDL and every quoting rule can be asserted as a string in a
unit test with **no database server anywhere near the test runner**. Only the integration
tests need Docker, and per `DEVELOPMENT-PLAN.md` those skip cleanly when it is absent.

### 1.1 Design decisions taken here, with the reasoning

| # | Decision | Why this one and not the alternative |
|---|---|---|
| D1 | A dialect **builds** statements; `engine.py` executes them. | The alternative — dialects that hold a connection — makes every dialect test an integration test and puts four engines' connection lifecycles into four classes instead of one. |
| D2 | Capability flags are **instance** properties computed after a server probe, not class constants. | MySQL gained roles at 8.0, MariaDB at 10.0.5; MS-SQL gained `CREATE OR ALTER` at 2016 SP1; Azure SQL Database removes server-level principals. A class constant would be wrong for half the estate. Before the probe the dialect reports the conservative answer (unsupported) and never the optimistic one. |
| D3 | ~~Row-operation builders take **structured predicates**, never a raw `WHERE` string.~~ **Superseded.** They take structured predicates *or* a `RawPredicate` fragment, never both. | The original reasoning — that a `where: str` reachable from an MCP tool is a SQL-injection hole with extra steps — assumed the fragment would reach the server unexamined. It does not: the dialect composes the whole statement, parenthesises the fragment and binds every value, and the tool layer then re-parses the **composed** text through the same `SqlGuard` as `run-read-query`, authorising every object the fragment reaches before anything runs (DESIGN-MCP-TOOLS.md §464). So free-form SQL still has exactly one entrance — the guard — and the fragment goes through it like any other statement. Composing it here rather than in the tool layer is not a convenience: only the dialect knows that MS-SQL's `TOP (?)` binds the cap *before* the predicate while its `OFFSET … FETCH` branch binds it *after*, and a positional paramstyle pairs values to markers by position alone. Ruled by the user on 2026-09-03, restoring the `where` argument DESIGN-MCP-TOOLS.md had specified all along. |
| D4 | Parameter style belongs to the **driver**, not the engine, and is injected into the dialect at construction. | MS-SQL ships two drivers with different styles: `pyodbc` is `qmark`, `pymssql` is `pyformat`. A dialect that hardcoded `?` would emit broken SQL for half of its own connections. |
| D5 | Identifier **canonicalisation** and identifier **match key** are two different functions. | MS-SQL stores `Salaries` as written but compares it case-insensitively under the default collation. The catalogue needs the stored form; the permission resolver needs the comparison form. Conflating them makes a rule for `dbo.salaries` silently miss `dbo.Salaries`. |
| D6 | Non-ASCII case folding is **refused**, not guessed. | `str.lower()` on `İ` yields `i̇` (two code points) and `str.casefold()` on `ß` yields `ss`. Either would let two distinct server objects collapse onto one permission rule. ASCII `A–Z` folds; anything else must match exactly or the resolver raises. |
| D7 | The row cap is applied **twice**: rewritten into the statement and enforced again at `fetchmany`. | The statement may already carry its own `TOP`/`LIMIT`, a stored procedure returns whatever it likes, and a server-side cursor can be told a limit it ignores. Belt and braces on the one control that stands between an LLM and a full table dump. |
| D8 | The guard's per-engine knowledge is delivered by **one** call, `Dialect.guard_traits()`, returning a frozen dataclass. | One seam to test, one seam to mock, and `sql_guard.py` keeps a single dependency on the dialect layer rather than reaching for eleven properties. |
| D9 | SQLite `ATTACH` is refused outright. | An `ATTACH` names a **file path**, which is outside the permission model entirely — it is the database analogue of f-MCP's symlink escape. `main` is the only schema d-MCP will address. |
| D10 | Where an engine cannot express an action at all, the capability flag is an extra **deny**, never an extra allow. | A rule granting `create_role` on a SQLite connection resolves to denied because the engine cannot do it, not to "allowed but it will probably fail". Default-deny holds at the capability layer too. |

---

## 2. Shared vocabulary

`src/sape_d_mcp/db/dialects/types.py`. These types cross the whole layer, so they are frozen and hashable.

```python
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
    They differ on MS-SQL under a case-insensitive collation and on MySQL under
    `lower_case_table_names = 2`.
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


# `GrantInfo` stood here and was deleted at stage 8 rather than implemented; the correction
# at the end of §3.5 says why, and what `SecurityManager.list_grants()` returns instead.


@dataclass(frozen=True, slots=True)
class ServerTraits:
    """What the version probe learned.  Every version-dependent capability derives from it.

    `raw_version` is kept verbatim for the log; `version` is the parsed tuple; `variant`
    separates MariaDB from MySQL and Azure SQL Database from a boxed SQL Server, both of
    which change the capability answers materially.
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
```

---

## 3. The `Dialect` abstract base class

`src/sape_d_mcp/db/dialects/base.py`. Four modules implement it: `mssql.py`, `postgres.py`, `mysql.py`,
`sqlite.py`. Nothing outside `src/sape_d_mcp/db/` may import a concrete dialect; everything goes through
`dialect_for()` (§7).

### 3.1 Construction, identity and capabilities

```python
class Dialect(ABC):
    """Authors SQL for one engine.  Holds no connection and executes nothing (decision D1).

    A dialect is constructed unprobed and is deliberately near-useless in that state: the
    catalogue builders work, but anything version-dependent reports the conservative answer
    and `normalise_identifier()` raises on MS-SQL and MySQL, where the folding rule is a
    property of the server rather than of the engine.  `engine.py` calls `configure()` with
    the probe result immediately after the first successful connect, once per pooled
    connection group.
    """

    engine: ClassVar[Engine]
    display_name: ClassVar[str]
    default_port: ClassVar[int | None]
    default_schema: ClassVar[str | None]

    def __init__(self, param_style: ParamStyle) -> None:
        """Bind the dialect to the parameter style of the driver that will run its SQL.

        The style comes from the driver, not the engine (decision D4): the same
        `MSSQLDialect` emits `WHERE id = ?` for pyodbc and `WHERE id = %s` for pymssql.
        """

    def configure(self, traits: ServerTraits) -> None:
        """Record what the version probe learned and unlock the version-dependent answers.

        Idempotent, and refuses a second call with different traits — a pool handing one
        dialect instance to connections against two different servers is a bug that would
        make capability answers non-deterministic.
        """

    @property
    def traits(self) -> ServerTraits:
        """The probe result.  Raises `DialectNotConfiguredError` before `configure()`."""

    @property
    @abstractmethod
    def capabilities(self) -> Capabilities:
        """What this connection can do, derived from `traits` where the answer is
        version-dependent and from the engine where it is not.

        Unprobed, every version-dependent flag reads `False`.  Reporting an optimistic
        default here would turn "we do not know yet" into "yes, go ahead", which is the one
        direction a default-deny system must never fail in.
        """

    @property
    @abstractmethod
    def case_folding(self) -> CaseFolding:
        """How this server treats the case of an unquoted identifier.

        Constant for PostgreSQL and SQLite; probe-dependent for MS-SQL (catalogue collation)
        and MySQL (`lower_case_table_names`), where it raises before `configure()`.
        """

    @property
    @abstractmethod
    def param_style(self) -> ParamStyle:
        """The bound driver's PEP 249 paramstyle."""

    def placeholder(self, index: int, name: str | None = None) -> str:
        """Render one parameter marker for the bound style.

        `?` for qmark, `%s` for format, `%(name)s` for pyformat, `:1` for numeric.  Every
        builder in the layer goes through this, so adding a driver with a fifth style is one
        edit rather than four hundred.
        """

    def parameters(self, values: Sequence[Any], names: Sequence[str] | None = None) -> tuple[Any, ...] | dict[str, Any]:
        """Package values in the shape the bound style expects: a tuple, or a mapping."""
```

### 3.2 Quoting and normalisation

This is the part that decides whether a permission rule matches. It is the highest-risk code
in the layer and gets the densest tests.

```python
    @abstractmethod
    def quote_identifier(self, name: str) -> str:
        """Wrap `name` in this engine's identifier delimiters, doubling any inner delimiter.

        Raises `InvalidIdentifierError` for an embedded NUL, for a name exceeding
        `capabilities.max_identifier_length`, and for the engine's own additional
        prohibitions (MySQL forbids a trailing space; MS-SQL forbids a name that is entirely
        whitespace).  It never returns unquoted output: quoting unconditionally is what makes
        a reserved word, a space or an accent a non-event, and it costs nothing.
        """

    def quote_ref(self, ref: ObjectRef | NormalisedRef) -> str:
        """Quote a schema-qualified name, omitting the schema part where the engine has none."""

    @abstractmethod
    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str:
        """Return the form the server's catalogue holds for `raw`.

        `quoted` says whether the identifier reached us already delimited, which changes the
        answer on PostgreSQL: unquoted `Foo` becomes `foo`, quoted `"Foo"` stays `Foo`, and
        they are two different tables that can coexist in one schema.

        Raises `ValueError` for a non-ASCII identifier that would need case folding, rather
        than folding it (decision D6), and raises before `configure()` wherever the rule is
        probe-dependent.  Fail closed: a guessed identifier is a permission rule matching the
        wrong object.
        """

    @abstractmethod
    def identifier_match_key(self, name: str) -> str:
        """Return the key `permissions.resolve()` compares against a rule pattern.

        Distinct from `normalise_identifier()` (decision D5).  On PostgreSQL and SQLite the
        two coincide.  On MS-SQL under the usual `..._CI_AS` collation the canonical form is
        `Salaries` while the match key is `salaries`; under a `..._CS_AS` collation the match
        key is `Salaries` and a rule written for `salaries` correctly fails to match.  On
        MySQL the answer differs for table names and column names, so callers must pass a
        table name here only through `normalise_ref()`.
        """

    def normalise_ref(self, ref: ObjectRef) -> NormalisedRef:
        """Canonicalise and key a whole object reference in one step.

        Applies the engine's default schema where `ref.schema` is `None` and the engine has
        schemas — except that the MCP tools require an explicit schema, so this path is only
        reached from the GUI and from introspection results, never from LLM input.
        """

    def is_valid_identifier(self, raw: str) -> bool:
        """Cheap pre-flight for the GUI's inline validation.  Never a substitute for
        `quote_identifier()`, which is the enforcing call."""
```

**The four folding rules, stated exactly.**

| Engine | Unquoted identifier | Quoted identifier | Comparison | Match key |
|---|---|---|---|---|
| PostgreSQL | folded to lower case | preserved verbatim | byte-exact on the stored form | the canonical form; identical to it |
| MS-SQL | preserved verbatim | preserved verbatim | by the **database** collation | ASCII-lower when the collation name contains `_CI_`; the canonical form when it contains `_CS_`, `_BIN` or `_BIN2` |
| MySQL/MariaDB | preserved or lower-cased per `lower_case_table_names` | same | see below | ASCII-lower except where `lower_case_table_names = 0` |
| SQLite | preserved verbatim | preserved verbatim | ASCII case-insensitive | ASCII-lower |

MySQL in detail, because it is the one that catches people out:

| `lower_case_table_names` | Stored as | Compared | Typical host |
|---|---|---|---|
| `0` | as given | case-**sensitively** | Linux (default) |
| `1` | lower-cased on creation | case-insensitively | Windows (default), and mandated on macOS for 8.0 |
| `2` | as given | case-insensitively | macOS on a case-preserving filesystem (default) |

Only *database, table and alias* names follow that setting. **Column, index, stored-routine
and event names are always case-insensitive on every platform**, and trigger names are case
*sensitive*, which is a MySQL deviation from the standard rather than a typo here. Two match
keys therefore exist on MySQL and `identifier_match_key()` alone cannot answer correctly
without knowing what kind of name it was handed — the reason `normalise_ref()` is the
supported entrance.

Setting `lower_case_table_names` after initialisation is rejected by MySQL 8.0, so the probe
value is stable for the life of the server and may be cached with the pool.

### 3.3 Catalogue introspection

Every method returns a `Query` whose row shape is fixed by the accompanying `parse_*`
classmethod, so the SQL and the row unpacking are tested together.

```python
    @abstractmethod
    def list_schemas(self) -> Query:
        """Every schema the current principal can see, system schemas excluded.

        SQLite returns a one-row synthetic result (`main`), so the Explorer page and the
        rule editor do not need an engine-specific branch.
        """

    @abstractmethod
    def list_tables(self, schema: str | None = None) -> Query:
        """Base tables only.  Views come from `list_views()` because they carry different
        actions in the permission model and must never be conflated."""

    @abstractmethod
    def list_views(self, schema: str | None = None) -> Query:
        """Views, including materialised views where the engine has them (PostgreSQL)."""

    @abstractmethod
    def list_functions(self, schema: str | None = None) -> Query:
        """Scalar and table-valued functions, aggregates excluded."""

    @abstractmethod
    def list_procedures(self, schema: str | None = None) -> Query:
        """Stored procedures.  On SQLite this is a synthetic empty result rather than an
        error: `list` operations hide what is unavailable instead of failing the call, which
        is the behaviour `dmcp-permissions` requires of every list-style tool."""

    @abstractmethod
    def describe_table(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Columns, primary key, unique keys and foreign keys, as a fixed-length tuple of
        queries in that order.  Kept as separate statements rather than one heroic join
        because the join is unreadable on three of the four engines and impossible on SQLite,
        where the answers come from four different pragma functions."""

    @abstractmethod
    def describe_routine(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Signature, parameters and return type for a function or procedure."""

    @abstractmethod
    def object_definition(self, ref: NormalisedRef) -> Query:
        """The stored source text of a view, function or procedure.

        Returns one row, one column, which may be `NULL`: MS-SQL returns `NULL` for a module
        created `WITH ENCRYPTION` and for CLR objects, and MySQL withholds a routine body
        from a principal lacking `SHOW_ROUTINE`.  The caller must distinguish "no definition"
        from "definition withheld" and say which — an empty editor with no explanation is the
        kind of thing that gets debugged for an hour.
        """

    @abstractmethod
    def estimate_row_count(self, ref: NormalisedRef) -> Query:
        """A cheap, approximate row count for the confirmation dialog's impact estimate.

        Approximate on purpose: an exact `COUNT(*)` on a large table is itself an expensive
        operation to trigger from a confirmation prompt.  `confirmation.py` labels the number
        as an estimate and, for a `DELETE`/`UPDATE` with a predicate, additionally runs the
        exact `count_matching()` below because that number is small by construction.
        """

    def count_matching(self, ref: NormalisedRef, predicates: Sequence[Predicate]) -> Query:
        """Exact `COUNT(*)` restricted by the same predicates as the pending write, so the
        confirmation dialog can say "this will delete 4 rows", not "this will delete some
        rows"."""
```

### 3.4 DDL generation

```python
    @abstractmethod
    def create_table(self, ref: NormalisedRef, columns: Sequence[ColumnSpec],
                     primary_key: Sequence[str] = (), if_not_exists: bool = False) -> Script:
        """Build a `CREATE TABLE`.  Types in `ColumnSpec` are given in the engine's own
        vocabulary and validated against the engine's type list before emission; d-MCP does
        not invent a portable type language, because a silent `TEXT`-for-`NVARCHAR(MAX)`
        substitution is a data-loss bug wearing a convenience costume."""

    @abstractmethod
    def drop_table(self, ref: NormalisedRef, if_exists: bool = True) -> Script:
        """Destructive.  Never emits `CASCADE`: dropping a table and taking its dependants
        with it must be an explicit, separately confirmed act, and the confirmation dialog
        lists the dependants first."""

    @abstractmethod
    def create_view(self, ref: NormalisedRef, body: str, or_replace: bool = False) -> Script:
        """`or_replace` is honoured only where `capabilities.supports_create_or_replace_view`
        is true; elsewhere the script is drop-then-create with `atomic=False` and a warning
        key, so the human sees what they are agreeing to."""

    @abstractmethod
    def drop_view(self, ref: NormalisedRef, if_exists: bool = True) -> Script: ...

    @abstractmethod
    def create_routine(self, ref: NormalisedRef, body: str,
                       object_type: ObjectType, or_replace: bool = False) -> Script:
        """`body` is the complete `CREATE …` text supplied by the caller and is **not**
        parsed for meaning — a routine body is a whole procedural language and pretending to
        validate it would be theatre.  It is checked for a single leading statement, checked
        that the object it declares matches `ref`, and then run under the confirmation
        broker.  The rule that authorises it is `create` on that object type."""

    @abstractmethod
    def edit_routine(self, ref: NormalisedRef, body: str, object_type: ObjectType) -> Script:
        """Replace the body of an existing routine.  Destructive per `dmcp-permissions`.

        Where the engine has no atomic replacement (MySQL routines), the script is
        drop-then-create, `atomic=False`, with the previously introspected definition in
        `rollback` so a failed create can be undone, and a warning key explaining that grants
        on the routine are lost.
        """

    @abstractmethod
    def drop_routine(self, ref: NormalisedRef, object_type: ObjectType,
                     signature: str | None = None, if_exists: bool = True) -> Script:
        """`signature` is required on PostgreSQL when the name is overloaded, because
        `DROP FUNCTION add` is ambiguous and the server will refuse it.

        Refused rather than ignored on the other three (§3.5's stage-8 correction), and
        rebuilt from validated pieces rather than passed through where it is accepted.
        """

    def resolve_overload(self, ref: NormalisedRef, signature: str | None,
                         overloads: Sequence[str]) -> str | None:
        """Pick the one overload `signature` names out of the set the catalogue reported, and
        return the **server's** spelling of it — the string to pass on to `drop_routine()`,
        `grant()` or `revoke()`.  `None` means the bare name is unambiguous.

        Not abstract: the whole of it is engine-independent given `overloads_routines`,
        `type_aliases` and `_render_argument_type()`, which are the three things a dialect
        declares about its own types.
        """

    @abstractmethod
    def rename_object(self, ref: NormalisedRef, new_name: str) -> Script:
        """Renaming moves an object out from under its permission rule, so this is treated as
        a `drop` plus a `create` for authorisation purposes and needs both flags."""
```

### 3.5 Security: roles, users, groups and grants

```python
    @abstractmethod
    def list_principals(self) -> Query:
        """Every role, user and group visible to the current principal, with enough columns
        to fill `PrincipalInfo` including which of the three d-MCP is calling it."""

    @abstractmethod
    def list_group_members(self, group: str) -> Query: ...

    @abstractmethod
    def list_grants(self, ref: NormalisedRef | None = None) -> Query:
        """Server-side privileges, optionally for one object.  Read-only and shown beside the
        d-MCP rules in the Explorer page: the two permission systems are independent, and
        seeing where they disagree is most of the value of the page."""

    @abstractmethod
    def create_role(self, name: str) -> Script:
        """Raises `CapabilityError` where `capabilities.supports_roles` is false — SQLite
        always, MySQL before 8.0, MariaDB before 10.0.5."""

    @abstractmethod
    def create_user(self, name: str, *, host: str | None = None,
                    login: str | None = None, default_schema: str | None = None) -> Script:
        """Create a user that **cannot log in**, for a human to give a credential to later.

        `host` is mandatory on MySQL, where identity is the pair `'user'@'host'`, and there is
        deliberately no default: defaulting to `'%'` would silently create a user reachable
        from anywhere on the network.

        `login` names an **existing** login to map the new user onto, which is the case §4.1
        was really about.  What each engine emits, and why each is genuinely unable to connect:
        `CREATE USER [x] WITHOUT LOGIN` on MS-SQL; `CREATE ROLE "x" NOLOGIN` on PostgreSQL,
        because `trust`, `peer`, `ident`, `cert`, `gss` and `sspi` never consult a password and
        a `LOGIN` role with none connects freely under any of the six; and
        `CREATE USER `x`@`h` ACCOUNT LOCK` on MySQL, because a bare `CREATE USER` leaves an
        **empty** authentication string, which is a password anyone can log in with.
        """

    @abstractmethod
    def create_group(self, name: str) -> Script:
        """"Group" is not a native object on any of the four engines; each dialect documents
        what it maps to (a `NOLOGIN` role, a database role, a MySQL 8 role)."""

    @abstractmethod
    def add_group_member(self, group: str, member: str, *,
                         host: str | None = None) -> Script: ...

    @abstractmethod
    def remove_group_member(self, group: str, member: str, *,
                            host: str | None = None) -> Script: ...

    @abstractmethod
    def assign_role(self, role: str, principal: str, *,
                    host: str | None = None) -> Script: ...

    @abstractmethod
    def revoke_role(self, role: str, principal: str, *,
                    host: str | None = None) -> Script: ...

    @abstractmethod
    def grant(self, privileges: Sequence[str], ref: NormalisedRef | None,
              principal: str, with_grant_option: bool = False, *,
              host: str | None = None, signature: str | None = None) -> Script:
        """`privileges` are validated against the engine's own privilege vocabulary before
        emission; an unrecognised privilege is refused rather than passed through, because
        passing it through is an identifier-injection hole in the one place it would be least
        expected.

        `signature` is `drop_routine()`'s overload discriminator, added at stage 8 and refused
        on the three engines that cannot overload and on any `ref` that is not a routine."""

    @abstractmethod
    def revoke(self, privileges: Sequence[str], ref: NormalisedRef | None,
               principal: str, *, host: str | None = None,
               signature: str | None = None) -> Script: ...
```

> **Corrected at stage 8**, four times, and every correction is recorded here rather than
> folded silently into the block above.
>
> **`create_user()` takes no password.** The signature read
> `create_user(name, password: SecretStr, *, host=None, login_only=False)`, with the password
> described as "the one and only value in the whole layer that cannot be a bound parameter",
> rendered by `_password_literal()` (§3.8). `DESIGN-MCP-TOOLS.md` §11.2 is the newer document
> and is emphatic: **`create-user` takes no password, by design. No credential is ever accepted
> from a model, generated by a tool, returned in a result or written to a log.** The `password`
> parameter is gone and `_password_literal()` was **deleted rather than implemented**, which
> removes the interpolation point instead of defending it — and with it the redaction, the
> traceback hygiene and the server-side-logging caveat §3.8 anticipated, because there is no
> secret to leak when none is ever sent. `login_only` went too: with no credential to send
> there is no `CREATE LOGIN` this layer can compose, so "the login half only" describes an act
> that no longer exists. `login` replaces it, naming an **existing** login to map onto, and
> `default_schema` carries §11.2's tool argument. What each engine emits instead is in the
> docstring above; each is genuinely unable to connect, which the obvious alternative on two of
> the three would not have been.
>
> **Six builders grew a keyword-only `host`.** It is the host half of the MySQL account name of
> the principal each statement *acts on* — the member, the grantee — and it is refused on the
> other three engines rather than accepted and ignored, because silently dropping it would let
> a caller believe it had scoped a grant that is in fact unscoped. A pre-joined `bob@localhost`
> is never split on the `@`: the two halves are quoted and escaped separately, `@` is legal
> inside a quoted user name, and a parser over hostile text is the one thing this layer must
> not contain.
>
> **`grant()` and `revoke()` grew the overload discriminator `drop_routine()` already had.**
> PostgreSQL identifies a routine by name *and* argument types, and `GRANT EXECUTE ON FUNCTION
> f` is refused there while more than one `f` exists — so an ordinary schema had routines
> d-MCP could list and read and then neither drop nor permission. The keyword-only `signature`
> now runs through one kit in `base.py` for all three paths, and the four engines answer it the
> way they answer `host`: offered everywhere, honoured on the one engine where it means
> something, refused on the three where it does not, and refused on any reference that is not a
> routine. Nothing else names a routine — `create_routine()`/`edit_routine()` carry the argument
> list inside the `CREATE` text, and `describe_routine()` already answers one header row per
> overload — so nothing else grew one.
>
> **Where the argument types come from: the catalogue, matched against.** They are neither
> bound values nor identifiers this layer took out of the catalogue itself, so they get two
> gates rather than one. `resolve_overload()` (§3.4) matches the caller's argument list against
> the overload set introspection already reports and hands back the server's own spelling of
> it, so the caller's text chooses between rows and is never the text written down. This is
> what makes a user-defined type reachable at all: an enum, a domain or a composite has no
> entry in `column_types` and never can, because whether one exists is a per-database question
> a dialect cannot ask, so a type-vocabulary allowlist alone would address `f(integer)` and not
> `f(mood)`. The second gate runs on every path including the one that skipped the first:
> `_render_argument_list()` rebuilds what it is given from a mode word out of a fixed tuple and
> a type that is either in the engine's vocabulary or a well-formed name this layer re-quotes,
> and refuses anything it cannot attribute — `(integer) CASCADE` included, because a parser
> that discards the fragment it cannot read and keeps the next word composes a statement about
> a type called `cascade`. A dialect *executes* nothing, so the matching cannot happen inside
> the builder: `resolve_overload()` is a pure function over rows the caller has already read,
> and calling it is the tool layer's job.
>
> **`GrantInfo` is deleted, not widened.** §2 declared
> `GrantInfo(grantee, privilege, object_ref, grantable)` and nothing ever constructed one:
> `db/security.py` shapes a server privilege as a plain dictionary and argues in
> `list_grants()`'s docstring that the dataclass is wrong in two independent ways. Its
> `object_ref` is an `ObjectRef`, whose `object_type` is the permission model's five-member
> vocabulary, while a server privilege can be held on a sequence, a schema or the database
> itself — so a real grant would be shown unattributed in the one panel whose job is to show
> access the rule table cannot see. And it has no `state`, which is how SQL Server tells a
> `DENY` from a `GRANT`, so a `DENY` rendered through it would read as a grant and over-report
> access. Both hold, and a shape wrong in two ways is not an incomplete one; exported and
> constructed nowhere, it was a trap for whoever next assumed it was canonical. What stands is
> the dictionary keyed `(grantee, privilege, schema, object, grantable, state)` — the column
> order `list_grants()` already contracts for, with nothing invented on top of it.

### 3.6 Row operations

Structured predicates or one `RawPredicate` fragment, never both (decision D3, as superseded).
A fragment is composed here — parenthesised, with every value bound in the position this
engine's paging requires — and the **composed statement** is what the tool layer re-parses
through the guard. `Query.touches` still reports only the `ref` it was given: what the
fragment reaches is the guard's answer, not the builder's, because only the guard parses SQL.

```python
    @abstractmethod
    def select(self, ref: NormalisedRef, columns: Sequence[str] | None = None, *,
               predicates: Sequence[Predicate] = (),
               where: RawPredicate | None = None,
               order_by: Sequence[tuple[str, bool]] = (),
               row_cap: int, offset: int = 0) -> Query:
        """A parameterised `SELECT` with a **mandatory** row cap.

        `row_cap` has no default anywhere in the signature chain, so no caller can forget it;
        `engine.py` caps again at `fetchmany(row_cap + 1)` and reports truncation honestly
        (decision D7).  `columns=None` means every column, expanded from the introspected
        catalogue rather than emitted as `*`, so the result shape is stable across a later
        `ALTER TABLE` and the LLM cannot be handed a column that appeared after the rule was
        written.  Every column name is validated against the catalogue and then quoted.
        """

    @abstractmethod
    def insert(self, ref: NormalisedRef, rows: Sequence[Mapping[str, Any]], *,
               returning: Sequence[str] = ()) -> Query:
        """A multi-row `INSERT` with every value bound.  `returning` is honoured only where
        `capabilities.supports_returning`; elsewhere it is refused rather than silently
        dropped, because a caller relying on the returned keys would otherwise get `None` and
        carry on."""

    @abstractmethod
    def update(self, ref: NormalisedRef, values: Mapping[str, Any], *,
               predicates: Sequence[Predicate]) -> Query:
        """`predicates` is required and an empty sequence is a legal — but destructive —
        request: the resulting `Query.kind` is `DESTRUCTIVE`, which routes it through
        `confirmation.py` regardless of the permission flag."""

    @abstractmethod
    def delete(self, ref: NormalisedRef, *, predicates: Sequence[Predicate]) -> Query:
        """As `update()`: always destructive, and doubly so with no predicate."""

    @abstractmethod
    def call_routine(self, ref: NormalisedRef, arguments: Sequence[Any] | Mapping[str, Any],
                     object_type: ObjectType, row_cap: int) -> Query:
        """Invoke a function or procedure with bound arguments.

        The spelling differs more than it looks: MS-SQL `EXEC`, PostgreSQL `CALL` for a
        procedure and `SELECT * FROM f(…)` for a set-returning function, MySQL `CALL` with
        session variables for `OUT` parameters.  The row cap applies to whatever result set
        comes back.
        """
```

### 3.7 Connection

```python
    @abstractmethod
    def build_dsn(self, profile: ConnectionProfile) -> str | dict[str, Any]:
        """Assemble the connection string or keyword mapping for the bound driver —
        **without the password**.

        The secret is passed to the driver as a separate argument by `engine.py` and is never
        part of a string that could reach a log, an exception message or the Connections
        page.  Where the driver only accepts a single string (pyodbc), the DSN is assembled
        with a placeholder and the secret substituted immediately before the `connect()` call,
        inside a `try/finally` that clears the local name.
        """

    @abstractmethod
    def health_check(self) -> Query:
        """The cheapest statement that proves the connection is alive and the session usable.
        `SELECT 1` on three engines; SQLite uses `PRAGMA quick_check` on the first check of a
        session and `SELECT 1` thereafter, because a corrupt file is the SQLite-specific
        failure mode and it is silent until it is not."""

    @abstractmethod
    def version_probe(self) -> tuple[Query, ...]:
        """The statements whose results build a `ServerTraits`.  A tuple because MS-SQL needs
        three (`SERVERPROPERTY` for the version, another for the edition, one more for the
        database collation) and MySQL needs two (`VERSION()` and
        `@@lower_case_table_names`)."""

    @classmethod
    @abstractmethod
    def parse_traits(cls, rows: Sequence[Sequence[Any]]) -> ServerTraits:
        """Turn the probe results into `ServerTraits`.

        Refuses a server d-MCP does not support: a PostgreSQL wire-protocol impostor
        (CockroachDB, Redshift, Greenplum) is rejected by name here rather than half-working
        for three tool calls and then failing inside `pg_get_functiondef`.
        """
```

### 3.8 The single interpolation point

> **Corrected at stage 8: this method was deleted, not written.** The whole of §3.8 below is
> kept as the record of what was reserved and why it turned out not to be needed. §11.2 of
> `DESIGN-MCP-TOOLS.md` forbids d-MCP from ever handling a credential, so `create_user()` has
> no password to render, and removing the method removes the interpolation point rather than
> defending it — a stronger outcome than the careful allow-list, NUL check and quote-doubling
> rule specified here. Everything downstream goes with it: no `"***"` redaction in the audit
> row, no traceback hygiene, and no server-side statement log — PostgreSQL's
> `log_statement = 'ddl'`, an MS-SQL audit specification — that could record a secret, because
> none is sent. The PostgreSQL SCRAM-SHA-256 verifier named at the end as "the recommended
> refinement once stage 8 is working" is also withdrawn: it is a credential in another
> encoding, and §11.2 admits no encoding of one.
>
> What is left that is not a bound parameter is `_default_literal()` — no engine accepts a
> parameter marker anywhere in DDL, so a column default has nowhere to be a bound value — and
> `_collate_clause()`. Both say so in their own docstrings, and neither ever handles a secret.
> A note stands in `base.py` where this method did, saying that a feature which needs it back
> is a feature that accepts a credential from a model.


```python
    def _password_literal(self, secret: SecretStr) -> str:
        """Render a password as a SQL string literal.  The **only** interpolation in `src/sape_d_mcp/db/`.

        No engine accepts a bound parameter in `CREATE USER`/`ALTER LOGIN`, so this exists and
        must be as small and as boring as possible: reject any character outside a documented
        allow-list, reject an embedded NUL or newline, double the quote character, wrap.  The
        `SecretStr` wrapper keeps the value out of `repr()`, out of tracebacks and out of the
        audit record; the audit row for a `create_user` stores the parameters with the
        password replaced by `"***"`, and a test asserts the literal never appears in
        `audit.db` or in the JSONL sink.

        Server-side logging is outside our control and must be stated in the documentation:
        MySQL rewrites password-bearing statements before they reach the general log, but
        PostgreSQL with `log_statement = 'ddl'` and MS-SQL under an audit specification will
        record the literal.  PostgreSQL offers a way out — a pre-computed SCRAM-SHA-256
        verifier can be sent in place of the plaintext — and that is the recommended
        refinement once stage 8 is working; it is not in the stage-4 scope.
        """
```

---

## 4. Per-engine notes

Only genuine divergence is recorded here. Where an engine behaves as the shared vocabulary in
§2 already describes, this section says nothing about it — restating the general case per
engine is how a design document rots.

### 4.1 MS-SQL

Server logins and database users are two distinct principal classes, and either alone is
misleading: a login with no matching database user cannot see any object even after a `GRANT`,
and a user with no login cannot authenticate at all yet may hold every permission in the
schema. `list_principals()` therefore reports both halves, and
`PrincipalInfo.native_kind` distinguishes `"SQL_LOGIN"` from `"SQL_USER"` — `sys.*_principals`
`type_desc`, the server's own word — while `kind` reports the d-MCP vocabulary term `"user"`.

`create_user()` emits the database user only:

```sql
CREATE USER [alice] WITHOUT LOGIN;              -- no login named
CREATE USER [alice] FOR LOGIN [aliceLogin];     -- an existing login named
```

> **Corrected at stage 8.** This section previously required `create_user()` to emit both
> halves, as `CREATE LOGIN [alice] WITH PASSWORD = N'...', CHECK_POLICY = ON;` followed by
> `CREATE USER [alice] FOR LOGIN [alice];`, in one `atomic=True` script. It cannot: a SQL login
> requires a password and `DESIGN-MCP-TOOLS.md` §11.2 forbids this application from handling
> one, while a Windows login requires an Active Directory principal d-MCP has no way to
> validate. What ships is the half that carries the permissions. `WITHOUT LOGIN` is the form
> that is genuinely unable to connect — no SID mapping to any login and no password of its own
> — and the login half is either named by the caller, which is what the two-statement version
> was really reaching for, or left to a human.

Schemas are real, independent of ownership, and every object is addressed `schema.object`
throughout (`default_schema = "dbo"`): `CREATE SCHEMA sales AUTHORIZATION dbo;`. Ownership
chaining means a principal with no direct grant on a table can still reach it through a view
or stored procedure owned by the same principal as the table — server behaviour d-MCP's rule
table cannot see or control. `list_grants()` is the only place it becomes visible, and the
Explorer page shows it beside the d-MCP rules for exactly this reason: the two systems can
disagree, and the human needs to see where.

`CREATE OR ALTER` — used by `create_view()`/`create_routine()` when `or_replace=True` — is
only available from SQL Server 2016 SP1 (decision D2). Below that floor,
`capabilities.supports_create_or_replace_view`/`..._routine` read `False` and the dialect
falls back to `DROP ... IF EXISTS` followed by `CREATE`; the pair still runs inside one
transaction, so `atomic=True` and no `warning_key` is needed, unlike MySQL's equivalent
fallback.

Azure SQL Database is a distinct `ServerTraits.variant` (`"azure_sql_database"`, detected from
`SERVERPROPERTY('EngineEdition') = 5`). It has no server-level principals: `create_role()` and
`create_user()` on that variant emit `CREATE ROLE`/`CREATE USER ... WITH PASSWORD = '...'` as
**contained database** principals with no matching `CREATE LOGIN`, and
`capabilities.supports_cross_database_reference` is `False` where a three-part name would be
legal on a boxed instance.

Case folding follows the **database** collation, never the server collation (§3.2's table
already states the rule); `version_probe()` reads it from `sys.databases.collation_name` for
the current database — `SERVERPROPERTY('Collation')` gives the instance default and can differ
from it.

### 4.2 PostgreSQL

One object, `ROLE`, is both user and group; the distinction is the `LOGIN` attribute:

```sql
CREATE ROLE alice LOGIN PASSWORD '...';   -- create_user()
CREATE ROLE readers NOLOGIN;              -- create_group()
GRANT readers TO alice;                   -- add_group_member()
```

`PrincipalInfo.native_kind` is always `"role"`; `kind` reports `"user"` or `"group"` according
to `pg_roles.rolcanlogin`, exactly as the `PrincipalInfo` docstring in §2 describes.

Function volatility is the one place a `SELECT` can write. `pg_proc.provolatile` is `'i'`
(`IMMUTABLE`), `'s'` (`STABLE`) or `'v'` (`VOLATILE`); only the first two guarantee no side
effect. `RoutineInfo.is_deterministic` is `True` for `'i'` and `False` for `'s'`/`'v'`, and
`select()`/`call_routine()` classify a call to a function whose volatility is `VOLATILE` — or
unreadable, for want of `USAGE` on the function — as `StatementKind.WRITE` rather than `READ`.
`SELECT set_config(...)` and `SELECT nextval(...)` are both syntactically a `SELECT` and both
mutate server state; a dialect never infers volatility from the function body, only from the
catalogue flag, and where that flag cannot be read it assumes `VOLATILE`. The same fail-closed
posture as decision D6.

`object_definition()` uses `pg_get_functiondef(oid)`/`pg_get_viewdef(oid)`, which return `NULL`
for an object the current role lacks privilege to see the definition of — not an error, the
same "definition withheld" contract as MS-SQL's encrypted modules. Materialised views appear in
`list_views()` with `comment` noting they are materialised: they carry `REFRESH MATERIALIZED
VIEW`, not a live re-`SELECT`, and are a table-shaped object rather than a routine, so
`RoutineInfo.definition_available=False` never applies to one.

`parse_traits()` rejects any server whose `version()` string does not begin `PostgreSQL` —
CockroachDB, Amazon Redshift and Greenplum all speak the wire protocol well enough to connect
and badly enough to break `pg_get_functiondef`, a role-membership query, or both, several tool
calls in. Reject at the probe, not at the first divergence.

A routine name is not an identity here, and PostgreSQL is the only one of the four where that
is true: `add(integer, integer)` and `add(text, text)` are two objects, `DROP FUNCTION add` is
an error while both exist, and `GRANT EXECUTE ON FUNCTION add` is refused for the same reason
from PostgreSQL 10. `overloads_routines` is `True` on this dialect alone, and it is what turns
the keyword-only `signature` on `drop_routine()`, `grant()` and `revoke()` from a refusal into
an argument list. `type_aliases` and `_render_argument_type()` are the two engine-specific
answers the shared kit asks for: the first folds `int`/`integer` and `varchar`/`character
varying` together **for matching only**, because
`pg_get_function_identity_arguments()` prints the canonical spelling and a human writes the
alias; the second renders a type from `column_types` where there is one and from a re-quoted,
optionally schema-qualified, optionally `[]`-suffixed **name** where there is not — which is
how an enum, a domain or a composite type becomes addressable at all, none of them being
something `column_types` can ever list.

`max_identifier_length` is 63 bytes (`NAMEDATALEN - 1`). PostgreSQL itself silently truncates a
longer identifier rather than erroring — precisely the silent-collision hazard
`quote_identifier()` exists to prevent (§3.2); it raises `InvalidIdentifierError` before the
truncated name ever reaches the server.

### 4.3 MySQL/MariaDB

Before MySQL 8.0 there is no role object: a "user" — the `'name'@'host'` pair — is the only
principal, and every privilege is granted to it directly. `capabilities.supports_roles` is
`False` for every MySQL server below 8.0 and every MariaDB server below 10.0.5;
`create_role()` raises `CapabilityError` there. `create_group()` has no native target to map
onto on 5.7 and raises the same — d-MCP never approximates a group with a dummy user, which
would put an unlogged, un-auditable principal into the server's own catalogue just to make a
GUI button work.

From MySQL 8.0, roles exist but are **inert until activated**, the gotcha this subsection
exists to record:

```sql
CREATE ROLE 'app_read';
GRANT SELECT ON sales.* TO 'app_read';
GRANT 'app_read' TO 'alice'@'%';
SET DEFAULT ROLE 'app_read' TO 'alice'@'%';   -- omit this and alice's session has no active role
```

`assign_role()` therefore always emits the `GRANT ... TO` **and** the `SET DEFAULT ROLE`
statement as one `Script`; granting a role and stopping there leaves the human believing access
was granted when the next login proves otherwise. MariaDB's syntax for the same pair differs
(`GRANT role TO user;` then `SET DEFAULT ROLE role FOR user;`, no host qualifier on the role
name) — the reason `assign_role()` is implemented per branch inside `mysql.py` rather than
shared between MySQL and MariaDB.

DDL commits implicitly on this engine — every `CREATE`, `ALTER` and `DROP` ends any open
transaction whether or not it was asked to. `Script.atomic` is therefore `False` for every
DDL-bearing script here without exception; §2's `Script` docstring already gives the canonical
case (editing a routine is a real drop-then-create with a window where the routine does not
exist), and `rollback`/`warning_key` are populated wherever a prior definition was
introspected.

`CREATE OR REPLACE` exists for views (`capabilities.supports_create_or_replace_view = True`
from 5.7 onward) but not for stored routines: `capabilities.supports_create_or_replace_routine`
is always `False` on this engine, so `edit_routine()` is unconditionally drop-then-create here
— never version-gated the way MS-SQL's `CREATE OR ALTER` is.

MySQL has no `MERGE` statement and no data-modifying CTE of any shape: `WITH`, at every
supported version of MySQL and MariaDB, introduces a read-only common table expression.
`capabilities.supports_data_modifying_cte` is `False` unconditionally for this engine, and
§6's guard traits rely on that directly rather than re-deriving it.

### 4.4 SQLite

SQLite has no server-side principal of any kind. Whoever can open the file has full DML and
DDL rights inherent in filesystem access; there is no `GRANT`, no login, nothing for
`list_principals()` to enumerate. This makes d-MCP's own rule table the **only** access
boundary that exists for a SQLite connection — file permissions are the sole other line of
defence, and they sit outside this application entirely.
`capabilities.supports_roles`/`supports_users`/`supports_groups` are all `False`, always, and
**all twelve** security builders raise `CapabilityError` immediately. The GUI's Permissions and
Explorer pages grey out every security action for a SQLite connection rather than presenting a
control that always fails.

> **Corrected at stage 8.** This paragraph previously exempted `list_principals()` and
> `list_grants()`, which were to "return an empty result rather than raising, consistent with
> 'hide rather than refuse' for `list`-style operations". They raise, along with the other ten.
> "Hide rather than refuse" exists so that the *existence* of an object is not leaked through
> the difference between "empty" and "denied" — it is a rule about objects the caller may not
> see. Nothing is being hidden here: there are no principals on this engine at all, for anyone.
> An empty list therefore reads as "this database has no roles", which is a claim about the
> database, when the truth is that the question does not apply to the engine — and the two lead
> a reader to opposite conclusions about how much has been locked down. `DESIGN-MCP-TOOLS.md`
> §11.2 requires the refusal in those terms and is the newer document. The same reasoning
> applies with most force to `list_grants()`, whose whole purpose is to be read *beside* the
> d-MCP rules so a human can see where the two permission systems disagree: on SQLite there is
> no second system, and an empty grant list would suggest a locked-down file when in fact
> everything is permitted to anyone holding it.

There are no stored procedures and no user-creatable functions —
`capabilities.supports_stored_procedures` is `False`, `list_procedures()`/`list_functions()`
return empty results, and `create_routine()`/`edit_routine()`/`drop_routine()`/`call_routine()`
all raise `CapabilityError`.

`ALTER TABLE` on SQLite supports exactly `RENAME TO`, `RENAME COLUMN` (3.25+), `ADD COLUMN`
and `DROP COLUMN` (3.35+) — never a type change, a nullability change or a default change on an
existing column. `capabilities.supports_alter_column` is `False` unconditionally, and there is
no `alter_column()` method on `Dialect` at all — deliberately absent from §3.4, not merely
capability-gated, because the only honest implementation is "rebuild the table", a
`create_table` + copy + `drop_table` sequence the human must explicitly request as a
**migration**, never something a single tool call performs silently under a misleadingly small
name.

`supports_returning` depends on the `RETURNING` clause, added in SQLite 3.35.0
(2021-03-12) — and the SQLite version in play is whatever the Python interpreter's `sqlite3`
module was linked against, not a function of the Python version. A Linux distribution's system
Python frequently links an older system `libsqlite3` (Ubuntu 20.04 LTS ships 3.31); the
python.org Windows and macOS installers bundle a current one. `version_probe()` reads
`sqlite3.sqlite_version_info` directly — never `sys.version_info` — and `supports_returning` is
`False` below 3.35 regardless of host OS.

`ATTACH` is refused outright per decision D9 in §1. `capabilities.supports_cross_database_reference`
is therefore `False` even though the SQLite grammar itself supports it, because the feature it
would need — naming an arbitrary file path from inside a tool call — is outside the permission
model entirely.

Every flag on this engine is a constant, never probe-dependent — SQLite has no server to probe
beyond its own linked version:

| Flag | Value |
|---|---|
| `supports_schemas` | `False` |
| `supports_stored_procedures` | `False` |
| `supports_table_valued_functions` | `False` |
| `supports_roles` / `supports_users` / `supports_groups` | `False` |
| `supports_create_or_replace_view` | `False` (`DROP VIEW IF EXISTS` + `CREATE VIEW`, `atomic=True` — SQLite DDL *is* transactional) |
| `supports_create_or_replace_routine` | `False` (no routines to replace) |
| `supports_transactional_ddl` | `True` |
| `supports_alter_column` | `False` |
| `supports_returning` | probe-dependent on the linked SQLite version (3.35 floor) |
| `supports_cross_database_reference` | `False` (decision D9) |
| `supports_data_modifying_cte` | `False` (SQLite CTEs are `SELECT`-only) |
| `max_identifier_length` | `1024` — SQLite itself imposes no limit; d-MCP caps it for sanity and for consistency with the GUI's identifier field |

A tool call that reaches a `CapabilityError` must never surface a bare Python traceback:
`mcp_server.py` catches it at the tool boundary and returns the message verbatim as the tool's
error text — for example `"'create_role' is not supported by sqlite — SQLite has no
server-side principals"` — and the same string is what the Connections and Explorer pages show
under the corresponding greyed-out control. This is the general rule for every engine, not only
SQLite; SQLite is simply where nearly every security capability is absent at once, so it is the
sharpest illustration of it.

---

## 5. Driver matrix

Both MS-SQL drivers ship together, on purpose, so the multi-platform promise never depends on
an external installer being reachable: `pyodbc` is the default and needs the Microsoft ODBC
Driver installed on the host; `pymssql` is the fallback for a locked-down machine, a minimal
container, or a Linux distribution where installing a Microsoft package is not an option, and
needs nothing beyond `pip install`.

| Engine | Driver | pip package | Version floor | Param style | Connection form | Host requirement |
|---|---|---|---|---|---|---|
| MS-SQL | pyodbc | `pyodbc` | `>=5.0` | `qmark` | ODBC connection string | Microsoft ODBC Driver 18 for SQL Server, installed separately |
| MS-SQL | pymssql | `pymssql` | `>=2.3` | `pyformat` | keyword arguments | none — FreeTDS is compiled into the wheel |
| PostgreSQL | psycopg | `psycopg[binary]` | `>=3.1` | `pyformat` | `postgresql://` DSN or keyword mapping | none — the `binary` extra bundles `libpq` |
| MySQL/MariaDB | PyMySQL | `PyMySQL` | `>=1.1` | `pyformat` | keyword arguments | none — pure Python |
| MySQL/MariaDB | mysql-connector-python | `mysql-connector-python` | `>=8.3` | `pyformat` | keyword arguments | none — no external client library |
| SQLite | `sqlite3` | stdlib | Python floor 3.10 | `qmark` | filesystem path | none — always present |

### 5.1 MS-SQL: pyodbc

`build_dsn()` assembles an ODBC connection string with the password left as a placeholder,
substituted immediately before `connect()` inside a `try/finally` (§3.7):

```
Driver={ODBC Driver 18 for SQL Server};Server=tcp:db.example.com,1433;
Database=sales;UID=alice;PWD={password};Encrypt=yes;TrustServerCertificate=no;
```

Driver 18, never 17: it defaults `Encrypt=yes`, matching what Azure SQL Database and any
modern on-premises instance under a TLS-enforcing policy already requires — the whole reason to
name a version floor here rather than "the ODBC driver". Install commands, run once per host,
never by d-MCP itself:

```bash
# Ubuntu/Debian
curl https://packages.microsoft.com/keys/microsoft.asc | sudo tee /etc/apt/trusted.gpg.d/microsoft.asc
curl https://packages.microsoft.com/config/ubuntu/22.04/prod.list | sudo tee /etc/apt/sources.list.d/mssql-release.list
sudo apt-get update && sudo ACCEPT_EULA=Y apt-get install -y msodbcsql18 unixodbc
```

```bash
# macOS (Homebrew)
brew tap microsoft/mssql-release https://github.com/Microsoft/homebrew-mssql-release
brew update && HOMEBREW_ACCEPT_EULA=Y brew install msodbcsql18
```

```
:: Windows 10+ — run the "Microsoft ODBC Driver 18 for SQL Server" MSI, or:
winget install --id Microsoft.msodbcsql.18 -e
```

The MSI needs administrator rights on Windows; where that is unavailable (a locked-down
corporate image), the connection profile should select `pymssql` instead — this is precisely
the case the second driver exists to cover. On Linux, `unixODBC` must additionally be present
(`apt install unixodbc`) as the driver-manager layer pyodbc itself links against.

### 5.2 MS-SQL: pymssql

```python
pymssql.connect(server="db.example.com", port=1433, database="sales",
                 user="alice", password="...")
```

Self-contained on every platform d-MCP targets: the published wheels for Windows, Linux and
macOS bundle FreeTDS, so no separate driver install and no admin rights are needed anywhere.
FreeTDS negotiates TDS 7.4, which is sufficient for every supported server version; there is no
driver-version-to-server-version matrix to track here the way there is for `msodbcsql`.

### 5.3 PostgreSQL: psycopg

```
postgresql://alice@db.example.com:5432/sales?sslmode=require
```

(password appended by `engine.py`, never present in the string handed to `build_dsn()`'s
caller). The `binary` extra ships prebuilt wheels with `libpq` statically linked for Windows,
Linux (`manylinux`) and macOS (Intel and Apple Silicon both), so no compiler and no system
PostgreSQL client library are required on any of the three platforms.

### 5.4 MySQL/MariaDB: PyMySQL and mysql-connector-python

```python
{"host": "db.example.com", "port": 3306, "user": "alice",
 "database": "sales", "charset": "utf8mb4"}
```

`charset` must always be passed explicitly: PyMySQL's own default is `latin1`, a silent
mojibake trap for anything outside ASCII that has caught out more than one integration. Both
drivers are pure Python or ship without an external client library, so nothing extra is
installed on the host for either.

MySQL 8.0.4 onward defaults new accounts to the `caching_sha2_password` authentication plugin,
which needs RSA key exchange to complete a login over a connection that is not already
TLS-secured. Both drivers need the `cryptography` package to do that; d-MCP already depends on
`cryptography>=42.0` for the credential store's AES fallback (per `dmcp-permissions`), so this
is satisfied incidentally — worth stating so nobody removes that dependency thinking it is
unused when MySQL/psycopg TLS is not configured.

### 5.5 SQLite: `sqlite3`

`connections.db`'s `host` column is repurposed to hold the absolute file path for a SQLite
profile; `port` and `username` are unused and stored `NULL`. `build_dsn()` for this dialect
returns the bare path — there is no server, no credential, and no separate DSN syntax.
Behaviour differs by the *linked* SQLite version, not by any driver setting (§4.4); there is
nothing to install and nothing to pin beyond the Python floor already set by
`sape-house-style`.

---

## 6. The `sql_guard` contract as seen by a dialect

`sqlparse` tokenises and classifies generic SQL; it has no idea that `#` starts a comment only
on MySQL, that `GO` ends a batch only on MS-SQL, or that MySQL's `WITH` clause can never write.
`sql_guard.py` is built on `sqlparse` and owns the classification logic, but it borrows these
engine facts from the dialect rather than hardcoding four special cases into itself — that
borrowing is the whole of `sql_guard.py`'s contact surface with the dialect layer, and it is
four methods, no more:

```python
    def guard_traits(self) -> GuardTraits:
        """Grammar facts the guard needs and cannot get from `sqlparse` alone, in one call
        (decision D8).  Constant per engine — none of these facts are version-dependent, so
        this never consults `traits` and is callable before `configure()`.
        """

    @abstractmethod
    def quote_identifier(self, name: str) -> str: ...   # already specified in §3.2

    @abstractmethod
    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str: ...  # §3.2

    @abstractmethod
    def identifier_match_key(self, name: str) -> str: ...  # §3.2
```

The first is new to this section; the other three are the identifier methods §3.2 already
specifies, reused here because the guard must validate and quote every identifier a statement
references before it can decide whether that statement is safe to run — it does not duplicate
that logic.

`GuardTraits` joins the frozen dataclasses in §2:

```python
class WritingCTEShape(StrEnum):
    """How this engine's grammar allows a `WITH` clause to write, if at all.

    `NONE`: `WITH` is read-only end to end (MySQL/MariaDB).  `DML_IN_BODY`: a data-modifying
    statement can itself be the body of a CTE, typically paired with `RETURNING` so the outer
    query has something to select from (PostgreSQL, SQLite).  `DML_THROUGH_REFERENCE`: the CTE
    body stays a `SELECT`, but a following `UPDATE`/`DELETE` targets the CTE's name directly
    (MS-SQL) — syntactically an `UPDATE`/`DELETE` statement, not a `WITH` statement, but one
    the guard must still connect back to the CTE's row set to authorise correctly.
    """

    NONE = "none"
    DML_IN_BODY = "dml_in_body"
    DML_THROUGH_REFERENCE = "dml_through_reference"


@dataclass(frozen=True, slots=True)
class GuardTraits:
    """Everything `sql_guard.py` borrows from the dialect layer (decision D8)."""

    write_keywords: frozenset[str]
    ddl_keywords: frozenset[str]
    security_keywords: frozenset[str]
    line_comment_prefixes: tuple[str, ...]
    block_comment_delimiters: tuple[str, str]
    executable_comment_pattern: re.Pattern[str] | None
    batch_separator_pattern: re.Pattern[str] | None
    writing_cte_shape: WritingCTEShape
```

Stated per engine:

| Engine | Write keywords | DDL keywords | Batch separator | Comment syntaxes | `writing_cte_shape` |
|---|---|---|---|---|---|
| MS-SQL | `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `TRUNCATE` | `CREATE`, `ALTER`, `DROP` | `GO` alone on a line — a client-side convention `sqlparse` never tokenises as a keyword, so the dialect supplies the regex | `--`, `/* */` | `DML_THROUGH_REFERENCE` |
| PostgreSQL | `INSERT`, `UPDATE`, `DELETE`, `MERGE` (16+), `TRUNCATE` | `CREATE`, `ALTER`, `DROP` | none | `--`, `/* */` | `DML_IN_BODY` |
| MySQL/MariaDB | `INSERT`, `UPDATE`, `DELETE`, `REPLACE`, `TRUNCATE` | `CREATE`, `ALTER`, `DROP` | none | `--` (requires a trailing space or control character to be recognised as a comment starter), `#`, `/* */`, **`/*! ... */`** and versioned `/*!50700 ... */` | `NONE` |
| SQLite | `INSERT`, `UPDATE`, `DELETE` | `CREATE`, `ALTER`, `DROP` | none | `--`, `/* */` | `NONE` |

`security_keywords` — `GRANT`, `REVOKE`, and each engine's principal-management verbs
(`CREATE LOGIN`/`CREATE USER`/`CREATE ROLE` and their `ALTER`/`DROP` counterparts) — are
identical in spelling across MS-SQL, PostgreSQL and MySQL 8.0+, and empty on SQLite, which has
none of them.

MySQL's `/*! ... */` executable comment is the one genuine injection vector in this table, and
it is worth spelling out exactly why: MySQL runs the content inside it while every other engine
treats it as an ordinary, inert comment, so a string that looks entirely commented-out to a
generic tokeniser — and to a human skimming the query — can hide a statement that only MySQL
executes:

```sql
SELECT 1 /*!50000 ; DROP TABLE users */;
```

On MySQL 5.00.00 and above the `DROP` runs; everywhere else it is dead text. `guard_traits()`'s
`executable_comment_pattern` gives the guard the regex to detect any `/*!` sequence on this
engine; the guard's rule is to refuse the statement outright the moment one is found, never to
parse what is inside it, because that content follows the same grammar as the rest of the
statement and could itself hide another layer of the same trick.

The writing-CTE shapes tie directly back to `capabilities.supports_data_modifying_cte` in §2:
`True` only where `writing_cte_shape` is `DML_IN_BODY` (PostgreSQL) or
`DML_THROUGH_REFERENCE` (MS-SQL); `False` for MySQL/MariaDB and SQLite, both `NONE`. The two
fields are asserted to agree by a parametrised test — one seam, tested once, per decision D8's
own reasoning.

---

## 7. Connection profile to driver mapping

`connections.db` stores `engine` and `driver` as plain text (§2's `Engine` values for the
former; the pip-package key — `"pyodbc"`, `"pymssql"`, `"psycopg"`, `"pymysql"`,
`"mysql-connector-python"` or `"sqlite3"` — for the latter). A small registry turns that pair
into a concrete, unprobed `Dialect`:

```python
# src/sape_d_mcp/db/dialects/registry.py

_DIALECT_REGISTRY: dict[tuple[Engine, str], tuple[str, str, ParamStyle]] = {
    (Engine.MSSQL, "pyodbc"):                 ("sape_d_mcp.db.dialects.mssql",    "MSSQLDialect",      ParamStyle.QMARK),
    (Engine.MSSQL, "pymssql"):                ("sape_d_mcp.db.dialects.mssql",    "MSSQLDialect",      ParamStyle.PYFORMAT),
    (Engine.POSTGRESQL, "psycopg"):           ("sape_d_mcp.db.dialects.postgres", "PostgreSQLDialect", ParamStyle.PYFORMAT),
    (Engine.MYSQL, "pymysql"):                ("sape_d_mcp.db.dialects.mysql",    "MySQLDialect",      ParamStyle.PYFORMAT),
    (Engine.MYSQL, "mysql-connector-python"): ("sape_d_mcp.db.dialects.mysql",    "MySQLDialect",      ParamStyle.PYFORMAT),
    (Engine.SQLITE, "sqlite3"):               ("sape_d_mcp.db.dialects.sqlite",   "SQLiteDialect",     ParamStyle.QMARK),
}

_DRIVER_PACKAGES: dict[str, str | None] = {
    "pyodbc": "pyodbc>=5.0",
    "pymssql": "pymssql>=2.3",
    "psycopg": "psycopg[binary]>=3.1",
    "pymysql": "PyMySQL>=1.1",
    "mysql-connector-python": "mysql-connector-python>=8.3",
    "sqlite3": None,  # stdlib — never missing
}


def dialect_for(engine: Engine, driver: str) -> Dialect:
    """Return an unconfigured `Dialect` instance for `(engine, driver)`.

    Imports only the dialect module, never the third-party DB-API package a `Dialect` never
    touches (decision D1) — so this call must succeed even when that package is not installed.
    The Connections page needs to show a fully-built profile, with a clear "driver not
    installed" state on the test-connection button, rather than failing before the user has
    even attempted to connect.  Raises `KeyError`-derived `UnknownDriverError` for a
    `(engine, driver)` pair absent from the registry — a corrupt or hand-edited
    `connections.db` row, not a missing package.
    """


def import_driver(driver: str) -> ModuleType:
    """Import the DB-API driver module named by `driver`.  Called only from
    `engine.py.connect()`, at the one moment the driver is actually needed.

    Turns a bare `ImportError` into `DriverNotInstalledError`, whose message names the exact
    pip requirement from `_DRIVER_PACKAGES` — for example "The 'pyodbc' driver is not
    installed. Run: pip install pyodbc>=5.0" — with an additional line for `pyodbc` naming the
    Microsoft ODBC Driver 18 install command for the current platform (§5.1).  The MCP tool
    boundary and the GUI's connection-test handler both catch `DriverNotInstalledError`
    specifically and show its message verbatim; neither ever lets a bare `ImportError` or its
    traceback reach the user.
    """
```

The two MS-SQL rows point at the same `MSSQLDialect` class with two different `ParamStyle`
values — the concrete illustration of decision D4: one dialect, two drivers, two placeholder
grammars, selected at construction and never guessed from the SQL text at build time.

---

## 8. Conformance checklist

Every dialect implementation — and the guard and registry code that sits either side of it —
must satisfy every line below. Each is written so the QA agent can turn it directly into a
`pytest` assertion, generally parametrised over the four engines.

- [ ] `quote_identifier()` doubles an embedded delimiter, rejects an embedded NUL, and rejects
      a name exceeding `capabilities.max_identifier_length`, on every engine.
- [ ] `quote_identifier()` never returns an unquoted string, even for a name that needs no
      quoting under the engine's grammar.
- [ ] `normalise_identifier()` raises `ValueError` on a non-ASCII identifier that would require
      case folding, both unprobed and after `configure()` (decision D6).
- [ ] `normalise_identifier()` and `identifier_match_key()` raise `DialectNotConfiguredError`
      before `configure()` on every engine where the folding rule is probe-dependent (MS-SQL,
      MySQL), and work immediately on PostgreSQL and SQLite, where it is not.
- [ ] Unprobed, every version-dependent flag on `capabilities` reads `False` — never an
      optimistic default (decision D2).
- [ ] A `capabilities` flag reading `False` causes the corresponding builder to raise
      `CapabilityError` naming the missing feature — never `NotImplementedError`, and never a
      bare driver exception surfacing from a half-built statement.
- [ ] `select()` has no default for `row_cap`; omitting it is a `TypeError` caught at the call
      site, not a runtime default silently substituted (decision D7).
- [ ] `update()`/`delete()` called with an empty `predicates` sequence produce
      `Query.kind == StatementKind.DESTRUCTIVE`, on every engine, unconditionally.
- [ ] `Query.touches`, for every builder, lists exactly the objects `sql_guard.py`
      independently enumerates from the same generated SQL text — the D3/D8 agreement test.
- [ ] A routine overloaded twice can be dropped by naming one overload, the other survives,
      and the same argument list reaches `grant()`/`revoke()` — pinned against a real
      PostgreSQL where one is configured and skipped with a named environment variable where
      there is not.
- [ ] `drop_routine()`, `grant()` and `revoke()` refuse a `signature` on MS-SQL, MySQL and
      SQLite rather than ignoring it, and refuse one on any reference that is not a routine, on
      every engine including PostgreSQL.
- [ ] No argument list reaches a statement except rebuilt from validated pieces:
      `(integer); DROP TABLE x --` and `(integer) CASCADE` are both refused, and the second is
      not "repaired" into a statement about a type called `cascade`.
- [ ] `create_view()` and `edit_routine()` fall back to `atomic=False` with a populated
      `warning_key` exactly where the relevant `capabilities.supports_create_or_replace_*` flag
      is `False`, and use the atomic single-statement path everywhere it is `True`.
- [ ] `guard_traits().write_keywords` contains `MERGE` only for MS-SQL and PostgreSQL 16+,
      `REPLACE` only for MySQL/MariaDB, and `TRUNCATE` on every engine except SQLite.
- [ ] The guard detects every `writing_cte_shape` this document names — `DML_IN_BODY` on
      PostgreSQL and SQLite, `DML_THROUGH_REFERENCE` on MS-SQL — and raises nothing false-positive
      on a read-only `WITH ... AS (SELECT ...) SELECT ...` on any engine.
- [ ] On MySQL, any statement containing `/*!` is refused outright, without the guard ever
      attempting to parse what follows it.
- [ ] `_password_literal()` rejects every character outside its documented allow-list,
      including an embedded NUL or newline, and the rendered literal never appears verbatim in
      `audit.db` or the JSONL sink after a `create_user()` call — asserted by scanning both.
- [ ] `dialect_for()` succeeds with the corresponding third-party driver package absent from
      the environment; only `import_driver()`, called from `engine.py.connect()`, fails, and it
      fails with `DriverNotInstalledError` naming the exact pip requirement — never a bare
      `ImportError` or traceback reaching the MCP tool boundary or the GUI.
- [ ] `version_probe()` + `parse_traits()` reject a PostgreSQL wire-protocol impostor
      (CockroachDB, Redshift, Greenplum) by name at the probe, rather than proceeding with a
      `ServerTraits` that is silently wrong.
- [ ] Every `list_*` method returns an empty result, never an exception, for an object kind the
      engine does not have (SQLite procedures and functions; MySQL 5.7 roles; SQLite
      principals and grants) — the "hide rather than refuse" rule for `list`-style operations.
- [ ] `identifier_match_key()` and `normalise_identifier()` return identical values on
      PostgreSQL and SQLite, and provably different values on MS-SQL under a `_CI_AS` collation
      and on MySQL under `lower_case_table_names = 0`.
- [ ] A permission rule written against an object's canonical form matches that object under
      every case variation the engine's folding rule considers equivalent, and fails to match
      after decision D6 refuses to fold a non-ASCII identifier.
- [ ] Every concrete dialect (`MSSQLDialect`, `PostgreSQLDialect`, `MySQLDialect`,
      `SQLiteDialect`) instantiates cleanly for each `ParamStyle` its driver row in §7 declares,
      with no unimplemented `@abstractmethod` left on `Dialect` — a collection-time test, not a
      runtime discovery.
- [ ] `build_dsn()`'s return value — string or mapping — never contains the password; a test
      asserts the secret string does not appear in `repr()` of the result.
- [ ] `health_check()` and `version_probe()` build statements `guard_traits()`'s own keyword
      sets would classify as read-only, on every engine — the dialect does not ask the guard to
      trust a probe query it would refuse from anywhere else.
- [ ] SQLite's `supports_returning` tracks `sqlite3.sqlite_version_info` from the live
      interpreter, not a hardcoded assumption tied to the Python version — asserted by a test
      that monkeypatches the reported SQLite version below and above 3.35.
- [ ] `list_databases()` builds a fixed, parameterless `SELECT` on every engine, and the
      MySQL one uses `information_schema.schemata` rather than `SHOW DATABASES` — the guard is
      not taught a new statement family to fill a combo box
      (`DESIGN-CONNECTION-SETUP.md` §8.2).
- [ ] `list_databases()`'s **result shape is a contract, not an illustration**: the **first**
      column is the database name (aliased `database_name` on all four engines) and the
      **last** is an `is_system` flag, with whatever metadata that engine reports for free
      in between. It is deliberately not a single-column `SELECT name`, and
      `engine._split_system_rows()` — which reads `row[0]` and `row[-1]` — is the reference
      reader of it.
- [ ] `list_databases(include_system=True)` differs from the default only by dropping a
      filter, and `SYSTEM_DATABASES` is a frozen set on every dialect: system databases are
      *marked*, never hidden, since a user administering `msdb` must still be able to choose
      it.
- [ ] `bootstrap_database` names a catalogue every account can open (`master`, `postgres`,
      `information_schema`) and is `None` on SQLite, where the file is the database — and the
      caller treats a short enumeration as a permission-filtered answer, never as an error,
      because all three server engines filter silently.
- [ ] `build_dsn()` under `auth_mode = 'integrated'` emits `Trusted_Connection=yes` with no
      `UID` and no `PWD` on MS-SQL/pyodbc, omits the `user` key entirely on
      PostgreSQL/psycopg, and raises `DialectError` carrying the matrix's own sentence on
      pymssql and on both MySQL drivers — the three-layer refusal of ADR 0002.
