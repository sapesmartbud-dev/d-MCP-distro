# SAPÉ d-MCP — Permission resolution, logical design

Stage 1 deliverable. Companion to `DESIGN-DATA-MODEL.md`, whose §4 defines the `rules` and
`rule_targets` tables this document operates on. Where the two disagree, the DDL wins and this
document is the bug.

**Re-issued at schema version 2.** A rule's target patterns have moved to a child table, so one
rule names a *collection* of objects rather than exactly one. §2.1, §2.3, §2.4, §5.6, §7, §9 and
§10 are updated; everything else stands as written, because the resolution model itself did not
change — only what a rule can be asked about. `docs/adr/0004-permission-rule-targets.md` records
why, and the four schema-level defences the new shape needs.

---

## 1. The guarantee

One sentence, and everything below exists to make it true:

> An MCP tool call reaches a database object **only** if the operator wrote a rule that names
> that object and ticks that action, and it reaches **every** object the statement touches only
> if a rule covers each of them.

Three consequences worth stating before the mechanism:

- **Default-deny.** Absence of a rule is a denial, never a neutral. An empty `permissions.db`
  authorises nothing at all.
- **Fail closed.** Every uncertainty — an identifier that will not normalise, a statement whose
  referenced-object set cannot be fully determined, an object type the dialect does not report
  — resolves to a denial. There is no path where "we could not tell" becomes "allowed".
- **The permission table is the authority, not the server's own grants.** d-MCP may well be
  connected as a highly privileged database user. Its job is to be a narrower gate than the
  credentials it holds, so it never delegates an access decision to the server.

This mirrors SAPÉ f-MCP, where a path outside every rule is refused and a symlink inside a
granted directory may not reach outside it. §6 is the database restatement of that defence and
is the section to read if you only read one.

---

## 2. The rule and the ordering

### 2.1 Pattern grammar

A rule carries `(connection_id, object_type)`, an allow-or-deny, one action set, and **one or
more targets**. A target is a `(schema_pattern, name_pattern)` pair, and
`uq_rule_targets_key UNIQUE (connection_id, object_type, schema_pattern, name_pattern)` is what
version 1 called `uq_rules_key` — the same four columns, one table lower.

Resolution therefore ranks `(rule, target)` pairs. Everything below about *patterns* is unchanged,
because a target's patterns are the version 1 rule's patterns.

`schema_pattern` and `name_pattern` each take one of exactly three forms, enforced by
`ck_rules_schema_pattern` / `ck_rules_name_pattern` in the DDL:

| Form | Example | Matches |
|---|---|---|
| Exact literal | `Customers` | that name only |
| Prefix wildcard | `rpt_*` | any name starting `rpt_` |
| Bare wildcard | `*` | any name |

There is no infix or suffix wildcard, no regular expression, no character class. `*x`, `a*b`
and `**` are rejected by the schema. The grammar is deliberately this poor: every additional
form is another way for an operator to write a rule whose reach they have misjudged, and the
three forms above cover the cases the GUI needs to express.

`object_type` is one of `table`, `view`, `function`, `procedure`, `database`. There is no
wildcard object type — action sets differ per type, so a wildcard would have no coherent set of
`can_*` columns to interpret.

### 2.2 Specificity of a single dimension

For a pattern `p` that matches a name `n`, define

```
spec(p) = (2, len(p))        if p contains no '*'      -- exact
        = (1, len(p) - 1)    if p == prefix + '*'      -- prefix, scored by prefix length
        = (0, 0)             if p == '*'               -- bare wildcard
```

compared as an ordinary tuple. So `Customers` (2, 9) beats `Cust*` (1, 4) beats `C*` (1, 1)
beats `*` (0, 0).

**Within one dimension, two distinct matching patterns can never score equal.** Only one exact
pattern can match a given name. Two prefix patterns of equal prefix length that both match the
same name must be the same string. Only one bare wildcard exists. This is the first half of the
totality proof in §2.4.

### 2.3 Combining the two dimensions

Rules are ordered lexicographically on

```
(spec(name_pattern), spec(schema_pattern))
```

— **the name dominates the schema.**

This is a real decision and the alternative is defensible, so here is why. Consider a rule
`dbo.*` (specific schema, wildcard name) against `*.Salaries` (wildcard schema, exact name),
both matching `dbo.Salaries`.

Under schema-major ordering, `dbo.*` wins, and the consequence is that **a cross-schema rule
about a named object can never take effect wherever a schema-wide rule exists**. An operator
who writes `*.Salaries` to lock down a sensitive table wherever it appears would find it
silently overridden in every schema that has a blanket rule — the single most dangerous kind of
surprise this system can produce.

Under name-major ordering, `*.Salaries` wins. Nothing is lost: an operator who genuinely wants
schema-wide behaviour to prevail for one object writes `dbo.Salaries`, which is exact in both
dimensions and beats everything. Name-major is therefore strictly more expressive, and its
failure mode is the safe direction — the narrowly named rule is the one that applies.

### 2.3a A rule's specificity at an object

A rule with several targets may have more than one of them match the same object — `dbo`/`*` and
`dbo`/`Cust*` both match `dbo.Customers`. The definition, which is the only coherent one:

> **A rule's specificity at an object is the specificity of its narrowest matching target.**

`rule_for()` takes `max` over all matching `(rule, target)` pairs, so this falls out of the same
comparison rather than needing a second rule, and the row it returns cites the target that won —
which is what the denial message must name.

### 2.4 The order is total

Two matching rules for the same connection and object type can never tie.

Suppose targets `T_A` (of rule `A`) and `T_B` (of rule `B`) both match, with
`spec(name_A) == spec(name_B)` and `spec(schema_A) == spec(schema_B)`. §2.2 is a statement about
*patterns*, not about rows, so it is untouched: equal specificity between two *matching* patterns
in one dimension forces the patterns to be identical. Both targets were reached through
`WHERE connection_id = ? AND object_type = ?`, so all four columns of `uq_rule_targets_key` agree.
Therefore `T_A = T_B`; a target has exactly one `rule_id`; therefore `A = B`. ∎

**`rule_id` is deliberately not in that key.** Scoping the uniqueness per rule reads as the more
natural constraint, and is what a later maintainer would "correct" it to. It would let two rules
own the same target, and the ordering would then tie for real — silently, with only the defensive
tiebreak below standing between that and an arbitrary decision.

The proof is *stronger* than version 1's, where `is_deny` had to be excluded from the key by hand
so that an allow row and a deny row could not coexist on one key. A target carries no decision at
all, so that contradiction is not merely forbidden but unrepresentable.

**`NOT NULL` on every column of `rule_targets` is part of this proof, not housekeeping.** SQLite
counts NULLs as distinct in a UNIQUE index, a CHECK that evaluates to NULL *passes* —
`instr(NULL,'*') IN (0, length(NULL))` is NULL, not 0 — and a composite foreign key whose child
carries a NULL is satisfied vacuously. A single nullable column here would switch off the
uniqueness, the pattern grammar and the parent check at once.

**Defensive tiebreak.** The resolver nonetheless implements one: on an impossible tie, the deny
wins, and if both are denies or both allows, the lower `id` wins. The database may have been
hand-edited with the constraint dropped, and a resolver that raises or picks arbitrarily under
those conditions is worse than one that fails closed deterministically. The tiebreak is
unreachable through the application's own API, and a test asserts that it is.

---

## 3. Deny semantics

`is_deny = 1` marks a rule that matches and grants nothing. The DDL requires every `can_*`
column to be 0 on such a row.

**The most specific matching rule wins wholesale, whether it is an allow or a deny.** Its
action set is applied in its entirety; less specific rules contribute nothing, and there is no
merging of action sets across rules.

**A more specific allow therefore does override a less specific deny.** This is deliberate and
symmetric with the reverse case, which nobody disputes — everyone expects a specific deny to
carve a hole in a broad allow. Making the relationship symmetric means one sentence describes
the whole model: *the narrowest rule you wrote about this object is the one that applies.* An
asymmetric model, where deny is sticky and cannot be overridden, has two costs: the operator
must delete and rewrite a broad rule to make a narrow exception, and the mental model needs a
second sentence, which is where misconfiguration lives.

It costs nothing in safety, because default-deny already provides absolute refusal: to make an
object permanently unreachable, do not grant it. `is_deny` exists to punch a hole in a broader
grant, not to be an unappealable verdict.

**Why `is_deny` earns a column at all**, given a deny is behaviourally identical to an allow
with nothing ticked: it records *intent*. The GUI must distinguish "I explicitly blocked this"
from "I created this rule and have not ticked anything yet", and the denial message says which.

---

## 4. Default-deny, and no seeding

No matching rule means denied. A fresh `permissions.db` contains zero rows and authorises
nothing.

There is deliberately **no seeding** of default rules — not a read-only starter set, not
`SELECT` on the public schema, nothing. Every object an operator wants an LLM to reach is
granted explicitly, through the GUI, by a human who looked at it.

Pinned by `test_a_new_database_grants_nothing`, parametrised over every action in every
object type's tuple.

---

## 5. Identifier normalisation

### 5.1 What an identifier is here

`connection_id` already fixes the server and the database — they come from the connection
profile, not from anything the LLM says. So the identifier the resolver keys on is just

```
(connection_id, object_type, schema, name)
```

The concrete type is `NormalisedRef`, defined by the dialect layer
(`DESIGN-DIALECTS.md` §2) and produced by `Dialect.normalise_identifier()`. The resolver
never accepts a bare string or a raw `ObjectRef`: taking a type that only the dialect can
mint is what makes "someone forgot to normalise" a type error rather than a permission hole.

An LLM cannot reach a second database by naming it, because there is nowhere in the tool
signatures to name one. Cross-database references smuggled inside free-form SQL are the
`sql_guard`'s problem, and it rejects them (§6.4).

### 5.2 The hazard

Case folding differs per engine, and a rule that fails to match because of a case mismatch is a
**silent security failure**: the resolver returns "no rule", the call is denied, the operator
sees a denial they did not intend and widens the rule until it works — typically to `*`.

| Engine | Behaviour |
|---|---|
| PostgreSQL | Unquoted identifiers fold to **lower** case; quoted ones are preserved verbatim. |
| MS-SQL | Case-preserving. Comparison depends on the database collation, which may be case-sensitive or not. |
| MySQL / MariaDB | Column and routine names are case-insensitive; **table** names depend on `lower_case_table_names`, which in turn depends on the host filesystem. |
| SQLite | ASCII case-insensitive for identifiers; non-ASCII is case-*sensitive* unless ICU is compiled in. |

### 5.3 The rule: normalise against the catalogue

Folding rules alone are not trustworthy — MS-SQL collation and MySQL's
`lower_case_table_names` are per-server settings, and SQLite's ASCII-only folding is a trap for
non-English schemas. So:

> An identifier for an **existing** object is normalised by resolving it against the
> introspected catalogue and adopting the spelling the server itself reports.

`Dialect.normalise_identifier()` applies the engine's folding as a first pass, then the
introspection layer looks the object up, returning a `NormalisedRef` that carries **two**
spellings:

- `canonical_schema` / `canonical_name` — what the server's catalogue holds. This is what
  d-MCP emits in SQL and records in the audit row, so the log shows the object as the server
  names it.
- `key_schema` / `key_name` — what the resolver compares against a rule pattern.

They coincide on PostgreSQL and on SQLite. They diverge on MS-SQL under a case-insensitive
collation and on MySQL under `lower_case_table_names = 2`, where the server *stores* one
spelling but *compares* under another. Keeping the two apart is what stops a rule written as
`dbo.Customers` from failing to match a call that arrives as `dbo.CUSTOMERS` on a
case-insensitive server — while still emitting the catalogue's own spelling in the SQL.

A rule written from the GUI's schema browser, which shows catalogue spellings, therefore
always matches.

Two cases fall outside that:

- **An object that does not exist yet** (`create-table`, `create-view`, …). Folding alone is
  used; there is nothing to resolve against. The permission check is on the *pattern*, which is
  what the operator authorised, so this is sound.
- **An identifier that resolves to more than one catalogue object**, which MySQL can produce
  under a case-insensitive setting with a case-sensitive filesystem, or MS-SQL under a
  case-sensitive collation. This raises `ValueError`; it is never guessed.

### 5.5 Engines without a schema layer, and objects without a schema

SQLite has no schema layer, so a naive `NormalisedRef` for one of its tables would carry
`key_schema = None` — while `rules.schema_pattern` is `NOT NULL`, leaving no defined way for a
rule to match.

**Resolved by canonicalising rather than special-casing.** SQLite's `default_schema` is
`"main"`, which is a real SQLite schema and, because d-MCP refuses `ATTACH` (dialect decision
D9), the only one it will ever address. Every `NormalisedRef` therefore carries a schema on
every engine, the resolver never sees `None`, and a SQLite rule reads exactly like any other:

```
main | table | *          list, select
main | table | Salaries   deny
```

The alternative — letting only the bare `*` pattern match "no schema" — was rejected because it
makes an operator who types `main` create a rule that silently matches nothing, and forces the
GUI to know that one engine is different.

### 5.6 Database-scoped actions

The `database` object type's seven actions (`read_catalogue`, `run_query`, `create_role`,
`create_user`, `create_group`, `assign_group`, `assign_role`) belong to the connection, not to
any object in it. There is nothing meaningful to pattern-match.

**A `database` rule is therefore resolved by connection alone.** The resolver short-circuits:
for `object_type = "database"` it skips the pattern comparison, and the rule's single target is
written as `*`/`*`. At most one such rule exists per connection, which is exactly what "the
permissions of this database" means.

At schema version 2 that last sentence had to become a constraint rather than a consequence.
Version 1 got it free from `uq_rules_key` plus the forced `'*'/'*'`; with the patterns gone from
`rules` there is nothing left in the key to stop a second one, and `rule_for()` would then pick
between two by storage order. Hence
`CREATE UNIQUE INDEX uq_rules_one_database_per_connection ON rules(connection_id) WHERE object_type = 'database'`.
The resolver still applies its tiebreak and logs an ERROR if a hand-edited file presents two.

The GUI renders it as a fixed *Database and security* section with its seven checkboxes and no
pattern fields, rather than as a row in the object-rule table.

### 5.4 Fail closed on malformed input

`rule_for()`, `is_allowed()` and `require()` all raise `ValueError` — not "deny", not a
best-effort guess — when handed an identifier that is not fully qualified, contains a wildcard
character, contains a null byte, or is empty in either component.

This mirrors f-MCP's `rule_for()`, which refuses a path that is not absolute or contains `..`
rather than normalising it silently. A `ValueError` is a programming error surfacing loudly at
the boundary; a silent normalisation is the same bug reaching production as a permission hole.

---

## 6. Multi-object authorisation

**This is the section that matters.** Everything above decides whether *one* object is
reachable. Almost no real statement touches only one.

### 6.1 The rule

> Every object a statement references must be individually authorised for the action that
> statement performs on it. Authorisation of one object never implies authorisation of another.

### 6.2 Views do not launder access

Reading a view requires `select` on the **view** *and* `select` on **every base object it
reads**, recursively through nested views.

This is the exact analogue of f-MCP's symlink boundary: a symlink sitting inside a granted
directory is refused when its target lies outside, even though the operating system would
happily follow it. A view over a forbidden table is the same shape of escape, and gets the same
answer.

**The honest trade-off.** In ordinary SQL practice a view *is* the mechanism for exposing a
filtered subset of a table you do not grant. The strict rule takes that away, and an operator
who wants it must grant `select` on the base tables too — which widens access beyond the view.

We take the strict reading anyway, for one reason: d-MCP's premise is that its own table is the
authority and the connection may hold far broader credentials than the operator wants exposed.
A lenient rule would mean any view in the database — including one the LLM was permitted to
*create* — becomes a channel to everything the connection can see. Given `create-view` is in
the catalogue, lenient view semantics would be a hole straight through the model.

The operator who genuinely wants view-only exposure has a better tool than a d-MCP rule:
point the connection at a database user that can see only the view. That enforces the intent
one layer below, where it belongs.

*Recorded as a candidate refinement, not in scope:* a per-rule "trusted view" flag that stops
recursion at a named view. It adds a second mental model and was not part of the approved
permission design, so it is not being built on speculation.

### 6.3 Obtaining the referenced set

`sql_guard.referenced_objects(statement, dialect)` returns a set of
`(object_type, schema, name, action)` tuples, resolving unqualified names against the
connection's default schema. For a structured tool the set is built from the tool's own
arguments, which is exact. For `run-read-query` it comes from parsing.

Then, for each element, `permissions.require(connection_id, identifier, action)`.

The order matters: **authorise everything before executing anything.** A statement that is
partly authorised must not run partly. This is why f-MCP authorises every descendant of a tree
before deleting any of it.

### 6.4 When the set cannot be determined, refuse

If the parse yields anything the guard cannot fully attribute — a dynamic identifier, a
construct it does not model, a cross-database reference, a function whose body it cannot
inspect, more than one statement — the call is **refused**, not attempted.

The failure message says so plainly, and names what could not be resolved. "The guard could not
determine every object this statement reads" is an acceptable thing to tell a user. Executing
it anyway is not.

### 6.5 The action each reference requires

| Construct | Object | Action |
|---|---|---|
| `FROM t` / `JOIN t` | table | `select` |
| `FROM v` | view | `select` on the view, then recurse into its bases |
| `WHERE ... IN (SELECT ... FROM t)` | table | `select` |
| `WITH c AS (SELECT ... FROM t)` | table | `select` |
| `UPDATE t SET ... WHERE ... FROM u` | t / u | `update` on `t`, `select` on `u` |
| `DELETE FROM t WHERE ... IN (SELECT ... FROM u)` | t / u | `delete` on `t`, `select` on `u` |
| `INSERT INTO t SELECT ... FROM u` | t / u | `insert` on `t`, `select` on `u` |
| `CREATE VIEW v AS SELECT ... FROM t` | v / t | `create` on `v`, `select` on `t` |
| Scalar function call in any clause | function | `select` on every object the function body reads |

A writing CTE (`WITH c AS (INSERT ...)`, PostgreSQL) is classified as a write, never as a read,
and so can never travel through `run-read-query`.

---

## 7. The algorithm

```
rule_for(connection_id, ref: NormalisedRef) -> Rule | None
───────────────────────────────────────────────────────────
    validate(ref)                             # ValueError if malformed, §5.4
    candidates = SELECT r.*, t.id AS target_id,                  # NEVER `SELECT r.*, t.*`
                        t.schema_pattern, t.name_pattern         #   -- see the note below
                   FROM rule_targets t
                   JOIN rules r ON r.id = t.rule_id
                               AND r.connection_id = t.connection_id
                               AND r.object_type   = t.object_type
                  WHERE t.connection_id = ? AND t.object_type = ?    # indexed
    matching   = [r for r in candidates
                  if glob(r.schema_pattern, ref.key_schema)
                  and glob(r.name_pattern,  ref.key_name)]       # matched in Python, §4.3 DDL note
    if not matching:
        return None                                              # default-deny, §4
    return max(matching, key=lambda r: (
        spec(r.name_pattern),           # name dominates, §2.3
        spec(r.schema_pattern),         #   ... narrowest target within a rule, §2.3a
        r.is_deny,                      # defensive tiebreak, §2.4
        -r.id,                          #   ... then the lower rule id
        -r.target_id,                   #   ... then the lower target id
    ))


is_allowed(connection_id, ref, action) -> bool
───────────────────────────────────────────────
    validate_action(action, ref.object_type)   # ValueError if not in this type's tuple
    rule = rule_for(connection_id, ref)
    if rule is None or rule.is_deny:
        return False
    return bool(rule["can_" + action])


require(connection_id, ref, action) -> None
────────────────────────────────────────────
    if is_allowed(...):
        return
    rule = rule_for(connection_id, ref)
    raise PermissionDenied(denial_message(action, ref, rule))   # cites canonical_* spelling
```

Pattern matching happens in Python rather than SQL. A `LIKE`/`GLOB` pattern held in a *column*
cannot use an index, so pushing it into SQLite would buy nothing — and it would move the
security decision into SQLite's pattern semantics instead of our own tested code.

Two things in that query are load-bearing rather than stylistic.

**The projection is explicit.** Under `SELECT r.*, t.*` the name `id` appears twice and
`sqlite3.Row` keeps the *last*, so `mcp_server._rule_id()` would write a **target** id into
`audit.matched_rule_id` — pointing every historical denial in the Logs page at the wrong rule,
with nothing anywhere failing to say so. `r.*` comes first and `t.id` is aliased.

**The join repeats `connection_id` and `object_type` on both sides.** The composite foreign key
`(rule_id, connection_id, object_type) -> rules(id, connection_id, object_type)` already forbids a
target whose denormalised columns disagree with its rule's — but only while `PRAGMA foreign_keys`
is on. A row that drifted while it was off is then *inert* here rather than authoritative, which
is the difference between a bug and a rule applied to the wrong connection. `_apply_pragmas()`
correspondingly now verifies that the pragma actually took, the way it already verifies WAL: a
SQLite built without foreign key support accepts the statement, sets nothing, and reports 0.

### 7.1 The denial message

Format, matching f-MCP's:

```
'select' is not permitted on dbo.Salaries (rule: dbo.*)
'drop' is not permitted on dbo.Customers (no rule)
'select' is not permitted on dbo.Salaries (rule: *.Salaries, explicit deny)
```

The matched rule is always cited, because the operator's next question is invariably *which
rule did that*. Distinguishing "no rule", a matched allow that lacks the tick, and an explicit
deny is what makes the message actionable rather than merely negative.

Denials are logged to `audit.db` with `decision = 'denied'` and `matched_rule_id` set, so the
Logs page shows the same three cases.

---

## 8. Worked examples

Connection `BD1` throughout. Rules are listed most-specific-first for readability, not as
stored.

| # | Rules in force | Request | Decision | Why |
|---|---|---|---|---|
| 1 | *(none)* | `select` on `dbo.Customers` | **Denied** — `(no rule)` | Default-deny, §4 |
| 2 | `dbo` / `table` / `*` → `list, select` | `select` on `dbo.Customers` | **Allowed** | Only match; `can_select = 1` |
| 3 | `dbo` / `table` / `*` → `list, select`<br>`dbo` / `table` / `Salaries` → *deny* | `select` on `dbo.Salaries` | **Denied** — explicit deny | Exact name (2,8) beats `*` (0,0); deny carves the hole |
| 4 | `dbo` / `table` / `*` → *deny*<br>`dbo` / `table` / `Customers` → `select` | `select` on `dbo.Customers` | **Allowed** | A more specific allow overrides a broader deny, §3 |
| 5 | `dbo` / `table` / `*` → `select`<br>`*` / `table` / `Salaries` → *deny* | `select` on `dbo.Salaries` | **Denied** | Name-major ordering: `Salaries` (2,8) beats `*` (0,0) in the dominant dimension, §2.3 |
| 6 | `dbo` / `view` / `v_Staff` → `select`<br>*(no rule on `dbo.Salaries`)* | `select` on view `dbo.v_Staff`, which reads `dbo.Salaries` | **Denied** — `'select' is not permitted on dbo.Salaries (no rule)` | Views do not launder access, §6.2 |
| 7 | `dbo` / `table` / `Customers` → `select`<br>*(no rule on `dbo.Orders`)* | `run-read-query` joining `Customers` to `Orders` | **Denied** on `dbo.Orders` | Every referenced object authorised, §6.1; nothing executes |
| 8 | `dbo` / `table` / `rpt_*` → `select`<br>`dbo` / `table` / `rpt_secret*` → *deny* | `select` on `dbo.rpt_secret_pay` | **Denied** | Longer prefix (1,10) beats shorter (1,4), §2.2 |
| 9 | `dbo` / `table` / `Customers` → `select`, `update` | `update` on `dbo.Customers` with no `WHERE` | **Permitted, then brokered** | Permission passes; the confirmation broker still gates it |
| 10 | `dbo` / `database` / `*` → `read_catalogue` *(no `run_query`)* | `run-read-query` on anything | **Denied** — `'run_query' is not permitted` | `run_query` gates free-form SQL per connection |

---

## 9. `src/sape_d_mcp/permissions.py` — API surface

```python
from __future__ import annotations

# Action tuples, per object type. THE single source of truth: these generate the
# can_* columns, the PRAGMA table_info migration, grant()/deny() validation, the
# GUI's checkbox grid, and a parametrised test. Adding an action means editing
# exactly one entry here.
ACTIONS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "table":     ("list", "read_structure", "select", "insert",
                  "update", "delete", "create", "drop"),
    "view":      ("list", "read_definition", "select", "create", "drop"),
    "function":  ("list", "read_definition", "create", "edit", "drop"),
    "procedure": ("list", "read_definition", "create", "edit", "drop"),
    "database":  ("read_catalogue", "create_role", "create_user", "create_group",
                  "assign_group", "assign_role", "run_query"),
}

OBJECT_TYPES: tuple[str, ...] = tuple(ACTIONS_BY_TYPE)
ALL_ACTIONS: tuple[str, ...] = tuple(sorted({a for s in ACTIONS_BY_TYPE.values() for a in s}))

# How long an operator's own name for a rule may be. Interpolated into the DDL's
# CHECK, into _validate_rule_name() and into its message, so the schema and the
# Python cannot disagree about the limit.
MAX_RULE_NAME_LENGTH = 80


class PermissionDenied(PermissionError):
    """Raised by require() when a rule does not authorise the action."""


# The resolver's identifier type is NormalisedRef, minted by the dialect layer
# (src/sape_d_mcp/db/dialects/base.py, DESIGN-DIALECTS.md §2). It carries canonical_schema /
# canonical_name — the catalogue's own spelling, used for SQL emission and audit —
# alongside key_schema / key_name, which is what the pattern matcher compares.
# Accepting only a type the dialect can mint makes a missed normalisation a type
# error instead of a permission hole.
from sape_d_mcp.db.dialects.base import NormalisedRef


class PermissionStore:
    """Rule storage and resolution for permissions.db.

    Default-deny: an empty store authorises nothing, and no rules are ever seeded.
    """

    def __init__(self, db_path: str | os.PathLike[str] | None = None,
                 user: str | None = None) -> None: ...

    def _migrate_schema(self) -> None:
        """Add a can_* column for any action in ALL_ACTIONS the table lacks."""

    # -- the version 2 primitives: a rule names a collection --------------------

    def create_rule(self, connection_id: int, object_type: str,
                    targets: Sequence[tuple[str, str]],
                    actions: Sequence[str] | str = "all",
                    *, is_deny: bool = False, rule_name: str | None = None) -> int:
        """Write one rule over many (schema_pattern, name_pattern) targets. Returns its id.

        A target may belong to only one rule per connection and object type; a
        collision raises ValueError naming the owning rule, never a bare
        IntegrityError. At least one target is required — 'every rule has a target'
        cannot be a SQLite constraint, so the API is where it is enforced.

        rule_name is the operator's own label, optional and unique per connection
        among the names actually set; a collision raises ValueError naming the rule
        that already holds it. It is metadata: no part of resolution reads it."""

    def update_rule(self, rule_id: int, targets: Sequence[tuple[str, str]],
                    actions: Sequence[str] | str = "all",
                    *, is_deny: bool = False, rule_name: str | None = None) -> None:
        """Replace a rule's targets, its action set AND its name, all wholesale.

        connection_id and object_type are fixed at creation: they are denormalised
        into every target row and are part of the composite foreign key.

        rule_name is the name the rule carries AFTER the call, not a name to add:
        omitting it leaves the rule unnamed, exactly as omitting an action leaves it
        ungranted. An edit dialog must put the current name back."""

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule and every target it names. False if it was not there."""

    def targets_for(self, rule_id: int) -> list[dict]:
        """One rule's targets, in a deterministic order."""

    # -- single-target wrappers, kept for the Database-and-security section -----

    def grant(self, connection_id: int, schema_pattern: str, object_type: str,
              name_pattern: str, actions: Sequence[str] | str = "all") -> None:
        """Upsert a single-target allow rule. Replaces that rule's whole action set,
        and carries an existing rule's NAME across untouched — it upserts an action
        set, not a whole rule, and the Permissions page calls it from a checkbox with
        no name in its hand.

        Raises ValueError if the target's rule names other objects too — see below."""

    def deny(self, connection_id: int, schema_pattern: str, object_type: str,
             name_pattern: str) -> None:
        """Upsert a single-target rule that matches and grants nothing."""

    def revoke(self, connection_id: int, schema_pattern: str, object_type: str,
               name_pattern: str) -> bool:
        """Delete a single-target rule. Returns False if it was not there.
        Raises ValueError if the target's rule names other objects too."""

    def rules(self, connection_id: int | None = None) -> list[dict]:
        """Every rule with its `targets` attached, newest first, optionally for one
        connection. Two queries and a grouping, never one query per rule.

        Each row is the whole `rules` row, so it carries `rule_name` — the operator's
        own label, or None for a rule nobody has named."""

    def rule_for(self, connection_id: int, ref: NormalisedRef) -> dict | None:
        """The single most specific matching rule, or None. Raises ValueError on a
        malformed identifier rather than guessing.

        Carries `rule_name` too, so a denial is traceable to the rule as the operator
        labelled it. It takes no part in the decision."""

    def is_allowed(self, connection_id: int, ref: NormalisedRef, action: str) -> bool: ...

    def require(self, connection_id: int, ref: NormalisedRef, action: str) -> None:
        """Raise PermissionDenied, citing the matched rule, unless allowed."""

    def require_all(self, connection_id: int,
                    references: Iterable[tuple[NormalisedRef, str]]) -> None:
        """Authorise every (identifier, action) before any of them is acted on."""

    def delete_rules_for_connection(self, connection_id: int) -> int:
        """Cascade for a deleted connection; see DESIGN-DATA-MODEL.md §7."""

    def close(self) -> None: ...
```

`grant()` and `update_rule()` replace the rule's entire action set rather than merging, so the
GUI's edit dialog always sends the complete checkbox state. This is f-MCP's documented semantic
and the GUI depends on it.

`format_rule()` emits `rule_name` — the operator's own label for the rule, or `null` — and
`targets: [{schema_pattern, name_pattern}, ...]` in place of the two scalar
keys. **No single-target alias is kept beside it**: a scalar holding "the first target" is a
half-truth about a rule's reach, and a half-truth is worse for an LLM deciding what it may touch
than a changed shape it has to read properly.

### 9.1 Why `grant()` refuses a shared target

Three cases on the existing target row: **none** → a new one-target rule; **a single-target rule**
→ version 1's upsert, byte for byte; **a multi-target rule** → `ValueError`, naming the rule and
its other objects. `revoke()` is symmetric.

Neither alternative is safe.

- *Mutating the siblings* gives the call a blast radius wider than its own arguments.
  `grant(cid, "dbo", "table", "Customers", ["drop"])` against a rule that also targets `dbo`/`*`
  hands `drop` to every table in the schema. A permission call whose reach cannot be read off its
  own call site is not auditable, and that property is worth more than the convenience.
- *Silently splitting the target out* into its own rule fails the other way, and more quietly.
  The operator's next tightening of the rule they believe covers that object leaves a hole they
  think they closed — the same shape of failure `synchronous = FULL` exists to prevent, arriving
  through the API instead of through a power cut, and with nothing in the GUI showing the split.

Callers that mean to change a collection say so, through `update_rule()`.

### 9.2 The rule's own name

Schema version 3 adds `rules.rule_name`. The rules list showed an object type, some patterns and
an effect, and nothing on the row said what the rule was *for*; an operator returning to a file
they wrote a month ago could not tell one broad `dbo`/`rpt_*` rule from another.

Four properties, and the first is the one that matters here:

1. **It is metadata and only metadata.** Nothing in `rule_for()`, `is_allowed()` or `require()`
   reads it; it appears in no ordering key and in no `WHERE` clause of the resolver. A rule
   authorises exactly what it authorised before it was named, which is what lets a label be
   edited freely by whoever is looking after the rules. Pinned by
   `test_naming_a_rule_cannot_change_a_permission_decision`, because this is the class of claim a
   security store has to prove rather than assert.
2. **Optional**, so the version 2 → 3 upgrade is an `ALTER TABLE … ADD COLUMN` that backfills
   nothing. Every rule written before version 3 is unnamed until a human names it.
3. **One spelling of "no name", and it is `NULL`.** `_validate_rule_name()` folds `None` and `''`
   to `NULL` and stores the *stripped* text of anything else. A string that is not empty but
   strips to empty — `'   '` — is **refused** rather than folded: it is a name the operator typed,
   and watching it vanish is the silent normalisation §5.4 refuses everywhere else. Over
   `MAX_RULE_NAME_LENGTH`, or carrying a control character, is likewise a `ValueError` with the
   store's usual voice, so the GUI can put `str(exc)` straight into a message box.
4. **Unique per connection, over the names actually set**, enforced by a partial unique index and
   not only in Python (DESIGN-DATA-MODEL.md §4.2). A duplicate surfaces as a `ValueError` naming
   the rule that already holds it — never a bare `sqlite3.IntegrityError`.

---

## 10. Invariants the test suite must pin

Sentence-style names, in the house style.

**Default-deny**
- `test_a_new_database_grants_nothing` — parametrised over every action of every object type
- `test_a_rule_that_matches_nothing_does_not_widen_anything`

**The collection**
- `test_one_rule_covers_every_object_it_names`
- `test_a_rules_reach_can_be_changed_after_it_is_written`
- `test_a_rule_must_name_at_least_one_object`
- `test_a_duplicate_target_in_one_call_is_collapsed_not_refused`

**Ordering**
- `test_an_exact_name_beats_a_prefix_which_beats_a_wildcard`
- `test_a_longer_prefix_beats_a_shorter_one`
- `test_a_specific_name_beats_a_specific_schema`
- `test_the_narrowest_matching_target_of_one_rule_is_the_one_cited`
- `test_two_rules_can_never_own_the_same_target`
- `test_a_refused_rule_leaves_nothing_behind`
- `test_the_same_target_may_be_reused_on_another_connection`
- `test_the_defensive_tiebreak_prefers_the_deny`

**The schema's own four defences**
- `test_a_null_pattern_cannot_be_stored`
- `test_a_malformed_pattern_is_refused_by_the_schema_as_well_as_by_python`
- `test_a_target_cannot_hang_off_a_rule_of_another_connection`
- `test_a_connection_cannot_hold_two_database_rules`
- `test_the_resolver_row_carries_the_rule_id_not_the_target_id`

**The single-target wrappers**
- `test_grant_still_upserts_a_single_target_rule`
- `test_grant_refuses_a_target_its_rule_shares_with_others`
- `test_revoke_refuses_a_shared_target_too`

**The version 1 -> 2 migration**
- `test_the_migration_keeps_every_rule_id`
- `test_the_migration_preserves_the_autoincrement_high_water_mark`
- `test_the_migration_transfers_every_permission_verbatim`
- `test_the_migration_keeps_a_column_for_an_action_since_withdrawn`
- `test_reopening_a_migrated_file_is_a_no_op`

**The rule's own name (§9.2)**
- `test_naming_a_rule_cannot_change_a_permission_decision` — the one that matters
- `test_a_fresh_database_carries_the_name_column_and_its_index`
- `test_two_rules_on_one_connection_cannot_share_a_name`
- `test_a_name_collision_is_not_escaped_by_changing_the_case`
- `test_the_same_name_may_be_used_on_another_connection`
- `test_any_number_of_rules_may_be_unnamed`
- `test_an_empty_name_is_stored_as_no_name_at_all`
- `test_a_name_is_stored_stripped_so_the_uniqueness_means_what_it_shows`
- `test_a_whitespace_only_name_is_refused_rather_than_quietly_emptied`
- `test_an_over_long_name_is_refused_with_the_limit_in_the_message`
- `test_the_schema_refuses_a_blank_or_duplicate_name_when_python_is_bypassed`
- `test_grant_does_not_clear_the_name_of_the_rule_it_upserts`

**The version 2 -> 3 migration**
- `test_the_version_three_migration_leaves_every_rule_and_target_untouched`
- `test_the_version_three_migration_transfers_every_permission_verbatim`
- `test_the_version_three_migration_invents_no_name`
- `test_the_version_three_migration_leaves_a_v2_backup_and_a_record`
- `test_the_upgraded_file_enforces_the_new_uniqueness`
- `test_reopening_a_version_three_file_is_a_no_op`
- `test_a_version_one_file_walks_the_whole_chain_and_arrives_nameable`

**Deny**
- `test_a_specific_deny_carves_a_hole_in_a_broad_grant`
- `test_a_specific_allow_overrides_a_broader_deny`
- `test_a_deny_rule_cannot_carry_a_granted_action`

**Identifiers**
- `test_an_unqualified_identifier_raises_rather_than_being_guessed`
- `test_an_identifier_containing_a_wildcard_is_rejected`
- `test_a_postgres_unquoted_identifier_matches_a_lowercase_rule`
- `test_an_ambiguous_mysql_table_name_raises`
- `test_a_case_insensitive_collation_matches_a_rule_in_catalogue_case`
- `test_the_key_and_canonical_spellings_diverge_only_where_the_engine_does`
- `test_the_audit_row_records_the_canonical_spelling_not_the_key`
- `test_a_null_byte_in_an_identifier_is_rejected`

**Multi-object — the f-MCP link-boundary analogue**
- `test_reading_a_view_does_not_grant_its_underlying_tables`
- `test_a_nested_view_recurses_to_every_base_object`
- `test_a_join_is_denied_when_one_of_two_tables_is_forbidden`
- `test_a_subquery_in_a_where_clause_is_authorised_too`
- `test_a_writing_cte_is_never_classified_as_a_read`
- `test_nothing_executes_when_one_reference_of_many_is_denied`
- `test_a_statement_whose_references_cannot_be_determined_is_refused`
- `test_a_cross_database_reference_is_refused`

**Free-form SQL**
- `test_run_read_query_requires_the_run_query_action`
- `test_run_read_query_refuses_a_second_statement`

**Messages and audit**
- `test_a_denial_names_the_matched_rule`
- `test_a_denial_distinguishes_no_rule_from_an_explicit_deny`
- `test_every_denial_is_written_to_the_audit_log`
