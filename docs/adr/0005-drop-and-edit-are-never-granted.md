# ADR 0005 — `drop` and `edit` can never be granted

- **Status:** accepted (post stage 9), by user ruling
- **Date:** 2026-09-13
- **Supersedes part of:** DESIGN-PERMISSIONS.md §3 (a ticked action is an authorisation),
  DESIGN-MCP-TOOLS.md §8.1 (the four `drop-*` and the two `edit-*` tools are reachable with the
  permission and the approval)
- **Schema:** `permissions.db` `user_version` 3 → 4
- **Implemented by:** `src/sape_d_mcp/permissions.py`; two call sites in
  `src/sape_d_mcp/mcp_server.py`; `src/sape_d_mcp/gui/dialogs/new_rule_dialog.py`;
  `src/sape_d_mcp/gui/pages/permissions_page.py`; two error texts in
  `src/sape_d_mcp/db/dialects/base.py`

---

## Context

`drop` destroys an object. Unlike `delete`, which removes rows from a table that still exists and
can be restored from a backup of that table, a dropped table takes its definition, its indexes,
its constraints and every dependant with it, and nothing in d-MCP undoes it.

Until now `drop` was an ordinary action: a tick in `NewRuleDialog`'s grid, a `can_drop = 1` in
`rules`, and `is_allowed()` answering `True`. The operator's own production database carries rule
id 4, named "Lectura" — *reading* — which grants `create, delete, drop, insert, list,
read_structure, select, update`. Whatever that rule was meant to be, it was not meant to authorise
the destruction of tables, and nothing about ticking eight boxes in a modal made that visible.
**The user has ruled that a box ticked by mistake must not be able to authorise the destruction of
an object.**

**`edit` is the same act under another name, and the inventory proved it.** `edit-function` and
`edit-procedure` ask for the `edit` action and never for `drop` (`mcp_server.py:2217`), but the
script they compose destroys the routine outright:

- Where the engine has no `CREATE OR REPLACE` for routines, `edit_routine()` falls through to
  `_replace_by_drop_and_create()` (`base.py:2399`), whose first steps come from
  `self._drop_script(ref, keyword, if_exists=True)` (`base.py:2421`) — a literal
  `DROP FUNCTION` / `DROP PROCEDURE`. On MySQL, which commits implicitly on DDL, there is no
  transaction around the pair, so the window in which the routine does not exist is real.
- Where the engine *does* have it, the spliced `CREATE OR REPLACE` is emitted as
  `StatementKind.DESTRUCTIVE` (`base.py:2390-2396`) for the honest reason: the previous body is
  gone either way.

So an operator who withheld `drop` and granted `edit` had withheld nothing. Three options were put
to the user and **the strict one was chosen: neither `drop` nor `edit`.**

The consequence is accepted and intended, and it is wider than routines. **No object created
through d-MCP can afterwards be removed or redefined through d-MCP.** A table cannot be dropped; a
view can neither be dropped nor replaced, because `create_view(or_replace=True)` was already
refused at the dialect (`base.py:2243`) and `create-view` refuses a name that is occupied
(`_require_absent`, `mcp_server.py:3416`); a function or procedure is the sharpest case, since it
loses its only replace path as well (`mcp_server.py:2212`). Everything stays readable and listable.
Changing or removing an object is a job for a DBA with a database client, which is the correct
owner of an irreversible act on something shared.

The four `drop-*` and the two `edit-*` MCP tools **stay in the catalogue** and are denied when
called: the user ruled that an audited denial is preferable to a tool that quietly disappears.
`delete` (rows) is explicitly out of scope and is not touched, and neither is `create`.

## Decision

`drop` and `edit` become **categorical prohibitions**: properties of the verb, checked by the
permission resolver itself, which no rule row can influence.

```python
#: Actions no rule may ever authorise, whatever its can_* columns say.
FORBIDDEN_ACTIONS: frozenset[str] = frozenset({"drop", "edit"})
```

A flat set over *verbs*, not a per-object-type tuple beside `ACTIONS_BY_TYPE`: the prohibition is a
property of the operation, not of the thing operated on, and a per-type mapping would be six places
to forget. Everything downstream is derived from the set, never re-listed.

**The reach of each verb was checked against the real tuple, not assumed.** `ACTIONS_BY_TYPE`
(`permissions.py:69-80`) gives:

| Object type | Has `drop` | Has `edit` |
|---|---|---|
| `table` | yes | **no** |
| `view` | yes | **no** |
| `function` (`permissions.py:75`) | yes | yes |
| `procedure` (`permissions.py:76`) | yes | yes |
| `database` | no | no |

`edit` exists on exactly two object types and nowhere else, so the prohibition reaches precisely
what the user meant by "editar funciones y procedimientos" and cannot spill onto a table, a view or
the connection-scoped actions. The pairs the invariant governs are therefore six, and they are
enumerated rather than written down:

```python
[(t, a) for t, acts in ACTIONS_BY_TYPE.items() for a in acts if a in FORBIDDEN_ACTIONS]
# -> (table, drop) (view, drop) (function, drop) (function, edit)
#    (procedure, drop) (procedure, edit)
```

### 1. The choke point

**Enforcement lives in `PermissionStore.is_allowed()` (`permissions.py:1681`) and
`PermissionStore.require()` (`permissions.py:1701`), and nowhere else.** One check covers both
verbs, because both are members of one set.

Every path that can destroy or replace an object passes through one of those two methods:

| Path | Reaches the resolver at |
|---|---|
| `drop-table`, `drop-view` | `mcp_server.py:2056` — `self._require(context, ref, "drop")` |
| `drop-function`, `drop-procedure`, `edit-function`, `edit-procedure` | `mcp_server.py:2217` — `self._require(context, ref, "edit" if action == "edit" else "drop")`; after this ADR **both** branches are forbidden, so the whole non-`create` half of `_routine_ddl()` denies |
| A `DROP` attributed by the guard | `_attribute_drop` (`sql_guard.py:2029`) emits `(ref, "drop")` pairs into a `StatementPlan`, which `_authorised_write` hands to `require_all()` (`mcp_server.py:1528`) — and `require_all()` is a loop over `require()` (`permissions.py:1719`) |
| GUI schema browser, "is this object covered" | `permissions_page.py:783` reads `can_*` columns off `rule_for()` — see §2 below |
| Any future consumer | Cannot decide anything without asking `is_allowed()` or `require()` |

`rule_for()` (`permissions.py:1594`) was considered and rejected as the site. It returns a *row*,
not a decision — the Permissions page and the denial message both need the winning rule regardless
of what it authorises — so making it lie about `can_drop` or `can_edit` would corrupt the two
consumers that legitimately want to see the stored rule. The decision surface is the pair of
methods that answer a yes/no question, and it is small enough to read in one screen.

The site cannot be bypassed because there is no second implementation of the answer: `is_allowed()`
is the only place a `can_*` column is turned into an authorisation, `require()` is the only place a
`PermissionDenied` is raised for a rule reason, and `require_all()` delegates to `require()` rather
than re-deriving anything. A tool that wanted to act without asking would have to compose and
execute DDL with no permission call at all, which is the failure mode
`test_a_new_database_authorises_no_write_at_all` (`tests/test_mcp_server.py:1415`) already exists
to catch.

**Both verbs stay in `ACTIONS_BY_TYPE` (`permissions.py:69`), and this is the load-bearing part of
the decision.** Removing them is the obvious move and it is wrong: `_validate_action()`
(`permissions.py:825`) would then reject `"drop"` as an unknown action for `table` and `"edit"` as
one for `function`, so `mcp_server.py:2056` and `:2217` would raise `ValueError` instead of
`PermissionDenied`, `_decision_for()` (`mcp_server.py:4132`) would file the row as `error` rather
than `denied`, and the six tools the user insisted on keeping would *crash* rather than *deny*. The
whole point of keeping them exposed is that the attempt is audited as a refusal of permission. A
drop and an edit must remain well-formed questions with a permanent answer of "no".

### 2. The `can_drop` / `can_edit` columns and the GUI checkboxes

**Both checkboxes stay visible, are rendered disabled and unticked, and carry a tooltip that says
why.** Not hidden, not left working.

- *Hiding them* makes the prohibition invisible. The six tools are still advertised to every MCP
  client, so an operator reading a denial in the Logs page would go looking for the tick that would
  fix it, find no such tick anywhere, and conclude the Permissions page is broken. A control that
  is absent teaches nothing.
- *Leaving them working* is the defect this ADR exists to remove: a ticked box that authorises
  nothing is a permission GUI showing more access than the system will grant — the same class of
  bug as stage 9's "a failed `grant()` leaving its checkbox ticked".
- *Disabled with an explanation* is the only option where the operator learns the rule at the
  moment they reach for it.

The explanation has to arrive by a route the existing code actually walks.
`_update_action_labels()` (`new_rule_dialog.py:463-473`) builds every tooltip from the dynamic
f-string `f"permissions.action_{action}_tooltip"` and suppresses any key that resolves to itself,
so a new literal key would never be displayed and the disabled boxes would keep showing
`permissions.action_drop_tooltip` ("Drop the object") and `permissions.action_edit_tooltip` — the
very lie this section exists to remove. **Add one branch to `_update_action_labels()` that prefers
`permissions.action_forbidden_tooltip` when `action in FORBIDDEN_ACTIONS`.** One shared key, not
one per verb: the set stays the single source of truth, and an action added to it later inherits
the explanation without a new translation entry. Its `en-US` text must read correctly for both
verbs — *"Never granted. d-MCP cannot destroy an object or replace a routine body, whatever a rule
says."* Because the key is named literally in that branch,
`test_no_new_translation_key_is_unreachable_from_any_module` (`tests/test_i18n_catalogue.py:389`)
is satisfied; a key reached only through the f-string would fail it.

**One risk for UIX to settle before implementing:** Qt does not deliver mouse events to a disabled
widget, and a tooltip set on a disabled `QCheckBox` is not reliably shown across platforms. If it
is not shown, the explanation is invisible and the control is merely mysterious. Verify it on
Windows and Linux; if it does not appear, put the tooltip on the enclosing grid container, or
append a short translated marker to the checkbox's own label. The requirement is that the
explanation is *readable*, not that it is a tooltip.

`can_drop` and `can_edit` stay as columns. `ALL_ACTIONS` generates them, `_migrate_schema()`
(`permissions.py:1071`) only ever adds columns and deliberately never removes them
(DESIGN-DATA-MODEL.md §4.5), and they are where the migration in §3 writes its zeroes.

Two reads of those columns elsewhere must stop counting forbidden actions:

- `format_rule()` (`permissions.py:893`) builds `allowed_actions`, which is what `show-permissions`
  (`mcp_server.py:2352`) and `main.py --show-permissions` (`main.py:133`) report. It must exclude
  `FORBIDDEN_ACTIONS`, or the server will tell an LLM it may drop or replace something it may not.
- `_object_covered()` (`permissions_page.py:783`) answers "is this object reachable at all" with
  `any(can_{action})`. A rule granting only `drop` and `edit` would show a routine unlocked while
  granting nothing. It must exclude `FORBIDDEN_ACTIONS` from the `any()`.
- **And so must its mock twin.** `_sample_object_is_covered()` (`permissions_page.py:146`, ending
  in `any(best_rule["actions"].values())` at `:181`) is the sample-data counterpart, and the
  docstring at `:235` promises in terms that the two "can never disagree about what". Fix only the
  real one and the padlocks on the sample tree contradict the padlocks on the live tree, on a page
  whose sample mode is a shipped Settings toggle. The fixture itself is already clean — checked:
  no rule in `SAMPLE_PERMISSION_RULES` (`gui/pages/_sample_data.py:104-153`) grants `drop` or
  `edit` — so nothing there needs changing, and nothing there demonstrates a grant the product now
  refuses.

### 3. Existing rows with `can_drop = 1` or `can_edit = 1`

**Migrate them to 0, at `permissions.db` schema version 3 → 4 — and understand that this is
hygiene, not enforcement.**

`is_allowed()` already makes a hand-edited `can_drop = 1` or `can_edit = 1` inert, so the migration
adds no safety. What it buys is that the database stops saying something untrue. Three consumers
read the columns directly rather than through `is_allowed()` (`format_rule`, `_object_covered`, and
the `NewRuleDialog` pre-tick at `new_rule_dialog.py:403`), and so will the next person who opens
`permissions.db` in a SQLite browser to answer "what was this rule allowed to do". A column named
`can_drop` holding `1` in a system where dropping is impossible is a lie that outlives the code
that ignores it.

Leaving the rows alone was the alternative. It was rejected because the operator's next interaction
with rule 4 is the surprising one either way — the tick vanishes from the modal whatever we do —
and only the migration leaves a written account of why, in the `permissions.db.v3.backup.log` the
house convention already produces (`db_migrations.backup_before_rebuild`).

Constraints on the step:

- `UPDATE rules SET can_drop = 0, can_edit = 0 WHERE can_drop = 1 OR can_edit = 1`, not a rebuild.
  There is no constraint to add and no column to remove, so this is `_migrate_2_to_3`'s cheap
  shape, not `_migrate_1_to_2`'s twelve-step one. The statement is best generated from
  `FORBIDDEN_ACTIONS` rather than typed, so a third member is migrated on the day it is added.
- **`created_at`, `user_created`, `updated_at` and `user_updated` are not touched.**
  `_migrate_1_to_2` carried all four verbatim; no human edited these rules, and writing
  `current_user()` into `user_updated` would put a person's name against a change they did not
  make.
- The `MigrationRecord` must list, by id and `rule_name`, **every rule whose entire granted set was
  forbidden** — not only the `drop`-only ones. With `edit` in the set, a routine rule granting
  `edit, drop` and nothing else empties out completely; one granting
  `list, read_definition, edit` does **not** — it keeps `list` and `read_definition` and is merely
  narrower than its author meant, which is why the criterion is "the whole granted set was
  forbidden" and not "any granted action was". A rule left granting nothing is legal
  (`_validate_actions` permits an empty allow set) but useless, and it is configuration a human
  wrote. **List them; do not delete them.** Automatically removing an operator's rules would itself
  be a drop.
- Rule 4 is *not* one of them, and the record should make that visible rather than leave the
  operator guessing: it is a `table` rule, so it loses `drop` and keeps
  `create, delete, insert, list, read_structure, select, update`.
- The version bump is one-way: a version 4 file opened by an older build raises the "written by a
  newer version" `RuntimeError` in `PermissionStore._migrate()` (`permissions.py:1051`). That is
  correct — the older build would honour both columns — but it must be in the changelog.

On **write**, `_validate_actions()` (`permissions.py:1829`) **silently drops** `FORBIDDEN_ACTIONS`
from an allow set and logs at INFO which rule and which action, rather than raising `ValueError`.
Rejecting is tempting and costs more than it is worth: `_grant_everything_write`
(`tests/test_mcp_server.py:245-249`) passes both `"drop"` and `"edit"` in its four lists, and any
operator script doing the same would start raising with the failure landing far from the cause. The
project has the precedent in `_database_scope_patterns()` (`permissions.py:950`), which rewrites a
caller's patterns for exactly this reason — any other value is meaningless rather than merely
unusual — and documents the rewrite in place. `actions == "all"` expands from `ACTIONS_BY_TYPE` and
is filtered by the same pass, so `grant(..., "all")` stops meaning "including drop and edit".

### 4. The denial message and the audit row

A new exception, `ActionForbidden(PermissionDenied)`, raised by `require()`. Subclassing is what
keeps every existing `except PermissionDenied` handler fail-closed while letting the audit layer
and the tests tell the two apart — the same shape as `ConfirmationRefused` being a
`PermissionError`. **It serves both verbs unchanged**: nothing about it is `drop`-specific, the
discriminator is the action already carried in the message.

The message keeps `_denial_message()`'s existing grammar so operator greps and the Logs page read
alike, and replaces the parenthetical, which is the part that tells the operator what to do next.
The reason clause is looked up per verb, so the sentence is true rather than generic:

```python
_FORBIDDEN_REASON: dict[str, str] = {
    "drop": "destroying an object is never granted",
    "edit": "replacing a routine body destroys the previous one, so it is never granted",
}
```

Giving, exactly:

```
'drop' is not permitted on public.wc2026_match (forbidden by d-MCP: destroying an object is never granted; no permission rule can authorise it)
'edit' is not permitted on public.add (forbidden by d-MCP: replacing a routine body destroys the previous one, so it is never granted; no permission rule can authorise it)
```

Three properties the wording must keep:

1. **The substring `no rule` does not appear.** That phrase is default-deny's, it means "write a
   rule and this will work", and here it never will. `no permission rule can authorise it` says the
   opposite and does not contain it.
2. **The prefix `'{action}' is not permitted on {qualified}` is preserved**, because
   `test_nothing_is_dropped_without_the_drop_permission_however_precise_the_signature`
   (`tests/test_mcp_server.py:2698`) asserts exactly that substring and should keep passing.
3. **`_FORBIDDEN_REASON` must cover `FORBIDDEN_ACTIONS` exactly.** Pin it with a set-equality
   assertion, not with a `.get(action, "")` default: the lesson of stage 9's `Operator` defect is
   that a member added and forgotten must fail at the table check, not at the first caller — and
   here the first caller is a denial message an operator reads under pressure.

`require()` must **not** hoist the prohibition above the `is_allowed()` call. The call to
`is_allowed()` is what validates — `_validate_ref` then `_validate_action` — so it is the only
reason `require(conn_id, ref, "edit")` with a malformed `ref`, or against a `table` (whose tuple
has no `edit`), still raises the `ValueError` DESIGN-PERMISSIONS.md §5.4 promises rather than
answering with a prohibition message. The `FORBIDDEN_ACTIONS` branch sits *after* it because by
then `is_allowed()` has already returned `False`:

```python
def require(self, connection_id, ref, action) -> None:
    if self.is_allowed(connection_id, ref, action):   # validates ref, then action
        return
    if action in FORBIDDEN_ACTIONS:
        raise ActionForbidden(_forbidden_message(action, ref))
    rule = self.rule_for(connection_id, ref)
    raise PermissionDenied(_denial_message(action, ref, rule))
```

`rule_for()` is never reached on the forbidden path, so no rule can be cited by accident.

**Audit (`audit.db`, `tool_calls`): `decision = 'denied'`, `matched_rule_id = NULL`**, for both
verbs.

- `denied`, not `refused`. `_decision_for()`'s own comment sets the boundary: `refused` is "d-MCP
  declined before any rule was consulted" (the guard, the human, a name the catalogue does not
  hold); `denied` is "the permission layer said no". The prohibition is raised by
  `PermissionStore.require()` — the permission layer — and its exact precedent is default-deny,
  which is already `denied` with a null rule. Widening `ck_tool_calls_decision`
  (`log_store.py:141`) to a fifth value was rejected: it would need a rebuild of `audit.db` and
  would break the Logs page's filter for every historical row.
- `matched_rule_id = NULL`, because no rule decided. This falls out for free — `_decision_for()`
  (`mcp_server.py:4132`) needs **no change at all**: `ActionForbidden` matches its
  `isinstance(exc, PermissionError)` branch and `getattr(exc, "matched_rule_id", None)` returns
  `None`.
- **Two lines in `mcp_server.py` must change, and only two, for both verbs together.** `_require()`
  (`mcp_server.py:1035-1038`) and `_require_all()` (`mcp_server.py:1069-1076`) both *tag* a caught
  `PermissionDenied` with `self._rule_id(context, ref)`. Left alone they would attach rule id 4 to
  a denial rule 4 did not make, and the Logs page would link the operator straight to a rule that
  has nothing to do with it. Both must skip the tagging when the exception is an `ActionForbidden`
  — a type test, so it covers `edit` on the day `edit` joins the set without a second edit. In
  `_require_all()` the skip is defensive today — no tool feeds `DROP` text to `require_write()`,
  whose only caller composes DML — and becomes load-bearing the moment a DDL-by-text path exists.

That two-line delta across a 4 300-line server is the evidence that the choke point is real.

### 5. What the invariant requires of QA

1. **The pinning test must bypass the store's own writer.** If §3's normalisation is in place,
   `create_rule(..., ["drop"])` followed by `assert is_allowed(...) is False` **passes even if
   `is_allowed()` has no invariant check at all** — it is testing the write path, not the resolver.
   The test must set `can_drop = 1` / `can_edit = 1` with a raw `UPDATE` on the store's open
   connection, then assert `is_allowed()` is `False` and that `require()` raises `ActionForbidden`.
   This is the third instance of the lesson stage 9 paid for twice (the unreached `Operator`
   branch, the three `pytest.raises(match=...)` patterns that matched for the wrong reason): *a
   test that passes is not the same as a test that checks*.
2. **Parametrised over the six `(object_type, action)` pairs**, enumerated from the comprehension
   in *Decision* rather than from a literal list, so a type or a verb that joins the prohibition is
   covered on the day it does.
3. The complement is tested too: `create`, `select`, `insert`, `update`, `delete`,
   `read_definition` and the seven `database` actions remain grantable. The prohibition must not
   leak, and `edit` in particular must not be readable as "no DDL at all" —
   `create-function` still works on an absent routine.
4. A rule with `is_deny = 0` and `can_drop = 1` / `can_edit = 1` at *maximum* specificity (exact
   schema, exact name) still denies: specificity must not be able to out-rank the invariant.
5. Each of the six tools — four `drop-*`, two `edit-*` — called end to end, raises
   `ActionForbidden`, writes `decision = 'denied'` with `matched_rule_id IS NULL`, and **executes
   nothing**: assert the recording connection saw no statement, that the catalogue was never asked
   for an overload, and — the one specific to `edit` — that
   `introspector.definition_of()` was never called, because the previous definition is read at
   `mcp_server.py:2224`, *after* the permission gate, and reading it would mean the gate had been
   passed.
6. The denial message for each verb does not contain `no rule`, contains `forbidden by d-MCP`, and
   names its own reason; and `set(_FORBIDDEN_REASON) == FORBIDDEN_ACTIONS`.
7. `format_rule()` never lists `drop` or `edit` in `allowed_actions`, even for a row carrying the
   columns set; `show-permissions` and `main.py --show-permissions` inherit this.
8. All six tool names are still in `tools/list` — `tests/test_mcp_server.py:415-421` and
   `tests/test_generated_config.py:84,102-109` already pin this and now pin the user's ruling that
   the tools stay exposed.
9. The `drop` and `edit` checkboxes are present, disabled and unticked for every object type that
   has them, and the explanation is *visible* (see §2's Qt caveat), not merely set.
10. Migration: a version 3 fixture with `can_drop = 1` and one with `can_edit = 1` open as version
    4 with both zero, the four audit columns unchanged, and a rule whose whole granted set was
    forbidden still present and named in the `MigrationRecord`.

## Consequences and risks

**Tests that break and must be retargeted, not deleted.** The `edit` half of this ADR adds almost
nothing to the list, and that was checked rather than assumed: a grep for `tool("edit-` across
`tests/` returns **nothing** — no test has ever driven `edit-function` or `edit-procedure` through
the tool registry. Everything below is the `drop` half, plus one retarget the `edit` ruling
invalidates.

- `tests/test_mcp_server.py:1472`,
  `test_a_broker_with_no_gui_subscribed_refuses_exactly_as_no_broker_does`, drives `drop-table` and
  asserts `ConfirmationRefused(reason="no_subscriber")` with `decision == "refused"`.
  `ActionForbidden` now raises before `_confirm` is reached. An earlier draft of this ADR sent it
  to `edit-function`; that is no longer available. **Retarget it to `delete-rows`** — the same tool
  its sibling `test_a_destructive_tool_with_no_subscriber_is_refused_and_audited_as_refused`
  (`tests/test_mcp_server.py:1444`) uses. Sharing the tool is not duplication here, it is the
  correct experiment: the two tests differ *only* in whether a broker object exists, which is
  exactly the distinction the second one's name claims to isolate, and holding the tool constant is
  what isolates it. After this ADR the reachable `BROKERED` set is `delete-rows`,
  `remove-user-from-group` and `revoke-role`; the two security tools would drag a `SecurityManager`
  into a test about the broker.
- Six overload tests, `tests/test_mcp_server.py:2570`, `:2585`, `:2601`, `:2625`, `:2652`, `:2675`,
  reach `_resolve_overload()` through `drop-function` with `granted=True`. The permission check at
  `mcp_server.py:2217` runs *before* resolution, so all six now get `ActionForbidden`. Only the
  `drop-*` tools carry a `signature` parameter (`tests/test_mcp_server.py:2567`), so there is no
  other tool to retarget them to: they must call `state.server._resolve_overload(...)` directly.
  The behaviour they pin — refusing an ambiguous overload rather than choosing one — is still worth
  pinning, because the resolver is still reachable code and the tools are still advertised.
- `tests/test_mcp_server.py:1410-1412`'s parametrised `("drop-table", ...)` and `("drop-view", ...)`
  cases still pass unchanged, and were checked rather than assumed: the body
  (`test_a_new_database_authorises_no_write_at_all`, `:1415`) asserts `PermissionDenied`, an
  unchanged row count and `decision == "denied"`, and never greps the denial wording. Like `:2698`
  below, the two cases stop proving default-deny and start proving the invariant.
- `tests/test_mcp_server.py:2698` keeps passing, and **stops proving what its name says**: with the
  invariant in place it would pass even under a grant. QA should add the `granted=True` companion
  rather than assume it is still covering the ordering of the two gates.
- `tests/test_write_composition.py:823` pins the dialect's refusal of
  `create_routine(or_replace=True)` with `match=r"edit-function|approval"`. The message it matches
  must be rewritten (see below) and the alternation will keep the test green on its `approval`
  branch whatever happens to the tool name — which is the pattern stage 9 already had to fix three
  times. **Narrow it to the new wording** rather than let it pass on a branch that no longer means
  anything.

**Tests that are unaffected, and should not be touched.** All of `tests/test_confirmation.py`
(78-364) and `tests/test_gui_confirmation_dialog.py` pass the literal string `"drop-table"` to
`ConfirmationBroker` and never reach `PermissionStore`. `tests/test_sql_guard.py` mentions neither
`PermissionStore`, `is_allowed` nor `require` anywhere — checked — so its `DROP` attribution tests
keep passing: the guard still models the statement and still emits a `drop` action, because the
guard's job is to say what a statement does, not whether it may.
`tests/test_write_composition.py:956,974,1040` exercise `Dialect.edit_routine()` directly, below
the permission layer, and stay: the composition is still worth pinning for the same reason the
builders stay (below).

**Two error texts now point at tools that can never run, and must be rewritten.** Both were written
when the advice was good and are now a dead end handed to a model:

- `base.py:2247` — `create_view(or_replace=True)` refuses with *"Use drop-view, which asks for
  approval in the d-MCP window, and then create-view."* `drop-view` will deny.
- `base.py:2350` — `create_routine(or_replace=True)` refuses with *"replacing a body destroys the
  old one, which is edit-function/edit-procedure and asks for approval in the d-MCP window."*
  `edit-function` will deny.

Both should now say plainly that d-MCP cannot replace an existing object at all, and that the
replacement is a job for a database client. The same correction is due in two comments:
`mysql.py:1240` ("which is `edit-function` by another name") and `sqlite.py:145` ("is told to use
drop-view and create-view").

**Code that becomes unreachable at runtime but stays.** `_impact()`'s `drop-table` branch
(`mcp_server.py:1807`) and the dependant-view scan behind it; `_resolve_overload()`; the dialects'
`drop_table`, `drop_view`, `drop_routine`, `edit_routine` and `_replace_by_drop_and_create`,
including its `previous_definition` rollback and the
`confirmation.warning_non_atomic_routine_replace` warning key; the `definition_of()` call at
`mcp_server.py:2224` (the function itself keeps five other callers and stays fully live); and
`_ddl_summary`'s `"drop"` and `"edit"` verbs (`mcp_server.py:4274`). All are kept: the tools are
still advertised, the code is still directly tested, and deleting the builders would be a second,
larger change smuggled in behind a permission ruling. They should be marked in their docstrings as
reachable only by test while ADR 0005 stands. `edit-function`, `edit-procedure` and the four
`drop-*` also stay in `BROKERED` (`mcp_server.py:289`) although the broker is never reached —
removing them would be the first edit anyone makes if this ADR is ever revisited, and it should not
have to be rediscovered.

**The functional loss, stated plainly — and it is not only routines.** Every object d-MCP can
create is create-once:

| Object | What is lost |
|---|---|
| Table | Cannot be dropped. A `create-table` with the wrong columns is permanent. |
| View | Cannot be dropped *or* replaced — redefining a view is its normal lifecycle, and `create_view(or_replace=True)` was already refused at `base.py:2243` while `create-view` refuses an occupied name (`mcp_server.py:3416`). |
| Function, procedure | The worst case: no drop, and no replace path at all, since `edit-*` was the replace path. |

A model that writes a function with a bug cannot fix it and cannot remove it and start again;
`create-function` will refuse the name as occupied (`_require_absent`, `mcp_server.py:2212`). The
recovery is always a DBA with a database client. This is the cost the user accepted in exchange for
the guarantee, and it belongs in `README.md` under *Known limitations*, stated for all four object
types, rather than being discovered from an error message.

**The deeper risk this does not remove.** A connection whose database credentials hold `DROP`
privilege is still one bad statement away from losing an object by some route other than d-MCP.
This ADR closes d-MCP's own path; it is not a substitute for a least-privilege database login, and
`DISCLAIMER.md` should not be read as promising otherwise.

**Scope, restated.** `delete` (rows) is untouched, still grantable, still brokered — deleting rows
from a table that survives is not the destruction of an object. `create` is untouched on every
object type. `drop` and `edit` are the whole of the prohibition; if a third verb ever joins it, it
is one more member of `FORBIDDEN_ACTIONS` and one more entry in `_FORBIDDEN_REASON`, which is the
point of the set.

## Implementation checklist

| # | File | Change |
|---|---|---|
| 1 | `permissions.py` (beside `ACTIONS_BY_TYPE`, :69) | Add `FORBIDDEN_ACTIONS = frozenset({"drop", "edit"})`, `_FORBIDDEN_REASON` and `ActionForbidden(PermissionDenied)`; document why both verbs stay in the tuple |
| 2 | `permissions.py:851` | Add `_forbidden_message()` beside `_denial_message()`, same grammar, per-verb reason, no `no rule` |
| 3 | `permissions.py:1681` | `is_allowed()` returns `False` for a forbidden action **after** `_validate_ref` and `_validate_action` |
| 4 | `permissions.py:1701` | `require()` per §4's ordering; never calls `rule_for()` on the forbidden path |
| 5 | `permissions.py:893` | `format_rule()` excludes `FORBIDDEN_ACTIONS` from `allowed_actions` |
| 6 | `permissions.py:1829` | `_validate_actions()` filters forbidden actions from an allow set, logs at INFO |
| 7 | `permissions.py:106,652` | `SCHEMA_VERSION = 4`; `_migrate_3_to_4` in `_MIGRATIONS`, zeroing every `can_<forbidden>` column generated from the set, with `MigrationRecord` and backup |
| 8 | `mcp_server.py:1035-1038`, `:1069-1076` | Do not tag an `ActionForbidden` with a `matched_rule_id` |
| 9 | `new_rule_dialog.py:442`, `:463` | Render both forbidden checkboxes disabled and unticked; `_update_action_labels()` prefers `permissions.action_forbidden_tooltip` when `action in FORBIDDEN_ACTIONS`; confirm the text is visible on a disabled widget |
| 10 | `permissions_page.py:783` and `:146` | `_object_covered()` **and** its mock twin `_sample_object_is_covered()` both exclude `FORBIDDEN_ACTIONS` from their `any()`; the docstring at `:235` promises they agree |
| 11 | `db/dialects/base.py:2247`, `:2350` | Rewrite both refusal texts: d-MCP cannot replace an existing object; no tool to redirect to. Comments at `mysql.py:1240`, `sqlite.py:145` likewise |
| 12 | `db/dialects/*`, `mcp_server.py:1807`, `:2224`, `:4274` | Docstring note: reachable by test only while this ADR stands |
| 13 | `tools/generate_translations.py` → `gui/i18n/translations.py` | New key `permissions.action_forbidden_tooltip`, named literally by row 9 so `test_no_new_translation_key_is_unreachable_from_any_module` passes; authored in `en-US` and `es-ES`, seeded English elsewhere; generated, never hand-edited |
| 14 | `CHANGELOG.md`, `README.md`, `DISCLAIMER.md` | The ruling; that **every** object is create-once through d-MCP — a table cannot be dropped, a view cannot be dropped or replaced, a routine neither (*Known limitations*); and that a version 4 `permissions.db` will not open on an older build |
