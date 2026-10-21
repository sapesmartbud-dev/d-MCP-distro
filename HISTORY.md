# Development history

This file records how SAPÉ d-MCP was built, stage by stage, as `DEVELOPMENT-PLAN.md` defines
the stages, up to and including version `0.1.0.8`. It is a closed record and is not updated any
more. Changes from `0.1.0.9` onwards are in [`CHANGELOG.md`](CHANGELOG.md).

This file does not assign dates to work it cannot date. `DEVELOPMENT-PLAN.md` records what each
stage delivered, not when; where you see no date below, none is claimed.

## [0.1.0.8] — 2026-09-14 (Beta, released)

This entry covers everything built in stages 0 through 9, all of which are complete. 0.1.0.8 was
the first release, so there is nothing to compare it against — this entry is the project's
history up to that release, not a diff against a previous tag. At release time no build had been
run on Windows or macOS.

This is a **Beta** release: the permission model and the tool
catalogue are considered final, but only SQLite has been exercised against a real database on
the development machine — MS-SQL, PostgreSQL and MySQL are covered by unit tests over each
dialect's composed SQL and by proving their drivers import, with twenty-nine integration tests
skipping for want of a live server — and the frozen PyInstaller bundle has been smoke-tested on
Linux only. Beta does not mean provisional permission semantics; it means the coverage above has
not yet been closed. Point it at a database holding data you cannot afford to lose only once you
have read [Known limitations](README.md#known-limitations) and are satisfied with what has and
has not been exercised.

### `drop` and `edit` can never be granted, whatever a rule says (`permissions.db` schema version 4)

Until now `drop` and `edit` were ordinary actions: a tick in `NewRuleDialog`'s grid, a
`can_drop`/`can_edit` column, and `is_allowed()` answering `True` if a rule granted them. The
operator's own production database carried rule id 4, named "Lectura" — *reading* — granting
`create, delete, drop, insert, list, read_structure, select, update`; nothing about ticking eight
boxes in a modal made it visible that one of those ticks authorised destroying a table. **You have
ruled that a box ticked by mistake must not be able to authorise the destruction of an object**,
and that replacing a function or procedure's body is the same act under another name, since the
only way d-MCP had of doing it was dropping the old routine and creating a new one in its place.

`drop` and `edit` are now checked in the permission resolver itself — `FORBIDDEN_ACTIONS`,
enforced in `PermissionStore.is_allowed()` and `.require()` — and no rule, at any specificity, can
turn either one on. The six tools that ask for them, `drop-table`, `drop-view`, `drop-function`,
`drop-procedure`, `edit-function` and `edit-procedure`, stay in the catalogue and stay callable —
on your ruling that an audited denial is preferable to a tool that quietly disappears — but every
call is now refused before it ever reaches the confirmation dialog. `delete` (removing rows from a
table that still exists) is untouched and still works exactly as before, brokered on its own
approval; it is a different act from `drop` and nothing here changes it.

**The consequence is wider than routines, and is now permanent: every object d-MCP creates is
create-once.** A table cannot be dropped. A view can neither be dropped nor replaced. A function
or a stored procedure can neither be dropped nor have its body replaced. Fixing or removing any of
the four is a job for a database client connecting directly to the server, not for d-MCP.

Both checkboxes stay visible on the New rule dialog, rendered disabled and unticked, with a
tooltip explaining why — hiding them would make the prohibition invisible while the six tools are
still advertised to every MCP client.

**The six tools' own descriptions, and the instructions string served at `initialize`, now say
"not available" rather than "needs approval".** Both used to tell an MCP client that a human would
approve the call in the d-MCP window; that stopped being true the moment `drop`/`edit` became
unconditional, and a model told to wait for an approval that is never requested would simply
stall. Each of the six now opens with "Not available: d-MCP never …", names `docs/adr/0005` and
says plainly that no permission rule and no approval can change the answer.

**The migration this brings (`permissions.db` schema version 3 → 4) has already been run against
the operator's own database**, with the usual backup at `permissions.db.v3.backup`. Every row with
`can_drop = 1` or `can_edit = 1` had that column zeroed; rule 4, "Lectura", lost only `drop` and
kept `create, delete, insert, list, read_structure, select, update` — it did not empty out, because
`drop` was not its only granted action. No rule was deleted; a rule whose entire granted set turned
out to be forbidden is left in place, granting nothing, rather than removed on the operator's
behalf.

**The version bump is one-way.** A `permissions.db` at schema version 4 will not open in a build
that still expects version 3 — the older build would honour `can_drop`/`can_edit` as real grants,
so it refuses to open the file rather than silently reintroducing the two actions. Anyone deploying
this build, or rolling back to an earlier one, needs to know which schema version the database
file in use is at.

Recorded in `docs/adr/0005-drop-and-edit-are-never-granted.md`, which supersedes part of
DESIGN-PERMISSIONS.md §3 and DESIGN-MCP-TOOLS.md §8.1.

### The header now reads "d-MCP (Data MCP)"

The GUI header's title label read "SAPÉ d-MCP" in every locale. `header.product_name` now
carries "d-MCP (Data MCP)" in all eighteen locales instead — still a brand rather than a
sentence, so still identical across languages, generated the same way as before from a single
authored en-US/es-ES pair in `tools/generate_translations.py`. Nothing else moved: the window
title (`window.title`), the GPL file-header comment, and the `application_name` sent to the
database drivers are separate keys and separate concerns and were left as they were.

### A permission rule can be given a name (`permissions.db` schema version 3)

The Permissions page listed a rule as an object type, some patterns and an effect, and nothing
on the row said what the rule was *for*. Two broad `dbo`/`rpt_*` rules written a month apart are
indistinguishable in that list, and the operator who wrote them is the person who has to tell
them apart. A rule now carries `rule_name`: the operator's own label, shown in the list, returned
by `rules()` and `rule_for()`, and rendered by `format_rule()` — so `show-permissions` and
`--show-permissions` say it too. The MCP tool's declared response shape in
`docs/DESIGN-MCP-TOOLS.md` §11.1 gained `rule_name` with it, and the tool's own description now
tells the model the label is there: a rule's patterns say what it matches, and only its name says
what it is *for*. The key is always present and holds `null` for an unnamed rule, so every row of
the returned array carries the same keys; `--show-permissions`, which is human text rather than
JSON, prints nothing at all for one instead.

**It is metadata and only metadata.** Nothing in `rule_for()`, `is_allowed()` or `require()`
reads it; it appears in no ordering key and in no `WHERE` clause of the resolver. A rule
authorises exactly what it authorised before it was named, which is what makes a label safe to
edit — and `test_naming_a_rule_cannot_change_a_permission_decision` pins it, because a field
added to a security store has to prove that rather than assert it.

**Optional, so nothing was backfilled.** Every rule written before version 3 has no name until a
human gives it one. That was the decision that let the upgrade be a single
`ALTER TABLE rules ADD COLUMN` with no table rebuild: the column is nullable, so every existing
row is already a valid version 3 row the moment it exists — there is no value to compute and no
row to rewrite. The alternative, a `NOT NULL` column, could only have been satisfied by inventing
a name for each of them, which is to say by writing text into the operator's own rules list that
the operator never wrote.

**One spelling of "no name", and it is `NULL`.** `None` and `''` both store `NULL`; anything else
is stored stripped, and it is the stripped text the length is measured against and the uniqueness
compares — `'  Reporting  '` and `'Reporting'` render identically in a table cell, and stored
verbatim they would be two rules the operator cannot tell apart and the database thinks are
different. A string that is *not* empty but strips to empty — `'   '` — is refused rather than
folded: it is a name that was typed, and watching it vanish is the silent normalisation this
module refuses everywhere else. Over 80 characters (`MAX_RULE_NAME_LENGTH`, interpolated into the
schema's `CHECK`, the Python check and its message so the three cannot disagree), or carrying a
control character, is likewise a `ValueError` in the store's usual voice, which `NewRuleDialog`
already puts straight into a message box.

**Unique per connection, in the schema and not only in Python.** A partial unique index,
`uq_rules_name_per_connection ON rules(connection_id, rule_name COLLATE NOCASE) WHERE rule_name
IS NOT NULL`, following the `database`-rule index already in the file. Partial because "unique"
here must mean "no two rules on one connection carry the same name", never "at most one rule may
be unnamed" — SQLite counts NULLs as distinct in a UNIQUE index, so a plain index would allow any
number of unnamed rules, but only by accident of NULL semantics, and the first person to
normalise a blank name to `''` would silently turn it into one unnamed rule per connection.
Case-folded, following `connections.display_name`: `Reporting` and `REPORTING` in one list tell
an operator nothing apart. The known limit is recorded beside the index rather than left to be
discovered — SQLite's `NOCASE` folds ASCII only, so `CAFÉ` and `café` would not collide, which is
a permissive failure on a field no permission decision reads. A duplicate raises `ValueError`
naming the rule that already holds it, and quoting *that* rule's spelling rather than the one just
typed, since `SALES` colliding with `Sales` is exactly the case the message has to explain.

**`grant()` and `deny()` carry an existing rule's name across untouched**, which is the one place
the wholesale discipline of `update_rule()` is deliberately not applied: they upsert an action
set, not a whole rule, and the Permissions page's Database-and-security section calls them from a
checkbox with no name in its hand. `update_rule()` itself takes the name the rule carries *after*
the call — omitting it leaves the rule unnamed, exactly as omitting an action leaves it ungranted
— so an edit dialog must put the current name back.

**The upgrade takes its backup all the same.** `permissions.db.v2.backup` and its
`.log` record are written through the same `db_migrations.backup_before_rebuild()` every other
step uses, even though this one rewrites nothing: a cheap upgrade that skipped its own account
because it judged itself safe is exactly the one nobody can check afterwards. The unique index is
created *inside* the step, before `PRAGMA user_version = 3` is committed, so a file can never sit
at version 3 carrying the column without the guarantee that gives it meaning. And the step keys
its idempotence on the column rather than the version, because a file coming up from version 1 is
rebuilt by the 1→2 step from the *current* DDL and therefore already has `rule_name` — so that
file takes one backup, not two.

DESIGN-DATA-MODEL.md §4.2, §4.3, §4.5 and §6 and DESIGN-PERMISSIONS.md §9, §9.2 and §10 re-issued
to match.

### A permission rule now covers a collection of objects (`permissions.db` schema version 2)

A rule was keyed by exactly one `(connection_id, schema_pattern, object_type, name_pattern)`
tuple, so it reached several objects only when they shared a name prefix. For an arbitrary
set — `Customers`, `Invoices`, `Payments` — there was no expression at all: three rules, and
three action sets to keep in step by hand. Two further defects came from the same key, and both
were felt as defects rather than as design. **A rule's reach could not be edited**: `grant()`
upserted on the key, so `NewRuleDialog` froze schema, type and name on an existing rule, and a
rule that reached one table too few had to be deleted and rewritten. And **the schema browser
selected one leaf at a time**, because one leaf was all a rule could take.

A rule's targets now live in a `rule_targets` child table. One rule carries one object type, one
allow-or-deny, one action set, and one or more `(schema_pattern, name_pattern)` targets. Ctrl- or
shift-click several tables in the tree, tick the actions once, and you get one rule; reopen it
later and add or remove objects. One object type per rule, because action sets genuinely differ
per type; per connection only, matching the rule that each database carries its own separate
permission assignment. The pattern grammar is untouched — a target is still an exact literal, a
`prefix*`, or a bare `*`.

**The ordering proof moves with the constraint rather than being weakened.** What was
`uq_rules_key` is now `uq_rule_targets_key`, the same four columns one table lower, and
DESIGN-PERMISSIONS.md §2.4's argument carries over verbatim: two matching targets can score equal
only if their patterns are identical, which the constraint forbids, and a target has exactly one
rule. It is in fact stronger — `is_deny` had to be excluded from the version 1 key by hand so an
allow row and a deny row could not coexist on it; a target carries no decision, so that
contradiction is now unrepresentable. `rule_id` is deliberately *not* in the key: scoping the
uniqueness per rule reads as the more natural constraint and is what a later maintainer would
"correct" it to, and it would let two rules own one target and let the ordering tie for real,
silently. Within a single rule several targets may match one object, and the narrowest wins.

Four things the new shape needs, each of which would have failed quietly:

- **`NOT NULL` on every column of `rule_targets`.** SQLite counts NULLs as distinct in a UNIQUE
  index, a CHECK that evaluates to NULL *passes* — `instr(NULL,'*') IN (0, length(NULL))` is NULL,
  not 0 — and a composite foreign key whose child carries a NULL is satisfied vacuously. One
  nullable column would have switched off the uniqueness, the pattern grammar and the parent check
  at once.
- **A partial unique index on `database` rules.** "At most one per connection" *is* the meaning of
  that object type. Version 1 got it free from `uq_rules_key` plus the forced `'*'/'*'`; with the
  patterns gone from `rules` there was nothing left to stop a second one, and the resolver would
  have picked between two by storage order.
- **The resolver's join repeats `connection_id` and `object_type` on both sides**, so a target that
  drifted while `PRAGMA foreign_keys` was off is inert rather than authoritative — and
  `_apply_pragmas()` now *verifies* that pragma took, the way it already verified WAL. A SQLite
  built without foreign key support accepts the statement, sets nothing, and reports `0`; harmless
  while this file had no foreign key, and not harmless now.
- **An explicit projection, never `SELECT r.*, t.*`.** `id` would appear twice, `sqlite3.Row`
  keeps the last, and `mcp_server._rule_id()` would have written a *target* id into
  `audit.matched_rule_id` — pointing every historical denial in the Logs page at the wrong rule,
  with nothing anywhere failing to say so.

**`grant()` and `revoke()` refuse a target whose rule names other objects.** They still exist with
their old signatures, and still do the version 1 upsert on a single-target rule, which is what the
Database-and-security section speaks. Mutating the siblings would give the call a blast radius
wider than its own arguments — `grant(..., "Customers", ["drop"])` against a rule that also targets
`dbo`/`*` hands `drop` to every table in the schema — and silently splitting the target out into
its own rule fails the other way and more quietly, leaving the operator's next tightening of that
rule with a hole they believe they closed. Callers that mean to change a collection say so, through
`update_rule()`.

**The upgrade runs on first open and transfers every permission verbatim** — each version 1 row
becomes one rule with one target holding the same two patterns, so no rule's reach changes by a
single object. It takes a `VACUUM INTO` backup first and unconditionally, writes a record beside
it, and `PRAGMA foreign_key_check` afterwards is a real proof here rather than the formality it is
in `connections.db`. `rules.id` is carried across explicitly, because `audit.db`'s
`matched_rule_id` is a logical foreign key to it and a renumbered rule would silently re-point
every historical denial; `DROP` precedes `RENAME` so the `AUTOINCREMENT` high-water mark survives;
and a `can_*` column for an action since withdrawn is carried over rather than dropped, as §4.5
promises. The migration chain now runs *before* `executescript(SCHEMA)`, unlike
`connection_store`'s, because version 2's second table declares a foreign key against a `rules`
that the rebuild has yet to create.

Two visible shape changes come with it. **`show-permissions` returns `targets`** in place of the
two scalar keys, with no single-target alias beside it: a scalar holding "the first target" is a
half-truth about a rule's reach, which is worse for a model deciding what it may touch than a shape
it has to read properly. And **the rule table went from eight columns to seven**, the old Schema
and Name-pattern columns merging into one Objects column that reads `dbo.Customers, dbo.Orders (+3)`
with the full list on its tooltip. The saved column widths were therefore *renamed* rather than
migrated — every index from `"1"` up now denotes a different column, so reusing
`permissions_table_columns` would have applied old widths to new meanings and left every existing
install looking subtly wrong with nothing raising. The old key sits harmlessly in `config.json`,
which is what the "unknown keys are preserved" policy is for.

`_MigrationRecord` and `_backup_before_rebuild` moved out of `db/connection_store.py` into a new
`src/sape_d_mcp/db_migrations.py`, since `permissions.py` must stay usable — and testable — with no
connections database present at all. Both stores now share them; `connections.db`'s own v1→2
migration is unchanged and still produces the same backup, record and host split.

Recorded in `docs/adr/0004-permission-rule-targets.md`, with DESIGN-PERMISSIONS.md §2, §5.6, §7,
§9 and §10 and DESIGN-DATA-MODEL.md §4 re-issued to match.

#### Fixed straight after: "New rule from selection" did nothing

Reported against the change above, and two separate defects were behind it.

**The button's enabled state described a selection that was no longer there.** The page
listened on the tree's `currentItemChanged`, which was right while the tree was
single-select and is not right now. Under `ExtendedSelection` the two are different
events: a shift-click range, a rubber-band drag and Ctrl+A all change *what is selected*
while moving the current item once or not at all. So the button could read ready while
the handler's own view of the selection disagreed with it. It listens on
`itemSelectionChanged` now.

**And the handler returned silently when the selection spanned object types.** That was
the visible symptom — a button that is enabled and then does nothing when pressed is
indistinguishable from a crash, and it is worse than an error, because there is nothing
to read and nothing to act on.

The restriction that produced the silence is gone rather than merely reported. One
*rule* still carries one object type — action sets differ per type, so a mixed rule would
have no coherent checkbox grid — but that is a fact about storage, not about the gesture.
A selection spanning kinds now fans out into one rule per kind: you are told what is
coming ("This selection covers Table × 2, View × 1 …"), then asked to set the actions for
each kind in turn, in the tree's own type order so the sequence is the same every time.
Backing out of one kind does not abandon the rest. Sweeping up a schema or type heading
still skips it rather than refusing the selection, and an object the dialect cannot
address still cannot seed a rule. Every path out of that handler now either opens a
dialog or says why it did not.

`tests/test_permissions_page.py` is new and pins all of it, including the shape of the
original bug: a selection built without moving the current item, which is what every
multi-row gesture does to every row but the last.

### Tests exist again, for this part of the tree

`tests/` was absent from the working copy, although `pyproject.toml` still configured
`testpaths = ["tests"]` and the design documents referenced a suite of some 3 600. **This work
restores only `tests/test_permissions.py` and `tests/test_permissions_page.py` — 97 tests, all
passing — and the rest of the suite is still missing.** Between them they cover default-deny
across every action of every object type, the collection itself, the ordering including the
restated totality proof, the four schema-level defences above, the single-target wrappers'
refusal, the version 1 → 2 migration against a fixture built from the module's own column
generator, and the schema-tree selection defects fixed above. There is no wider suite to regress
this change against, which is worth knowing when reading the claim that nothing else broke.

---

### What each stage gave you

| Stage | Status | What it delivered |
|---|---|---|
| 0 — Plan + agents | Done | `DEVELOPMENT-PLAN.md` in the project root; eight agent definitions under `.claude/agents/`, with their skills under `.claude/skills/` and a model chosen for each |
| 1 — Logical design | Done | `docs/DESIGN-DATA-MODEL.md`, `DESIGN-PERMISSIONS.md`, `DESIGN-DIALECTS.md`, `DESIGN-MCP-TOOLS.md` — 4 296 lines between them |
| 2 — Stack | Done | `pyproject.toml`, `requirements.txt`, `requirements-dev.txt`, the `src/sape_d_mcp/` skeleton (src-layout, 9 packages), `_version.py` at `0.1.0.8`, GPL headers throughout, the legal documents, `Stack.md`, `README.md` |
| 3 — GUI mockup | Done | A navigable PyQt6 shell in both themes: sidebar (Connections, Permissions, Logs, Settings, Legal, Help, About), every page as a static layout, i18n wired end to end, legal documents rendering |
| 4 — Connection tool | Done | `src/sape_d_mcp/db/` dialects, the credential store, the connection engine and its health check; the Connections page working against real MS-SQL, PostgreSQL, MySQL and SQLite |
| 5 — Introspection + permissions | Done | `introspection.py`, `permissions.py`, the Permissions page and the schema-browser panel folded into it, both functional |
| 6 — MCP server, read | Done | `db/sql_guard.py` (brought forward from stage 7 because three read tools could not be authorised without it), `mcp_server.py` with the 18 read-only tools, `gui/server_thread.py`, `main.py --cli` wired up. 506 tests |
| 7 — MCP server, write | Done | `confirmation.py`, `gui/dialogs/confirmation_dialog.py` and `gui/confirmation_bridge.py`, the guard's write side (`require_write`, `has_effective_where`), twelve DML/DDL builders across four dialects, and 13 write tools — the catalogue grew from 18 to 31 tools. `read_only_session()` and `statement_timeout_for()` closed out. 1 584 tests |
| 8 — Security & audit | Done | `db/security.py` (`SecurityManager`, one per connection) and the 7 security tools — catalogue 31 → 38. `_password_literal()` deleted rather than implemented: `create-user` takes no password on any engine, so a model can never introduce a credential. Per-engine privilege allowlists closed. The Logs page reading real `audit.db`, one tab per connection, one per deleted connection, a System tab for connection-less rows, filters and CSV export hardened against spreadsheet formula injection. `drop-function`/`drop-procedure` now take a `signature` resolved against the catalogue. `revoke-role` and `remove-user-from-group` joined the destructive set on the user's own ruling — 10 destructive tools, not 8. 1 853 tests |
| 9 — QA & packaging | Done | `db_location.py`, the single module that decides where `connections.db`, `permissions.db` and `audit.db` live — three modules had each hand-counted their own `.parent` hops, and a wheel install put all three databases inside the interpreter's own `lib/`. `--show-permissions` implemented, `--db` removed: the four `DMCP_*` environment variables are now the whole mechanism. `Operator` was never imported into `db/dialects/base.py`, so every structured `select()`, `update()`, `delete()` and `count_matching()` on all four engines raised `NameError` at the first predicate — fixed, and swept by a test driven off the enum itself. The MCP configuration dialog built and the Settings buttons wired to it. Sample data now defaults to off, which is what exposed the empty-state layout bug on two pages. An end-to-end test that launches the generated configuration as a subprocess and speaks real JSON-RPC to it. Roughly 900 new tests, and four GUI defects fixed — the sharpest being a failed grant that left its checkbox ticked, showing more access than the engine would have given. `ruff`, `mypy` and `black` configured for the first time, then `ruff` swept from 279 findings to zero and `mypy` brought clean at its configured floor. Three of those findings were `pytest.raises(match=...)` patterns passing for the wrong reason, fixed at the raise site rather than silenced; a fourth defect of the same kind was `settings.about_text`, whose `{version}` placeholder `translate()` never formats, so the Settings About group showed the literal text `{version}` on screen in all eighteen locales. `black` stays configured and deliberately unsatisfied, on your ruling. `.gitignore`, `mapping.txt`, this file, and a PyInstaller bundle that builds and has been smoke-tested on Linux. 3 178 tests passing, 29 skipped |

### Decisions this release carries

These were put to you and settled before or during the stages above, and the code follows them
throughout rather than reopening them stage by stage:

- Permission rules match on `(schema, object_type, name_pattern)` with action flags, most
  specific wins — the database analogue of f-MCP's `path` plus `allow_subfolders`.
- Credentials live in the OS keyring, with an AES/master-password fallback where no backend
  exists. `connections.db` never stores a password.
- A destructive operation needs a permission flag and a live GUI confirmation — except `drop` and
  `edit`, which schema version 4 made unconditional prohibitions that no permission flag can grant
  at all. With no GUI attached, the operations that still ask for one are denied and the denial is
  logged. There is no "remember this decision" — every approval is single-use, always.
- Both MS-SQL drivers ship, `pyodbc` as the default and `pymssql` as the driver that needs
  nothing installed on the system.
- One MCP tool catalogue, not one per connection: every tool takes a required `connection`
  parameter, its enum generated from your configured connection names.
- 18 locales are registered; only `en-US` and `es-ES` are genuinely authored today, the
  remaining 16 carry English text pending translation — see
  `gui_resources/flags/mapping.txt` for the full table.

### Decisions added in stage 9

- **Sample data defaults to off.** The empty state is what a first-run user meets, so it is the
  one that has to look finished.
- **The three databases follow the current working directory**, with `DMCP_DB_DIR` and the three
  per-file variables as the override. `--db` was dropped rather than adapted. Launching from two
  different directories genuinely means two different rule sets — `src/sape_d_mcp/db_location.py`
  states the cost as plainly as this does.
- **The Settings page keeps its Server group**, description and all, rather than losing it now
  that the server is started from the status bar.
- **`black` stays configured and deliberately unsatisfied.** It would reformat 68 of 92 files, and
  running it would put a formatting-only diff across three quarters of a hand-reviewed tree into
  the same commit as this stage's real fixes. `ruff` passes clean and already enforces import
  ordering and the same 120-column limit, so nothing goes unguarded. Satisfying `black` is a
  future commit of its own.

### Known gaps at this point

- **`mypy --strict` does not pass.** 34 errors across 18 files, almost all of them missing
  parameter and return annotations on functions written before the configuration existed. The
  floor `pyproject.toml` configures *does* pass — 62 source files, no issues — and `--strict` is
  a stated target rather than a gate this release claims to meet. `ruff` and `pytest` are clean;
  `black` is unsatisfied by the decision recorded above, not by neglect.
- **Only Linux has been verified.** The test suite, the GUI and the PyInstaller bundle all run
  there. Nothing has been built or launched on Windows or macOS.
  `docs/CROSS-PLATFORM-SMOKE-TEST.md` is the manual checklist that closes this, and its last
  section says exactly what the development machine could not prove — including that PyInstaller's
  `.ico` embedding path has never executed anywhere, and that `pyodbc` cannot be imported there
  at all.
- **`pyodbc` is excluded from every Linux bundle**, because `collect_submodules()` cannot import
  it without `libodbc.so.2`. `sape-d-mcp.spec` prints a warning when this happens; grep the build
  output for it on every platform.
- **Sixteen of the eighteen locales are untranslated** and carry the English source text.

### Connection setup remodelling (packaging notes; in progress)

`docs/DESIGN-CONNECTION-SETUP.md` §12 lists 22 tasks that replace the connection subsystem's
authentication and discovery model; tasks 1–19 have landed (`db/auth_modes.py`, `db/targets.py`,
`db/discovery.py`, `db/ssrp.py`, the `discovery_dialog.py` GUI dialog and the reshaped
`connection_dialog.py`/`connections_page.py`), and the full suite passes at 3 602 tests. This
entry records only task 21, the packaging slice of that batch — the design-model documentation,
the driver-matrix update and the "Known limitations" additions are task 20's, owned by the
software architect, and are not claimed here.

- **No new runtime dependency.** All four new modules were checked import by import: `re`,
  `dataclasses`, `platform`, `logging` (`auth_modes.py`, `targets.py`), and `socket`,
  `selectors`, `struct`, `threading.Event` alongside a function-scoped `winreg`
  (`discovery.py`, `ssrp.py`) — every one of them standard library. `requirements.txt` and
  `pyproject.toml` are unchanged.
- **`sape-d-mcp.spec` needs no new `hiddenimports` entry.** `winreg` is imported as a literal
  statement, not a computed one, so PyInstaller's bytecode scan finds it on any platform without
  help; verified against a real Linux build, whose `warn-*.txt` logs the expected
  "missing module named winreg ... sape_d_mcp.db.discovery (delayed)" line, the same harmless
  shape already carried for `platform` and `mimetypes`. The spec file now documents this
  reasoning inline so the next person who adds a Windows-only import does not have to
  re-derive it.
- **README gained two platform-facing notes.** The Windows section now documents exactly which
  two `HKEY_LOCAL_MACHINE` registry paths "Discover" reads (`Instance Names\SQL` and each
  instance's `SuperSocketNetLib\Tcp\IPAll`), that both are opened `KEY_READ`-only and need no
  administrator rights, and what a locked-down machine sees instead (an empty result, not an
  error). The Linux, Windows and macOS sections each now state what system (integrated)
  authentication needs on that platform — nothing, on Windows; `kinit`, a `krb5.conf` and a
  server SPN, everywhere else — in the same pasteable, per-platform style
  `dialects/registry.py`'s `_ODBC_DRIVER_HINTS` already used for the ODBC driver install.

### Fixed after the first MS-SQL connection attempt

Reported against the New connection dialog with a working address that d-MCP would not accept:
`Host = 10.129.203.19\NRP`, `Port = 1435`, ODBC Driver 18, a SQL Server login.

- **A host carrying an instance is now split instead of refused.** The dialog understood the
  address — it said so in the note under the field — and then still failed "Find databases" with
  *"the host ... carries a server, an instance and a port in one field"*. `reconcile_mssql_profile()`
  (`db/targets.py`) now merges what the host carries with the `instance` and `port` columns, and
  both `ConnectionStore._validate()` and `MSSQLDialect._connection_target()` go through it, so
  typing the environment-file form works and a saved profile still holds separated columns. Only
  a host that *contradicts* a column the user also filled in is refused. This is §13 D6's ruling —
  split, do not flag and wait — extended from migrated rows to typed input;
  `docs/DESIGN-CONNECTION-SETUP.md` §6.2a records it.
- **"Windows / system authentication" was there all along and looked as though it was not.**
  The option is offered and enabled for MS-SQL + pyodbc on Windows, but both stylesheets carried
  `QComboBox::drop-down { border: none; }`, and styling that subcontrol at all suppresses the
  arrow Qt would otherwise draw. Every combo box in the application rendered as a rounded box
  indistinguishable from a read-only line edit, so the Authentication row read as a field with
  one fixed value. The rule is gone from both themes and the native arrow is back.
- **`Encrypt` and `TrustServerCertificate` are defaults, not fixtures.** `options_json` now
  overrides them instead of being appended after them, which previously put the same key in the
  ODBC string twice and left the driver to decide which one counted.
- **A TLS failure is no longer reported as a stopped SQL Server Browser.** With the address
  fixed, the next attempt failed on the certificate — and the message blamed the Browser service,
  UDP 1434 and the instance name, all three of which were fine. A failed handshake arrives under
  SQLSTATE 08001 carrying transport vocabulary, so it had been bucketed as `network`. `tls` is now
  the seventh `ERROR_KIND`, matched ahead of everything else, on the SChannel status codes as well
  as the words — msodbcsql18 localises the words and not the codes, and the reported message was
  German. Its sentence names the two real repairs, and the Connections page paints it amber rather
  than red: the server was reached and the profile has the setting that resolves it.
- **"Trust the server certificate" is now a tick box on the profile.** `options_json` had never
  been exposed in the GUI, so the setting the message points at could not actually be reached.
  MS-SQL only, unticked by default (Driver 18 encrypts and verifies, which stays the default),
  with an italic note stating the trade: still encrypted, identity no longer checked. Stored in
  `options_json`, so no schema change and no migration. Any other key already in an edited
  profile's `options_json` is kept verbatim — ticking this box cannot drop a driver option someone
  set by hand. Recorded in `docs/DESIGN-CONNECTION-SETUP.md` §6.4a and §6.5.

### Fixed in the same session

- **`header.logo` is gone from the catalogue.** The key carried the string "SAPÉ d-MCP" in all
  eighteen locales and no module ever read it: it existed because f-MCP's
  `get_supported_languages()` derived its locale list from that one key's own set of language
  keys, a derivation d-MCP replaced with `LanguageRegistry.LANGUAGES` precisely so no translation
  key would stand in for the registry. It is dropped from `HEADER_NS` in
  `tools/generate_translations.py` and the catalogue regenerated, taking it from 402 keys to 401.
  `tests/test_i18n_catalogue.py` loses it from `_KNOWN_ORPHAN_KEYS` — the ratchet list of dead
  keys, which may only shrink — and the defect-6 regression test no longer deletes that key to
  prove the derivation: it empties `TRANSLATIONS` entirely, which is the same proof and a
  stronger one, and does not depend on any particular key still existing. The explanations of
  f-MCP's bug in `header.py`, the generator's docstring and `DEVELOPMENT-PLAN.md` still describe
  f-MCP's implementation and are unchanged.

- **One launch opened two windows.** `SAPEApplication.__init__` builds and owns a `MainWindow`,
  and `main()` constructed a second one — so the whole window was built twice. Only the second was
  ever shown deliberately; the first put itself on screen from its own constructor, because
  `_restore_window_geometry()` called `showMaximized()` there and a saved `"maximized": true` made
  that fire. Both halves are fixed: `main()` uses `app.main_window`, and the restore records the
  state with `setWindowState()` instead of showing the window before anything asked it to.
- **The combo boxes are flat again.** Deleting `QComboBox::drop-down` brought back Qt's own
  arrow — a raised native control at odds with the rest of the design. The subcontrol is styled
  again, this time with a marker to draw: a flat chevron in the secondary text colour, one SVG per
  theme under `gui_resources/icons/`. A relative `url()` in a stylesheet resolves against the
  working directory, so the sheets carry an `@ICONS@` token that `SAPEApplication` replaces with
  the `resource_path()`-resolved directory at load time; a missing icons directory leaves the
  token, and Qt drops the one rule rather than the whole sheet.
- **A new connection never reached the Permissions page.** Every page is built once at start-up,
  and the Permissions page filled its Connection combo only there, on a language change, and on
  Refresh. A profile created on the Connections page therefore did not exist as far as that page
  was concerned — the combo still read "No connections defined yet", the schema browser had
  nothing to browse, and no rule could be written against the connection the operator had just
  made. The page now re-reads the list in `showEvent()`, so switching to it picks up anything
  added or deleted while it was hidden. `_refresh_rules_and_tree()` is deliberately *not* run on
  every show — it opens a live connection to load the schema — only when the connections or the
  selection actually changed.
