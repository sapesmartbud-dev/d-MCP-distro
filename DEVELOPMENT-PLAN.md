# SAPÉ d-MCP — Development Plan

## Context

`prompt.md` asks for a new application, **SAPÉ d-MCP**, that does for *databases* what the
existing **SAPÉ f-MCP** does for the *file system*: an MCP server giving an LLM **controlled,
permission-gated access** to resources, driven by a PyQt6 desktop GUI where a human defines
exactly what is allowed and audits everything that happened.

The reference lives at `C:\Coding\SAPE\f-MCP` (read-only, ~9 900 lines). d-MCP reuses its
visual language, structural conventions and legal posture, replacing the filesystem domain
(paths, files, folders) with the database domain (connections, schemas, tables, views,
functions, stored procedures).

At the time this plan was written the project directory held only `CLAUDE.md`, `prompt.md`,
`LICENSE` and a `gui_resources/` tree **already populated** with the 18 flags, the icon set and
the logos; everything else was to be built. That paragraph is left in the past tense rather than
deleted, because the staged-delivery table below is a record of what was planned as much as of
what was shipped, and it should still be readable as the document it was on day one.

`prompt.md` mandates **staged delivery with user authorisation between every stage**, so this
plan defines the stages and the gates, not just the code.

### Decisions confirmed with the user

| Question | Decision |
|---|---|
| Permission granularity | **Rule per object collection** — one `object_type` plus one or more `(schema, name_pattern)` targets, + action flags; the most specific matching target wins, and a rule's specificity at an object is its narrowest matching target. Pattern grammar is f-MCP's `path + allow_subfolders` analogue; the collection arrived at `permissions.db` schema version 2, see `docs/adr/0004-permission-rule-targets.md`. |
| Credential storage | **OS keyring** (`keyring`) with an **AES/master-password fallback** where no backend exists. The `.db` never stores a password. |
| Destructive operations | **Permission flag + live GUI confirmation dialog.** With no GUI attached the operation is denied and the denial logged. |
| MS-SQL driver | **Both `pyodbc` (default) and `pymssql`**, selectable per connection profile. |
| MCP tool namespacing | **One tool set with a required `connection` parameter** whose JSON-Schema is an enum generated from the configured connection names. The catalogue does not grow when a database is added. |
| Initial version | **0.1.0.8**, carried by `src/sape_d_mcp/_version.py` and referenced by the legal documents. |
| Landing page | **Connections** is sidebar index 0 and opens on launch — without a connection there is nothing to permission, browse or log. |
| Explorer page | **Folded into Permissions** as a schema-browser panel beside the rule table, so the object and its rule are seen together and there is only one tree to keep in sync. Drops one sidebar entry. |
| Mockup data | **Sample data plus a Settings toggle for the empty states**, so density, column widths and text overflow can be judged without losing sight of the real first-run screen. |
| Translation scope | **18 locales registered, `en-US` and `es-ES` authored**, the other 16 seeded from English — f-MCP's approach, and what the README already states honestly. |
| Unattended unlock | **`DMCP_MASTER_PASSWORD` kept**, opt-in and only where no keyring backend exists, because a headless MCP server otherwise cannot reach any database. Documented as a risk in `DISCLAIMER.md` §11 and `DATA-PROTECTION.md`; warns on every use. |
| Engine and driver spelling | **`postgresql` and `mysql-connector-python`** — the pip package name is the driver key, as `dialects/registry.py` requires. `DESIGN-DATA-MODEL.md` said `postgres`/`mysqlconnector` and has been corrected. |
| SQLite schema | **Canonicalised to `main`** rather than `None`, so the resolver never meets a schema-less reference and all four engines read alike. |
| Database-scoped actions | **Resolved by connection alone** — a `database` rule short-circuits pattern matching, is written with `*`/`*`, and appears in the GUI as a fixed section, not a pattern row. |
| Audit log layout | **One `audit.db` with a `connection_id` column** and an index on `(connection_id, timestamp)`. The Logs page renders one tab per connection by filtering on it. |
| Row filtering in `select-rows` | **A free-form `where` string with bound `parameters`**, as `DESIGN-MCP-TOOLS.md` specified — not the structured `filters` list stage 6 first shipped. The fragment is composed into the statement by the dialect, which alone knows where each engine binds the row cap, and the **composed** text is re-parsed through the same `SqlGuard` as `run-read-query`, so a subquery reaching an unauthorised table is caught before anything runs. Supersedes `DESIGN-DIALECTS.md` D3. |
| Remembered approvals | **Single use, always.** The `confirmations.remember_for_session` key `DESIGN-DATA-MODEL.md` §9 defined is withdrawn from the configuration schema, because `DESIGN-MCP-TOOLS.md` §8.2 forbids in terms what it enables: no blanket approval, no "approve all", no remembered decision. Every destructive operation raises its own modal, bound to the exact `(connection, tool_name, sql)` triple. The cost is real friction across a run of repeated drops; the benefit is that a human saw each one. |
| Confirmation modal | **Ships in stage 7, not stage 8.** Without a subscriber the broker denies everything, so deferring the dialog would close the stage with the whole destructive half of the catalogue unexercisable from the GUI and verifiable only by test. |
| Sample data | **Defaults to `False`.** Supersedes the mockup-data decision above, which left the toggle on: the empty state is what every first-run user actually meets, so it is the one that has to look finished, and shipping with it hidden is how it stops being looked at. Turning the default off immediately exposed the `empty_label` stretch bug on `connections_page.py` and `permissions_page.py`, which is the argument for the ruling rather than against it. |
| Database location | **Current working directory, and no `--db` flag at all.** Three candidates were put to the user for where `connections.db`, `permissions.db` and `audit.db` live once the code is in `site-packages` and "project root" means nothing — the installed package's own directory, `~/.sape/d-mcp/`, and the working directory — and the working directory was chosen, with the consequence stated plainly: two launch directories genuinely mean two rule sets and two audit trails. `--db` is **dropped entirely** rather than adapted; f-MCP's single prefix argument assumes one database, and d-MCP's three need not share a directory. `DMCP_CONNECTIONS_DB`, `DMCP_PERMISSIONS_DB`, `DMCP_AUDIT_DB` and `DMCP_DB_DIR` are the whole mechanism, and `mcp_config_generator.py` always emits all three so a client-spawned server can never resolve them against the client's own directory. See `docs/adr/0001-database-location.md` for the three candidates and what the chosen one costs, and `src/sape_d_mcp/db_location.py` for the implementation. |
| Settings "Server" group | **Kept, description and all.** The group holds no control of its own now that the server is started from the status bar, and removing it was proposed; the user ruled it stays, because a Settings page that says nothing about the server reads as a Settings page that forgot about it. Its text is a description, not a placeholder. |
| `black` conformance | **Configured, deliberately unsatisfied.** `black --check` would reformat 68 of the 92 files in `src/` and `tests/`. Running it was proposed and the user ruled against it *for this stage*: the tree is reviewed and committed by hand, and a formatting-only diff across three quarters of it, landed in the same commit as stage 9's real fixes, would hide those fixes inside it. Nothing is left unguarded — `ruff` passes clean and already enforces import ordering and the same 120-column limit `black` is configured with, so the two cannot disagree about line length. Satisfying `black` is a future commit of its own, and is documented as a decision rather than as an outstanding failure. |

---

## Conventions inherited from f-MCP

Established first-hand from the reference; binding on the implementation.

**Stack.** Python ≥3.10 (`from __future__ import annotations` in every module), **PyQt6**
≥6.6.1 with fully-qualified enums (`Qt.AlignmentFlag.AlignCenter`), **`mcp` ≥2.0** — in the 2.x
SDK `FastMCP` was renamed `MCPServer`:

```python
from mcp.server import MCPServer
from mcp.types import ToolAnnotations
```

Tools are nested closures inside one `_register_tools(self)`, each with an explicit name,
description and annotations; schemas come from the type hints. Transport is a passthrough:
`stdio | sse | streamable-http`.

**Licence header** — byte-identical 16-line block atop every `.py` file, then a one-line module
docstring, then `logger = logging.getLogger(__name__)`. Line 1 is the strapline the GPL's "How
to Apply" appendix asks for:

```python
# SAPÉ d-MCP — controlled database access with granular permissions for LLMs
# Copyright (C) 2026 Luciano Arrezze
# … FSF boilerplate verbatim, "version 3", double space before "See the" …
# SPDX-License-Identifier: GPL-3.0-only
```

Two identities stay distinct: **copyright holder** = the natural person *Luciano Arrezze*;
**publisher brand** = *SAPÉ smart bud* (info@sapebud.com, Arenys de Mar, Spain). Year `2026`,
no ranges. GPL **version 3 only** — "or any later version" is deliberately not granted. PyQt6
is itself GPL, noted in README and LEGAL-README. Trademark reserved: *"fork freely, but give
your fork its own name."*

**Single-source-of-truth tuple.** `ACTIONS` in `permissions.py` drives the SQL columns, the
migration, validation, the `show-permissions` output and a parametrised test. d-MCP keeps that
discipline, per object type.

**Default-deny, never seeded.** An empty database authorises nothing — documented in the module
docstring and pinned by a `test_a_new_database_grants_nothing`-style test.

**Schema migration.** `_migrate_schema()` reads `PRAGMA table_info(...)`, diffs against the
action tuple, `ALTER TABLE … ADD COLUMN … INTEGER NOT NULL DEFAULT 0` for each missing one.

**Error handling.** Every tool body is `try: … emit_success … except Exception as e:
emit_error; raise`. Stdlib exceptions with actionable messages; no custom result envelope.
Logging fan-out is wrapped so a logging failure never breaks a tool.

**Dual logging.** Append-only JSONL beside the permissions DB (survives being spawned as a
Claude Desktop subprocess) *plus* a WAL SQLite store keyed by `session_id`, with `"cli"` as the
well-known id for externally spawned servers. Record shape:

```json
{"timestamp": "2026-09-01T07:48:56.668912+02:00", "tool_name": "create",
 "params": {…}, "result": null,
 "error": "'create' is not permitted on C:\\Coding\\_Borrar (rule: C:\\Coding)"}
```

Rotation: above 10 000 rows delete the oldest 1 000 by `id`; no `VACUUM`.

**GUI architecture.** `SAPEApplication(QApplication)` is the theme/language broadcast bus;
managers persist then emit. `MainWindow` is a vertical sandwich — `Header` / (`Sidebar` +
`QStackedWidget`) / `StatusBar` — using plain `QWidget`s, not `QMainWindow`'s dock and status
bar. Widgets are constructed **empty** and filled exclusively by `_update_language(language)`,
which takes the language as a parameter rather than reading it back off the app. Every widget
connects `app.language_changed` and `app.theme_manager.theme_changed`, then calls both
handlers directly at the end of `__init__`. Pages use 24 px margins, 16 px spacing, an 18 pt
bold title and a 10 pt italic subtitle. `QMessageBox` is always constructed explicitly so the
buttons can be translated. Lambdas bind with default args
(`lambda checked, p=rule['path']: …`). Geometry persistence is debounced through a 300 ms
`QTimer`.

**Theming.** Three layers: `sape_design_tokens.py` (`QColor` constants + two `QPalette`
factories) · twin 470-line QSS files with hardcoded hex (`application.qss` /
`application_light.qss`) · `ThemeManager` for persistence and signalling only. The runtime swap
reloads the whole stylesheet in `SAPEApplication.set_theme`. Palette:

- Brand `#1C3FF0` / `#122AD2` / accent `#2E86FF`; graphite `#212832` / `#6B7280`
- Light bg `#F4F6FA`, surface `#FFFFFF`, text `#212832`/`#4B5563`, border `#E1E5EA`, alt `#F9FAFB`
- Dark bg `#0A0C10`, surface `#15181D`, text `#E0E2E7`/`#A7ACB3`, border `#2D3139`, alt `#1F2329`
- Semantic success `#10B981`, error `#EF4444`, warning `#F59E0B`, info `#3B82F6`
- `IBM Plex Sans` / `JetBrains Mono`; 4px spacing base; radii 4/6/8/12

The `ACTION_*` block is the filesystem verb palette and is where d-MCP substitutes database
verbs, keeping the same hue vocabulary: SELECT blue, INSERT green, UPDATE amber, DELETE red,
DDL purple, EXECUTE cyan, GRANT pink.

**i18n.** `TRANSLATIONS` is one machine-generated dict, `'namespace.snake_case' -> {lang: text}`
— 175 keys × 18 locales on a single 154 KB line. It must be **generated, never hand-edited**.
Only `en-US` and `es-ES` are genuinely authored; the rest carry English. `translate(key,
language)` is a plain function — no `QTranslator`, no `.ts` files.

**Server thread.** In-process `QThread` (not a subprocess) running `anyio.run(...)`. The GUI
rewrites `stdio` → `streamable-http` on start, because stdio would hang on stdin inside a
thread. Stop is a `threading.Event` polled every 100 ms that cancels an `anyio.CancelScope`,
with `wait(5000)` before `terminate()`. Ports probe 8089–8098 by attempting `socket.bind()`.

**Config generation.** `MCPConfigGenerator` detects the install (frozen → console script →
source), always injects `--cli`, uses `sys.executable` (mapping `pythonw.exe` → `python.exe`)
and emits `{"command": …, "args": [… "--cli", "--transport", …], "env": {}}`. It writes only
`~/.sape/installation.json` and never the client's config file — it tells the user to **merge**.

**Legal.** `legal-documents/en-US/{LICENSE,DISCLAIMER,DATA-PROTECTION,LEGAL-README}.md` plus
byte-identical root mirrors. Bodies stay English-only (the FSF publishes no binding
translations); only *labels* are localised. Per-locale directory shape is retained so a locale
can be added without a code change.

**README.** Plain, unmarketed, second-person register — no emoji, no "Features" section, one
GPLv3 badge after the intro prose. Tables for anything enumerable. It documents its own
defects prominently (`## What this is not`, `### Known limitations`) and is honest about
translation coverage. d-MCP copies the heading outline and the tone.

**Test style.** pytest, no `conftest.py`; module docstrings narrate *the bug the tests pin
down*; test names are full sentences; tools are reached through the SDK registry as a client
would: `server.server._tool_manager._tools[name].fn`.

### f-MCP defects to fix rather than copy

1. **`~/.sape/` collision.** f-MCP puts `config.json`, `log.db` and `installation.json`
   directly in `~/.sape/`. d-MCP namespaces its own under **`~/.sape/d-mcp/`** so the two
   applications cannot clobber each other.
2. **Resource paths.** No `resource_path()` helper exists; consumers hand-count 2/3/4 `.parent`
   hops and nothing is `sys._MEIPASS`-aware. d-MCP adds one frozen-aware
   `src/sape_d_mcp/gui/resources.py` and routes everything through it.
3. **Dead QSS.** `setObjectName` is never called, so every `#header` / `#sidebar` /
   `#statusBar` rule in both stylesheets is inert. d-MCP sets the object names.
4. **Four config writers** (`ConfigManager`, `ThemeManager`, `LanguageManager`, `MainWindow`,
   plus a duplicate private `ConfigManager` inside `permissions_page.py`) each read-modify-write
   the same file and can clobber one another. d-MCP has one writer, and deep-copies
   `DEFAULT_CONFIG` (the shallow copy aliases the nested dict).
5. **Packaging.** `packages = ["src"]` omits the GUI and console-script subpackages, so a clean
   wheel install is broken. d-MCP adopts a proper package layout.
6. `get_supported_languages()` derives the locale list from `TRANSLATIONS["header.logo"]` and
   excludes `en-US`; build it from `LanguageRegistry.LANGUAGES` instead.
7. **Untranslated strings**: the whole MCP-config dialog, the header title literal, and the
   `"{Category} Operations"` group labels. Drop the 12 unused `page.*` keys.
8. Legal page shows **raw markdown**; use `QTextBrowser.setMarkdown()`.
9. `closeEvent` never stops the server thread; an unparented `QTimer` is GC'd before firing.
10. `mapping.txt` is stale (`.svg`, 2-letter codes, vs 18 shipped `.png` keyed by BCP-47);
    `DATA-PROTECTION.md` is bilingual despite the English-only policy and contains a
    `SAPÉ f-MCPf-MCP` typo; `requirements-dev.txt` and the `dev` extra have drifted.

---

## Target architecture

```
d-MCP/
├── main.py                     # GUI by default; --cli headless, never imports PyQt6
├── pyproject.toml  requirements.txt  requirements-dev.txt  .gitattributes
├── README.md  LEGAL-README.md  DISCLAIMER.md  DATA-PROTECTION.md  LICENSE
├── legal-documents/en-US/*.md
├── gui_resources/              # ALREADY POPULATED
├── connections.db  permissions.db  audit.db     # created on first run
├── src/sape_d_mcp/          # the installable package, imported as sape_d_mcp.*
│   ├── _version.py             # no imports; setuptools parses it statically
│   ├── db_location.py          # the one module that decides where the three .db files live
│   ├── db/
│   │   ├── dialects/           # base.py, mssql.py, postgres.py, mysql.py, sqlite.py,
│   │   │                       #   registry.py, types.py
│   │   ├── connection_store.py # profiles CRUD, never secrets
│   │   ├── credential_store.py # keyring + AES fallback
│   │   ├── engine.py           # pooling, connect, health check
│   │   ├── introspection.py    # list/describe tables, views, functions, procedures
│   │   ├── sql_guard.py        # statement parsing and classification
│   │   └── security.py         # roles, users, groups, grants
│   ├── permissions.py          # pattern-matching rule engine
│   ├── confirmation.py         # destructive-op approval broker
│   ├── log_store.py  tool_logger.py
│   ├── mcp_server.py           # DatabaseMCPServer
│   ├── mcp_config_generator.py  config_json_generator.py
│   ├── language_registry.py  flag_mapping.py  legal_document_loader.py
│   └── gui/
│       ├── resources.py        # NEW: frozen-aware resource_path()
│       ├── app.py main_window.py config_manager.py language_manager.py
│       ├── theme_manager.py server_thread.py splash_screen.py
│       └── components/ dialogs/ i18n/ styles/ pages/
└── tests/
```

### Persistence

`prompt.md` requires GUI config in `.json` and everything else in SQLite. All files are created
on first run; a clean checkout has none of them.

- **`~/.sape/d-mcp/config.json`** — theme, language, window state, table column widths, log
  preferences. Written on first `set_*()`, not at construction.
- **`connections.db`** (project root) — `connections(id, display_name, engine, driver, host,
  port, database, username, options_json, colour_tag, created_at, user_created, updated_at,
  user_updated)`. **No passwords.**
- **`permissions.db`** (project root) — `rules(id, connection_id, schema_pattern, object_type,
  name_pattern, is_deny, can_* …, + the four audit columns)`.
- **`audit.db`** (project root) — `tool_calls(id, connection_id, session_id, timestamp,
  tool_name, params_json, rows_affected, duration_ms, result, error, decision,
  matched_rule_id)`, WAL, same 10 000/1 000 rotation.

### Permission model

A rule is `(connection_id, schema_pattern, object_type, name_pattern) -> {action: bool}`.
Resolution collects matching rules, orders by specificity (exact name > prefix pattern > `*`)
and applies the most specific; an explicit **deny** beats an allow at equal specificity. An
unnormalised or ambiguous identifier raises `ValueError` — fail closed, exactly as `rule_for()`
does today.

| Group | Actions |
|---|---|
| Tables | `list, read_structure, select, insert, update, delete, create, drop` |
| Views | `list, read_definition, select, create, drop` |
| Functions | `list, read_definition, create, edit, drop` |
| Stored Procedures | `list, read_definition, create, edit, drop` |
| Database / security | `read_catalogue, create_role, create_user, create_group, assign_group, assign_role, run_query` |

As shipped in `permissions.py`'s `ACTIONS_BY_TYPE`, which is the single source of truth and
differs from this plan's first draft in two places: there is no `execute` action on functions or
procedures, because `DESIGN-MCP-TOOLS.md` §13 decision 1 dropped `execute-function` and
`execute-procedure` from the catalogue and an action no tool can reach is a permission that
cannot be honoured; and `run_query` is a database-scoped action, because `run-read-query` is
gated per connection before its referenced objects are resolved individually.

`sql_guard.py` (on `sqlparse`) classifies every statement, refuses anything it cannot classify,
and blocks multi-statement batches so a `DROP` cannot ride along inside a `SELECT`.
Parameterised values only; identifiers quoted per dialect. This is the analogue of f-MCP's
resolve-then-authorise-then-act discipline and its symlink-escape tests — and the same class of
test (`test_a_drop_cannot_be_smuggled_through_select`) must exist.

### Destructive-operation confirmation

`confirmation.py` brokers approval before any action flagged destructive (`drop`, `delete`,
body `edit`, and `update`/`delete` with no `WHERE`). The GUI subscribes and raises a modal
showing the connection, the exact SQL and the estimated impact. No subscriber ⇒ denied and
logged. Those tools carry `ToolAnnotations(destructive_hint=True)`.

### GUI pages

Sidebar mirrors f-MCP's `(translation_key, page_index)` + emoji-icon parallel lists, retargeted:
**Connections** (profiles, engine/driver pickers, keyring-backed credential entry, test button)
· **Permissions** (connection selector, rule table, `NewRuleDialog`-style modal with actions
grouped by category, and the schema-browser panel the Explorer page was folded into — see the
decisions table) · **Logs** (one `QTabWidget` tab per connection, filterable, CSV export) ·
**Settings** · **Legal** · **Help** · **About**. Seven sidebar entries, not eight. Header, status bar, splash, theme manager, language switcher
and the MCP-config dialog port over with content changes only.

The Logs page is a genuine change from f-MCP: `prompt.md` requires per-database tabs, whereas
f-MCP uses a single `QPlainTextEdit`. Each tab gets a `QTableWidget` over `audit.db` filtered by
`connection_id`, keeping f-MCP's 500 ms poll timer and its success/error colour pairs
(`#8FD8B7`/`#0F5C3C` and `#F0A6AA`/`#842126`).

---

## Staged delivery

Stages 1–4 are the sequence `prompt.md` drafted; 5–9 are the continuation it asked me to
define. The user authorises each stage before it begins.

Everything is created **inside the project only**. Nothing is written to a global or
user-level location: the agent and skill definitions go in `./.claude/agents/` and
`./.claude/skills/`, never `~/.claude/`. This development plan itself is saved to the project
root as `./DEVELOPMENT-PLAN.md` as the first action of stage 0.

| # | Stage | Deliverable |
|---|---|---|
| 0 | ✅ **Plan + agents** | `./DEVELOPMENT-PLAN.md` in the project root; eight agent definitions in `./.claude/agents/` with their skills in `./.claude/skills/` and the models below |
| 1 | ✅ **Logical design** | `docs/DESIGN-DATA-MODEL.md`, `DESIGN-PERMISSIONS.md`, `DESIGN-DIALECTS.md`, `DESIGN-MCP-TOOLS.md` — 4 296 lines |
| 2 | ✅ **Stack** | `pyproject.toml`, both requirements, `src/sape_d_mcp/` skeleton (src-layout, 9 packages), `_version.py` = 0.1.0.8, GPL headers, legal documents, `Stack.md`, `README.md` |
| 3 | ✅ **GUI mockup** | Navigable PyQt6 shell: both themes, sidebar (Connections · Permissions · Logs · Settings · Legal · Help · About), all pages as static layouts, i18n wired, legal documents rendering |
| 4 | ✅ **Connection tool** | `src/sape_d_mcp/db/` dialects, credential store, engine, connection test; Connections page working against real MS-SQL/Postgres/MySQL/SQLite |
| 5 | ✅ **Introspection + permissions** | `introspection.py`, `permissions.py`, the Permissions page functional — with the Explorer folded into it as the schema-browser panel, per the decisions table, so there is no separate Explorer page |
| 6 | ✅ **MCP server — read** | `db/sql_guard.py` (brought forward from stage 7 — three read tools cannot be authorised without it), `mcp_server.py` with the 18 read-only tools, `gui/server_thread.py`, `main.py --cli` wired. 506 tests |
| 7 | ✅ **MCP server — write** | `confirmation.py` (broker, single-use approval), `gui/dialogs/confirmation_dialog.py` + `gui/confirmation_bridge.py`, the guard's write side (`require_write`, `has_effective_where`), the twelve DML/DDL builders across four dialects, and the 13 write tools — catalogue 18 → 31. Carried-in items both closed: `read_only_session()` per engine and `statement_timeout_for()` applied per connection. 1584 tests |
| 8 | ✅ **Security & audit** | The 14 remaining `DeferredSurface` stubs — the class is now empty and the dialect layer closed — `db/security.py` (`SecurityManager`, one per connection), and the 7 security tools: catalogue 31 → 38. `_password_literal()` **deleted** rather than implemented, per `DESIGN-MCP-TOOLS.md` §11.2: `create-user` takes no password on any engine, so no credential can enter from a model. Per-engine privilege allowlists, closed. Logs page reading real `audit.db` with a tab per connection, a tab per deleted connection (labelled from the denormalised name, since there is nothing left to join to), a System tab for null-connection rows, filters and CSV export defused against spreadsheet formula injection. Carried-in gap closed: `drop-function`/`drop-procedure` take a `signature`, resolved against the catalogue so the server's own spelling is what gets written. **User ruling:** `revoke-role` and `remove-user-from-group` joined §8.1's destructive set — 10 destructive tools, not 8. 1853 tests |
| 9 | ✅ **QA & packaging** | `db_location.py`, the one module that decides where the three databases live — `connection_store.py`, `permissions.py` and `log_store.py` each hand-counted their own `.parent` hops (`parents[3]`, `[2]`, `[2]`) and a wheel install put all three databases inside the interpreter's own `lib/`. **User ruling:** the current working directory, with `DMCP_DB_DIR` and the three per-file variables as the escape hatch; `--db` **removed from the CLI entirely** rather than reintroduced, and `--show-permissions` implemented — it opens the two stores directly rather than a `DatabaseMCPServer`, so a human asking "what is configured" gets an answer even for an unreachable database. **The defect the suite had missed:** `Dialect._where_clause()` coerces every predicate through `Operator(predicate.operator)` — and `base.py` never imported `Operator`, so every structured `select()`, `update()`, `delete()` and `count_matching()` on all four engines raised `NameError` at the first predicate. 2 277 passing tests did not notice, because exactly one test reached that signature and it asserted the `ValueError` `_check_one_where()` raises *before* the operator loop is entered; the free-form `where` fragment the user ruled for the row tools is what `mcp_server.py` actually builds, so no tool call walked the branch either. Public dialect API, no caller, no happy-path test. The sweep that replaces it is driven by the `Operator` enum itself, so a member added and forgotten fails at the table check rather than at the first caller. `gui/dialogs/mcp_config_dialog.py` built and the Settings page's Setup and Copy buttons wired to it — the first attempt left `_on_setup_clicked` and `_on_copy_clicked` as `.connect()` targets with no method definitions behind them, which Qt accepts silently at construction and only fails on the click. `show_sample_data` **defaulted to False** (user ruling), which is what exposed the empty-state layout bug: `empty_label` carried no stretch factor, so with the table hidden Qt redistributed the surplus height across every Preferred-policy widget above it and stranded the message below a pulled-apart title block — the first-run screen, on the page a first-run user opens. `tests/test_generated_config.py`: the wizard's own configuration launched as a **subprocess**, real JSON-RPC over stdio, `tools/list` asserted against a literal 38 names, and the three databases proved to have followed through the environment into `tmp_path`. Roughly 900 new tests, including the first coverage of `permissions_page.py`, `connections_page.py`, the i18n catalogue, the theme/language broadcast contract and window shutdown. **Four GUI defects fixed**, the two sharpest being a failed `grant()` leaving its checkbox ticked — a permission GUI showing more access than the engine would grant — and a language change re-opening the database connection, which on a locked vault could raise a master-password prompt the operator never asked for; the other two were three concurrent `_SchemaLoadWorker` threads from three quick combo changes, and that empty-state layout. `ruff`, `mypy` and `black` configured for the first time, with every setting and exclusion justified in `pyproject.toml` beside the setting itself — and then **`ruff` swept from 279 findings to zero** and `mypy` brought clean at its configured floor (62 source files, no issues; `--strict` remains a stated 34-error target across 18 files, almost all of it missing annotations). The sweep was not cosmetic: among the 279 were three `pytest.raises(match=...)` patterns that had been passing for the wrong reason — an unescaped `.` matching any character, and two alternations carrying a branch that could never fire — each traced back to the actual raise site and narrowed there rather than merely silenced, which is the same lesson as the `Operator` defect above: a test that passes is not the same as a test that checks. `settings.about_text` is a third instance of it — the string carried a `{version}` placeholder and `translate()` is a plain dictionary lookup that never calls `.format()`, so the Settings About group rendered the literal `SAPÉ d-MCP {version} — … — v0.1.0.8` on screen, in every one of the eighteen locales, with nothing failing. **User ruling:** `black` stays configured and deliberately unsatisfied — 68 of 92 files would be reformatted, and running it would land a formatting-only diff across three quarters of a hand-reviewed tree in the same commit as this stage's real fixes; `ruff` already enforces import order and the same 120-column limit, so nothing is unguarded meanwhile, and satisfying `black` is its own future commit. `.gitignore`, `gui_resources/flags/mapping.txt` rewritten against what actually ships, `CHANGELOG.md`. `sape-d-mcp.spec`: a one-directory PyInstaller bundle that builds, warns loudly when `collect_submodules()` silently drops a driver, and has been smoke-tested on Linux only — `docs/CROSS-PLATFORM-SMOKE-TEST.md` is the manual checklist for the other two platforms. 3 178 tests passing, 29 skipped |

### Proposed agents, skills and models

Model choice favours quality where a mistake is expensive — the permission engine, the SQL
guard and the MCP tool surface are where a subtle bug becomes data loss or exfiltration. GUI
work, routine implementation and packaging are specified tightly enough for Sonnet.

| Agent | Responsibility | Key skills | Model |
|---|---|---|---|
| **Orchestrator** (default) | Sole user-facing agent; coordinates, writes no code | planning, delegation, stage gating | Opus |
| **Software Architect** | Logical design, module boundaries, dialect abstraction | architecture, ADRs, packaging | Opus |
| **DB-Specialist** | Dialects, drivers, SQL, roles/permissions, introspection | SQL across 4 engines, DBA, driver matrix | Opus |
| **UIX-Designer** | PyQt6 pages, QSS, theming, i18n | PyQt6, Qt layouts, design tokens, a11y | Sonnet |
| **Python Senior** | Core implementation, refactoring | Python 3.10+, typing, async/anyio | Sonnet |
| **MCP-Engineer** | Tool catalogue, `mcp>=2.0` server, client config | MCP protocol, JSON-Schema, transports | Opus |
| **QA-Specialist** | Review, test, debug, assess | pytest, pytest-qt, security review | Opus |
| **Deployment Specialist** | Packaging, PyInstaller, cross-platform builds | setuptools, PyInstaller, CI | Sonnet |

---

## Dependencies

```
mcp>=2.0                      # 2.x MCPServer API; 1.x fails at import
PyQt6>=6.6.1                  # GUI only — main.py --cli never imports it
anyio>=4.0                    # used directly (BlockingPortal, CancelScope); f-MCP relies
                              # on it arriving transitively through mcp, which is a latent break
keyring>=24.0                 # OS credential stores
cryptography>=42.0            # AES fallback where no keyring backend exists
sqlparse>=0.5                 # statement classification in sql_guard
pyodbc>=5.0                   # MS-SQL, default — needs system ODBC Driver 18
pymssql>=2.3                  # MS-SQL, self-contained alternative
psycopg[binary]>=3.1          # PostgreSQL
PyMySQL>=1.1                  # MySQL/MariaDB, pure Python
mysql-connector-python>=8.3   # MySQL, Oracle driver alternative
# sqlite3 — standard library
```

Every pin carries an inline comment justifying its floor, as f-MCP's requirements files do.
Both MS-SQL drivers ship so the multi-platform promise never depends on an external installer;
the connection profile records which to use. `requirements-dev.txt` and the `dev` extra are
kept identical.

---

## Verification

- `pytest` — permission resolution (specificity, deny-wins, empty DB grants nothing),
  `sql_guard` classification including multi-statement and comment-smuggling attempts, and
  credential round-trips against a mocked keyring. Parametrise over the action tuples.
- Per-dialect integration tests: SQLite always; MS-SQL, PostgreSQL and MySQL against a real
  server when one is reachable, skipped with a clear marker otherwise. As shipped, the server is
  named by a `DMCP_TEST_PROFILE_MSSQL` / `_POSTGRESQL` / `_MYSQL` environment variable holding a
  JSON connection profile plus a `password` key, rather than by Docker: a JSON profile is the
  same shape the application itself stores, so the test connects the way the product does. With
  none of them set, 29 tests skip and each names exactly which variable it wanted.
- An end-to-end test in the style of `test_generated_config.py`: launch the exact command the
  wizard emits as a subprocess, speak JSON-RPC over stdio, assert `tools/list` returns exactly
  the expected names.
- `python main.py` on a clean checkout with **no** `.json`/`.db` present — it must create them
  in the directory it was launched from (`db_location.py`); check both themes, all 18 languages,
  and the legal pages.
- `python main.py --cli` in an environment without PyQt6 installed.
- Manual end-to-end: connect a real database, define a narrow rule, then from an MCP client
  confirm permitted reads succeed, non-permitted reads fail with a rule-citing error, and a
  `DROP` raises the GUI confirmation and is denied when refused — and that all three land in
  that connection's log tab. **Not done:** no MS-SQL, PostgreSQL or MySQL server was reachable
  from the development VM. This is §7 and §8 of the cross-platform checklist.
- Smoke test on Windows 10+, Linux and macOS before the stage-9 gate. Only Linux can be run
  from the development VM; the manual checklist for all three, and an explicit record of what
  the VM could **not** prove, is [`docs/CROSS-PLATFORM-SMOKE-TEST.md`](docs/CROSS-PLATFORM-SMOKE-TEST.md).
  It lives in its own file rather than in this list because it is a runbook executed on three
  machines with a terminal open beside it, not a statement of what must be true.

---

## Stage-1 gate items — resolved

Both were put to the user at the opening of stage 1 and are now recorded in the decisions
table above: a single tool set keyed by a `connection` enum, and a single `audit.db`
discriminated by `connection_id`.
