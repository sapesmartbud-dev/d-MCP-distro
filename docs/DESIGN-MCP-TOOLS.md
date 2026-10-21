# SAPÉ d-MCP — MCP tool catalogue, logical design

Stage 1 deliverable. Owner: MCP-Engineer. Status: **design only — no implementation**.

This document is the contract for `src/sape_d_mcp/mcp_server.py`. It fixes the tool names, their
signatures, their JSON-Schema surface, the permission action each one requires, the shape of
what each returns, and the cross-cutting rules (authorisation, row caps, transactions,
confirmation, audit) that every tool body obeys. Stage 6 (read tools) and stage 7 (write tools)
implement it; the QA-Specialist asserts against the table in §12.

Nothing here is written to disk at import time and nothing is seeded. A d-MCP with no
`connections.db` and no `permissions.db` starts, serves `tools/list`, and authorises nothing.

---

## 1. Scope and the decisions this design assumes

Settled before this document and not re-opened here:

| Decision | Consequence for the catalogue |
|---|---|
| **One tool set, not one per connection** | Every tool that reaches a database takes a required `connection` argument. The catalogue is a fixed 38 tools whatever the number of configured connections. |
| Permission granularity is `(connection_id, object_type) + a set of (schema_pattern, name_pattern) targets -> {action: bool}` | Every tool maps onto exactly one action from the fixed per-object-type tuples, resolved per referenced object. |
| Destructive operations need a permission flag **and** a live GUI approval | Four tools plus one conditional case route through `src/sape_d_mcp/confirmation.py`. Six more — the four `drop-*` and the two `edit-*` — are catalogued as destructive but **never reach the broker at all**: `docs/adr/0005-drop-and-edit-are-never-granted.md` made `drop` and `edit` prohibitions no rule can grant, checked and refused at the permission layer before confirmation is ever considered. §8.1 below has the detail; this row is left describing the design as it stood before that ADR, for the four tools it still applies to. |
| Credentials never leave the credential store | No tool takes, returns, generates or logs a password — including `create-user`. |
| `mcp>=2.0` | `from mcp.server import MCPServer`, `from mcp.types import ToolAnnotations`, tools as nested closures in one `_register_tools(self)`. |

The action tuples are owned by `src/sape_d_mcp/permissions.py` and are the single source of truth. This
document references them; it does not restate them as a second list, and it introduces **no new
actions**.

---

## 2. The `connection` parameter

### 2.1 Shape

`connection: str`, **required** (no default) on all 37 database-touching tools. It is always the
first parameter, and its `Args:` line is identical everywhere:

```
connection: Display name of the configured d-MCP connection to act on.
```

The generated JSON Schema for the property is:

```json
{
  "type": "string",
  "description": "Display name of the configured d-MCP connection to act on.",
  "enum": ["Payroll (MS-SQL)", "Warehouse (Postgres)", "Local scratch (SQLite)"]
}
```

The enum holds **display names, not ids**. Display names are `UNIQUE` in `connections.db`, are
what the human sees in the GUI and in the log tabs, and are what appears in a transcript the
human may later read. Integer ids are an implementation detail the model never sees; the
resolved `connection_id` is what `audit.db` stores.

Nothing else about the connection is exposed. `list-connections` returns the display name, the
engine, the database name and the default schema — **never the host, port, username, driver
string or any part of a DSN.** A host name in an LLM transcript is needless attack surface.

### 2.2 The enum is steering, not the security boundary

State this plainly in the module docstring, because it is the thing a future maintainer will get
wrong: the enum exists so the model does not waste turns guessing, and so a client that validates
schemas rejects nonsense locally. The boundary is `_resolve_connection()`, which looks the name
up in the live registry and raises `ValueError` on a miss. A client that ignores the schema, a
stale cached tool list, or a hand-written JSON-RPC frame all fail there. The enum can therefore
be absent (see §2.5) without weakening anything.

### 2.3 Regeneration: patch the schema, do not re-register the tool

```python
def refresh_connections(self) -> None:
    """Re-derive the `connection` enum from the registry and tell clients.

    Called by the GUI after any connection is added, renamed or deleted, and by
    the registry's own change poller (see 2.6). Cheap and idempotent.
    """
```

1. `names = self.connections.display_names()` — sorted, so two runs of `tools/list` on an
   unchanged registry are byte-identical (a churning enum invalidates client-side prompt caches
   for no reason).
2. For every entry in `self.server._tool_manager._tools.values()` whose input schema has a
   `connection` property, assign `prop["enum"] = names` — or delete the key when `names` is
   empty. One dict mutation per tool; the closures are untouched.
3. Increment `self._catalogue_revision` (used by the tests and shown in the GUI status bar).
4. Emit `notifications/tools/list_changed` (§2.4).

**Why not re-register.** Re-registration — building a fresh `Literal[...]` annotation and calling
`server.add_tool` / `remove_tool` for all 37 tools — is the obvious alternative and is rejected:
it churns tool identity for a change that alters one keyword in one property; it opens a window
in which `tools/list` returns a partial catalogue; and it would rebuild 37 closures on every
rename. Nothing in a tool closure depends on which connections exist, so nothing needs rebuilding.

The mutation reaches into `_tool_manager`, which is SDK-private. That is accepted deliberately —
it is the same private surface the test style already uses
(`server.server._tool_manager._tools[name].fn`) — and it is pinned by a test that adds a
connection and asserts the enum served by a real `tools/list` round-trip changed. If the 2.x SDK
caches a serialised schema alongside `Tool.parameters`, `refresh_connections()` must invalidate
that cache too; the test is what will catch it.

### 2.4 Emitting `notifications/tools/list_changed`

`refresh_connections()` is called from the **Qt GUI thread**; the MCP session lives on the server
thread's `anyio` event loop. Notifications must be scheduled across that boundary:

- When the server thread starts it opens an `anyio.from_thread.BlockingPortal` and stores it as
  `self._portal`. `refresh_connections()` patches the schema synchronously, then does
  `self._portal.start_task_soon(self._notify_tools_changed)`.
- `_notify_tools_changed()` calls the SDK's own helper if the 2.x `MCPServer` exposes one
  (`await self.server.notify_tool_list_changed()`); otherwise it walks the active sessions and
  awaits `session.send_tool_list_changed()` on each. Which of the two exists is verified at the
  start of stage 6 against the installed SDK — it is one line either way, and the fallback is the
  low-level protocol call, so the design does not depend on the answer.
- With no portal (server stopped, or a `--cli` process with no GUI), the schema is patched and no
  notification is sent. The next client to connect sees the current enum in its initial
  `tools/list`.
- Notification failures are swallowed and logged at `warning`, exactly as logging failures are.
  A client that never learns of the change simply sends a name the resolver then rejects.

`tools/list_changed` is a notification: there is no acknowledgement and no guarantee the client
re-reads the list. Everything downstream is therefore designed to be correct with a stale
catalogue.

### 2.5 Zero connections configured

A JSON-Schema `enum` may not be an empty array, so with an empty registry the `enum` keyword is
**removed** and the property description is replaced with:

```
"No d-MCP connections are configured. Add one in the d-MCP Connections page; no database
operation can succeed until then."
```

Every call then fails at `_resolve_connection()`:

```
ValueError: no database connections are configured; add one in the d-MCP Connections page
```

logged with `decision='denied_no_connection'`. Two alternatives were considered and rejected:

- **Removing the 37 tools from the catalogue** while the registry is empty. It produces the
  cleanest `tools/list`, but it makes the tool list flap on the very first connection, breaks
  clients that cache the catalogue at handshake, and gives the model no way to discover that the
  server exists but is unconfigured.
- **A sentinel enum value** such as `"(no connections configured)"`. Valid JSON Schema, but it
  invites the model to pass a value that can only ever fail, and it puts a fake connection name
  into transcripts and audit rows.

Dropping the keyword keeps one code path, one catalogue, and a single honest error. The
degenerate state is fail-closed by construction: with no connections there is no `connection_id`,
so there are no rules, so nothing is permitted.

### 2.6 Registry changes made in another process

The GUI and a client-spawned `--cli` server are **separate processes** sharing `connections.db`.
A connection added in the GUI never reaches the CLI server's in-memory registry through a Qt
signal. `ConnectionStore` therefore runs a poller on the server task: every 2 s it reads
`PRAGMA data_version` on its own SQLite handle — the value changes whenever *another* connection
commits to that database — and on a change reloads the registry and calls
`refresh_connections()`. This is the mechanism that makes `tools/list_changed` meaningful on
stdio, where the server is a subprocess of Claude Desktop and has no GUI at all.

### 2.7 A connection deleted while a call is in flight

Deletion is two-phase, and a running statement is never killed:

1. **Retire.** The row is marked retired in the registry, the enum is refreshed and
   `list_changed` is emitted. From this instant `_resolve_connection()` raises
   `ValueError: connection 'Payroll (MS-SQL)' is no longer configured` for any *new* call.
2. **Drain.** The engine holds a per-connection in-flight counter incremented by
   `_resolve_connection()` and decremented in the tool body's `finally`. The pool is closed once
   the counter reaches zero, or after a 5 s grace period — the same `wait(5000)`-then-force shape
   the server thread already uses for shutdown.

A call that resolved before retirement runs to completion and is audited normally against its
`connection_id`. A call still running at grace expiry has its pool closed underneath it; the
driver raises, and the tool emits a normal error result and an audit row with
`error='connection was closed while the statement was running'`. Killing a write mid-transaction
is worse than letting it finish, which is why the grace period exists at all.

`audit.db` keeps history for connections that no longer exist: `tool_calls` stores
`connection_id` **and** a `connection_name` snapshot, with no foreign key to `connections.db`
(they are separate files). The Logs page can therefore still render the tab for a deleted
connection.

---

## 3. The server class

### 3.1 Skeleton

```python
# <16-line GPL header>

"""The d-MCP server: database tools whose every reach is checked against the rule store."""

from __future__ import annotations

import logging
from typing import Any, Optional, TYPE_CHECKING

from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from sape_d_mcp._version import __version__
from sape_d_mcp.confirmation import ConfirmationBroker
from sape_d_mcp.db.connection_store import ConnectionStore
from sape_d_mcp.db.engine import EngineRegistry
from sape_d_mcp.db.introspection import Introspector
from sape_d_mcp.db.sql_guard import SqlGuard
from sape_d_mcp.permissions import PermissionStore
from sape_d_mcp.tool_logger import ToolLogger

if TYPE_CHECKING:
    from sape_d_mcp.log_store import LogStore

logger = logging.getLogger(__name__)

# Read caps. An LLM must not be able to pull a table into a context window, and
# a runaway SELECT must not be able to fill audit.db either. See section 6.
DEFAULT_ROW_LIMIT = 100
MAX_ROW_LIMIT = 1000
MAX_WRITE_ROWS = 1000
MAX_CELL_CHARS = 4096
CONFIRMATION_TIMEOUT_S = 120

# The statement timeout is a per-connection value (connections.statement_timeout_s),
# not a fixed cap: a warehouse connection running genuine analytics needs longer
# than a production OLTP one should ever be left holding a query. This is the
# default the column carries and the value used until an operator changes it.
# There is no per-call override — the model gets no lever over it. See §6.1.
DEFAULT_STATEMENT_TIMEOUT_S = 30

# Tools that must be approved by a human in the d-MCP window before they run,
# on top of the permission flag. 'update-rows' joins them only when the guard
# reports the statement has no effective WHERE. See section 8.
#
# Superseded in part by docs/adr/0005-drop-and-edit-are-never-granted.md: the four
# drop-* and the two edit-* below never actually reach this broker any more. 'drop'
# and 'edit' are refused by the permission layer first, unconditionally, so a human
# is never asked about any of the six. See §8.1.
BROKERED = frozenset({
    "delete-rows", "drop-table", "drop-view",
    "edit-function", "drop-function",
    "edit-procedure", "drop-procedure",
})


class DatabaseMCPServer:
    """An MCP server exposing database operations as tools.

    Access is governed entirely by the ``rules`` table of ``permissions.db``.
    Every object a statement references — through views, CTEs, subqueries and
    joins, not just the object named in the arguments — is resolved against the
    connection's introspected catalogue and authorised before any work happens.
    Objects no rule covers are refused. This is the database analogue of f-MCP
    resolving a path and its symlink target before acting: a view the caller may
    read grants nothing over the tables beneath it.
    """

    def __init__(
        self,
        connections_db: str | None = None,
        permissions_db: str | None = None,
        audit_db: str | None = None,
        user: str | None = None,
        name: str = "database-mcp-server",
        log_store: Optional["LogStore"] = None,
        session_id: Optional[str] = None,
        confirmation: Optional[ConfirmationBroker] = None,
    ) -> None: ...
```

Members created in `__init__`:

| Member | Purpose |
|---|---|
| `self.connections` | `ConnectionStore` — profiles, display-name lookup, the `data_version` poller. |
| `self.permissions` | `PermissionStore` — `is_allowed()` / `require()` per `(connection_id, schema, object_type, name, action)`. |
| `self.engines` | `EngineRegistry` — pooled connections, per-dialect session setup, in-flight counters. |
| `self.introspector` | `Introspector` — the catalogue used to validate every identifier. |
| `self.guard` | `SqlGuard` — parse, classify, enumerate referenced objects. |
| `self.confirmation` | `ConfirmationBroker` or `None`. `None` means every brokered tool is denied. |
| `self.logger` | `ToolLogger` — JSONL beside the DB plus the WAL SQLite store, keyed by `session_id` (`"cli"` for an externally spawned server). |
| `self.server` | `MCPServer` (§3.2). |
| `self.tool_executed_callback` | Set by the GUI, as in f-MCP. |
| `self._portal`, `self._catalogue_revision` | See §2.4/§2.3. |

`__init__` ends with `self._register_tools()` then `self.refresh_connections()`, in that order —
the enum can only be patched onto schemas that already exist.

`set_tool_executed_callback(callback)` and `set_log_store(log_store, session_id)` port from f-MCP
unchanged, including the `ValueError` when `session_id` is falsy.

### 3.2 Construction and the `instructions` string

```python
self.server = MCPServer(
    name=name,
    version=__version__,
    instructions=(
        "Database tools for SQL Server, PostgreSQL, MySQL and SQLite, over the connections "
        "configured in SAPÉ d-MCP. Every tool except list-connections takes a 'connection' "
        "argument naming one of those connections; call list-connections first if you do not "
        "know the names. Access is default-deny: an operation runs only where the human "
        "operator has granted that action, on that object, in that connection, and anything "
        "else is refused with the rule that denied it — call show-permissions to see what is "
        "granted before planning work rather than probing for it. Reads are capped at 100 rows "
        "by default and 1000 at most; page with limit and offset. Free-form SQL goes through "
        "run-read-query, which takes a single read-only statement and authorises every object "
        "it touches. Writes and DDL are here too, with one standing limit: the four drop-* "
        "tools and edit-function/edit-procedure are advertised but always denied, because d-MCP "
        "never destroys an object or replaces a routine body and no permission rule can "
        "authorise it — nothing created through d-MCP can afterwards be removed or redefined "
        "through it. The destructive tools that do run — delete-rows, an update-rows with no "
        "real WHERE, remove-user-from-group and revoke-role — additionally wait for a human to "
        "approve them in the d-MCP window, showing the exact statement and its estimated "
        "impact; with no window attached they are refused, so plan for that rather than "
        "retrying. Roles, users and groups have their own tools: they "
        "create principals, move them in and out of groups and grant or revoke roles, they "
        "never accept, set or return a password, and revoke-role and remove-user-from-group "
        "wait for the same human approval as delete-rows does. On MySQL an account is "
        "'name'@'host', "
        "so write the username or grantee as name@host there. SQLite has no principals at all "
        "and every one of those tools is refused on it. "
        "Every call is audited, whether it succeeded, failed or was refused."
    ),
)
```

It has to carry five facts the model cannot infer: destinations are named and enumerated; access
is granted rather than discovered; reads are capped; the four `drop-*` and two `edit-*` tools are
advertised but never actually run, whatever a rule says; and the remaining destructive operations
block on a human instead. The sentence about `show-permissions` is there to stop the classic
failure mode of an agent brute-forcing tables to find out what it may read — every probe is an
audited denial the human has to read later. **The `drop`/`edit` clause was added by
`docs/adr/0005-drop-and-edit-are-never-granted.md`**, which changed what a model is told about
those six tools from "needs approval" to "never runs" — telling a model to wait for an approval
that is never requested would leave it stalled on nothing.

### 3.3 Transports

```python
def run(self, transport: str = "stdio", **kwargs) -> None:
    """Run the server. Transport is 'stdio', 'sse' or 'streamable-http'."""
    self.server.run(transport=transport, **kwargs)
```

A passthrough, as in f-MCP. The GUI's `server_thread.py` rewrites `stdio` to `streamable-http`
before calling it, because stdio would block on stdin inside a `QThread`; that rewrite belongs to
the thread, not here.

---

## 4. The house tool body pattern

Every one of the 38 bodies has this shape. Deviating from it is a review failure.

```python
@server.tool(
    name="delete-rows",
    description=(
        "Delete rows from a table. Requires 'delete' permission on the table and "
        "approval in the d-MCP window. A call with no WHERE clause deletes every row."
    ),
    annotations=ToolAnnotations(title="Delete rows", destructive_hint=True),
)
def delete_rows(
    connection: str,
    table: str,
    where: str | None = None,
    parameters: dict[str, Any] | None = None,
    schema: str | None = None,
) -> str:
    """Delete rows from a table.

    Args:
        connection: Display name of the configured d-MCP connection to act on.
        table: Table name, optionally schema-qualified.
        where: SQL predicate. Omitting it deletes every row.
        parameters: Values bound to placeholders in `where`. Never interpolated.
        schema: Schema name. Defaults to the connection's default schema.
    """
    params = {"connection": connection, "table": table, "schema": schema,
              "where": where, "parameters": _bind_shape(parameters)}
    try:
        ctx = self._resolve_connection(connection)
        ref = self._object(ctx, table, schema, "table")
        self._authorise(ctx, "delete", ref)
        plan = self.guard.compose_delete(ctx.dialect, ref, where)
        self._authorise_statement(ctx, plan)          # every object the predicate reaches
        self._confirm(ctx, "delete-rows", plan.sql, self._impact(ctx, plan))
        affected = self.engines.execute(ctx, plan, parameters)
        result = f"Deleted {affected} row(s) from {ref}"
        self._emit_tool_executed("delete-rows", params, result, None,
                                 ctx=ctx, rows_affected=affected)
        return result
    except Exception as e:
        self._emit_tool_executed("delete-rows", params, None, str(e), ctx=locals().get("ctx"))
        raise
```

Fixed order, and the order is load-bearing:

**resolve connection → resolve identifiers → authorise → classify/compose → authorise every
referenced object → estimate impact → confirm → execute → emit → return.**

Two orderings that must never be swapped:

- **Authorise before confirming.** A human must never be shown a modal for an operation the rules
  already forbid. Otherwise a tired operator clicking Approve becomes a way to convert a denial
  into an execution, and the rule store stops being the boundary.
- **Confirm before executing.** Obvious, and the reason `self._confirm` returns `None` or raises
  rather than returning a boolean nobody checks.

Other invariants:

- **Stdlib exceptions only.** No result envelope, no error dict, no swallowed exception. The SDK
  turns the raised exception into a protocol error result.
- **Both branches emit.** Success and failure both produce exactly one audit row and one JSONL
  line. `_emit_tool_executed` wraps its own sinks in `try/except` so a logging fault can never
  break a tool — f-MCP's rule, kept.
- **`params` is built once, before the `try`,** so the failure branch logs the same dictionary the
  success branch does even when resolution was what failed.

### 4.1 Exception vocabulary

| Raised | When | Example message |
|---|---|---|
| `PermissionDenied(PermissionError)` | A rule refuses the action | `'select' is not permitted on dbo.Salaries (rule: dbo.*)` |
| `PermissionDenied` | No rule covers the object at all | `no permission rule covers dbo.Salaries on 'Payroll (MS-SQL)'` |
| `ActionForbidden(PermissionDenied)` | `drop` or `edit` was requested — categorically refused, per `docs/adr/0005-drop-and-edit-are-never-granted.md`; never reaches the confirmation broker | `'drop' is not permitted on public.wc2026_match (forbidden by d-MCP: destroying an object is never granted; no permission rule can authorise it)` |
| `PermissionError` | Confirmation refused, timed out, or no subscriber | `'delete-rows' needs approval in the d-MCP window, and no d-MCP window is attached` |
| `ValueError` | Unknown connection; unnormalisable or ambiguous identifier; SQL the guard cannot classify; a limit out of range | `permission checks require a schema-qualified name, got 'Salaries'` |
| `LookupError` | The object is not in the connection's catalogue | `no table 'dbo.Salries' on 'Payroll (MS-SQL)' (did you mean dbo.Salaries?)` |
| `TimeoutError` | Statement timeout | `statement exceeded the connection's statement timeout (30 s) and was cancelled` |
| `RuntimeError` | Driver or engine fault | `the database refused the statement: <scrubbed driver message>` |

Every message is actionable: it names the object, the connection, and what would make the call
succeed. Denial messages cite the matched rule, in the same shape f-MCP uses:

```
'select' is not permitted on dbo.Salaries (rule: dbo.*)
```

**Driver messages are scrubbed** before they are re-raised or logged. A `pyodbc` failure can echo
the whole DSN including `PWD=`; `_scrub()` strips any `PWD=`/`PASSWORD=`/`pwd=` fragment and any
occurrence of the live credential. A credential must never reach a transcript, an error string or
`audit.db`.

---

## 5. Authorising every referenced object

The filesystem analogue is exact: f-MCP authorises a path *and its symlink target* for any
operation that dereferences, because a link planted inside an allowed directory would otherwise
reach a path no rule covers. In a database, views, CTEs, subqueries, joins, synonyms and
table-valued functions are the links.

`SqlGuard` returns a `StatementPlan` carrying `sql`, `classification`, `is_read_only`,
`has_effective_where`, and `references: tuple[ObjectRef, ...]`. `_authorise_statement()` walks
`references` and calls `self.permissions.require(...)` for each, with the action implied by how
the object is used (`select` for a table or view read as a source). A function called as a
source carries no action of its own — `function` has no `select` or `execute` entry in
`ACTIONS_BY_TYPE` (there is no `execute-function` tool to grant one for, §11.5) — so it is
transparently expanded like a view: `select` is required on every object its body reads, never
on the function itself.

Consequences that are easy to get wrong and must be tested:

- **`select-view-rows` requires `select` on the view *and* `select` on every base object the view
  resolves to, transitively.** A grant on a view is not a grant on what it reads. The view's
  definition is expanded through the introspected catalogue, not by trusting the engine.
- **`create-view` requires `create` on the view *and* `select` on every object its body
  references.** Without that, `create-view` followed by `select-view-rows` is a two-step
  escalation straight around the rule store.
- **`create-function` / `edit-function` / `create-procedure` / `edit-procedure`** authorise the
  objects their bodies reference on the same principle. A routine body that cannot be parsed
  confidently is refused, not guessed at.
- **A `where` fragment is free-form SQL.** `select-rows`, `update-rows` and `delete-rows` compose
  the full statement and re-parse the composed text through the same guard as `run-read-query`, so
  a subquery in the predicate reaching an unauthorised table is caught.
- **A CTE alias defined in the same statement is not an object** and is not looked up in the
  catalogue; the objects the CTE itself reads are.
- **List-shaped tools hide rather than refuse.** `list-tables`, `list-views`, `list-functions`,
  `list-procedures` and `list-schemas` filter out anything the caller lacks `list` on and return
  what remains, exactly as f-MCP's `list` does. A caller with no `list` grant anywhere gets an
  empty list, not an error — refusing the whole call would leak the existence of objects through
  the difference between "empty" and "denied".
- **Internal catalogue lookups are not an authorised action.** Resolving `Salaries` to
  `dbo.Salaries` to check a rule reads the catalogue but returns nothing to the model, so it
  needs no grant. Only catalogue data *returned to the model* costs `read_catalogue` or
  `read_structure`.

---

## 6. Row caps, pagination and result shapes

### 6.1 Caps

`limit: int = DEFAULT_ROW_LIMIT` (100) and `offset: int = 0` on every row-returning tool.
`limit` is clamped by validation, not silently: a value above `MAX_ROW_LIMIT` (1000) or below 1
raises `ValueError: limit must be between 1 and 1000, got 50000`. Silent clamping would let the
model believe it had a complete result set.

Truncation is detected by fetching `limit + 1` rows and discarding the extra — no `COUNT(*)`,
which on a large table costs more than the query. Cell values longer than `MAX_CELL_CHARS` (4096)
are cut with a trailing `…` and the envelope's `cells_truncated` flag is set.

Also applied to every statement: a timeout, set per dialect at session level from the
**connection's own** `statement_timeout_s`, not a fixed constant. It lives on the connection
profile and defaults to `DEFAULT_STATEMENT_TIMEOUT_S` (30 s), so an operator can raise it for a
warehouse connection whose genuine analytical queries would otherwise be killed, or leave it low
on a production OLTP connection a pathological join must not be allowed to tie up. There is
deliberately **no per-call `timeout_s` parameter**: the model gets no lever over how long its own
statement may run — that decision belongs to whoever configured the connection, not to whoever
is calling it. Caps bound the payload; the timeout bounds the damage a pathological join can do
to the production server the human pointed us at.

### 6.2 Three result shapes

| Shape | Used by | Rationale |
|---|---|---|
| **`str` summary** | Every mutating tool, every DDL tool, every security tool | `"Deleted 12 row(s) from dbo.Audit"`. There is no payload; a sentence is what the model needs and what reads well in the log. |
| **`list[dict]`** | `list-connections`, `show-permissions`, `list-schemas`, `list-roles`, `list-users`, `list-groups`, `list-tables`, `list-views`, `list-functions`, `list-procedures` | Bounded, self-describing catalogue data with no truncation to signal. |
| **`dict` envelope** | `select-rows`, `select-view-rows`, `run-read-query` | Truncation must be machine-visible, and a bare list has nowhere to put it. |

`describe-table`, `read-view-definition`, `read-function-definition`,
`read-procedure-definition` and `read-catalogue` return a single `dict`.

### 6.3 The row envelope

```python
{
  "columns": [{"name": "id", "type": "int"}, {"name": "surname", "type": "nvarchar(80)"}],
  "rows": [{"id": 1, "surname": "Arrezze"}, ...],
  "row_count": 100,
  "truncated": True,
  "next_offset": 100,
  "row_cap": 100,
  "cells_truncated": False,
}
```

`next_offset` is `offset + len(rows)` when truncated and `None` otherwise, so the model can page
without arithmetic. `columns` carries declared types so the model can interpret the values it
gets back.

Value serialisation, fixed across all four dialects so a result does not change shape with the
engine: dates and timestamps as ISO 8601 strings; `Decimal` as a **string**, never a float, so
money never silently loses precision on its way through JSON; `bytes` as base64; `None` as JSON
null; a UUID as its canonical string.

**Ordering.** `OFFSET` without `ORDER BY` is not stable on any of the four engines. Row-returning
tools take `order_by: str | None = None`, validated against the introspected column list of the
object being read (an unknown column is a `ValueError`, never interpolated). When it is omitted
and `offset > 0`, the tool description and the docstring both say the page may overlap or skip
rows — this is a database property, not something a wrapper can fix, so it is documented rather
than hidden.

### 6.4 What goes into the log is not what goes back to the client

f-MCP's `list` returns the listing but logs `"Listed 194 entries"`. d-MCP generalises the habit:
**every audit row and JSONL line records a short summary string, never the payload.** A 1000-row
read logs `"Selected 1000 row(s) from dbo.Customers (truncated)"`. Reasons: `audit.db` would
otherwise become a mirror of the production data it is meant to police, the 10 000-row rotation
would evict real history within a session, and the Logs page would be unreadable.

The same rule applies to arguments. `params_json` stores structural information only:

- `rows`, `values` and `parameters` are logged as **counts, key names and value types** —
  `{"rows": {"count": 3, "keys": ["id", "surname"]}}` — never values.
- The composed SQL is stored with its **placeholders intact**, never with binds interpolated.

That is what makes the audit trail defensible under the project's own DATA-PROTECTION policy: it
records what was done, to which objects, by which decision, without becoming a second copy of the
personal data.

---

## 7. Transactions

**Write tools autocommit. The LLM gets no transaction control. There are no
`begin`/`commit`/`rollback` tools.**

Justification:

1. **MCP calls are independent.** There is no guarantee the same client, session or even process
   makes the next call. A transaction opened by one tool call and left for another to close is a
   lock held across an unbounded gap.
2. **Models forget.** An agent that opens a transaction and then hits a context limit, an error,
   or a user interruption leaves a write transaction open against production. On SQL Server that
   blocks readers; on Postgres it pins the xmin horizon and stops vacuum. The failure mode is an
   outage, hours later, that nobody attributes to the MCP server.
3. **Pooling.** A transaction pins its pooled connection, so a forgotten one removes a connection
   from the pool permanently.
4. **The guard already forbids multi-statement batches**, which is the only thing cross-call
   atomicity would buy.

Where atomicity genuinely matters, the **tool body** opens and commits its own transaction, and
that transaction never outlives the call:

- `insert-rows` with several rows — one transaction, so a partial batch never lands.
- `edit-function` / `edit-procedure` on engines with no `CREATE OR REPLACE`, where the operation
  is a `DROP` followed by a `CREATE`.

**The MySQL exception, stated rather than hidden.** MySQL commits implicitly on DDL, so a
`DROP`-then-`CREATE` routine edit cannot be atomic there. Mitigation: `edit-function` and
`edit-procedure` read and keep the existing definition *before* dropping, include it verbatim in
the error message if the `CREATE` fails, and record it in the audit row — so the human has the
text needed to restore it. **This paragraph describes the composition code, which stays and stays
tested; it does not describe a live path any more.** `docs/adr/0005-drop-and-edit-are-never-granted.md`
made `edit` a categorical prohibition, so `edit-function` and `edit-procedure` are refused by the
permission layer before either tool body runs — the human approval this paragraph used to promise
is never actually requested, because the call never reaches that point.

---

## 8. The destructive set and the confirmation broker

### 8.1 The set

**Superseded in part by `docs/adr/0005-drop-and-edit-are-never-granted.md`.** This section
originally described all ten destructive tools as reaching the broker; that is no longer true for
six of them. `drop` and `edit` are now categorical prohibitions, checked and refused in
`PermissionStore.is_allowed()`/`.require()` **before** a tool body ever calls the confirmation
broker — no rule can grant either action, so no approval is ever requested for the six tools
below, whatever the table said before. The tools stay in `BROKERED` in the source (removing them
would be the obvious, and wrong, first edit — see the ADR), which is why the "Brokered" column
below still names them; read it as "would be brokered if the permission layer let the call
through", not as "waits on a human today".

| Tool | Brokered | Note |
|---|---|---|
| `drop-table`, `drop-view`, `drop-function`, `drop-procedure` | **never reached — `drop` is refused outright** | Categorically forbidden since ADR 0005. Every call is denied and audited before the broker is asked; the object cannot be dropped through d-MCP by any route. |
| `delete-rows` | always | Even with a WHERE. Deleted rows do not come back. |
| `edit-function`, `edit-procedure` | **never reached — `edit` is refused outright** | Categorically forbidden since ADR 0005, for the same reason: replacing a body is destroying the old one, and no rule can grant it. The routine cannot be replaced through d-MCP by any route. |
| `remove-user-from-group`, `revoke-role` | always | **User ruling** — see below. Reversible with their opposite tool, but not necessarily *by whoever just lost the access*. |
| `update-rows` | **only when the statement has no effective WHERE** | `guard.has_effective_where` is False for a missing WHERE *and* for a predicate that references no column (`WHERE 1=1`, `WHERE 'a'='a'`). A tautology is not a filter. |

That is **ten** destructive operations, but only **four** now reach the broker unconditionally,
one more conditionally, and **six never reach it at all** — refused at the permission layer with
`ActionForbidden` instead. §4.1's exception table and the ADR itself have the exact wording.

Everything brokered carries `ToolAnnotations(destructive_hint=True)`, and — the invariant, worth
more than any individual nuance — **nothing carries `destructive_hint=True` unless it is
brokered.** `update-rows` is the one tool whose annotation is static while its behaviour is
conditional; it is annotated `destructive_hint=True` because that is the truthful hint for the
worst case it can perform.

**`remove-user-from-group` and `revoke-role`, resolved by the user as: brokered.** This section
first placed them among the additive tools, reasoning that each is reversed by its opposite tool
and that brokering a tool annotated `destructive_hint=False` would make the annotation a lie —
`db/security.py`'s class docstring was written on the strength of that and records it. The user
ruled the other way, and the ruling is the design now: *reversible* is not the same as
*reversible by whoever just lost the access*. Revoke the last administrator's role and no
principal remains that may grant it back from inside d-MCP, and no amount of `assign-role`
afterwards helps. A human shown the principal and the role **before** it happens is worth two
more tools that block when nobody is watching. Both are annotated `destructive_hint=True`, so the
invariant holds in the direction that costs nothing and is enforced by equality in
`test_nothing_is_annotated_destructive_unless_it_is_brokered`.

Their impact line is words rather than SQL, which is the one place the estimate is not a count:
an approver reading `REVOKE "analyst" FROM "alice"` should be told what alice loses, and no
`SELECT COUNT(*)` answers that. What a revoke does is a fact about its arguments, so the impact
names the principal, names the role, says that sessions already open may keep the access until
they reconnect, and says what putting it back requires. The statement itself is shown beside it,
exactly as for every other brokered tool.

The mechanics: `SecurityManager.revoke_role()` and `.remove_user_from_group()` take an `approve`
callable and invoke it with the built `Script` after their own lexical tripwire has passed every
step and before the first one runs. The MCP layer passes a callable that raises unless a human
approves. Composing the statement twice — once to show, once to run — was rejected: the object a
human approved is then the identical object that executes, and MySQL's `'name'@'host'` rule
keeps the single reader `db/security.py` insists on.

The other five security tools remain additive and unbrokered: the three `create-*` produce a
principal that holds nothing, and `add-user-to-group` / `assign-role` are the granting direction.

Deliberately **not** destructive:

- `insert-rows`, `create-table`, `create-view`, `create-function`, `create-procedure` — additive.
  `create-*` **rejects any `OR REPLACE`, `CREATE OR ALTER` or equivalent clause in the supplied
  body or generated DDL**, and raises `ValueError` on a name that already exists. Otherwise
  `create-function(or_replace=True)` would be `edit-function` in disguise. Replacing an object is
  `edit-*`, and since ADR 0005, `edit-*` is not brokered at all — it is refused outright, which is
  one more reason `create-*` cannot be allowed to double as a replace path.
- `create-role`, `create-user`, `create-group`, `add-user-to-group`, `assign-role` — additive.
  A created principal holds nothing until a human grants it something, and the two granting
  directions add access rather than taking it away. `create-user` sets no password and creates a
  principal that cannot log in at all (§11.2), which is as additive as a user gets.
- `create-table` on a table name that exists — `ValueError`, never an implicit replace.

### 8.2 Broker contract

```python
self.confirmation.request(
    connection=ctx.display_name,
    tool_name="drop-table",
    sql=plan.sql,                       # the exact statement, placeholders intact
    impact="dbo.Salaries — 4 812 rows, 2 dependent views",
    timeout=CONFIRMATION_TIMEOUT_S,
) -> None                               # returns on approval, raises PermissionError otherwise
```

- **No subscriber attached ⇒ denied immediately**, with no timeout wait, `PermissionError`, and
  an audit row with `decision='denied_no_subscriber'`. This is the normal state of a `--cli`
  server spawned by Claude Desktop with the GUI closed, and it is the intended behaviour: with
  nobody watching, nothing irreversible happens.
- Timeout ⇒ denied, `decision='denied_timeout'`. Silence is refusal.
- Explicit refusal ⇒ denied, `decision='denied_operator'`.
- **Approval is single-use and bound to the exact `(connection, tool_name, sql)` triple**, and is
  consumed by the call that requested it. There is no blanket approval, no "approve all", no
  remembered decision, and no approval that survives a change to the statement text.
- The modal shows the connection display name, the exact SQL, and the impact estimate.

**Impact estimation** runs before the modal and is read-only: a `SELECT COUNT(*)` with the same
predicate for `delete-rows` and an unqualified `update-rows`; row count and dependent-object count
for `drop-*`; the current definition's line count for `edit-*`. It runs under the authorisation
already established, on the read-only session, under the statement timeout. If it fails, the modal
says `impact could not be estimated` — a failed estimate does not block the operation, but it does
tell the human they are approving blind.

The broker call is a blocking wait on the server task; it must be `await`ed through an anyio
event so it does not block the event loop, and it must respect the server thread's cancel scope so
a Stop while a modal is open tears down cleanly rather than hanging the 5 s shutdown grace.

---

## 9. Free-form SQL: `run-read-query`

`prompt.md` requires "cualquier otro tipo de consulta de lectura" in three of the four groups.
One tool serves all of them, and it is the single most dangerous thing in the catalogue, so its
gate is specified as a checklist the implementation must satisfy in order.

```python
@server.tool(
    name="run-read-query",
    description=(
        "Run one read-only SQL statement and return its rows. A single SELECT (or a WITH whose "
        "CTEs are all SELECTs); anything else, including multiple statements, is refused. "
        "Requires 'run_query' on this connection, plus 'select' permission on every table and "
        "view the statement reads — including, transitively, every object read by a function "
        "it calls. Bind values through `parameters` rather than writing them into the SQL."
    ),
    annotations=ToolAnnotations(title="Run a read-only query", read_only_hint=True),
)
def run_read_query(
    connection: str,
    sql: str,
    parameters: dict[str, Any] | None = None,
    limit: int = DEFAULT_ROW_LIMIT,
    offset: int = 0,
) -> dict: ...
```

### 9.1 The gate, in order

1. **Authorise `run_query` on the connection.** This is the per-connection switch (§1, §12): the
   `database` action tuple carries `run_query`, deny-by-default like every other action, so an
   operator can leave a connection reachable only through the structured tools by simply never
   granting it. Checked first and cheaply, before anything is even parsed —
   `PermissionDenied: 'run_query' is not permitted on 'Payroll (MS-SQL)'`.
2. **Split.** `sqlparse.split(sql)` must yield exactly one non-empty statement. Two or more ⇒
   `ValueError: run-read-query accepts a single statement; 2 were supplied`.
3. **Strip comments, then split again.** If the statement count changes once comments are
   removed, the input was comment-smuggled ⇒ refused. Classification then runs on the
   comment-stripped text, so `SELECT 1 --\n; DROP TABLE x` cannot classify as a SELECT while the
   engine sees two statements.
4. **No batch separators.** A bare `GO` line (SQL Server), a stray `;`, or a `\g` is refused
   before parsing.
5. **Classify.** Only `SELECT`, and `WITH` where every CTE body *and* the outer statement are
   SELECTs, pass. Explicitly refused: `INSERT`/`UPDATE`/`DELETE`/`MERGE`; writing CTEs
   (`WITH x AS (INSERT ... RETURNING ...)`); `SELECT ... INTO`; `SELECT ... FOR UPDATE` /
   `FOR SHARE`; `EXEC`/`CALL`/`DO`; `SET`, `USE`, `PRAGMA`, `ATTACH`, `BEGIN`, any DDL; and
   anything procedural.
6. **Unclassifiable is refused.** `ValueError: this statement could not be classified as
   read-only and was refused`. Unknown is never allowed — this is the rule the whole design
   leans on, and the reason the guard may be conservative to the point of inconvenience.
7. **Denylist of file- and OS-reaching constructs**, checked per dialect against every function
   and keyword token even though step 5 should already have caught them, because these are the
   ones that turn a read into an exfiltration or an RCE: `xp_cmdshell`, `sp_executesql`,
   `OPENROWSET`, `OPENDATASOURCE`, `EXEC(...)`, `pg_read_file`, `pg_ls_dir`, `lo_import`,
   `lo_export`, `COPY ... TO PROGRAM`, `dblink`, `LOAD_FILE`, `INTO OUTFILE`, `INTO DUMPFILE`,
   `ATTACH DATABASE`, `readfile`, `writefile`, `load_extension`.
8. **Enumerate every referenced object** — FROM, every JOIN, every subquery at any depth, every
   CTE's own sources, `APPLY`/`LATERAL`, and table-valued function calls. Resolve each against the
   introspected catalogue, qualifying with the connection's default schema. **An object that is
   not in the catalogue is refused**, not passed through: what cannot be resolved cannot be
   authorised, and a made-up name reaching the engine is how a typo becomes a probe.
9. **Authorise each one**: `select` for a table or view, plus the transitive base objects of any
   view (§5). A function used as a source carries no action of its own — there is no
   `execute-function` tool, and no `select`/`execute` entry for `function` in `ACTIONS_BY_TYPE` —
   so it is expanded the same way: `select` is required on every object *its* body reads.
10. **Bind, never interpolate.** `parameters` values are bound by the driver. The tool never
    formats a value into `sql`. Identifiers in the model's SQL are validated against the catalogue
    and re-emitted with the dialect's own quoting.
11. **Execute on a read-only session.** `SET TRANSACTION READ ONLY` (PostgreSQL),
    `SET SESSION TRANSACTION READ ONLY` (MySQL), `PRAGMA query_only = ON` (SQLite), and on SQL
    Server an explicit read-only transaction plus, where the profile provides one, a read-only
    login. This is defence in depth: even a guard miss cannot write. A guard that is the only
    line of defence is one bug away from being none.
12. **Cap and time-limit** as in §6.

### 9.2 What this deliberately does not become

`run-read-query` is not a way to reach a connection the operator has not opted into, because step 1
gates on `run_query` before anything else runs. It is not a way to reach objects
the rules do not cover, because step 9 applies the identical `require()` calls that `select-rows`
makes. It is not a way to run one statement whose classification is arguable, because step 6
refuses. It is not a way to write, because steps 5, 7 and 11 each independently stop it. Its only
privilege over `select-rows` is expressiveness — joins, aggregates, window functions — over
objects the caller could already read one at a time.

The test the QA-Specialist writes for this is
`test_a_drop_cannot_be_smuggled_through_run_read_query`, parametrised over stacked statements,
comment smuggling, writing CTEs, unicode and quoting tricks per dialect, and identifier injection
through the schema and object names.

---

## 10. Audit

Every call produces exactly one `tool_calls` row in `audit.db` and one JSONL line, whether it
succeeded, failed or was refused. `_emit_tool_executed` keeps f-MCP's positional signature and
extends it with keyword-only audit fields:

```python
def _emit_tool_executed(
    self,
    tool_name: str,
    params: dict,
    result: str | None = None,
    error: str | None = None,
    *,
    ctx: "ConnectionContext | None" = None,
    decision: str = "allowed",
    rows_affected: int | None = None,
    duration_ms: int | None = None,
    matched_rule_id: int | None = None,
) -> None: ...
```

Columns written: `connection_id`, `connection_name`, `session_id`, `timestamp` (ISO 8601 with
offset), `tool_name`, `params_json` (structural only, §6.4), `rows_affected`, `duration_ms`,
`result` (short summary), `error`, `decision`, `matched_rule_id`.

`decision` is a module-level tuple in `permissions.py`, so the GUI filter, the CSV export, the
column check constraint and the tests all read one list:

```
allowed · denied_rule · denied_guard · denied_no_subscriber · denied_operator ·
denied_timeout · denied_no_connection · error
```

Rules that hold without exception:

- **A denial is a logged event, not a silent no-op.** `decision='denied_rule'` rows carry
  `matched_rule_id`, so the Permissions page can show the human which of their rules refused the
  call, and the Logs page can link straight to it.
- **A connection with no `connection_id` still logs.** An unresolvable connection name writes a
  row with `connection_id = NULL` and `connection_name` set to whatever the model sent; those
  land in an "Unassigned" tab. Losing the record of a call that named a connection that does not
  exist would hide exactly the probing behaviour the log is for.
- **Logging never propagates.** Both sinks are individually wrapped; a failure logs at `warning`
  and the tool continues, as in f-MCP.
- WAL, and the same 10 000/1 000 rotation by `id` with no `VACUUM`.

---

## 11. The catalogue

38 tools. The Python function name is the tool name with hyphens replaced by underscores in
every case; the table in §12 marks it explicitly. All of them are nested closures inside
`_register_tools(self)`. Each has a Google-style docstring with an `Args:` block whose first
entry is the standard `connection` line from §2.1; it is written out once below and elided as
`# … standard Args block …` thereafter to keep this document readable, not because it is optional.

### 11.1 Meta

```python
@server.tool(
    name="list-connections",
    description=(
        "List the database connections configured in SAPÉ d-MCP. Use the display_name of one "
        "of these as the 'connection' argument of every other tool. This is the only tool that "
        "does not take a connection."
    ),
    annotations=ToolAnnotations(title="List connections", read_only_hint=True),
)
def list_connections() -> list[dict]:
    """List the configured connections.

    Returns one entry per connection with its display name, engine, database and
    default schema. Host, port, username and driver details are deliberately not
    exposed: they are of no use in planning a query and do not belong in a
    transcript.
    """
```
Returns `[{"display_name", "engine", "database", "default_schema", "rule_count", "reachable"}]`.
No permission action; logged. `reachable` reflects the last health check, not a fresh connect —
`list-connections` must stay cheap enough to be the model's first call.

```python
@server.tool(
    name="show-permissions",
    description=(
        "Show every permission rule in force for a connection: which actions are allowed on "
        "which schemas and object patterns. Each rule also carries the operator's own name "
        "for it where they gave it one, which says what the rule is for rather than merely "
        "what it matches. Call this before planning work rather than discovering the limits "
        "by being refused."
    ),
    annotations=ToolAnnotations(title="Show permissions", read_only_hint=True),
)
def show_permissions(connection: str) -> list[dict]:
    """Show the permission rules for one connection.

    Args:
        connection: Display name of the configured d-MCP connection to act on.
    """
```
Returns `[{"rule_name", "object_type", "targets", "is_deny", "allowed_actions", "created_at",
"user_created", "updated_at", "user_updated"}]`, where `targets` is
`[{"schema_pattern", "name_pattern"}, ...]` —
a rule names a *collection* at `permissions.db` schema version 2 — and `allowed_actions` is derived
from the `can_*` columns through the action tuple, the same transform f-MCP does. **No scalar
`schema_pattern` alias is kept beside `targets`**: a scalar holding "the first target" would be a
half-truth about a rule's reach, and a half-truth is worse for a model deciding what it may touch
than a shape it has to read properly. No action required:
it reveals what was granted, which is the information that stops the model probing. Scoped to one
connection; it never reveals rules for another.

`rule_name` arrived at `permissions.db` schema version 3 and is the operator's own label for the
rule — the answer to *what is this rule for*, which the patterns alone never give. It is
deliberately part of what the model sees: two broad `dbo`/`rpt_*` rules are indistinguishable by
pattern, and a model planning work against them is better served by "Reporting read-only" than by
guessing. The key is **always present and holds `null` for a rule nobody has named**, rather than
being omitted: this is a JSON array read row by row, every row carrying the same keys is what makes
it readable as a table, and `null` says *unnamed* where `""` would read as a name that happens to
be empty. `main.py`'s `--show-permissions` prints nothing at all for an unnamed rule instead — that
is human text, where a column of `None` is noise. The asymmetry between the two is intended; do not
"correct" either to match the other.

The name is metadata and nothing else. `rule_for()` never reads it, so it cannot change what a rule
authorises, and it is operator-authored free text — the same trust level as the rule it labels —
validated on the way in (no control characters, at most `MAX_RULE_NAME_LENGTH` = 80 characters,
unique per connection), so it needs no treatment on the way out beyond the JSON encoding every
other string value gets. The `outputSchema` the SDK derives from the `list[dict]` annotation is
`{"type": "array", "items": {"type": "object", "additionalProperties": true}}`, so the shape
declared to the client is satisfied by the added key; this section is the contract that had to be
kept in step with it.

### 11.2 Database and security

```python
@server.tool(
    name="read-catalogue",
    description=(
        "Read a summary of the database: engine and version, default schema, and how many "
        "schemas, tables, views, functions and procedures it holds. Requires 'read_catalogue'."
    ),
    annotations=ToolAnnotations(title="Read database catalogue", read_only_hint=True),
)
def read_catalogue(connection: str) -> dict: ...

@server.tool(
    name="list-schemas",
    description="List the schemas in the database. Requires 'read_catalogue'.",
    annotations=ToolAnnotations(title="List schemas", read_only_hint=True),
)
def list_schemas(connection: str) -> list[dict]: ...

@server.tool(
    name="list-roles",
    description="List the database roles and who holds them. Requires 'read_catalogue'.",
    annotations=ToolAnnotations(title="List roles", read_only_hint=True),
)
def list_roles(connection: str) -> list[dict]: ...

@server.tool(
    name="list-users",
    description="List the database users. Requires 'read_catalogue'.",
    annotations=ToolAnnotations(title="List users", read_only_hint=True),
)
def list_users(connection: str) -> list[dict]: ...

@server.tool(
    name="list-groups",
    description=(
        "List the groups (SQL Server database roles used as groups, PostgreSQL NOLOGIN roles, "
        "MySQL roles) and their members. Requires 'read_catalogue'."
    ),
    annotations=ToolAnnotations(title="List groups", read_only_hint=True),
)
def list_groups(connection: str) -> list[dict]: ...
```

`read-catalogue` returns a `dict`; the four list tools return `list[dict]` and log a summary
(`"Listed 12 schemas"`). SQLite has no roles, users or groups: those three tools raise
`NotImplementedError("SQLite has no role, user or group concept")` rather than returning an empty
list that would read as "there are none".

```python
@server.tool(
    name="create-role",
    description="Create a database role. Requires 'create_role'.",
    annotations=ToolAnnotations(title="Create role", destructive_hint=False),
)
def create_role(connection: str, role: str) -> str: ...

@server.tool(
    name="create-user",
    description=(
        "Create a database user. No password is accepted or set: the user is created without "
        "the ability to log in, and a human sets its credential outside this tool. "
        "Requires 'create_user'."
    ),
    annotations=ToolAnnotations(title="Create user", destructive_hint=False),
)
def create_user(
    connection: str,
    username: str,
    default_schema: str | None = None,
    login: str | None = None,
) -> str: ...
```

**`create-user` takes no password, by design.** No credential is ever accepted from a model,
generated by a tool, returned in a result or written to a log. On SQL Server the tool creates a
contained user or maps to the existing `login` given; on PostgreSQL a `NOLOGIN` role; on MySQL a
user with an unusable authentication string. The result string says so explicitly, so the model
reports the follow-up rather than inventing a password:
`"Created user 'reporting' with no login; a d-MCP operator must set its credential before it can connect"`.

```python
@server.tool(
    name="create-group",
    description="Create a group. Requires 'create_group'.",
    annotations=ToolAnnotations(title="Create group", destructive_hint=False),
)
def create_group(connection: str, group: str) -> str: ...

@server.tool(
    name="add-user-to-group",
    description="Add a user to a group. Requires 'assign_group'.",
    annotations=ToolAnnotations(title="Add user to group", destructive_hint=False),
)
def add_user_to_group(connection: str, username: str, group: str) -> str: ...

@server.tool(
    name="remove-user-from-group",
    description=(
        "Remove a principal from a group. Requires 'assign_group' AND approval in the d-MCP "
        "window: add-user-to-group reverses it, but not necessarily as whoever has just lost "
        "the access. Refuses outright to strip the login this connection is running as. On "
        "MySQL write the username as name@host."
    ),
    annotations=ToolAnnotations(title="Remove user from group", destructive_hint=True),
)
def remove_user_from_group(connection: str, username: str, group: str) -> str: ...

@server.tool(
    name="assign-role",
    description="Grant a role to a user, group or another role. Requires 'assign_role'.",
    annotations=ToolAnnotations(title="Assign role", destructive_hint=False),
)
def assign_role(connection: str, role: str, grantee: str) -> str: ...

@server.tool(
    name="revoke-role",
    description=(
        "Revoke a role from a user, group or another role. Requires 'assign_role' AND "
        "approval in the d-MCP window. assign-role puts it back only while some principal "
        "that may still grant the role exists. Refuses outright to strip the login this "
        "connection is running as. On MySQL write the grantee as name@host."
    ),
    annotations=ToolAnnotations(title="Revoke role", destructive_hint=True),
)
def revoke_role(connection: str, role: str, grantee: str) -> str: ...
```

`prompt.md`'s "asignar/reasignar roles" is served by the `assign-role` / `revoke-role` pair rather
than one tool with a `revoke: bool` flag. A boolean that inverts a tool's meaning is the kind of
argument a model gets wrong, and it makes the audit row harder to read at a glance. The pair
mirrors `add-user-to-group` / `remove-user-from-group`, and both members of each pair share one
action, so a grant of `assign_role` is a grant of both directions — a human granting the ability
to assign roles is granting the ability to manage them.

All seven security tools return a `str` summary and are refused outright on SQLite, with
`NotImplementedError("… has no role, user or group concept …")` — the dialect layer's
`CapabilityError` is deliberately *not* a subclass of it, and this refusal is raised above that
layer so the message names the tool and the connection the operator called.

**No `host` argument, anywhere in the seven.** MySQL identifies an account as `'name'@'host'`,
so on that engine the `username` or `grantee` is written `reporting@10.0.0.5`. A bare name is
refused rather than widened to `'%'` — which would reach every host on the network — and a name
holding more than one `@` is refused rather than split at a guess. Every affected description
says so, because a model that does not know this collects refusals it cannot interpret. On the
other three engines an `@` is an ordinary character in a principal name and nothing is split.

**`list-roles` and `list-groups` answer over the same principals** and differ only in the word
they use: PostgreSQL's catalogue never says `role` (it stores "may log in" and nothing else) and
MS-SQL reserves `group` for a Windows group. Filtering either strictly would empty it on a real
server, so each entry carries its own `kind` and `native_kind` and no principal is lost to the
vocabulary.

### 11.3 Tables

```python
@server.tool(
    name="list-tables",
    description=(
        "List tables. Only tables you have 'list' permission on are returned; the rest are "
        "omitted rather than the call being refused."
    ),
    annotations=ToolAnnotations(title="List tables", read_only_hint=True),
)
def list_tables(
    connection: str,
    schema: str | None = None,
    name_pattern: str | None = None,
) -> list[dict]:
    """List the tables in a schema.

    Args:
        connection: Display name of the configured d-MCP connection to act on.
        schema: Schema to list. Defaults to the connection's default schema; pass '*' for all.
        name_pattern: Optional name filter, e.g. 'inv*'. Matched by d-MCP, not by the database.
    """

@server.tool(
    name="describe-table",
    description=(
        "Read a table's structure: columns with types, nullability and defaults, the primary "
        "key, foreign keys, indexes and an estimated row count. Requires 'read_structure'."
    ),
    annotations=ToolAnnotations(title="Describe table", read_only_hint=True),
)
def describe_table(connection: str, table: str, schema: str | None = None) -> dict: ...

@server.tool(
    name="select-rows",
    description=(
        "Read rows from a table. Requires 'select' on the table, and on every object a "
        "subquery in `where` reaches. Returns at most 100 rows by default and 1000 at most; "
        "page with limit and offset, and pass order_by to make paging stable."
    ),
    annotations=ToolAnnotations(title="Select rows", read_only_hint=True),
)
def select_rows(
    connection: str,
    table: str,
    schema: str | None = None,
    columns: list[str] | None = None,
    where: str | None = None,
    parameters: dict[str, Any] | None = None,
    order_by: str | None = None,
    limit: int = DEFAULT_ROW_LIMIT,
    offset: int = 0,
) -> dict:
    """Read rows from a table.

    Args:
        connection: Display name of the configured d-MCP connection to act on.
        table: Table name, optionally schema-qualified.
        schema: Schema name. Defaults to the connection's default schema.
        columns: Columns to return. Defaults to all of them.
        where: SQL predicate. Composed into the statement and re-parsed by the SQL guard, so a
            subquery inside it is authorised like any other reference.
        parameters: Values bound to placeholders in `where`. Never interpolated into the SQL.
        order_by: Column and direction, e.g. 'surname DESC'. Without it, paging past the first
            page may repeat or skip rows — that is a property of the database, not of d-MCP.
        limit: Rows to return, 1 to 1000.
        offset: Rows to skip before returning.
    """

@server.tool(
    name="insert-rows",
    description=(
        "Insert rows into a table. Values are bound, never interpolated. All rows are inserted "
        "in one transaction, so a partial batch never lands. Requires 'insert'."
    ),
    annotations=ToolAnnotations(title="Insert rows", destructive_hint=False),
)
def insert_rows(
    connection: str,
    table: str,
    rows: list[dict[str, Any]],
    schema: str | None = None,
) -> str: ...

@server.tool(
    name="update-rows",
    description=(
        "Update rows in a table. Requires 'update'. Omitting `where` updates every row and "
        "additionally requires approval in the d-MCP window."
    ),
    annotations=ToolAnnotations(title="Update rows", destructive_hint=True),
)
def update_rows(
    connection: str,
    table: str,
    values: dict[str, Any],
    where: str | None = None,
    parameters: dict[str, Any] | None = None,
    schema: str | None = None,
) -> str: ...

@server.tool(
    name="delete-rows",
    description=(
        "Delete rows from a table. Requires 'delete' permission and approval in the d-MCP "
        "window. Omitting `where` deletes every row."
    ),
    annotations=ToolAnnotations(title="Delete rows", destructive_hint=True),
)
def delete_rows(
    connection: str,
    table: str,
    where: str | None = None,
    parameters: dict[str, Any] | None = None,
    schema: str | None = None,
) -> str: ...

@server.tool(
    name="create-table",
    description=(
        "Create a table from a column specification. Requires 'create'. The DDL is generated "
        "by d-MCP from the validated specification; raw DDL is not accepted. Fails if the "
        "table already exists — replacing one is a drop followed by a create."
    ),
    annotations=ToolAnnotations(title="Create table", destructive_hint=False),
)
def create_table(
    connection: str,
    table: str,
    columns: list[dict[str, Any]],
    schema: str | None = None,
    primary_key: list[str] | None = None,
) -> str:
    """Create a table.

    Args:
        connection: Display name of the configured d-MCP connection to act on.
        table: Name of the table to create.
        columns: One entry per column: {'name', 'type', 'nullable', 'default'}. Types are
            validated against the dialect's own type list before any DDL is generated.
        schema: Schema name. Defaults to the connection's default schema.
        primary_key: Column names forming the primary key.
    """

@server.tool(
    name="drop-table",
    description=(
        "Not available: d-MCP never drops a table. The 'drop' action is refused by "
        "the permission layer itself (docs/adr/0005) — no permission rule can "
        "authorise it and no approval is ever requested, so every call is denied and "
        "audited. A table that exists can be neither replaced nor removed through "
        "d-MCP by any route; dropping it is a job for a database client."
    ),
    annotations=ToolAnnotations(title="Drop table", destructive_hint=True),
)
def drop_table(connection: str, table: str, schema: str | None = None) -> str: ...
```

**`create-table` takes a structured column specification, not a DDL string.** A `ddl: str`
parameter would be an arbitrary-DDL hole with a `create` label on it: the guard would have to
classify an unbounded `CREATE TABLE` body including constraints, computed columns and triggers,
and "refuse what cannot be classified" would make the tool unusable for anything real. Generating
the DDL from validated pieces means every identifier is quoted by the dialect and every type is
one the dialect declares. The cost is that exotic table shapes are out of reach from the MCP
surface, which is the correct trade for a tool an LLM drives.

### 11.4 Views

```python
@server.tool(
    name="list-views",
    description=(
        "List views. Only views you have 'list' permission on are returned; the rest are "
        "omitted rather than the call being refused."
    ),
    annotations=ToolAnnotations(title="List views", read_only_hint=True),
)
def list_views(
    connection: str,
    schema: str | None = None,
    name_pattern: str | None = None,
) -> list[dict]: ...

@server.tool(
    name="read-view-definition",
    description="Read a view's SQL definition and its column list. Requires 'read_definition'.",
    annotations=ToolAnnotations(title="Read view definition", read_only_hint=True),
)
def read_view_definition(connection: str, view: str, schema: str | None = None) -> dict: ...

@server.tool(
    name="select-view-rows",
    description=(
        "Read rows from a view. Requires 'select' on the view AND 'select' on every table and "
        "view it reads, transitively: permission on a view is not permission on what is "
        "underneath it. Capped and paged like select-rows."
    ),
    annotations=ToolAnnotations(title="Select view rows", read_only_hint=True),
)
def select_view_rows(
    connection: str,
    view: str,
    schema: str | None = None,
    columns: list[str] | None = None,
    where: str | None = None,
    parameters: dict[str, Any] | None = None,
    order_by: str | None = None,
    limit: int = DEFAULT_ROW_LIMIT,
    offset: int = 0,
) -> dict: ...

@server.tool(
    name="create-view",
    description=(
        "Create a view. Requires 'create' on the view AND 'select' on every object its body "
        "reads — otherwise creating a view would be a way around the permissions on the tables "
        "beneath it. Fails if the view exists; replacing one is a drop followed by a create."
    ),
    annotations=ToolAnnotations(title="Create view", destructive_hint=False),
)
def create_view(connection: str, view: str, sql: str, schema: str | None = None) -> str: ...

@server.tool(
    name="drop-view",
    description=(
        "Not available: d-MCP never drops a view. The 'drop' action is refused by the "
        "permission layer itself (docs/adr/0005) — no permission rule can authorise "
        "it and no approval is ever requested, so every call is denied and audited. A "
        "view that exists can be neither replaced nor removed through d-MCP by any "
        "route; redefining or removing it is a job for a database client."
    ),
    annotations=ToolAnnotations(title="Drop view", destructive_hint=True),
)
def drop_view(connection: str, view: str, schema: str | None = None) -> str: ...
```

`create-view` takes the view body as SQL because a view *is* a SELECT, and that SELECT goes
through the identical gate as `run-read-query` (§9) before the `CREATE VIEW` is composed: single
statement, read-only classification, every referenced object resolved and authorised for `select`.
`OR REPLACE` and `CREATE OR ALTER` are rejected.

### 11.5 Functions

**Execution is out of scope, deliberately.** There is no `execute-function` tool. `prompt.md`
never lists calling a function among the required actions for any of its groups — that tool was
scope this design added on its own, and it is withdrawn. A scalar or table-valued function stays
reachable all the same: inside a `run-read-query` SELECT, where the guard resolves what the
function's own body reads and authorises every one of those objects individually (§5, §9.1
step 9), exactly as it does for a view. That closes the blank-cheque path an `execute` grant on
an unparsed function body would have opened, without losing any genuine read functionality —
only the ability to call a function as a standalone operation, which nothing in `prompt.md` asked
for.

```python
@server.tool(
    name="list-functions",
    description=(
        "List functions. Only functions you have 'list' permission on are returned; the rest "
        "are omitted rather than the call being refused."
    ),
    annotations=ToolAnnotations(title="List functions", read_only_hint=True),
)
def list_functions(
    connection: str,
    schema: str | None = None,
    name_pattern: str | None = None,
) -> list[dict]: ...

@server.tool(
    name="read-function-definition",
    description=(
        "Read a function's source, parameters and return type. Requires 'read_definition'."
    ),
    annotations=ToolAnnotations(title="Read function definition", read_only_hint=True),
)
def read_function_definition(
    connection: str, function: str, schema: str | None = None
) -> dict: ...

@server.tool(
    name="create-function",
    description=(
        "Create a function. Requires 'create' on the function and 'select' on every object its "
        "body references. Fails if it exists — replacing a body is edit-function, which is "
        "never available (docs/adr/0005)."
    ),
    annotations=ToolAnnotations(title="Create function", destructive_hint=False),
)
def create_function(
    connection: str,
    function: str,
    body: str,
    schema: str | None = None,
    language: str | None = None,
) -> str: ...

@server.tool(
    name="edit-function",
    description=(
        "Not available: d-MCP never replaces a function's body. Replacing a body "
        "destroys the old one, so the 'edit' action is refused by the permission "
        "layer itself (docs/adr/0005) — no permission rule can authorise it and no "
        "approval is ever requested, so every call is denied and audited. A function "
        "that exists can be neither replaced nor removed through d-MCP by any route; "
        "rewriting its body is a job for a database client."
    ),
    annotations=ToolAnnotations(title="Edit function", destructive_hint=True),
)
def edit_function(
    connection: str,
    function: str,
    body: str,
    schema: str | None = None,
    language: str | None = None,
) -> str: ...

@server.tool(
    name="drop-function",
    description=(
        "Not available: d-MCP never drops a function. The 'drop' action is refused "
        "by the permission layer itself (docs/adr/0005) — no permission rule can "
        "authorise it and no approval is ever requested, so every call is denied and "
        "audited whatever 'signature' says. A function that exists can be neither "
        "replaced nor removed through d-MCP by any route; removing it is a job for a "
        "database client."
    ),
    annotations=ToolAnnotations(title="Drop function", destructive_hint=True),
)
def drop_function(
    connection: str,
    function: str,
    schema: str | None = None,
    signature: str | None = None,
) -> str: ...
```

### 11.6 Stored procedures

**Execution is out of scope, deliberately.** There is no `execute-procedure` tool. A procedure is
an opaque write d-MCP cannot inspect — its body may do anything, dynamic SQL and nested calls
included, and re-parsing it at call time would only give a false sense of coverage — so an
`execute` grant on it would have been a blank cheque for whatever it does, checked by nothing d-MCP
can see. `prompt.md` never lists executing a procedure among its required actions either, so
withdrawing the tool loses no requirement. Procedures stay fully manageable through `list`,
`read_definition`, `create`, `edit` and `drop`; running one is left to the database's own tooling,
outside d-MCP's reach and therefore outside its blast radius too.

```python
@server.tool(
    name="list-procedures",
    description=(
        "List stored procedures. Only procedures you have 'list' permission on are returned; "
        "the rest are omitted rather than the call being refused."
    ),
    annotations=ToolAnnotations(title="List procedures", read_only_hint=True),
)
def list_procedures(
    connection: str,
    schema: str | None = None,
    name_pattern: str | None = None,
) -> list[dict]: ...

@server.tool(
    name="read-procedure-definition",
    description="Read a procedure's source and parameters. Requires 'read_definition'.",
    annotations=ToolAnnotations(title="Read procedure definition", read_only_hint=True),
)
def read_procedure_definition(
    connection: str, procedure: str, schema: str | None = None
) -> dict: ...

@server.tool(
    name="create-procedure",
    description=(
        "Create a stored procedure. Requires 'create' on the procedure and permission on every "
        "object its body references. Fails if it exists — replacing a body is edit-procedure, "
        "which is never available (docs/adr/0005)."
    ),
    annotations=ToolAnnotations(title="Create procedure", destructive_hint=False),
)
def create_procedure(
    connection: str, procedure: str, body: str, schema: str | None = None
) -> str: ...

@server.tool(
    name="edit-procedure",
    description=(
        "Not available: d-MCP never replaces a stored procedure's body. Replacing a "
        "body destroys the old one, so the 'edit' action is refused by the permission "
        "layer itself (docs/adr/0005) — no permission rule can authorise it and no "
        "approval is ever requested, so every call is denied and audited. A procedure "
        "that exists can be neither replaced nor removed through d-MCP by any route; "
        "rewriting its body is a job for a database client."
    ),
    annotations=ToolAnnotations(title="Edit procedure", destructive_hint=True),
)
def edit_procedure(
    connection: str, procedure: str, body: str, schema: str | None = None
) -> str: ...

@server.tool(
    name="drop-procedure",
    description=(
        "Not available: d-MCP never drops a stored procedure. The 'drop' action is "
        "refused by the permission layer itself (docs/adr/0005) — no permission rule "
        "can authorise it and no approval is ever requested, so every call is denied "
        "and audited whatever 'signature' says. A procedure that exists can be "
        "neither replaced nor removed through d-MCP by any route; removing it is a "
        "job for a database client."
    ),
    annotations=ToolAnnotations(title="Drop procedure", destructive_hint=True),
)
def drop_procedure(connection: str, procedure: str, schema: str | None = None) -> str: ...
```

---

## 12. Complete tool list

The Python function name is the tool name with `-` replaced by `_` in all 38 cases. "Hint" is
the `ToolAnnotations` flag: R = `read_only_hint=True`, W = `destructive_hint=False`, D =
`destructive_hint=True`. A QA test asserts `tools/list` returns exactly these 38 names — neither
`execute-function` nor `execute-procedure` among them.

**The "Confirmation" column below predates ADR 0005 for the six rows marked `†`.** `drop` and
`edit` are now refused by the permission layer itself, unconditionally — no rule can grant them,
and no approval is ever requested. Read `**yes**` on those six rows as "was designed to be
brokered", not as what happens today; see §8.1.

| # | Tool | Group | Action(s) required | Hint | Confirmation |
|---|---|---|---|---|---|
| 1 | `list-connections` | Meta | none | R | no |
| 2 | `show-permissions` | Meta | none | R | no |
| 3 | `read-catalogue` | Database | `read_catalogue` | R | no |
| 4 | `list-schemas` | Database | `read_catalogue` | R | no |
| 5 | `list-roles` | Database | `read_catalogue` | R | no |
| 6 | `list-users` | Database | `read_catalogue` | R | no |
| 7 | `list-groups` | Database | `read_catalogue` | R | no |
| 8 | `create-role` | Security | `create_role` | W | no |
| 9 | `create-user` | Security | `create_user` | W | no |
| 10 | `create-group` | Security | `create_group` | W | no |
| 11 | `add-user-to-group` | Security | `assign_group` | W | no |
| 12 | `remove-user-from-group` | Security | `assign_group` | D | **yes** |
| 13 | `assign-role` | Security | `assign_role` | W | no |
| 14 | `revoke-role` | Security | `assign_role` | D | **yes** |
| 15 | `list-tables` | Tables | `list` (filters) | R | no |
| 16 | `describe-table` | Tables | `read_structure` | R | no |
| 17 | `select-rows` | Tables | `select` + `select` on every object `where` reaches | R | no |
| 18 | `insert-rows` | Tables | `insert` | W | no |
| 19 | `update-rows` | Tables | `update` + `select` on every object `where` reaches | D | **only with no effective WHERE** |
| 20 | `delete-rows` | Tables | `delete` + `select` on every object `where` reaches | D | **yes** |
| 21 | `create-table` | Tables | `create` | W | no |
| 22† | `drop-table` | Tables | `drop` | D | **never — `drop` refused outright** |
| 23 | `list-views` | Views | `list` (filters) | R | no |
| 24 | `read-view-definition` | Views | `read_definition` | R | no |
| 25 | `select-view-rows` | Views | `select` on the view + `select` on every base object | R | no |
| 26 | `create-view` | Views | `create` + `select` on every referenced object | W | no |
| 27† | `drop-view` | Views | `drop` | D | **never — `drop` refused outright** |
| 28 | `list-functions` | Functions | `list` (filters) | R | no |
| 29 | `read-function-definition` | Functions | `read_definition` | R | no |
| 30 | `create-function` | Functions | `create` + `select` on every referenced object | W | no |
| 31† | `edit-function` | Functions | `edit` + `select` on every referenced object | D | **never — `edit` refused outright** |
| 32† | `drop-function` | Functions | `drop` | D | **never — `drop` refused outright** |
| 33 | `list-procedures` | Procedures | `list` (filters) | R | no |
| 34 | `read-procedure-definition` | Procedures | `read_definition` | R | no |
| 35 | `create-procedure` | Procedures | `create` + rights on every referenced object | W | no |
| 36† | `edit-procedure` | Procedures | `edit` + rights on every referenced object | D | **never — `edit` refused outright** |
| 37† | `drop-procedure` | Procedures | `drop` | D | **never — `drop` refused outright** |
| 38 | `run-read-query` | Query | `run_query` on the connection + `select` on every table and view read | R | no |

† Rows 22, 27, 31, 32, 36, 37 never reach the confirmation broker: `drop` and `edit` are refused
by the permission layer itself since `docs/adr/0005-drop-and-edit-are-never-granted.md`, and no
rule can change that. The "action(s) required" column is unchanged and still describes what the
tool would check next if the `drop`/`edit` gate ever passed — it never does, so that second check
is never reached in practice; see `mcp_server.py:2217` and the ADR's §1 (choke point).

Counts for the assertion: 38 tools · 37 take `connection` · 18 `read_only_hint=True` ·
10 `destructive_hint=True` — of which 4 always reach the broker, 1 reaches it conditionally, and
6 (the four `drop-*` and the two `edit-*`) never reach it at all, refused outright per ADR 0005.

---

## 13. Decisions the user has ruled on

Four questions this design escalated per `CLAUDE.md` rather than deciding unilaterally. All
four are now resolved, and the catalogue above reflects the rulings.

1. **`execute-procedure` confirmation, resolved as: remove the tool.** The question was whether
   executing a procedure should additionally require GUI confirmation, on top of its `execute`
   grant, because a procedure is an opaque write d-MCP cannot inspect. The user's ruling goes
   further than confirmation: `execute-procedure` does not ship at all. Re-reading `prompt.md`
   confirmed it never asked for procedure execution among its required actions, so the tool was
   scope this design had added on its own — and with it gone, the blank-cheque risk the question
   was about no longer exists to be mitigated. `execute-function` is withdrawn on the same
   reasoning: `prompt.md` doesn't ask for it either. Both action sets shrink to
   `list, read_definition, create, edit, drop` (§11.5, §11.6).

2. **Statement timeout, resolved as: per-connection, default 30 s.** The fixed
   `DEFAULT_STATEMENT_TIMEOUT_S` (30 s) applied identically to every connection is replaced by a
   `statement_timeout_s` column on the connection profile, defaulting to 30 s. An operator can
   raise it for a warehouse connection whose genuine analytical queries need longer, or hold it
   down on a production connection that must never be tied up. There is no per-call `timeout_s`
   parameter — the user chose the per-connection form only, so the model gets no lever over it
   (§3.1, §6.1).

3. **`run-read-query` switchability, resolved as: yes, per connection.** A new `run_query` action
   joins the `database` action tuple (§9.1, §12). It is deny-by-default like every other action,
   so an operator must grant it explicitly, and a connection can be left reachable only through
   the structured tools by simply never granting it. `run-read-query` now requires `run_query` in
   addition to `select` on every table and view the statement reads.

4. **`remove-user-from-group` and `revoke-role`, resolved as: destructive and brokered.** §8.1
   originally kept both out of the destructive set because each is reversed by its opposite tool,
   and `db/security.py` was written against that reading. The user ruled the other way: revoking
   is reversible in principle but not necessarily by whoever has just lost the access, and a
   human seeing the principal and the role named before it happens is worth two more tools that
   block when nobody is watching. §8.1 therefore lists ten destructive operations, not eight,
   and both tools are annotated `destructive_hint=True` (§8.1, §11.2, §12).

---

## 14. What stage 6 and 7 must verify against the SDK

Everything above is protocol- and SDK-level design. Three points touch `mcp>=2.0` internals and
are confirmed against the installed package on the first day of stage 6, because the design
depends on them being one of two known shapes:

1. The tool-list-changed notification helper — `MCPServer.notify_tool_list_changed()` or the
   low-level `session.send_tool_list_changed()` (§2.4).
2. Whether `Tool.parameters` is the live dict served by `tools/list` or a cache that must be
   invalidated after the enum patch (§2.3).
3. Whether `@server.tool` accepts a return annotation of `dict` / `list[dict]` without an output
   schema, or whether an output schema is derived and must be declared. If it is derived, the
   envelope in §6.3 becomes a `TypedDict` so the derived schema is accurate.

None of the three changes a tool name, a signature, a permission mapping or a return shape, so
this catalogue stands whichever way they resolve.
