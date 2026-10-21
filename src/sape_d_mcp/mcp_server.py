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

"""The d-MCP server: database tools whose every reach is checked against the rule store.

Stage 6 registered the **eighteen read-only tools** of DESIGN-MCP-TOOLS.md §12, stage 7
the **thirteen write and DDL tools**, and stage 8 the **seven security tools** — the
catalogue is now the **thirty-eight** §12 lists. ``execute-function`` and
``execute-procedure`` will never land: §13 decision 1 records the user's ruling that
``prompt.md`` never asked for routine execution, so both were withdrawn from the design
rather than deferred, and §12's count of 38 already excludes them: 18 read + 13 write +
7 security.

Four things a future maintainer will otherwise get wrong:

**The ``connection`` enum is steering, not the security boundary.** Its JSON-Schema
``enum`` is patched onto each tool's input schema by :meth:`DatabaseMCPServer.refresh_connections`
so a model does not waste turns guessing names and a schema-validating client rejects
nonsense locally. The boundary is :meth:`DatabaseMCPServer._resolve_connection`, which looks
the name up in the live registry and raises ``ValueError`` on a miss. A stale cached tool
list, a hand-written JSON-RPC frame or an empty registry all fail there.

**A grant on a view is not a grant on what it reads.** Reading a view authorises the view
*and*, recursively, every base object its stored definition reads — the exact analogue of
f-MCP refusing a symlink whose target lies outside the granted directory. The recursion runs
through the introspected catalogue, never by trusting the engine, and a definition that
cannot be read or cannot be parsed is refused rather than assumed harmless
(DESIGN-PERMISSIONS.md §6.2).

**Authorise everything, then act.** Every object a statement touches is resolved and checked
before a single statement runs. There is no path in this module that executes some of a
statement's objects and authorises the rest afterwards (DESIGN-PERMISSIONS.md §6.1, §6.3).

**The guard is not the only line of defence.** Every path that executes a *read* —
``select-rows``, ``select-view-rows``, ``run-read-query`` and every impact estimate — runs it
inside :func:`sape_d_mcp.db.engine.read_only_session`, which hardens the session with the
engine's own read-only mechanism first and refuses the read if it cannot prove the hardening
took (DESIGN-MCP-TOOLS.md §9.1 step 11). The guard decides what d-MCP is willing to send; the
session decides what the server is willing to accept; a bug in either one is survivable. The
hardening is undone at the end of the block, because these are the same sessions the write
tools use, and a session left read-only would break them silently. The write path deliberately
does **not** enter that block — it is the read path's defence, and a write inside it would
simply be refused by the server — so :meth:`DatabaseMCPServer._run_write` asserts the session
is *not* currently hardened rather than trusting that no caller nested the two.

**Every mutating and DDL tool returns a ``str`` summary, never an envelope** (§6.2):
``"Deleted 12 row(s) from dbo.Audit"``. There is no payload to shape, and the sentence is what
reads well in the audit log the Logs page renders.

**Destructive ⇔ brokered, and the implication runs both ways.** :data:`BROKERED` is
DESIGN-MCP-TOOLS.md §8.1's set — the four ``drop-*``, ``delete-rows``, ``edit-function``,
``edit-procedure``, ``remove-user-from-group`` and ``revoke-role``, always — plus
``update-rows``, brokered exactly when the guard reports the composed statement has no
*effective* ``WHERE`` (a missing predicate, or a tautology like ``WHERE 1=1``, which is not a
filter). Those ten are the only tools carrying ``destructive_hint=True``, and
``test_nothing_is_annotated_destructive_unless_it_is_brokered``
pins that in both directions: an annotation a host may auto-approve against must never be
attached to something no human is asked about, and a tool that asks a human must not look mild.
With no broker, or a broker with no GUI subscribed, the operation is refused before it runs and
the refusal is audited as ``refused`` — the normal, intended state of a ``--cli`` server.

The last two joined that set on the user's ruling, against §8.1's first reading and against
``db/security.py``'s own: revoking is reversible in principle, but not necessarily by whoever
has just lost the access, and a human shown the principal and the role *before* it happens is
worth two more tools that block when nobody is watching. They reach the broker through an
``approve`` callable ``SecurityManager`` invokes with the built script — after its own
tripwire, before the first statement — so what a human approved is the statement that then
runs rather than a second build of it, and so the MySQL ``name@host`` rule keeps one reader.
Their impact line names the principal and the role in words: an approver reading
``REVOKE "analyst" FROM "alice"`` should be told what alice loses, not shown the SQL twice.

**One name can be two functions.** PostgreSQL identifies a routine by its name *and* its
argument types, so ``f(integer)`` and ``f(text)`` are two objects and a bare ``DROP FUNCTION f``
is a server error while both exist. ``drop-function`` and ``drop-procedure`` therefore take an
optional ``signature``, and the model's text never reaches the SQL: it selects a row out of the
overload set the catalogue reported, and ``Dialect.resolve_overload()`` hands back the
*server's* own spelling of that row, which is what is composed, what the confirmation modal
names and what the summary reports. A signature matching no overload, or two, is refused with
the real set listed, and so is a bare name against a routine that carries several — nothing
resolves an ambiguity by choosing, because the one outcome worse than "d-MCP cannot drop this
function" is "d-MCP dropped the other one". The other three engines have one object per routine
name and refuse a signature rather than ignoring it: a caller that believes it has
disambiguated and has not has a different object in mind from the one about to be dropped.

**Nothing here chooses how long a statement may run.** The budget is the connection profile's
``statement_timeout_s``, applied once per session by ``engine.connect()`` and defaulting to 30 s.
No tool takes a timeout argument and none should grow one: that decision belongs to whoever
configured the connection, not to whoever is calling it (§6.1, §13 decision 2).

**A ``where`` fragment is free-form SQL, and only the re-parse makes it safe.** ``select-rows``,
``select-view-rows``, ``update-rows`` and ``delete-rows`` take a ``where`` string with its
values bound through ``parameters``,
as DESIGN-MCP-TOOLS.md §5 specifies: the model writes a predicate d-MCP did not author, and
``Dialect.select()`` places it — parenthesised, values bound, never interpolated — inside a
statement d-MCP did. Nothing about ``id IN (SELECT cust FROM dbo.Salaries)`` looks dangerous
in the arguments, and ``Query.touches`` reports only the table the caller named — deliberately,
because a second, weaker enumeration in the dialect would be one more reader to disagree with
the server's. So :meth:`DatabaseMCPServer._select` hands the **composed** text back to the
``guard.require_read_only()`` walk ``run-read-query`` uses, and every object the fragment
reaches — subquery, join, view and the bases underneath it — is authorised before the cursor
is opened (DESIGN-MCP-TOOLS.md §4). A fragment that is not one statement's worth of text is
refused by the guard's own engine-aware lexer before it is composed at all.

``update-rows`` and ``delete-rows`` do the same thing through ``guard.require_write()``, which
distinguishes the write target from the objects the statement merely reads: ``DELETE FROM T
WHERE id IN (SELECT cust FROM Orders)`` needs ``delete`` on ``T`` and ``select`` on ``Orders``,
and a set that named both under one action would either under-authorise the write or
over-authorise the read. Under-reporting there is the failure that matters, which is why the
walk is the *same* walk — :meth:`DatabaseMCPServer._targets_for` — the read tools use, rather
than a second one written for writes.

Two deviations from DESIGN-MCP-TOOLS.md remain, reported at the stage gate rather than hidden
here:

1. §11.2 gives the seven security tools no ``host`` argument, and MySQL identifies an
   account as ``'name'@'host'`` rather than by a bare name. The username or grantee is
   therefore written ``reporting@10.0.0.5`` there; a bare name is refused rather than widened
   to ``'%'``, which would reach every host on the network, and a name holding more than one
   ``@`` is refused rather than split at a guess. Every affected tool's description says so,
   because a model that does not know it collects refusals it cannot interpret. Relatedly,
   ``list-roles`` and ``list-groups`` answer over the *same* principals and differ only in the
   word they use for them: PostgreSQL's catalogue never says ``role`` and MS-SQL reserves
   ``group`` for a Windows group, so filtering either strictly would empty it on a real server
   (``db/security.py._matches_kind`` gives the engine-by-engine evidence). Each entry carries
   its own ``kind`` and ``native_kind`` for a caller that needs the distinction.
2. §5 asks ``create-function`` / ``edit-function`` / ``create-procedure`` / ``edit-procedure``
   to authorise the objects their bodies reference. Nothing in the stack can enumerate those:
   a routine body is a whole procedural language, ``SqlGuard`` refuses routine DDL outright
   ("the guard cannot read the body of a function, so it cannot say what that body will read
   once it runs. Routine DDL is authorised from the tool's own arguments, not from parsed
   text"), and ``Dialect.create_routine()`` says the same. These four tools therefore authorise
   the routine itself — ``create`` or ``edit`` on that object — and no more, and their tool
   descriptions say exactly that instead of §11's wording, because a description promising a
   check that does not happen is worse than one that admits the gap. Both ``edit-*`` tools are
   brokered, so a human sees the body before it lands.
"""

from __future__ import annotations

import base64
import datetime as _datetime
import decimal
import fnmatch
import logging
import os
import re
import threading
import uuid
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass
from time import perf_counter
from typing import TYPE_CHECKING, Any

# mcp>=2.0 only: the 2.x SDK renamed FastMCP to MCPServer, so a 1.x install fails right
# here rather than somewhere subtler later. requirements.txt carries the floor and the
# reason beside it.
from mcp.server import MCPServer
from mcp.types import ToolAnnotations

from sape_d_mcp._version import VERSION_DISPLAY
from sape_d_mcp.confirmation import DEFAULT_TIMEOUT_S, ConfirmationRefused
from sape_d_mcp.db import engine as db_engine
from sape_d_mcp.db.connection_store import ConnectionStore
from sape_d_mcp.db.dialects.base import (
    Dialect,
    DialectError,
    NormalisedRef,
    rewrite_placeholders,
)
from sape_d_mcp.db.dialects.types import ColumnSpec, ObjectRef, ObjectType, RawPredicate, Script
from sape_d_mcp.db.introspection import Introspector
from sape_d_mcp.db.security import SecurityManager
from sape_d_mcp.db.sql_guard import GuardRefusal, Reference, SqlGuard
from sape_d_mcp.log_store import LogStore
from sape_d_mcp.permissions import (
    ActionForbidden,
    PermissionDenied,
    PermissionStore,
    database_scope_ref,
    format_rule,
)
from sape_d_mcp.tool_logger import ToolLogger

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sape_d_mcp.db.credential_store import CredentialStore
    from sape_d_mcp.db.engine import DatabaseConnection

logger = logging.getLogger(__name__)

# Read caps. An LLM must not be able to pull a table into a context window, and a runaway
# SELECT must not be able to fill audit.db either (DESIGN-MCP-TOOLS.md §6).
DEFAULT_ROW_LIMIT = 100
MAX_ROW_LIMIT = 1000
MAX_CELL_CHARS = 4096

#: How deep a view may nest before the expansion gives up. A cycle is impossible in a
#: well-formed catalogue and is caught by the visited set anyway; this bounds a catalogue
#: that is *not* well formed, and a chain this long is unreadable rather than legitimate.
MAX_VIEW_DEPTH = 12

#: The eighteen read-only tools of DESIGN-MCP-TOOLS.md §12. Written out rather than derived
#: from the registry so a tool that quietly disappears — or a write tool that quietly
#: appears — is a test failure rather than a silent change to the attack surface.
READ_TOOLS: tuple[str, ...] = (
    "list-connections",
    "show-permissions",
    "read-catalogue",
    "list-schemas",
    "list-roles",
    "list-users",
    "list-groups",
    "list-tables",
    "describe-table",
    "select-rows",
    "list-views",
    "read-view-definition",
    "select-view-rows",
    "list-functions",
    "read-function-definition",
    "list-procedures",
    "read-procedure-definition",
    "run-read-query",
)

#: The thirteen write and DDL tools of DESIGN-MCP-TOOLS.md §12, in the order §11 introduces
#: them. Written out for the same reason ``READ_TOOLS`` is: the served catalogue is the
#: attack surface, and it should change only when someone edits this tuple on purpose.
WRITE_TOOLS: tuple[str, ...] = (
    "insert-rows",
    "update-rows",
    "delete-rows",
    "create-table",
    "drop-table",
    "create-view",
    "drop-view",
    "create-function",
    "edit-function",
    "drop-function",
    "create-procedure",
    "edit-procedure",
    "drop-procedure",
)

#: The seven security tools of DESIGN-MCP-TOOLS.md §11.2, in the order it introduces them.
#: Written out like the other two tuples, and for a sharper version of the same reason: these
#: are the tools that change *who may do what*, so a name appearing here without a permission
#: gate, an audit row and — for the destructive pair — a broker is the one change to the attack
#: surface that cannot be seen from a result. The five ``list-*`` readers over principals live
#: in ``READ_TOOLS``; these are the writers.
SECURITY_TOOLS: tuple[str, ...] = (
    "create-role",
    "create-user",
    "create-group",
    "add-user-to-group",
    "remove-user-from-group",
    "assign-role",
    "revoke-role",
)

#: Everything this build serves: §12's thirty-eight in full. ``execute-function`` and
#: ``execute-procedure`` are not coming at all (§13 decision 1) and are absent from §12's own
#: count too.
TOOLS: tuple[str, ...] = READ_TOOLS + WRITE_TOOLS + SECURITY_TOOLS

#: Tools that always route through :mod:`sape_d_mcp.confirmation` before executing
#: (DESIGN-MCP-TOOLS.md §8.1). ``delete-rows`` is here even with a ``WHERE``, because deleted
#: rows do not come back, and ``edit-*`` is here because replacing a body destroys the old one.
#:
#: ``remove-user-from-group`` and ``revoke-role`` are here on the user's ruling, which
#: overrides §8.1's first reading and the reasoning ``db/security.py`` wrote on the strength
#: of it. Both are reversible with their opposite tool — and *reversible* is not *reversible
#: by whoever just lost the access*: revoke the last administrator's role and no principal is
#: left that may grant it back from inside d-MCP. The two other directions of the same pairs,
#: ``add-user-to-group`` and ``assign-role``, are additive and stay out; so do the three
#: ``create-*``, which produce a principal holding nothing.
BROKERED: frozenset[str] = frozenset(
    {
        "drop-table",
        "drop-view",
        "drop-function",
        "drop-procedure",
        "delete-rows",
        "edit-function",
        "edit-procedure",
        "remove-user-from-group",
        "revoke-role",
    }
)

#: The one tool whose brokering is decided per call, from the *composed* statement:
#: ``update-rows`` asks a human exactly when ``StatementPlan.has_effective_where`` is False.
#: A tautology is not a filter, and the guard resolves every ambiguity towards False, so the
#: cost of a wrong answer here is one dialog too many rather than a table-wide UPDATE nobody saw.
CONDITIONALLY_BROKERED: frozenset[str] = frozenset({"update-rows"})

#: The ten tools annotated ``destructive_hint=True`` — and the invariant §8.1 calls "worth
#: more than any individual nuance": this set is exactly ``BROKERED | CONDITIONALLY_BROKERED``,
#: never a superset. ``update-rows`` earns the static annotation on the strength of the worst
#: case it can perform, which is the truthful hint for a flag a host may auto-approve against.
DESTRUCTIVE_TOOLS: frozenset[str] = BROKERED | CONDITIONALLY_BROKERED

#: The keys ``create-table`` accepts in a column specification (§11.3's four, plus
#: ``is_identity``). Unknown keys are refused rather than ignored: a caller who wrote
#: ``"nullible"`` and got a NOT NULL column would find out from the first failed INSERT.
_COLUMN_SPEC_KEYS: frozenset[str] = frozenset(
    {"name", "type", "nullable", "default", "is_identity"}
)

#: How many views the ``drop-table`` impact estimate will read definitions for before it gives
#: up on counting dependants and says so. The count is genuinely useful to whoever is about to
#: approve a drop, and it is also O(views) catalogue reads — on a warehouse with thousands of
#: views that is a modal that takes minutes to appear, which is its own kind of failure.
MAX_DEPENDENCY_SCAN_VIEWS = 200

#: ``LANGUAGE sql`` in a routine body, so a ``language`` argument that contradicts the body can
#: be refused rather than silently ignored. d-MCP never rewrites a routine body (the dialect
#: layer is explicit that it is not parsed for meaning), so the argument can only ever be
#: checked against what the body already says.
_ROUTINE_LANGUAGE = re.compile(r"\bLANGUAGE\s+(?:'([^']+)'|\"([^\"]+)\"|([A-Za-z_][A-Za-z0-9_]*))", re.IGNORECASE)

#: The `connection` argument's description, identical on all seventeen tools that take one
#: (DESIGN-MCP-TOOLS.md §2.1). Patched onto the generated schema, because the 2.x SDK derives
#: property schemas from type hints alone and does not read the docstring's Args block.
CONNECTION_ARG_DESCRIPTION = "Display name of the configured d-MCP connection to act on."

#: What the same property says when the registry is empty. A JSON-Schema `enum` may not be an
#: empty array, so the keyword is removed and the description carries the explanation
#: instead — one code path, one catalogue, one honest error (§2.5).
NO_CONNECTIONS_DESCRIPTION = (
    "No d-MCP connections are configured. Add one in the d-MCP Connections page; no "
    "database operation can succeed until then."
)

_INSTRUCTIONS = (
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
)

#: `CREATE [OR REPLACE|OR ALTER] [MATERIALIZED] VIEW <name> [(cols)] AS <body>` — the wrapper
#: MS-SQL and SQLite store around a view body while PostgreSQL and MySQL hand back the body
#: alone. Non-greedy up to the first `AS` keyword, and applied only to text that begins with
#: CREATE; when the strip leaves something the guard cannot classify as a read, the view is
#: refused rather than assumed harmless.
_CREATE_VIEW_PREFIX = re.compile(r"^\s*CREATE\b.*?\bVIEW\b.*?\bAS\b", re.IGNORECASE | re.DOTALL)

#: Fragments of a driver message that can echo a DSN. A pyodbc failure will happily repeat
#: `PWD=hunter2` in its exception text, and that text goes into audit.db and into the
#: transcript unless it is cut out first.
_SECRET_FRAGMENT = re.compile(
    r"(?i)\b(pwd|password|passwd|secret|token)\s*=\s*[^;,\s\"']*"
)


@dataclass
class ConnectionContext:
    """One resolved connection: the profile, the live session, and the three readers over it.

    Held in :attr:`DatabaseMCPServer._contexts` and reused across calls, because
    ``Introspector``'s catalogue cache *is* the instance and throwing it away per call would
    turn every authorisation into a fresh round of catalogue queries.

    :class:`~sape_d_mcp.db.security.SecurityManager` is held the same way and for a weaker
    reason — it caches nothing, deliberately, because a principal list moves under a running
    session whenever a DBA opens another window — but one per connection is what its own
    docstring asks for, and it is built with *this* context's guard so its lexical tripwire
    reads the engine's grammar exactly as ``run-read-query`` does.
    """

    connection_id: int
    display_name: str
    profile: dict[str, Any]
    db: DatabaseConnection
    dialect: Dialect
    introspector: Introspector
    guard: SqlGuard
    security: SecurityManager

    @property
    def default_schema(self) -> str | None:
        """The schema an unqualified name resolves against, or ``None`` when unknown.

        Read off the guard rather than the dialect so the structured path and the free-form
        path can never disagree about what `Salaries` means: `SqlGuard.default_schema` is the
        probed default, else the engine's, else the addressable stand-in (`main` on SQLite).
        ``None`` means the connection genuinely does not know, and an unqualified name is
        then refused instead of resolved against a guess.
        """

        return self.guard.default_schema


class DatabaseMCPServer:
    """An MCP server exposing permission-gated database operations as tools.

    Access is governed entirely by the ``rules`` table of ``permissions.db``. Every object a
    statement references — through views, subqueries and joins, not just the object named in
    the arguments — is resolved against the connection's introspected catalogue and
    authorised before any work happens. Objects no rule covers are refused, and objects the
    catalogue does not know are refused rather than guessed at.
    """

    def __init__(
        self,
        connections_db: str | os.PathLike[str] | None = None,
        permissions_db: str | os.PathLike[str] | None = None,
        audit_db: str | os.PathLike[str] | None = None,
        user: str | None = None,
        name: str = "database-mcp-server",
        log_store: LogStore | None = None,
        session_id: str | None = None,
        confirmation: Any | None = None,
        credentials: CredentialStore | None = None,
        confirmation_timeout_s: float | None = None,
        language: Callable[[], str] | str | None = None,
    ) -> None:
        """Open the stores and register the tool catalogue.

        Args:
            connections_db: Path to ``connections.db``; the default resolves from the
                environment, then the project root.
            permissions_db: Path to ``permissions.db``, same defaulting.
            audit_db: Path the JSONL log is written beside. Only its parent directory is
                used here; ``LogStore`` owns the file itself.
            user: The operator name recorded on rules written through this server.
            name: The MCP server name a client sees.
            log_store: An open ``LogStore`` to fan audit rows out to, or ``None`` for
                JSONL-only logging.
            session_id: ``"cli"`` for a server spawned by an MCP client, else the GUI
                session's own id.
            confirmation: The confirmation broker every tool in :data:`BROKERED` waits on.
                ``None`` is the ``--cli`` case and is not a misconfiguration: those tools
                then refuse before running, exactly as they do when a broker exists but no
                GUI is subscribed to it.
            credentials: An open ``CredentialStore``, or ``None`` to build one lazily. It is
                lazy because constructing one probes the OS keyring with a real round trip,
                and a SQLite-only installation must not pay for that — nor a test suite.
            confirmation_timeout_s: How long a brokered tool waits for a human, in seconds.
                The authority is ``confirmations.timeout_seconds`` in ``config.json``, which
                only the GUI can read, so ``gui/server_thread.py`` reads it and passes it
                here. It matters that the *same* number reaches the broker and the dialog:
                the dialog's countdown is cosmetic and the broker's clock is authoritative,
                so a mismatch shows the operator a timer that is not the one deciding.
                ``None`` falls back to :data:`sape_d_mcp.confirmation.DEFAULT_TIMEOUT_S`.
            language: The operator's BCP-47 locale, or a callable returning it — a callable
                because the language can change while the server runs. Used for one thing
                only: translating a ``Script.warning_key`` into the impact text a
                confirmation modal shows. A headless server has no operator and no locale,
                and gets en-US.
        """
        self.connections = ConnectionStore(connections_db, user=user)
        self.permissions = PermissionStore(permissions_db, user=user)
        self.confirmation = confirmation
        self.confirmation_timeout_s = (
            DEFAULT_TIMEOUT_S if confirmation_timeout_s is None else float(confirmation_timeout_s)
        )
        self._language = language

        # An audit store is opened rather than left to the caller: DESIGN-MCP-TOOLS.md §10
        # promises exactly one `tool_calls` row per call, and a --cli server spawned by an
        # MCP client has no GUI to hand one in. `"cli"` is the well-known session id for
        # such a server, and ToolLogger writes to SQLite only when both are present.
        self._owns_log_store = log_store is None
        if log_store is None:
            log_store = LogStore(audit_db)
        self.log_store = log_store
        self.logger = ToolLogger(
            db_path=str(log_store.db_path), log_store=log_store, session_id=session_id or "cli"
        )

        self._credentials = credentials
        # Keyed by (connection_id, thread) and not by connection_id alone. A DB-API
        # connection is not portable between threads — the standard library's sqlite3
        # refuses outright with "SQLite objects created in a thread can only be used in that
        # same thread" — and the SDK runs a synchronous tool body on whichever worker thread
        # anyio hands it, which is not the thread the previous call ran on. Sharing one
        # session across the pool therefore fails on the second call, non-deterministically,
        # in production and not in a single-threaded test. One session per thread is also
        # what the eventual EngineRegistry pool will look like.
        self._contexts: dict[tuple[int, int], ConnectionContext] = {}
        self._reachable: dict[int, bool] = {}
        # A tool body runs on the SDK's worker thread while the GUI may be adding a
        # connection on Qt's, so the context cache needs a real lock. Reentrant because
        # _resolve_connection() is reached from helpers that already hold it.
        self._lock = threading.RLock()

        self._portal: Any | None = None
        self._sessions: set[Any] = set()
        self._catalogue_revision = 0

        # VERSION_DISPLAY and not __version__: the release stage is part of how this build
        # identifies itself, and a client that shows the server's version should show that it
        # is a Beta. The space that puts there is safe: `Implementation.version` — what
        # `serverInfo.version` is typed as — is a bare `str` with no pattern and no semver
        # constraint (its generated JSON-Schema is `{"type": "string"}`), and the SDK's own
        # client reads the 2026-era `_meta` serverInfo stamp as display-only. __version__
        # stays the packaging identifier PEP 440 constrains, and is not served to anyone.
        self.server = MCPServer(name=name, version=VERSION_DISPLAY, instructions=_INSTRUCTIONS)
        self.tool_executed_callback: Callable[..., None] | None = None

        # Order is load-bearing: the enum can only be patched onto schemas that exist.
        self._register_tools()
        self.refresh_connections()

    # -- lifecycle -------------------------------------------------------

    def set_tool_executed_callback(self, callback: Callable[..., None] | None) -> None:
        """Set a callback invoked after every tool execution.

        Args:
            callback: ``callback(tool_name, params, result, error)``, f-MCP's signature
                unchanged so the GUI's existing slot keeps working. Exceptions raised by it
                are swallowed: a broken observer must not break a tool.
        """
        self.tool_executed_callback = callback

    def set_log_store(self, log_store: LogStore, session_id: str) -> None:
        """Point the audit fan-out at a SQLite store.

        Args:
            log_store: The open ``LogStore``.
            session_id: The session id every row is keyed by.

        Raises:
            ValueError: If ``session_id`` is falsy — an unkeyed audit row cannot be shown in
                the Logs page and would be worse than no row at all.
        """
        if not session_id:
            raise ValueError("session_id is required")
        self.logger.log_store = log_store
        self.logger.session_id = session_id

    def set_portal(self, portal: Any | None) -> None:
        """Give the server the anyio portal notifications are scheduled through.

        Args:
            portal: An ``anyio.from_thread.BlockingPortal`` opened by the server thread, or
                ``None`` when the server stops. With no portal the enum is still patched and
                no notification is sent; the next client to connect sees the current enum in
                its own ``tools/list``.

        The confirmation broker needs the *same* portal, for the opposite direction of the
        same problem — a human's Approve click happens on Qt's thread and cannot set an
        anyio ``Event`` from there — so ``gui/server_thread.py`` hands one portal to both.
        This method does not forward it itself: the broker may be shared with something that
        is not this server, and a server quietly reaching into an object it was merely handed
        is how two owners of one portal end up clearing each other's.
        """
        self._portal = portal

    def register_session(self, session: Any) -> None:
        """Remember a live MCP session so it can be told the tool list changed.

        Args:
            session: A ``ServerSession``. The 2.x ``MCPServer`` exposes no notification
                helper of its own and keeps no session registry, so a caller that wants
                ``notifications/tools/list_changed`` delivered has to hand the session over.
        """
        self._sessions.add(session)

    def unregister_session(self, session: Any) -> None:
        """Forget a session that has closed.

        Args:
            session: The ``ServerSession`` previously passed to :meth:`register_session`.
        """
        self._sessions.discard(session)

    @property
    def catalogue_revision(self) -> int:
        """How many times the ``connection`` enum has been re-derived. Shown in the GUI."""
        return self._catalogue_revision

    def close(self) -> None:
        """Close every live database session and both SQLite stores. Safe to call twice."""
        with self._lock:
            for context in self._contexts.values():
                try:
                    context.db.close()
                except Exception:  # pragma: no cover - close is best effort
                    logger.debug("Error closing %r", context.display_name, exc_info=True)
            self._contexts.clear()
        stores: list[Any] = [self.connections, self.permissions]
        if self._owns_log_store:
            stores.append(self.log_store)
        for store in stores:
            try:
                store.close()
            except Exception:  # pragma: no cover - close is best effort
                logger.debug("Error closing a store", exc_info=True)

    # -- the connection enum ---------------------------------------------

    def refresh_connections(self) -> None:
        """Re-derive the ``connection`` enum from the registry and tell clients.

        Called by the GUI after any connection is added, renamed or deleted. Cheap and
        idempotent: it mutates one property of each tool's input schema and leaves the
        closures alone. Re-registering the tools instead would churn tool identity for a
        change that alters one keyword, and would open a window in which ``tools/list``
        returns a partial catalogue.
        """
        try:
            names = sorted(str(profile["display_name"]) for profile in self.connections.all())
        except Exception as exc:  # pragma: no cover - registry unreadable
            logger.warning("Could not re-derive the connection enum: %s", exc)
            return

        for tool in self.server._tool_manager._tools.values():
            prop = (tool.parameters or {}).get("properties", {}).get("connection")
            if prop is None:
                continue
            if names:
                prop["enum"] = names
                prop["description"] = CONNECTION_ARG_DESCRIPTION
            else:
                prop.pop("enum", None)
                prop["description"] = NO_CONNECTIONS_DESCRIPTION

        self._catalogue_revision += 1
        self._schedule_tools_changed()

    def _schedule_tools_changed(self) -> None:
        """Emit ``notifications/tools/list_changed`` across the thread boundary, if we can.

        A notification has no acknowledgement and no guarantee the client re-reads the list,
        so everything downstream is designed to be correct with a stale catalogue: a name
        the enum no longer holds simply fails at ``_resolve_connection()``. Failures are
        logged at warning and swallowed, exactly as logging failures are.
        """
        portal = self._portal
        if portal is None:
            return
        try:
            portal.start_task_soon(self._notify_tools_changed)
        except Exception as exc:  # pragma: no cover - portal closing under us
            logger.warning("Could not schedule tools/list_changed: %s", exc)

    async def _notify_tools_changed(self) -> None:
        """Send the notification through whichever channel this SDK build offers."""
        helper = getattr(self.server, "notify_tool_list_changed", None)
        if callable(helper):
            try:
                await helper()
            except Exception as exc:  # pragma: no cover - transport level
                logger.warning("tools/list_changed was not delivered: %s", exc)
            return
        for session in tuple(self._sessions):
            try:
                await session.send_tool_list_changed()
            except Exception as exc:  # pragma: no cover - transport level
                logger.warning("tools/list_changed was not delivered to a session: %s", exc)

    # -- audit -----------------------------------------------------------

    def _emit_tool_executed(
        self,
        tool_name: str,
        params: dict[str, Any],
        result: str | None = None,
        error: str | None = None,
        *,
        connection: str | None = None,
        exc: BaseException | None = None,
        started: float | None = None,
        rows_affected: int | None = None,
    ) -> None:
        """Write one audit row and one JSONL line, and notify the GUI. Never raises.

        Args:
            tool_name: The MCP tool name, hyphenated as the client sees it.
            params: Structural arguments only — counts, key names and object names, never a
                bound value and never a returned row (DESIGN-MCP-TOOLS.md §6.4).
            result: A short summary sentence, never the payload.
            error: The failure message, already scrubbed of anything credential-shaped.
            connection: The display name the caller supplied, used to look the
                ``connection_id`` up. A name that resolves to nothing still writes a row with
                a null id: losing the record of a call naming a connection that does not
                exist would hide exactly the probing the log is for.
            exc: The exception, so the decision can be read off its type rather than
                guessed from the message.
            started: ``perf_counter()`` taken before the work, for ``duration_ms``.
            rows_affected: Rows returned or changed, where the verb has a count.
        """
        decision, matched_rule_id = _decision_for(exc, error)
        duration_ms = None if started is None else int((perf_counter() - started) * 1000)

        connection_id: int | None = None
        if connection:
            try:
                profile = self.connections.get_by_name(connection)
                connection_id = None if profile is None else int(profile["id"])
            except Exception:  # pragma: no cover - registry unreadable mid-call
                connection_id = None

        try:
            self.logger.log_execution(
                tool_name,
                params,
                result,
                error,
                connection_id=connection_id,
                decision=decision,
                duration_ms=duration_ms,
                rows_affected=rows_affected,
                matched_rule_id=matched_rule_id,
            )
        except Exception:  # pragma: no cover - ToolLogger already swallows its own
            logger.warning("Tool execution logging failed for %s", tool_name, exc_info=True)

        if self.tool_executed_callback:
            try:
                self.tool_executed_callback(tool_name, params, result, error)
            except Exception:
                logger.warning("The tool_executed callback raised for %s", tool_name, exc_info=True)

    # -- connections -----------------------------------------------------

    def _resolve_connection(self, connection: str) -> ConnectionContext:
        """Look a display name up in the live registry and return an open context.

        This is the security boundary the ``connection`` enum only advertises: a name that is
        not in the registry raises here whatever the client believed.

        Args:
            connection: The display name the model sent.

        Returns:
            The cached context, reopened if the profile changed since it was opened.

        Raises:
            ValueError: The registry is empty, or holds no connection of that name.
            RuntimeError: The connection could not be opened; the driver's own message is
                scrubbed of anything credential-shaped before it is re-raised.
        """
        if not isinstance(connection, str) or not connection.strip():
            raise ValueError("connection must be the display name of a configured d-MCP connection")

        profile = self.connections.get_by_name(connection)
        if profile is None:
            if not self.connections.all_ids():
                raise ValueError(
                    "no database connections are configured; add one in the d-MCP "
                    "Connections page"
                )
            known = ", ".join(sorted(str(p["display_name"]) for p in self.connections.all()))
            raise ValueError(
                f"there is no d-MCP connection called {connection!r}; the configured "
                f"connections are: {known}"
            )

        connection_id = int(profile["id"])
        key = (connection_id, threading.get_ident())
        with self._lock:
            cached = self._contexts.get(key)
            if cached is not None:
                if cached.profile.get("updated_at") == profile.get("updated_at") and not cached.db.closed:
                    return cached
                # The operator edited the profile, or the session died. Either way the old
                # session is answering for a configuration nobody approved any more.
                try:
                    cached.db.close()
                except Exception:  # pragma: no cover - close is best effort
                    logger.debug("Error closing a stale session", exc_info=True)
                del self._contexts[key]
            self._drop_dead_threads()

            password = self._password_for(profile)
            try:
                db = db_engine.connect(profile, password)
            except Exception as exc:
                self._reachable[connection_id] = False
                raise RuntimeError(
                    f"the connection {connection!r} could not be opened: "
                    f"{_scrub(str(exc), password)}"
                ) from None

            guard = SqlGuard(db.dialect)
            context = ConnectionContext(
                connection_id=connection_id,
                display_name=str(profile["display_name"]),
                profile=profile,
                db=db,
                dialect=db.dialect,
                introspector=Introspector(db),
                guard=guard,
                security=SecurityManager(db, guard=guard),
            )
            self._contexts[key] = context
            self._reachable[connection_id] = True
            return context

    def _drop_dead_threads(self) -> None:
        """Close the sessions of worker threads that have finished. Caller holds the lock.

        A thread pool that shrinks would otherwise leave one open session per retired
        thread, and on a file database that is a file handle nobody will ever close.
        """
        alive = {thread.ident for thread in threading.enumerate()}
        for key in [k for k in self._contexts if k[1] not in alive]:
            context = self._contexts.pop(key)
            try:
                context.db.close()
            except Exception:  # pragma: no cover - close is best effort
                logger.debug("Error closing the session of a finished thread", exc_info=True)

    def _password_for(self, profile: dict[str, Any]) -> str | None:
        """The stored password for a profile, or ``None`` where the engine needs none.

        Args:
            profile: The connection profile row.

        Returns:
            The secret, held only as a local name by the caller and never logged.

        Raises:
            RuntimeError: The credential store exists but is locked, which a headless server
                cannot resolve by itself and must therefore say plainly.
        """
        if str(profile.get("engine")) == "sqlite":
            return None
        if self._credentials is None:
            from sape_d_mcp.db.credential_store import CredentialStore

            self._credentials = CredentialStore()
        try:
            return self._credentials.get_password(int(profile["id"]))
        except Exception as exc:
            raise RuntimeError(
                f"the password for {profile['display_name']!r} could not be read: {exc}"
            ) from None

    # -- identifiers -----------------------------------------------------

    def _object(
        self,
        context: ConnectionContext,
        name: str,
        schema: str | None,
        object_type: ObjectType,
    ) -> NormalisedRef:
        """Resolve a tool argument to a catalogue object, or refuse.

        The name may be given as ``schema.name`` or as ``name`` with ``schema`` supplied
        separately; the two must agree when both are present. An unqualified name is resolved
        against the connection's own default schema and refused outright when the connection
        has none to offer — a permission rule keys on a schema, so a name with no schema
        cannot be checked against one.

        Args:
            context: The resolved connection.
            name: The object name from the tool arguments.
            schema: The schema from the tool arguments, or ``None``.
            object_type: What kind of object the tool is addressing.

        Returns:
            The ``NormalisedRef`` carrying the catalogue's own spelling.

        Raises:
            ValueError: Malformed, ambiguous, or unqualifiable input.
            LookupError: The catalogue holds no such object.
        """
        bare, qualifier = self._split_name(context, name, schema, object_type)
        return context.introspector.resolve(bare, qualifier, object_type)

    def _prospective(
        self,
        context: ConnectionContext,
        name: str,
        schema: str | None,
        object_type: ObjectType,
    ) -> NormalisedRef:
        """Mint the reference for an object a ``create-*`` tool is about to bring into being.

        :meth:`_object` cannot serve here — it resolves against the catalogue, and the whole
        point of a create is that the catalogue does not hold the name yet. The reference is
        minted through ``Dialect.normalise_ref()``, which applies the **unquoted** folding
        rule, and that is the correct one: this is a name a model typed as an argument, not a
        spelling read back out of a server's own catalogue, so PostgreSQL's ``Foo`` must
        become ``foo`` exactly as it would if the ``CREATE`` were typed at a prompt. Folding
        it the other way would create ``foo`` and write the audit row against ``Foo``.

        The permission rule is then checked against a name nothing has confirmed exists,
        which is the one thing that makes ``create`` grantable at all: a rule pattern is
        matched against the key, and the key is derived from the argument.

        Args:
            context: The resolved connection.
            name: The object name from the tool arguments.
            schema: The schema from the tool arguments, or ``None``.
            object_type: What kind of object is being created.

        Returns:
            A ``NormalisedRef`` for an object that may or may not exist.

        Raises:
            ValueError: Malformed or unqualifiable input, or an identifier the dialect will
                not accept — an identifier d-MCP cannot quote is one it will not create.
        """
        bare, qualifier = self._split_name(context, name, schema, object_type)
        try:
            return context.dialect.normalise_ref(ObjectRef(qualifier, bare, object_type))
        except DialectError as exc:
            raise ValueError(f"{name!r} is not a usable {object_type} name: {exc}") from None

    def _require_absent(self, context: ConnectionContext, ref: NormalisedRef) -> None:
        """Refuse a ``create-*`` whose name the catalogue already holds (§8.1).

        ``create-*`` is not brokered *because* it destroys nothing, so a create that silently
        replaced something would be an ``edit`` with the approval step deleted. The dialects
        refuse ``OR REPLACE`` for the same reason; this closes the other half of it, the
        engine's own "already exists" error, which some engines report in a way a caller can
        mistake for success.

        Args:
            context: The resolved connection.
            ref: The prospective object.

        Raises:
            ValueError: The catalogue already holds an object of that type and name.
        """
        try:
            context.introspector.resolve(
                ref.canonical_name, ref.canonical_schema, ref.object_type
            )
        except LookupError:
            return
        except ValueError:
            # Ambiguous: more than one object already answers to that name. Whatever else
            # that is, it is not "nothing is there".
            pass
        raise ValueError(
            f"{_qualified(ref)} already exists. d-MCP will not replace an object behind a "
            "'create' grant, and there is no other route: the drop and edit tools are always "
            "denied (docs/adr/0005), so an object that exists can be neither replaced nor "
            "removed through d-MCP. Changing it is a job for a database client."
        )

    def _split_name(
        self,
        context: ConnectionContext,
        name: str,
        schema: str | None,
        object_type: ObjectType,
    ) -> tuple[str, str]:
        """Split a tool's ``name``/``schema`` pair into a bare name and a settled schema.

        Shared by :meth:`_object` and :meth:`_prospective` so that "what does
        ``Sales.Orders`` mean" has exactly one answer whether the object exists yet or not.

        Args:
            context: The resolved connection.
            name: The object name from the tool arguments, optionally qualified.
            schema: The schema argument, or ``None``.
            object_type: What kind of object the tool is addressing, for the error text.

        Returns:
            ``(bare_name, schema)``, both stripped and both non-empty.

        Raises:
            ValueError: Malformed, contradictory, or unqualifiable input.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"a {object_type} name is required")
        if "\x00" in name or (schema is not None and "\x00" in schema):
            raise ValueError("an identifier must not contain a null byte")

        bare = name.strip()
        parts = bare.split(".")
        if len(parts) > 2:
            raise ValueError(
                f"{name!r} names more than a schema and an object. A d-MCP connection "
                "authorises one database, so a three-part name cannot be checked against "
                "any rule."
            )
        if len(parts) == 2:
            qualifier, bare = parts[0].strip(), parts[1].strip()
            if not qualifier or not bare:
                raise ValueError(f"{name!r} is not a usable schema-qualified name")
            if schema is not None and schema.strip() and schema.strip() != qualifier:
                raise ValueError(
                    f"the schema argument {schema!r} and the qualified name {name!r} "
                    "disagree; pass one or the other"
                )
            schema = qualifier

        if schema is None or not str(schema).strip():
            schema = context.default_schema
        if schema is None:
            raise ValueError(
                f"permission checks require a schema-qualified name, got {name!r}: this "
                "connection has no default schema d-MCP can resolve against, so pass the "
                "schema explicitly"
            )

        return bare, str(schema).strip()

    # -- authorisation ---------------------------------------------------

    def _require(self, context: ConnectionContext, ref: NormalisedRef, action: str) -> None:
        """Authorise one action on one object, tagging the denial with the rule that decided it.

        Args:
            context: The resolved connection.
            ref: The object, in the catalogue's own spelling.
            action: The action from that object type's tuple.

        Raises:
            ActionForbidden: For a member of ``FORBIDDEN_ACTIONS`` -- ``drop`` or ``edit``
                (ADR 0005 §4). It is deliberately left *untagged*, so ``matched_rule_id``
                stays ``None`` in the audit row: the prohibition is a property of the verb
                and no rule decided it. Tagging it would file the refusal against whichever
                rule happens to match the object -- on the operator's own database, rule
                id 4, which never made that decision -- and the Logs page would link the
                operator straight to a rule that has nothing to do with it. The test is on
                the type rather than on the action, so a third verb joining the set is
                covered on the day it does.
            PermissionDenied: Carrying ``matched_rule_id`` so the Logs page can link to the
                rule the operator will ask about.
        """
        try:
            self.permissions.require(context.connection_id, ref, action)
        except PermissionDenied as denied:
            if not isinstance(denied, ActionForbidden):
                denied.matched_rule_id = self._rule_id(context, ref)  # type: ignore[attr-defined]
            raise

    def _require_database(self, context: ConnectionContext, action: str) -> None:
        """Authorise a connection-scoped action such as ``read_catalogue`` or ``run_query``.

        Args:
            context: The resolved connection.
            action: One of the ``database`` object type's actions.

        Raises:
            PermissionDenied: A ``database`` rule is resolved by connection alone, so the
                denial names the database rather than an object in it.
        """
        self._require(context, database_scope_ref(str(context.profile.get("database") or "")), action)

    def _require_all(
        self, context: ConnectionContext, targets: Sequence[tuple[NormalisedRef, str]]
    ) -> None:
        """Authorise every ``(object, action)`` pair before the caller acts on any of them.

        This is what makes "authorise everything, then act" hold: it only ever raises, so a
        statement that is partly authorised never runs partly.

        Args:
            context: The resolved connection.
            targets: Every object the statement touches and the action it performs on each.

        Raises:
            ActionForbidden: For a pair whose action is forbidden outright (ADR 0005 §4),
                left untagged for the reason :meth:`_require` gives: the search below would
                otherwise stop at that pair -- ``is_allowed()`` answers ``False`` for a
                forbidden action exactly as it does for an unauthorised one -- and cite the
                rule that merely *matched* the object as though it had refused. The skip is
                defensive today, since the only caller of ``require_write()`` composes DML
                and no tool feeds ``DROP`` text through it; it becomes load-bearing the
                moment a DDL-by-text path exists.
            PermissionDenied: On the first pair no rule authorises.
        """
        try:
            self.permissions.require_all(context.connection_id, targets)
        except PermissionDenied as denied:
            if not isinstance(denied, ActionForbidden):
                for ref, action in targets:
                    if not self.permissions.is_allowed(context.connection_id, ref, action):
                        denied.matched_rule_id = self._rule_id(context, ref)  # type: ignore[attr-defined]
                        break
            raise

    def _rule_id(self, context: ConnectionContext, ref: NormalisedRef) -> int | None:
        """The id of the rule that decided, or ``None`` on default-deny."""
        try:
            rule = self.permissions.rule_for(context.connection_id, ref)
        except Exception:  # pragma: no cover - the denial already carries the message
            return None
        return None if rule is None else int(rule["id"])

    def _targets_for(
        self, context: ConnectionContext, references: Iterable[Reference]
    ) -> list[tuple[NormalisedRef, str]]:
        """Settle what the guard found against the catalogue and expand every view.

        ``Reference.object_type`` is ``None`` for everything the guard pulls out of a ``FROM``
        clause: only the catalogue knows whether ``dbo.Customers`` is a table or a view, and
        the two are different rows in the permission table. Guessing either way would
        authorise one against the other's rule. A view additionally contributes every object
        *its* body reads, recursively — a grant on a view is not a grant on what is
        underneath it.

        One walk serves reads and writes alike, and it has to: ``Reference.action`` already
        carries what each reference needs — ``select`` for a source, ``update``/``delete``/
        ``insert`` for the object a write statement changes — so the write path authorises
        through the same code the read path does rather than through a second enumeration
        that could quietly disagree with it. This is where a subquery hidden in a
        ``delete-rows`` predicate stops being invisible.

        It is not, however, the path a ``CREATE`` takes: the object being created is not in
        the catalogue yet, so :meth:`_prospective` mints its reference and the tool
        authorises ``create`` on it directly. Only what a ``CREATE VIEW`` body *reads* comes
        through here.

        Args:
            context: The resolved connection.
            references: What ``SqlGuard`` enumerated from the statement.

        Returns:
            Every ``(object, action)`` pair the statement needs, views before their bases.

        Raises:
            GuardRefusal: A view whose definition cannot be read or cannot be parsed, or a
                nesting depth that suggests a catalogue this code should not trust.
            LookupError: A name the catalogue does not hold.
        """
        targets: list[tuple[NormalisedRef, str]] = []
        seen: set[NormalisedRef] = set()
        for reference in references:
            self._collect(context, reference.schema, reference.name, reference.action, targets, seen, 0)
        return targets

    def _collect(
        self,
        context: ConnectionContext,
        schema: str | None,
        name: str,
        action: str,
        targets: list[tuple[NormalisedRef, str]],
        seen: set[NormalisedRef],
        depth: int,
    ) -> None:
        """Add one reference and, when it is a view, everything beneath it."""
        if depth > MAX_VIEW_DEPTH:
            raise GuardRefusal(
                f"views nest more than {MAX_VIEW_DEPTH} deep under {schema}.{name}, so d-MCP "
                "cannot enumerate every object this statement reads and will not run it.",
                unresolved=(f"{schema}.{name}",),
            )

        ref = self._find_relation(context, schema, name)
        if ref in seen:
            return
        seen.add(ref)
        targets.append((ref, action))

        if ref.object_type is not ObjectType.VIEW:
            return

        definition = context.introspector.definition_of(ref)
        qualified = _qualified(ref)
        if not definition.available or not definition.text:
            raise GuardRefusal(
                f"the definition of view {qualified} could not be read "
                f"({definition.reason or 'no reason given by the server'}), so the objects it "
                "reads cannot be authorised and the call is refused.",
                unresolved=(qualified,),
            )

        body = _CREATE_VIEW_PREFIX.sub("", definition.text, count=1).strip().rstrip(";").strip()
        try:
            inner = context.guard.require_read_only(
                body, default_schema=ref.canonical_schema or context.default_schema
            )
        except GuardRefusal as refusal:
            raise GuardRefusal(
                f"the definition of view {qualified} could not be attributed "
                f"({refusal}), so d-MCP cannot authorise what the view reads.",
                unresolved=(qualified, *refusal.unresolved),
            ) from None

        for reference in inner:
            self._collect(
                context, reference.schema, reference.name, reference.action, targets, seen, depth + 1
            )

    def _find_relation(
        self, context: ConnectionContext, schema: str | None, name: str
    ) -> NormalisedRef:
        """Find a table or a view the guard named, by match key, in the catalogue.

        The guard hands back **canonical** spellings, so they are keyed with
        ``identifier_match_key()`` directly rather than run through ``Introspector.resolve()``,
        which applies the *unquoted* folding rule appropriate to text a human typed. Folding
        a canonical name a second time turns PostgreSQL's ``"Foo"`` into ``foo`` and
        authorises a different table.

        Args:
            context: The resolved connection.
            schema: The reference's schema, as the guard resolved it.
            name: The reference's name.

        Returns:
            The catalogue's own ``NormalisedRef``, typed table or view.

        Raises:
            ValueError: The reference has no schema, or matches more than one object.
            LookupError: The catalogue holds no such table or view.
        """
        if schema is None:
            raise ValueError(
                f"permission checks require a schema-qualified name, got {name!r}"
            )
        dialect = context.dialect
        try:
            key_schema = dialect.identifier_match_key(schema)
            key_name = dialect.identifier_match_key(name)
        except DialectError as exc:
            raise ValueError(f"{schema}.{name} cannot be keyed against a rule: {exc}") from None

        matches: list[NormalisedRef] = []
        for entry in (*context.introspector.list_tables(), *context.introspector.list_views()):
            ref = entry.ref
            if ref is None or ref.key_name != key_name:
                continue
            if ref.key_schema is not None and ref.key_schema != key_schema:
                continue
            if ref not in matches:
                matches.append(ref)

        if not matches:
            raise LookupError(
                f"no table or view called {schema}.{name} exists in this connection's "
                "catalogue, or it is not visible to this login; d-MCP refuses what it "
                "cannot resolve rather than passing the name to the server"
            )
        if len(matches) > 1:
            spellings = ", ".join(_qualified(m) for m in matches)
            raise ValueError(
                f"{schema}.{name} matches more than one object in this catalogue "
                f"({spellings}); d-MCP will not guess which was meant"
            )
        return matches[0]

    # -- reading ---------------------------------------------------------

    def _columns_for(
        self, context: ConnectionContext, ref: NormalisedRef, columns: Sequence[str] | None
    ) -> list[str]:
        """Validate a requested column list against the catalogue, or expand to all of them.

        ``Dialect.select()`` refuses to emit ``*`` — the result shape would then change under
        a later ``ALTER TABLE``, and the model would be handed a column that appeared after
        the rule was written — so the expansion happens here, where the catalogue is.

        Args:
            context: The resolved connection.
            ref: The table or view being read.
            columns: What the caller asked for, or ``None`` for every column.

        Returns:
            Column names in the catalogue's own spelling.

        Raises:
            ValueError: A column the object does not have, or an empty list.
            LookupError: The object has no columns the catalogue can see.
        """
        described = context.introspector.describe_table(ref)
        available = list(described.column_names)
        if not available:
            raise LookupError(
                f"the catalogue reports no columns for {_qualified(ref)}; it may have been "
                "dropped, or its columns may not be visible to this login"
            )
        if columns is None:
            return available

        if not isinstance(columns, (list, tuple)) or not columns:
            raise ValueError("columns must be a non-empty list of column names, or omitted")
        by_key = {context.dialect.column_match_key(c): c for c in available}
        chosen: list[str] = []
        for requested in columns:
            if not isinstance(requested, str) or not requested.strip():
                raise ValueError("every entry of columns must be a column name")
            try:
                key = context.dialect.column_match_key(requested.strip())
            except DialectError as exc:
                raise ValueError(f"{requested!r} is not a usable column name: {exc}") from None
            if key not in by_key:
                raise ValueError(
                    f"{_qualified(ref)} has no column {requested!r}; it has: "
                    f"{', '.join(available)}"
                )
            chosen.append(by_key[key])
        return chosen

    def _order_by(
        self, context: ConnectionContext, ref: NormalisedRef, order_by: str | None
    ) -> list[tuple[str, bool]]:
        """Parse ``'surname DESC, id'`` into validated, quotable ordering terms.

        Every column is checked against the catalogue and re-emitted in the catalogue's
        spelling; nothing the caller wrote is interpolated into SQL.

        Args:
            context: The resolved connection.
            ref: The object being read.
            order_by: The caller's ordering clause, or ``None``.

        Returns:
            ``(column, ascending)`` pairs, empty when nothing was asked for.

        Raises:
            ValueError: An unknown column or an unrecognised direction.
        """
        if order_by is None or not str(order_by).strip():
            return []
        available = list(context.introspector.describe_table(ref).column_names)
        by_key = {context.dialect.column_match_key(c): c for c in available}

        terms: list[tuple[str, bool]] = []
        for fragment in str(order_by).split(","):
            words = fragment.split()
            if not words or len(words) > 2:
                raise ValueError(
                    f"{fragment.strip()!r} is not a column optionally followed by ASC or DESC"
                )
            direction = True
            if len(words) == 2:
                spelled = words[1].upper()
                if spelled not in ("ASC", "DESC"):
                    raise ValueError(f"{words[1]!r} is not a sort direction; use ASC or DESC")
                direction = spelled == "ASC"
            try:
                key = context.dialect.column_match_key(words[0])
            except DialectError as exc:
                raise ValueError(f"{words[0]!r} is not a usable column name: {exc}") from None
            if key not in by_key:
                raise ValueError(
                    f"{_qualified(ref)} has no column {words[0]!r} to order by; it has: "
                    f"{', '.join(available)}"
                )
            terms.append((by_key[key], direction))
        return terms

    def _where(
        self,
        context: ConnectionContext,
        where: str | None,
        parameters: dict[str, Any] | None,
    ) -> RawPredicate | None:
        """Turn the caller's free-form predicate and its values into a bindable fragment.

        The fragment is SQL d-MCP did not write, so the first thing done to it is to ask the
        guard's own engine-aware lexer whether it is one statement's worth of text. That
        catches the ``;`` that would let a second statement ride along, and with it the
        invisible characters, the MySQL executable comment and the ``GO`` batch separator
        that no SQL tokeniser reports as a split — all as a ``GuardRefusal``, which
        ``audit.db`` records as ``refused`` rather than as a denial no rule ever made. The
        classification it returns is discarded: a predicate is not a statement and its verb
        means nothing. What is wanted here is the refusal.

        ``Dialect.select()`` refuses a ``;`` again when it composes, and that second check is
        the one that does not depend on this one having been called.

        Args:
            context: The resolved connection, for its guard.
            where: The caller's SQL predicate, or ``None`` for no predicate at all.
            parameters: Values for the ``:name`` placeholders in ``where``, or ``None``.

        Returns:
            The fragment, or ``None`` when the caller asked for no predicate.

        Raises:
            ValueError: ``where`` or ``parameters`` is the wrong shape, or values were
                supplied with no fragment to bind them into. The dialect raises the same way
                for a placeholder the fragment binds and ``parameters`` does not supply.
            GuardRefusal: The fragment is more than one statement's worth of text, or is
                lexically undecidable.
        """
        if where is None:
            if parameters:
                supplied = ", ".join(sorted(str(name) for name in parameters))
                raise ValueError(
                    f"`parameters` supplies {supplied}, which the statement never binds: "
                    "there is no `where` fragment for it to bind into"
                )
            return None
        if not isinstance(where, str):
            raise ValueError(
                f"where must be a SQL predicate written as text, not {type(where).__name__}"
            )
        if parameters is not None and not isinstance(parameters, dict):
            raise ValueError(
                "parameters must be an object mapping placeholder names, written without "
                "the colon, to their values"
            )
        if where.strip():
            context.guard.classify(where)
        return RawPredicate(text=where, values=dict(parameters or {}))

    def _select(
        self,
        context: ConnectionContext,
        ref: NormalisedRef,
        columns: Sequence[str] | None,
        where: str | None,
        parameters: dict[str, Any] | None,
        order_by: str | None,
        limit: int,
        offset: int,
    ) -> tuple[dict[str, Any], str, list[str]]:
        """Compose one read, authorise everything the composed text reaches, then run it.

        The caller has already authorised ``ref`` — and, for a view, everything beneath it.
        Nothing here widens it without authorising the widening first: where a ``where``
        fragment is present, the composed statement goes back through the same
        ``guard.require_read_only()`` walk ``run-read-query`` uses, and **every** object it
        names is authorised before the cursor is opened. That re-parse is the whole security
        argument for the fragment, because ``Query.touches`` reports ``ref`` and nothing the
        fragment reaches (DESIGN-MCP-TOOLS.md §4).

        With no fragment there is nothing to re-read: every token of the statement was
        written by the dialect out of identifiers already validated against the catalogue,
        and the guard would find exactly ``ref``, which the caller authorised. The parse is
        skipped there rather than paid for on every structured read.

        Truncation is detected by asking the engine for one row more than the caller wanted
        and discarding it — never by a ``COUNT(*)``, which on a large table costs more than
        the read.

        Args:
            context: The resolved connection.
            ref: The table or view to read.
            columns: Columns to return, or ``None`` for all of them.
            where: The caller's SQL predicate, or ``None``.
            parameters: Values bound to the fragment's ``:name`` placeholders, or ``None``.
            order_by: Ordering clause, or ``None``.
            limit: Rows to return, already validated.
            offset: Rows to skip.

        Returns:
            The row envelope, the composed SQL for the audit row, and every object this read
            was authorised against, ``ref`` first.

        Raises:
            GuardRefusal: The fragment, or the statement composed from it, is not something
                the guard will attribute.
            PermissionDenied: An object the fragment reaches that no rule authorises.
        """
        chosen = self._columns_for(context, ref, columns)
        ordering = self._order_by(context, ref, order_by)
        fragment = self._where(context, where, parameters)

        # row_cap has no default anywhere in this chain: it is passed explicitly, one higher
        # than the caller asked for, so the extra row is what proves truncation.
        query = context.dialect.select(
            ref,
            chosen,
            where=fragment,
            order_by=ordering,
            row_cap=limit + 1,
            offset=offset,
        )

        objects = [_qualified(ref)]
        if fragment is not None:
            references = context.guard.require_read_only(
                query.sql, default_schema=context.default_schema
            )
            targets = self._targets_for(context, references)
            self._require_all(context, targets)
            objects = _merge_objects(objects, [_qualified(target) for target, _ in targets])

        # Defence in depth, DESIGN-MCP-TOOLS.md §9.1 step 11: the statement runs on a session
        # the engine itself will not let write. Everything above this line is d-MCP deciding
        # what to send; this line is the server deciding what it will accept, and the two are
        # independent on purpose. Hardening that fails raises and the read never happens.
        with db_engine.read_only_session(context.db):
            cursor = context.db.execute(query.sql, query.params)
            try:
                fetched = cursor.fetchall()
            finally:
                _close_quietly(cursor)

        types = {
            column.name: column.data_type
            for column in context.introspector.describe_table(ref).columns
        }
        envelope = _envelope(
            [(name, types.get(name)) for name in chosen],
            [tuple(row) for row in fetched],
            limit=limit,
            offset=offset,
        )
        return envelope, query.sql, objects

    # -- writing ---------------------------------------------------------

    def _plan_write(
        self, context: ConnectionContext, sql: str
    ) -> tuple[Any, list[tuple[NormalisedRef, str]]]:
        """Re-parse a composed write and authorise every object it turns out to reach.

        The composition is the dialect's, but the ``where`` fragment inside it is the
        model's, so the statement that is about to run is not one d-MCP wrote end to end.
        This is the re-parse that makes the difference: ``Query.touches`` names only the
        table the caller asked for, and a subquery in the predicate reaches whatever it
        likes. Handing the composed text back to ``guard.require_write()`` is what turns
        ``DELETE FROM Customers WHERE id IN (SELECT cust FROM Orders)`` into a denial that
        names ``Orders``, rather than a delete authorised solely by the grant on
        ``Customers``.

        Nothing is executed here — this method only raises — so a statement that is partly
        authorised never runs partly (DESIGN-PERMISSIONS.md §6.3).

        Args:
            context: The resolved connection.
            sql: The composed statement, placeholders intact.

        Returns:
            The guard's ``StatementPlan`` and every ``(object, action)`` pair it needs. The
            plan is returned as well as the targets because ``update-rows`` reads
            ``has_effective_where`` off it, and that answer must come from *this* parse
            rather than from a second one that could read the text differently.

        Raises:
            GuardRefusal: The composed statement is not one the guard will attribute.
            PermissionDenied: An object it reaches that no rule authorises.
            LookupError: A name the catalogue does not hold.
        """
        plan = context.guard.require_write(sql, default_schema=context.default_schema)
        targets = self._targets_for(context, plan.references)
        self._require_all(context, targets)
        return plan, targets

    def _run_write(self, context: ConnectionContext, query: Any) -> int:
        """Execute one composed write and commit it. Returns the row count, or ``-1``.

        **Not** inside :func:`sape_d_mcp.db.engine.read_only_session`: that block is the read
        path's second line of defence and a write inside it would be refused by the server
        itself. The statement budget still applies — ``engine.connect()`` sets it once per
        session, out of the connection profile, so every statement on this session carries it
        whether or not the caller thought about it.

        Autocommit, per DESIGN-MCP-TOOLS.md §7: the LLM gets no transaction control, and a
        transaction opened by one tool call and left for another to close is a lock held
        across an unbounded gap. A multi-row ``INSERT`` is one statement, so the "one
        transaction, no partial batch" §7 asks for is a property of the statement rather than
        of a wrapper around it.

        Args:
            context: The resolved connection.
            query: The dialect-composed ``Query``.

        Returns:
            ``cursor.rowcount``, or ``-1`` where the driver does not report one.

        Raises:
            RuntimeError: The session is currently hardened read-only, which means a caller
                nested a write inside a read block — a bug, and one that would otherwise
                surface as an unhelpful driver error.
        """
        self._refuse_read_only_session(context)
        cursor = context.db.execute(query.sql, query.params)
        try:
            affected = getattr(cursor, "rowcount", -1)
        finally:
            _close_quietly(cursor)
        self._commit(context)
        return -1 if affected is None else int(affected)

    def _run_script(self, context: ConnectionContext, script: Script) -> None:
        """Execute a DDL ``Script``, and put back what it destroyed if it fails halfway.

        A one-step script is the common case and needs nothing clever. The case this method
        exists for is the other one: MySQL cannot replace a routine in a single statement, so
        ``edit_routine()`` returns a drop followed by a create, MySQL commits implicitly on
        DDL, and there is therefore a window in which the routine is simply gone. When the
        create fails in that window, ``script.rollback`` holds the definition read *before*
        the drop, and this runs it.

        When even that fails, the previous definition goes into the error message verbatim
        (DESIGN-MCP-TOOLS.md §7). That is not decoration: the audit row's ``error`` column is
        then the only place in the world holding the text needed to restore the object, and a
        message that said "restore failed" without saying what to restore would be a
        footnote on a data-loss incident.

        Args:
            context: The resolved connection.
            script: The dialect-composed script.

        Raises:
            RuntimeError: The script failed. The message says whether the previous definition
                was put back, and carries it verbatim when it was not.
            Exception: Whatever the driver raised, when the *first* step failed and nothing
                had yet been destroyed — re-raised unwrapped, because the original error is
                the whole story there.
        """
        self._refuse_read_only_session(context)
        executed = 0
        try:
            for step in script.steps:
                _close_quietly(context.db.execute(step.sql, step.params))
                executed += 1
            self._commit(context)
            return
        except Exception as failure:
            self._rollback(context)
            if executed == 0 or not script.rollback:
                # Nothing ran, or nothing was kept to put back. The driver's own message is
                # the most useful thing anyone will read here.
                raise
            try:
                for step in script.rollback:
                    _close_quietly(context.db.execute(step.sql, step.params))
                self._commit(context)
            except Exception as restore_failure:
                self._rollback(context)
                restore_sql = "\n".join(step.sql for step in script.rollback)
                raise RuntimeError(
                    f"{failure}. d-MCP then tried to restore the previous definition and "
                    f"that failed too ({restore_failure}), so the object is now missing. "
                    f"Restore it by hand with:\n{restore_sql}"
                ) from None
            raise RuntimeError(
                f"{failure}. The previous definition was restored, so the object is as it "
                "was before this call."
            ) from None
        finally:
            context.introspector.invalidate()

    def _refuse_read_only_session(self, context: ConnectionContext) -> None:
        """Refuse to write on a session a read block is currently holding hardened."""
        if context.db.read_only:
            raise RuntimeError(
                "this session is currently hardened read-only for a read, so d-MCP will not "
                "write on it; this is a d-MCP bug rather than anything the caller did"
            )

    def _commit(self, context: ConnectionContext) -> None:
        """Commit the write. Reaches through to the DB-API connection deliberately.

        ``DatabaseConnection`` is a thin holder for the raw handle, its dialect and its
        traits, and does not offer a ``commit()`` of its own — deliberately, because until
        now nothing in d-MCP wrote anything. Rather than grow the engine layer a method with
        one caller, the write path uses the DB-API 2.0 method every driver d-MCP ships has.
        A failure here is *not* swallowed: an uncommitted write reported as a success is the
        worst outcome available.
        """
        context.db.raw.commit()

    def _rollback(self, context: ConnectionContext) -> None:
        """Undo whatever the failed statement left open. Best effort, never raises.

        Some engines (MySQL on DDL) will have committed already and there is nothing to roll
        back; some drivers raise on a rollback with no transaction open. Neither is worth
        masking the real failure for.
        """
        try:
            context.db.raw.rollback()
        except Exception:  # pragma: no cover - driver dependent
            logger.debug("Rollback after a failed write did not take", exc_info=True)

    # -- the confirmation broker -----------------------------------------

    def _brokered(self, tool_name: str, plan: Any | None = None) -> bool:
        """Whether this call has to wait for a human (DESIGN-MCP-TOOLS.md §8.1).

        Args:
            tool_name: The MCP tool name.
            plan: The guard's plan for the composed statement, where there is one. Only
                ``update-rows`` consults it, and it is required there: brokering a
                conditional tool without knowing what the statement says would either ask
                every time (friction the design explicitly declined) or never (a table-wide
                UPDATE with nobody watching).

        Returns:
            True when :meth:`_confirm` must be called before executing.

        Raises:
            RuntimeError: ``tool_name`` is conditionally brokered and no plan was supplied.
        """
        if tool_name in BROKERED:
            return True
        if tool_name not in CONDITIONALLY_BROKERED:
            return False
        if plan is None:
            raise RuntimeError(
                f"{tool_name} is brokered conditionally and its statement was not planned; "
                "d-MCP refuses rather than guessing which way"
            )
        return not plan.has_effective_where

    def _confirm(
        self,
        context: ConnectionContext,
        tool_name: str,
        sql: str,
        impact: str,
    ) -> None:
        """Wait for a human to approve one statement, or raise.

        Args:
            context: The resolved connection, for the display name the modal shows.
            tool_name: The MCP tool name, which is half the triple an approval binds to.
            sql: The exact statement, placeholders intact and never with binds interpolated
                — a human approving a paraphrase has not approved the statement.
            impact: The estimate, or ``""`` when it could not be made. Blank is the dialog's
                own contract for "tell them they are approving blind".

        Raises:
            ConfirmationRefused: No broker, no subscriber, a timeout, or an operator saying
                no. All four are one exception type mapping to one audit decision,
                ``refused``, with the three-way distinction carried on ``.reason`` and in the
                message (see :mod:`sape_d_mcp.confirmation`).
        """
        broker = self.confirmation
        if broker is None:
            # A --cli server has no broker at all. Identical outcome to a broker with nobody
            # subscribed, and it must be: "nothing is watching" is the state this whole
            # mechanism exists to make safe, not an edge case to fall through.
            raise ConfirmationRefused(
                f"'{tool_name}' needs approval in the d-MCP window, and this server is "
                "running without one attached",
                reason="no_subscriber",
            )
        broker.request(
            connection=context.display_name,
            tool_name=tool_name,
            sql=sql,
            impact=impact,
            timeout=self.confirmation_timeout_s,
        )

    def _impact(
        self,
        context: ConnectionContext,
        tool_name: str,
        ref: NormalisedRef,
        *,
        fragment: RawPredicate | None = None,
        signature: str | None = None,
        warning_key: str | None = None,
    ) -> str:
        """The impact estimate the modal shows, and never a reason the call fails.

        Runs **before** the modal, read-only, under the authorisation already established and
        on the read-only session, under the connection's own statement timeout
        (DESIGN-MCP-TOOLS.md §8.2). Row counts come from
        ``Dialect.count_matching()`` — the same condition the statement carries, composed by
        the same code, because a count restricted by a *different* condition is worse than no
        count — and from ``estimate_row_count()`` where an exact count would cost more than
        the operation being approved.

        A failed estimate does not block: it returns ``""``, which the dialog renders as its
        translated "impact could not be estimated" line, so the human is told they are
        approving blind rather than shown a blank field that reads like a rendering fault.

        Args:
            context: The resolved connection.
            tool_name: Which estimate to make.
            ref: The object being written to or destroyed.
            fragment: The predicate, for the two row-counting tools.
            signature: The **resolved** overload of a routine, where one was resolved — the
                catalogue's own spelling, out of :meth:`_resolve_overload`. It has to reach
                here and not merely the SQL: the object line is what an approver reads first,
                and ``public.add`` above a statement that drops one of three functions called
                ``add`` invites approval of the wrong one.
            warning_key: A ``Script.warning_key`` the dialect attached, translated and shown
                alongside the estimate.

        Returns:
            The impact text, possibly empty, never raising.
        """
        if self.confirmation is None:
            # No broker means no modal, and an estimate nobody will read is a COUNT(*) run
            # against someone's production server for nothing. The refusal follows one line
            # later at `_confirm`, so nothing is lost by not making it.
            return ""
        estimate = ""
        try:
            with db_engine.read_only_session(context.db):
                estimate = self._estimate(context, tool_name, ref, fragment, signature)
        except Exception as exc:
            logger.info(
                "The impact of %s on %s could not be estimated: %s", tool_name, _qualified(ref), exc
            )
            estimate = ""

        warning = self._warning_text(warning_key)
        if not warning:
            return estimate
        # With a warning to show and no estimate, the field is no longer blank, so the
        # dialog's own "approving blind" fallback would never fire. Say it here instead,
        # in the operator's language, rather than let a warning hide a missing estimate.
        return "\n".join([estimate or self._translate("confirmation.impact_unknown"), warning])

    def _estimate(
        self,
        context: ConnectionContext,
        tool_name: str,
        ref: NormalisedRef,
        fragment: RawPredicate | None,
        signature: str | None = None,
    ) -> str:
        """Compose one impact sentence. Raises freely; :meth:`_impact` is what catches."""
        qualified = _addressed(ref, signature)
        if tool_name in ("delete-rows", "update-rows"):
            matched = self._scalar(context, context.dialect.count_matching(ref, where=fragment))
            verb = "deleted" if tool_name == "delete-rows" else "updated"
            return f"{qualified} — {int(matched):,} row(s) would be {verb}".replace(",", " ")
        if tool_name == "drop-table":
            rows = self._scalar(context, context.dialect.estimate_row_count(ref))
            sentence = f"{qualified} — {int(rows):,} row(s) (estimated)".replace(",", " ")
            dependants = self._dependent_views(context, ref)
            if dependants is None:
                return f"{sentence}, dependent views not counted (too many to scan)"
            return f"{sentence}, {dependants} dependent view(s)"
        # drop-view, drop-function, drop-procedure, edit-function, edit-procedure: what is
        # being destroyed is a definition, so its size is the honest measure of it.
        definition = context.introspector.definition_of(ref)
        if not definition.available or not definition.text:
            raise LookupError(
                f"the definition of {qualified} could not be read "
                f"({definition.reason or 'no reason given by the server'})"
            )
        lines = len(definition.text.splitlines()) or 1
        if signature is not None and definition.reason:
            # ``definition_of()`` answers one text per *name*, and where that name carries
            # several overloads the text it returns is all of their bodies concatenated —
            # which is the only honest thing it can do, and says so on ``reason``. Reporting
            # its length as the length of the one overload being dropped would overstate it,
            # so the sentence says what was measured instead of implying something narrower.
            return (
                f"{qualified} — {lines} line(s) of definition across every overload of "
                f"{_qualified(ref)}; only the one named here is dropped"
            )
        return f"{qualified} — its current definition is {lines} line(s) long"

    def _scalar(self, context: ConnectionContext, query: Any) -> Any:
        """The single value one catalogue-shaped query returns."""
        cursor = context.db.execute(query.sql, query.params)
        try:
            row = cursor.fetchone()
        finally:
            _close_quietly(cursor)
        if row is None:
            raise LookupError("the server returned no row for the impact estimate")
        return row[0]

    def _dependent_views(self, context: ConnectionContext, ref: NormalisedRef) -> int | None:
        """How many views read ``ref``, transitively, or ``None`` when it was not worth asking.

        Whoever is about to approve a ``DROP TABLE`` wants to know what else stops working,
        and §8.2's own example of an impact string says "2 dependent views". Counting them
        means expanding every view in the catalogue through the same recursion the read path
        uses, which is one definition read per view — cheap on a small schema, and a modal
        that takes minutes to appear on a warehouse with thousands of them. Above
        :data:`MAX_DEPENDENCY_SCAN_VIEWS` the scan is skipped and the caller says so, which is
        an honest "not counted" rather than a wrong zero.

        A view whose definition cannot be read or parsed is skipped rather than fatal: this is
        an estimate, and refusing to show a row count because one unrelated view is encrypted
        would help nobody.
        """
        views = context.introspector.list_views()
        if len(views) > MAX_DEPENDENCY_SCAN_VIEWS:
            return None
        dependants = 0
        for entry in views:
            if entry.ref is None:
                continue
            try:
                targets = self._targets_for(
                    context,
                    (
                        Reference(
                            object_type=None,
                            schema=entry.ref.canonical_schema,
                            name=entry.ref.canonical_name,
                            action="select",
                        ),
                    ),
                )
            except Exception:
                logger.debug("Could not expand %r while counting dependants", entry.ref, exc_info=True)
                continue
            if any(target == ref for target, _ in targets if target != entry.ref):
                dependants += 1
        return dependants

    def _warning_text(self, warning_key: str | None) -> str:
        """Translate a ``Script.warning_key`` for the confirmation modal, or return ``""``.

        The dialects set ``warning_key`` on exactly the two scripts whose *shape* changes what
        the operator is agreeing to — a SQL Server below 2016 dropping outright because it has
        no ``IF EXISTS``, and a MySQL routine replace that is a drop followed by a create and
        can therefore leave the routine absent. Both reach the human through the impact field,
        because :class:`~sape_d_mcp.confirmation.ConfirmationRequest` has no separate slot for
        them and the impact field is the one piece of free text the dialog renders verbatim.

        A warning that the engine layer produces and nobody ever shows is worse than no
        warning: it reads as covered in review and is invisible in the product.
        """
        if not warning_key:
            return ""
        text = self._translate(warning_key)
        return "" if text == warning_key else text

    def _translate(self, key: str) -> str:
        """One translated string in the operator's language, or the key if there is none.

        Imported lazily and defensively. ``sape_d_mcp.gui.i18n.translations`` is a generated
        dict and a lookup function and imports no PyQt6 — ``main.py --cli`` stays clean — but
        it lives under ``gui/`` all the same, and a trimmed headless install may not ship that
        package at all. Returning the key is what ``translate()`` itself does for a key it
        does not hold, so an absent table degrades exactly as an absent key does.
        """
        try:
            from sape_d_mcp.gui.i18n.translations import translate
        except Exception:  # pragma: no cover - a build without the GUI package
            return key
        language = self._language() if callable(self._language) else self._language
        return translate(key, language or "en-US")

    # -- shared write bodies ---------------------------------------------

    def _write_rows(
        self,
        tool_name: str,
        connection: str,
        table: str,
        schema: str | None,
        where: str | None,
        parameters: dict[str, Any] | None,
        *,
        values: dict[str, Any] | None,
    ) -> str:
        """The shared body of ``update-rows`` and ``delete-rows``.

        The two differ in one clause of SQL and one word of English, and they must not differ
        anywhere else: both take a free-form ``where`` the model wrote, both compose it
        through the dialect, both re-parse the composed statement, and both authorise
        everything that re-parse turns up before a cursor is opened. A second implementation
        of that sequence would eventually be a second, weaker one.

        Where they genuinely differ is the broker: ``delete-rows`` always asks a human,
        ``update-rows`` asks only when the guard reports the composed statement has no
        effective ``WHERE``. That decision is taken from ``plan``, i.e. from the same parse
        that authorised the statement, so the thing approved and the thing authorised cannot
        be two different readings of the text.

        Args:
            tool_name: ``update-rows`` or ``delete-rows``.
            connection: The connection display name.
            table: The table name, optionally schema-qualified.
            schema: The schema argument, or ``None``.
            where: The model's predicate, or ``None`` for every row.
            parameters: Values bound into the predicate's placeholders.
            values: The ``SET`` list for an update; ``None`` for a delete.

        Returns:
            The one-sentence summary §6.2 asks every mutating tool for.
        """
        action = "update" if tool_name == "update-rows" else "delete"
        params: dict[str, Any] = {
            "_connection": connection,
            "table": table,
            "schema": schema,
            # The predicate is logged as written — it is the model's own SQL and an operator
            # reading a refusal needs to see it — while its values, and the values being
            # written, are only ever counted and named (§6.4).
            "where": where,
            "parameters": _shape(parameters),
        }
        if values is not None:
            params["values"] = _shape(values)
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            ref = self._object(context, table, schema, ObjectType.TABLE)
            self._require(context, ref, action)
            params["_objects"] = [_qualified(ref)]

            fragment = self._where(context, where, parameters)
            if values is None:
                query = context.dialect.delete(ref, where=fragment)
            else:
                if not isinstance(values, dict) or not values:
                    raise ValueError("values must be a non-empty object of column name to value")
                query = context.dialect.update(ref, values, where=fragment)

            plan, targets = self._plan_write(context, query.sql)
            params["_objects"] = _merge_objects(
                params["_objects"], [_qualified(target) for target, _ in targets]
            )
            params["_sql"] = query.sql

            if self._brokered(tool_name, plan):
                self._confirm(
                    context,
                    tool_name,
                    query.sql,
                    self._impact(context, tool_name, ref, fragment=fragment),
                )

            affected = self._run_write(context, query)
            summary = _rows_phrase(
                "Updated" if action == "update" else "Deleted",
                affected,
                _qualified(ref),
                "in" if action == "update" else "from",
            )
            self._emit_tool_executed(
                tool_name,
                params,
                summary,
                None,
                connection=connection,
                started=started,
                rows_affected=None if affected < 0 else affected,
            )
            return summary
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _drop_object(
        self,
        tool_name: str,
        connection: str,
        name: str,
        schema: str | None,
        object_type: ObjectType,
    ) -> str:
        """The shared body of ``drop-table`` and ``drop-view``.

        Both are brokered unconditionally, and the impact estimate is the whole reason the
        modal is worth reading: for a table, how many rows and how many views stop working;
        for a view, how much definition is about to stop existing. The dialects never emit
        ``CASCADE``, so what the estimate lists as dependent is what will *break*, not what
        will also be dropped — a distinction the human has to be able to make.

        Args:
            tool_name: ``drop-table`` or ``drop-view``.
            connection: The connection display name.
            name: The object name, optionally schema-qualified.
            schema: The schema argument, or ``None``.
            object_type: ``TABLE`` or ``VIEW``.

        Returns:
            The one-sentence summary §6.2 asks every DDL tool for.
        """
        params: dict[str, Any] = {"_connection": connection, "name": name, "schema": schema}
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            ref = self._object(context, name, schema, object_type)
            self._require(context, ref, "drop")
            params["_objects"] = [_qualified(ref)]

            if object_type is ObjectType.TABLE:
                script = context.dialect.drop_table(ref)
            else:
                script = context.dialect.drop_view(ref)
            sql = "\n".join(step.sql for step in script.steps)
            params["_sql"] = sql

            self._confirm(
                context,
                tool_name,
                sql,
                self._impact(context, tool_name, ref, warning_key=script.warning_key),
            )
            self._run_script(context, script)

            summary = _ddl_summary("drop", str(object_type), _qualified(ref))
            self._emit_tool_executed(
                tool_name, params, summary, None, connection=connection, started=started
            )
            return summary
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _resolve_overload(
        self,
        context: ConnectionContext,
        ref: NormalisedRef,
        object_type: ObjectType,
        signature: str | None,
    ) -> str | None:
        """Turn the model's ``signature`` into the server's own spelling of one overload.

        ``Dialect.resolve_overload()`` is a pure function over rows somebody else has read —
        a dialect executes nothing — so the catalogue lookup belongs here, and this is the
        only place in the module that does it. What comes back is the **catalogue's** string,
        never the caller's: the argument list is the one part of a ``DROP FUNCTION`` that is
        neither a bound value nor an identifier this stack took out of the catalogue and
        quoted, and routing it through the reported overload set is what keeps it that way.
        Handing the model's text to ``drop_routine()`` directly would compose SQL out of a
        string the server never uttered, so it is not done, not even where the two would come
        out identical.

        Args:
            context: The resolved connection.
            ref: The routine, in the catalogue's own spelling.
            object_type: ``FUNCTION`` or ``PROCEDURE``, which decides which listing is read.
            signature: The model's argument list, unmodified. ``None`` means it did not say.

        Returns:
            The overload's signature as the server spells it, or ``None`` when the bare name
            is unambiguous — which is every routine on three of the four engines.

        Raises:
            ValueError: The signature matches no overload, matches two, or was omitted for a
                name that carries several. All three name the real overload set, and all
                three are returned to the model verbatim, because the set it needs to see is
                the one thing it cannot work out for itself.
            CapabilityError: SQLite, which has no stored routine to address at all.
        """
        if signature is None and not context.dialect.overloads_routines:
            # Three engines out of four hold one object per routine name, so "which one" has
            # no answer to get wrong and a catalogue read here would buy a `None` the dialect
            # already declares. On SQLite it would buy worse than nothing: `resolve_overload`
            # refuses outright there, and a drop that today fails saying there are no stored
            # routines would start failing one line earlier, saying the same thing about a
            # question nobody asked. A signature that *was* passed still goes through, so
            # all three still refuse it rather than discarding it.
            return None
        listing = (
            context.introspector.list_functions
            if object_type is ObjectType.FUNCTION
            else context.introspector.list_procedures
        )
        # Compared by reference and not by name: a `NormalisedRef` carries the folded match
        # keys as well as the catalogue spelling, so this is the same comparison the
        # permission resolver makes, on an engine that folds case and on one that does not.
        overloads = [
            entry.signature for entry in listing(ref.canonical_schema) if entry.ref == ref
        ]
        return context.dialect.resolve_overload(ref, signature, overloads)

    def _routine_tool(
        self,
        tool_name: str,
        connection: str,
        name: str,
        body: str | None,
        schema: str | None,
        language: str | None,
        object_type: ObjectType,
        signature: str | None = None,
    ) -> str:
        """The shared body of the six function and procedure DDL tools.

        Six copies of the house pattern would be six places for the audit call, the
        authorisation or the broker hop to drift, and the six differ only in the object type,
        the action and whether a body is supplied at all.

        **What is not authorised here, and why.** DESIGN-MCP-TOOLS.md §5 asks the create and
        edit tools to authorise every object a routine body references. Nothing in d-MCP can
        enumerate those: ``SqlGuard`` refuses routine DDL in terms — "the guard cannot read
        the body of a function, so it cannot say what that body will read once it runs.
        Routine DDL is authorised from the tool's own arguments, not from parsed text" — and
        ``Dialect.create_routine()`` says the same, that parsing a procedural language here
        would be theatre. So this authorises the routine itself and nothing else, the tool
        descriptions say so rather than promising a check that does not happen, and both
        ``edit-*`` tools are brokered so a human reads the body before it lands.

        **Which overload.** Only the drop path takes a ``signature``, and it needs one because
        PostgreSQL addresses a routine by name and argument types. ``create`` and ``edit`` need
        none: the argument list is inside the ``CREATE`` text the caller supplied. The resolved
        overload — the server's spelling, never the model's — then reaches three places, and
        the third is the one easiest to leave out: the composed SQL, the summary the model
        reads back, and the impact line the human approves. An approver shown the bare name is
        being asked about an object the statement does not name.

        Args:
            tool_name: The MCP tool name, for the audit row and the broker triple.
            connection: The connection display name.
            name: The routine name, optionally schema-qualified.
            body: The complete ``CREATE …`` text, or ``None`` for a drop.
            schema: The schema argument, or ``None``.
            language: The declared language, checked against the body rather than applied.
            object_type: ``FUNCTION`` or ``PROCEDURE``.
            signature: The overload discriminator from the tool arguments, passed through
                unmodified so the refusals :meth:`_resolve_overload` raises are the model's to
                read. ``None`` on every path but the two drops.

        Returns:
            The one-sentence summary §6.2 asks every DDL tool for.
        """
        action = tool_name.split("-", 1)[0]
        # The body is not logged as an argument: it *is* the SQL, and `_sql` records the
        # composed statement in full a few lines below. Two copies of a routine body in one
        # audit row is one copy too many.
        params: dict[str, Any] = {"_connection": connection, "name": name, "schema": schema}
        if language is not None:
            params["language"] = language
        if signature is not None:
            params["signature"] = signature
        # What the *server* calls the overload, once the catalogue has been asked. `None`
        # everywhere but an overloaded drop, and `""` is a real value: `f()` is an overload.
        resolved: str | None = None
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            if action == "create":
                ref = self._prospective(context, name, schema, object_type)
                self._require(context, ref, "create")
                params["_objects"] = [_qualified(ref)]
                self._require_absent(context, ref)
                _check_routine_language(body or "", language)
                script = context.dialect.create_routine(ref, body or "", object_type)
            else:
                ref = self._object(context, name, schema, object_type)
                self._require(context, ref, "edit" if action == "edit" else "drop")
                params["_objects"] = [_qualified(ref)]
                if action == "edit":
                    _check_routine_language(body or "", language)
                    # Read the old definition *before* anything is dropped: on MySQL the
                    # replace is a drop and a create with no transaction around it, and this
                    # text is the only way back if the create fails (§7).
                    previous = context.introspector.definition_of(ref)
                    script = context.dialect.edit_routine(
                        ref,
                        body or "",
                        object_type,
                        previous_definition=previous.text if previous.available else None,
                    )
                else:
                    resolved = self._resolve_overload(context, ref, object_type, signature)
                    script = context.dialect.drop_routine(
                        ref, object_type, signature=resolved
                    )

            sql = "\n".join(step.sql for step in script.steps)
            params["_sql"] = sql
            if self._brokered(tool_name):
                self._confirm(
                    context,
                    tool_name,
                    sql,
                    self._impact(
                        context,
                        tool_name,
                        ref,
                        signature=resolved,
                        warning_key=script.warning_key,
                    ),
                )
            self._run_script(context, script)

            summary = _ddl_summary(action, str(object_type), _addressed(ref, resolved))
            self._emit_tool_executed(
                tool_name, params, summary, None, connection=connection, started=started
            )
            return summary
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    # -- tools -----------------------------------------------------------

    def _register_tools(self) -> None:
        """Register the thirty-eight tools of :data:`TOOLS` as closures over this instance."""
        server = self.server

        # -- meta --------------------------------------------------------

        @server.tool(
            name="list-connections",
            description=(
                "List the database connections configured in SAPÉ d-MCP. Use the display_name "
                "of one of these as the 'connection' argument of every other tool. This is "
                "the only tool that does not take a connection."
            ),
            annotations=ToolAnnotations(title="List connections", read_only_hint=True),
        )
        def list_connections() -> list[dict]:
            """List the configured connections.

            Returns one entry per connection with its display name, engine, database and
            default schema. Host, port, username and driver details are deliberately not
            exposed: they are of no use in planning a query and do not belong in a
            transcript. `reachable` reflects the last attempt d-MCP made, not a fresh
            connect, and is null where none has been made in this process.
            """
            params: dict[str, Any] = {}
            started = perf_counter()
            try:
                listed: list[dict] = []
                for profile in self.connections.all():
                    connection_id = int(profile["id"])
                    listed.append(
                        {
                            "display_name": profile["display_name"],
                            "engine": profile["engine"],
                            "database": profile["database"],
                            "default_schema": _profile_default_schema(profile),
                            "rule_count": len(self.permissions.rules(connection_id)),
                            "reachable": self._reachable.get(connection_id),
                        }
                    )
                summary = f"Listed {len(listed)} connection(s)"
                self._emit_tool_executed("list-connections", params, summary, None, started=started)
                return listed
            except Exception as e:
                self._emit_tool_executed("list-connections", params, None, str(e), exc=e, started=started)
                raise

        @server.tool(
            name="show-permissions",
            description=(
                "Show every permission rule in force for a connection: which actions are "
                "allowed on which schemas and object patterns. Each rule also carries the "
                "operator's own name for it where they gave it one, which says what the "
                "rule is for rather than merely what it matches. Call this before planning "
                "work rather than discovering the limits by being refused."
            ),
            annotations=ToolAnnotations(title="Show permissions", read_only_hint=True),
        )
        def show_permissions(connection: str) -> list[dict]:
            """Show the permission rules for one connection.

            Returns one entry per rule, exactly as :func:`permissions.format_rule` renders
            it: `rule_name`, `object_type`, `targets` (a list of `schema_pattern` /
            `name_pattern` pairs, because a rule names a *collection* since `permissions.db`
            schema version 2), `is_deny`, `allowed_actions` and the four audit columns.

            `rule_name` is the operator's own label and is always present, holding `null`
            for a rule nobody has named. Explicit null rather than an omitted key, because
            this is a JSON array a model reads row by row: every row carrying the same keys
            is what lets it be read as a table, and `null` says "unnamed" where `""` would
            read as a name that happens to be empty. `main.py`'s `--show-permissions`
            deliberately does the opposite and prints nothing at all for an unnamed rule —
            that is human text, where a column of `None` is noise, and the asymmetry is
            intended rather than an oversight in either place.

            The name is metadata: `rule_for()` never reads it, so it explains a rule without
            being part of what the rule authorises.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
            """
            params = {"_connection": connection}
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                shown = [format_rule(rule) for rule in self.permissions.rules(context.connection_id)]
                summary = f"Listed {len(shown)} permission rule(s) for {connection}"
                self._emit_tool_executed(
                    "show-permissions", params, summary, None, connection=connection, started=started
                )
                return shown
            except Exception as e:
                self._emit_tool_executed(
                    "show-permissions", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        # -- database ----------------------------------------------------

        @server.tool(
            name="read-catalogue",
            description=(
                "Read a summary of the database: engine and version, default schema, and how "
                "many schemas, tables, views, functions and procedures it holds. Requires "
                "'read_catalogue'."
            ),
            annotations=ToolAnnotations(title="Read database catalogue", read_only_hint=True),
        )
        def read_catalogue(connection: str) -> dict:
            """Summarise the database this connection points at.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
            """
            params = {"_connection": connection}
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                self._require_database(context, "read_catalogue")
                introspector = context.introspector
                traits = context.db.traits
                payload = {
                    "connection": context.display_name,
                    "engine": str(context.dialect.engine),
                    "server_version": None if traits is None else traits.raw_version,
                    "database": context.profile.get("database"),
                    "default_schema": context.default_schema,
                    "schemas": len(introspector.list_schemas()),
                    "tables": len(introspector.list_tables()),
                    "views": len(introspector.list_views()),
                    "functions": len(introspector.list_functions()),
                    "procedures": len(introspector.list_procedures()),
                }
                summary = (
                    f"Read the catalogue of {context.display_name}: {payload['tables']} table(s), "
                    f"{payload['views']} view(s)"
                )
                self._emit_tool_executed(
                    "read-catalogue", params, summary, None, connection=connection, started=started
                )
                return payload
            except Exception as e:
                self._emit_tool_executed(
                    "read-catalogue", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        @server.tool(
            name="list-schemas",
            description="List the schemas in the database. Requires 'read_catalogue'.",
            annotations=ToolAnnotations(title="List schemas", read_only_hint=True),
        )
        def list_schemas(connection: str) -> list[dict]:
            """List the schemas this connection can see.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
            """
            params = {"_connection": connection}
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                self._require_database(context, "read_catalogue")
                listed = [
                    {
                        "name": entry.canonical_name,
                        "addressable": entry.addressable,
                        "unaddressable_reason": entry.unaddressable_reason,
                    }
                    for entry in context.introspector.list_schemas()
                ]
                summary = f"Listed {len(listed)} schema(s)"
                self._emit_tool_executed(
                    "list-schemas", params, summary, None, connection=connection, started=started
                )
                return listed
            except Exception as e:
                self._emit_tool_executed(
                    "list-schemas", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        @server.tool(
            name="list-roles",
            description="List the database roles and who holds them. Requires 'read_catalogue'.",
            annotations=ToolAnnotations(title="List roles", read_only_hint=True),
        )
        def list_roles(connection: str) -> list[dict]:
            """List the database roles.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
            """
            return self._principals("list-roles", connection, "role")

        @server.tool(
            name="list-users",
            description="List the database users. Requires 'read_catalogue'.",
            annotations=ToolAnnotations(title="List users", read_only_hint=True),
        )
        def list_users(connection: str) -> list[dict]:
            """List the database users.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
            """
            return self._principals("list-users", connection, "user")

        @server.tool(
            name="list-groups",
            description=(
                "List the groups (SQL Server database roles used as groups, PostgreSQL "
                "NOLOGIN roles, MySQL roles) and their members. Requires 'read_catalogue'."
            ),
            annotations=ToolAnnotations(title="List groups", read_only_hint=True),
        )
        def list_groups(connection: str) -> list[dict]:
            """List the groups and their members.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
            """
            return self._principals("list-groups", connection, "group")

        # -- security: the seven that change who may do what --------------
        #
        # The one corner of the catalogue where what a tool changes is a principal's rights
        # rather than an object's rows. Three layers, each holding one thing: the dialect
        # authors every statement, ``db/security.py`` runs it and reports it in a sentence
        # and authorises nothing, and this layer authorises, brokers and audits and holds no
        # SQL. The permission gate is the ``database`` action group, resolved by connection
        # alone, so a human ticks ``create_role`` or ``assign_role`` per connection before a
        # model can reach any of this.
        #
        # No tool here takes a password, and none may grow one: §11.2 rules that no
        # credential is accepted from a model, generated by a tool, returned in a result or
        # written to a log, and ``create-user`` therefore creates a principal that cannot log
        # in and says so in its result rather than leaving the model to invent the gap away.

        @server.tool(
            name="create-role",
            description=(
                "Create a database role. It holds no privileges and no members until a "
                "human grants them. Requires 'create_role'. Refused on SQLite, which has no "
                "role, user or group concept at all."
            ),
            annotations=ToolAnnotations(title="Create role", destructive_hint=False),
        )
        def create_role(connection: str, role: str) -> str:
            """Create a database role.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                role: Role name, spelled exactly as it is to be stored — it is quoted, not
                    folded, so 'Analyst' and 'analyst' are two different roles on
                    PostgreSQL.
            """
            return self._security_tool(
                "create-role",
                connection,
                "create_role",
                {"role": role},
                lambda manager, approve: manager.create_role(role),
            )

        @server.tool(
            name="create-user",
            description=(
                "Create a database user. No password is accepted, generated or returned: "
                "the user is created without the ability to log in, and a d-MCP operator "
                "sets its credential outside this tool. Requires 'create_user'. On MySQL an "
                "account is 'name'@'host', so write the username as name@host "
                "(reporting@10.0.0.5, reporting@localhost); a bare name is refused rather "
                "than widened to every host. Refused on SQLite."
            ),
            annotations=ToolAnnotations(title="Create user", destructive_hint=False),
        )
        def create_user(
            connection: str,
            username: str,
            default_schema: str | None = None,
            login: str | None = None,
        ) -> str:
            """Create a database user that cannot log in.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                username: User name. On MySQL write it as name@host.
                default_schema: Schema unqualified names resolve against for this user.
                    Applied where the engine has such a notion and refused where it does
                    not, never accepted and ignored.
                login: Existing server login to map the user to. SQL Server only;
                    PostgreSQL and MySQL refuse it, because a role there is the login.
            """
            return self._security_tool(
                "create-user",
                connection,
                "create_user",
                {"username": username, "default_schema": default_schema, "login": login},
                lambda manager, approve: manager.create_user(
                    username, default_schema=default_schema, login=login
                ),
            )

        @server.tool(
            name="create-group",
            description=(
                "Create a group. None of the four engines has a native group object, so "
                "this creates what the engine actually uses for one — a database role on "
                "SQL Server, a NOLOGIN role on PostgreSQL, a role on MySQL — and the result "
                "says which. Requires 'create_group'. Refused on SQLite."
            ),
            annotations=ToolAnnotations(title="Create group", destructive_hint=False),
        )
        def create_group(connection: str, group: str) -> str:
            """Create a group.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                group: Group name, spelled exactly as it is to be stored.
            """
            return self._security_tool(
                "create-group",
                connection,
                "create_group",
                {"group": group},
                lambda manager, approve: manager.create_group(group),
            )

        @server.tool(
            name="add-user-to-group",
            description=(
                "Add a principal to a group. Requires 'assign_group', which grants both "
                "directions: a human granting the ability to manage membership grants the "
                "ability to remove it too. On MySQL write the username as name@host. "
                "Sessions already open may not see the change until they reconnect. "
                "Refused on SQLite."
            ),
            annotations=ToolAnnotations(title="Add user to group", destructive_hint=False),
        )
        def add_user_to_group(connection: str, username: str, group: str) -> str:
            """Add a user to a group.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                username: The principal to add. On MySQL write it as name@host.
                group: The group to add it to.
            """
            return self._security_tool(
                "add-user-to-group",
                connection,
                "assign_group",
                {"username": username, "group": group},
                lambda manager, approve: manager.add_user_to_group(username, group),
            )

        @server.tool(
            name="remove-user-from-group",
            description=(
                "Remove a principal from a group. Requires 'assign_group' AND approval in "
                "the d-MCP window: add-user-to-group reverses it, but not necessarily as "
                "whoever has just lost the access. Refuses outright to strip the login this "
                "connection is running as. On MySQL write the username as name@host. "
                "Sessions already open may keep the access until they reconnect. Refused on "
                "SQLite."
            ),
            annotations=ToolAnnotations(
                title="Remove user from group", destructive_hint=True
            ),
        )
        def remove_user_from_group(connection: str, username: str, group: str) -> str:
            """Remove a user from a group.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                username: The principal to remove. On MySQL write it as name@host.
                group: The group to remove it from.
            """
            return self._security_tool(
                "remove-user-from-group",
                connection,
                "assign_group",
                {"username": username, "group": group},
                lambda manager, approve: manager.remove_user_from_group(
                    username, group, approve=approve
                ),
                impact=(
                    f"{username} leaves the group {group} and loses every privilege that "
                    f"membership carries. Sessions already open may keep the access until "
                    f"they reconnect, and add-user-to-group puts it back."
                ),
            )

        @server.tool(
            name="assign-role",
            description=(
                "Grant a role to a user, a group or another role. Requires 'assign_role', "
                "which grants both directions of the pair. On MySQL write the grantee as "
                "name@host. Sessions already open may not see the change until they "
                "reconnect. Refused on SQLite."
            ),
            annotations=ToolAnnotations(title="Assign role", destructive_hint=False),
        )
        def assign_role(connection: str, role: str, grantee: str) -> str:
            """Grant a role to a principal.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                role: The role to grant.
                grantee: The user, group or role receiving it. On MySQL write it as
                    name@host.
            """
            return self._security_tool(
                "assign-role",
                connection,
                "assign_role",
                {"role": role, "grantee": grantee},
                lambda manager, approve: manager.assign_role(role, grantee),
            )

        @server.tool(
            name="revoke-role",
            description=(
                "Revoke a role from a user, a group or another role. Requires 'assign_role' "
                "AND approval in the d-MCP window. assign-role puts it back only while some "
                "principal that may still grant the role exists, so check that one does. "
                "Refuses outright to strip the login this connection is running as. On "
                "MySQL write the grantee as name@host. Sessions already open may keep the "
                "access until they reconnect. Refused on SQLite."
            ),
            annotations=ToolAnnotations(title="Revoke role", destructive_hint=True),
        )
        def revoke_role(connection: str, role: str, grantee: str) -> str:
            """Revoke a role from a principal.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                role: The role to revoke.
                grantee: The user, group or role losing it. On MySQL write it as name@host.
            """
            return self._security_tool(
                "revoke-role",
                connection,
                "assign_role",
                {"role": role, "grantee": grantee},
                lambda manager, approve: manager.revoke_role(
                    role, grantee, approve=approve
                ),
                impact=(
                    f"{grantee} loses the role {role} and every privilege that role "
                    f"carries. Sessions already open may keep the access until they "
                    f"reconnect, and only a principal that may still grant {role} can put "
                    f"it back."
                ),
            )

        # -- tables ------------------------------------------------------

        @server.tool(
            name="list-tables",
            description=(
                "List tables. Only tables you have 'list' permission on are returned; the "
                "rest are omitted rather than the call being refused."
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
                schema: Schema to list. Defaults to the connection's default schema; pass '*'
                    for all of them.
                name_pattern: Optional name filter, e.g. 'inv*'. Matched by d-MCP, not by the
                    database.
            """
            return self._list_relations(
                "list-tables", connection, schema, name_pattern, ObjectType.TABLE
            )

        @server.tool(
            name="describe-table",
            description=(
                "Read a table's structure: columns with types, nullability and defaults, the "
                "primary key, foreign keys and unique keys. Requires 'read_structure'."
            ),
            annotations=ToolAnnotations(title="Describe table", read_only_hint=True),
        )
        def describe_table(connection: str, table: str, schema: str | None = None) -> dict:
            """Read a table's structure.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                table: Table name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
            """
            params = {"_connection": connection, "table": table, "schema": schema}
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                ref = self._object(context, table, schema, ObjectType.TABLE)
                self._require(context, ref, "read_structure")
                params["_objects"] = [_qualified(ref)]
                payload = _describe(context.introspector.describe_table(ref), ref)
                summary = f"Described {_qualified(ref)} ({len(payload['columns'])} column(s))"
                self._emit_tool_executed(
                    "describe-table", params, summary, None, connection=connection, started=started
                )
                return payload
            except Exception as e:
                self._emit_tool_executed(
                    "describe-table", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        @server.tool(
            name="select-rows",
            description=(
                "Read rows from a table. Requires 'select' on the table, and on every object "
                "a subquery in `where` reaches. Write :name placeholders in `where` and pass "
                "the values in `parameters`; never write a value into the predicate text. "
                "Returns at most 100 rows by default and 1000 at most; page with limit and "
                "offset, and pass order_by to make paging stable."
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
                where: SQL predicate. Composed into the statement and re-parsed by the SQL
                    guard, so a subquery inside it is authorised like any other reference.
                parameters: Values bound to placeholders in `where`. Never interpolated into
                    the SQL.
                order_by: Column and direction, e.g. 'surname DESC'. Without it, paging past
                    the first page may repeat or skip rows — that is a property of the
                    database, not of d-MCP.
                limit: Rows to return, 1 to 1000.
                offset: Rows to skip before returning.
            """
            params = {
                "_connection": connection,
                "table": table,
                "schema": schema,
                "columns": _shape(columns),
                # The predicate is logged as written — it is the model's own SQL and an
                # operator reading a refusal needs to see it — while its values are only
                # ever counted and named, never recorded.
                "where": where,
                "parameters": _shape(parameters),
                "order_by": order_by,
                "limit": limit,
                "offset": offset,
            }
            started = perf_counter()
            try:
                _check_paging(limit, offset)
                context = self._resolve_connection(connection)
                ref = self._object(context, table, schema, ObjectType.TABLE)
                self._require(context, ref, "select")
                params["_objects"] = [_qualified(ref)]
                envelope, sql, objects = self._select(
                    context, ref, columns, where, parameters, order_by, limit, offset
                )
                params["_objects"] = _merge_objects(params["_objects"], objects)
                params["_sql"] = sql
                summary = (
                    f"Selected {envelope['row_count']} row(s) from {_qualified(ref)}"
                    + (" (truncated)" if envelope["truncated"] else "")
                )
                self._emit_tool_executed(
                    "select-rows",
                    params,
                    summary,
                    None,
                    connection=connection,
                    started=started,
                    rows_affected=envelope["row_count"],
                )
                return envelope
            except Exception as e:
                self._emit_tool_executed(
                    "select-rows", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        # -- views -------------------------------------------------------

        @server.tool(
            name="list-views",
            description=(
                "List views. Only views you have 'list' permission on are returned; the rest "
                "are omitted rather than the call being refused."
            ),
            annotations=ToolAnnotations(title="List views", read_only_hint=True),
        )
        def list_views(
            connection: str,
            schema: str | None = None,
            name_pattern: str | None = None,
        ) -> list[dict]:
            """List the views in a schema.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                schema: Schema to list. Defaults to the connection's default schema; pass '*'
                    for all of them.
                name_pattern: Optional name filter, e.g. 'v_*'. Matched by d-MCP, not by the
                    database.
            """
            return self._list_relations(
                "list-views", connection, schema, name_pattern, ObjectType.VIEW
            )

        @server.tool(
            name="read-view-definition",
            description="Read a view's SQL definition and its column list. Requires 'read_definition'.",
            annotations=ToolAnnotations(title="Read view definition", read_only_hint=True),
        )
        def read_view_definition(connection: str, view: str, schema: str | None = None) -> dict:
            """Read a view's stored definition.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                view: View name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
            """
            params = {"_connection": connection, "view": view, "schema": schema}
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                ref = self._object(context, view, schema, ObjectType.VIEW)
                self._require(context, ref, "read_definition")
                params["_objects"] = [_qualified(ref)]
                definition = context.introspector.definition_of(ref)
                described = context.introspector.describe_table(ref)
                payload = {
                    "schema": ref.canonical_schema,
                    "name": ref.canonical_name,
                    "definition": definition.text,
                    "definition_available": definition.available,
                    "reason": definition.reason,
                    "columns": [
                        {"name": column.name, "type": column.data_type, "nullable": column.nullable}
                        for column in described.columns
                    ],
                }
                summary = (
                    f"Read the definition of {_qualified(ref)}"
                    if definition.available
                    else f"The definition of {_qualified(ref)} was not available"
                )
                self._emit_tool_executed(
                    "read-view-definition", params, summary, None, connection=connection, started=started
                )
                return payload
            except Exception as e:
                self._emit_tool_executed(
                    "read-view-definition", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        @server.tool(
            name="select-view-rows",
            description=(
                "Read rows from a view. Requires 'select' on the view AND 'select' on every "
                "table and view it reads, transitively: permission on a view is not "
                "permission on what is underneath it. A subquery in `where` is authorised "
                "the same way. Capped and paged like select-rows."
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
        ) -> dict:
            """Read rows from a view, having authorised everything beneath it.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                view: View name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
                columns: Columns to return. Defaults to all of them.
                where: SQL predicate. Composed into the statement and re-parsed by the SQL
                    guard, so a subquery inside it is authorised like any other reference —
                    on top of the view's own bases, not instead of them.
                parameters: Values bound to placeholders in `where`. Never interpolated into
                    the SQL.
                order_by: Column and direction, e.g. 'surname DESC'.
                limit: Rows to return, 1 to 1000.
                offset: Rows to skip before returning.
            """
            params = {
                "_connection": connection,
                "view": view,
                "schema": schema,
                "columns": _shape(columns),
                "where": where,
                "parameters": _shape(parameters),
                "order_by": order_by,
                "limit": limit,
                "offset": offset,
            }
            started = perf_counter()
            try:
                _check_paging(limit, offset)
                context = self._resolve_connection(connection)
                ref = self._object(context, view, schema, ObjectType.VIEW)
                # The view and its bases are authorised in one pass, before anything runs:
                # a grant on the view is not a grant on what it reads.
                targets = self._targets_for(
                    context, (Reference(object_type=None, schema=ref.canonical_schema,
                                        name=ref.canonical_name, action="select"),)
                )
                self._require_all(context, targets)
                params["_objects"] = [_qualified(target) for target, _ in targets]
                envelope, sql, objects = self._select(
                    context, ref, columns, where, parameters, order_by, limit, offset
                )
                params["_objects"] = _merge_objects(params["_objects"], objects)
                params["_sql"] = sql
                summary = (
                    f"Selected {envelope['row_count']} row(s) from view {_qualified(ref)}"
                    + (" (truncated)" if envelope["truncated"] else "")
                )
                self._emit_tool_executed(
                    "select-view-rows",
                    params,
                    summary,
                    None,
                    connection=connection,
                    started=started,
                    rows_affected=envelope["row_count"],
                )
                return envelope
            except Exception as e:
                self._emit_tool_executed(
                    "select-view-rows", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        # -- functions and procedures ------------------------------------

        @server.tool(
            name="list-functions",
            description=(
                "List functions. Only functions you have 'list' permission on are returned; "
                "the rest are omitted rather than the call being refused."
            ),
            annotations=ToolAnnotations(title="List functions", read_only_hint=True),
        )
        def list_functions(
            connection: str,
            schema: str | None = None,
            name_pattern: str | None = None,
        ) -> list[dict]:
            """List the functions in a schema.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                schema: Schema to list. Defaults to the connection's default schema; pass '*'
                    for all of them.
                name_pattern: Optional name filter, e.g. 'fn_*'. Matched by d-MCP, not by the
                    database.
            """
            return self._list_routines(
                "list-functions", connection, schema, name_pattern, ObjectType.FUNCTION
            )

        @server.tool(
            name="read-function-definition",
            description="Read a function's source, parameters and return type. Requires 'read_definition'.",
            annotations=ToolAnnotations(title="Read function definition", read_only_hint=True),
        )
        def read_function_definition(
            connection: str, function: str, schema: str | None = None
        ) -> dict:
            """Read a function's source and signature.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                function: Function name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._read_routine(
                "read-function-definition", connection, function, schema, ObjectType.FUNCTION
            )

        @server.tool(
            name="list-procedures",
            description=(
                "List stored procedures. Only procedures you have 'list' permission on are "
                "returned; the rest are omitted rather than the call being refused."
            ),
            annotations=ToolAnnotations(title="List procedures", read_only_hint=True),
        )
        def list_procedures(
            connection: str,
            schema: str | None = None,
            name_pattern: str | None = None,
        ) -> list[dict]:
            """List the stored procedures in a schema.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                schema: Schema to list. Defaults to the connection's default schema; pass '*'
                    for all of them.
                name_pattern: Optional name filter, e.g. 'sp_*'. Matched by d-MCP, not by the
                    database.
            """
            return self._list_routines(
                "list-procedures", connection, schema, name_pattern, ObjectType.PROCEDURE
            )

        @server.tool(
            name="read-procedure-definition",
            description="Read a procedure's source and parameters. Requires 'read_definition'.",
            annotations=ToolAnnotations(title="Read procedure definition", read_only_hint=True),
        )
        def read_procedure_definition(
            connection: str, procedure: str, schema: str | None = None
        ) -> dict:
            """Read a stored procedure's source and signature.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                procedure: Procedure name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._read_routine(
                "read-procedure-definition", connection, procedure, schema, ObjectType.PROCEDURE
            )

        # -- free-form SQL -----------------------------------------------

        @server.tool(
            name="run-read-query",
            description=(
                "Run one read-only SQL statement and return its rows. A single SELECT (or a "
                "WITH whose CTEs are all SELECTs); anything else, including multiple "
                "statements, is refused. Requires 'run_query' on this connection, plus "
                "'select' permission on every table and view the statement reads — "
                "including, transitively, every object read by a view it names. Bind values "
                "by writing :name placeholders in the SQL and passing them in `parameters`; "
                "never write a value into the statement text."
            ),
            annotations=ToolAnnotations(title="Run a read-only query", read_only_hint=True),
        )
        def run_read_query(
            connection: str,
            sql: str,
            parameters: dict[str, Any] | None = None,
            limit: int = DEFAULT_ROW_LIMIT,
            offset: int = 0,
        ) -> dict:
            """Run one read-only statement.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                sql: One SELECT or read-only WITH statement. Placeholders are written
                    :name whatever the engine; d-MCP rewrites them for the driver.
                parameters: Values bound to the :name placeholders. Never interpolated.
                limit: Rows to return, 1 to 1000.
                offset: Rows to skip. The skip happens after the server has produced the
                    rows, so a large offset costs what reading that many rows costs.
            """
            params = {
                "_connection": connection,
                "parameters": _shape(parameters),
                "limit": limit,
                "offset": offset,
            }
            started = perf_counter()
            try:
                _check_paging(limit, offset)
                context = self._resolve_connection(connection)
                # Step 1 of the gate: the per-connection switch, checked before anything is
                # even parsed. An operator can leave a connection reachable only through the
                # structured tools by never granting run_query.
                self._require_database(context, "run_query")

                references = context.guard.require_read_only(
                    sql, default_schema=context.default_schema
                )
                targets = self._targets_for(context, references)
                self._require_all(context, targets)
                params["_objects"] = [_qualified(target) for target, _ in targets]

                bound_sql, bound_params = _bind_placeholders(context.dialect, sql, parameters)
                # The rewrite only replaces placeholder tokens, but re-checking costs one
                # parse and closes the gap between "what was authorised" and "what will run".
                rewritten = context.guard.require_read_only(
                    bound_sql, default_schema=context.default_schema
                )
                if set(rewritten) != set(references):
                    raise GuardRefusal(
                        "binding the parameters changed what the statement reads, so d-MCP "
                        "will not run it"
                    )
                params["_sql"] = bound_sql

                # Defence in depth, DESIGN-MCP-TOOLS.md §9.1 step 11. This is the tool the
                # step was written for: the model authored this SQL, the guard is the only
                # thing that has read it, and a guard that is the only line of defence is one
                # bug away from being none. The session the statement runs on refuses to
                # write whatever the guard concluded.
                with db_engine.read_only_session(context.db):
                    cursor = context.db.execute(bound_sql, bound_params)
                    try:
                        # The skip is client-side: wrapping arbitrary SQL in a portable
                        # LIMIT/OFFSET is not possible across these four engines (SQL Server's
                        # OFFSET needs its own ORDER BY), and rewriting the model's statement
                        # to add one would change the text the guard authorised. One row more
                        # than was asked for is fetched, and that extra row is the proof of
                        # truncation.
                        produced = [tuple(row) for row in cursor.fetchmany(offset + limit + 1)]
                        description = cursor.description or ()
                    finally:
                        _close_quietly(cursor)
                fetched = produced[offset:]

                envelope = _envelope(
                    [(str(column[0]), None) for column in description],
                    fetched,
                    limit=limit,
                    offset=offset,
                )
                summary = (
                    f"Ran a read-only query on {context.display_name} returning "
                    f"{envelope['row_count']} row(s)"
                    + (" (truncated)" if envelope["truncated"] else "")
                )
                self._emit_tool_executed(
                    "run-read-query",
                    params,
                    summary,
                    None,
                    connection=connection,
                    started=started,
                    rows_affected=envelope["row_count"],
                )
                return envelope
            except Exception as e:
                self._emit_tool_executed(
                    "run-read-query", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        # -- tables: writing and DDL -------------------------------------

        @server.tool(
            name="insert-rows",
            description=(
                "Insert rows into a table. Values are bound, never interpolated. All rows go "
                "in one statement, so a partial batch never lands. Requires 'insert'."
            ),
            annotations=ToolAnnotations(title="Insert rows", destructive_hint=False),
        )
        def insert_rows(
            connection: str,
            table: str,
            rows: list[dict[str, Any]],
            schema: str | None = None,
        ) -> str:
            """Insert rows into a table.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                table: Table name, optionally schema-qualified.
                rows: One object per row, mapping column name to value. Every row must name
                    the same columns: a column left out of one row is a value the server
                    would choose and you would never be told about.
                schema: Schema name. Defaults to the connection's default schema.
            """
            params = {
                "_connection": connection,
                "table": table,
                "schema": schema,
                "rows": _shape(rows),
            }
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                ref = self._object(context, table, schema, ObjectType.TABLE)
                self._require(context, ref, "insert")
                params["_objects"] = [_qualified(ref)]
                if not isinstance(rows, (list, tuple)) or not rows:
                    raise ValueError("rows must be a non-empty list of objects")
                # No re-parse: every token of this statement was written by the dialect out
                # of identifiers already validated against the catalogue, and there is no
                # free-form fragment for anything to hide in.
                query = context.dialect.insert(ref, rows)
                params["_sql"] = query.sql
                affected = self._run_write(context, query)
                if affected < 0:
                    affected = len(rows)
                summary = _rows_phrase("Inserted", affected, _qualified(ref), "into")
                self._emit_tool_executed(
                    "insert-rows",
                    params,
                    summary,
                    None,
                    connection=connection,
                    started=started,
                    rows_affected=affected,
                )
                return summary
            except Exception as e:
                self._emit_tool_executed(
                    "insert-rows", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

        @server.tool(
            name="update-rows",
            description=(
                "Update rows in a table. Requires 'update' on the table, and 'select' on "
                "every object a subquery in `where` reaches. Write :name placeholders in "
                "`where` and pass the values in `parameters`; never write a value into the "
                "predicate text. Omitting `where` updates every row, and so does a predicate "
                "that filters nothing such as '1=1' — both additionally require approval in "
                "the d-MCP window."
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
        ) -> str:
            """Update rows in a table.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                table: Table name, optionally schema-qualified.
                values: Column name to new value. Bound, never interpolated.
                where: SQL predicate selecting the rows to change. Composed into the
                    statement and re-parsed by the SQL guard, so a subquery inside it is
                    authorised like any other reference. Omitting it updates every row.
                parameters: Values bound to placeholders in `where`. Never interpolated.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._write_rows(
                "update-rows", connection, table, schema, where, parameters, values=values
            )

        @server.tool(
            name="delete-rows",
            description=(
                "Delete rows from a table. Requires 'delete' on the table, 'select' on every "
                "object a subquery in `where` reaches, and approval in the d-MCP window — "
                "always, even with a WHERE, because deleted rows do not come back. Write "
                ":name placeholders in `where` and pass the values in `parameters`. Omitting "
                "`where` deletes every row."
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
                where: SQL predicate selecting the rows to delete. Composed into the
                    statement and re-parsed by the SQL guard, so a subquery inside it is
                    authorised like any other reference. Omitting it deletes every row.
                parameters: Values bound to placeholders in `where`. Never interpolated.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._write_rows(
                "delete-rows", connection, table, schema, where, parameters, values=None
            )

        @server.tool(
            name="create-table",
            description=(
                "Create a table from a column specification. Requires 'create'. The DDL is "
                "generated by d-MCP from the validated specification; raw DDL is not "
                "accepted. Fails if the table already exists — replacing one is a drop "
                "followed by a create."
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
                columns: One entry per column: {'name', 'type', 'nullable', 'default',
                    'is_identity'}. Types are given in the engine's own vocabulary and are
                    validated against the dialect's own type list before any DDL is
                    generated; d-MCP does not invent a portable type language.
                schema: Schema name. Defaults to the connection's default schema.
                primary_key: Column names forming the primary key.
            """
            params = {
                "_connection": connection,
                "table": table,
                "schema": schema,
                "columns": _shape(columns),
                "primary_key": primary_key,
            }
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                ref = self._prospective(context, table, schema, ObjectType.TABLE)
                self._require(context, ref, "create")
                params["_objects"] = [_qualified(ref)]
                self._require_absent(context, ref)
                specs = _column_specs(columns)
                if primary_key is not None and (
                    not isinstance(primary_key, (list, tuple))
                    or not all(isinstance(c, str) and c.strip() for c in primary_key)
                ):
                    raise ValueError("primary_key must be a list of column names")
                script = context.dialect.create_table(
                    ref, specs, primary_key=tuple(primary_key or ())
                )
                params["_sql"] = "\n".join(step.sql for step in script.steps)
                self._run_script(context, script)
                summary = _ddl_summary("create", "table", _qualified(ref))
                self._emit_tool_executed(
                    "create-table", params, summary, None, connection=connection, started=started
                )
                return summary
            except Exception as e:
                self._emit_tool_executed(
                    "create-table", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

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
        def drop_table(connection: str, table: str, schema: str | None = None) -> str:
            """Drop a table.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                table: Table name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._drop_object("drop-table", connection, table, schema, ObjectType.TABLE)

        # -- views: writing and DDL --------------------------------------

        @server.tool(
            name="create-view",
            description=(
                "Create a view. Requires 'create' on the view AND 'select' on every object "
                "its body reads, transitively — otherwise creating a view would be a way "
                "around the permissions on the tables beneath it. The body goes through the "
                "same gate as run-read-query. Fails if the view exists; replacing one is a "
                "drop followed by a create."
            ),
            annotations=ToolAnnotations(title="Create view", destructive_hint=False),
        )
        def create_view(
            connection: str, view: str, sql: str, schema: str | None = None
        ) -> str:
            """Create a view.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                view: Name of the view to create.
                sql: The view body — one read-only SELECT. Do not write CREATE VIEW yourself
                    and do not write OR REPLACE: both are refused. Every object the body
                    reads must be one you hold 'select' on.
                schema: Schema name. Defaults to the connection's default schema.
            """
            params = {"_connection": connection, "view": view, "schema": schema}
            started = perf_counter()
            try:
                context = self._resolve_connection(connection)
                ref = self._prospective(context, view, schema, ObjectType.VIEW)
                self._require(context, ref, "create")
                params["_objects"] = [_qualified(ref)]
                self._require_absent(context, ref)
                if not isinstance(sql, str) or not sql.strip():
                    raise ValueError("sql must be the view's body, written as one SELECT")

                # The body is authorised exactly as run-read-query's statement is: one
                # read-only statement, every object it reaches resolved and checked for
                # 'select', views expanded to their bases. Without this, create-view
                # followed by select-view-rows is a two-step escalation straight around the
                # rule store (DESIGN-MCP-TOOLS.md §5).
                references = context.guard.require_read_only(
                    sql, default_schema=context.default_schema
                )
                targets = self._targets_for(context, references)
                self._require_all(context, targets)
                params["_objects"] = _merge_objects(
                    params["_objects"], [_qualified(target) for target, _ in targets]
                )

                script = context.dialect.create_view(ref, sql)
                params["_sql"] = "\n".join(step.sql for step in script.steps)
                self._run_script(context, script)
                summary = _ddl_summary("create", "view", _qualified(ref))
                self._emit_tool_executed(
                    "create-view", params, summary, None, connection=connection, started=started
                )
                return summary
            except Exception as e:
                self._emit_tool_executed(
                    "create-view", params, None, str(e), connection=connection, exc=e, started=started
                )
                raise

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
        def drop_view(connection: str, view: str, schema: str | None = None) -> str:
            """Drop a view.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                view: View name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._drop_object("drop-view", connection, view, schema, ObjectType.VIEW)

        # -- functions ---------------------------------------------------

        @server.tool(
            name="create-function",
            description=(
                "Create a function from the complete CREATE FUNCTION text. Requires 'create' "
                "on the function. d-MCP does not parse a routine body, so it cannot and does "
                "not authorise what the body will read once it runs — a 'create' grant on a "
                "function is a grant to install code. Fails if it exists, and there is no "
                "replace path at all: a function can be neither replaced nor removed through "
                "d-MCP by any route, edit-function included, so get the body right first "
                "time."
            ),
            annotations=ToolAnnotations(title="Create function", destructive_hint=False),
        )
        def create_function(
            connection: str,
            function: str,
            body: str,
            schema: str | None = None,
            language: str | None = None,
        ) -> str:
            """Create a function.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                function: Name of the function to create; must match the name the body
                    declares.
                body: The complete CREATE FUNCTION statement. OR REPLACE and CREATE OR ALTER
                    are refused: d-MCP never replaces a routine body, and edit-function is
                    always denied.
                schema: Schema name. Defaults to the connection's default schema.
                language: The language the body declares, e.g. 'sql' or 'plpgsql'. Checked
                    against the body rather than applied to it — d-MCP never rewrites a
                    routine body — so a value contradicting the body is refused.
            """
            return self._routine_tool(
                "create-function", connection, function, body, schema, language,
                ObjectType.FUNCTION,
            )

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
        ) -> str:
            """Replace a function's body.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                function: Name of the function to replace.
                body: The complete CREATE FUNCTION statement for the new body. Write plain
                    CREATE; d-MCP adds the engine's own replace clause where there is one.
                schema: Schema name. Defaults to the connection's default schema.
                language: The language the body declares. Checked against the body, not
                    applied to it.
            """
            return self._routine_tool(
                "edit-function", connection, function, body, schema, language,
                ObjectType.FUNCTION,
            )

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
        ) -> str:
            """Drop a function.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                function: Function name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
                signature: Argument types of an overload, e.g. '(integer, text)'. Still
                    declared and still accepted, and on PostgreSQL it is what would have told
                    two functions of one name apart. It changes nothing here: the call is
                    refused before any name is resolved, so no signature makes it succeed.
            """
            return self._routine_tool(
                "drop-function", connection, function, None, schema, None, ObjectType.FUNCTION,
                signature=signature,
            )

        # -- stored procedures -------------------------------------------

        @server.tool(
            name="create-procedure",
            description=(
                "Create a stored procedure from the complete CREATE PROCEDURE text. Requires "
                "'create' on the procedure. d-MCP does not parse a routine body, so it "
                "cannot and does not authorise what the body will do once it runs — a "
                "'create' grant on a procedure is a grant to install code. Fails if it "
                "exists, and there is no replace path at all: a procedure can be neither "
                "replaced nor removed through d-MCP by any route, edit-procedure included, "
                "so get the body right first time."
            ),
            annotations=ToolAnnotations(title="Create procedure", destructive_hint=False),
        )
        def create_procedure(
            connection: str, procedure: str, body: str, schema: str | None = None
        ) -> str:
            """Create a stored procedure.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                procedure: Name of the procedure to create; must match the name the body
                    declares.
                body: The complete CREATE PROCEDURE statement. OR REPLACE and CREATE OR ALTER
                    are refused: d-MCP never replaces a routine body, and edit-procedure is
                    always denied.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._routine_tool(
                "create-procedure", connection, procedure, body, schema, None,
                ObjectType.PROCEDURE,
            )

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
        ) -> str:
            """Replace a stored procedure's body.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                procedure: Name of the procedure to replace.
                body: The complete CREATE PROCEDURE statement for the new body. Write plain
                    CREATE; d-MCP adds the engine's own replace clause where there is one.
                schema: Schema name. Defaults to the connection's default schema.
            """
            return self._routine_tool(
                "edit-procedure", connection, procedure, body, schema, None,
                ObjectType.PROCEDURE,
            )

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
        def drop_procedure(
            connection: str,
            procedure: str,
            schema: str | None = None,
            signature: str | None = None,
        ) -> str:
            """Drop a stored procedure.

            Args:
                connection: Display name of the configured d-MCP connection to act on.
                procedure: Procedure name, optionally schema-qualified.
                schema: Schema name. Defaults to the connection's default schema.
                signature: Argument types of an overload, e.g. '(integer, text)'. Still
                    declared and still accepted, and on PostgreSQL it is what would have told
                    two procedures of one name apart. It changes nothing here: the call is
                    refused before any name is resolved, so no signature makes it succeed.
            """
            return self._routine_tool(
                "drop-procedure", connection, procedure, None, schema, None,
                ObjectType.PROCEDURE, signature=signature,
            )

    # -- shared tool bodies ----------------------------------------------
    #
    # Five tools differ from a sibling only in the object type they address. Their bodies
    # live here rather than being copied into the closures: five copies of the house pattern
    # is five places for the audit call or the authorisation to drift.

    def _principals(self, tool_name: str, connection: str, kind: str) -> list[dict]:
        """The shared body of list-roles, list-users and list-groups.

        The listing itself is ``SecurityManager``'s: it owns the row-shape contract with the
        dialects, the membership queries and the reading of ``kind`` versus ``native_kind``,
        and a second shaping here would be a second answer to "who can reach this data" for
        whoever compared the two. What stays here is what stays here for every tool — resolve
        the connection, authorise ``read_catalogue`` on it, audit the outcome.

        Args:
            tool_name: The MCP tool name, for the audit row.
            connection: The connection display name.
            kind: ``role``, ``user`` or ``group``.

        Raises:
            NotImplementedError: The engine has no such concept. SQLite has no server-side
                principal of any kind, and the refusal says so rather than answering with an
                empty list that would read as "there are none". MySQL below 8.0 has no roles
                either, and an unprobed connection reads False for every version-dependent
                capability — the direction a default-deny system must fail in.
        """
        params = {"_connection": connection}
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            self._require_database(context, "read_catalogue")
            listed = {
                "role": context.security.list_roles,
                "user": context.security.list_users,
                "group": context.security.list_groups,
            }[kind]()
            summary = f"Listed {len(listed)} {kind}(s)"
            self._emit_tool_executed(
                tool_name, params, summary, None, connection=connection, started=started
            )
            return listed
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _security_tool(
        self,
        tool_name: str,
        connection: str,
        action: str,
        params: dict[str, Any],
        run: Callable[[SecurityManager, Callable[[Script], None] | None], str],
        *,
        impact: str | None = None,
    ) -> str:
        """The shared body of the seven security tools.

        Seven copies of the house pattern would be seven places for the permission gate, the
        broker or the audit row to drift, and this is the one group of tools where drift
        changes who may do what rather than what they may see. So the tools differ in three
        things and nothing else: the ``database`` action that authorises them, the arguments
        the audit row records, and the one call they make into
        :class:`~sape_d_mcp.db.security.SecurityManager`.

        The summary is **the manager's own sentence**, returned unaltered. Those sentences
        carry the caveats the model has to report onward — that a created user has no
        credential yet, that open sessions may not see a membership change until they
        reconnect, that ``assign-role`` reverses a revoke only while some principal that may
        grant it still exists — and a summary composed here would be a paraphrase that lost
        them.

        Args:
            tool_name: The MCP tool name, hyphenated as the client sees it.
            connection: The connection display name.
            action: The ``database``-scoped action authorising this tool: ``create_role``,
                ``create_user``, ``create_group``, ``assign_group`` or ``assign_role``.
            params: The tool's own arguments, for the audit row. Principal names, never a
                credential — there is no parameter on this path one could arrive through.
            run: Called with the connection's manager and the approval hook, returning the
                manager's summary sentence. The hook is ``None`` for the five tools that are
                not brokered, and those pass it no further.
            impact: The words a human approving this operation reads, required for a
                brokered tool and meaningless for the rest.

        Returns:
            The manager's summary sentence.

        Raises:
            RuntimeError: ``tool_name`` is brokered and no impact text was supplied. A modal
                showing only SQL would tell an approver what statement runs and not what the
                principal named in it loses, which is the question they are being asked.
        """
        audited: dict[str, Any] = {"_connection": connection, **params}
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            self._require_database(context, action)
            approve: Callable[[Script], None] | None = None
            if self._brokered(tool_name):
                if impact is None:
                    raise RuntimeError(
                        f"{tool_name} is brokered and was registered without impact text; "
                        "d-MCP refuses rather than asking a human to approve a bare statement"
                    )
                approve = self._security_approval(context, tool_name, audited, impact)
            summary = run(context.security, approve)
            self._emit_tool_executed(
                tool_name, audited, summary, None, connection=connection, started=started
            )
            return summary
        except Exception as e:
            self._emit_tool_executed(
                tool_name, audited, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _security_approval(
        self,
        context: ConnectionContext,
        tool_name: str,
        params: dict[str, Any],
        impact: str,
    ) -> Callable[[Script], None]:
        """The hook ``SecurityManager`` calls before running a brokered security script.

        Handed in rather than the script being built here and run there: the object a human
        approved is then the identical object that executes, and the MySQL ``name@host``
        rule — which decides *which* account a revoke addresses — keeps the single reader
        ``db/security.py`` insists on. The manager calls it after its own tripwire has passed
        every step and before the first one runs, so the text shown is text d-MCP has already
        agreed to send, and declining costs nothing.

        No impact *query* is run, unlike the row counts and dependant scans of ``drop-table``.
        What a revoke does is a fact about its arguments, not about the data: naming the
        principal and the role in words is the estimate, and a ``COUNT(*)`` here would answer
        a question nobody asked.

        Args:
            context: The resolved connection, for the display name the modal shows.
            tool_name: The MCP tool name, half of the triple an approval binds to.
            params: The audit row being assembled, which gains the exact statement.
            impact: The sentence naming the principal and the role.

        Returns:
            A callable raising ``ConfirmationRefused`` when no human approves.
        """

        def approve(script: Script) -> None:
            sql = "\n".join(step.sql for step in script.steps)
            params["_sql"] = sql
            warning = self._warning_text(script.warning_key)
            self._confirm(
                context,
                tool_name,
                sql,
                impact if not warning else "\n".join([impact, warning]),
            )

        return approve

    def _list_relations(
        self,
        tool_name: str,
        connection: str,
        schema: str | None,
        name_pattern: str | None,
        object_type: ObjectType,
    ) -> list[dict]:
        """The shared body of list-tables and list-views.

        Filters rather than refuses: an object the caller has no ``list`` grant on is omitted
        and the call succeeds. Refusing the whole call would leak the existence of objects
        through the difference between "empty" and "denied".
        """
        params = {
            "_connection": connection,
            "schema": schema,
            "name_pattern": name_pattern,
            "object_type": str(object_type),
        }
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            wanted = self._listing_schema(context, schema)
            entries = (
                context.introspector.list_tables(wanted)
                if object_type is ObjectType.TABLE
                else context.introspector.list_views(wanted)
            )
            listed = [
                {
                    "schema": entry.ref.canonical_schema,
                    "name": entry.canonical_name,
                    "type": str(object_type),
                    "comment": entry.comment,
                    "materialised": entry.is_materialised,
                }
                for entry in self._visible(context, entries, name_pattern)
            ]
            summary = f"Listed {len(listed)} {object_type}(s)"
            self._emit_tool_executed(
                tool_name, params, summary, None, connection=connection, started=started
            )
            return listed
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _list_routines(
        self,
        tool_name: str,
        connection: str,
        schema: str | None,
        name_pattern: str | None,
        object_type: ObjectType,
    ) -> list[dict]:
        """The shared body of list-functions and list-procedures. Filters like the others."""
        params = {
            "_connection": connection,
            "schema": schema,
            "name_pattern": name_pattern,
            "object_type": str(object_type),
        }
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            wanted = self._listing_schema(context, schema)
            entries = (
                context.introspector.list_functions(wanted)
                if object_type is ObjectType.FUNCTION
                else context.introspector.list_procedures(wanted)
            )
            listed = [
                {
                    "schema": entry.ref.canonical_schema,
                    "name": entry.canonical_name,
                    "type": str(object_type),
                    "signature": entry.signature,
                    "returns": entry.returns,
                    "language": entry.language,
                    "deterministic": entry.is_deterministic,
                }
                for entry in self._visible(context, entries, name_pattern)
            ]
            summary = f"Listed {len(listed)} {object_type}(s)"
            self._emit_tool_executed(
                tool_name, params, summary, None, connection=connection, started=started
            )
            return listed
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _read_routine(
        self,
        tool_name: str,
        connection: str,
        name: str,
        schema: str | None,
        object_type: ObjectType,
    ) -> dict:
        """The shared body of read-function-definition and read-procedure-definition."""
        params = {"_connection": connection, "name": name, "schema": schema}
        started = perf_counter()
        try:
            context = self._resolve_connection(connection)
            ref = self._object(context, name, schema, object_type)
            self._require(context, ref, "read_definition")
            params["_objects"] = [_qualified(ref)]
            definition = context.introspector.definition_of(ref)
            overloads = context.introspector.describe_routine(ref)
            payload = {
                "schema": ref.canonical_schema,
                "name": ref.canonical_name,
                "type": str(object_type),
                "definition": definition.text,
                "definition_available": definition.available,
                "reason": definition.reason,
                "overloads": [
                    {
                        "signature": overload.signature,
                        "returns": overload.returns,
                        "language": overload.language,
                        "deterministic": overload.is_deterministic,
                        "parameters": [
                            {
                                "name": parameter.name,
                                "type": parameter.data_type,
                                "mode": parameter.mode,
                                "position": parameter.position,
                                "has_default": parameter.has_default,
                            }
                            for parameter in overload.parameters
                        ],
                    }
                    for overload in overloads
                ],
            }
            summary = (
                f"Read the definition of {object_type} {_qualified(ref)}"
                if definition.available
                else f"The definition of {object_type} {_qualified(ref)} was not available"
            )
            self._emit_tool_executed(
                tool_name, params, summary, None, connection=connection, started=started
            )
            return payload
        except Exception as e:
            self._emit_tool_executed(
                tool_name, params, None, str(e), connection=connection, exc=e, started=started
            )
            raise

    def _listing_schema(self, context: ConnectionContext, schema: str | None) -> str | None:
        """Which schema a list tool should ask the catalogue for.

        Args:
            context: The resolved connection.
            schema: The caller's argument: a name, ``'*'`` for every schema, or ``None`` for
                the connection's default.

        Returns:
            The schema name, or ``None`` meaning every visible schema.
        """
        if schema is None or not str(schema).strip():
            return context.default_schema
        wanted = str(schema).strip()
        return None if wanted == "*" else wanted

    def _visible(
        self,
        context: ConnectionContext,
        entries: Iterable[Any],
        name_pattern: str | None,
    ) -> list[Any]:
        """Keep the entries the caller may ``list``, in catalogue order.

        An entry the catalogue cannot key — a name whose case mapping the dialect refuses —
        is dropped rather than shown: a match key that cannot be computed cannot be compared
        against a rule, so no rule can authorise it.
        """
        pattern = None if name_pattern is None or not str(name_pattern).strip() else str(name_pattern).strip().lower()
        kept = []
        for entry in entries:
            ref = entry.ref
            if ref is None:
                continue
            if pattern is not None and not fnmatch.fnmatch(entry.canonical_name.lower(), pattern):
                continue
            try:
                if not self.permissions.is_allowed(context.connection_id, ref, "list"):
                    continue
            except ValueError:  # an identifier no rule could ever key on
                continue
            kept.append(entry)
        return kept

    # -- entry point -----------------------------------------------------

    def run(self, transport: str = "stdio", **kwargs: Any) -> None:
        """Run the server.

        Args:
            transport: ``stdio``, ``sse`` or ``streamable-http``. A passthrough: the GUI's
                server thread rewrites ``stdio`` to ``streamable-http`` before calling this,
                because stdio would block on stdin inside a ``QThread`` — that rewrite
                belongs to the thread, not here.
            **kwargs: Forwarded to the SDK unchanged (host, port, mount path).
        """
        self.server.run(transport=transport, **kwargs)


# --------------------------------------------------------------------------------------
# Module-level helpers
# --------------------------------------------------------------------------------------


def _decision_for(exc: BaseException | None, error: str | None) -> tuple[str, int | None]:
    """The audit ``decision`` and matched rule for one outcome.

    A ``GuardRefusal`` is ``refused``, not ``denied``: nothing was checked against the rule
    table, so calling it a denial would put a permission decision in the log that no rule
    made, and would send the operator looking for a rule that does not exist.

    A ``ConfirmationRefused`` is ``refused`` for the mirror-image reason, and the ordering of
    the two branches below is load-bearing: it is a subclass of ``PermissionError``, so
    without its own case ahead of that branch every declined modal, every timeout and every
    "no window attached" would be logged as ``denied`` — the outcome that means *the rules*
    said no. That is precisely the distinction the audit design exists to make. ``refused``
    means a human said no (or was not there to say yes); ``denied`` means a rule did. The
    ``decision`` domain stays closed at the four values ``audit.db`` accepts
    (DESIGN-DATA-MODEL.md §5.2); the three-way ``no_subscriber``/``timeout``/``operator``
    distinction DESIGN-MCP-TOOLS.md §8.2 wants lives in the message, which the exception
    already carries, and on ``ConfirmationRefused.reason``.
    """
    if exc is None:
        return ("error", None) if error else ("allowed", None)
    if isinstance(exc, GuardRefusal):
        return "refused", None
    if isinstance(exc, ConfirmationRefused):
        return "refused", None
    if isinstance(exc, PermissionError):
        return "denied", getattr(exc, "matched_rule_id", None)
    if isinstance(exc, LookupError):
        # An identifier the catalogue does not hold. d-MCP declined to hand it to the
        # server, which is a refusal rather than a fault: nothing went wrong, and nothing
        # was checked against the rule table either.
        return "refused", None
    return "error", None


def _column_specs(columns: Any) -> list[ColumnSpec]:
    """Validate ``create-table``'s column list and turn it into ``ColumnSpec``s.

    ``create-table`` takes a structured specification and not a DDL string on purpose
    (DESIGN-MCP-TOOLS.md §11.3): a ``ddl: str`` parameter would be an arbitrary-DDL hole with
    a ``create`` label on it. The cost of that trade is paid here — every entry is checked,
    every key is one the dialect understands, and the type text is handed to the dialect,
    which validates it against the engine's own type list before any DDL is emitted.

    Unknown keys are refused rather than ignored. A caller who wrote ``"nullible"`` and got a
    ``NOT NULL`` column would discover it from the first failed INSERT, days later.

    Args:
        columns: The tool argument, expected to be a non-empty list of mappings.

    Returns:
        One ``ColumnSpec`` per entry, in order.

    Raises:
        ValueError: Anything about the shape that is not exactly right.
    """
    if not isinstance(columns, (list, tuple)) or not columns:
        raise ValueError(
            "columns must be a non-empty list of column specifications, each an object with "
            "at least 'name' and 'type'"
        )
    specs: list[ColumnSpec] = []
    for position, entry in enumerate(columns, start=1):
        if not isinstance(entry, dict):
            raise ValueError(
                f"column {position} is a {type(entry).__name__}; every entry must be an "
                "object like {'name': 'id', 'type': 'INTEGER', 'nullable': false}"
            )
        unknown = sorted(set(entry) - _COLUMN_SPEC_KEYS)
        if unknown:
            raise ValueError(
                f"column {position} carries unknown key(s) {', '.join(unknown)}; a column "
                f"specification takes only: {', '.join(sorted(_COLUMN_SPEC_KEYS))}"
            )
        name = entry.get("name")
        data_type = entry.get("type")
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"column {position} has no usable 'name'")
        if not isinstance(data_type, str) or not data_type.strip():
            raise ValueError(
                f"column {name!r} has no usable 'type'; give it in the engine's own "
                "vocabulary, e.g. 'NVARCHAR(80)' or 'integer'"
            )
        nullable = entry.get("nullable", True)
        if not isinstance(nullable, bool):
            raise ValueError(f"column {name!r} has a non-boolean 'nullable'")
        identity = entry.get("is_identity", False)
        if not isinstance(identity, bool):
            raise ValueError(f"column {name!r} has a non-boolean 'is_identity'")
        default = entry.get("default")
        if default is not None and not isinstance(default, str):
            raise ValueError(
                f"column {name!r} has a non-string 'default'; it is emitted into the DDL as "
                "written, so give it as the SQL literal or expression the engine expects"
            )
        specs.append(
            ColumnSpec(
                name=name.strip(),
                data_type=data_type.strip(),
                nullable=nullable,
                default=default,
                is_identity=identity,
            )
        )
    return specs


def _check_routine_language(body: str, language: str | None) -> None:
    """Refuse a ``language`` argument that contradicts what the routine body declares.

    d-MCP never rewrites a routine body — the dialect layer is explicit that the body is not
    parsed for meaning — so ``language`` cannot be *applied*; it can only be checked. §11.5
    declares the parameter, and the two honest things to do with it are to check it or to
    refuse it. Checking is more useful: a caller who passes ``language='plpgsql'`` alongside a
    body that says ``LANGUAGE sql`` has made a mistake worth hearing about.

    A body that declares no language at all — every T-SQL routine, since SQL Server has no
    such clause — is accepted with the argument recorded in the audit row and nothing else
    done with it, rather than refused for lacking a clause its engine does not have.

    Args:
        body: The routine body as supplied.
        language: The declared language, or ``None``.

    Raises:
        ValueError: The body declares a different language.
    """
    if not language or not isinstance(language, str) or not language.strip():
        return
    match = _ROUTINE_LANGUAGE.search(body or "")
    if match is None:
        return
    declared = next(group for group in match.groups() if group)
    if declared.strip().lower() != language.strip().lower():
        raise ValueError(
            f"the language argument says {language!r} but the body declares "
            f"{declared!r}. d-MCP does not rewrite a routine body, so it will not run one "
            "that contradicts its own arguments; correct whichever is wrong."
        )


def _ddl_summary(action: str, what: str, qualified: str) -> str:
    """The one-sentence result a DDL tool returns and the audit row records (§6.2)."""
    verbs = {"create": "Created", "drop": "Dropped", "edit": "Replaced the body of"}
    return f"{verbs[action]} {what} {qualified}"


def _rows_phrase(verb: str, affected: int, qualified: str, preposition: str) -> str:
    """``"Deleted 12 row(s) from dbo.Audit"``, or an honest sentence when nobody counted.

    Not every driver fills ``rowcount`` — pyodbc returns ``-1`` for some statements — and a
    ``-1`` rendered straight into the sentence would read as a count. It is not one.
    """
    if affected < 0:
        return f"{verb} rows in {qualified} (the driver reported no count)"
    return f"{verb} {affected} row(s) {preposition} {qualified}"


def _scrub(text: str, secret: str | None = None) -> str:
    """Cut anything credential-shaped out of a driver message.

    A pyodbc failure can echo the whole DSN including ``PWD=``; a credential must never
    reach a transcript, an error string or ``audit.db``.
    """
    cleaned = _SECRET_FRAGMENT.sub(lambda m: f"{m.group(1)}=***", text or "")
    if secret:
        cleaned = cleaned.replace(secret, "***")
    return cleaned


def _merge_objects(*groups: Iterable[str]) -> list[str]:
    """The order-preserving union of several object lists, for the audit row's ``_objects``.

    A read authorises the object it was handed and then, where a ``where`` fragment is
    present, everything the composed statement reaches; the two overlap on the object itself
    and, for a view, on its bases. The log must show each object once, in the order it was
    authorised, so an operator reads the statement's reach from the top down.
    """
    merged: list[str] = []
    for group in groups:
        for name in group:
            if name not in merged:
                merged.append(name)
    return merged


def _qualified(ref: NormalisedRef) -> str:
    """``schema.name`` in the catalogue's own spelling, or just the name where there is none."""
    if ref.canonical_schema is None:
        return ref.canonical_name
    return f"{ref.canonical_schema}.{ref.canonical_name}"


def _addressed(ref: NormalisedRef, signature: str | None = None) -> str:
    """:func:`_qualified`, plus the overload's argument list where one was resolved.

    ``None`` and ``""`` are different answers and the difference is load-bearing: ``None`` is
    "this name carries one object", rendering ``public.add``, while ``""`` is PostgreSQL's
    ``add()`` — a real overload taking no arguments — and rendering it as the bare name would
    show an approver the ambiguous spelling of the statement that is about to run.
    """
    if signature is None:
        return _qualified(ref)
    return f"{_qualified(ref)}({signature})"


def _profile_default_schema(profile: dict[str, Any]) -> str | None:
    """The default schema a profile implies, without opening a connection.

    ``list-connections`` must stay cheap enough to be the model's first call, so this reads
    the dialect's compile-time default rather than the probed one.
    """
    try:
        dialect = db_engine.resolve_dialect(profile)
    except Exception:
        return None
    try:
        return dialect.effective_default_schema() or dialect.addressable_schema
    except Exception:  # pragma: no cover - a dialect that needs a probe to answer
        return None


def _check_paging(limit: int, offset: int) -> None:
    """Validate the row cap and the offset, rather than clamping them.

    Silent clamping would let the model believe it had a complete result set.
    """
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= MAX_ROW_LIMIT:
        raise ValueError(f"limit must be between 1 and {MAX_ROW_LIMIT}, got {limit!r}")
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise ValueError(f"offset must be zero or more, got {offset!r}")


def _shape(value: Any) -> Any:
    """The loggable shape of an argument that may carry data.

    Counts, key names and value types — never a value. This is what keeps ``audit.db`` from
    becoming a second copy of the personal data it exists to police.
    """
    if value is None:
        return None
    if isinstance(value, dict):
        return {"count": len(value), "keys": sorted(str(k) for k in value)}
    if isinstance(value, (list, tuple)):
        keys: set[str] = set()
        for item in value:
            if isinstance(item, dict):
                keys.update(str(k) for k in item)
        return {"count": len(value), "keys": sorted(keys)} if keys else {"count": len(value)}
    return {"type": type(value).__name__}


def _close_quietly(cursor: Any) -> None:
    """Close a cursor without letting a driver's close error mask the real outcome."""
    try:
        cursor.close()
    except Exception:  # pragma: no cover - driver dependent
        logger.debug("Error closing a cursor", exc_info=True)


def _cell(value: Any) -> tuple[Any, bool]:
    """One value, serialised the same way whichever engine produced it.

    Dates and timestamps as ISO 8601, ``Decimal`` as a **string** so money never silently
    loses precision on its way through JSON, ``bytes`` as base64, a UUID as its canonical
    string. Returns the value and whether it had to be cut at ``MAX_CELL_CHARS``.
    """
    if value is None or isinstance(value, (bool, int, float)):
        return value, False
    if isinstance(value, decimal.Decimal):
        return str(value), False
    if isinstance(value, (bytes, bytearray, memoryview)):
        return base64.b64encode(bytes(value)).decode("ascii"), False
    if isinstance(value, (_datetime.datetime, _datetime.date, _datetime.time)):
        return value.isoformat(), False
    if isinstance(value, _datetime.timedelta):
        return str(value), False
    if isinstance(value, uuid.UUID):
        return str(value), False
    text = value if isinstance(value, str) else str(value)
    if len(text) > MAX_CELL_CHARS:
        return text[:MAX_CELL_CHARS] + "…", True
    return text, False


def _envelope(
    columns: Sequence[tuple[str, str | None]],
    rows: Sequence[Sequence[Any]],
    *,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Package a result set, making truncation machine-visible.

    ``rows`` may hold up to ``limit + 1`` entries; the extra one is the proof of truncation
    and is discarded rather than returned. ``next_offset`` is filled in only when there is a
    next page, so the model can page without arithmetic.
    """
    names = [name for name, _ in columns]
    kept = list(rows[: limit])
    truncated = len(rows) > limit

    cells_truncated = False
    shaped: list[dict[str, Any]] = []
    for row in kept:
        record: dict[str, Any] = {}
        for index, name in enumerate(names):
            value, cut = _cell(row[index] if index < len(row) else None)
            cells_truncated = cells_truncated or cut
            record[name] = value
        shaped.append(record)

    return {
        "columns": [{"name": name, "type": data_type} for name, data_type in columns],
        "rows": shaped,
        "row_count": len(shaped),
        "truncated": truncated,
        "next_offset": offset + len(shaped) if truncated else None,
        "row_cap": limit,
        "cells_truncated": cells_truncated,
    }


def _describe(described: Any, ref: NormalisedRef) -> dict[str, Any]:
    """Turn a ``TableDescription`` into the JSON shape ``describe-table`` returns."""
    return {
        "schema": ref.canonical_schema,
        "name": ref.canonical_name,
        "columns": [
            {
                "name": column.name,
                "type": column.data_type,
                "nullable": column.nullable,
                "default": column.default,
                "is_identity": column.is_identity,
                "is_generated": column.is_generated,
                "position": column.position,
                "comment": column.comment,
            }
            for column in described.columns
        ],
        "primary_key": (
            None
            if described.primary_key is None
            else {
                "name": described.primary_key.name,
                "columns": list(described.primary_key.columns),
            }
        ),
        "unique_keys": [
            {"name": key.name, "columns": list(key.columns)} for key in described.unique_keys
        ],
        "foreign_keys": [
            {
                "name": key.name,
                "columns": list(key.columns),
                "referenced_schema": key.referenced_schema,
                "referenced_table": key.referenced_table,
                "referenced_columns": list(key.referenced_columns),
                "on_delete": key.on_delete,
                "on_update": key.on_update,
            }
            for key in described.foreign_keys
        ],
    }


def _bind_placeholders(
    dialect: Dialect, sql: str, parameters: dict[str, Any] | None
) -> tuple[str, Any]:
    """Rewrite ``:name`` placeholders into the driver's own paramstyle and bind the values.

    A thin wrapper over ``rewrite_placeholders()``, which lives in the dialect layer because
    ``Dialect.select()`` needs the very same rewrite for the free-form ``where`` fragment of
    ``select-rows``. Two implementations of "what is a placeholder" would eventually disagree,
    and that disagreement is the one parsing difference that becomes an injection. All this
    adds is packaging the values in the shape the driver expects — a tuple for a positional
    style, a mapping for a named one.

    Args:
        dialect: The connection's dialect, which owns the paramstyle.
        sql: The statement as the model wrote it.
        parameters: The values, keyed by placeholder name.

    Returns:
        The rewritten statement and the parameter object the driver expects.

    Raises:
        ValueError: A placeholder that is not ``:name``, a name with no value, or a value
            with no placeholder.
    """
    text, values, names = rewrite_placeholders(dialect, sql, parameters)
    mapping_style = dialect.param_style.is_mapping_style
    return text, dialect.parameters(values, names if mapping_style else None)
