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

"""The destructive-operation confirmation broker: a human must approve before it runs.

A brokered tool (``drop-table``, ``delete-rows``, an unqualified ``update-rows``, …,
DESIGN-MCP-TOOLS.md §8.1) has already passed the permission check by the time it reaches
here — this module is the *second* gate, not a replacement for the first. Its only job is
to make one statement wait for one human decision, and to make silence, absence and
disconnection all mean the same thing: no.

**Fail-closed is the whole point.** A ``--cli`` server spawned by an MCP client routinely
runs with no GUI attached at all; that is not a misconfiguration, it is the common case,
and it must not become "nothing is watching, so anything goes". Three invariants follow
directly and are pinned by ``tests/test_confirmation.py``:

1. No subscriber attached ⇒ refused immediately, with no timeout wait at all.
2. Timeout ⇒ refused. Silence is refusal, never assent.
3. An approval is single-use, bound to the exact ``(connection, tool_name, sql)`` triple
   it was granted for, and is consumed by the call that requested it. Changing so much as
   whitespace in the statement text is a different triple and gets no approval at all.

**Reconciling the two design documents.** DESIGN-MCP-TOOLS.md §8.2 and
DESIGN-DATA-MODEL.md §5.2/§9 disagree in three places; this module follows the data
model, per the brief that resolved the disagreement, and the reasoning is recorded here
rather than left for a maintainer to rediscover from the diff:

* §8.2 asks for three audit ``decision`` values (``denied_no_subscriber``,
  ``denied_timeout``, ``denied_operator``). ``audit.db`` implements the closed four-value
  domain from DESIGN-DATA-MODEL.md §5.2 (``allowed`` · ``denied`` · ``refused`` ·
  ``error``), where ``refused`` means precisely "permitted by rule, but the confirmation
  was declined, or no subscriber was attached". That domain is not widened here: every
  denial this module raises is a :class:`ConfirmationRefused`, a single exception type
  that maps to the single ``'refused'`` decision. The three-way distinction §8.2 wants is
  not lost, it just does not live in the ``decision`` column — it lives in the exception's
  ``reason`` attribute (``"no_subscriber"`` / ``"timeout"`` / ``"operator"``) and in the
  human-readable message, both of which the caller is free to fold into the audit row's
  ``error`` text. Whoever finishes wiring this into ``mcp_server.py`` should special-case
  ``ConfirmationRefused`` in ``_decision_for()`` ahead of the generic ``PermissionError``
  branch — exactly the way that function already special-cases ``GuardRefusal`` — because
  today that branch would otherwise map every ``PermissionError``, this one included, to
  ``'denied'``, which is the rule-refusal outcome, not this one.
* §8.2's ``CONFIRMATION_TIMEOUT_S`` is 120 s; ``confirmations.timeout_seconds`` in
  ``config.json`` defaults to 60. The operator's config key is the authority — it is the
  lever a human can actually pull without a code change — so :data:`DEFAULT_TIMEOUT_S`
  here is 60, not 120, and is used only when a caller does not pass an explicit
  ``timeout``. A caller that reads the config should always pass it explicitly; the
  default exists for callers (and tests) that have no config to read.
* ``confirmations.remember_for_session`` exists as a config key, but §8.2 is explicit that
  there is "no blanket approval, no 'approve all', no remembered decision". This module
  implements single-use approval **only** and has no code path that could honour
  ``remember_for_session`` — there is no cache of past decisions anywhere in it, not even
  one that is currently unused. Wiring that key up later means adding a new store and a
  new branch here, not flipping a flag, which is deliberate: the user has not yet been
  asked to resolve the contradiction between the config schema and the design brief, and
  this module must not pre-empt that conversation by implementing half of it.

**Threading.** A tool body is a plain synchronous function that the MCP SDK runs on one of
anyio's own worker threads, so :meth:`ConfirmationBroker.request` is itself a plain
synchronous, blocking call — matching the DESIGN-MCP-TOOLS.md §8.2 call shape exactly,
with no ``await`` at the call site. Internally it hops onto the server's event loop with
``anyio.from_thread.run`` and waits there on an :class:`anyio.Event`, so the wait costs one
blocked worker thread, never the event loop itself: every other tool call, and the 100 ms
shutdown watchdog in ``gui/server_thread.py``, keep running while a modal is up. Because
that hop schedules the wait as an ordinary task inside whatever cancel scope the caller's
own task is already running under, cancelling that scope — which is exactly what pressing
Stop does — cancels the wait too, promptly and without any special-casing here: this
module never shields the wait or swallows the cancellation, so a Stop mid-modal unwinds
the same way any other in-flight call does, rather than blocking the shutdown grace for up
to ``timeout`` seconds.

The other direction of the same problem — the human's Approve/Refuse click, which happens
on a thread anyio does not own at all (the GUI's, typically Qt's) — cannot safely call
``anyio.Event.set()`` directly: an asyncio ``Event`` is not thread-safe, and setting one
from the wrong thread can simply fail to wake the waiter. :meth:`ConfirmationBroker.approve`
and :meth:`ConfirmationBroker.refuse` therefore route through an
``anyio.from_thread.BlockingPortal`` when one has been registered with
:meth:`ConfirmationBroker.set_portal` — the same portal ``DatabaseMCPServer.set_portal``
already exists to receive (see ``mcp_server.py``'s ``_schedule_tools_changed``), reused
here rather than duplicated. With no portal bound, both methods act directly, which is
correct exactly when the caller already is the loop thread — as every test in this
package's test file is, and as a hypothetical GUI-less embedding of this broker would be.

This module imports nothing from ``sape_d_mcp.gui`` and nothing from ``PyQt6``: the broker
does not know the GUI exists, only that *something* may or may not be subscribed to it.
``main.py --cli`` constructs a server with no confirmation broker at all, which is the
simplest way to get invariant 1 for free.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

import anyio
import anyio.from_thread

logger = logging.getLogger(__name__)

#: Fallback wait, in seconds, used only when a caller does not pass ``timeout`` explicitly.
#: Mirrors ``config.json``'s ``confirmations.timeout_seconds`` default (DESIGN-DATA-MODEL.md
#: §9.1) rather than DESIGN-MCP-TOOLS.md §8's 120 s constant — see the module docstring.
DEFAULT_TIMEOUT_S: Final[float] = 60.0

#: The three reasons a request can be refused. Not part of the ``audit.db`` decision
#: domain (that stays the closed ``allowed``/``denied``/``refused``/``error`` set) — this
#: is carried on the exception for whoever composes the audit row's free-text message.
_REASONS: Final[frozenset[str]] = frozenset({"no_subscriber", "timeout", "operator"})

#: A confirmation identity: the exact triple an approval is bound to. A tuple rather than
#: a dataclass because it is used only as a dict key, never displayed.
_Key = tuple[str, str, str]


@dataclass(frozen=True, slots=True)
class ConfirmationRequest:
    """One statement waiting for a human decision. Handed to the subscriber, and only to it.

    ``impact`` arrives pre-computed — estimating it is read-only work against the live
    database (DESIGN-MCP-TOOLS.md §8.2's "impact estimation") and belongs to whoever holds
    the database session, not to this broker, which knows nothing about SQL beyond the
    text it is showing a human.
    """

    connection: str
    tool_name: str
    sql: str
    impact: str


class ConfirmationRefused(PermissionError):
    """Raised by :meth:`ConfirmationBroker.request` for every outcome except approval.

    A subclass of ``PermissionError`` rather than a new hierarchy, so a caller that only
    catches ``PermissionError`` — the vocabulary DESIGN-MCP-TOOLS.md §4.1 already uses for
    "confirmation refused, timed out, or no subscriber" — still catches it without change.
    It is nonetheless a *distinct* class precisely so that code translating an exception
    into an ``audit.db`` decision (``mcp_server.py``'s ``_decision_for``) can tell it apart
    from :class:`sape_d_mcp.permissions.PermissionDenied`, which must keep mapping to
    ``'denied'``. See the module docstring's first reconciliation note.
    """

    def __init__(self, message: str, *, reason: str) -> None:
        if reason not in _REASONS:
            # A typo here would silently mislabel every refusal this module ever raises —
            # worth a hard failure at the call site that got it wrong, not a bad log line
            # discovered months later.
            raise ValueError(f"unknown confirmation refusal reason: {reason!r}")
        super().__init__(message)
        self.reason = reason


@dataclass(slots=True)
class _Pending:
    """One in-flight wait. Mutable, unlike :class:`ConfirmationRequest`: ``outcome`` is
    written by :meth:`ConfirmationBroker.approve`/``refuse`` after this is created."""

    event: anyio.Event = field(default_factory=anyio.Event)
    outcome: ConfirmationRefused | None = None


class ConfirmationBroker:
    """Brokers human approval for one destructive statement at a time.

    Holds no reference to a database, a connection or a permission store — it is handed
    an already-composed statement and an already-computed impact string, and it hands back
    either nothing (approved) or a :class:`ConfirmationRefused` (everything else). Nothing
    here is persisted: a restart, or simply a GUI window closing, means every prior
    decision is gone, which is exactly what "no remembered decision" requires.
    """

    def __init__(self) -> None:
        self._subscriber: Callable[[ConfirmationRequest], None] | None = None
        self._portal: anyio.from_thread.BlockingPortal | None = None
        self._pending: dict[_Key, list[_Pending]] = {}
        # Guards `_subscriber`, `_portal` and the `_pending` dict's structure (not the
        # anyio primitives inside a `_Pending`, which are only ever touched from the loop
        # thread — see the module docstring's threading section).
        self._lock = threading.Lock()

    # -- wiring, called by the GUI ---------------------------------------------------

    def subscribe(self, callback: Callable[[ConfirmationRequest], None]) -> None:
        """Attach the one subscriber a running broker can have.

        There is exactly one modal at a time in this design — d-MCP has one main window,
        not one per session — so a second ``subscribe()`` replaces the first rather than
        queuing, and is logged, because it usually means a caller forgot to
        :meth:`unsubscribe` first.
        """
        with self._lock:
            if self._subscriber is not None:
                logger.warning("A confirmation subscriber replaced another without unsubscribing first")
            self._subscriber = callback

    def unsubscribe(self) -> None:
        """Detach the subscriber and refuse every call currently waiting on one.

        Without the second half, closing the d-MCP window while a modal is open would
        leave the waiting tool call to sit out its full timeout rather than fail the
        instant nobody could possibly answer it — technically still fail-closed, but a
        needless wait for an outcome that is already certain.
        """
        with self._lock:
            self._subscriber = None
            keys = list(self._pending)
        for connection, tool_name, sql in keys:
            message = (
                f"'{tool_name}' needed approval in the d-MCP window, and the window was "
                "closed while it was waiting"
            )
            self._resolve(connection, tool_name, sql, ConfirmationRefused(message, reason="no_subscriber"))

    def set_portal(self, portal: anyio.from_thread.BlockingPortal | None) -> None:
        """Give the broker the portal onto the server's event loop, or ``None`` to clear it.

        Args:
            portal: An ``anyio.from_thread.BlockingPortal`` opened by the server thread —
                the same one ``DatabaseMCPServer.set_portal`` receives, and it is expected
                to be handed to both. ``None`` when the server stops, so a stale click
                arriving after shutdown cannot reach into a loop that no longer exists;
                it is then resolved directly instead (see :meth:`approve`).
        """
        with self._lock:
            self._portal = portal

    # -- the tool-body side ------------------------------------------------------------

    def request(
        self,
        connection: str,
        tool_name: str,
        sql: str,
        impact: str,
        timeout: float = DEFAULT_TIMEOUT_S,
    ) -> None:
        """Block the calling (worker) thread until a human approves, or raise.

        Returns ``None`` on approval; raises :class:`ConfirmationRefused` — a
        ``PermissionError`` — for everything else. See the module docstring for why the
        "no subscriber" case never touches anyio at all: it is checked and raised before
        this method does anything that could wait.
        """
        with self._lock:
            subscriber = self._subscriber
        if subscriber is None:
            raise ConfirmationRefused(
                f"'{tool_name}' needs approval in the d-MCP window, and no d-MCP window is attached",
                reason="no_subscriber",
            )
        outcome = anyio.from_thread.run(
            self._await_decision, connection, tool_name, sql, impact, float(timeout)
        )
        if outcome is not None:
            raise outcome

    async def _await_decision(
        self, connection: str, tool_name: str, sql: str, impact: str, timeout: float
    ) -> ConfirmationRefused | None:
        """Runs on the event loop: register the wait, notify, and block on it.

        The registration happens under the lock and *before* the subscriber is told
        anything, so a decision that somehow arrives the instant it is announced (a test
        double answering synchronously, say) always finds something to resolve.
        """
        key: _Key = (connection, tool_name, sql)
        pending = _Pending()
        with self._lock:
            self._pending.setdefault(key, []).append(pending)
        try:
            self._notify(ConfirmationRequest(connection, tool_name, sql, impact))
            with anyio.move_on_after(timeout) as scope:
                await pending.event.wait()
            if scope.cancelled_caught:
                return ConfirmationRefused(
                    f"'{tool_name}' was not approved within {timeout:g}s and was refused",
                    reason="timeout",
                )
            return pending.outcome
        finally:
            # Reached on approval, refusal, timeout, and — because this is a plain
            # `finally`, not an `except` — on the surrounding cancel scope being
            # cancelled too, which is precisely the "Stop while a modal is open" case:
            # the exception keeps propagating, and the pending entry does not leak.
            with self._lock:
                waiters = self._pending.get(key)
                if waiters is not None and pending in waiters:
                    waiters.remove(pending)
                    if not waiters:
                        del self._pending[key]

    def _notify(self, request: ConfirmationRequest) -> None:
        """Tell the subscriber a decision is wanted. Never lets the subscriber break this.

        A subscriber is arbitrary GUI code; if it raises — a bug in a signal handler, say —
        the wait must still behave exactly as if nobody had been told, i.e. it runs out the
        clock and times out. A logging fault must never turn into a confirmation appearing
        to hang instead of failing loudly in the log.
        """
        with self._lock:
            subscriber = self._subscriber
        if subscriber is None:
            return
        try:
            subscriber(request)
        except Exception:
            logger.exception("Confirmation subscriber raised while being notified of %r", request)

    # -- the human side ------------------------------------------------------------

    def approve(self, connection: str, tool_name: str, sql: str) -> None:
        """Approve the pending request matching this exact triple, if there is one.

        A mismatch — the sql has changed, the request already timed out, a duplicate
        click — finds nothing to resolve and is logged rather than raised: the human is
        clicking a button in a window that cannot know, at the instant of the click,
        whether the call it is answering is still waiting.
        """
        self._answer(connection, tool_name, sql, refusal=None)

    def refuse(self, connection: str, tool_name: str, sql: str, *, reason: str | None = None) -> None:
        """Refuse the pending request matching this exact triple, if there is one.

        Args:
            reason: Optional operator-supplied text (why the modal was declined),
                folded into the exception message. Never required — a bare "no" is a
                complete answer.
        """
        message = f"'{tool_name}' was declined by the operator in the d-MCP window"
        if reason:
            message = f"{message}: {reason}"
        self._answer(connection, tool_name, sql, refusal=ConfirmationRefused(message, reason="operator"))

    def _answer(self, connection: str, tool_name: str, sql: str, *, refusal: ConfirmationRefused | None) -> None:
        with self._lock:
            portal = self._portal
        if portal is not None:
            portal.call(self._resolve, connection, tool_name, sql, refusal)
        else:
            # No portal bound: correct when the caller already is the loop thread (every
            # test in this package, and any embedding with no cross-thread GUI at all).
            # A real GUI always binds one via `set_portal` before a human can click
            # anything, because the click handler runs on the GUI's own thread.
            self._resolve(connection, tool_name, sql, refusal)

    def _resolve(self, connection: str, tool_name: str, sql: str, refusal: ConfirmationRefused | None) -> None:
        """Runs on the event loop: hand the decision to every waiter on this exact triple.

        A list, not a single slot, because nothing stops two identical brokered calls
        being in flight at once (a retried ``delete-rows`` after a transient driver
        blip, say). They are indistinguishable to a human looking at one modal, so one
        decision answers all of them — each still only consumes its own ``_Pending``,
        so this is one decision fanned out, not one approval reused.
        """
        key: _Key = (connection, tool_name, sql)
        with self._lock:
            waiters = self._pending.pop(key, [])
        if not waiters:
            logger.warning(
                "No confirmation is pending for %s / %s (stale click, or it already resolved)",
                tool_name,
                connection,
            )
            return
        for pending in waiters:
            pending.outcome = refusal
            pending.event.set()
