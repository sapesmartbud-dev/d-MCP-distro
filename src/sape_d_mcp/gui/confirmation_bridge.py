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

"""Marshals a :class:`~sape_d_mcp.confirmation.ConfirmationBroker` notification from
whatever thread the broker calls a subscriber on, onto the Qt GUI thread, and shows a
:class:`~sape_d_mcp.gui.dialogs.confirmation_dialog.ConfirmationDialog` there.

**Why this class exists at all.** ``ConfirmationBroker._notify`` — see
``confirmation.py``'s module docstring, "Threading" — calls the subscriber it was given
on the anyio event loop thread, i.e. the MCP server's own worker thread when running
in-process inside ``gui/server_thread.py``, never Qt's thread. Constructing, or even
touching, a ``QWidget`` from that thread is undefined behaviour: it may appear to work in
a quick manual test and then crash or hang under real load, which is exactly the kind of
bug that is expensive to find later and cheap to design out now. The fix is the
oldest one in Qt: a signal emitted on one thread and connected with a queued connection
is delivered as an event on the *receiving* object's thread, which is this bridge's own
thread — the one it was constructed on, always the GUI thread in this application.

**What runs where, concretely:**

- :meth:`ConfirmationBridge.subscribe_to` is called once, from the GUI thread, when the
  window that owns a running server comes up.
- :meth:`_on_confirmation_requested` is the broker's subscriber callback. It runs on the
  loop thread, must not block — ``ConfirmationBroker._notify`` catches and logs anything
  it raises, but it does *not* protect the caller from a slow subscriber, since it calls
  the subscriber synchronously and inline — and does nothing except emit
  :attr:`confirmation_requested`, a Qt signal, which is thread-safe to emit from anywhere.
- :meth:`_show_dialog` is the slot on the other end of that signal, connected with
  ``Qt.ConnectionType.QueuedConnection`` explicitly (not left to Qt's default
  auto-detection) so the cross-thread hop is a documented, deliberate design decision
  here rather than an accident of which thread happened to construct which object. It
  runs on the GUI thread, and only there does it construct and ``exec()`` a
  :class:`ConfirmationDialog`.
- The dialog's Approve/Refuse buttons call
  :meth:`~sape_d_mcp.confirmation.ConfirmationBroker.approve`/``refuse`` directly, on the
  GUI thread — the *other* direction of the cross-thread problem, which
  ``ConfirmationBroker`` itself solves by routing through the
  ``anyio.from_thread.BlockingPortal`` given to :meth:`ConfirmationBroker.set_portal`.
  Nothing in this module touches that portal; it is the server thread's to set (see this
  module's own limitations, noted in the stage report, for what remains unwired there).

This module imports ``PyQt6`` and must never be imported from ``main.py --cli``'s code
path; :mod:`sape_d_mcp.confirmation` itself imports nothing from here, keeping the
broker importable from a headless server with no GUI installed at all.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QObject, Qt, pyqtSignal

from sape_d_mcp.confirmation import ConfirmationBroker, ConfirmationRequest
from sape_d_mcp.gui.dialogs.confirmation_dialog import ConfirmationDialog

logger = logging.getLogger(__name__)


class ConfirmationBridge(QObject):
    """Owns the GUI's side of one :class:`ConfirmationBroker` subscription.

    One instance lives for the life of the main window (constructed alongside it,
    destroyed with it), independently of whether an MCP server is actually running —
    subscribing costs nothing when no request ever arrives, and a broker with a
    subscriber attached before the server starts is simpler to reason about than one
    that races the server thread's own start-up.
    """

    # Carries the request across the thread boundary. Qt, not this class, decides
    # whether the connection to `_show_dialog` is queued — see `subscribe_to`, which
    # asks for a queued connection explicitly rather than trusting AutoConnection to
    # infer it from thread affinity.
    confirmation_requested = pyqtSignal(object)

    def __init__(self, app, main_window) -> None:
        # Parented to `main_window` itself, not left parentless: this bridge must not
        # outlive the window whose broker it is subscribed to, and Qt destroys parented
        # children automatically when the parent is destroyed.
        super().__init__(main_window)
        self.app = app
        self._main_window = main_window
        self._broker: ConfirmationBroker | None = None
        self.confirmation_requested.connect(
            self._show_dialog, type=Qt.ConnectionType.QueuedConnection
        )

    # -- wiring ----------------------------------------------------------------------

    def subscribe_to(self, broker: ConfirmationBroker) -> None:
        """Attach to ``broker``. Call once the window (or the server) is up.

        Replaces any previous subscription first: this bridge, like the broker itself,
        supports exactly one live broker at a time (DEVELOPMENT-PLAN.md — one main
        window, one broker, one modal).
        """
        if self._broker is not None and self._broker is not broker:
            self._broker.unsubscribe()
        self._broker = broker
        broker.subscribe(self._on_confirmation_requested)
        logger.debug("Confirmation bridge subscribed to the broker")

    def unsubscribe(self) -> None:
        """Detach from the broker, if attached. Call when the window goes down.

        Safe to call whether or not :meth:`subscribe_to` was ever called — a window
        that never started a server still calls this from ``closeEvent`` unconditionally.
        """
        if self._broker is None:
            return
        self._broker.unsubscribe()
        self._broker = None
        logger.debug("Confirmation bridge unsubscribed from the broker")

    # -- the loop-thread side: must never touch a widget -------------------------

    def _on_confirmation_requested(self, request: ConfirmationRequest) -> None:
        """The broker's subscriber callback. Runs on the anyio event loop thread.

        Does nothing but hand ``request`` across the thread boundary via a signal
        emission — emitting a Qt signal is thread-safe from any thread, which is the
        one operation this method is allowed to perform. Anything else here — building
        a widget, reading `self.app.current_language` in a way that were not already
        thread-safe, blocking on anything — would either be undefined behaviour or
        would stall the loop thread for as long as it took, which is exactly the "must
        not block" contract :meth:`ConfirmationBroker._notify` relies on its caller
        to honour.
        """
        self.confirmation_requested.emit(request)

    # -- the GUI-thread side: the only place a dialog may be built ------------------

    def _show_dialog(self, request: ConfirmationRequest) -> None:
        """Build and run the modal. Runs on the GUI thread, via the queued connection.

        `self._broker` is read fresh here, at the moment this queued slot actually
        runs, not carried over from `_on_confirmation_requested`: the two calls are
        separated by however long the request sat in the Qt event queue, and
        `unsubscribe()` can run in that gap — a window closing right as a request
        arrives. When it does, the broker has already refused this exact request as
        part of `unsubscribe()`'s own fan-out (see confirmation.py), so finding
        `self._broker` cleared here means there is nothing left to show a modal for:
        the correct response is to skip it, not to pop up a dialog for a decision
        that has already been made.
        """
        broker = self._broker
        if broker is None:
            logger.warning(
                "A confirmation request for '%s' arrived after the bridge was "
                "unsubscribed; showing no dialog for it",
                request.tool_name,
            )
            return

        timeout_seconds = self.app.config_manager.get_confirmation_timeout_seconds()
        dialog = ConfirmationDialog(
            self._main_window,
            self.app.current_language,
            request=request,
            broker=broker,
            timeout_seconds=timeout_seconds,
        )
        dialog.exec()
