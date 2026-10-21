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

"""Runs ``DatabaseMCPServer`` inside the GUI process, on a thread of its own.

In-process rather than a subprocess, so the operator's start/stop button governs the
same server the Permissions page is writing rules for — a subprocess would read
``permissions.db`` from disk and lag a rule the operator had just changed.

Two things make that harder than it looks, and both are why this file exists rather
than the window simply calling ``server.run()``:

**stdio cannot be used from a thread.** ``run_stdio_async()`` reads the process's own
standard input, which the GUI does not own and which no button can interrupt; the
thread would block on ``stdin`` forever and ``stop()`` would never be seen. The GUI
therefore rewrites ``stdio`` to ``streamable-http`` and says so in the log. ``stdio``
remains the right transport for the ``--cli`` server an MCP client spawns, where the
process *does* own its standard input.

**A thread cannot be killed politely.** ``QThread.terminate()`` stops it mid-instruction,
which with a SQLite handle open means a half-written WAL. Shutdown is instead a
``threading.Event`` — settable from the Qt thread — that a task inside the event loop
polls every 100 ms and turns into an ``anyio`` cancellation, so the server unwinds its
own resources. ``terminate()`` stays as the last resort the window applies after
``wait()`` times out.

**Nothing on the Qt thread can touch the event loop, and the confirmation modal has to.**
The human's Approve click happens on Qt's thread; the tool call waiting for it is parked on
an ``anyio.Event`` belonging to *this* thread's loop, and an asyncio ``Event`` set from the
wrong thread can simply fail to wake its waiter. The bridge across is an
``anyio.from_thread.BlockingPortal``, opened here in :meth:`ServerThread._serve` and handed
to **both** ``DatabaseMCPServer.set_portal`` — which schedules
``notifications/tools/list_changed`` through it — and ``ConfirmationBroker.set_portal``.
One portal, two users, because there is one event loop: two portals would be two task
groups on the same loop for no gain, and a broker with no portal at all silently degrades
into the failure mode it was written to prevent, an Approve click that never wakes anything.

The portal is opened **outside** the cancel scope the stop button closes, deliberately.
Inside it, pressing Stop would cancel the scope while ``BlockingPortal.__aexit__`` was still
waiting for its own task group to finish, and the portal would be torn down under
cancellation rather than closed. Outside, the scope unwinds first and the portal closes
normally, with both ``set_portal(None)`` calls made in a ``finally`` so a click arriving
after shutdown cannot reach into a loop that no longer exists.

Three defects in f-MCP's equivalent are deliberately not reproduced:

1. It declares ``started``/``finished`` signals on a ``QThread`` subclass, which
   **shadows** ``QThread``'s own signals of those names. Anything relying on Qt's
   ``finished`` — ``deleteLater`` chains included — silently stops being notified. The
   signals here are named ``server_started``/``server_stopped`` so both survive.
2. It emits ``started`` before the server is listening, so the status bar reads
   "running" during a bind that may still fail. Here the port is bound-tested first and
   the signal carries the port actually in use.
3. It never closes the server, leaving ``connections.db``, ``permissions.db`` and
   ``audit.db`` open until the process exits. Here ``close()`` runs in a ``finally``.

Known cosmetic defect: stopping the server prints one ``CancelledError`` traceback from
``uvicorn.error`` at ERROR level. It is uvicorn's lifespan task reporting the
cancellation that *is* the stop button, so nothing is wrong — but it reads like a crash.
A ``logging.Filter`` does not reach it: uvicorn reconfigures logging as it starts, which
drops any filter attached beforehand, and it emits the record during a teardown phase
that runs after the task group this module controls has already unwound, so a filter
attached at stop time is gone again before the record appears. Suppressing it properly
needs a handle on uvicorn's own ``Server`` object, which ``run_streamable_http_async()``
does not expose. Left visible rather than papered over with code that does not work.
"""

from __future__ import annotations

import errno
import logging
import socket
import threading
from typing import Any

import anyio
import anyio.from_thread
from PyQt6.QtCore import QThread, pyqtSignal

logger = logging.getLogger(__name__)

#: First port tried. The nine above it are tried in turn, matching f-MCP's 8089–8098
#: range so the two applications' generated client configurations never collide by
#: accident — d-MCP simply takes the first port f-MCP has not.
DEFAULT_PORT = 8089

#: How many consecutive ports to try before giving up.
PORT_ATTEMPTS = 10

#: How often the event loop checks whether the GUI has asked it to stop. Short enough
#: that stopping feels immediate, long enough that an idle server is not busy-waiting.
_SHUTDOWN_POLL_SECONDS = 0.1


class ServerThread(QThread):
    """The MCP server, running in the GUI process on a background thread."""

    #: The server is listening; carries the port it actually bound.
    server_started = pyqtSignal(int)
    #: The server has stopped and released its stores, whether by request or by failure.
    server_stopped = pyqtSignal()
    #: The server could not start, or died. Carries a message fit for a dialog.
    server_failed = pyqtSignal(str)
    #: The requested port was busy and another was used instead.
    port_changed = pyqtSignal(int)
    #: One tool call: name, parameters, result, error. Empty strings, not ``None``, so
    #: the signal's signature stays valid for Qt.
    tool_executed = pyqtSignal(str, dict, str, str)

    def __init__(
        self,
        app: Any,
        port: int = DEFAULT_PORT,
        host: str = "127.0.0.1",
        transport: str = "streamable-http",
        server: Any | None = None,
        confirmation: Any | None = None,
    ) -> None:
        """Prepare the thread. Nothing is opened here; see :meth:`run`.

        Args:
            app: The ``SAPEApplication``, used as the Qt parent and read for the operator's
                language and confirmation timeout.
            port: The port to try first; nine above it are tried in turn.
            host: The interface to bind.
            transport: ``sse`` or ``streamable-http``. ``stdio`` is rewritten, with a log
                line saying why — see the module docstring.
            server: An already-built ``DatabaseMCPServer`` to serve instead of building one.
                Its stores are the caller's to close.
            confirmation: The window's ``ConfirmationBroker``. Handed to the server it
                builds, and given the event loop's portal once that loop exists. ``None``
                means every destructive tool refuses, which is correct rather than broken —
                it is exactly the state a ``--cli`` server runs in.
        """
        super().__init__(app if isinstance(app, QThread) else None)
        self.app = app
        self.host = host
        self.port = port
        self.requested_port = port
        self.server = server
        self.confirmation = confirmation
        self._owns_server = server is None

        # Read on the Qt thread, at construction, rather than from the server thread while
        # the loop is running: ConfigManager is the GUI's, and the value has to reach the
        # broker's clock and the dialog's countdown as the *same* number or the operator is
        # shown a timer that is not the one deciding. Defensive, because a window may hand
        # in an `app` double that has no config manager at all.
        self._confirmation_timeout_s: float | None = None
        try:
            self._confirmation_timeout_s = float(
                app.config_manager.get_confirmation_timeout_seconds()
            )
        except Exception:
            logger.debug("No confirmation timeout could be read from the configuration")

        if transport == "stdio":
            logger.info(
                "stdio was requested but cannot be served from a thread — it would block "
                "on the process's standard input, which the GUI does not own. Using "
                "streamable-http instead; --cli still serves stdio."
            )
            transport = "streamable-http"
        self.transport = transport

        self._shutdown = threading.Event()
        self._cancel_scope: anyio.CancelScope | None = None

    # -- lifecycle -----------------------------------------------------------------

    def stop(self) -> None:
        """Ask the server to shut down. Safe to call from the Qt thread, and from a
        thread that is not running one — setting an :class:`threading.Event` is the only
        cross-thread operation here, and it is idempotent."""

        self._shutdown.set()

    def run(self) -> None:
        """Build the server, bind a port and serve until asked to stop.

        The server is constructed **here**, on this thread, rather than in ``__init__``.
        Opening three SQLite stores can fail — a permissions database made read-only by
        a backup tool, a directory that is not writable — and doing it on the Qt thread
        would either freeze the click or raise inside a signal handler. Failing here
        turns into ``server_failed`` like any other startup problem.
        """

        try:
            port = self._find_available_port(self.port)
            if port is None:
                last = self.port + PORT_ATTEMPTS - 1
                self._fail(
                    f"No free port between {self.port} and {last}. Another d-MCP or f-MCP "
                    "instance is probably already serving."
                )
                return
            if port != self.requested_port:
                logger.info("Port %d is busy; using %d instead", self.requested_port, port)
                self.port = port
                self.port_changed.emit(port)

            if self.server is None:
                self.server = self._build_server()
            if hasattr(self.server, "set_tool_executed_callback"):
                self.server.set_tool_executed_callback(self._on_tool_executed)

            logger.info("MCP server starting on %s:%d (%s)", self.host, self.port, self.transport)
            anyio.run(self._serve)

        except OSError as exc:
            # A port can be taken between the probe above and the bind below — the probe
            # is a courtesy, not a lock, so the race is expected rather than exceptional.
            if getattr(exc, "errno", None) in (errno.EADDRINUSE, 10048):
                self._fail(
                    f"Port {self.port} was taken while starting. Try again, or stop the "
                    "other instance."
                )
            else:
                self._fail(f"The server could not start: {exc}")
        except Exception as exc:
            logger.exception("MCP server thread failed")
            self._fail(f"The server stopped unexpectedly: {exc}")
        finally:
            self._close_server()
            self.server_stopped.emit()

    # -- the event loop ------------------------------------------------------------

    async def _serve(self) -> None:
        """Serve inside a cancel scope a watchdog can close from outside the loop."""

        async def watch_for_shutdown() -> None:
            while not self._shutdown.is_set():
                await anyio.sleep(_SHUTDOWN_POLL_SECONDS)
            logger.info("Shutdown requested; cancelling the MCP server")
            if self._cancel_scope is not None:
                self._cancel_scope.cancel()

        # The portal wraps the cancel scope, not the other way round — see the module
        # docstring. Cancelling from inside would tear it down mid-``__aexit__``.
        async with anyio.from_thread.BlockingPortal() as portal:
            self._bind_portal(portal)
            try:
                self._cancel_scope = anyio.CancelScope()
                with self._cancel_scope:
                    async with anyio.create_task_group() as tasks:
                        tasks.start_soon(watch_for_shutdown)
                        self.server_started.emit(self.port)
                        if self.transport == "sse":
                            await self.server.server.run_sse_async(host=self.host, port=self.port)
                        else:
                            await self.server.server.run_streamable_http_async(
                                host=self.host, port=self.port
                            )
            finally:
                self._bind_portal(None)

    def _bind_portal(self, portal: Any | None) -> None:
        """Give the server and the broker the loop's portal, or take it back on the way out.

        Both, not either: the server schedules ``tools/list_changed`` through it and the
        broker resolves a human's Approve click through it, and a portal handed to only one
        of them is a whole feature that silently does nothing. ``None`` clears both, so a
        click landing after the loop has gone is resolved directly instead of being posted
        into a loop that no longer exists.

        Failures are logged and swallowed. A server that cannot be told about its portal
        still serves — it simply does not send one notification — and refusing to start over
        it would be a worse trade than a warning in the log.
        """
        for owner in (self.server, self.confirmation):
            setter = getattr(owner, "set_portal", None)
            if setter is None:
                continue
            try:
                setter(portal)
            except Exception as exc:
                logger.warning("Could not %s a portal on %r: %s",
                               "bind" if portal is not None else "clear", owner, exc)

    # -- helpers -------------------------------------------------------------------

    def _build_server(self) -> Any:
        """Construct the server with the GUI's own session id, broker and timeout.

        Imported here rather than at module scope so that importing this module — which
        ``main_window`` does defensively at start-up — cannot drag the whole database
        layer and the MCP SDK into a GUI that is only being shown, not served from.

        The broker is handed in at construction rather than attached afterwards: a server
        that came up brokerless for even one call would refuse a destructive tool the
        operator's own window was sitting there ready to approve, and would log it as though
        nobody had been watching.

        ``language`` is a callable, not the current value: the operator can change language
        while the server runs, and the string is read at the moment a confirmation warning is
        composed. It is read from another thread, which is safe because it is a plain
        attribute read of a string.
        """

        from sape_d_mcp.mcp_server import DatabaseMCPServer

        return DatabaseMCPServer(
            session_id="gui",
            confirmation=self.confirmation,
            confirmation_timeout_s=self._confirmation_timeout_s,
            language=lambda: getattr(self.app, "current_language", "en-US"),
        )

    def _on_tool_executed(
        self,
        tool_name: str,
        params: dict[str, Any] | None = None,
        result: str | None = None,
        error: str | None = None,
    ) -> None:
        """Relay one tool call to the GUI. Called on this thread; Qt queues the signal
        across to the Qt thread on its own, which is why nothing here touches a widget."""

        self.tool_executed.emit(tool_name, dict(params or {}), result or "", error or "")

    def _close_server(self) -> None:
        """Release the stores, but only those this thread opened.

        A server handed in through the constructor belongs to the caller — closing it
        would shut the databases under a GUI that is still using them.
        """

        if self.server is None or not self._owns_server:
            return
        try:
            if hasattr(self.server, "set_tool_executed_callback"):
                self.server.set_tool_executed_callback(None)
            self.server.close()
        except Exception:
            logger.exception("Failed to close the MCP server cleanly")
        finally:
            self.server = None

    def _fail(self, message: str) -> None:
        logger.error(message)
        self.server_failed.emit(message)

    def _is_port_available(self, port: int) -> bool:
        """Whether ``port`` can be bound right now.

        ``SO_REUSEADDR`` is deliberately not set: on Windows it lets two sockets bind the
        same port and would report a busy port as free.
        """

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind((self.host, port))
            return True
        except OSError:
            return False

    def _find_available_port(self, start: int) -> int | None:
        """The first free port from ``start``, or ``None`` if all attempts are taken."""

        for port in range(start, start + PORT_ATTEMPTS):
            if self._is_port_available(port):
                return port
        return None

