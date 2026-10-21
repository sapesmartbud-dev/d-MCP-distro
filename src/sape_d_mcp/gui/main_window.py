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

"""Main application window: Header / (Sidebar + pages) / StatusBar.

A plain ``QWidget`` sandwich, not a ``QMainWindow`` — f-MCP's own choice,
kept here because ``QMainWindow``'s dock areas, menu bar and native status
bar are all unused weight, and because ``QMainWindow.statusBar()`` would
otherwise be one accidental attribute clash away from swallowing
``self.status_bar_widget``.

Stage 3 wires the shell and all seven pages; the MCP server itself
(``mcp_server.py``, ``server_thread.py``) lands in stage 6. Until then the
status bar's start/stop controls are chrome without a server behind them —
see :meth:`_on_start_server` — but ``closeEvent`` already stops a real
server thread the moment one exists, rather than that being a fix deferred
to whichever stage adds it.
"""

from __future__ import annotations

import inspect
import logging

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from .components.header import Header
from .components.sidebar import Sidebar
from .components.status_bar import DEFAULT_PORT, StatusBarWidget
from .confirmation_bridge import ConfirmationBridge
from .i18n import translate
from .pages import (
    AboutPage,
    ConnectionsPage,
    HelpPage,
    LegalPage,
    LogsPage,
    PermissionsPage,
    SettingsPage,
)
from .resources import resource_path

logger = logging.getLogger(__name__)

# Minimum window size the restored geometry is validated against — anything
# smaller is treated as corrupt/stale rather than honoured, mirroring the
# floor MainWindow itself is given.
# How long the window waits for the server thread to unwind on its own. Generous by
# measurement, not by guess: see MainWindow._shutdown_server().
_SERVER_STOP_GRACE_MS = 20000
_SERVER_TERMINATE_GRACE_MS = 2000

# How long closeEvent waits for a page's own background worker
# (PermissionsPage._tree_worker / ConnectionsPage._test_thread) to finish on
# its own before terminating it. Neither is a cooperative thread the way
# ServerThread is — there is no stop() to call, only a live connect-or-
# introspect that either completes or hits engine.py's own connect timeout
# (DEFAULT_CONNECT_TIMEOUT_S + _WALL_CLOCK_MARGIN_S, 15 s worst case) — so
# this only needs the same doubling-for-safety headroom _SERVER_STOP_GRACE_MS
# takes over its own measured worst case.
_PAGE_WORKER_GRACE_MS = 30000

_MIN_WIDTH = 900
_MIN_HEIGHT = 600
_DEFAULT_GEOMETRY = {"x": 100, "y": 100, "width": 1280, "height": 800}

# server_thread.py is a stage-6 deliverable; importing it defensively means
# this module works unchanged before and after it lands.
try:
    from .server_thread import ServerThread
except ImportError:  # pragma: no cover - expected until stage 6
    ServerThread = None  # type: ignore[assignment, misc]

# confirmation.py is a stage-7 deliverable, imported the same defensive way as
# ServerThread just above even though it pulls in only anyio: a window with no
# confirmation module available still opens, it simply has nothing to subscribe.
try:
    from sape_d_mcp.confirmation import ConfirmationBroker
except ImportError:  # pragma: no cover - expected until stage 7
    ConfirmationBroker = None  # type: ignore[assignment, misc]


class MainWindow(QWidget):
    """The application's single top-level window."""

    def __init__(self, app) -> None:
        super().__init__()
        self.app = app
        self.server_thread = None
        self._restoring_geometry = False

        # The confirmation broker is owned by this window, not by the server thread:
        # it is subscribed the moment the window comes up and unsubscribed the moment
        # it closes (see closeEvent), independently of whether a server is actually
        # running — DESIGN-MCP-TOOLS.md §8.2's "no subscriber attached ⇒ denied" is
        # the correct posture for a --cli server or a server not yet started, and
        # subscribing early costs nothing since a broker with nobody calling
        # `request()` never notifies anybody. `ConfirmationBridge` is what actually
        # marshals a notification from the broker's (non-Qt) thread onto this one; see
        # its module docstring for the cross-thread contract in both directions.
        self.confirmation_broker = ConfirmationBroker() if ConfirmationBroker is not None else None
        self.confirmation_bridge = (
            ConfirmationBridge(self.app, self) if self.confirmation_broker is not None else None
        )
        if self.confirmation_bridge is not None:
            self.confirmation_bridge.subscribe_to(self.confirmation_broker)

        # Debounced geometry save: resize/move events fire far faster than
        # any human resizes a window, so every event triggering an
        # immediate write would thrash config.json. A single-shot timer
        # restarted on every event only ever writes once the user stops.
        self._geometry_save_timer = QTimer(self)
        self._geometry_save_timer.setSingleShot(True)
        self._geometry_save_timer.setInterval(300)
        self._geometry_save_timer.timeout.connect(self._save_window_geometry)

        self.setMinimumSize(_MIN_WIDTH, _MIN_HEIGHT)
        self._restore_window_geometry()

        self.setWindowTitle(translate("window.title", self.app.current_language))

        try:
            icon_path = resource_path("icons", "dark.ico")
        except FileNotFoundError as exc:
            logger.warning("Window icon not found: %s", exc)
        else:
            self.setWindowIcon(QIcon(str(icon_path)))

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # ===== HEADER =====
        self.header = Header(self.app)
        main_layout.addWidget(self.header)

        # ===== CONTENT (SIDEBAR + PAGES) =====
        content_widget = QWidget()
        content_layout = QHBoxLayout(content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(0)

        self.sidebar = Sidebar(self.app)
        self.sidebar.nav_clicked.connect(self._on_page_change)
        content_layout.addWidget(self.sidebar)

        self.pages = QStackedWidget()
        self.pages.setObjectName("pagesWidget")

        # Index order is the contract shared with Sidebar.nav_items — keep
        # both in step with each other if a page is ever added or reordered.
        self.connections_page = ConnectionsPage(self.app)
        self.permissions_page = PermissionsPage(self.app)
        self.logs_page = LogsPage(self.app)
        self.settings_page = SettingsPage(self.app)
        self.legal_page = LegalPage(self.app)
        self.help_page = HelpPage(self.app)
        self.about_page = AboutPage(self.app)

        self.pages.addWidget(self.connections_page)  # 0
        self.pages.addWidget(self.permissions_page)  # 1
        self.pages.addWidget(self.logs_page)  # 2
        self.pages.addWidget(self.settings_page)  # 3
        self.pages.addWidget(self.legal_page)  # 4
        self.pages.addWidget(self.help_page)  # 5
        self.pages.addWidget(self.about_page)  # 6

        content_layout.addWidget(self.pages, 1)
        main_layout.addWidget(content_widget, 1)

        # ===== STATUS BAR =====
        self.status_bar_widget = StatusBarWidget(self.app)
        self.status_bar_widget.start_clicked.connect(self._on_start_server)
        self.status_bar_widget.stop_clicked.connect(self._on_stop_server)
        main_layout.addWidget(self.status_bar_widget)

        # Connections is index 0 and opens on first launch — without a
        # connection there is nothing to permission, browse or log. Every
        # subsequent launch resumes wherever the user last was.
        last_page = self.app.config_manager.get_last_page()
        if not isinstance(last_page, int) or not (0 <= last_page < self.pages.count()):
            last_page = 0
        self.pages.setCurrentIndex(last_page)
        self.sidebar.set_active_page(last_page)

        self.app.language_changed.connect(self._update_language)

        logger.info("Main window created")

    def _on_page_change(self, page_index: int) -> None:
        """Switch pages and persist the choice as the next launch's default."""
        self.pages.setCurrentIndex(page_index)
        self.app.config_manager.set_last_page(page_index)
        logger.debug("Switched to page: %d", page_index)

    def _update_language(self, language: str) -> None:
        self.setWindowTitle(translate("window.title", language))

    def _on_start_server(self) -> None:
        """Start the MCP server thread.

        The import is still guarded: PyQt6 is present by definition here, but
        ``server_thread`` pulls in the MCP SDK and the database layer, and a GUI
        installed without them should degrade to a dead button rather than a
        traceback on start-up.

        ``server_started`` and ``server_stopped`` rather than ``started`` and
        ``finished``: the latter two are ``QThread``'s own, and a subclass that
        redeclares them shadows Qt's — see ``server_thread``'s module docstring.
        """
        if ServerThread is None:
            logger.warning("The MCP server is unavailable: server_thread could not be imported.")
            self.status_bar_widget.set_running(False)
            return

        if self.server_thread is None or not self.server_thread.isRunning():
            logger.info("Starting MCP server...")
            self.server_thread = ServerThread(self.app, port=DEFAULT_PORT, **self._server_thread_kwargs())
            self.server_thread.server_started.connect(self._on_server_started)
            self.server_thread.server_stopped.connect(self._on_server_stopped)
            self.server_thread.server_failed.connect(self._on_server_failed)
            self.server_thread.port_changed.connect(self.status_bar_widget.set_port_info)
            self.server_thread.start()

    def _server_thread_kwargs(self) -> dict:
        """Extra keyword arguments for ``ServerThread``, forward-compatible with
        whichever stage wires the confirmation broker into it.

        As of this stage ``ServerThread`` builds its own ``DatabaseMCPServer``
        internally (see ``server_thread.py``'s ``_build_server``) and has no
        parameter this window could pass a broker through — the server is built on
        the server thread itself, deliberately, so this window constructing one
        instead and handing it in via ``ServerThread(server=...)`` would reintroduce
        exactly the "opening SQLite handles on the Qt thread" problem that
        constructor arrangement exists to avoid. Rather than duplicate that
        machinery here, this checks ``ServerThread``'s own signature and passes
        ``confirmation=`` only once it grows a place to put it, logging once if it
        has not — see the stage-7 report for the flag this covers.
        """
        if self.confirmation_broker is None:
            return {}
        try:
            parameters = inspect.signature(ServerThread.__init__).parameters
        except (TypeError, ValueError):  # pragma: no cover - defensive only
            parameters = {}
        if "confirmation" in parameters:
            return {"confirmation": self.confirmation_broker}
        logger.warning(
            "ServerThread does not yet accept a confirmation broker; destructive "
            "operations will be denied until it is wired through (see the stage-7 report)."
        )
        return {}

    def _on_server_started(self, port: int) -> None:
        """The server is listening. The port comes from the thread rather than from
        ``DEFAULT_PORT`` because the requested one may have been busy."""
        self.status_bar_widget.set_port_info(port)
        self.status_bar_widget.set_running(True)

    def _on_server_stopped(self) -> None:
        self.status_bar_widget.set_running(False)

    def _on_server_failed(self, message: str) -> None:
        """Report a start-up failure the operator can act on.

        Constructed explicitly rather than through ``QMessageBox.critical`` so the
        button text is translated — f-MCP's static-helper calls are always English.
        """
        self.status_bar_widget.set_running(False)
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Critical)
        box.setWindowTitle(translate("status_bar.error_title", self.app.current_language))
        box.setText(message)
        box.addButton(
            translate("common.close", self.app.current_language),
            QMessageBox.ButtonRole.AcceptRole,
        )
        box.exec()

    def _on_stop_server(self) -> None:
        """Stop the MCP server thread, if one is actually running."""
        self._shutdown_server()
        self.status_bar_widget.set_running(False)

    def _shutdown_server(self) -> None:
        """Stop the server thread and do not return until it has actually stopped.

        The grace period is 20 seconds, not the 5 f-MCP uses. Measured over repeated
        start/stop cycles, a cancelled uvicorn takes between 4.6 and 10.2 seconds to
        unwind — so a 5-second wait times out more often than not, and the old code then
        simply carried on and let the window close over a live thread holding three open
        SQLite handles. Qt destroying a running ``QThread`` is undefined behaviour; a
        half-written WAL is the best case.

        ``terminate()`` is the last resort and is genuinely last: it stops the thread
        mid-instruction, so it runs only once the polite path has had twice as long as it
        has ever needed.

        Known defect, deliberately left for the GUI stage: this blocks the Qt thread for
        those seconds, so the window is unresponsive while the server stops. Fixing it
        means driving the wait from a timer and showing progress, which is a page-level
        change; hanging on to the thread is the safe half and it is what is done here.
        """
        thread = self.server_thread
        if thread is None or not thread.isRunning():
            return

        logger.info("Stopping MCP server...")
        thread.stop()
        if thread.wait(_SERVER_STOP_GRACE_MS):
            return

        logger.warning(
            "The MCP server did not stop within %d ms; terminating the thread.",
            _SERVER_STOP_GRACE_MS,
        )
        thread.terminate()
        if not thread.wait(_SERVER_TERMINATE_GRACE_MS):
            logger.error("The MCP server thread could not be terminated.")

    def _shutdown_page_workers(self) -> None:
        """Wait for the Connections and Permissions pages' own background workers.

        ``_ConnectionTestWorker`` and ``_SchemaLoadWorker`` are both ``QThread``s that
        hold a live database connection and, for a non-SQLite profile, a password for
        as long as they run — f-MCP defect 9's exact shape (an abandoned ``QThread``
        destroyed mid-run is undefined behaviour), reproduced in two threads
        ``closeEvent`` did not know about until now. Closing the window during a slow
        connect is precisely when a user closes the window.

        Neither worker is cooperative the way ``ServerThread`` is: there is no
        ``stop()`` to call, only a wait for it to finish on its own, followed by
        ``terminate()`` as the same last resort ``_shutdown_server()`` uses.
        """
        connections_page = getattr(self, "connections_page", None)
        permissions_page = getattr(self, "permissions_page", None)
        workers = (
            getattr(connections_page, "_test_thread", None),
            getattr(permissions_page, "_tree_worker", None),
        )
        for worker in workers:
            if worker is None or not worker.isRunning():
                continue
            logger.info("Waiting for %s to finish before closing...", type(worker).__name__)
            if worker.wait(_PAGE_WORKER_GRACE_MS):
                continue
            logger.warning(
                "%s did not finish within %d ms; terminating.",
                type(worker).__name__, _PAGE_WORKER_GRACE_MS,
            )
            worker.terminate()
            worker.wait(_SERVER_TERMINATE_GRACE_MS)

    def _save_window_geometry(self) -> None:
        """Persist window position, size and maximised state via ConfigManager.

        f-MCP does this with a private ``open()``/``json.load``/``json.dump``
        inside ``MainWindow`` itself — one of the four independent writers of
        ``config.json`` this project fixes. Everything here goes through
        ``config_manager.set_window_state()`` instead.
        """
        if self._restoring_geometry:
            return

        geometry = self.geometry()
        self.app.config_manager.set_window_state(
            {
                "x": geometry.x(),
                "y": geometry.y(),
                "width": geometry.width(),
                "height": geometry.height(),
                "maximized": self.isMaximized(),
            }
        )
        logger.debug("Window geometry saved")

    def _restore_window_geometry(self) -> None:
        """Restore window position, size and maximised state, or fall back
        to the default 1280x800 if nothing was saved or it looks corrupt."""
        self._restoring_geometry = True
        try:
            saved = self.app.config_manager.get_window_state() or _DEFAULT_GEOMETRY

            width = saved.get("width", _DEFAULT_GEOMETRY["width"])
            height = saved.get("height", _DEFAULT_GEOMETRY["height"])
            x = saved.get("x", _DEFAULT_GEOMETRY["x"])
            y = saved.get("y", _DEFAULT_GEOMETRY["y"])

            if width < _MIN_WIDTH or height < _MIN_HEIGHT:
                x, y = _DEFAULT_GEOMETRY["x"], _DEFAULT_GEOMETRY["y"]
                width, height = _DEFAULT_GEOMETRY["width"], _DEFAULT_GEOMETRY["height"]

            self.setGeometry(x, y, width, height)

            if saved.get("maximized", False):
                # setWindowState(), not showMaximized(): this runs from __init__, and
                # showMaximized() *shows* the window there — before the splash screen
                # is up and before main() has decided anything should be on screen.
                # This records the state, and the caller's own show() honours it.
                self.setWindowState(self.windowState() | Qt.WindowState.WindowMaximized)

            logger.info("Window geometry restored")
        finally:
            self._restoring_geometry = False

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if not self._restoring_geometry:
            self._geometry_save_timer.start()

    def moveEvent(self, event) -> None:
        super().moveEvent(event)
        if not self._restoring_geometry:
            self._geometry_save_timer.start()

    def closeEvent(self, event) -> None:
        """Stop every background thread this window knows about before the
        process exits: the server thread, and the Connections and
        Permissions pages' own workers.

        f-MCP's ``closeEvent`` only ever calls ``event.accept()`` after
        saving window state — a running server thread is simply abandoned.
        ``_shutdown_page_workers()`` closes the same gap for
        ``_ConnectionTestWorker`` and ``_SchemaLoadWorker``, which f-MCP has
        no equivalent of at all: both hold a live database connection, and
        for a non-SQLite profile a password, for as long as they run.

        The confirmation bridge is unsubscribed first, before anything is asked to
        stop: ``ConfirmationBroker.unsubscribe()`` immediately refuses every
        call still waiting on a decision (DESIGN-MCP-TOOLS.md §8.2's "no subscriber
        attached ⇒ denied"), which is what should happen to a modal left open when
        the window that owns it is going away, rather than leaving it to sit out
        its own timeout while the process is already shutting down underneath it.
        """
        if self.confirmation_bridge is not None:
            self.confirmation_bridge.unsubscribe()
        self._shutdown_page_workers()
        self._shutdown_server()
        self._save_window_geometry()
        event.accept()
