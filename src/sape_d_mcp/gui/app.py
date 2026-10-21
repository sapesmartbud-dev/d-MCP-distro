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

"""``SAPEApplication`` — the theme/language broadcast bus every widget hangs
off.

Two signals, deliberately asymmetric in how widgets are meant to consume
them:

- ``language_changed`` is emitted by *this* class, re-broadcasting
  ``LanguageManager.language_changed`` — every widget connects
  ``app.language_changed``.
- ``theme_changed`` also exists here for any consumer that only cares about
  the application object, but the binding convention for widgets is to
  connect ``app.theme_manager.theme_changed`` directly, since that manager
  is the one thing guaranteed to exist before the stylesheet has been
  applied for the first time.

Managers persist their own change to ``ConfigManager`` *before* emitting;
this class never writes ``config.json`` itself — see ``theme_manager.py``
for why f-MCP's four independent writers are the defect being fixed here.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication

from sape_d_mcp.db.connection_store import ConnectionStore
from sape_d_mcp.db.credential_store import CredentialStore
from sape_d_mcp.log_store import LogStore
from sape_d_mcp.permissions import PermissionStore

from .config_manager import ConfigManager
from .language_manager import LanguageManager
from .main_window import MainWindow
from .resources import resource_path
from .styles.sape_design_tokens import DARK_THEME_PALETTE, LIGHT_THEME_PALETTE
from .theme_manager import ThemeManager

logger = logging.getLogger(__name__)

_STYLESHEETS = {
    "dark": "application.qss",
    "light": "application_light.qss",
}


class SAPEApplication(QApplication):
    """The PyQt6 application object for SAPÉ d-MCP."""

    theme_changed = pyqtSignal(str)  # "light" or "dark"
    language_changed = pyqtSignal(str)  # e.g. "es-ES"

    def __init__(self, argv: list[str] | None = None) -> None:
        super().__init__(argv if argv is not None else sys.argv)

        self._set_application_icon()

        # One writer for config.json: every manager below is handed this
        # instance and calls its typed getters/setters rather than opening
        # the file itself.
        self.config_manager = ConfigManager()

        self.theme_manager = ThemeManager(self.config_manager)
        self.current_theme = self.theme_manager.current_theme
        self.theme_manager.theme_changed.connect(self._on_theme_changed)

        self.language_manager = LanguageManager(self.config_manager)
        self.current_language = self.language_manager.current_language
        self.language_manager.language_changed.connect(self._on_language_changed)

        # Apply the theme that was just loaded before anything paints.
        self._apply_theme_visuals(self.current_theme)

        # The Connections and Permissions pages' stores. Created lazily, on
        # first access, not here: a headless inspection of this class or a
        # GUI launch that only ever shows sample data must not touch
        # connections.db, permissions.db or probe the OS keyring before it is
        # actually asked to. Closed in _close_stores(), hooked to
        # aboutToQuit rather than MainWindow's closeEvent, because this class
        # is what owns them.
        self._connection_store: ConnectionStore | None = None
        self._credential_store: CredentialStore | None = None
        self._permission_store: PermissionStore | None = None
        self._log_store: LogStore | None = None
        self.aboutToQuit.connect(self._close_stores)

        self.main_window = MainWindow(self)

        logger.info("SAPÉ d-MCP GUI initialised")

    @property
    def connection_store(self) -> ConnectionStore:
        """The one ``ConnectionStore`` for this process, opened on first use.

        Constructed with this application's ``credential_store`` so that
        ``ConnectionStore.delete()``'s cascade (DESIGN-DATA-MODEL.md §7.2)
        purges the right backend without the Connections page having to know
        which one that is.
        """
        if self._connection_store is None:
            self._connection_store = ConnectionStore(credential_store=self.credential_store)
        return self._connection_store

    @property
    def credential_store(self) -> CredentialStore:
        """The one ``CredentialStore`` for this process, opened on first use."""
        if self._credential_store is None:
            self._credential_store = CredentialStore()
        return self._credential_store

    @property
    def permission_store(self) -> PermissionStore:
        """The one ``PermissionStore`` for this process, opened on first use.

        The Permissions page's sole route to ``permissions.db`` — no page may
        open its own handle, per the "one config writer" discipline this
        application follows throughout.
        """
        if self._permission_store is None:
            self._permission_store = PermissionStore()
        return self._permission_store

    @property
    def log_store(self) -> LogStore:
        """The one ``LogStore`` for this process, opened on first use.

        The Logs page's sole route to ``audit.db`` — the MCP server thread opens its
        own ``LogStore`` independently (``server_thread.py``), because the two
        processes-in-spirit (GUI and server) each need their own SQLite handle even
        though WAL lets them share the file.
        """
        if self._log_store is None:
            self._log_store = LogStore()
        return self._log_store

    def _close_stores(self) -> None:
        """Close the connection, permission and log stores' SQLite handles before
        the process exits.

        ``CredentialStore`` holds no persistent handle to close: the OS
        keyring is a service call and the AES vault is read and rewritten
        whole on each use, so there is nothing here for it to release.
        """
        if self._connection_store is not None:
            self._connection_store.close()
        if self._permission_store is not None:
            self._permission_store.close()
        if self._log_store is not None:
            self._log_store.close()

    def _set_application_icon(self) -> None:
        """Set the taskbar/title-bar icon, best-effort.

        A missing icon must never stop the GUI from starting — it is
        cosmetic, unlike a missing logo in the splash screen, which raises
        because it signals a broken resource tree before any window exists
        to show a warning in.
        """
        try:
            icon_path = resource_path("icons", "dark.ico")
        except FileNotFoundError as exc:
            logger.warning("Could not resolve application icon: %s", exc)
            return

        self.setWindowIcon(QIcon(str(icon_path)))

        if sys.platform == "win32":
            try:
                import ctypes

                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
                    "SAPE.d-MCP"
                )
            except Exception as exc:
                logger.debug("Could not set app model ID: %s", exc)

    def set_theme(self, theme: str) -> None:
        """Request a theme change; the manager decides whether it is a
        no-op, persists it, then emits."""
        self.theme_manager.set_theme(theme)

    def set_language(self, code: str) -> None:
        """Request a language change; the manager decides whether it is a
        no-op, persists it, then emits."""
        self.language_manager.set_language(code)

    def _on_theme_changed(self, theme: str) -> None:
        """React to ``ThemeManager`` having already persisted the change."""
        self._apply_theme_visuals(theme)
        self.current_theme = theme
        self.theme_changed.emit(theme)
        logger.info("Application theme changed to: %s", theme)

    def _on_language_changed(self, language: str) -> None:
        """React to ``LanguageManager`` having already persisted the change."""
        self.current_language = language
        self.language_changed.emit(language)
        logger.info("Application language changed to: %s", language)

    def _apply_theme_visuals(self, theme: str) -> None:
        """Reload the whole stylesheet and swap the palette for ``theme``.

        The QSS files are package data shipped inside ``gui/styles/``
        alongside this module (declared in ``pyproject.toml``'s
        ``package-data``), not assets from ``./gui_resources`` — so this is
        the one place a single, same-package ``Path(__file__).parent`` hop
        is correct rather than a defect: ``resource_path()`` resolves the
        *external* resource tree (frozen ``sys._MEIPASS``, checkout root or
        ``sys.prefix``), which is a different question from "where is this
        module's own data file", and conflating the two would make a frozen
        build look in the wrong place for one of them.
        """
        palette = DARK_THEME_PALETTE if theme == "dark" else LIGHT_THEME_PALETTE
        stylesheet_file = _STYLESHEETS.get(theme, _STYLESHEETS["light"])

        stylesheet_path = Path(__file__).parent / "styles" / stylesheet_file
        if stylesheet_path.exists():
            with open(stylesheet_path, encoding="utf-8") as handle:
                self.setStyleSheet(self._resolve_icon_urls(handle.read()))
        else:
            logger.warning("Stylesheet not found: %s", stylesheet_path)

        self.setPalette(palette)

    @staticmethod
    def _resolve_icon_urls(stylesheet: str) -> str:
        """Replace ``@ICONS@`` with the absolute ``gui_resources/icons`` path.

        Qt resolves a relative ``url()`` in a stylesheet against the *current working
        directory*, which is wherever the user happened to launch from — so a relative
        path works from the project root and silently draws nothing from anywhere else.
        ``resource_path()`` already answers "where is the resource tree" for a checkout,
        a frozen build and an installed package alike, and this is that answer spliced
        into the sheet. Forward slashes because Qt's url() parser treats a backslash as
        an escape, whatever the platform.

        A missing icons directory is not fatal: the token is left as it stands, Qt
        ignores the rule it cannot load, and the combo boxes fall back to no marker
        rather than the whole sheet failing to apply.
        """
        if "@ICONS@" not in stylesheet:
            return stylesheet
        try:
            icons_dir = resource_path("icons").as_posix()
        except FileNotFoundError:
            logger.warning("Icons directory not found; combo-box markers will not be drawn")
            return stylesheet
        return stylesheet.replace("@ICONS@", icons_dir)

    def run(self, splash=None) -> int:
        """Show the main window, close ``splash`` if given, then run the
        Qt event loop."""
        self.main_window.show()

        if splash is not None:
            splash.close()

        return self.exec()
