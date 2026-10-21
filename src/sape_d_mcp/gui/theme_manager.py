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

"""Theme persistence and broadcasting for the SAPÉ d-MCP GUI.

f-MCP gives ``ThemeManager`` its own private read-modify-write of
``~/.sape/config.json``, and ``LanguageManager`` and ``MainWindow`` each do
the same for their own slice of the same file — four writers racing on one
file, the fourth being a duplicate ``ConfigManager`` a page instantiates for
itself. d-MCP keeps exactly one writer: the ``ConfigManager`` handed to this
class at construction. ``ThemeManager`` only decides *when* to persist and
broadcasts the result; it never touches the filesystem itself.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QObject, pyqtSignal

logger = logging.getLogger(__name__)


class ThemeManager(QObject):
    """Manages theme persistence and application-wide theme signals.

    Loads the saved theme from ``config_manager`` on construction and
    persists every change back through it before broadcasting
    :attr:`theme_changed`, matching the "managers persist, then emit"
    contract the whole GUI is built on.
    """

    # Emits "dark" or "light" whenever the active theme changes.
    theme_changed = pyqtSignal(str)

    def __init__(self, config_manager) -> None:
        super().__init__()
        self.config_manager = config_manager
        self._current_theme = self._sanitise(config_manager.get_theme())
        logger.info("Theme manager initialised with theme: %s", self._current_theme)

    @staticmethod
    def _sanitise(theme: str) -> str:
        """Fall back to light rather than trust an unexpected config value.

        A hand-edited or corrupted config.json could hold anything; failing
        open to a theme rather than raising keeps a bad config from making
        the GUI unusable.
        """
        return theme if theme in ("dark", "light") else "light"

    @property
    def current_theme(self) -> str:
        """Return the currently active theme ("dark" or "light")."""
        return self._current_theme

    def set_theme(self, theme: str) -> None:
        """Set the theme, persist it, then broadcast the change.

        A no-op when ``theme`` already matches the current theme, so toggling
        twice in quick succession does not write to disk or emit twice.
        """
        theme = self._sanitise(theme)

        if theme == self._current_theme:
            logger.debug("Theme already set to: %s", theme)
            return

        self._current_theme = theme
        self.config_manager.set_theme(theme)
        self.theme_changed.emit(theme)
        logger.info("Theme changed and persisted: %s", theme)

    def toggle_theme(self) -> str:
        """Flip between dark and light, returning the theme now in effect."""
        new_theme = "light" if self._current_theme == "dark" else "dark"
        self.set_theme(new_theme)
        return new_theme
