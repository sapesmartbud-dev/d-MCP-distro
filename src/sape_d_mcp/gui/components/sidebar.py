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

"""Sidebar navigation: seven pages, Connections first.

The Explorer page f-MCP would have had is folded into Permissions as a
schema-browser panel, so there are seven entries here rather than f-MCP's
six, and no Explorer key. ``nav_items`` and the ``QStackedWidget`` index
order in :class:`~sape_d_mcp.gui.main_window.MainWindow` are one contract —
keep them index-aligned with ``addWidget`` order if either changes.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtWidgets import QPushButton, QVBoxLayout, QWidget

from ..i18n import translate
from ..styles.sape_design_tokens import SPACING_MD, SPACING_SM


class Sidebar(QWidget):
    """Left sidebar with menu-style navigation."""

    nav_clicked = pyqtSignal(int)  # page index

    def __init__(self, app=None) -> None:
        super().__init__()
        self.app = app
        self.setObjectName("sidebar")
        self.setMaximumWidth(250)
        self.setMinimumWidth(200)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(SPACING_MD, SPACING_MD, SPACING_MD, SPACING_MD)
        layout.setSpacing(SPACING_SM)

        # (translation_key, page_index) pairs — index-aligned with
        # MainWindow.pages.addWidget() order.
        self.nav_items = [
            ("sidebar.connections", 0),
            ("sidebar.permissions", 1),
            ("sidebar.logs", 2),
            ("sidebar.settings", 3),
            ("sidebar.legal", 4),
            ("sidebar.help", 5),
            ("sidebar.about", 6),
        ]
        self.nav_icons = ["🔌", "🔐", "📋", "⚙️", "📜", "❓", "ℹ️"]

        self.button_group: list[QPushButton] = []

        for _trans_key, page_index in self.nav_items:
            btn = QPushButton()
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.clicked.connect(lambda checked, idx=page_index: self._on_nav(idx))
            btn.setMinimumHeight(36)
            btn.setProperty("page_index", page_index)
            layout.addWidget(btn)
            self.button_group.append(btn)

        self.button_group[0].setChecked(True)
        layout.addStretch()

        if self.app is not None:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    def _on_nav(self, page_index: int) -> None:
        """Handle a navigation button click."""
        self.set_active_page(page_index)
        self.nav_clicked.emit(page_index)

    def set_active_page(self, page_index: int) -> None:
        """Reflect ``page_index`` as active without emitting a signal.

        Used both by internal clicks and by ``MainWindow`` restoring the
        last-visited page on startup, where re-emitting ``nav_clicked``
        would just navigate back to the page already being shown.
        """
        if 0 <= page_index < len(self.button_group):
            for btn in self.button_group:
                btn.setChecked(False)
            self.button_group[page_index].setChecked(True)

    def _update_language(self, language: str) -> None:
        """Refresh every language-dependent string in the sidebar."""
        for i, (trans_key, _page_index) in enumerate(self.nav_items):
            label_text = translate(trans_key, language)
            icon = self.nav_icons[i]
            self.button_group[i].setText(f"{icon} {label_text}")

    def _update_theme(self, theme: str) -> None:
        """No inline styling depends on the theme — the ``#sidebar`` QSS
        rules cover the checked/hover states for both palettes. Present for
        contract symmetry with every other widget, and as the hook a future
        icon set (replacing the emoji placeholders) would use.
        """
