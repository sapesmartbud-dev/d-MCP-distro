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

"""Status bar: server running indicator, port info, and start/stop controls.

Named ``StatusBarWidget`` rather than ``StatusBar`` for the attribute
``MainWindow`` holds it under (``status_bar_widget``), not the class itself
— the class name collision with ``QMainWindow.statusBar()`` that the skill
warns about is avoided simply by d-MCP's ``MainWindow`` never being a
``QMainWindow`` in the first place, but the widget still gets an unambiguous
name of its own.

f-MCP hardcodes the port label to ``color: #2D3139`` regardless of theme —
that is ``DARK_BORDER``, so in dark mode the port number is nearly invisible
against the status bar background. d-MCP drives that colour from
``_update_theme`` instead.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QWidget,
)

from ..i18n import translate
from ..styles.sape_design_tokens import (
    DARK_TEXT_SECONDARY,
    LIGHT_TEXT_SECONDARY,
    SPACING_LG,
    SPACING_MD,
)

DEFAULT_PORT = 8089


class StatusBarWidget(QWidget):
    """Status bar showing MCP server status and start/stop controls."""

    start_clicked = pyqtSignal()
    stop_clicked = pyqtSignal()

    def __init__(self, app=None) -> None:
        super().__init__()
        self.app = app
        self.setObjectName("statusBar")

        self.is_running = False
        self._port: int | None = None
        self._default_port = DEFAULT_PORT

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACING_LG, SPACING_MD, SPACING_LG, SPACING_MD)
        layout.setSpacing(SPACING_MD)

        self.status_dot = QLabel("⭕")
        self.status_dot.setStyleSheet("font-size: 14px;")
        layout.addWidget(self.status_dot)

        self.status_label = QLabel()
        status_font = QFont()
        status_font.setPointSize(10)
        status_font.setBold(True)
        self.status_label.setFont(status_font)
        layout.addWidget(self.status_label)

        self.port_label = QLabel("")
        port_font = QFont()
        port_font.setPointSize(9)
        self.port_label.setFont(port_font)
        layout.addWidget(self.port_label)

        layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding))

        self.start_btn = QPushButton()
        self.start_btn.setMinimumHeight(32)
        self.start_btn.setMaximumWidth(110)
        self.start_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.start_btn.clicked.connect(self.start_clicked.emit)
        layout.addWidget(self.start_btn)

        self.stop_btn = QPushButton()
        self.stop_btn.setMinimumHeight(32)
        self.stop_btn.setMaximumWidth(110)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.stop_btn.clicked.connect(self.stop_clicked.emit)
        layout.addWidget(self.stop_btn)

        if self.app is not None:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    def set_running(self, is_running: bool) -> None:
        """Reflect the server's running state in the indicator and buttons."""
        self.is_running = is_running
        language = self.app.current_language if self.app else "en-US"

        if is_running:
            self.status_dot.setText("🟢")
            self.status_label.setText(f"✓ {translate('status_bar.service_running', language)}")
            self.start_btn.setEnabled(False)
            self.stop_btn.setEnabled(True)
            if self._port is not None:
                self._render_port_label(language)
        else:
            self.status_dot.setText("⭕")
            self.status_label.setText(f"○ {translate('status_bar.service_stopped', language)}")
            self.port_label.setText("")
            self.start_btn.setEnabled(True)
            self.stop_btn.setEnabled(False)

    def set_port_info(self, port: int | None, default_port: int = DEFAULT_PORT) -> None:
        """Show which port the server actually bound to.

        ``default_port`` is kept alongside the actual ``port`` (rather than
        the widget only ever knowing the latter) because the server probes
        8089-8098 by attempting ``socket.bind()`` and moves on when a port is
        already taken — a future revision surfacing *that* distinction in
        the label still only needs to change this widget, not every caller.
        """
        self._port = port
        self._default_port = default_port
        language = self.app.current_language if self.app else "en-US"
        self._render_port_label(language)

    def _render_port_label(self, language: str) -> None:
        if self._port is None:
            self.port_label.setText(translate("status_bar.port_info_alt", language))
        else:
            self.port_label.setText(translate("status_bar.port_info", language).format(port=self._port))

    def _update_language(self, language: str) -> None:
        """Refresh every language-dependent string in the status bar."""
        self.start_btn.setText(f"▶ {translate('status_bar.start_button', language)}")
        self.stop_btn.setText(f"■ {translate('status_bar.stop_button', language)}")

        if self.is_running:
            self.status_label.setText(f"✓ {translate('status_bar.service_running', language)}")
        else:
            self.status_label.setText(f"○ {translate('status_bar.service_stopped', language)}")

        if self._port is not None:
            self._render_port_label(language)

    def _update_theme(self, theme: str) -> None:
        """Recolour the port label, the one hand-styled label in the bar."""
        colour = DARK_TEXT_SECONDARY if theme == "dark" else LIGHT_TEXT_SECONDARY
        self.port_label.setStyleSheet(f"color: {colour.name()};")
