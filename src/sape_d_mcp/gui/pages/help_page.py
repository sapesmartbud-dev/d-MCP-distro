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

"""Help page: getting started, permissions guide, MCP server and FAQ."""

from __future__ import annotations

from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    DARK_TEXT_PRIMARY,
    LIGHT_TEXT_PRIMARY,
)


class HelpPage(QWidget):
    """Static help and documentation, retargeted to databases."""

    def __init__(self, app=None):
        super().__init__()
        self.app = app

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        self.title = QLabel()
        title_font = QFont()
        title_font.setPointSize(18)
        title_font.setBold(True)
        self.title.setFont(title_font)
        layout.addWidget(self.title)

        self.subtitle = QLabel()
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle_font.setItalic(True)
        self.subtitle.setFont(subtitle_font)
        layout.addWidget(self.subtitle)

        section_title_font = QFont()
        section_title_font.setPointSize(12)
        section_title_font.setBold(True)

        self.started_title = QLabel()
        self.started_title.setFont(section_title_font)
        layout.addWidget(self.started_title)
        self.started_text = QLabel()
        self.started_text.setWordWrap(True)
        layout.addWidget(self.started_text)

        self.permission_title = QLabel()
        self.permission_title.setFont(section_title_font)
        layout.addWidget(self.permission_title)
        self.permission_text = QLabel()
        self.permission_text.setWordWrap(True)
        layout.addWidget(self.permission_text)

        self.mcp_title = QLabel()
        self.mcp_title.setFont(section_title_font)
        layout.addWidget(self.mcp_title)
        self.mcp_text = QLabel()
        self.mcp_text.setWordWrap(True)
        layout.addWidget(self.mcp_text)

        self.faq_title = QLabel()
        self.faq_title.setFont(section_title_font)
        layout.addWidget(self.faq_title)
        self.faq_text = QLabel()
        self.faq_text.setWordWrap(True)
        layout.addWidget(self.faq_text)

        layout.addStretch()

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)

        if self.app:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    def _update_language(self, language: str) -> None:
        self.title.setText(translate("help.title", language))
        self.subtitle.setText(translate("help.subtitle", language))
        self.started_title.setText(translate("help.started", language))
        self.started_text.setText(translate("help.started_text", language))
        self.permission_title.setText(translate("help.permission", language))
        self.permission_text.setText(translate("help.permission_text", language))
        self.mcp_title.setText(translate("help.mcp", language))
        self.mcp_text.setText(translate("help.mcp_text", language))
        self.faq_title.setText(translate("help.faq", language))
        self.faq_text.setText(translate("help.faq_text", language))

    def _update_theme(self, theme: str) -> None:
        colour = DARK_TEXT_PRIMARY if theme == "dark" else LIGHT_TEXT_PRIMARY
        self.subtitle.setStyleSheet(f"color: {colour.name()};")
        for label in (self.started_text, self.permission_text, self.mcp_text, self.faq_text):
            label.setStyleSheet(f"line-height: 1.6; margin: 8px 0 16px 0; color: {colour.name()};")
