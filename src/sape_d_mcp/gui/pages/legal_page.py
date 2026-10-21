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

"""Legal documents page: a document list beside a rendered viewer.

Ported from f-MCP's two-pane layout, fixing its worst defect along the way —
f-MCP puts raw markdown text into a plain ``QLabel``, so every ``#``, ``*`` and
link target is shown to the reader verbatim. This page renders through
``QTextBrowser.setMarkdown()`` instead, with external links enabled, so the
licence actually reads as a formatted document.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    DARK_BORDER,
    DARK_SURFACE,
    DARK_TEXT_SECONDARY,
    LIGHT_BORDER,
    LIGHT_SURFACE,
    LIGHT_TEXT_SECONDARY,
    SAPE_PRIMARY,
)
from sape_d_mcp.legal_document_loader import LegalDocumentLoader

logger = logging.getLogger(__name__)

# (document key, translation key, description key, file name)
_DOCUMENTS: list[tuple[str, str, str, str]] = [
    ("license", "legal.license", "legal.license_desc", "LICENSE.md"),
    ("disclaimer", "legal.disclaimer", "legal.disclaimer_desc", "DISCLAIMER.md"),
    ("data-protection", "legal.data", "legal.data_desc", "DATA-PROTECTION.md"),
    ("legal-readme", "legal.legal_readme", "legal.legal_readme_desc", "LEGAL-README.md"),
]


class LegalPage(QWidget):
    """Legal document viewer with a navigable document list."""

    def __init__(self, app=None):
        super().__init__()
        self.app = app
        self.loader = LegalDocumentLoader()
        self._current_document = _DOCUMENTS[0][0]
        self._nav_buttons: dict[str, QPushButton] = {}

        layout = QVBoxLayout(self)
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

        body = QHBoxLayout()
        body.setSpacing(16)

        nav_column = QVBoxLayout()
        nav_column.setSpacing(4)
        for doc_key, _label_key, _desc_key, _filename in _DOCUMENTS:
            button = QPushButton()
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.clicked.connect(lambda checked, key=doc_key: self._on_document_selected(key))
            nav_column.addWidget(button)
            self._nav_buttons[doc_key] = button
        nav_column.addStretch()
        nav_widget = QWidget()
        nav_widget.setLayout(nav_column)
        nav_widget.setMaximumWidth(220)
        nav_widget.setMinimumWidth(180)
        body.addWidget(nav_widget)

        self.viewer = QTextBrowser()
        self.viewer.setOpenExternalLinks(True)
        body.addWidget(self.viewer, 1)

        layout.addLayout(body, 1)

        if self.app:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._nav_buttons[self._current_document].setChecked(True)
        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    def _on_document_selected(self, doc_key: str) -> None:
        self._current_document = doc_key
        for key, button in self._nav_buttons.items():
            button.setChecked(key == doc_key)
        self._load_document(self.app.current_language if self.app else "en-US")

    def _load_document(self, language: str) -> None:
        filename = next(f for k, _l, _d, f in _DOCUMENTS if k == self._current_document)
        try:
            content = self.loader.get_document(language, filename)
            self.viewer.setMarkdown(content)
        except Exception as exc:  # pragma: no cover - defensive, matches f-MCP
            logger.error("Failed to load legal document %s: %s", filename, exc)
            self.viewer.setMarkdown(translate("legal.doc_not_available_message", language))

    def _update_language(self, language: str) -> None:
        self.title.setText(translate("legal.title", language))
        self.subtitle.setText(translate("legal.subtitle", language))
        for doc_key, label_key, desc_key, _filename in _DOCUMENTS:
            button = self._nav_buttons[doc_key]
            button.setText(translate(label_key, language))
            button.setToolTip(translate(desc_key, language))
        self._load_document(language)

    def _update_theme(self, theme: str) -> None:
        is_dark = theme == "dark"
        secondary = DARK_TEXT_SECONDARY if is_dark else LIGHT_TEXT_SECONDARY
        surface = DARK_SURFACE if is_dark else LIGHT_SURFACE
        border = DARK_BORDER if is_dark else LIGHT_BORDER

        self.subtitle.setStyleSheet(f"color: {secondary.name()};")
        self.viewer.setStyleSheet(
            f"QTextBrowser {{ background-color: {surface.name()}; border: 1px solid {border.name()}; "
            f"padding: 8px; }}"
        )
        for button in self._nav_buttons.values():
            button.setStyleSheet(f"""
                QPushButton {{ text-align: left; padding: 8px 12px; border: none; border-radius: 4px; }}
                QPushButton:checked {{ background-color: {SAPE_PRIMARY.name()}; color: white; font-weight: bold; }}
            """)
