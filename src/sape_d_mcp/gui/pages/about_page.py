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

"""About page — branding, mission, tech stack and the GPL §5(d) notice."""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QPixmap
from PyQt6.QtWidgets import QLabel, QScrollArea, QVBoxLayout, QWidget

from sape_d_mcp._version import VERSION_DISPLAY
from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.resources import resource_path
from sape_d_mcp.gui.styles.sape_design_tokens import (
    DARK_BORDER,
    DARK_TEXT_PRIMARY,
    DARK_TEXT_SECONDARY,
    LIGHT_BORDER,
    LIGHT_TEXT_PRIMARY,
    LIGHT_TEXT_SECONDARY,
    SAPE_ACCENT,
    SAPE_PRIMARY,
    SPACING_LG,
    SPACING_MD,
)

logger = logging.getLogger(__name__)

_TECH_KEYS = ("about.tech_python", "about.tech_pyqt", "about.tech_sqlite",
              "about.tech_mcp", "about.tech_design")
_BENEFIT_KEYS = (
    ("about.benefit_security", "about.benefit_security_desc"),
    ("about.benefit_performance", "about.benefit_performance_desc"),
    ("about.benefit_auditability", "about.benefit_auditability_desc"),
)


class AboutPage(QWidget):
    """About SAPÉ d-MCP, with a theme-aware logo and the GPL §5(d) notice."""

    def __init__(self, app=None):
        super().__init__()
        self.app = app
        self._benefit_labels: list[QLabel] = []
        self._tech_labels: list[QLabel] = []

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(24, 24, 24, 24)
        outer_layout.setSpacing(SPACING_LG)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("QScrollArea { border: none; }")

        content = QWidget()
        self._layout = QVBoxLayout(content)
        self._layout.setContentsMargins(0, 0, 0, 0)
        self._layout.setSpacing(SPACING_LG)

        self.logo_label = QLabel()
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._layout.addWidget(self.logo_label)

        self.title_label = QLabel()
        title_font = QFont()
        title_font.setPointSize(24)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        self.title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.title_label.setStyleSheet(f"color: {SAPE_PRIMARY.name()};")
        self._layout.addWidget(self.title_label)

        self.tagline_label = QLabel()
        tagline_font = QFont()
        tagline_font.setPointSize(11)
        tagline_font.setItalic(True)
        self.tagline_label.setFont(tagline_font)
        self.tagline_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._layout.addWidget(self.tagline_label)

        self.version_label = QLabel(f"v{VERSION_DISPLAY}")
        self.version_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._layout.addWidget(self.version_label)

        self._layout.addSpacing(SPACING_MD)

        section_font = QFont()
        section_font.setPointSize(13)
        section_font.setBold(True)

        self.mission_title_label = QLabel()
        self.mission_title_label.setFont(section_font)
        self.mission_title_label.setStyleSheet(f"color: {SAPE_PRIMARY.name()};")
        self._layout.addWidget(self.mission_title_label)
        self.mission_desc_label = QLabel()
        self.mission_desc_label.setWordWrap(True)
        self._layout.addWidget(self.mission_desc_label)

        self._layout.addSpacing(SPACING_MD)

        self.why_title_label = QLabel()
        self.why_title_label.setFont(section_font)
        self.why_title_label.setStyleSheet(f"color: {SAPE_PRIMARY.name()};")
        self._layout.addWidget(self.why_title_label)
        self.why_desc_label = QLabel()
        self.why_desc_label.setWordWrap(True)
        self._layout.addWidget(self.why_desc_label)

        self._benefits_container = QVBoxLayout()
        self._layout.addLayout(self._benefits_container)

        self._layout.addSpacing(SPACING_MD)

        self.tech_title_label = QLabel()
        self.tech_title_label.setFont(section_font)
        self.tech_title_label.setStyleSheet(f"color: {SAPE_PRIMARY.name()};")
        self._layout.addWidget(self.tech_title_label)

        self._tech_container = QVBoxLayout()
        self._layout.addLayout(self._tech_container)

        self._layout.addSpacing(SPACING_MD)

        self.separator1 = QLabel()
        self.separator1.setFixedHeight(1)
        self._layout.addWidget(self.separator1)

        self.author_label = QLabel()
        author_font = QFont()
        author_font.setPointSize(10)
        author_font.setBold(True)
        self.author_label.setFont(author_font)
        self.author_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.author_label.setStyleSheet(f"color: {SAPE_PRIMARY.name()};")
        self._layout.addWidget(self.author_label)

        self.email_label = QLabel("info@sapebud.com")
        self.email_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._layout.addWidget(self.email_label)

        # Carries the copyright line and the GPL-3.0 §5(d) notice, so it must
        # wrap rather than widen the layout.
        self.copyright_label = QLabel()
        copyright_font = QFont()
        copyright_font.setPointSize(8)
        self.copyright_label.setFont(copyright_font)
        self.copyright_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.copyright_label.setWordWrap(True)
        self._layout.addWidget(self.copyright_label)

        self.separator2 = QLabel()
        self.separator2.setFixedHeight(1)
        self._layout.addWidget(self.separator2)

        self.sapebud_link = QLabel()
        self.sapebud_link.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.sapebud_link.setOpenExternalLinks(True)
        self.sapebud_link.setCursor(Qt.CursorShape.PointingHandCursor)
        self._layout.addWidget(self.sapebud_link)

        self._layout.addStretch()

        scroll.setWidget(content)
        outer_layout.addWidget(scroll)

        if self.app:
            self.app.theme_manager.theme_changed.connect(self._on_theme_changed)
            self.app.language_changed.connect(self._update_language)

        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    def _load_icon(self, theme: str) -> None:
        icon_filename = "trans-256.png" if theme == "light" else "dark-256.png"
        try:
            icon_path = resource_path("icons", icon_filename)
            pixmap = QPixmap(str(icon_path))
            self.logo_label.setPixmap(
                pixmap.scaledToWidth(128, Qt.TransformationMode.SmoothTransformation))
        except FileNotFoundError as exc:  # pragma: no cover - gui_resources ships this
            logger.warning("Could not load About page icon: %s", exc)
            self.logo_label.setText("SAPÉ")
            font = QFont()
            font.setPointSize(48)
            font.setBold(True)
            self.logo_label.setFont(font)

    def _on_theme_changed(self, theme: str) -> None:
        self._update_theme(theme)

    def _update_language(self, language: str) -> None:
        self.title_label.setText(translate("about.title", language))
        self.tagline_label.setText(translate("about.tagline", language))
        self.mission_title_label.setText(translate("about.mission_title", language))
        self.mission_desc_label.setText(translate("about.mission_desc", language))
        self.why_title_label.setText(translate("about.why_title", language))
        self.why_desc_label.setText(translate("about.why_desc", language))
        self.tech_title_label.setText(translate("about.tech_title", language))
        self.author_label.setText(translate("about.author", language))
        self.copyright_label.setText(translate("about.copyright", language))

        link_text = translate("about.sapebud_link", language)
        self.sapebud_link.setText(f'<a href="https://sapebud.com">{link_text}</a>')
        self.sapebud_link.setToolTip(translate("about.sapebud_link_tooltip", language))

        while self._benefits_container.count():
            item = self._benefits_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._benefit_labels = []
        for title_key, desc_key in _BENEFIT_KEYS:
            title_text = translate(title_key, language)
            desc_text = translate(desc_key, language)
            label = QLabel(f"• {title_text}: {desc_text}")
            label.setWordWrap(True)
            self._benefits_container.addWidget(label)
            self._benefit_labels.append(label)

        while self._tech_container.count():
            item = self._tech_container.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._tech_labels = []
        for tech_key in _TECH_KEYS:
            label = QLabel(f"• {translate(tech_key, language)}")
            label.setWordWrap(True)
            self._tech_container.addWidget(label)
            self._tech_labels.append(label)

        self._update_theme(self.app.current_theme if self.app else "light")

    def _update_theme(self, theme: str) -> None:
        self._load_icon(theme)
        is_dark = theme == "dark"
        text_colour = DARK_TEXT_PRIMARY if is_dark else LIGHT_TEXT_PRIMARY
        secondary_colour = DARK_TEXT_SECONDARY if is_dark else LIGHT_TEXT_SECONDARY
        border_colour = DARK_BORDER if is_dark else LIGHT_BORDER
        link_colour = SAPE_ACCENT if is_dark else SAPE_PRIMARY

        self.tagline_label.setStyleSheet(f"color: {text_colour.name()};")
        self.mission_desc_label.setStyleSheet(f"color: {text_colour.name()}; line-height: 1.6;")
        self.why_desc_label.setStyleSheet(f"color: {text_colour.name()}; line-height: 1.6;")
        self.version_label.setStyleSheet(f"color: {secondary_colour.name()};")
        self.email_label.setStyleSheet(f"color: {secondary_colour.name()};")
        self.copyright_label.setStyleSheet(f"color: {secondary_colour.name()};")
        self.sapebud_link.setStyleSheet(f"color: {link_colour.name()};")
        self.separator1.setStyleSheet(f"border-top: 1px solid {border_colour.name()};")
        self.separator2.setStyleSheet(f"border-top: 1px solid {border_colour.name()};")
        for label in self._benefit_labels + self._tech_labels:
            label.setStyleSheet(f"color: {text_colour.name()}; line-height: 1.6;")
