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

"""Header component: logo, translated application title, theme toggle and
language selector.

f-MCP hardcodes the title label to the literal ``"f-MCP"`` and never routes
it through ``translate()`` — the one string in its header that eighteen
locales never actually reach. d-MCP fills it from ``header.product_name``
instead, and drives the theme toggle straight off ``app.theme_manager``
rather than round-tripping through :class:`MainWindow` signals that only
existed to relay a call the widget could make itself.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QSize, Qt
from PyQt6.QtGui import QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QComboBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QSpacerItem,
    QWidget,
)

from sape_d_mcp._version import VERSION_DISPLAY
from sape_d_mcp.language_registry import LanguageRegistry

from ..i18n import translate
from ..resources import resource_path
from ..styles.sape_design_tokens import (
    DARK_TEXT_PRIMARY,
    FONT_FAMILY,
    LIGHT_TEXT_PRIMARY,
    SPACING_LG,
    SPACING_MD,
    SPACING_XL,
)

logger = logging.getLogger(__name__)


class Header(QWidget):
    """Application header: logo, title, theme toggle and language selector."""

    def __init__(self, app=None) -> None:
        super().__init__()
        self.app = app
        self.setObjectName("header")

        # Loaded once, reused for all 18 locales rather than re-hit on every
        # combo repaint.
        self._flag_icon_cache: dict[str, QIcon | None] = {}

        layout = QHBoxLayout(self)
        layout.setContentsMargins(SPACING_LG, SPACING_MD, SPACING_LG, SPACING_MD)
        layout.setSpacing(SPACING_MD)

        # Logo: native aspect ratio 3660x920 = 3.978:1, height fixed at 75px.
        self.logo_label = QLabel()
        self.logo_label.setMaximumWidth(300)
        self.logo_label.setMaximumHeight(75)
        self.logo_label.setMinimumHeight(75)
        self.logo_label.setScaledContents(False)
        layout.addWidget(self.logo_label)

        # Application title, built empty — filled by _update_language.
        self.title_label = QLabel()
        title_font = QFont(FONT_FAMILY)
        title_font.setPointSize(22)
        title_font.setWeight(QFont.Weight.Normal)
        self.title_label.setFont(title_font)
        self.title_label.setStyleSheet("padding-top: 5px;")
        layout.addWidget(self.title_label)

        layout.addSpacing(SPACING_XL)
        layout.addItem(QSpacerItem(40, 20, QSizePolicy.Policy.Expanding))

        # Theme toggle.
        self.theme_btn = QPushButton()
        self.theme_btn.setMaximumWidth(40)
        self.theme_btn.setMaximumHeight(40)
        self.theme_btn.setMinimumHeight(32)
        self.theme_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.theme_btn.clicked.connect(self._on_theme_toggle_clicked)
        layout.addWidget(self.theme_btn)

        # Language selector — all 18 locales, sorted by native name, each
        # carrying a flag icon. Built from LanguageRegistry.LANGUAGES, never
        # from a translation key: f-MCP's get_supported_languages() derives
        # its list from TRANSLATIONS["header.logo"] and silently excludes
        # en-US, which is exactly the bug this sidesteps.
        self.language_combo = QComboBox()
        self.language_combo.setMaximumWidth(630)
        self.language_combo.setMinimumHeight(32)
        self.language_combo.setCursor(Qt.CursorShape.PointingHandCursor)
        self.language_combo.setMaxVisibleItems(10)
        self.language_combo.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToContents
        )
        self._populate_language_combo()
        # activated (not currentIndexChanged) avoids a spurious emit when we
        # set the index programmatically below.
        self.language_combo.activated.connect(self._on_language_selected)
        layout.addWidget(self.language_combo)

        if self.app is not None:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    def _populate_language_combo(self) -> None:
        """Fill the combo with every registered language, native name first."""
        languages_sorted = sorted(
            LanguageRegistry.LANGUAGES.items(), key=lambda item: item[1]["native"]
        )
        for lang_code, meta in languages_sorted:
            self.language_combo.addItem(meta["native"], lang_code)
            index = self.language_combo.count() - 1
            flag_icon = self._flag_icon(lang_code, meta.get("flag_file"))
            if flag_icon is not None:
                self.language_combo.setItemIcon(index, flag_icon)

    def _flag_icon(self, lang_code: str, flag_file: str | None) -> QIcon | None:
        """Return the cached flag icon for ``lang_code``, loading it once.

        ``resource_path`` raises ``FileNotFoundError`` rather than returning
        a dangling path, so a single missing flag is caught here and turns
        into "no icon for this one language" instead of an exception that
        would take the whole header down with it.
        """
        if lang_code in self._flag_icon_cache:
            return self._flag_icon_cache[lang_code]

        icon: QIcon | None = None
        if flag_file:
            try:
                flag_path = resource_path("flags", flag_file)
            except FileNotFoundError:
                logger.debug("Flag file not found for %s: %s", lang_code, flag_file)
            else:
                candidate = QIcon(str(flag_path))
                if not candidate.isNull():
                    icon = candidate
                else:
                    logger.warning("Failed to load flag icon: %s", flag_path)

        # Cache the miss too, so a missing flag is not retried on every open.
        self._flag_icon_cache[lang_code] = icon
        return icon

    def _load_logo(self, theme: str) -> None:
        """Load the theme-matched logo PNG into the header, falling back to
        a text label if the asset is missing rather than raising."""
        logo_filename = (
            "sape-logo-h-dark.png" if theme == "dark" else "sape-logo-h-light.png"
        )
        try:
            logo_path = resource_path("logos", logo_filename)
        except FileNotFoundError:
            logger.error("Logo file not found: %s", logo_filename)
            self.logo_label.setText("SAPÉ")
            return

        logo_pixmap = QPixmap(str(logo_path))
        if logo_pixmap.isNull():
            logger.error("Failed to load pixmap: %s", logo_path)
            self.logo_label.setText("SAPÉ")
            return
        self.logo_label.setPixmap(logo_pixmap)

    def _load_theme_icon(self, theme: str) -> None:
        """Load the toggle icon: sun in dark mode (click for light), moon
        in light mode (click for dark). Falls back to a text glyph if the
        SVG is missing rather than raising."""
        icon_filename = "sun.svg" if theme == "dark" else "moon.svg"
        try:
            icon_path = resource_path("icons", icon_filename)
        except FileNotFoundError:
            logger.error("Icon file not found: %s", icon_filename)
            self.theme_btn.setText("?" if theme == "dark" else "!")
            return

        icon = QIcon(str(icon_path))
        if icon.isNull():
            logger.error("Failed to load icon: %s", icon_path)
            self.theme_btn.setText("?" if theme == "dark" else "!")
            return
        self.theme_btn.setIcon(icon)
        self.theme_btn.setIconSize(QSize(32, 32))
        self.theme_btn.setText("")

    def _on_theme_toggle_clicked(self) -> None:
        if self.app is not None:
            self.app.theme_manager.toggle_theme()

    def _on_language_selected(self, index: int) -> None:
        language_code = self.language_combo.itemData(index)
        if self.app is not None and language_code:
            self.app.set_language(language_code)

    def _update_language(self, language: str) -> None:
        """Refresh every language-dependent string in the header."""
        product_name = translate("header.product_name", language)
        # VERSION_DISPLAY is composed once in _version.py (version + release
        # stage, e.g. "0.1.0.8 Beta") so dropping the "Beta" word on release
        # day is a single-line change there rather than a hunt through every
        # surface that shows it — this being one of the three, see
        # about_page.py and settings_page.py for the other two.
        self.title_label.setText(f"{product_name} v{VERSION_DISPLAY}")
        self.theme_btn.setToolTip(translate("header.theme_toggle", language))
        self.language_combo.setToolTip(translate("header.language_selector", language))

        index = self.language_combo.findData(language)
        if index >= 0:
            self.language_combo.blockSignals(True)
            self.language_combo.setCurrentIndex(index)
            self.language_combo.blockSignals(False)

    def _update_theme(self, theme: str) -> None:
        """Refresh every theme-dependent visual in the header."""
        self._load_logo(theme)
        self._load_theme_icon(theme)
        text_colour = DARK_TEXT_PRIMARY if theme == "dark" else LIGHT_TEXT_PRIMARY
        self.title_label.setStyleSheet(f"color: {text_colour.name()}; padding-top: 5px;")
