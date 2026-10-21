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

"""Settings page.

Mirrors f-MCP's section layout (MCP client configuration, Appearance, Server,
Data, About) with one addition: a "Mockup" group exposing the
``show_sample_data`` toggle so a reviewer can flip between the populated and
the honest first-run view without editing ``config.json`` by hand.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QCheckBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPlainTextEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp._version import VERSION_DISPLAY
from sape_d_mcp.config_json_generator import ConfigJSONGenerator
from sape_d_mcp.db.connection_store import default_db_path as connections_db_path
from sape_d_mcp.gui.dialogs.mcp_config_dialog import AppAsServer, MCPConfigDialog
from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    DARK_BORDER,
    DARK_SURFACE,
    DARK_TEXT_SECONDARY,
    FONT_MONO,
    LIGHT_BORDER,
    LIGHT_SURFACE,
    LIGHT_TEXT_SECONDARY,
)
from sape_d_mcp.log_store import default_db_path as audit_db_path
from sape_d_mcp.permissions import default_db_path as permissions_db_path

#: How long the "Copied!" feedback stays on the button before reverting —
#: matches the same constant in mcp_config_dialog.py, the dialog this page's
#: own Copy button offers a shortcut around.
_COPY_FEEDBACK_MS = 2000

logger = logging.getLogger(__name__)


class SettingsPage(QWidget):
    """Application settings."""

    def __init__(self, app=None):
        super().__init__()
        self.app = app
        self.config_json_str: str | None = None
        self.config_error: str | None = None
        self._copy_button_label = ""

        outer_layout = QVBoxLayout(self)
        outer_layout.setContentsMargins(0, 0, 0, 0)

        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setStyleSheet("QScrollArea { border: none; }")

        scroll_widget = QWidget()
        layout = QVBoxLayout(scroll_widget)
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

        # ===== MCP client configuration =====
        self.config_group = QGroupBox()
        config_layout = QVBoxLayout()

        self.config_desc = QLabel()
        self.config_desc.setWordWrap(True)
        config_layout.addWidget(self.config_desc)

        self.setup_button = QPushButton()
        self.setup_button.clicked.connect(self._on_setup_clicked)
        setup_row = QHBoxLayout()
        setup_row.addWidget(self.setup_button)
        setup_row.addStretch()
        config_layout.addLayout(setup_row)

        self.config_text = QPlainTextEdit()
        self.config_text.setReadOnly(True)
        self.config_text.setMinimumHeight(160)
        config_layout.addWidget(self.config_text)

        copy_row = QHBoxLayout()
        self.copy_button = QPushButton()
        self.copy_button.clicked.connect(self._on_copy_clicked)
        copy_row.addWidget(self.copy_button)
        copy_row.addStretch()
        config_layout.addLayout(copy_row)

        self.config_group.setLayout(config_layout)
        layout.addWidget(self.config_group)

        # ===== Appearance =====
        self.appearance_group = QGroupBox()
        appearance_layout = QVBoxLayout()

        self.theme_desc = QLabel()
        appearance_layout.addWidget(self.theme_desc)

        theme_row = QHBoxLayout()
        self.light_button = QPushButton()
        self.light_button.clicked.connect(self._on_theme_light)
        theme_row.addWidget(self.light_button)
        self.dark_button = QPushButton()
        self.dark_button.clicked.connect(self._on_theme_dark)
        theme_row.addWidget(self.dark_button)
        theme_row.addStretch()
        appearance_layout.addLayout(theme_row)

        self.appearance_group.setLayout(appearance_layout)
        layout.addWidget(self.appearance_group)

        # ===== Server =====
        self.server_group = QGroupBox()
        server_layout = QVBoxLayout()
        self.server_desc = QLabel()
        self.server_desc.setWordWrap(True)
        server_layout.addWidget(self.server_desc)
        self.server_group.setLayout(server_layout)
        layout.addWidget(self.server_group)

        # ===== Data =====
        self.data_group = QGroupBox()
        data_layout = QVBoxLayout()
        self.connections_db_label = QLabel()
        self.permissions_db_label = QLabel()
        self.audit_db_label = QLabel()
        self.config_json_label = QLabel()
        for label in (self.connections_db_label, self.permissions_db_label,
                      self.audit_db_label, self.config_json_label):
            label.setWordWrap(True)
            data_layout.addWidget(label)
        self.data_group.setLayout(data_layout)
        layout.addWidget(self.data_group)

        # ===== Mockup (development aid, not part of the shipped product) =====
        self.mockup_group = QGroupBox()
        mockup_layout = QVBoxLayout()
        self.show_sample_data_checkbox = QCheckBox()
        self.show_sample_data_checkbox.toggled.connect(self._on_show_sample_data_toggled)
        mockup_layout.addWidget(self.show_sample_data_checkbox)
        self.show_sample_data_desc = QLabel()
        self.show_sample_data_desc.setWordWrap(True)
        mockup_layout.addWidget(self.show_sample_data_desc)
        self.mockup_group.setLayout(mockup_layout)
        layout.addWidget(self.mockup_group)

        # ===== About =====
        self.about_group = QGroupBox()
        about_layout = QVBoxLayout()
        self.about_text_label = QLabel()
        self.about_text_label.setWordWrap(True)
        about_layout.addWidget(self.about_text_label)
        self.about_group.setLayout(about_layout)
        layout.addWidget(self.about_group)

        layout.addStretch()

        scroll_area.setWidget(scroll_widget)
        outer_layout.addWidget(scroll_area)

        # Parented to this page, per the project's "parent every QTimer" rule
        # (f-MCP defect 9) — an unparented one is garbage-collected before it
        # ever fires, leaving the copy button stuck reading "Copied!" forever
        # instead of reverting after two seconds.
        self._copy_reset_timer = QTimer(self)
        self._copy_reset_timer.setSingleShot(True)
        self._copy_reset_timer.timeout.connect(self._reset_copy_button)

        if self.app:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        # Generated once, at construction, exactly like MCPConfigDialog's own
        # _perform_setup — so the inline preview and the Copy button reflect
        # reality from the first paint rather than the permanent
        # "unavailable" placeholder that stood in before this page's own
        # config generation was wired up.
        self._generate_config_json()
        self._sync_sample_data_checkbox()
        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    # -- data ---------------------------------------------------------------

    def _config_manager(self):
        return getattr(self.app, "config_manager", None) if self.app else None

    def _generate_config_json(self) -> None:
        """Generate the MCP client configuration once, so the Copy button can
        act as a shortcut around opening the full :class:`MCPConfigDialog`
        wizard just for the JSON this page already needs for its own
        read-only preview."""
        try:
            source = ConfigJSONGenerator(AppAsServer(self.app) if self.app is not None else None)
            self.config_json_str = source.to_client_config_string()
            self.config_error = None
        except Exception as exc:
            logger.error("Could not generate the MCP client configuration: %s", exc)
            self.config_json_str = None
            self.config_error = str(exc)

    def _sync_sample_data_checkbox(self) -> None:
        config_manager = self._config_manager()
        show_sample_data = False
        if config_manager is not None:
            try:
                show_sample_data = bool(config_manager.get_show_sample_data())
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not read show_sample_data: %s", exc)
        self.show_sample_data_checkbox.blockSignals(True)
        self.show_sample_data_checkbox.setChecked(show_sample_data)
        self.show_sample_data_checkbox.blockSignals(False)

    def _on_show_sample_data_toggled(self, checked: bool) -> None:
        config_manager = self._config_manager()
        if config_manager is None:
            return
        try:
            config_manager.set_show_sample_data(checked)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Could not save show_sample_data: %s", exc)

    def _config_file_path(self) -> str:
        config_manager = self._config_manager()
        if config_manager is not None and getattr(config_manager, "config_file", None):
            return str(config_manager.config_file)
        return "~/.sape/d-mcp/config.json"

    # -- actions --------------------------------------------------------

    def _on_theme_light(self) -> None:
        if self.app:
            self.app.theme_manager.set_theme("light")

    def _on_theme_dark(self) -> None:
        if self.app:
            self.app.theme_manager.set_theme("dark")

    def _on_setup_clicked(self) -> None:
        """Open the full MCP client configuration wizard.

        This page's own preview only ever shows the generated JSON; the
        wizard additionally detects the installation, shows setup
        instructions and offers a Test button — reasons enough to keep it as
        a separate dialog rather than duplicating all of it here.
        """
        dialog = MCPConfigDialog(self, self.app)
        dialog.exec()
        # The wizard may be the first thing this session to touch a
        # lazily-opened store (see AppAsServer's docstring); regenerate so
        # the inline preview reflects the same outcome rather than whatever
        # was cached from before the dialog ran.
        self._generate_config_json()
        self._update_config_display(self.app.current_language if self.app else "en-US")

    def _on_copy_clicked(self) -> None:
        """Copy the client configuration straight to the clipboard.

        The shortcut this module's docstring promises around opening
        :class:`MCPConfigDialog` merely to reach its own Copy button.
        """
        language = self.app.current_language if self.app else "en-US"
        if self.config_json_str is None:
            self._generate_config_json()
            self._update_config_display(language)
        if not self.config_json_str:
            return

        clipboard = QGuiApplication.clipboard()
        clipboard.setText(self.config_json_str)

        self.copy_button.setText(f"✓ {translate('settings.copy_success', language)}")
        self.copy_button.setEnabled(False)
        self._copy_reset_timer.start(_COPY_FEEDBACK_MS)

        logger.info("MCP configuration copied to clipboard")

    def _reset_copy_button(self) -> None:
        self.copy_button.setText(self._copy_button_label)
        self.copy_button.setEnabled(bool(self.config_json_str))

    def _update_config_display(self, language: str) -> None:
        if self.config_json_str:
            self.config_text.setPlainText(self.config_json_str)
            self.copy_button.setEnabled(True)
        else:
            message = translate("settings.config_unavailable", language)
            if self.config_error:
                message = f"{message}\n\n{self.config_error}"
            self.config_text.setPlainText(message)
            self.copy_button.setEnabled(False)

    # -- i18n / theming ----------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.title.setText(translate("settings.title", language))
        self.subtitle.setText(translate("settings.subtitle", language))

        self.config_group.setTitle(translate("settings.config_group", language))
        self.config_desc.setText(translate("settings.config_desc", language))
        self.setup_button.setText(translate("settings.setup_mcp_button", language))
        self.setup_button.setToolTip(translate("settings.setup_mcp_button_tooltip", language))
        self._copy_button_label = translate("settings.copy_button", language)
        self.copy_button.setText(self._copy_button_label)
        self.copy_button.setToolTip(translate("settings.copy_button_tooltip", language))
        self._update_config_display(language)

        self.appearance_group.setTitle(translate("settings.appearance_group", language))
        self.theme_desc.setText(translate("settings.theme_desc", language))
        self.light_button.setText(translate("settings.light_theme", language))
        self.dark_button.setText(translate("settings.dark_theme", language))

        self.server_group.setTitle(translate("settings.server_group", language))
        self.server_desc.setText(translate("settings.server_desc", language))

        self.data_group.setTitle(translate("settings.data_group", language))
        connections_prefix = translate("settings.data_connections_label", language)
        permissions_prefix = translate("settings.data_permissions_label", language)
        audit_prefix = translate("settings.data_audit_label", language)
        config_prefix = translate("settings.data_config_label", language)
        # Each store's own default_db_path() is called rather than joining one
        # directory to three filenames: DMCP_CONNECTIONS_DB, DMCP_PERMISSIONS_DB
        # and DMCP_AUDIT_DB can each point somewhere different, and this page
        # used to show a single guessed directory (RESOURCES_DIR.parent) that
        # was simply wrong once the process was not launched from its own
        # resource root — see sape_d_mcp.db_location for the defect and the fix.
        self.connections_db_label.setText(f"{connections_prefix} {connections_db_path()}")
        self.permissions_db_label.setText(f"{permissions_prefix} {permissions_db_path()}")
        self.audit_db_label.setText(f"{audit_prefix} {audit_db_path()}")
        self.config_json_label.setText(f"{config_prefix} {self._config_file_path()}")

        self.mockup_group.setTitle(translate("settings.mockup_group", language))
        self.show_sample_data_checkbox.setText(translate("settings.show_sample_data_label", language))
        self.show_sample_data_desc.setText(translate("settings.show_sample_data_desc", language))

        self.about_group.setTitle(translate("settings.about_group", language))
        self.about_text_label.setText(f"{translate('settings.about_text', language)} — v{VERSION_DISPLAY}")

    def _update_theme(self, theme: str) -> None:
        is_dark = theme == "dark"
        secondary = DARK_TEXT_SECONDARY if is_dark else LIGHT_TEXT_SECONDARY
        surface = DARK_SURFACE if is_dark else LIGHT_SURFACE
        border = DARK_BORDER if is_dark else LIGHT_BORDER

        self.subtitle.setStyleSheet(f"color: {secondary.name()};")
        for label in (self.connections_db_label, self.permissions_db_label,
                      self.audit_db_label, self.config_json_label):
            label.setStyleSheet(f"font-family: '{FONT_MONO}'; font-size: 9pt; color: {secondary.name()};")
        self.show_sample_data_desc.setStyleSheet(f"color: {secondary.name()};")
        self.config_text.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {surface.name()}; color: {secondary.name()}; "
            f"border: 1px solid {border.name()}; font-family: '{FONT_MONO}'; }}"
        )
