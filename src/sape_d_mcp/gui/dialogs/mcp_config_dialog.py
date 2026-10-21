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

"""MCP client configuration wizard.

Detects how this copy of SAPÉ d-MCP was started, generates the ``mcpServers``
snippet for the three databases this GUI process is actually using, and lets
a human copy it to the clipboard. Ported from SAPÉ f-MCP's
``dialogs/mcp_config_dialog.py`` with two changes the stage-9 brief asks for
rather than a straight carry-over:

1. **Translated throughout.** f-MCP defect 7 leaves this whole dialog as bare
   English literals no ``translate()`` call ever reaches. Every string here
   goes through ``translate(key, language)``; the widgets are built empty and
   refilled by :meth:`MCPConfigDialog._update_language`, exactly like every
   other page and dialog in this project.
2. **Never a second config writer.** ``MCPConfigGenerator`` already never
   writes the client's own configuration file (see its module docstring);
   this dialog repeats that constraint at the GUI layer rather than merely
   inheriting it — there is no "Save" button, and the JSON on screen only
   ever leaves this window through the clipboard, for the human to merge by
   hand, per :meth:`MCPConfigGenerator.generate_instructions`.
"""

from __future__ import annotations

import logging
import subprocess

from PyQt6.QtCore import QTimer
from PyQt6.QtGui import QFont, QGuiApplication
from PyQt6.QtWidgets import (
    QDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QVBoxLayout,
)

from sape_d_mcp.config_json_generator import ConfigJSONGenerator
from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    COLOR_ERROR,
    COLOR_SUCCESS,
    DARK_BORDER,
    DARK_SURFACE,
    DARK_TEXT_SECONDARY,
    FONT_MONO,
    LIGHT_BORDER,
    LIGHT_SURFACE,
    LIGHT_TEXT_SECONDARY,
)
from sape_d_mcp.mcp_config_generator import InstallationInfo, MCPConfigGenerator

logger = logging.getLogger(__name__)

#: How long the "Copied!" feedback stays on the button before reverting.
_COPY_FEEDBACK_MS = 2000


class AppAsServer:
    """Present ``SAPEApplication``'s lazily-opened stores under the
    attribute names :class:`~sape_d_mcp.config_json_generator.
    ConfigJSONGenerator` expects from a ``DatabaseMCPServer`` duck-type
    (``.connections``, ``.permissions``, ``.log_store``).

    The GUI's application object never runs a server itself — that is
    ``server_thread.py``'s own ``DatabaseMCPServer``, built on its own thread
    and started independently of whether this dialog is even open — so there
    is no live server object to hand ``ConfigJSONGenerator`` here. What the
    wizard actually needs is which three database files *this* GUI process is
    using, and ``app.connection_store``, ``app.permission_store`` and
    ``app.log_store`` already open exactly those on first access; this
    adapter only renames them to the attributes the generator reads, so a
    client-spawned subprocess is told the databases this window is actually
    enforcing rather than left to resolve its own defaults, which need not
    agree with them (see ``mcp_config_generator.py``'s own docstring on
    ``generate_config`` for why that gap matters).
    """

    def __init__(self, app) -> None:
        self.connections = app.connection_store
        self.permissions = app.permission_store
        self.log_store = app.log_store


class MCPConfigDialog(QDialog):
    """Detect the installation, generate the client configuration, and let
    the user copy it. Nothing here ever opens the client's own file."""

    def __init__(self, parent=None, app=None) -> None:
        super().__init__(parent)
        self.setObjectName("mcpConfigDialog")
        self.app = app
        self.language = app.current_language if app is not None else "en-US"
        theme = app.current_theme if app is not None else "light"

        self.generator = MCPConfigGenerator()
        self.installation: InstallationInfo | None = None
        self.config_json_str: str | None = None
        self.setup_error: str | None = None
        self._copy_button_label = ""

        self.setMinimumWidth(700)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(16)

        self.title_label = QLabel()
        self.title_label.setObjectName("mcpConfigTitle")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        self.title_label.setFont(title_font)
        layout.addWidget(self.title_label)

        # ----- installation detection -----
        self.status_group = QGroupBox()
        status_layout = QVBoxLayout()
        self.status_label = QLabel()
        self.status_label.setWordWrap(True)
        status_layout.addWidget(self.status_label)
        self.status_group.setLayout(status_layout)
        layout.addWidget(self.status_group)

        # ----- setup instructions -----
        self.instructions_group = QGroupBox()
        instructions_layout = QVBoxLayout()
        self.instructions_text = QPlainTextEdit()
        self.instructions_text.setReadOnly(True)
        self.instructions_text.setMaximumHeight(120)
        instructions_layout.addWidget(self.instructions_text)
        self.instructions_group.setLayout(instructions_layout)
        layout.addWidget(self.instructions_group)

        # ----- configuration JSON -----
        self.config_group = QGroupBox()
        config_layout = QVBoxLayout()

        self.config_desc_label = QLabel()
        self.config_desc_label.setWordWrap(True)
        config_layout.addWidget(self.config_desc_label)

        self.config_display = QPlainTextEdit()
        self.config_display.setReadOnly(True)
        self.config_display.setMinimumHeight(200)
        config_layout.addWidget(self.config_display, 1)

        copy_row = QHBoxLayout()
        self.copy_button = QPushButton()
        self.copy_button.setMaximumWidth(260)
        self.copy_button.clicked.connect(self._on_copy_clicked)
        copy_row.addWidget(self.copy_button)
        copy_row.addStretch()
        config_layout.addLayout(copy_row)

        self.config_group.setLayout(config_layout)
        layout.addWidget(self.config_group, 1)

        # ----- buttons -----
        button_row = QHBoxLayout()
        button_row.addStretch()
        self.test_button = QPushButton()
        self.test_button.setMaximumWidth(160)
        self.test_button.clicked.connect(self._on_test_clicked)
        button_row.addWidget(self.test_button)
        self.close_button = QPushButton()
        self.close_button.setMaximumWidth(150)
        self.close_button.clicked.connect(self.accept)
        button_row.addWidget(self.close_button)
        layout.addLayout(button_row)

        # Parented to this dialog, per the project's "parent every QTimer"
        # rule (f-MCP defect 9) — an unparented one is garbage-collected
        # before it ever fires, leaving the copy button stuck reading
        # "Copied!" forever instead of reverting after two seconds.
        self._copy_reset_timer = QTimer(self)
        self._copy_reset_timer.setSingleShot(True)
        self._copy_reset_timer.timeout.connect(self._reset_copy_button)

        self._perform_setup()
        self._update_theme(theme)
        self._update_language(self.language)

    # -- setup ---------------------------------------------------------

    def _perform_setup(self) -> None:
        """Detect the installation and generate the configuration once, at
        construction. Failures are recorded, never raised past here — a
        dialog that could not detect anything must still open and say so,
        rather than take the whole window down with it."""
        try:
            self.installation = self.generator.detect_installation()
            self.generator.save_installation_metadata(self.installation)
        except Exception as exc:
            logger.error("MCP installation detection failed: %s", exc)
            self.installation = None
            self.setup_error = str(exc)
            return

        if not self.installation.is_valid:
            self.setup_error = self.installation.error_message
            return

        try:
            source = ConfigJSONGenerator(AppAsServer(self.app) if self.app is not None else None)
            self.config_json_str = source.to_client_config_string()
        except Exception as exc:
            logger.error("Could not generate the MCP client configuration: %s", exc)
            self.setup_error = str(exc)

    # -- display -------------------------------------------------------

    def _update_status_display(self, language: str) -> None:
        if self.installation is None:
            colour = COLOR_ERROR
            self.status_label.setText(f"{translate('mcp_config.error_label', language)} {self.setup_error}")
        else:
            lines = [
                f"{translate('mcp_config.install_type_label', language)} {self.installation.install_type}"
            ]
            if self.installation.is_valid:
                colour = COLOR_SUCCESS
                lines.append(f"✓ {translate('mcp_config.status_valid_message', language)}")
                if self.installation.entry_point:
                    lines.append(
                        f"{translate('mcp_config.entry_point_label', language)} {self.installation.entry_point}"
                    )
                if self.installation.python_executable:
                    lines.append(
                        f"{translate('mcp_config.python_label', language)} "
                        f"{self.installation.python_executable}"
                    )
                if self.installation.venv_path:
                    lines.append(
                        f"{translate('mcp_config.venv_label', language)} {self.installation.venv_path}"
                    )
            else:
                colour = COLOR_ERROR
                lines.append(f"✗ {translate('mcp_config.status_invalid_message', language)}")
                lines.append(
                    f"{translate('mcp_config.error_label', language)} {self.installation.error_message}"
                )
            self.status_label.setText("\n".join(lines))

        self.status_label.setStyleSheet(f"color: {colour.name()};")
        self.status_group.setStyleSheet(f"QGroupBox {{ border: 2px solid {colour.name()}; }}")

    def _update_instructions(self) -> None:
        if self.installation is not None and self.installation.is_valid:
            self.instructions_text.setPlainText(self.generator.generate_instructions(self.installation))
        else:
            self.instructions_text.setPlainText(self.setup_error or "")

    def _update_config_display(self, language: str) -> None:
        if self.config_json_str:
            self.config_display.setPlainText(self.config_json_str)
            self.copy_button.setEnabled(True)
            self.test_button.setEnabled(True)
        else:
            message = translate("settings.config_unavailable", language)
            if self.setup_error:
                message = f"{message}\n\n{self.setup_error}"
            self.config_display.setPlainText(message)
            self.copy_button.setEnabled(False)
            self.test_button.setEnabled(False)

    # -- actions ---------------------------------------------------------

    def _show_message(self, icon, title_key: str, text: str, language: str) -> None:
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(translate(title_key, language))
        box.setText(text)
        box.addButton(translate("common.ok", language), QMessageBox.ButtonRole.AcceptRole)
        box.exec()

    def _on_copy_clicked(self) -> None:
        if not self.config_json_str:
            return
        clipboard = QGuiApplication.clipboard()
        clipboard.setText(self.config_json_str)

        self.copy_button.setText(f"✓ {translate('settings.copy_success', self.language)}")
        self.copy_button.setEnabled(False)
        self._copy_reset_timer.start(_COPY_FEEDBACK_MS)

        logger.info("MCP configuration copied to clipboard")

    def _reset_copy_button(self) -> None:
        self.copy_button.setText(self._copy_button_label)
        self.copy_button.setEnabled(bool(self.config_json_str))

    def _on_test_clicked(self) -> None:
        language = self.language
        if self.installation is None or not self.installation.is_valid:
            self._show_message(
                QMessageBox.Icon.Warning, "mcp_config.test_invalid_title",
                translate("mcp_config.test_invalid_message", language), language,
            )
            return

        try:
            if self.installation.entry_point:
                command = [self.installation.entry_point, "--version"]
            else:
                command = [self.installation.python_executable, self.installation.main_module, "--version"]
            result = subprocess.run(command, capture_output=True, timeout=15, text=True)
            if result.returncode == 0:
                text = translate("mcp_config.test_success_message", language).format(
                    output=result.stdout.strip())
                self._show_message(
                    QMessageBox.Icon.Information, "mcp_config.test_success_title", text, language)
            else:
                text = translate("mcp_config.test_failed_message", language).format(
                    code=result.returncode, error=result.stderr.strip())
                self._show_message(
                    QMessageBox.Icon.Warning, "mcp_config.test_failed_title", text, language)
        except subprocess.TimeoutExpired:
            self._show_message(
                QMessageBox.Icon.Warning, "mcp_config.test_timeout_title",
                translate("mcp_config.test_timeout_message", language), language,
            )
        except Exception as exc:
            logger.error("MCP installation test failed: %s", exc)
            self._show_message(QMessageBox.Icon.Critical, "mcp_config.test_exception_title", str(exc), language)

    # -- i18n / theming ----------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.language = language
        self._copy_button_label = translate("settings.copy_button", language)

        self.setWindowTitle(translate("mcp_config.dialog_title", language))
        self.title_label.setText(translate("mcp_config.dialog_title", language))

        self.status_group.setTitle(translate("mcp_config.status_group", language))
        self._update_status_display(language)

        self.instructions_group.setTitle(translate("mcp_config.instructions_group", language))
        self._update_instructions()

        self.config_group.setTitle(translate("mcp_config.config_group", language))
        self.config_desc_label.setText(
            translate("mcp_config.config_desc", language).format(
                path=MCPConfigGenerator.client_config_path())
        )
        self.copy_button.setText(self._copy_button_label)
        self._update_config_display(language)

        self.test_button.setText(translate("mcp_config.test_button", language))
        self.close_button.setText(translate("common.close", language))

    def _update_theme(self, theme: str) -> None:
        is_dark = theme == "dark"
        surface = DARK_SURFACE if is_dark else LIGHT_SURFACE
        border = DARK_BORDER if is_dark else LIGHT_BORDER
        secondary = DARK_TEXT_SECONDARY if is_dark else LIGHT_TEXT_SECONDARY

        self.config_display.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {surface.name()}; color: {secondary.name()}; "
            f"border: 1px solid {border.name()}; font-family: '{FONT_MONO}'; }}"
        )
        self.instructions_text.setStyleSheet(
            f"QPlainTextEdit {{ background-color: {surface.name()}; color: {secondary.name()}; "
            f"border: 1px solid {border.name()}; }}"
        )
