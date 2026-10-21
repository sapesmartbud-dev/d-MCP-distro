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

"""Connections page — the landing page (sidebar index 0).

Without a connection there is nothing to permission, browse or log, so this
is what opens on launch. Stage 4 wires it to the real ``connections.db`` and
the OS keyring/AES vault: New, Edit, Test and Delete all act on
``app.connection_store`` and ``app.credential_store``, never on the sample
fixture. The sample-data toggle keeps meaning what it always meant — with it
on, the table shows fictitious rows and the CRUD buttons are disabled,
because acting on a mockup row against the real store would either corrupt
nothing (the row's id does not exist there) or, worse, silently succeed
against an unrelated row that happens to share it.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.db.credential_store import CredentialError
from sape_d_mcp.db.engine import test_connection
from sape_d_mcp.gui.dialogs.connection_dialog import ConnectionDialog
from sape_d_mcp.gui.dialogs.discovery_dialog import DiscoveryDialog
from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.pages._sample_data import SAMPLE_CONNECTIONS
from sape_d_mcp.gui.styles.sape_design_tokens import (
    COLOR_ERROR,
    COLOR_SUCCESS,
    COLOR_WARNING,
    DARK_TEXT_SECONDARY,
    LIGHT_TEXT_SECONDARY,
    SAPE_GRAPHITE_LIGHT,
    SAPE_PRIMARY,
)

logger = logging.getLogger(__name__)

# The mockup fixture's ad hoc "status" field, unchanged from stage 3.
_STATUS_COLOUR = {
    "success": COLOR_SUCCESS,
    "warning": COLOR_WARNING,
    "error": COLOR_ERROR,
}

# error_kind -> dot colour for a real Test result (engine.ERROR_KINDS). Amber
# for the kinds an operator can fix without knowing anything about the
# server (a missing pip package, a slow network, an untrusted certificate); red
# for the kinds that mean the server itself said no or something is
# structurally wrong.
_ERROR_KIND_COLOUR = {
    "driver_missing": COLOR_WARNING,
    "timeout": COLOR_WARNING,
    "auth": COLOR_ERROR,
    "network": COLOR_ERROR,
    # Amber, not red: the server was reached and answered, and the profile has a
    # tick box that resolves it. It is a decision waiting to be made, not a fault.
    "tls": COLOR_WARNING,
    "protocol": COLOR_ERROR,
    "unknown": COLOR_ERROR,
}

# Name, Engine, Driver, Auth, Host, Database, Username, Status, Review — the
# last two added by the connection-setup redesign
# (DESIGN-CONNECTION-SETUP.md §17): the authentication mode a row uses, and a
# marker for a profile the schema v1->v2 migration could not split
# unambiguously (see ConnectionStore.needs_review()).
_COLUMN_COUNT = 9


class _ConnectionTestWorker(QThread):
    """Runs :func:`test_connection` off the GUI thread.

    A dead host can take the whole connect timeout to answer, and
    ``test_connection()`` already builds in its own wall-clock guard on top
    of that (engine.py's ``_WALL_CLOCK_MARGIN_S``) for drivers that ignore
    their own timeout — calling it straight from a button handler would
    freeze the entire window for that whole budget, not just the Connections
    page.

    The password lives only as an attribute of this one worker object, for
    only as long as the test runs, and is never logged, put in a signal
    argument's repr, or written anywhere.
    """

    completed = pyqtSignal(int, object)  # connection_id, ConnectionTestResult

    def __init__(
        self, connection_id: int, profile: dict, password: str | None, parent: QWidget | None = None
    ) -> None:
        super().__init__(parent)
        self._connection_id = connection_id
        self._profile = profile
        self._password = password

    def run(self) -> None:
        result = test_connection(self._profile, self._password)
        self.completed.emit(self._connection_id, result)


class ConnectionsPage(QWidget):
    """Manage database connection profiles."""

    #: Generic config key this page's column widths are stored under —
    #: there is no page-specific ``get_*``/``set_*`` pair for this table
    #: the way there is for permissions, so this goes through
    #: ``ConfigManager.get()``/``set()`` directly.
    TABLE_KEY = "connections_table_columns"

    def __init__(self, app=None):
        super().__init__()
        self.app = app
        self._connections: list[dict] = []
        self._real_mode = False
        self._saving_widths = False
        self._test_results: dict[int, object] = {}  # connection_id -> ConnectionTestResult
        self._test_thread: _ConnectionTestWorker | None = None

        # Parented to self, per the skill's "parent every QTimer" rule — an
        # unparented one is f-MCP defect 9 and is collected before it fires.
        self._column_save_timer = QTimer(self)
        self._column_save_timer.setSingleShot(True)
        self._column_save_timer.timeout.connect(self._save_column_widths)

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

        button_row = QHBoxLayout()
        button_row.setSpacing(8)

        self.new_button = QPushButton()
        self.new_button.setStyleSheet(
            f"background-color: {SAPE_PRIMARY.name()}; color: white; font-weight: bold;")
        self.new_button.clicked.connect(self._on_new)
        button_row.addWidget(self.new_button)

        self.edit_button = QPushButton()
        self.edit_button.setEnabled(False)
        self.edit_button.clicked.connect(self._on_edit)
        button_row.addWidget(self.edit_button)

        self.test_button = QPushButton()
        self.test_button.setEnabled(False)
        self.test_button.clicked.connect(self._on_test)
        button_row.addWidget(self.test_button)

        self.delete_button = QPushButton()
        self.delete_button.setEnabled(False)
        self.delete_button.clicked.connect(self._on_delete)
        button_row.addWidget(self.delete_button)

        self.discover_button = QPushButton()
        self.discover_button.clicked.connect(self._on_discover)
        button_row.addWidget(self.discover_button)

        button_row.addStretch()
        layout.addLayout(button_row)

        # Which backend is actually holding the passwords, so a user who
        # cares can tell an OS keyring apart from the encrypted vault
        # without having to open Settings or a terminal.
        self.backend_label = QLabel()
        backend_font = self.backend_label.font()
        backend_font.setPointSize(9)
        backend_font.setItalic(True)
        self.backend_label.setFont(backend_font)
        layout.addWidget(self.backend_label)

        self.table = QTableWidget()
        self.table.setColumnCount(_COLUMN_COUNT)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.horizontalHeader().setStretchLastSection(False)
        self.table.itemSelectionChanged.connect(self._on_selection_changed)
        self.table.horizontalHeader().sectionResized.connect(self._on_column_resized)
        layout.addWidget(self.table, 1)

        self.empty_label = QLabel()
        self.empty_label.setWordWrap(True)
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setVisible(False)
        # Same stretch factor as self.table: with show_sample_data defaulting to
        # False (stage 9), this is the state a clean checkout actually opens on,
        # and with no stretch of its own the label left the leftover vertical
        # space to be redistributed across the widgets above it instead — each
        # grew to fill the gap the hidden table used to occupy (Qt spreads
        # surplus height across every box with a "Preferred" size policy once
        # nothing is left claiming stretch 1), pushing the title, subtitle and
        # button row apart and stranding the message far below them.
        layout.addWidget(self.empty_label, 1)

        if self.app:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    # -- data -----------------------------------------------------------

    def _show_sample_data(self) -> bool:
        config_manager = getattr(self.app, "config_manager", None) if self.app else None
        if config_manager is None:
            return False
        try:
            return bool(config_manager.get_show_sample_data())
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not read show_sample_data: %s", exc)
            return False

    def _refresh_table(self, language: str) -> None:
        selected_id = None
        current = self._selected_connection()
        if current is not None:
            selected_id = current.get("id")

        self._real_mode = self.app is not None and not self._show_sample_data()
        if self._real_mode:
            try:
                self._connections = self.app.connection_store.all()
            except Exception as exc:
                logger.error("Could not load connections from connections.db: %s", exc)
                self._connections = []
        else:
            self._connections = list(SAMPLE_CONNECTIONS)

        self.new_button.setEnabled(self._real_mode)
        self.discover_button.setEnabled(self._real_mode)

        self.table.setRowCount(len(self._connections))
        for row, connection in enumerate(self._connections):
            self.table.setItem(row, 0, QTableWidgetItem(connection["display_name"]))
            self.table.setItem(
                row, 1, QTableWidgetItem(translate(f"connections.engine_{connection['engine']}", language)))
            driver_key = connection["driver"].replace("-", "_")
            self.table.setItem(
                row, 2, QTableWidgetItem(translate(f"connections.driver_{driver_key}", language)))
            # Sample rows (stage-3 fixture) predate auth_mode; default to
            # 'password' rather than blanking the column for them.
            auth_mode = connection.get("auth_mode") or "password"
            self.table.setItem(
                row, 3, QTableWidgetItem(translate(f"connections.auth_mode_{auth_mode}", language)))
            # "—" for SQLite, which has no host/port; not a linguistic string.
            host_port = (
                f"{connection['host']}:{connection['port']}" if connection.get("host") else "—"
            )
            self.table.setItem(row, 4, QTableWidgetItem(host_port))
            self.table.setItem(row, 5, QTableWidgetItem(connection["database"]))
            self.table.setItem(row, 6, QTableWidgetItem(connection.get("username") or "—"))

            glyph, tooltip, colour = self._status_for(connection, language)
            status_item = QTableWidgetItem(glyph)
            status_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            status_item.setForeground(colour)
            status_item.setToolTip(tooltip)
            self.table.setItem(row, 7, status_item)

            review_reason = self._needs_review(connection)
            review_item = QTableWidgetItem("⚠" if review_reason else "")
            review_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            if review_reason:
                review_item.setForeground(COLOR_WARNING)
                review_item.setToolTip(
                    f"{review_reason}\n{translate('connections.needs_review_tooltip', language)}")
            self.table.setItem(row, 8, review_item)

        has_rows = bool(self._connections)
        self.table.setVisible(has_rows)
        self.empty_label.setVisible(not has_rows)
        self._load_column_widths()

        if selected_id is not None:
            for row, connection in enumerate(self._connections):
                if connection.get("id") == selected_id:
                    self.table.setCurrentCell(row, 0)
                    break

        self._update_backend_label(language)
        self._on_selection_changed()

    def _status_for(self, connection: dict, language: str) -> tuple[str, str, object]:
        """The status dot's glyph, tooltip and colour for one row."""
        if not self._real_mode:
            status = connection.get("status", "warning")
            return "●", translate(f"common.{status}", language), _STATUS_COLOUR.get(status, COLOR_WARNING)

        result = self._test_results.get(connection.get("id"))
        if result is None:
            # Never tested this session. "—" matches the glyph already used
            # above for "no host/port" — a structural absence, not a result.
            return "—", "", SAPE_GRAPHITE_LIGHT
        if result.ok:
            version = result.server_version or ""
            latency = f"{result.latency_ms:.0f} ms" if result.latency_ms is not None else ""
            tooltip = " · ".join(part for part in (version, latency) if part)
            return "●", tooltip, COLOR_SUCCESS
        colour = _ERROR_KIND_COLOUR.get(result.error_kind, COLOR_ERROR)
        return "●", result.error or "", colour

    def _needs_review(self, connection: dict) -> str | None:
        """A sentence when the v1->v2 migration could not split this row's
        host unambiguously, or ``None`` for anything else.

        ``ConnectionStore.needs_review()`` is schema-version-2 machinery
        (DESIGN-CONNECTION-SETUP.md §3.5) that predates this page's stage-9
        sample fixture and may not exist yet on the store this build is
        wired to, so the call is guarded rather than assumed — a missing
        migration step must never turn into a crashed Connections page.
        """
        if not self._real_mode or self.app is None:
            return None
        needs_review = getattr(self.app.connection_store, "needs_review", None)
        if needs_review is None:
            return None
        try:
            return needs_review(connection)
        except Exception as exc:  # pragma: no cover - defensive, store still maturing
            logger.debug("needs_review() failed for connection %s: %s", connection.get("id"), exc)
            return None

    # -- discovery ---------------------------------------------------------

    def _on_discover(self) -> None:
        if self.app is None or not self._real_mode:
            return
        language = self._language()
        dialog = DiscoveryDialog(self, language=language, app=self.app)
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.result_candidate is None:
            return

        candidate = dialog.result_candidate
        prefill = {
            "engine": candidate.engine,
            "host": candidate.host,
            "port": candidate.port,
            "instance": candidate.instance,
            "database": candidate.database,
            "driver": candidate.driver_hint,
            "auth_hint": candidate.auth_hint,
        }
        # A network-reported candidate is never auto-filled into a saved
        # profile: it opens the same New-connection dialog every other path
        # does, so the human reviews and presses Save themselves
        # (ADR 0003 point 5).
        edit_dialog = ConnectionDialog(self, language=language, prefill=prefill, app=self.app)
        if edit_dialog.exec() != QDialog.DialogCode.Accepted or edit_dialog.result_data is None:
            return

        profile = dict(edit_dialog.result_data)
        password = profile.pop("password", None) or None
        if password and not self._ensure_unlocked(language):
            return
        try:
            connection_id = self.app.connection_store.add(profile)
        except ValueError as exc:
            self._show_message(
                QMessageBox.Icon.Warning, "connections.validation_error_title", str(exc), language)
            return
        if password:
            self._store_password(connection_id, password, language)
        self._refresh_table(language)

    # -- selection / actions ---------------------------------------------

    def _on_selection_changed(self) -> None:
        connection = self._selected_connection()
        has_selection = connection is not None
        self.edit_button.setEnabled(has_selection and self._real_mode)
        self.delete_button.setEnabled(has_selection and self._real_mode)
        test_running = self._test_thread is not None and self._test_thread.isRunning()
        self.test_button.setEnabled(has_selection and self._real_mode and not test_running)

    def _selected_connection(self) -> dict | None:
        row = self.table.currentRow()
        if row < 0 or row >= len(self._connections):
            return None
        return self._connections[row]

    def _language(self) -> str:
        return self.app.current_language if self.app else "en-US"

    def _show_message(self, icon, title_key: str, text: str, language: str) -> None:
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(translate(title_key, language))
        box.setText(text)
        box.addButton(translate("common.ok", language), QMessageBox.ButtonRole.AcceptRole)
        box.exec()

    # -- new / edit --------------------------------------------------------

    def _on_new(self) -> None:
        if self.app is None or not self._real_mode:
            return
        language = self._language()
        dialog = ConnectionDialog(self, language=language, app=self.app)
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.result_data is None:
            return

        profile = dict(dialog.result_data)
        password = profile.pop("password", None) or None
        if password and not self._ensure_unlocked(language):
            return

        try:
            connection_id = self.app.connection_store.add(profile)
        except ValueError as exc:
            self._show_message(
                QMessageBox.Icon.Warning, "connections.validation_error_title", str(exc), language)
            return

        if password:
            self._store_password(connection_id, password, language)

        self._refresh_table(language)

    def _on_edit(self) -> None:
        connection = self._selected_connection()
        if connection is None or self.app is None or not self._real_mode:
            return
        language = self._language()
        dialog = ConnectionDialog(self, language=language, existing=connection, app=self.app)
        if dialog.exec() != QDialog.DialogCode.Accepted or dialog.result_data is None:
            return

        profile = dict(dialog.result_data)
        password = profile.pop("password", None) or None
        connection_id = int(connection["id"])
        if password and not self._ensure_unlocked(language):
            return

        try:
            self.app.connection_store.update(connection_id, profile)
        except ValueError as exc:
            self._show_message(
                QMessageBox.Icon.Warning, "connections.validation_error_title", str(exc), language)
            return

        if password:
            self._store_password(connection_id, password, language)

        self._refresh_table(language)

    def _store_password(self, connection_id: int, password: str, language: str) -> None:
        try:
            self.app.credential_store.set_password(connection_id, password)
        except CredentialError as exc:
            self._show_message(
                QMessageBox.Icon.Warning, "connections.validation_error_title", str(exc), language)

    # -- delete --------------------------------------------------------

    def _on_delete(self) -> None:
        connection = self._selected_connection()
        if connection is None or self.app is None or not self._real_mode:
            return
        language = self._language()

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(translate("connections.delete_confirm_title", language))
        box.setText(f"{translate('connections.delete_confirm_message', language)}\n{connection['display_name']}")
        yes_button = box.addButton(translate("common.yes", language), QMessageBox.ButtonRole.YesRole)
        box.addButton(translate("common.no", language), QMessageBox.ButtonRole.NoRole)
        box.exec()
        if box.clickedButton() != yes_button:
            return

        connection_id = int(connection["id"])
        try:
            # ConnectionStore.delete() also purges the keyring/vault secret
            # and sweeps permission rules (DESIGN-DATA-MODEL.md §7.2) — it was
            # constructed with app.credential_store, so this one call does
            # all three steps in the safe order.
            self.app.connection_store.delete(connection_id)
        except Exception as exc:
            logger.error("Could not delete connection %s: %s", connection_id, exc)
            self._show_message(
                QMessageBox.Icon.Critical, "connections.test_error_title", str(exc), language)
            return

        self._test_results.pop(connection_id, None)
        self._refresh_table(language)

    # -- test ------------------------------------------------------------

    def _ensure_unlocked(self, language: str) -> bool:
        """Prompt for the vault's master password if it is locked.

        A no-op, returning ``True`` immediately, when the OS keyring is the
        backend: ``CredentialStore.is_locked()`` is only ever ``True`` for
        the AES vault fallback.
        """
        creds = self.app.credential_store
        if not creds.is_locked():
            return True
        master, ok = QInputDialog.getText(
            self,
            translate("connections.vault_locked_title", language),
            translate("connections.vault_locked_message", language),
            QLineEdit.EchoMode.Password,
        )
        if not ok or not master:
            return False
        if not creds.unlock(master):
            self._show_message(
                QMessageBox.Icon.Warning,
                "connections.vault_locked_title",
                translate("connections.wrong_master_password_message", language),
                language,
            )
            return False
        self._update_backend_label(language)
        return True

    def _on_test(self) -> None:
        connection = self._selected_connection()
        if connection is None or self.app is None or not self._real_mode:
            return
        if self._test_thread is not None and self._test_thread.isRunning():
            return
        language = self._language()
        connection_id = int(connection["id"])

        password: str | None = None
        if connection.get("engine") != "sqlite":
            if not self._ensure_unlocked(language):
                return
            try:
                password = self.app.credential_store.get_password(connection_id)
            except CredentialError as exc:
                self._show_message(
                    QMessageBox.Icon.Warning, "connections.test_error_title", str(exc), language)
                return

        self._test_thread = _ConnectionTestWorker(connection_id, dict(connection), password, self)
        self._test_thread.completed.connect(self._on_test_completed)
        self._test_thread.finished.connect(self._on_test_thread_finished)
        # Disabled directly rather than through _on_selection_changed(): the
        # thread has not started yet at this point, so isRunning() would
        # still say False and the button would stay enabled for the instant
        # between construction and start().
        self.test_button.setEnabled(False)
        self._test_thread.start()

    def _on_test_completed(self, connection_id: int, result) -> None:
        self._test_results[connection_id] = result
        language = self._language()
        self._refresh_table(language)

        if result.ok:
            text = translate("connections.test_success_message", language).format(
                version=result.server_version or "?",
                latency=f"{result.latency_ms:.0f}" if result.latency_ms is not None else "?",
            )
            self._show_message(
                QMessageBox.Icon.Information, "connections.test_success_title", text, language)
        else:
            text = result.error or translate("connections.test_error_message", language)
            self._show_message(QMessageBox.Icon.Critical, "connections.test_error_title", text, language)

    def _on_test_thread_finished(self) -> None:
        self._test_thread = None
        self._on_selection_changed()

    # -- column width persistence ----------------------------------------

    def _on_column_resized(self, *_args) -> None:
        self._column_save_timer.stop()
        self._column_save_timer.start(300)

    def _load_column_widths(self) -> None:
        config_manager = getattr(self.app, "config_manager", None) if self.app else None
        if config_manager is None or self._saving_widths:
            return
        self._saving_widths = True
        try:
            widths = config_manager.get(self.TABLE_KEY, {}) or {}
            for column_str, width in widths.items():
                try:
                    column = int(column_str)
                except (TypeError, ValueError):
                    continue
                if 0 <= column < self.table.columnCount():
                    self.table.setColumnWidth(column, int(width))
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not load column widths: %s", exc)
        finally:
            self._saving_widths = False

    def _save_column_widths(self) -> None:
        config_manager = getattr(self.app, "config_manager", None) if self.app else None
        if config_manager is None or self._saving_widths:
            return
        self._saving_widths = True
        try:
            widths = {str(i): self.table.columnWidth(i) for i in range(self.table.columnCount())}
            config_manager.set(self.TABLE_KEY, widths)
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not save column widths: %s", exc)
        finally:
            self._saving_widths = False

    # -- i18n / theming ----------------------------------------------------

    def _update_backend_label(self, language: str) -> None:
        if self.app is None:
            self.backend_label.setVisible(False)
            return
        try:
            creds = self.app.credential_store
            text = translate("connections.credential_backend_label", language).format(
                backend=creds.backend_name())
            if creds.is_locked():
                text += " \U0001F512"  # padlock; a glyph, not a translated word
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not read the credential backend name: %s", exc)
            self.backend_label.setVisible(False)
            return
        self.backend_label.setText(text)
        self.backend_label.setVisible(True)

    def _update_language(self, language: str) -> None:
        self.title.setText(translate("connections.title", language))
        self.subtitle.setText(translate("connections.subtitle", language))
        self.new_button.setText(translate("connections.new_button", language))
        self.edit_button.setText(translate("common.edit", language))
        self.test_button.setText(translate("connections.test_button", language))
        self.test_button.setToolTip(translate("connections.test_tooltip", language))
        self.delete_button.setText(translate("common.delete", language))
        self.discover_button.setText(translate("connections.discover_button", language))
        self.table.setHorizontalHeaderLabels([
            translate("connections.table_header_name", language),
            translate("connections.table_header_engine", language),
            translate("connections.table_header_driver", language),
            translate("connections.table_header_auth", language),
            translate("connections.table_header_host", language),
            translate("connections.table_header_database", language),
            translate("connections.table_header_username", language),
            translate("connections.table_header_status", language),
            translate("connections.table_header_review", language),
        ])
        self.empty_label.setText(translate("connections.no_connections", language))
        self._refresh_table(language)

    def _update_theme(self, theme: str) -> None:
        colour = DARK_TEXT_SECONDARY if theme == "dark" else LIGHT_TEXT_SECONDARY
        self.subtitle.setStyleSheet(f"color: {colour.name()};")
        self.empty_label.setStyleSheet(f"color: {colour.name()};")
        self.backend_label.setStyleSheet(f"color: {colour.name()};")
