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

"""Add/edit modal for a connection profile.

Rebuilt against ``docs/DESIGN-CONNECTION-SETUP.md`` §9 to fix the three
things the user named directly: one combined engine+driver picker instead of
two independent combos, system (Windows/Kerberos) authentication as a first-
class, validated choice instead of a user name nobody checks, and an editable
database combo that a restricted account's short list can never lock the
user out of.

Nothing here is persisted by this dialog itself: accepting it only hands the
caller (``connections_page.py``) the fields the form collected in
``result_data``, exactly as before stage 4 wired the page to
``ConnectionStore``.
"""

from __future__ import annotations

import json
import logging
import sys

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QIntValidator, QStandardItemModel
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.db.auth_modes import AUTH_MODES, support_for
from sape_d_mcp.db.dialects.registry import (
    driver_requirement,
    drivers_for,
    is_driver_available,
)
from sape_d_mcp.db.targets import MsSqlTarget, parse_mssql_target
from sape_d_mcp.gui.dialogs.discovery_dialog import _DiscoveryWorker
from sape_d_mcp.gui.i18n import translate

logger = logging.getLogger(__name__)

# Engine order the combined picker groups drivers under — mirrors the order
# db.dialects.registry.drivers_for() registers pyodbc before pymssql, so the
# multi-platform default is offered first without looking like an
# afterthought (registry.py's own comment on drivers_for()).
_ENGINES: tuple[str, ...] = ("mssql", "postgresql", "mysql", "sqlite")

_DEFAULT_PORTS: dict[str, int | None] = {
    "mssql": 1433, "postgresql": 5432, "mysql": 3306, "sqlite": None,
}

# The Find-databases / Resolve-port network calls both use a short, fixed
# budget: this is an interactive click, not an analytical query
# (DESIGN-CONNECTION-SETUP.md §8.3).
_ENUMERATION_TIMEOUT_S = 10
_RESOLVE_TIMEOUT_S = 2.0


def _standard_item_model(combo: QComboBox) -> QStandardItemModel:
    """Return ``combo``'s own model, typed for the ``.item()`` calls below.

    ``QComboBox.model()`` is typed as ``QAbstractItemModel | None`` because
    that is the most general type PyQt6's stubs can promise, but a
    ``QComboBox`` that nobody has called ``setModel()`` on — true for every
    combo in this dialog — always owns a ``QStandardItemModel`` of its own
    at runtime, never ``None``. The cast, not a suppression, is the fix:
    genuinely narrowing what mypy sees to what Qt actually guarantees here.
    """
    model = combo.model()
    assert isinstance(model, QStandardItemModel)
    return model


class _DatabaseListWorker(QThread):
    """Runs :func:`sape_d_mcp.db.engine.list_server_databases` off the GUI thread.

    Shaped exactly like ``_ConnectionTestWorker`` in ``connections_page.py``:
    the password lives only on this one worker object, for only as long as
    the call takes, and is never logged or put in a signal argument's repr.
    """

    completed = pyqtSignal(object)  # (names: tuple[str, ...], system: frozenset[str])
    failed = pyqtSignal(str)

    def __init__(self, profile: dict, password: str | None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._profile = profile
        self._password = password

    def run(self) -> None:
        try:
            from sape_d_mcp.db.engine import list_server_databases

            result = list_server_databases(self._profile, self._password, timeout_s=_ENUMERATION_TIMEOUT_S)
        except Exception as exc:
            logger.warning("could not list databases for %r: %s", self._profile.get("display_name"), exc)
            self.failed.emit(str(exc))
            return

        # DatabaseListResult.error is only ever set when every bootstrap candidate
        # failed to connect (§8.4) — a short, even empty, list with no error is the
        # ordinary shape of a least-privilege account and is reported through
        # ``completed``, not ``failed``.
        if result.error is not None:
            logger.warning(
                "could not list databases for %r: %s", self._profile.get("display_name"), result.error)
            self.failed.emit(result.error)
            return

        self.completed.emit((result.databases, result.system))


class ConnectionDialog(QDialog):
    """Create or edit a connection profile."""

    def __init__(
        self,
        parent=None,
        language: str = "en-US",
        existing: dict | None = None,
        prefill: dict | None = None,
        app=None,
    ):
        super().__init__(parent)
        self.language = language
        self.existing = existing
        self.app = app
        self.result_data: dict | None = None
        self._pending_split: MsSqlTarget | None = None
        # Everything in the edited profile's options_json that this dialog does not
        # own. Kept so that ticking a checkbox cannot silently drop a driver option
        # somebody set by hand.
        self._other_options: dict = {}
        self._db_worker: _DatabaseListWorker | None = None
        self._resolve_worker: _DiscoveryWorker | None = None

        self.setMinimumWidth(480)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.heading_label = QLabel()
        layout.addWidget(self.heading_label)

        form = QFormLayout()
        form.setSpacing(10)
        self._form = form

        self.name_edit = QLineEdit()
        self.name_label = QLabel()
        form.addRow(self.name_label, self.name_edit)

        # (a) One combined engine+driver picker, grouped under a non-selectable
        # header per engine, replacing the old pair of independent combos.
        self.engine_driver_combo = QComboBox()
        self.engine_driver_combo.currentIndexChanged.connect(self._on_engine_driver_changed)
        self.engine_driver_label = QLabel()
        form.addRow(self.engine_driver_label, self.engine_driver_combo)

        self.driver_note = QLabel()
        self.driver_note.setWordWrap(True)
        form.addRow(self.driver_note)

        # (b) System authentication as a validated, first-class mode.
        self.auth_mode_combo = QComboBox()
        self.auth_mode_combo.currentIndexChanged.connect(self._on_auth_mode_changed)
        self.auth_mode_label = QLabel()
        form.addRow(self.auth_mode_label, self.auth_mode_combo)

        self.auth_identity_note = QLabel()
        self.auth_identity_note.setWordWrap(True)
        form.addRow(self.auth_identity_note)

        self.sqlite_note = QLabel()
        self.sqlite_note.setWordWrap(True)
        form.addRow(self.sqlite_note)

        self.host_edit = QLineEdit()
        self.host_edit.editingFinished.connect(self._on_host_edited)
        self.host_label = QLabel()
        form.addRow(self.host_label, self.host_edit)

        # MS-SQL only: instance name plus a button that asks the SQL Server
        # Browser which port that instance is really on today (a dynamic
        # port moves at every service restart — this is the user's own
        # PC-ARR\SQLEXPRESS:56879 made safe to type).
        instance_row = QHBoxLayout()
        self.instance_edit = QLineEdit()
        instance_row.addWidget(self.instance_edit, 1)
        self.resolve_port_button = QPushButton()
        self.resolve_port_button.clicked.connect(self._on_resolve_port)
        instance_row.addWidget(self.resolve_port_button)
        self.instance_label = QLabel()
        form.addRow(self.instance_label, instance_row)

        self.port_edit = QLineEdit()
        self.port_edit.setValidator(QIntValidator(1, 65535, self.port_edit))
        self.port_label = QLabel()
        form.addRow(self.port_label, self.port_edit)

        # A compound host (server\instance:port, all in one field — the exact
        # shape of the reported failure) is parsed and offered a one-click
        # split, never silently guessed at (DESIGN-CONNECTION-SETUP.md §6.1).
        host_note_row = QHBoxLayout()
        self.host_note = QLabel()
        self.host_note.setWordWrap(True)
        host_note_row.addWidget(self.host_note, 1)
        self.split_button = QPushButton()
        self.split_button.setVisible(False)
        self.split_button.clicked.connect(self._on_split_for_me)
        host_note_row.addWidget(self.split_button)
        # Wrapped in a plain QWidget rather than added as a bare QLayout:
        # QFormLayout.setRowVisible() only resolves a row from a widget it
        # knows directly as that row's label or field, and a QHBoxLayout
        # added with addRow(layout) is neither — the widgets nested inside
        # it are invisible to that lookup, so hiding this row for a non-
        # MS-SQL engine would silently do nothing without this wrapper.
        self.host_note_container = QWidget()
        self.host_note_container.setLayout(host_note_row)
        form.addRow(self.host_note_container)

        # ODBC Driver 18 encrypts by default and verifies the certificate, so an
        # internal SQL Server with a self-signed certificate is refused before any
        # credential is sent. That is the right default and it stays the default; this
        # is the documented way out of it, and it is a checkbox rather than a line in
        # options_json because a security decision nobody can find is one nobody makes
        # deliberately.
        self.trust_cert_check = QCheckBox()
        self.trust_cert_note = QLabel()
        self.trust_cert_note.setWordWrap(True)
        trust_note_font = self.trust_cert_note.font()
        trust_note_font.setItalic(True)
        trust_note_font.setPointSize(9)
        self.trust_cert_note.setFont(trust_note_font)
        form.addRow("", self.trust_cert_check)
        form.addRow("", self.trust_cert_note)

        # (c) The database field is always an editable combo: a restricted
        # account gets a short list, never an error, and the list is never
        # authoritative (DESIGN-CONNECTION-SETUP.md §8.4).
        db_row = QHBoxLayout()
        self.database_combo = QComboBox()
        self.database_combo.setEditable(True)
        self.database_combo.activated.connect(self._on_database_item_activated)
        db_row.addWidget(self.database_combo, 1)
        self.browse_button = QPushButton()
        self.browse_button.setVisible(False)
        self.browse_button.clicked.connect(self._on_browse_file)
        db_row.addWidget(self.browse_button)
        self.find_db_button = QPushButton()
        self.find_db_button.clicked.connect(self._on_find_databases)
        db_row.addWidget(self.find_db_button)
        self.database_label = QLabel()
        form.addRow(self.database_label, db_row)

        self.database_note = QLabel()
        self.database_note.setWordWrap(True)
        form.addRow(self.database_note)

        self.username_edit = QLineEdit()
        self.username_label = QLabel()
        form.addRow(self.username_label, self.username_edit)

        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_label = QLabel()
        form.addRow(self.password_label, self.password_edit)

        layout.addLayout(form)

        self.keyring_note = QLabel()
        self.keyring_note.setWordWrap(True)
        note_font = self.keyring_note.font()
        note_font.setItalic(True)
        note_font.setPointSize(9)
        self.keyring_note.setFont(note_font)
        layout.addWidget(self.keyring_note)

        button_row = QHBoxLayout()
        button_row.addStretch()
        self.cancel_button = QPushButton()
        self.cancel_button.clicked.connect(self.reject)
        button_row.addWidget(self.cancel_button)
        self.save_button = QPushButton()
        self.save_button.setDefault(True)
        self.save_button.clicked.connect(self._on_save)
        button_row.addWidget(self.save_button)
        layout.addLayout(button_row)

        self._populate_engine_driver_combo()

        if existing:
            self._populate(existing)
        elif prefill:
            self._populate_prefill(prefill)
        else:
            self._on_engine_driver_changed()

        self._update_language(language)

    # -- the combined engine+driver picker ---------------------------------

    def _populate_engine_driver_combo(self) -> None:
        combo = self.engine_driver_combo
        previous = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        for engine in _ENGINES:
            combo.addItem(translate(f"connections.driver_group_{engine}", self.language))
            header_item = _standard_item_model(combo).item(combo.count() - 1)
            # Never None: the index just came from addItem() on the same model.
            assert header_item is not None
            # A non-selectable, non-enabled header — the grouping the user
            # asked for ("── MS-SQL Server ──") rather than a flat list.
            header_item.setFlags(Qt.ItemFlag.NoItemFlags)
            font = header_item.font()
            font.setBold(True)
            header_item.setFont(font)
            for driver in drivers_for(engine):
                combo.addItem(f"    {self._driver_label(driver)}", (engine, driver))
        if previous is not None:
            index = combo.findData(previous)
            combo.setCurrentIndex(index if index >= 0 else self._first_driver_index_for(_ENGINES[0]))
        else:
            combo.setCurrentIndex(self._first_driver_index_for(_ENGINES[0]))
        combo.blockSignals(False)

    def _driver_label(self, driver: str) -> str:
        driver_key = driver.replace("-", "_")
        base = translate(f"connections.driver_{driver_key}", self.language)
        status_key = (
            "connections.driver_status_installed" if is_driver_available(driver)
            else "connections.driver_status_not_installed"
        )
        return f"{base}   {translate(status_key, self.language)}"

    def _first_driver_index_for(self, engine: str) -> int:
        combo = self.engine_driver_combo
        for index in range(combo.count()):
            data = combo.itemData(index)
            if isinstance(data, tuple) and data[0] == engine:
                return index
        return 0

    def _current_engine(self) -> str | None:
        data = self.engine_driver_combo.currentData()
        return data[0] if isinstance(data, tuple) else None

    def _current_driver(self) -> str | None:
        data = self.engine_driver_combo.currentData()
        return data[1] if isinstance(data, tuple) else None

    def _on_engine_driver_changed(self, *_args) -> None:
        data = self.engine_driver_combo.currentData()
        if not isinstance(data, tuple):
            return  # a header row cannot be selected; defensive only
        engine, driver = data

        default_port = _DEFAULT_PORTS.get(engine)
        self.port_edit.setText(str(default_port) if default_port else "")

        self._update_driver_note(driver)
        self._populate_auth_combo(engine, driver)
        self._apply_shape(engine)

    def _update_driver_note(self, driver: str) -> None:
        if is_driver_available(driver):
            self.driver_note.setVisible(False)
            self._form.setRowVisible(self.driver_note, False)
            return
        requirement = driver_requirement(driver)
        text = translate("connections.driver_requirement_pip", self.language).format(
            requirement=requirement or "")
        if driver == "pyodbc":
            hint_key = (
                "connections.driver_requirement_pyodbc_windows" if sys.platform.startswith("win")
                else "connections.driver_requirement_pyodbc_other"
            )
            text = f"{text} {translate(hint_key, self.language)}"
        self.driver_note.setText(text)
        self.driver_note.setVisible(True)
        self._form.setRowVisible(self.driver_note, True)

    # -- authentication mode -------------------------------------------------

    def _populate_auth_combo(self, engine: str, driver: str) -> None:
        combo = self.auth_mode_combo
        previous = combo.currentData()
        combo.blockSignals(True)
        combo.clear()
        for mode in AUTH_MODES:
            # 'none' is reserved for SQLite, and SQLite conversely offers
            # only 'none' (DESIGN-CONNECTION-SETUP.md §3.1): PostgreSQL
            # 'trust' and every other "send nothing" case off SQLite is
            # modelled as 'integrated' instead, so there is exactly one
            # value meaning that, never two competing ones. The row is
            # hidden outright for SQLite (_apply_shape), so this only
            # matters for keeping the combo's own data consistent.
            if (mode == "none") != (engine == "sqlite"):
                continue
            combo.addItem(translate(f"connections.auth_mode_{mode}", self.language), mode)
        if previous is not None:
            index = combo.findData(previous)
            combo.setCurrentIndex(index if index >= 0 else 0)
        else:
            combo.setCurrentIndex(0)
        combo.blockSignals(False)
        self._refresh_integrated_support(engine, driver)
        self._on_auth_mode_changed()

    def _refresh_integrated_support(self, engine: str, driver: str) -> None:
        """Disable 'integrated' where the (engine, driver) pair cannot do it.

        This is the direct, three-layer fix for the reported pymssql +
        Windows-authentication failure (error 20009): the impossible
        combination is refused here, in the GUI, before a password is even
        asked for — never left to fail in the driver's own vocabulary.
        """
        index = self.auth_mode_combo.findData("integrated")
        if index < 0:
            return
        support = support_for(engine, driver)
        item = _standard_item_model(self.auth_mode_combo).item(index)
        # Never None: `index` just came from findData() on the same model.
        assert item is not None
        item.setEnabled(support.supported)
        tooltip = "" if support.supported else translate(support.message_key, self.language)
        item.setToolTip(tooltip)
        self.auth_mode_combo.setToolTip(tooltip if self.auth_mode_combo.currentData() == "integrated" else "")
        if not support.supported and self.auth_mode_combo.currentData() == "integrated":
            password_index = self.auth_mode_combo.findData("password")
            if password_index >= 0:
                self.auth_mode_combo.setCurrentIndex(password_index)
            self.username_edit.setFocus()

    def _on_auth_mode_changed(self, *_args) -> None:
        mode = self.auth_mode_combo.currentData()
        show_credentials = mode == "password"
        for label, field in (
            (self.username_label, self.username_edit),
            (self.password_label, self.password_edit),
        ):
            field.setVisible(show_credentials)
            self._form.setRowVisible(label, show_credentials)

        show_identity_note = mode == "integrated"
        self.auth_identity_note.setVisible(show_identity_note)
        self._form.setRowVisible(self.auth_identity_note, show_identity_note)
        if show_identity_note:
            identity_key = (
                "connections.auth_integrated_identity_windows" if sys.platform.startswith("win")
                else "connections.auth_integrated_identity_other"
            )
            self.auth_identity_note.setText(translate(identity_key, self.language))

    # -- shape per engine -----------------------------------------------------

    def _apply_shape(self, engine: str) -> None:
        """Collapse the form for SQLite, and show the MS-SQL-only fields."""
        is_sqlite = engine == "sqlite"
        is_mssql = engine == "mssql"

        for label, field in (
            (self.host_label, self.host_edit),
            (self.port_label, self.port_edit),
        ):
            field.setVisible(not is_sqlite)
            self._form.setRowVisible(label, not is_sqlite)

        self._form.setRowVisible(self.instance_label, is_mssql)
        self.instance_edit.setVisible(is_mssql)
        self.resolve_port_button.setVisible(is_mssql)
        self._form.setRowVisible(self.host_note_container, is_mssql)
        self.host_note_container.setVisible(is_mssql)
        self._form.setRowVisible(self.trust_cert_check, is_mssql)
        self.trust_cert_check.setVisible(is_mssql)
        self._form.setRowVisible(self.trust_cert_note, is_mssql)
        self.trust_cert_note.setVisible(is_mssql)
        if not is_mssql:
            self.host_note.setText("")
            self.split_button.setVisible(False)

        self._form.setRowVisible(self.auth_mode_label, not is_sqlite)
        self.auth_mode_combo.setVisible(not is_sqlite)
        self._form.setRowVisible(self.sqlite_note, is_sqlite)
        self.sqlite_note.setVisible(is_sqlite)
        if is_sqlite:
            self._form.setRowVisible(self.username_label, False)
            self._form.setRowVisible(self.password_label, False)
            self.username_edit.setVisible(False)
            self.password_edit.setVisible(False)
            self._form.setRowVisible(self.auth_identity_note, False)

        self.browse_button.setVisible(is_sqlite)
        self.find_db_button.setVisible(not is_sqlite)
        self._form.setRowVisible(self.database_note, not is_sqlite)
        self.database_note.setVisible(not is_sqlite)

    # -- MS-SQL host normalisation -------------------------------------------

    def _on_host_edited(self) -> None:
        if self._current_engine() != "mssql":
            return
        text = self.host_edit.text().strip()
        self._pending_split = None
        if not text:
            self.host_note.setText("")
            self.split_button.setVisible(False)
            return
        try:
            target = parse_mssql_target(text)
        except ValueError as exc:
            self.host_note.setText(
                translate("connections.host_parse_error_label", self.language).format(detail=str(exc)))
            self.split_button.setVisible(False)
            return
        if target.compound:
            self._pending_split = target
            self._show_parsed_note(target)
            self.split_button.setVisible(True)
        else:
            self.host_note.setText("")
            self.split_button.setVisible(False)

    def _show_parsed_note(self, target: MsSqlTarget) -> None:
        instance_part = (
            translate("connections.host_parsed_instance_part", self.language).format(instance=target.instance)
            if target.instance else ""
        )
        port_part = (
            translate("connections.host_parsed_port_part", self.language).format(port=target.port)
            if target.port else ""
        )
        self.host_note.setText(
            translate("connections.host_parsed_note", self.language).format(
                server=target.server, instance_part=instance_part, port_part=port_part))

    def _on_split_for_me(self) -> None:
        target = self._pending_split
        if target is None:
            return
        self.host_edit.setText(target.server)
        if target.instance:
            self.instance_edit.setText(target.instance)
        if target.port:
            self.port_edit.setText(str(target.port))
        self.split_button.setVisible(False)
        self.host_note.setText("")
        self._pending_split = None

    # -- Resolve port (unicast SSRP query against a named host) -------------

    def _on_resolve_port(self) -> None:
        if self._resolve_worker is not None and self._resolve_worker.isRunning():
            return
        host = self.host_edit.text().strip()
        if not host:
            return
        self.resolve_port_button.setEnabled(False)
        self.host_note.setText(translate("connections.resolve_port_searching", self.language))
        self._audit_resolve_port(host)
        # A unicast query to a host the user already typed needs no
        # confirmation — no broadcast leaves the machine — but it is still
        # audited (DESIGN-CONNECTION-SETUP.md §9).
        self._resolve_worker = _DiscoveryWorker(
            "network", {"timeout_s": _RESOLVE_TIMEOUT_S, "targets": [host]}, self)
        self._resolve_worker.completed.connect(self._on_resolve_completed)
        self._resolve_worker.failed.connect(self._on_resolve_failed)
        self._resolve_worker.finished.connect(self._on_resolve_worker_finished)
        self._resolve_worker.start()

    def _audit_resolve_port(self, host: str) -> None:
        log_store = getattr(self.app, "log_store", None) if self.app else None
        if log_store is None:
            return
        try:
            log_store.log_tool(
                None, "gui", "discover-network",
                {"timeout_s": _RESOLVE_TIMEOUT_S, "scope": "unicast", "host": host},
                decision="allowed",
            )
        except Exception as exc:  # pragma: no cover - defensive, audit must never block the GUI
            logger.debug("could not audit the port-resolve query: %s", exc)

    def _on_resolve_completed(self, result) -> None:
        matches = [c for c in result.candidates if c.engine == "mssql"]
        if not matches:
            self.host_note.setText(translate("connections.resolve_port_no_result", self.language))
            return
        candidate = matches[0]
        if candidate.instance:
            self.instance_edit.setText(candidate.instance)
        if candidate.port:
            self.port_edit.setText(str(candidate.port))
        self.host_note.setText(
            translate("connections.resolve_port_result", self.language).format(
                instance=candidate.instance or "", port=candidate.port or ""))

    def _on_resolve_failed(self, message: str) -> None:
        self.host_note.setText(message)

    def _on_resolve_worker_finished(self) -> None:
        self._resolve_worker = None
        self.resolve_port_button.setEnabled(True)

    # -- database enumeration -------------------------------------------------

    def _on_browse_file(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self,
            translate("connections.browse_dialog_title", self.language),
            self.database_combo.currentText() or "",
            "SQLite (*.db *.sqlite *.sqlite3);;All files (*)",
        )
        if path:
            self.database_combo.setEditText(path)

    def _on_database_item_activated(self, index: int) -> None:
        # itemData holds the bare database name; the visible label may carry
        # a translated " (system)" suffix that must never reach the saved
        # profile (DESIGN-CONNECTION-SETUP.md §8.2's system-database marker
        # is presentation only).
        name = self.database_combo.itemData(index)
        if name is not None:
            self.database_combo.setEditText(name)

    def _on_find_databases(self) -> None:
        if self._db_worker is not None and self._db_worker.isRunning():
            return
        engine = self._current_engine()
        if engine is None or engine == "sqlite":
            return
        profile = self._collect_profile_snapshot()
        auth_mode = profile.get("auth_mode", "password")
        password = self.password_edit.text() if auth_mode == "password" else None

        self.find_db_button.setEnabled(False)
        self.database_note.setText(translate("connections.find_databases_running", self.language))
        self._db_worker = _DatabaseListWorker(profile, password, self)
        self._db_worker.completed.connect(self._on_databases_found)
        self._db_worker.failed.connect(self._on_databases_failed)
        self._db_worker.finished.connect(self._on_db_worker_finished)
        self._db_worker.start()

    _TRUST_CERT_KEY = "TrustServerCertificate"

    def _load_options(self, existing: dict) -> None:
        """Split the edited profile's ``options_json`` into "ours" and "everyone else's".

        Anything but this dialog's own key is kept verbatim in ``_other_options`` and
        written back untouched, so a hand-set driver option survives an edit that only
        came here to change the display name.  Unparseable JSON is left alone for the
        same reason: it is not this dialog's to discard.
        """
        raw = existing.get("options_json")
        if raw in (None, "", b""):
            return
        decoded = raw if isinstance(raw, dict) else None
        if decoded is None:
            try:
                decoded = json.loads(raw)
            except (TypeError, ValueError):
                logger.warning("options_json is not valid JSON; leaving it untouched")
                return
        if not isinstance(decoded, dict):
            return
        self._other_options = {
            key: value for key, value in decoded.items()
            if key.lower() != self._TRUST_CERT_KEY.lower()
        }
        trusted = next(
            (value for key, value in decoded.items() if key.lower() == self._TRUST_CERT_KEY.lower()),
            None,
        )
        self.trust_cert_check.setChecked(str(trusted).strip().lower() in ("yes", "true", "1"))

    def _options_json(self, engine: str | None) -> str:
        """``options_json`` for the profile being saved, as a JSON string.

        Empty when there is nothing to say, so an untouched MS-SQL profile carries no
        options column at all rather than ``{}`` — `_profile_options()` treats the two
        the same, but only one of them reads as "nothing was configured here".
        """
        options = dict(self._other_options)
        if engine == "mssql" and self.trust_cert_check.isChecked():
            options[self._TRUST_CERT_KEY] = "yes"
        return json.dumps(options) if options else ""

    def _collect_profile_snapshot(self) -> dict:
        """The in-progress form, as a profile dict — never saved, only used
        to drive Find-databases / Resolve-port while the human is still
        editing."""
        engine = self._current_engine()
        driver = self._current_driver()
        return {
            "display_name": self.name_edit.text().strip() or "?",
            "engine": engine,
            "driver": driver,
            "host": self.host_edit.text().strip(),
            "port": self.port_edit.text().strip(),
            "instance": self.instance_edit.text().strip() if engine == "mssql" else "",
            "database": self.database_combo.currentText().strip(),
            "auth_mode": self.auth_mode_combo.currentData() or "password",
            "username": self.username_edit.text().strip(),
            "options_json": self._options_json(engine),
        }

    def _on_databases_found(self, payload) -> None:
        names, system = payload
        current_text = self.database_combo.currentText()
        self.database_combo.blockSignals(True)
        self.database_combo.clear()
        suffix = translate("connections.database_system_suffix", self.language)
        for name in names:
            label = f"{name}{suffix}" if name in system else name
            self.database_combo.addItem(label, name)
        self.database_combo.setEditText(current_text)
        self.database_combo.blockSignals(False)
        self.database_note.setText(translate("connections.database_editable_note", self.language))

    def _on_databases_failed(self, message: str) -> None:
        # Enumeration failing never blocks saving a profile
        # (DESIGN-CONNECTION-SETUP.md §8.4) — the combo keeps whatever the
        # user had typed, and Save stays enabled.
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(translate("connections.find_databases_error_title", self.language))
        box.setText(message)
        box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
        box.exec()
        self.database_note.setText(translate("connections.database_editable_note", self.language))

    def _on_db_worker_finished(self) -> None:
        self._db_worker = None
        self.find_db_button.setEnabled(True)

    # -- populate / prefill ---------------------------------------------------

    def _populate(self, existing: dict) -> None:
        self.name_edit.setText(existing.get("display_name", ""))
        engine = existing.get("engine", "mssql")
        driver = existing.get("driver")
        self._select_engine_driver(engine, driver)

        self._load_options(existing)
        self.host_edit.setText(existing.get("host") or "")
        self.instance_edit.setText(existing.get("instance") or "")
        port = existing.get("port")
        self.port_edit.setText(str(port) if port else "")
        self.database_combo.setEditText(existing.get("database") or "")
        self.username_edit.setText(existing.get("username") or "")

        auth_mode = existing.get("auth_mode") or "password"
        auth_index = self.auth_mode_combo.findData(auth_mode)
        if auth_index >= 0:
            self.auth_mode_combo.setCurrentIndex(auth_index)
        self._on_auth_mode_changed()

        if engine == "mssql":
            self._on_host_edited()

    def _populate_prefill(self, prefill: dict) -> None:
        """Fill the form from a discovery :class:`Candidate`, never a saved row.

        The candidate is a *suggestion*: nothing here saves a profile or
        opens a connection, and a network-reported candidate arrives exactly
        like any other — the human still reviews every field and presses
        Save (ADR 0003 point 5).
        """
        engine = prefill.get("engine")
        driver = prefill.get("driver") or prefill.get("driver_hint")
        self._select_engine_driver(engine, driver)

        self.host_edit.setText(prefill.get("host") or "")
        if prefill.get("instance"):
            self.instance_edit.setText(str(prefill["instance"]))
        if prefill.get("port"):
            self.port_edit.setText(str(prefill["port"]))
        if prefill.get("database"):
            self.database_combo.setEditText(str(prefill["database"]))

        auth_hint = prefill.get("auth_hint") or prefill.get("auth_mode")
        if auth_hint:
            auth_index = self.auth_mode_combo.findData(auth_hint)
            if auth_index >= 0:
                self.auth_mode_combo.setCurrentIndex(auth_index)
        self._on_auth_mode_changed()

        if engine == "mssql":
            self._on_host_edited()

    def _select_engine_driver(self, engine: str | None, driver: str | None) -> None:
        index = self.engine_driver_combo.findData((engine, driver)) if engine and driver else -1
        if index < 0:
            index = self._first_driver_index_for(engine or _ENGINES[0])
        self.engine_driver_combo.blockSignals(True)
        self.engine_driver_combo.setCurrentIndex(max(index, 0))
        self.engine_driver_combo.blockSignals(False)
        self._on_engine_driver_changed()

    # -- save ------------------------------------------------------------

    def _on_save(self) -> None:
        name = self.name_edit.text().strip()
        database = self.database_combo.currentText().strip()

        if not name or not database:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle(translate("connections.validation_error_title", self.language))
            box.setText(translate("connections.validation_error_message", self.language))
            box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
            box.exec()
            return

        engine = self._current_engine()
        driver = self._current_driver()
        auth_mode = self.auth_mode_combo.currentData() or "password"

        profile: dict = {
            "display_name": name,
            "engine": engine,
            "driver": driver,
            "database": database,
            "options_json": self._options_json(engine),
        }
        if engine == "sqlite":
            # ConnectionStore._validate() forces auth_mode='none' and requires
            # host/port/username/instance to be structurally absent for
            # SQLite (DESIGN-CONNECTION-SETUP.md §3.6) — sent explicitly
            # rather than read from widgets that may carry stale text from a
            # previous engine selection.
            profile["host"] = ""
            profile["port"] = ""
            profile["instance"] = ""
            profile["username"] = ""
            profile["auth_mode"] = "none"
        else:
            profile["host"] = self.host_edit.text().strip()
            profile["port"] = self.port_edit.text().strip()
            profile["instance"] = self.instance_edit.text().strip() if engine == "mssql" else ""
            if engine == "mssql" and not profile["port"] and not profile["instance"]:
                # ConnectionStore._validate() would refuse this with the same
                # sentence, but only after a round trip through the store — say
                # it here, before Save even leaves the dialog, so it reads as
                # guidance rather than as an error message in translation.
                box = QMessageBox(self)
                box.setIcon(QMessageBox.Icon.Warning)
                box.setWindowTitle(translate("connections.validation_error_title", self.language))
                box.setText(translate("connections.port_or_instance_hint", self.language))
                box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
                box.exec()
                return
            profile["auth_mode"] = auth_mode
            # Under 'integrated' the username must be NULL, not merely
            # blank (ADR 0002 point 2) — a stored name the driver ignores
            # is a profile that lies about whose identity connects.
            profile["username"] = self.username_edit.text().strip() if auth_mode == "password" else ""
            if auth_mode == "password":
                password = self.password_edit.text()
                if password:
                    # Blank means "leave the stored password unchanged" on
                    # an edit, and "no password to store" on a new
                    # connection - see CredentialStore.set_password()'s own
                    # caller in the page.
                    profile["password"] = password

        self.result_data = profile
        self.accept()

    # -- lifecycle: stop every worker before the dialog is destroyed --------

    def _stop_workers(self) -> None:
        # f-MCP defect 9: a closeEvent that never stopped its thread.
        # ``_DiscoveryWorker`` (used for Resolve port) cancels cooperatively
        # through its own ``threading.Event``, matching §7.9 point 3.
        # ``_DatabaseListWorker`` wraps a single blocking call with no
        # documented cancellation point of its own (DESIGN-CONNECTION-
        # SETUP.md §8.3 names no ``cancel`` parameter for
        # ``list_server_databases()``), so it is only waited for, briefly,
        # and never ``terminate()``d — a bounded wait can time out and leave
        # it finishing in the background, which is safe because it touches
        # nothing this dialog still owns once closed.
        for worker in (self._db_worker, self._resolve_worker):
            if worker is not None and worker.isRunning():
                cancel = getattr(worker, "cancel", None)
                if cancel is not None:
                    cancel()
                worker.wait(3000)

    def closeEvent(self, event) -> None:
        self._stop_workers()
        super().closeEvent(event)

    def reject(self) -> None:
        self._stop_workers()
        super().reject()

    # -- i18n --------------------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.language = language
        title_key = "connections.edit_connection_title" if self.existing else "connections.new_connection_title"
        self.setWindowTitle(translate(title_key, language))
        self.heading_label.setText(translate(title_key, language))

        self.name_label.setText(translate("connections.field_display_name", language))
        self.engine_driver_label.setText(translate("connections.field_engine_driver", language))
        self.auth_mode_label.setText(translate("connections.field_auth_mode", language))
        # 'None' is only ever added to the combo for SQLite (_populate_auth_combo),
        # so a non-SQLite user who wonders where it went never sees it in the list
        # itself — the explanation has to live on the label they are looking at.
        self.auth_mode_label.setToolTip(translate("connections.auth_none_sqlite_only", language))
        self.sqlite_note.setText(translate("connections.auth_sqlite_note", language))
        self.host_label.setText(translate("connections.field_host", language))
        self.instance_label.setText(translate("connections.field_instance", language))
        self.resolve_port_button.setText(translate("connections.resolve_port_button", language))
        self.resolve_port_button.setToolTip(translate("connections.resolve_port_tooltip", language))
        self.split_button.setText(translate("connections.split_for_me_button", language))
        self.port_label.setText(translate("connections.field_port", language))
        # DESIGN-CONNECTION-SETUP.md §3.6: port is optional for MS-SQL only when
        # an instance is given instead, and mandatory otherwise. Said once here,
        # on both fields that make up the choice, rather than only discovered
        # from ConnectionStore._validate()'s own ValueError after Save is pressed.
        port_or_instance_hint = translate("connections.port_or_instance_hint", language)
        self.port_label.setToolTip(port_or_instance_hint)
        self.port_edit.setToolTip(port_or_instance_hint)
        self.instance_label.setToolTip(port_or_instance_hint)
        self.instance_edit.setToolTip(port_or_instance_hint)
        self.trust_cert_check.setText(translate("connections.trust_server_certificate", language))
        self.trust_cert_note.setText(translate("connections.trust_server_certificate_note", language))
        self.database_label.setText(translate("connections.field_database", language))
        self.username_label.setText(translate("connections.field_username", language))
        self.password_label.setText(translate("connections.field_password", language))
        self.keyring_note.setText(translate("connections.keyring_note", language))
        self.browse_button.setText(translate("connections.browse_button", language))
        self.find_db_button.setText(translate("connections.find_databases_button", language))
        self.cancel_button.setText(translate("common.cancel", language))
        self.save_button.setText(translate("common.save", language))

        self._populate_engine_driver_combo()
        engine = self._current_engine() or _ENGINES[0]
        driver = self._current_driver()
        if driver:
            self._populate_auth_combo(engine, driver)
        self._apply_shape(engine)
