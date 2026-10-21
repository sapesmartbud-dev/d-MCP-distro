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

"""Logs page — one tab per connection, each a real table over ``audit.db``.

A deliberate departure from f-MCP, whose single ``QPlainTextEdit`` ``prompt.md`` asks
d-MCP not to repeat: a database audit trail is tabular and per-connection, and a table
sorts, filters and exports better than scrolled text ever could.

Stage 8 retires the sample-data fixture this page used to render: every tab, and every
row in it, comes from :class:`~sape_d_mcp.log_store.LogStore` over ``audit.db``, reached
through ``app.log_store`` (never a private second handle — the "one config writer"
discipline this application applies to ``config.json`` applies here too, to the audit
store).

**Tabs.** One per connection known to ``app.connection_store``, in that store's own
``(engine, display_name)`` order; then one per ``connection_id`` ``audit.db`` still holds
rows for but ``connections.db`` no longer does — DESIGN-DATA-MODEL.md §5.3's "audit rows
are never deleted when a connection is deleted", so a deleted connection's tab is
labelled from the denormalised ``_connection`` name its own rows carry (§5.4), as
``«name» (deleted)``, or ``Connection #<id> (deleted)`` where no row carries a name; then,
last, a **System** tab for the rows whose ``connection_id`` is ``NULL`` — tools that touch
no connection at all (``list-connections``, a server status check), which §5.2 says exist
and which no per-connection tab could ever show. A tab is only ever added when there is
something for it to show: a fresh ``audit.db`` with no rows and no connections configured
renders the honest empty state, not an empty System tab nobody asked for.

**The ``decision`` column is the point of the page.** ``allowed``/``denied``/``refused``/
``error`` are given a distinct glyph *and* colour each — never colour alone, so the
distinction survives a colour-blind operator or a monochrome print — because ``denied``
("a permission rule said no") and ``refused`` ("a human declined the confirmation modal,
or nobody was watching") are different findings a security review needs to tell apart
(DESIGN-DATA-MODEL.md §5.2).

**CSV export is the one place d-MCP writes evidence out of the application.** Every cell
is passed through :func:`_csv_safe` first: ``audit.db`` holds tool arguments and error
text verbatim, including whatever an LLM or a hostile caller supplied, and a cell that
begins ``=``, ``+``, ``-``, ``@``, a tab or a carriage return is a live formula the
instant Excel, LibreOffice Calc or Google Sheets opens the file — OWASP's CSV-injection
guidance lists all six, since Excel strips a leading tab or carriage return before it
ever looks at what follows. Such a cell is prefixed with a single quote, which every one
of those applications renders as a leading apostrophe and reads as plain text rather than
a formula — the standard mitigation for this class of injection, applied to every column,
not only the ones a human is likely to have typed. A leading space is deliberately left
alone: unlike a tab or carriage return, no mainstream spreadsheet application strips it,
so `` =1+1`` is read as the literal text it looks like, and quoting it would only add
noise to a cell nothing was ever going to execute.

**Column widths, the 500 ms poll and the success/error colour pairs are f-MCP's, kept.**
Column widths persist through a debounced 300 ms ``QTimer`` (house style), shared across
every tab's table since they all have the same six columns. The poll timer re-derives the
tab set and refreshes the visible tab every 500 ms by default, from
``config.json``'s ``logs.poll_interval_ms`` (floor 200 ms, ceiling 10 000 ms,
DESIGN-DATA-MODEL.md §9.2); switching tabs refreshes the newly visible one immediately
rather than waiting for the next tick.
"""

from __future__ import annotations

import csv
import logging
from datetime import datetime
from pathlib import Path

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    ACTION_DDL,
    ACTION_DELETE,
    ACTION_GRANT,
    ACTION_INSERT,
    ACTION_SELECT,
    ACTION_UPDATE,
    COLOR_INFO,
    COLOR_WARNING,
    DARK_TEXT_SECONDARY,
    LIGHT_TEXT_SECONDARY,
)

logger = logging.getLogger(__name__)

# f-MCP's success/error text-colour pairs (application.qss's semantic tokens),
# kept identical rather than re-derived, per the task brief.
_SUCCESS_COLOUR = {"dark": QColor("#8FD8B7"), "light": QColor("#0F5C3C")}
_ERROR_COLOUR = {"dark": QColor("#F0A6AA"), "light": QColor("#842126")}

_LOG_COLUMNS = 6  # timestamp, tool, decision, rows, duration, result/error
_DECISIONS = ("allowed", "denied", "refused", "error")

# One glyph per decision, so "denied" and "refused" are told apart without relying on
# colour alone — see the module docstring. Unicode, not an icon asset: it must render
# correctly inside a plain QTableWidgetItem and survive a CSV export untouched.
_DECISION_GLYPH = {
    "allowed": "✓",  # check mark
    "denied": "⛔",   # no entry
    "refused": "✋",  # raised hand
    "error": "✕",    # multiplication x
}

# Tool name -> database-verb hue (DEVELOPMENT-PLAN.md's ACTION_* vocabulary), the same
# mapping ConfirmationDialog and NewRuleDialog use for the same verbs elsewhere in the
# GUI. A closed map over exactly the thirty-eight tools mcp_server.py's TOOLS registers —
# a name this page has not been taught about yet is left in the theme's own secondary
# text colour rather than guessed at, since this is a readability aid, not a security
# signal. Coverage of every registered name is pinned by
# test_logs_page.py::test_every_registered_tool_has_a_colour, parametrised over
# ``sape_d_mcp.mcp_server.TOOLS`` itself rather than over a hand-typed count, so this
# comment is a courtesy, not the thing that actually catches drift.
_TOOL_COLOUR: dict[str, QColor] = {
    "list-connections": ACTION_SELECT,
    "show-permissions": ACTION_SELECT,
    "read-catalogue": ACTION_SELECT,
    "list-schemas": ACTION_SELECT,
    "list-roles": ACTION_SELECT,
    "list-users": ACTION_SELECT,
    "list-groups": ACTION_SELECT,
    "list-tables": ACTION_SELECT,
    "describe-table": ACTION_SELECT,
    "select-rows": ACTION_SELECT,
    "list-views": ACTION_SELECT,
    "read-view-definition": ACTION_SELECT,
    "select-view-rows": ACTION_SELECT,
    "list-functions": ACTION_SELECT,
    "read-function-definition": ACTION_SELECT,
    "list-procedures": ACTION_SELECT,
    "read-procedure-definition": ACTION_SELECT,
    "run-read-query": ACTION_SELECT,
    "insert-rows": ACTION_INSERT,
    "update-rows": ACTION_UPDATE,
    "delete-rows": ACTION_DELETE,
    "create-table": ACTION_DDL,
    "drop-table": ACTION_DDL,
    "create-view": ACTION_DDL,
    "drop-view": ACTION_DDL,
    "create-function": ACTION_DDL,
    "edit-function": ACTION_DDL,
    "drop-function": ACTION_DDL,
    "create-procedure": ACTION_DDL,
    "edit-procedure": ACTION_DDL,
    "drop-procedure": ACTION_DDL,
    "create-role": ACTION_GRANT,
    "create-user": ACTION_GRANT,
    "create-group": ACTION_GRANT,
    "add-user-to-group": ACTION_GRANT,
    "remove-user-from-group": ACTION_GRANT,
    "assign-role": ACTION_GRANT,
    "revoke-role": ACTION_GRANT,
}

# CSV/spreadsheet-formula-injection guard: a cell whose FIRST character is one of these
# is read as a formula, not as text, by Excel, LibreOffice Calc and Google Sheets alike —
# OWASP's CSV-injection guidance names all six: the four printable formula sigils, plus a
# leading tab (0x09) and carriage return (0x0D), because Excel discards those two before it
# ever decides whether what follows is a formula. A leading SPACE is deliberately absent:
# no mainstream spreadsheet strips it, so a cell beginning " =1+1" reads as literal text in
# every one of them, and quoting it would only add noise to a cell nothing was ever going
# to execute.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _csv_safe(value: object) -> str:
    """Defuse one CSV cell against spreadsheet formula injection.

    ``audit.db`` holds tool arguments and error text verbatim — including whatever an
    LLM, or a hostile caller upstream of it, supplied — and this export is the one place
    that text leaves d-MCP as a file a human is likely to open directly in a spreadsheet
    application. A cell beginning ``=``, ``+``, ``-``, ``@``, a tab or a carriage return is
    then a live formula, not inert text: ``=1+1``, or a crafted ``=WEBSERVICE(...)``/DDE
    payload, executes the moment the file is opened — the tab and carriage return are on
    OWASP's list precisely because Excel strips them before it looks at the first visible
    character, so a cell that *looks* like it starts with an error message can still open
    as a formula. The mitigation is to prefix such a cell with a single quote, which every
    mainstream spreadsheet application renders as a leading apostrophe and treats as plain
    text — applied here to every column of the export, not only the ones a human is likely
    to have typed, since ``params_json``-derived text can appear in the tool name, the
    result and the error columns alike. A leading space is left alone: no mainstream
    spreadsheet strips it, so it is never itself the start of a formula.
    """
    text = str(value)
    if text[:1] in _CSV_FORMULA_PREFIXES:
        return "'" + text
    return text


class LogsPage(QWidget):
    """Per-connection audit log tabs over ``audit.db``, filterable, with CSV export."""

    def __init__(self, app=None):
        super().__init__()
        self.app = app
        self._theme = "light"
        self._saving_widths = False
        # (kind, id) pairs for the tabs currently on screen, so a poll tick that finds
        # nothing new can update labels/rows in place rather than tearing the widgets
        # down — which would lose the current selection and any in-flight resize.
        self._tab_keys: list[tuple[str, int | None]] = []

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

        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        self.tool_filter_edit = QLineEdit()
        self.tool_filter_edit.textChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.tool_filter_edit)

        self.decision_filter_combo = QComboBox()
        self.decision_filter_combo.currentIndexChanged.connect(self._on_filter_changed)
        filter_row.addWidget(self.decision_filter_combo)

        self.denied_only_checkbox = QCheckBox()
        self.denied_only_checkbox.toggled.connect(self._on_denied_only_toggled)
        filter_row.addWidget(self.denied_only_checkbox)

        filter_row.addStretch()

        self.export_button = QPushButton()
        self.export_button.clicked.connect(self._on_export)
        filter_row.addWidget(self.export_button)

        layout.addLayout(filter_row)

        self.tabs = QTabWidget()
        self.tabs.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.tabs, 1)

        self.empty_label = QLabel()
        self.empty_label.setWordWrap(True)
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setVisible(False)
        layout.addWidget(self.empty_label)

        # Parented to self, per the house rule "parent every QTimer" — an unparented one
        # is f-MCP defect 9 and is garbage-collected before it ever fires.
        self._column_save_timer = QTimer(self)
        self._column_save_timer.setSingleShot(True)
        self._column_save_timer.timeout.connect(self._save_column_widths)

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._on_poll)
        self._apply_poll_interval()
        self._poll_timer.start()

        if self.app:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        self._sync_denied_only_checkbox()
        self._update_language(self.app.current_language if self.app else "en-US")
        self._update_theme(self.app.current_theme if self.app else "light")

    # -- helpers ------------------------------------------------------------

    def _language(self) -> str:
        return self.app.current_language if self.app else "en-US"

    def _config_manager(self):
        return getattr(self.app, "config_manager", None) if self.app else None

    def _log_store(self):
        if self.app is None:
            return None
        try:
            return self.app.log_store
        except Exception as exc:  # pragma: no cover - defensive, unopenable audit.db
            logger.error("Could not open audit.db for the Logs page: %s", exc)
            return None

    def _secondary_colour(self) -> QColor:
        return DARK_TEXT_SECONDARY if self._theme == "dark" else LIGHT_TEXT_SECONDARY

    def _max_rows(self) -> int:
        config_manager = self._config_manager()
        if config_manager is None:
            return 1000
        try:
            return int(config_manager.get_logs_max_rows_displayed())
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("Could not read logs.max_rows_displayed: %s", exc)
            return 1000

    def _apply_poll_interval(self) -> None:
        config_manager = self._config_manager()
        interval = 500
        if config_manager is not None:
            try:
                interval = int(config_manager.get_logs_poll_interval_ms())
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not read logs.poll_interval_ms: %s", exc)
                interval = 500
        self._poll_timer.setInterval(interval)

    # -- tab set --------------------------------------------------------

    def _tab_specs(self, language: str) -> list[dict]:
        """The tabs that should exist right now, in display order.

        Real connections first, in ``ConnectionStore.all()``'s own order; then any
        connection ``audit.db`` still holds rows for but ``connections.db`` no longer
        does (DESIGN-DATA-MODEL.md §5.3); then, last, System — and only if there is a
        row for it to show, so a fresh installation with nothing logged yet renders no
        tabs at all rather than one that would sit empty forever.
        """
        specs: list[dict] = []
        if self.app is None:
            return specs

        try:
            connections = self.app.connection_store.all()
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.error("Could not load connections for the Logs page: %s", exc)
            connections = []

        live_ids: set[int] = set()
        for connection in connections:
            connection_id = int(connection["id"])
            live_ids.add(connection_id)
            specs.append(
                {"kind": "connection", "id": connection_id, "label": str(connection["display_name"])}
            )

        store = self._log_store()
        if store is None:
            return specs

        try:
            audited_ids = store.distinct_connection_ids()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Could not list audited connections: %s", exc)
            audited_ids = []

        for connection_id in sorted(i for i in audited_ids if i not in live_ids):
            name = store.latest_connection_name(connection_id)
            if name:
                label = translate("logs.tab_deleted_named", language).format(name=name)
            else:
                label = translate("logs.tab_deleted_unnamed", language).format(id=connection_id)
            specs.append({"kind": "deleted", "id": connection_id, "label": label})

        try:
            has_system = store.has_system_rows()
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Could not check for system audit rows: %s", exc)
            has_system = False
        if has_system:
            specs.append({"kind": "system", "id": None, "label": translate("logs.tab_system", language)})

        return specs

    def _tab_tooltip(self, spec: dict, language: str) -> str:
        if spec["kind"] == "system":
            return translate("logs.tab_system_tooltip", language)
        return ""

    def _rebuild_tabs(self, language: str) -> None:
        specs = self._tab_specs(language)
        keys = [(spec["kind"], spec["id"]) for spec in specs]

        if keys == self._tab_keys:
            # The same tabs still exist; only their labels (language) or their rows
            # (poll) might have changed, so update in place rather than rebuilding —
            # rebuilding would lose the current selection and any in-progress resize.
            for index, spec in enumerate(specs):
                self.tabs.setTabText(index, spec["label"])
                self.tabs.setTabToolTip(index, self._tab_tooltip(spec, language))
                table = self.tabs.widget(index)
                if isinstance(table, QTableWidget):
                    self._set_headers(table, language)
            self._update_empty_state(bool(specs))
            self._refresh_visible_tab(language)
            return

        previous_key: tuple[str, int | None] | None = None
        current = self.tabs.currentWidget()
        if isinstance(current, QTableWidget):
            previous_key = (current.property("kind"), current.property("connection_id"))

        self.tabs.blockSignals(True)
        self.tabs.clear()
        for spec in specs:
            table = self._build_table(spec, language)
            self.tabs.addTab(table, spec["label"])
            self.tabs.setTabToolTip(self.tabs.count() - 1, self._tab_tooltip(spec, language))
        self.tabs.blockSignals(False)

        self._tab_keys = keys
        self._update_empty_state(bool(specs))

        if previous_key is not None and previous_key in keys:
            self.tabs.setCurrentIndex(keys.index(previous_key))

        self._refresh_visible_tab(language)

    def _update_empty_state(self, has_tabs: bool) -> None:
        self.tabs.setVisible(has_tabs)
        self.empty_label.setVisible(not has_tabs)

    def _build_table(self, spec: dict, language: str) -> QTableWidget:
        table = QTableWidget()
        table.setObjectName("logsTable")
        table.setColumnCount(_LOG_COLUMNS)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.verticalHeader().setDefaultSectionSize(28)
        table.setProperty("kind", spec["kind"])
        table.setProperty("connection_id", spec["id"])
        self._set_headers(table, language)
        # A sensible first-time default, ahead of any persisted width — the widths
        # loaded immediately below take priority over this on every subsequent build.
        table.resizeColumnsToContents()
        table.horizontalHeader().sectionResized.connect(self._on_column_resized)
        self._load_column_widths(table)
        return table

    def _set_headers(self, table: QTableWidget, language: str) -> None:
        table.setHorizontalHeaderLabels([
            translate("logs.table_header_timestamp", language),
            translate("logs.table_header_tool", language),
            translate("logs.table_header_decision", language),
            translate("logs.table_header_rows", language),
            translate("logs.table_header_duration", language),
            translate("logs.table_header_result", language),
        ])

    # -- polling / row rendering ------------------------------------------

    def _on_poll(self) -> None:
        self._rebuild_tabs(self._language())

    def _on_tab_changed(self, _index: int) -> None:
        self._refresh_visible_tab(self._language())

    def _on_filter_changed(self, *_args) -> None:
        self._refresh_visible_tab(self._language())

    def _refresh_visible_tab(self, language: str) -> None:
        table = self.tabs.currentWidget()
        if isinstance(table, QTableWidget):
            self._refresh_table(table, language)

    def _rows_for(self, table: QTableWidget) -> list[dict]:
        store = self._log_store()
        if store is None:
            return []
        kind = table.property("kind")
        connection_id = table.property("connection_id")
        max_rows = self._max_rows()
        try:
            if kind == "system":
                return store.get_system_logs(limit=max_rows)
            return store.get_logs(connection_id=connection_id, limit=max_rows)
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("Could not read audit.db for the Logs page: %s", exc)
            return []

    def _filtered(self, rows: list[dict]) -> list[dict]:
        tool_needle = self.tool_filter_edit.text().strip().lower()
        decision = self.decision_filter_combo.currentData()
        if self.denied_only_checkbox.isChecked():
            decision = "denied"
        result = rows
        if tool_needle:
            result = [r for r in result if tool_needle in str(r["tool_name"]).lower()]
        if decision:
            result = [r for r in result if r["decision"] == decision]
        return result

    def _refresh_table(self, table: QTableWidget, language: str) -> None:
        rows = self._filtered(self._rows_for(table))

        table.setRowCount(len(rows))
        for row_index, entry in enumerate(rows):
            table.setItem(row_index, 0, QTableWidgetItem(str(entry["timestamp"])))

            tool_item = QTableWidgetItem(str(entry["tool_name"]))
            tool_item.setForeground(_TOOL_COLOUR.get(entry["tool_name"], self._secondary_colour()))
            table.setItem(row_index, 1, tool_item)

            decision = entry["decision"]
            glyph = _DECISION_GLYPH.get(decision, "")
            decision_text = f"{glyph} {translate(f'logs.decision_{decision}', language)}".strip()
            decision_item = QTableWidgetItem(decision_text)
            decision_item.setForeground(self._decision_colour(decision))
            if decision in ("denied", "refused"):
                # Bold as well as its own colour and glyph: three independent signals
                # for the one distinction ("the rules said no" vs "a human said no")
                # the whole decision column exists to make legible at a glance.
                font = decision_item.font()
                font.setBold(True)
                decision_item.setFont(font)
                decision_item.setToolTip(translate(f"logs.decision_{decision}_tooltip", language))
            table.setItem(row_index, 2, decision_item)

            rows_affected = entry["rows_affected"]
            rows_item = QTableWidgetItem("—" if rows_affected is None else str(rows_affected))
            rows_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            table.setItem(row_index, 3, rows_item)

            duration = entry["duration_ms"]
            duration_item = QTableWidgetItem("—" if duration is None else f"{duration} ms")
            duration_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            table.setItem(row_index, 4, duration_item)

            message = entry["result"] if entry["error"] is None else entry["error"]
            message_item = QTableWidgetItem(message or "")
            message_item.setForeground(self._decision_colour(decision))
            message_item.setToolTip(message or "")
            table.setItem(row_index, 5, message_item)

    def _decision_colour(self, decision: str) -> QColor:
        if decision == "allowed":
            return _SUCCESS_COLOUR[self._theme]
        if decision == "error":
            return _ERROR_COLOUR[self._theme]
        if decision == "denied":
            return COLOR_WARNING
        if decision == "refused":
            return COLOR_INFO
        return self._secondary_colour()  # pragma: no cover - decision is a closed domain

    # -- filters ----------------------------------------------------------

    def _sync_denied_only_checkbox(self) -> None:
        config_manager = self._config_manager()
        denied_only = False
        if config_manager is not None:
            try:
                denied_only = bool(config_manager.get_logs_denied_only())
            except Exception as exc:  # pragma: no cover - defensive, no store yet
                logger.debug("Could not read logs.denied_only: %s", exc)
        self.denied_only_checkbox.blockSignals(True)
        self.denied_only_checkbox.setChecked(denied_only)
        self.denied_only_checkbox.blockSignals(False)
        self.decision_filter_combo.setEnabled(not denied_only)

    def _on_denied_only_toggled(self, checked: bool) -> None:
        config_manager = self._config_manager()
        if config_manager is not None:
            try:
                config_manager.set_logs_denied_only(checked)
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not save logs.denied_only: %s", exc)

        self.decision_filter_combo.setEnabled(not checked)
        if checked:
            index = self.decision_filter_combo.findData("denied")
            if index >= 0:
                self.decision_filter_combo.blockSignals(True)
                self.decision_filter_combo.setCurrentIndex(index)
                self.decision_filter_combo.blockSignals(False)

        self._refresh_visible_tab(self._language())

    # -- column width persistence, shared by every tab's table -------------

    def _on_column_resized(self, *_args) -> None:
        self._column_save_timer.stop()
        self._column_save_timer.start(300)

    def _load_column_widths(self, table: QTableWidget) -> None:
        config_manager = self._config_manager()
        if config_manager is None or self._saving_widths:
            return
        self._saving_widths = True
        try:
            widths = config_manager.get_logs_table_columns() or {}
            for column_str, width in widths.items():
                try:
                    column = int(column_str)
                except (TypeError, ValueError):
                    continue
                if 0 <= column < table.columnCount():
                    table.setColumnWidth(column, int(width))
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not load Logs table column widths: %s", exc)
        finally:
            self._saving_widths = False

    def _save_column_widths(self) -> None:
        config_manager = self._config_manager()
        table = self.tabs.currentWidget()
        if config_manager is None or self._saving_widths or not isinstance(table, QTableWidget):
            return
        self._saving_widths = True
        try:
            widths = {str(i): table.columnWidth(i) for i in range(table.columnCount())}
            config_manager.set_logs_table_columns(widths)
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not save Logs table column widths: %s", exc)
            return
        finally:
            self._saving_widths = False
        self._apply_column_widths_to_all_tabs(widths)

    def _apply_column_widths_to_all_tabs(self, widths: dict[str, int]) -> None:
        """Keep every tab's table in step, since they share one set of widths.

        Only the tab a user actually resizes fires ``sectionResized``; without this the
        other tabs would keep whatever width they were built with until the tab set is
        next rebuilt, which could be a long wait on a quiet connection.
        """
        for index in range(self.tabs.count()):
            table = self.tabs.widget(index)
            if not isinstance(table, QTableWidget):
                continue
            header = table.horizontalHeader()
            header.blockSignals(True)
            for column_str, width in widths.items():
                try:
                    column = int(column_str)
                except (TypeError, ValueError):
                    continue
                if 0 <= column < table.columnCount():
                    table.setColumnWidth(column, int(width))
            header.blockSignals(False)

    # -- CSV export ---------------------------------------------------------

    def _on_export(self) -> None:
        language = self._language()
        table = self.tabs.currentWidget()
        if not isinstance(table, QTableWidget):
            return

        rows = self._filtered(self._rows_for(table))
        tab_index = self.tabs.currentIndex()
        tab_label = self.tabs.tabText(tab_index) if tab_index >= 0 else ""

        config_manager = self._config_manager()
        default_dir = ""
        if config_manager is not None:
            try:
                default_dir = config_manager.get_logs_last_export_directory() or ""
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not read logs.last_export_directory: %s", exc)

        default_name = f"log_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        default_path = str(Path(default_dir) / default_name) if default_dir else default_name

        filename, _selected_filter = QFileDialog.getSaveFileName(
            self,
            translate("logs.export_dialog_title", language),
            default_path,
            translate("logs.export_dialog_filter", language),
        )
        if not filename:
            return

        try:
            with open(filename, "w", encoding="utf-8", newline="") as handle:
                writer = csv.writer(handle)
                writer.writerow([
                    translate("logs.table_header_connection", language),
                    translate("logs.export_csv_header_session", language),
                    translate("logs.table_header_timestamp", language),
                    translate("logs.table_header_tool", language),
                    translate("logs.table_header_decision", language),
                    translate("logs.table_header_rows", language),
                    translate("logs.table_header_duration", language),
                    translate("logs.table_header_result", language),
                    translate("logs.export_csv_header_matched_rule", language),
                ])
                for entry in rows:
                    message = entry["result"] if entry["error"] is None else entry["error"]
                    writer.writerow([
                        _csv_safe(tab_label),
                        _csv_safe(entry["session_id"]),
                        _csv_safe(entry["timestamp"]),
                        _csv_safe(entry["tool_name"]),
                        _csv_safe(entry["decision"]),
                        entry["rows_affected"] if entry["rows_affected"] is not None else "",
                        entry["duration_ms"] if entry["duration_ms"] is not None else "",
                        _csv_safe(message or ""),
                        entry["matched_rule_id"] if entry["matched_rule_id"] is not None else "",
                    ])
        except OSError as exc:
            logger.error("Failed to export log: %s", exc)
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle(translate("logs.export_error_title", language))
            box.setText(f"{translate('logs.export_error_message', language)}\n{exc}")
            box.addButton(translate("common.ok", language), QMessageBox.ButtonRole.AcceptRole)
            box.exec()
            return

        if config_manager is not None:
            try:
                config_manager.set_logs_last_export_directory(str(Path(filename).resolve().parent))
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("Could not save logs.last_export_directory: %s", exc)

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Information)
        box.setWindowTitle(translate("logs.export_success_title", language))
        box.setText(f"{translate('logs.export_success_message', language)}\n{filename}")
        box.addButton(translate("common.ok", language), QMessageBox.ButtonRole.AcceptRole)
        box.exec()

    # -- i18n / theming ----------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.title.setText(translate("logs.title", language))
        self.subtitle.setText(translate("logs.subtitle", language))
        self.tool_filter_edit.setPlaceholderText(translate("logs.filter_placeholder", language))

        current_decision = self.decision_filter_combo.currentData()
        self.decision_filter_combo.blockSignals(True)
        self.decision_filter_combo.clear()
        self.decision_filter_combo.addItem(translate("logs.decision_all", language), None)
        for decision in _DECISIONS:
            glyph = _DECISION_GLYPH.get(decision, "")
            text = f"{glyph} {translate(f'logs.decision_{decision}', language)}".strip()
            self.decision_filter_combo.addItem(text, decision)
        index = self.decision_filter_combo.findData(current_decision)
        self.decision_filter_combo.setCurrentIndex(max(index, 0))
        self.decision_filter_combo.blockSignals(False)

        self.denied_only_checkbox.setText(translate("logs.denied_only_label", language))
        self.denied_only_checkbox.setToolTip(translate("logs.denied_only_tooltip", language))

        self.export_button.setText(translate("logs.export_button", language))
        self.empty_label.setText(translate("logs.no_logs", language))

        self._rebuild_tabs(language)

    def _update_theme(self, theme: str) -> None:
        self._theme = theme
        colour = DARK_TEXT_SECONDARY if theme == "dark" else LIGHT_TEXT_SECONDARY
        self.subtitle.setStyleSheet(f"color: {colour.name()};")
        self.empty_label.setStyleSheet(f"color: {colour.name()};")
        self._refresh_visible_tab(self._language())
