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

"""Permissions page — connection selector, schema browser and the rule table.

The Explorer page f-MCP would have had is folded in here as the left-hand
schema browser (DEVELOPMENT-PLAN.md's confirmed decision), so the object and
the rule that covers it are seen side by side and there is only one tree to
keep in sync.

Everything on the right is backed by ``app.permission_store`` (a real
``PermissionStore`` over ``permissions.db``) and needs only a connection id —
it never has to reach the live database. The left-hand tree is the one part
that does: it comes from ``Introspector`` over a real connection, opened on a
background ``QThread`` so a slow or unreachable server never freezes the
window, and is rendered honestly for every state that can happen — no
connection selected, a connection whose driver is missing, one that will not
connect, and a schema that connects fine but has nothing in it.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt, QThread, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.db.credential_store import CredentialError
from sape_d_mcp.db.engine import connect, test_connection
from sape_d_mcp.db.introspection import Introspector, RoutineEntry
from sape_d_mcp.gui.dialogs.new_rule_dialog import NewRuleDialog
from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.pages._sample_data import (
    SAMPLE_CONNECTIONS,
    SAMPLE_PERMISSION_RULES,
    SAMPLE_SCHEMA_TREE,
)
from sape_d_mcp.gui.styles.sape_design_tokens import (
    ACTION_EXECUTE,
    ACTION_GRANT,
    ACTION_SELECT,
    COLOR_ERROR,
    COLOR_SUCCESS,
    DARK_TEXT_SECONDARY,
    LIGHT_TEXT_SECONDARY,
    SAPE_GRAPHITE_LIGHT,
    SAPE_PRIMARY,
)
from sape_d_mcp.permissions import (
    ACTIONS_BY_TYPE,
    DATABASE_TYPE,
    FORBIDDEN_ACTIONS,
    OBJECT_TYPES,
    database_scope_ref,
)

logger = logging.getLogger(__name__)

#: Name, objects, object type, effect, actions, created, user, edit.  Eight since
#: schema version 3 added ``rules.rule_name`` -- the operator's own label for what a
#: rule is *for*, which the objects/type/effect columns alone could not say. It leads
#: the row, the same reason it leads the New/Edit Rule dialog's form: it is what a
#: human reads first. (Version 2 merged the old Schema and Name-pattern columns into
#: one Objects column, which is why this is eight rather than nine.)
_RULE_TABLE_COLUMNS = 8

#: How many of a rule's objects the Objects cell spells out before it summarises the
#: rest as "(+n)".  The full list is always on the cell's tooltip, so this trades
#: nothing but the width of a column the operator can drag.
_OBJECTS_SHOWN = 2

#: The tree's own object-type nodes: every object type except ``database``,
#: which is the fixed "Database and security" section below, never a tree
#: branch. Derived from ``OBJECT_TYPES`` itself, exactly as
#: ``new_rule_dialog.OBJECT_TYPES`` is, rather than restated as a second,
#: hand-written list that a fifth object type could land in one of and not
#: the other.
_TREE_OBJECT_TYPES: tuple[str, ...] = tuple(t for t in OBJECT_TYPES if t != DATABASE_TYPE)

# The "Database and security" section's own category grouping and colouring —
# a small, fixed echo of NewRuleDialog's, since its action set never changes
# and never appears in that dialog's own combo (DESIGN-PERMISSIONS.md §5.6).
_DB_SECURITY_CATEGORY: dict[str, str] = {
    "read_catalogue": "read",
    "run_query": "execute",
    "create_role": "grant", "create_user": "grant", "create_group": "grant",
    "assign_group": "grant", "assign_role": "grant",
}
_DB_SECURITY_CATEGORY_ORDER: tuple[str, ...] = ("read", "execute", "grant")
_DB_SECURITY_CATEGORY_COLOUR = {
    "read": ACTION_SELECT, "execute": ACTION_EXECUTE, "grant": ACTION_GRANT,
}
_DB_SECURITY_CATEGORY_TRANSLATION_KEY = {
    "read": "permissions.category_read",
    "execute": "permissions.category_execute",
    "grant": "permissions.category_grant",
}


def _sample_pattern_specificity(pattern: str, value: str) -> int | None:
    """Score how specifically ``pattern`` matches ``value``, or ``None``.

    Exact beats prefix beats wildcard, mirroring the resolution order in
    ``docs/DESIGN-PERMISSIONS.md``. Used only for the sample-data schema
    fixture, which carries plain strings rather than a ``NormalisedRef`` —
    real objects are covered by ``PermissionStore.rule_for()`` instead, in
    ``PermissionsPage._object_covered()``.
    """
    if pattern == value:
        return 2
    if pattern == "*":
        return 0
    if pattern.endswith("*") and value.startswith(pattern[:-1]):
        return 1
    return None


def _sample_object_is_covered(rules: list[dict], connection_id: int, schema: str,
                               object_type: str, name: str) -> bool:
    """Whether some allow rule covers this sample-fixture object.

    The mock counterpart of ``PermissionStore.rule_for()`` for the sample
    schema tree, which has no real ``NormalisedRef`` to resolve against.
    """
    best_key: tuple[int, int] | None = None
    best_rule: dict | None = None
    for rule in rules:
        if rule["connection_id"] != connection_id or rule["object_type"] != object_type:
            continue
        # A rule names a collection, so the mock resolver scores every target and
        # keeps the narrowest that matches -- the same "a rule's specificity at an
        # object is its narrowest matching target" rule PermissionStore.rule_for()
        # applies, kept in step here so the mockup's padlocks do not disagree with the
        # real screen's.
        key = None
        for target in _rule_object_targets(rule):
            schema_score = _sample_pattern_specificity(target["schema_pattern"], schema)
            name_score = _sample_pattern_specificity(target["name_pattern"], name)
            if schema_score is None or name_score is None:
                continue
            candidate = (schema_score, name_score)
            if key is None or candidate > key:
                key = candidate
        if key is None:
            continue
        if best_key is None or key > best_key or (
                key == best_key and rule["is_deny"] and best_rule and not best_rule["is_deny"]):
            best_key, best_rule = key, rule
    if best_rule is None:
        return False
    if best_rule["is_deny"]:
        return False
    # ADR 0005: 'drop' and 'edit' can never be granted by any rule, so a rule
    # naming only forbidden actions covers nothing -- the padlock this mock
    # tree draws must agree with the real tree's _object_covered(), which
    # excludes the same set, or the sample screen and the live screen would
    # contradict each other about a rule that grants nothing real.
    return any(
        granted for action, granted in best_rule["actions"].items()
        if action not in FORBIDDEN_ACTIONS
    )


class _SchemaLoadWorker(QThread):
    """Connects and introspects one connection's whole catalogue off the GUI thread.

    A dead host can take the whole connect timeout to answer, and each of the
    ``list_*`` calls below is its own round trip — running this from a button
    handler or a combo box signal would freeze the entire window, not just
    the tree, for however long the server takes to answer or fail. Mirrors
    ``ConnectionsPage``'s ``_ConnectionTestWorker`` in shape and in never
    letting the password outlive the run.
    """

    completed = pyqtSignal(int, object)  # connection_id, {"ok": bool, ...}

    def __init__(self, connection_id: int, profile: dict, password: str | None,
                 parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._connection_id = connection_id
        self._profile = profile
        self._password = password

    def run(self) -> None:
        try:
            with connect(self._profile, self._password) as db:
                introspector = Introspector(db)
                schemas: dict[str, dict] = {}
                for schema_entry in introspector.list_schemas():
                    name = schema_entry.canonical_name
                    schemas[name] = {
                        "entry": schema_entry,
                        "table": introspector.list_tables(name),
                        "view": introspector.list_views(name),
                        "function": introspector.list_functions(name),
                        "procedure": introspector.list_procedures(name),
                    }
        except Exception as exc:
            # test_connection() classifies the failure and renders the same
            # sentence the Connections page's Test button would show, so a
            # connection that will not connect reads identically everywhere
            # in the application rather than getting a second, ad hoc wording
            # here.
            result = test_connection(self._profile, self._password)
            message = result.error or str(exc)
            self.completed.emit(self._connection_id, {"ok": False, "error": message})
            return
        self.completed.emit(self._connection_id, {"ok": True, "schemas": schemas})


def _rule_object_targets(rule: dict) -> list[dict]:
    """A rule's target dicts, accepting either shape a caller can hold.

    One place, so ``_rule_object_labels`` (which renders them) and
    ``_sample_object_is_covered`` (which matches them) can never disagree about what
    a rule reaches.
    """
    targets = rule.get("targets")
    if targets:
        return list(targets)
    if rule.get("schema_pattern") and rule.get("name_pattern"):
        return [{"schema_pattern": rule["schema_pattern"], "name_pattern": rule["name_pattern"]}]
    return []


def _rule_object_labels(rule: dict) -> list[str]:
    """Every object a rule names, as ``schema.name``, in the order it is stored.

    Reads the ``targets`` list that ``PermissionStore.rules()`` attaches, and falls
    back to the two scalar keys so the sample-data fixtures and any single-target
    payload still render -- the same two shapes ``permissions.format_rule()`` accepts,
    settled the same way rather than twice differently.
    """
    return [
        f"{t['schema_pattern']}.{t['name_pattern']}" for t in _rule_object_targets(rule)
    ]


def _summarise_objects(labels: list[str]) -> str:
    """``dbo.A, dbo.B (+3)`` -- what fits in a column, with the count of what does not.

    The cell summarises and the tooltip carries the full list, because a rule over
    forty tables has to be *identifiable* in one row without the row becoming
    unreadable, and the operator's question at that point is "which rule is this",
    not "name every table".
    """
    if not labels:
        return ""
    shown = ", ".join(labels[:_OBJECTS_SHOWN])
    remaining = len(labels) - _OBJECTS_SHOWN
    return f"{shown} (+{remaining})" if remaining > 0 else shown


class PermissionsPage(QWidget):
    """Connection selector, schema browser and permission rule editor."""

    def __init__(self, app=None):
        super().__init__()
        self.app = app
        self._connections: list[dict] = []
        self._real_mode = False
        self._current_connection_id: int | None = None

        self._rules: list[dict] = []

        # The catalogue cache for the currently selected connection: filled
        # by _SchemaLoadWorker, kept until the connection changes or Refresh
        # is pressed, and re-rendered (never re-fetched) after a grant/deny/
        # revoke so the lock glyphs update without another round trip to the
        # live database.
        self._tree_entries: dict[str, dict] = {}
        self._tree_loading = False
        self._tree_error: str | None = None
        self._tree_worker: _SchemaLoadWorker | None = None
        # Set when a load was requested while another was already in flight
        # (defect: three quick combo changes starting three concurrent
        # workers) — _on_tree_load_finished() replays it once the worker
        # holding the connection is actually free.
        self._tree_pending_load = False

        self._db_checkboxes: dict[str, QCheckBox] = {}
        self._db_category_headers: dict[str, QLabel] = {}
        self._loading_db_state = False

        self._saving_widths = False
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

        connection_row = QHBoxLayout()
        self.connection_label = QLabel()
        connection_row.addWidget(self.connection_label)
        self.connection_combo = QComboBox()
        self.connection_combo.currentIndexChanged.connect(self._on_connection_changed)
        connection_row.addWidget(self.connection_combo, 1)
        connection_row.addStretch()
        layout.addLayout(connection_row)

        splitter = QSplitter(Qt.Orientation.Horizontal)

        # -- left: schema browser -----------------------------------------
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        self.tree_title = QLabel()
        left_layout.addWidget(self.tree_title)

        self.tree = QTreeWidget()
        self.tree.setHeaderHidden(True)
        # Several objects, one rule -- the whole point of schema version 2. Ctrl- and
        # shift-click build the collection here and "New rule from selection" carries
        # the lot into the dialog, rather than making the operator write one rule per
        # table and keep the action sets in step by hand.
        self.tree.setSelectionMode(QTreeWidget.SelectionMode.ExtendedSelection)
        # itemSelectionChanged, not currentItemChanged. With ExtendedSelection the two
        # are different events: a shift-click range, a rubber-band drag and Ctrl+A all
        # change *what is selected* while moving the current item once or not at all.
        # Listening on the wrong one left the button's enabled state describing a
        # selection that was no longer there -- which is how "New rule from selection"
        # came to look ready and then do nothing.
        self.tree.itemSelectionChanged.connect(self._on_tree_selection_changed)
        left_layout.addWidget(self.tree, 1)

        self.tree_empty_label = QLabel()
        self.tree_empty_label.setWordWrap(True)
        self.tree_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tree_empty_label.setVisible(False)
        # Same stretch factor as self.tree — see connections_page.py's own
        # empty_label for why a stretch-less label here would strand its
        # message below whatever this pane's empty state left growing above it.
        left_layout.addWidget(self.tree_empty_label, 1)

        splitter.addWidget(left_widget)

        # -- right: database-and-security section, then the rule table -----
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(8)

        self.db_security_group = QGroupBox()
        db_layout = QVBoxLayout(self.db_security_group)
        db_layout.setContentsMargins(12, 12, 12, 12)
        db_layout.setSpacing(6)
        for category in _DB_SECURITY_CATEGORY_ORDER:
            header = QLabel()
            header_font = QFont()
            header_font.setBold(True)
            header.setFont(header_font)
            header.setStyleSheet(f"color: {_DB_SECURITY_CATEGORY_COLOUR[category].name()};")
            db_layout.addWidget(header)
            self._db_category_headers[category] = header

            grid = QGridLayout()
            grid.setSpacing(6)
            grid.setContentsMargins(12, 0, 0, 0)
            actions_in_category = [
                a for a in ACTIONS_BY_TYPE[DATABASE_TYPE] if _DB_SECURITY_CATEGORY[a] == category
            ]
            for col_index, action in enumerate(actions_in_category):
                checkbox = QCheckBox()
                checkbox.setStyleSheet(f"color: {_DB_SECURITY_CATEGORY_COLOUR[category].name()};")
                checkbox.toggled.connect(self._on_db_checkbox_toggled)
                self._db_checkboxes[action] = checkbox
                grid.addWidget(checkbox, col_index // 2, col_index % 2)
            db_layout.addLayout(grid)
        right_layout.addWidget(self.db_security_group)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        self.new_from_selection_button = QPushButton()
        self.new_from_selection_button.setStyleSheet(
            f"background-color: {SAPE_PRIMARY.name()}; color: white; font-weight: bold;")
        self.new_from_selection_button.setEnabled(False)
        self.new_from_selection_button.clicked.connect(self._on_new_from_selection)
        button_row.addWidget(self.new_from_selection_button)

        self.edit_rule_button = QPushButton()
        self.edit_rule_button.setEnabled(False)
        self.edit_rule_button.clicked.connect(self._on_edit_rule)
        button_row.addWidget(self.edit_rule_button)

        self.delete_rule_button = QPushButton()
        self.delete_rule_button.setEnabled(False)
        self.delete_rule_button.clicked.connect(self._on_delete_rule)
        button_row.addWidget(self.delete_rule_button)

        self.refresh_button = QPushButton()
        self.refresh_button.clicked.connect(self._on_refresh)
        button_row.addWidget(self.refresh_button)

        button_row.addStretch()
        right_layout.addLayout(button_row)

        self.rule_table = QTableWidget()
        self.rule_table.setColumnCount(_RULE_TABLE_COLUMNS)
        self.rule_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.rule_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.rule_table.verticalHeader().setDefaultSectionSize(36)
        self.rule_table.itemSelectionChanged.connect(self._on_rule_selection_changed)
        self.rule_table.horizontalHeader().sectionResized.connect(self._on_column_resized)
        right_layout.addWidget(self.rule_table, 1)

        self.rule_table_empty_label = QLabel()
        self.rule_table_empty_label.setWordWrap(True)
        self.rule_table_empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.rule_table_empty_label.setVisible(False)
        # Same stretch factor as self.rule_table — see connections_page.py's
        # own empty_label for why a stretch-less label here would strand its
        # message below whatever this pane's empty state left growing above it.
        right_layout.addWidget(self.rule_table_empty_label, 1)

        splitter.addWidget(right_widget)
        splitter.setStretchFactor(0, 2)
        splitter.setStretchFactor(1, 3)

        layout.addWidget(splitter, 1)

        if self.app:
            self.app.language_changed.connect(self._update_language)
            self.app.theme_manager.theme_changed.connect(self._update_theme)

        initial_language = self.app.current_language if self.app else "en-US"
        self._update_language(initial_language)
        self._update_theme(self.app.current_theme if self.app else "light")
        # The one legitimate reconnect: the very first render, before a
        # catalogue snapshot exists at all. _update_language() itself must
        # only re-render, never re-fetch (see its docstring) — a language
        # change re-opening the connection is what let a locked vault raise
        # a master-password prompt out of a broadcast signal nobody asked
        # for, on whichever page happened to be on screen at the time.
        self._start_or_render_tree(initial_language)

    # -- helpers ------------------------------------------------------------

    def _language(self) -> str:
        return self.app.current_language if self.app else "en-US"

    def _theme(self) -> str:
        return self.app.current_theme if self.app else "light"

    def _show_sample_data(self) -> bool:
        config_manager = getattr(self.app, "config_manager", None) if self.app else None
        if config_manager is None:
            return False
        try:
            return bool(config_manager.get_show_sample_data())
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not read show_sample_data: %s", exc)
            return False

    def _connections_list(self) -> list[dict]:
        if self.app is not None and not self._show_sample_data():
            try:
                return self.app.connection_store.all()
            except Exception as exc:
                logger.error("Could not load connections from connections.db: %s", exc)
                return []
        return list(SAMPLE_CONNECTIONS)

    def _connection_by_id(self, connection_id: int) -> dict | None:
        return next((c for c in self._connections if c.get("id") == connection_id), None)

    def _muted_colour(self):
        return DARK_TEXT_SECONDARY if self._theme() == "dark" else LIGHT_TEXT_SECONDARY

    def _show_message(self, icon, title_key: str, text: str, language: str) -> None:
        box = QMessageBox(self)
        box.setIcon(icon)
        box.setWindowTitle(translate(title_key, language))
        box.setText(text)
        box.addButton(translate("common.ok", language), QMessageBox.ButtonRole.AcceptRole)
        box.exec()

    def _ensure_unlocked(self, language: str) -> bool:
        """Prompt for the vault's master password if it is locked; see
        ``ConnectionsPage._ensure_unlocked()``, which this mirrors."""
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
                QMessageBox.Icon.Warning, "connections.vault_locked_title",
                translate("connections.wrong_master_password_message", language), language)
            return False
        return True

    # -- connection selection --------------------------------------------

    def _populate_connection_combo(self, language: str) -> None:
        previous = self._current_connection_id
        self._real_mode = self.app is not None and not self._show_sample_data()

        # Signals stay blocked through setCurrentIndex() too: every caller of
        # this method (__init__, _update_language, _on_refresh) always calls
        # _refresh_rules_and_tree() itself immediately afterwards, and a
        # signal fired from here as well would start a second, redundant
        # background schema-load thread racing the explicit one.
        self.connection_combo.blockSignals(True)
        try:
            self.connection_combo.clear()
            self._connections = self._connections_list()
            for connection in self._connections:
                self.connection_combo.addItem(connection["display_name"], connection["id"])
            if not self._connections:
                self.connection_combo.addItem(translate("connections.no_connections", language), None)

            if self._connections:
                index = self.connection_combo.findData(previous) if previous is not None else -1
                self.connection_combo.setCurrentIndex(index if index >= 0 else 0)
                self._current_connection_id = self.connection_combo.currentData()
            else:
                self._current_connection_id = None
        finally:
            self.connection_combo.blockSignals(False)

    def _on_connection_changed(self, *_args) -> None:
        self._current_connection_id = self.connection_combo.currentData()
        self._tree_entries = {}
        self._tree_error = None
        self._tree_loading = False
        self._refresh_rules_and_tree(self._language())

    def _refresh_rules_and_tree(self, language: str) -> None:
        """Reload everything for the current connection, including a live
        reconnect for the tree. Used on connection change and on Refresh —
        both are the operator explicitly asking to see the current state of
        a (possibly different) connection, which is the only time this page
        may open one."""
        self._build_rule_table(language)
        self._refresh_db_security_section(language)
        self._start_or_render_tree(language)

    def _render_rules_and_tree(self, language: str) -> None:
        """The render-only half of ``_refresh_rules_and_tree()``.

        The rule table and the database-and-security section are always
        cheap, local reads of ``permissions.db``; the tree's catalogue
        snapshot already held in ``self._tree_entries`` is reused rather
        than re-fetched. Used by ``_update_language()``, whose contract
        (DEVELOPMENT-PLAN.md) is to re-render on a broadcast signal, never
        to reconnect — a live schema load can reach ``_ensure_unlocked()``
        and raise a master-password prompt, which must never come out of a
        language change nobody asked for.
        """
        self._build_rule_table(language)
        self._refresh_db_security_section(language)
        self._render_tree(language)

    def _refresh_after_mutation(self, language: str) -> None:
        """Reflect a grant/deny/revoke that just happened, with no reconnect.

        The rule table always re-reads ``permissions.db`` — cheap, local,
        and the only source of truth for it — but the tree only needs its
        lock glyphs recomputed against the catalogue snapshot already held
        in ``self._tree_entries``.
        """
        self._build_rule_table(language)
        self._render_tree(language)

    # -- schema tree: loading ---------------------------------------------

    def _start_or_render_tree(self, language: str) -> None:
        connection_id = self._current_connection_id
        if connection_id is None or not self._real_mode:
            self._render_tree(language)
            return
        self._begin_tree_load(connection_id, language)

    def _begin_tree_load(self, connection_id: int, language: str) -> None:
        if self.app is None:
            return
        if self._tree_worker is not None and self._tree_worker.isRunning():
            # ConnectionsPage._on_test() refuses a second worker the same
            # way: three quick combo changes must not open three connections
            # concurrently, each holding a password and a live handle. The
            # in-flight worker's result will be for a connection the operator
            # has already left, so it is discarded as stale by
            # _on_tree_load_completed(); _on_tree_load_finished() retries
            # against whichever connection is actually current once the
            # worker is free.
            self._tree_pending_load = True
            self._tree_loading = True
            self._render_tree(language)
            return
        connection = self._connection_by_id(connection_id)
        if connection is None:
            self._tree_error = translate("connections.no_connections", language)
            self._render_tree(language)
            return

        password: str | None = None
        if connection.get("engine") != "sqlite":
            if not self._ensure_unlocked(language):
                self._tree_error = translate("connections.vault_locked_title", language)
                self._render_tree(language)
                return
            try:
                password = self.app.credential_store.get_password(connection_id)
            except CredentialError as exc:
                self._tree_error = str(exc)
                self._render_tree(language)
                return

        self._tree_loading = True
        self._tree_error = None
        self._render_tree(language)

        self._tree_worker = _SchemaLoadWorker(connection_id, dict(connection), password, self)
        self._tree_worker.completed.connect(self._on_tree_load_completed)
        self._tree_worker.finished.connect(self._on_tree_load_finished)
        self._tree_worker.start()

    def _on_tree_load_completed(self, connection_id: int, result: dict) -> None:
        if connection_id != self._current_connection_id:
            return  # stale: the user switched connections while this ran
        self._tree_loading = False
        if result.get("ok"):
            self._tree_entries = result.get("schemas", {})
            self._tree_error = None
        else:
            self._tree_entries = {}
            self._tree_error = result.get("error") or translate("common.error", self._language())
        self._render_tree(self._language())

    def _on_tree_load_finished(self) -> None:
        self._tree_worker = None
        if self._tree_pending_load:
            self._tree_pending_load = False
            self._start_or_render_tree(self._language())

    # -- schema tree: rendering ---------------------------------------------

    def _show_tree_message(self, text: str, *, error: bool) -> None:
        self.tree.setVisible(False)
        self.tree_empty_label.setVisible(True)
        self.tree_empty_label.setText(text)
        colour = COLOR_ERROR if error else self._muted_colour()
        self.tree_empty_label.setStyleSheet(f"color: {colour.name()};")

    def _render_tree(self, language: str) -> None:
        self.tree.clear()
        connection_id = self._current_connection_id

        if connection_id is None:
            self._show_tree_message(translate("permissions.explorer_empty", language), error=False)
            return

        if not self._real_mode:
            self._render_sample_tree(connection_id, language)
            return

        if self._tree_loading:
            self._show_tree_message(translate("common.loading", language), error=False)
            return

        if self._tree_error is not None:
            self._show_tree_message(self._tree_error, error=True)
            return

        total_objects = sum(
            len(info.get(object_type) or ())
            for info in self._tree_entries.values()
            for object_type in _TREE_OBJECT_TYPES
        )
        if not self._tree_entries or total_objects == 0:
            # A connection *is* selected here — it simply has nothing in it. Saying "select a
            # connection" at this point reads as though the click had not registered.
            self._show_tree_message(translate("permissions.explorer_no_objects", language), error=False)
            return

        self.tree.setVisible(True)
        self.tree_empty_label.setVisible(False)

        store = self.app.permission_store
        for schema_name, info in self._tree_entries.items():
            schema_entry = info["entry"]
            schema_item = QTreeWidgetItem([schema_name])
            if not schema_entry.addressable:
                schema_item.setForeground(0, SAPE_GRAPHITE_LIGHT)
                schema_item.setToolTip(0, schema_entry.unaddressable_reason or "")
            self.tree.addTopLevelItem(schema_item)
            for object_type in _TREE_OBJECT_TYPES:
                entries = info.get(object_type) or ()
                if not entries:
                    continue
                type_item = QTreeWidgetItem([translate(f"permissions.object_type_{object_type}", language)])
                schema_item.addChild(type_item)
                for entry in entries:
                    type_item.addChild(self._build_leaf_item(store, connection_id, object_type, entry))
        self.tree.expandAll()

    def _build_leaf_item(self, store, connection_id: int, object_type: str, entry) -> QTreeWidgetItem:
        if isinstance(entry, RoutineEntry) and entry.signature:
            name_display = f"{entry.canonical_name}({entry.signature})"
        else:
            name_display = entry.canonical_name

        if entry.ref is None:
            # Decision D6: a name that cannot be keyed at all. Shown, because
            # hiding an object the human can see in their own database is
            # worse than useless, but it can never be covered by a rule, so
            # it is greyed with the reason as a tooltip and carries no
            # selectable pattern data.
            item = QTreeWidgetItem([name_display])
            item.setForeground(0, SAPE_GRAPHITE_LIGHT)
            item.setToolTip(0, entry.unaddressable_reason or "")
            item.setData(0, Qt.ItemDataRole.UserRole, None)
            return item

        covered = self._object_covered(store, connection_id, entry.ref, object_type)
        label = name_display if covered else f"\U0001F512 {name_display}"
        item = QTreeWidgetItem([label])
        item.setData(0, Qt.ItemDataRole.UserRole, {
            # The *key* spelling, not the canonical one: PermissionStore
            # matches a pattern against ref.key_schema/key_name, not the
            # display spelling (DESIGN-DIALECTS.md, decision D5) — a bare
            # "*" is also the only pattern that can ever match a schema-less
            # ref, per PermissionStore._glob_match().
            "schema_pattern": entry.ref.key_schema or "*",
            "object_type": object_type,
            "name_pattern": entry.ref.key_name,
        })
        return item

    def _object_covered(self, store, connection_id: int, ref, object_type: str) -> bool:
        """The honest test: does some non-deny rule grant at least one action?

        Excludes ``FORBIDDEN_ACTIONS`` (ADR 0005): ``can_drop`` / ``can_edit`` can
        still read ``1`` on a hand-edited or pre-migration row, but neither is ever
        actually granted, so a rule carrying only those columns must leave the
        object **locked**, exactly like one carrying nothing at all -- drawing it
        unlocked would be this page showing more access than the resolver gives.
        Its mock twin, ``_sample_object_is_covered()`` above, excludes the same set
        so the sample tree and the live tree never disagree about what a rule
        covers.
        """
        try:
            rule = store.rule_for(connection_id, ref)
        except ValueError as exc:  # pragma: no cover - a malformed ref is a dialect bug
            logger.error("Could not resolve a rule for %r: %s", ref, exc)
            return False
        if rule is None or rule["is_deny"]:
            return False
        return any(
            bool(rule.get(f"can_{action}"))
            for action in ACTIONS_BY_TYPE[object_type]
            if action not in FORBIDDEN_ACTIONS
        )

    def _render_sample_tree(self, connection_id: int, language: str) -> None:
        schema_map = SAMPLE_SCHEMA_TREE.get(connection_id, {})
        if not schema_map:
            self._show_tree_message(translate("permissions.explorer_no_objects", language), error=False)
            return

        self.tree.setVisible(True)
        self.tree_empty_label.setVisible(False)

        rules = [r for r in SAMPLE_PERMISSION_RULES if r["connection_id"] == connection_id]
        for schema_name, by_type in schema_map.items():
            schema_item = QTreeWidgetItem([schema_name])
            self.tree.addTopLevelItem(schema_item)
            for object_type, names in by_type.items():
                type_item = QTreeWidgetItem([translate(f"permissions.object_type_{object_type}", language)])
                schema_item.addChild(type_item)
                for name in names:
                    covered = _sample_object_is_covered(rules, connection_id, schema_name, object_type, name)
                    label = name if covered else f"\U0001F512 {name}"
                    leaf = QTreeWidgetItem([label])
                    leaf.setData(0, Qt.ItemDataRole.UserRole, {
                        "schema_pattern": schema_name, "object_type": object_type, "name_pattern": name,
                    })
                    type_item.addChild(leaf)
        self.tree.expandAll()

    # -- database-and-security section --------------------------------------

    def _refresh_db_security_section(self, language: str) -> None:
        connection_id = self._current_connection_id
        enabled = self._real_mode and connection_id is not None and self.app is not None
        checked_actions: set[str] = set()

        if enabled:
            connection = self._connection_by_id(connection_id) or {}
            ref = database_scope_ref(str(connection.get("database") or ""))
            try:
                rule = self.app.permission_store.rule_for(connection_id, ref)
            except Exception as exc:
                logger.error("Could not read the database-and-security rule: %s", exc)
                rule = None
            if rule is not None and not rule["is_deny"]:
                checked_actions = {a for a in ACTIONS_BY_TYPE[DATABASE_TYPE] if rule.get(f"can_{a}")}

        self._loading_db_state = True
        try:
            for action, checkbox in self._db_checkboxes.items():
                checkbox.blockSignals(True)
                checkbox.setChecked(action in checked_actions)
                checkbox.blockSignals(False)
        finally:
            self._loading_db_state = False
        self.db_security_group.setEnabled(enabled)

    def _on_db_checkbox_toggled(self, *_args) -> None:
        if self._loading_db_state or not self._real_mode or self._current_connection_id is None:
            return
        if self.app is None:
            return
        connection_id = self._current_connection_id
        checked = [action for action, checkbox in self._db_checkboxes.items() if checkbox.isChecked()]
        language = self._language()
        try:
            if checked:
                self.app.permission_store.grant(connection_id, "*", DATABASE_TYPE, "*", checked)
            else:
                self.app.permission_store.revoke(connection_id, "*", DATABASE_TYPE, "*")
        except Exception as exc:
            logger.error("Could not update the database-and-security rule: %s", exc)
            # A permission GUI must never show more access than the engine
            # will grant. The checkbox the operator just ticked is already
            # painted checked at this point (Qt fires toggled() after the
            # visual state changes), so re-read permissions.db and re-render
            # the section from that truth rather than leaving the widget
            # showing a grant that was never actually written.
            self._refresh_db_security_section(language)
            self._show_message(QMessageBox.Icon.Critical, "permissions.grant_error_title", str(exc), language)

    # -- rule table -----------------------------------------------------

    def _build_rule_table(self, language: str) -> None:
        connection_id = self._current_connection_id
        if connection_id is None:
            self._rules = []
        elif self._real_mode and self.app is not None:
            try:
                # object_type == 'database' never becomes a row here — it is
                # the fixed section above, resolved by connection alone
                # (DESIGN-PERMISSIONS.md §5.6).
                self._rules = [
                    r for r in self.app.permission_store.rules(connection_id)
                    if r["object_type"] != DATABASE_TYPE
                ]
            except Exception as exc:
                logger.error("Could not load rules for connection %s: %s", connection_id, exc)
                self._rules = []
        else:
            self._rules = [r for r in SAMPLE_PERMISSION_RULES if r["connection_id"] == connection_id]

        self.rule_table.setRowCount(len(self._rules))
        for row, rule in enumerate(self._rules):
            # An em dash, not an empty cell: a blank cell reads as data that failed to
            # load, and this is instead a deliberate "the operator did not name this
            # one" -- the same distinction _rule_object_labels() draws for a rule with
            # no targets, just for the one column a rule can legitimately leave blank.
            name_item = QTableWidgetItem(rule.get("rule_name") or "—")
            self.rule_table.setItem(row, 0, name_item)

            objects = _rule_object_labels(rule)
            objects_item = QTableWidgetItem(_summarise_objects(objects))
            # The full list on the tooltip, always: the cell summarises, and an
            # operator checking what a rule actually reaches must not have to open the
            # edit dialog to find out.
            objects_item.setToolTip("\n".join(objects))
            self.rule_table.setItem(row, 1, objects_item)
            self.rule_table.setItem(
                row, 2, QTableWidgetItem(translate(f"permissions.object_type_{rule['object_type']}", language)))

            is_deny = bool(rule["is_deny"])
            decision_key = "permissions.deny_label" if is_deny else "permissions.allow_label"
            decision_item = QTableWidgetItem(translate(decision_key, language))
            decision_item.setForeground(COLOR_ERROR if is_deny else COLOR_SUCCESS)
            self.rule_table.setItem(row, 3, decision_item)

            if self._real_mode:
                action_names = [
                    a for a in ACTIONS_BY_TYPE[rule["object_type"]]
                    if a not in FORBIDDEN_ACTIONS
                ]
                granted = sum(1 for a in action_names if rule.get(f"can_{a}"))
                total = len(action_names)
            else:
                granted = sum(1 for value in rule["actions"].values() if value)
                total = len(rule["actions"])
            count_item = QTableWidgetItem(f"{granted}/{total}")
            count_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.rule_table.setItem(row, 4, count_item)

            self.rule_table.setItem(row, 5, QTableWidgetItem(str(rule["created_at"])[:10]))
            self.rule_table.setItem(row, 6, QTableWidgetItem(rule["user_created"]))

            actions_widget = QWidget()
            actions_layout = QHBoxLayout(actions_widget)
            actions_layout.setContentsMargins(4, 0, 4, 0)
            actions_layout.setSpacing(4)

            edit_button = QPushButton("✎")
            edit_button.setMaximumWidth(32)
            edit_button.setToolTip(translate("permissions.edit_button_tooltip", language))
            edit_button.setEnabled(self._real_mode)
            edit_button.clicked.connect(lambda checked, rule_id=rule["id"]: self._edit_rule_by_id(rule_id))
            actions_layout.addWidget(edit_button)

            delete_button = QPushButton("✕")
            delete_button.setMaximumWidth(32)
            delete_button.setToolTip(translate("permissions.delete_button_tooltip", language))
            delete_button.setEnabled(self._real_mode)
            delete_button.clicked.connect(lambda checked, rule_id=rule["id"]: self._delete_rule_by_id(rule_id))
            actions_layout.addWidget(delete_button)

            self.rule_table.setCellWidget(row, 7, actions_widget)

        has_rows = bool(self._rules)
        self.rule_table.setVisible(has_rows)
        self.rule_table_empty_label.setVisible(not has_rows)
        self.rule_table_empty_label.setText(translate("permissions.no_rules", language))
        self._load_column_widths()
        self._update_button_states()

    # -- selection --------------------------------------------------------

    def _on_tree_selection_changed(self, *_args) -> None:
        self._update_button_states()

    def _on_rule_selection_changed(self) -> None:
        self._update_button_states()

    def _selected_leaves(self) -> list[dict]:
        """Every selected tree leaf that can actually seed a rule.

        Items with no ``UserRole`` payload are schema and type branches, and leaves
        the dialect could not address at all (decision D6) -- both are skipped rather
        than refused, so a shift-click that happens to sweep a branch heading still
        does what the operator plainly meant.
        """
        return [
            data
            for item in self.tree.selectedItems()
            if (data := item.data(0, Qt.ItemDataRole.UserRole))
        ]

    def _update_button_states(self) -> None:
        mutating_enabled = self._real_mode and self._current_connection_id is not None

        # Any addressable leaf will do. One *rule* still carries one object type --
        # action sets differ per type, so a mixed rule would have no coherent checkbox
        # grid (DESIGN-DATA-MODEL.md §4.2) -- but that is a fact about storage, not
        # about the gesture: a selection spanning kinds is fanned out into one rule per
        # kind by _on_new_from_selection(), rather than disabling the button and leaving
        # the operator to work out which of thirty selected rows is the odd one.
        self.new_from_selection_button.setEnabled(
            mutating_enabled and bool(self._selected_leaves()))

        has_rule_selection = self.rule_table.currentRow() >= 0 and bool(self._rules)
        self.edit_rule_button.setEnabled(mutating_enabled and has_rule_selection)
        self.delete_rule_button.setEnabled(mutating_enabled and has_rule_selection)

    def _rule_by_id(self, rule_id: int) -> dict | None:
        return next((r for r in self._rules if r["id"] == rule_id), None)

    def _selected_rule(self) -> dict | None:
        row = self.rule_table.currentRow()
        if row < 0 or row >= len(self._rules):
            return None
        return self._rules[row]

    # -- actions ------------------------------------------------------------

    def _grouped_selection(self) -> dict[str, list[dict]]:
        """The selected leaves, grouped by object type, in the tree's own type order.

        ``_TREE_OBJECT_TYPES`` rather than the order they were clicked in, so a
        selection spanning kinds always fans out in the same sequence and the operator
        is not shown tables before views one time and after them the next.
        """
        grouped: dict[str, list[dict]] = {}
        for leaf in self._selected_leaves():
            grouped.setdefault(leaf["object_type"], []).append(leaf)
        return {t: grouped[t] for t in _TREE_OBJECT_TYPES if t in grouped}

    def _on_new_from_selection(self) -> None:
        if not self._real_mode or self._current_connection_id is None or self.app is None:
            return
        language = self._language()
        grouped = self._grouped_selection()

        # Never a silent return. A button that is enabled and then does nothing when
        # pressed is indistinguishable from a crash, and that is exactly how this
        # method was first reported as broken.
        if not grouped:
            self._show_message(
                QMessageBox.Icon.Information, "permissions.selection_empty_title",
                translate("permissions.selection_empty_message", language), language)
            return

        if len(grouped) > 1:
            # One rule per kind, and said before the first dialog rather than discovered
            # after the third. The summary counts by kind instead of pluralising a noun,
            # which no single phrasing can do across eighteen locales.
            summary = ", ".join(
                f"{translate(f'permissions.object_type_{object_type}', language)} \u00d7 {len(leaves)}"
                for object_type, leaves in grouped.items()
            )
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Question)
            box.setWindowTitle(translate("permissions.mixed_types_title", language))
            box.setText(
                translate("permissions.mixed_types_message", language).replace("{summary}", summary))
            proceed = box.addButton(
                translate("common.ok", language), QMessageBox.ButtonRole.AcceptRole)
            box.addButton(translate("common.cancel", language), QMessageBox.ButtonRole.RejectRole)
            box.exec()
            if box.clickedButton() is not proceed:
                return

        saved = False
        for object_type, leaves in grouped.items():
            dialog = NewRuleDialog(
                self, language=language, theme=self._theme(),
                store=self.app.permission_store, connection_id=self._current_connection_id,
                initial={
                    "object_type": object_type,
                    "targets": [
                        {"schema_pattern": leaf["schema_pattern"],
                         "name_pattern": leaf["name_pattern"]}
                        for leaf in leaves
                    ],
                },
            )
            if dialog.exec() == QDialog.DialogCode.Accepted:
                saved = True
            # A cancelled kind does not abandon the rest: the operator asked for rules
            # over several kinds, and backing out of one is not backing out of all.
        if saved:
            self._on_rule_saved(language)

    def _on_edit_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        self._edit_rule_by_id(rule["id"])

    def _edit_rule_by_id(self, rule_id: int) -> None:
        if not self._real_mode or self._current_connection_id is None or self.app is None:
            return
        rule = self._rule_by_id(rule_id)
        if rule is None:
            return
        language = self._language()
        dialog = NewRuleDialog(
            self, language=language, theme=self._theme(),
            store=self.app.permission_store, connection_id=self._current_connection_id,
            existing_rule=rule,
        )
        if dialog.exec() == QDialog.DialogCode.Accepted:
            self._on_rule_saved(language)

    def _on_rule_saved(self, language: str) -> None:
        self._show_message(
            QMessageBox.Icon.Information, "permissions.grant_success_title",
            translate("permissions.grant_success_message", language), language)
        self._refresh_after_mutation(language)

    def _on_delete_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        self._delete_rule_by_id(rule["id"])

    def _delete_rule_by_id(self, rule_id: int) -> None:
        if not self._real_mode or self._current_connection_id is None or self.app is None:
            return
        rule = self._rule_by_id(rule_id)
        if rule is None:
            return
        language = self._language()
        label = "\n".join(_rule_object_labels(rule))

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Question)
        box.setWindowTitle(translate("permissions.delete_confirm_title", language))
        box.setText(f"{translate('permissions.delete_confirm_message', language)}\n{label}")
        yes_button = box.addButton(translate("common.yes", language), QMessageBox.ButtonRole.YesRole)
        box.addButton(translate("common.no", language), QMessageBox.ButtonRole.NoRole)
        box.exec()
        if box.clickedButton() != yes_button:
            return

        try:
            # By id, not by pattern: a rule names a collection now, so there is no
            # single (schema, type, name) key to revoke it by -- and revoke() would
            # refuse a target shared with the rule's other objects in any case.
            removed = self.app.permission_store.delete_rule(rule_id)
        except Exception as exc:
            logger.error("Could not delete rule %s: %s", rule_id, exc)
            self._show_message(
                QMessageBox.Icon.Critical, "permissions.delete_error_title", str(exc), language)
            return

        if removed:
            self._show_message(
                QMessageBox.Icon.Information, "permissions.delete_success_title",
                translate("permissions.delete_success_message", language), language)
        self._refresh_after_mutation(language)

    def showEvent(self, event) -> None:
        """Pick up connections added on another page while this one was hidden.

        Every page is built once, at start-up, and the combo was filled only there, on a
        language change and on Refresh. A connection created on the Connections page
        therefore did not exist as far as this page was concerned: the combo still read
        "No connections defined yet" and no rule could be written against the profile the
        operator had just made. That is the reported defect.

        The list is re-read on every show because it is a handful of rows from a local
        SQLite file, but ``_refresh_rules_and_tree()`` is *not* run unconditionally --
        it opens a live connection to the database to load the schema, and paying that
        on every visit to the page would be a new defect in place of this one. It runs
        only when the connections or the selection actually changed.
        """
        super().showEvent(event)
        if self.app is None:
            return
        language = self._language()
        before_id = self._current_connection_id
        before = [(c.get("id"), c.get("display_name")) for c in self._connections]
        self._populate_connection_combo(language)
        after = [(c.get("id"), c.get("display_name")) for c in self._connections]
        if before == after and before_id == self._current_connection_id:
            return
        self._tree_entries = {}
        self._tree_error = None
        self._tree_loading = False
        self._refresh_rules_and_tree(language)

    def _on_refresh(self) -> None:
        language = self._language()
        self._populate_connection_combo(language)
        self._tree_entries = {}
        self._tree_error = None
        self._tree_loading = False
        self._refresh_rules_and_tree(language)

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
            widths = config_manager.get_permissions_rules_table_columns() or {}
            for column_str, width in widths.items():
                try:
                    column = int(column_str)
                except (TypeError, ValueError):
                    continue
                if 0 <= column < self.rule_table.columnCount():
                    self.rule_table.setColumnWidth(column, int(width))
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
            widths = {str(i): self.rule_table.columnWidth(i) for i in range(self.rule_table.columnCount())}
            config_manager.set_permissions_rules_table_columns(widths)
        except Exception as exc:  # pragma: no cover - defensive, no store yet
            logger.debug("Could not save column widths: %s", exc)
        finally:
            self._saving_widths = False

    # -- i18n / theming ----------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.title.setText(translate("permissions.title", language))
        self.subtitle.setText(translate("permissions.subtitle", language))
        self.connection_label.setText(translate("permissions.connection_selector_label", language))
        self.tree_title.setText(translate("permissions.explorer_title", language))
        self.new_from_selection_button.setText(translate("permissions.new_rule_from_selection_button", language))
        self.edit_rule_button.setText(translate("common.edit", language))
        self.delete_rule_button.setText(translate("common.delete", language))
        self.refresh_button.setText(translate("permissions.refresh_button", language))
        self.rule_table.setHorizontalHeaderLabels([
            translate("permissions.table_header_rule_name", language),
            translate("permissions.table_header_objects", language),
            translate("permissions.table_header_object_type", language),
            translate("permissions.table_header_effect", language),
            translate("permissions.table_header_actions", language),
            translate("permissions.table_header_created", language),
            translate("permissions.table_header_user", language),
            translate("permissions.table_header_edit", language),
        ])

        self.db_security_group.setTitle(translate("permissions.object_type_database", language))
        for category, header in self._db_category_headers.items():
            header.setText(translate(_DB_SECURITY_CATEGORY_TRANSLATION_KEY[category], language))
        for action, checkbox in self._db_checkboxes.items():
            checkbox.setText(translate(f"permissions.action_{action}", language))
            tooltip_key = f"permissions.action_{action}_tooltip"
            tooltip_text = translate(tooltip_key, language)
            checkbox.setToolTip(tooltip_text if tooltip_text != tooltip_key else "")

        self._populate_connection_combo(language)
        self._render_rules_and_tree(language)

    def _update_theme(self, theme: str) -> None:
        colour = DARK_TEXT_SECONDARY if theme == "dark" else LIGHT_TEXT_SECONDARY
        self.subtitle.setStyleSheet(f"color: {colour.name()};")
        self.rule_table_empty_label.setStyleSheet(f"color: {colour.name()};")
        # tree_empty_label's colour depends on which state it is showing
        # (informational vs. error), so re-render rather than restyle it
        # directly — _render_tree()/_show_tree_message() is the one place
        # that decides its colour.
        self._render_tree(self._language())
