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

"""Create/edit modal for a permission rule, f-MCP's ``NewRuleDialog`` retargeted
to database objects.

A rule names a *collection* since schema version 2, so the two pattern fields are
a list an operator adds to and takes from, seeded from whatever they selected in
the schema tree. That is also why nothing here is read-only in edit mode any more:
version 1 keyed a rule by its single target, so changing the target meant writing a
different rule, and the dialog had to freeze the three fields to stop it. Addressed
by ``rule_id``, a rule's reach is editable like anything else about it.

Writes through the real resolver: accepting the dialog calls
``PermissionStore.create_rule()``/``.update_rule()`` directly, and the dialog only
closes once that call has actually returned without raising. There is nothing left
here that pretends a rule was saved.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QDialog,
    QFormLayout,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    ACTION_DDL,
    ACTION_DELETE,
    ACTION_EXECUTE,
    ACTION_GRANT,
    ACTION_INSERT,
    ACTION_SELECT,
    ACTION_UPDATE,
)
from sape_d_mcp.permissions import (
    ACTIONS_BY_TYPE,
    DATABASE_TYPE,
    FORBIDDEN_ACTIONS,
    MAX_RULE_NAME_LENGTH,
)
from sape_d_mcp.permissions import OBJECT_TYPES as _ALL_OBJECT_TYPES

logger = logging.getLogger(__name__)

# ``database`` is not a pattern row — it is the fixed "Database and security"
# section the Permissions page renders itself (DESIGN-PERMISSIONS.md §5.6) —
# so it never appears in this dialog's object-type combo.
OBJECT_TYPES: tuple[str, ...] = tuple(t for t in _ALL_OBJECT_TYPES if t != DATABASE_TYPE)

# Every action is coloured by the SELECT/INSERT/UPDATE/DELETE/DDL/EXECUTE/GRANT
# hue vocabulary, and grouped under a translated category header in that order.
_ACTION_CATEGORY: dict[str, str] = {
    "list": "read", "read_structure": "read", "read_definition": "read",
    "read_catalogue": "read", "select": "read",
    "run_query": "execute",
    "insert": "insert",
    "update": "update",
    "delete": "delete",
    "create": "ddl", "drop": "ddl", "edit": "ddl",
    "create_role": "grant", "create_user": "grant", "create_group": "grant",
    "assign_group": "grant", "assign_role": "grant",
}

_CATEGORY_ORDER: tuple[str, ...] = ("read", "insert", "update", "delete", "ddl",
                                    "execute", "grant")

_CATEGORY_COLOUR = {
    "read": ACTION_SELECT,
    "insert": ACTION_INSERT,
    "update": ACTION_UPDATE,
    "delete": ACTION_DELETE,
    "ddl": ACTION_DDL,
    "execute": ACTION_EXECUTE,
    "grant": ACTION_GRANT,
}

_CATEGORY_TRANSLATION_KEY = {
    "read": "permissions.category_read",
    "insert": "permissions.category_insert",
    "update": "permissions.category_update",
    "delete": "permissions.category_delete",
    "ddl": "permissions.category_ddl",
    "execute": "permissions.category_execute",
    "grant": "permissions.category_grant",
}

# Default action set proposed for a brand-new rule: read-only.
_DEFAULT_READONLY_ACTIONS = {"list", "read_structure", "read_definition",
                             "read_catalogue", "select"}


class _AddTargetDialog(QDialog):
    """Ask for one ``(schema_pattern, name_pattern)`` pair under the §2.1 grammar.

    Deliberately a plain pair of line edits rather than a browser: the schema tree on
    the Permissions page is how an operator picks objects that *exist*, and this is
    the other case — a pattern such as ``rpt_*`` that is meant to catch objects not
    created yet, which no browser can offer.
    """

    def __init__(self, parent=None, language: str = "en-US"):
        super().__init__(parent)
        self.language = language
        self.target: tuple[str, str] | None = None
        self.setMinimumWidth(420)
        self.setWindowTitle(translate("permissions.add_target_title", language))

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        form = QFormLayout()
        form.setSpacing(10)
        self.schema_edit = QLineEdit()
        self.schema_edit.setPlaceholderText(
            translate("permissions.new_rule_schema_placeholder", language))
        form.addRow(translate("permissions.field_schema_pattern", language), self.schema_edit)
        self.name_edit = QLineEdit()
        self.name_edit.setPlaceholderText(
            translate("permissions.new_rule_name_placeholder", language))
        form.addRow(translate("permissions.field_name_pattern", language), self.name_edit)
        layout.addLayout(form)

        row = QHBoxLayout()
        row.addStretch()
        cancel = QPushButton(translate("common.cancel", language))
        cancel.clicked.connect(self.reject)
        row.addWidget(cancel)
        add = QPushButton(translate("common.ok", language))
        add.setDefault(True)
        add.clicked.connect(self._on_accept)
        row.addWidget(add)
        layout.addLayout(row)

    def _on_accept(self) -> None:
        schema_pattern = self.schema_edit.text().strip()
        name_pattern = self.name_edit.text().strip()
        if not schema_pattern or not name_pattern:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle(translate("permissions.validation_error_title", self.language))
            box.setText(translate("permissions.validation_error_message", self.language))
            box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
            box.exec()
            return
        self.target = (schema_pattern, name_pattern)
        self.accept()


class NewRuleDialog(QDialog):
    """Create a rule, or edit one, over a collection of objects of one type.

    ``store`` and ``connection_id`` are required: ``_on_save()`` calls
    ``store.create_rule()``/``store.update_rule()`` on them directly and only
    accepts the dialog once that call has returned without raising, so the
    caller never has to trust a mocked ``rule_data`` payload — the write has
    already happened by the time ``exec()`` returns ``Accepted``.

    One object type per rule, and in edit mode the combo stays disabled: a
    rule's ``object_type`` is denormalised into every one of its target rows and
    is part of the composite foreign key, so it genuinely cannot be changed
    after creation (``PermissionStore.update_rule``). Its *targets* can.
    """

    def __init__(self, parent=None, language: str = "en-US", theme: str = "light",
                 store=None, connection_id: int | None = None,
                 existing_rule: dict | None = None, initial: dict | None = None):
        super().__init__(parent)
        self.language = language
        self.theme = theme
        self.store = store
        self.connection_id = connection_id
        self.existing_rule = existing_rule
        self.rule_data: dict | None = None
        self._action_checkboxes: dict[str, QCheckBox] = {}
        self._category_headers: dict[str, QLabel] = {}

        self.setMinimumSize(560, 620)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.heading_label = QLabel()
        layout.addWidget(self.heading_label)

        form = QFormLayout()
        form.setSpacing(10)

        # First row, deliberately above the object-type combo: this is the operator's
        # own label for the rule -- what it is *for* -- and reads before anything about
        # how the rule is mechanically built. Optional, so left blank rather than
        # refused; the store folds an empty field to NULL rather than storing "".
        self.rule_name_edit = QLineEdit()
        self.rule_name_edit.setMaxLength(MAX_RULE_NAME_LENGTH)
        self.rule_name_label = QLabel()
        form.addRow(self.rule_name_label, self.rule_name_edit)

        self.object_type_combo = QComboBox()
        for object_type in OBJECT_TYPES:
            self.object_type_combo.addItem(object_type, object_type)
        # Changing the type does not disturb the target list: a (schema, name)
        # pattern pair means the same thing whichever kind of object it names, and
        # silently emptying a list the operator has just built would cost more than
        # the tidiness is worth. Only the action grid is rebuilt, because that genuinely
        # differs per type.
        self.object_type_combo.currentIndexChanged.connect(self._rebuild_action_grid)
        self.object_type_label = QLabel()
        form.addRow(self.object_type_label, self.object_type_combo)

        layout.addLayout(form)

        # -- the collection ------------------------------------------------
        self.targets_label = QLabel()
        layout.addWidget(self.targets_label)

        self.targets_list = QListWidget()
        self.targets_list.setSelectionMode(QListWidget.SelectionMode.ExtendedSelection)
        self.targets_list.setMinimumHeight(96)
        self.targets_list.itemSelectionChanged.connect(self._update_target_buttons)
        layout.addWidget(self.targets_list)

        self.targets_empty_label = QLabel()
        self.targets_empty_label.setWordWrap(True)
        # Palette colour, not a literal: this dialog opens under both themes and a
        # hard-coded hex would be unreadable in one of them. Italic is how the rest of
        # the application marks an aside.
        empty_font = QFont()
        empty_font.setItalic(True)
        self.targets_empty_label.setFont(empty_font)
        layout.addWidget(self.targets_empty_label)

        target_row = QHBoxLayout()
        self.add_target_button = QPushButton()
        self.add_target_button.clicked.connect(self._on_add_target)
        target_row.addWidget(self.add_target_button)
        self.remove_target_button = QPushButton()
        self.remove_target_button.setEnabled(False)
        self.remove_target_button.clicked.connect(self._on_remove_target)
        target_row.addWidget(self.remove_target_button)
        target_row.addStretch()
        layout.addLayout(target_row)

        # Allow / deny
        decision_row = QHBoxLayout()
        self.allow_radio = QRadioButton()
        self.deny_radio = QRadioButton()
        self.allow_radio.setChecked(True)
        self._decision_group = QButtonGroup(self)
        self._decision_group.addButton(self.allow_radio)
        self._decision_group.addButton(self.deny_radio)
        decision_row.addWidget(self.allow_radio)
        decision_row.addWidget(self.deny_radio)
        decision_row.addStretch()
        layout.addLayout(decision_row)

        self.actions_title_label = QLabel()
        layout.addWidget(self.actions_title_label)

        self._actions_container = QWidget()
        self._actions_layout = QVBoxLayout(self._actions_container)
        self._actions_layout.setContentsMargins(0, 0, 0, 0)
        self._actions_layout.setSpacing(8)
        layout.addWidget(self._actions_container, 1)

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

        if existing_rule:
            self._populate(existing_rule)
        elif initial:
            self._apply_initial(initial)
        else:
            self._rebuild_action_grid()

        self._update_language(language)

    @staticmethod
    def _targets_of(payload: dict) -> list[tuple[str, str]]:
        """Read a target list off either shape the page can hand this dialog.

        ``targets`` is what a rule row and a multi-selection both carry; the single
        ``schema_pattern``/``name_pattern`` pair is what one tree leaf carries, and
        is accepted so the page does not have to wrap a one-object selection.
        """
        targets = payload.get("targets")
        if targets:
            return [
                (str(t["schema_pattern"]), str(t["name_pattern"]))
                for t in targets
            ]
        schema_pattern = payload.get("schema_pattern")
        name_pattern = payload.get("name_pattern")
        if schema_pattern and name_pattern:
            return [(str(schema_pattern), str(name_pattern))]
        return []

    def _set_targets(self, targets: list[tuple[str, str]]) -> None:
        """Replace the list, de-duplicated and ordered as the store will store it."""
        self.targets_list.clear()
        for schema_pattern, name_pattern in sorted(set(targets)):
            item = QListWidgetItem(f"{schema_pattern}.{name_pattern}")
            item.setData(Qt.ItemDataRole.UserRole, (schema_pattern, name_pattern))
            self.targets_list.addItem(item)
        self._update_target_buttons()

    def _current_targets(self) -> list[tuple[str, str]]:
        return [
            self.targets_list.item(row).data(Qt.ItemDataRole.UserRole)
            for row in range(self.targets_list.count())
        ]

    def _update_target_buttons(self) -> None:
        self.remove_target_button.setEnabled(bool(self.targets_list.selectedItems()))
        empty = self.targets_list.count() == 0
        self.targets_empty_label.setVisible(empty)

    def _on_add_target(self) -> None:
        dialog = _AddTargetDialog(self, self.language)
        if dialog.exec() == QDialog.DialogCode.Accepted and dialog.target:
            self._set_targets([*self._current_targets(), dialog.target])

    def _on_remove_target(self) -> None:
        doomed = {item.data(Qt.ItemDataRole.UserRole) for item in self.targets_list.selectedItems()}
        self._set_targets([t for t in self._current_targets() if t not in doomed])

    def _apply_initial(self, initial: dict) -> None:
        object_type = initial.get("object_type", OBJECT_TYPES[0])
        index = self.object_type_combo.findData(object_type)
        if index >= 0:
            self.object_type_combo.setCurrentIndex(index)
        self._set_targets(self._targets_of(initial))
        # "New rule from selection" does not seed a name today, but a caller that
        # someday does should not have it silently dropped.
        self.rule_name_edit.setText(initial.get("rule_name") or "")
        self._rebuild_action_grid()

    def _populate(self, existing_rule: dict) -> None:
        object_type = existing_rule.get("object_type", OBJECT_TYPES[0])
        index = self.object_type_combo.findData(object_type)
        if index >= 0:
            self.object_type_combo.blockSignals(True)
            self.object_type_combo.setCurrentIndex(index)
            self.object_type_combo.blockSignals(False)
        self._set_targets(self._targets_of(existing_rule))
        # THE TRAP: update_rule() sets the name wholesale, exactly like targets and
        # actions. A blank field here would save the dialog's "Save" button pressed on
        # an untouched name field as a request to *clear* it -- so the existing name is
        # read back into the field rather than left for _on_save() to invent from
        # nothing.
        self.rule_name_edit.setText(existing_rule.get("rule_name") or "")
        self.deny_radio.setChecked(bool(existing_rule.get("is_deny")))
        self.allow_radio.setChecked(not existing_rule.get("is_deny"))

        # object_type alone stays frozen. It is denormalised into every one of the
        # rule's target rows and is part of the composite foreign key to
        # rules(id, connection_id, object_type), so the store cannot change it either
        # -- update_rule() reads it back off the rule rather than accepting one.
        self.object_type_combo.setEnabled(False)

        # A real rule row from PermissionStore.rules()/rule_for() carries one
        # ``can_<action>`` column per action in ALL_ACTIONS, not the fixture's
        # ``actions`` dict — read the columns that apply to this row's own
        # object type, per ACTIONS_BY_TYPE (DESIGN-DATA-MODEL.md §4.3).
        checked_actions = {
            action: bool(existing_rule.get(f"can_{action}"))
            for action in ACTIONS_BY_TYPE[object_type]
        }
        self._rebuild_action_grid(checked_actions=checked_actions)

    def _rebuild_action_grid(self, *_args, checked_actions: dict[str, bool] | None = None) -> None:
        while self._actions_layout.count():
            item = self._actions_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self._clear_layout(item.layout())
        self._action_checkboxes.clear()
        self._category_headers.clear()

        object_type = self.object_type_combo.currentData() or OBJECT_TYPES[0]
        actions = ACTIONS_BY_TYPE[object_type]

        by_category: dict[str, list[str]] = {}
        for action in actions:
            category = _ACTION_CATEGORY[action]
            by_category.setdefault(category, []).append(action)

        for category in _CATEGORY_ORDER:
            if category not in by_category:
                continue

            header = QLabel()
            header_font = QFont()
            header_font.setBold(True)
            header.setFont(header_font)
            header.setStyleSheet(f"color: {_CATEGORY_COLOUR[category].name()};")
            self._actions_layout.addWidget(header)
            self._category_headers[category] = header

            grid = QGridLayout()
            grid.setSpacing(6)
            grid.setContentsMargins(12, 0, 0, 0)
            for col_index, action in enumerate(by_category[category]):
                checkbox = QCheckBox()
                checkbox.setStyleSheet(f"color: {_CATEGORY_COLOUR[category].name()};")
                if action in FORBIDDEN_ACTIONS:
                    # ADR 0005: 'drop' and 'edit' can never be granted, by any rule,
                    # whatever a rule row's own can_drop/can_edit columns say. The
                    # box stays visible -- hiding it would make the prohibition look
                    # like a control that simply is not there -- but it is always
                    # unticked and disabled, never a tick that authorises nothing.
                    checkbox.setChecked(False)
                    checkbox.setEnabled(False)
                elif checked_actions is not None:
                    checkbox.setChecked(bool(checked_actions.get(action)))
                else:
                    checkbox.setChecked(action in _DEFAULT_READONLY_ACTIONS)
                self._action_checkboxes[action] = checkbox
                grid.addWidget(checkbox, col_index // 2, col_index % 2)
            self._actions_layout.addLayout(grid)

        self._actions_layout.addStretch()
        self._update_action_labels(self.language)

    @staticmethod
    def _clear_layout(layout) -> None:
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

    def _update_action_labels(self, language: str) -> None:
        for category, header in self._category_headers.items():
            header.setText(translate(_CATEGORY_TRANSLATION_KEY[category], language))
        for action, checkbox in self._action_checkboxes.items():
            checkbox.setText(translate(f"permissions.action_{action}", language))
            if action in FORBIDDEN_ACTIONS:
                # ADR 0005 §2: the dynamic f-string below never resolves to this
                # explanation -- "permissions.action_forbidden_tooltip" is not
                # "permissions.action_drop_tooltip" or "..._edit_tooltip", so a
                # literal key here is the only way the box ever stops showing
                # "Drop the object" / "Replace the routine body" once it is
                # disabled. One shared key for both verbs: the set stays the
                # single source of truth, and a third forbidden action inherits
                # the explanation without a new translation entry.
                checkbox.setToolTip(translate("permissions.action_forbidden_tooltip", language))
                continue
            # Not every action has a tooltip in the catalogue yet; translate()
            # returns the key itself when a translation is missing, so only
            # set one when it actually resolved to something else (f-MCP's
            # own guard against showing a raw key as a tooltip).
            tooltip_key = f"permissions.action_{action}_tooltip"
            tooltip_text = translate(tooltip_key, language)
            checkbox.setToolTip(tooltip_text if tooltip_text != tooltip_key else "")

    def _on_save(self) -> None:
        targets = self._current_targets()
        object_type = self.object_type_combo.currentData()
        is_deny = self.deny_radio.isChecked()
        # Stripped, then folded to None rather than "": the store treats an empty
        # string and no name as the same thing, but a caller sending "   " gets a
        # ValueError telling it to send nothing instead -- so nothing is what this
        # sends for an untouched or whitespace-only field.
        rule_name = self.rule_name_edit.text().strip() or None
        # A deny is exactly "a rule that matches and grants nothing", and the store
        # rejects one carrying actions, so the ticks are dropped rather than sent.
        actions = (
            []
            if is_deny
            else [action for action, cb in self._action_checkboxes.items() if cb.isChecked()]
        )

        if not targets:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Warning)
            box.setWindowTitle(translate("permissions.validation_error_title", self.language))
            box.setText(translate("permissions.validation_error_message", self.language))
            box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
            box.exec()
            return

        if self.store is None or self.connection_id is None:
            # The page only ever opens this dialog with both set — a missing
            # one here is a caller bug, not a user-facing situation, so it is
            # logged for a developer and reported the same honest way rather
            # than silently no-op'd, using the closest existing translation
            # rather than a hand-rolled English sentence.
            logger.error("NewRuleDialog opened without a store/connection_id; cannot save")
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle(translate("permissions.grant_error_title", self.language))
            box.setText(translate("permissions.grant_error_message", self.language))
            box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
            box.exec()
            return

        try:
            if self.existing_rule:
                self.store.update_rule(
                    int(self.existing_rule["id"]), targets, actions, is_deny=is_deny,
                    rule_name=rule_name)
            else:
                self.store.create_rule(
                    self.connection_id, object_type, targets, actions, is_deny=is_deny,
                    rule_name=rule_name)
        except ValueError as exc:
            box = QMessageBox(self)
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle(translate("permissions.grant_error_title", self.language))
            box.setText(str(exc))
            box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
            box.exec()
            return

        self.rule_data = {
            "rule_name": rule_name,
            "object_type": object_type,
            "targets": [
                {"schema_pattern": schema, "name_pattern": name} for schema, name in targets
            ],
            "is_deny": is_deny,
            "actions": {action: cb.isChecked() for action, cb in self._action_checkboxes.items()},
        }
        self.accept()

    def _update_language(self, language: str) -> None:
        self.language = language
        title_key = "permissions.edit_rule_title" if self.existing_rule else "permissions.new_rule_title"
        self.setWindowTitle(translate(title_key, language))
        self.heading_label.setText(translate(title_key, language))

        self.rule_name_label.setText(translate("permissions.field_rule_name", language))
        self.rule_name_edit.setPlaceholderText(translate("permissions.rule_name_placeholder", language))
        self.object_type_label.setText(translate("permissions.field_object_type", language))
        self.targets_label.setText(translate("permissions.field_targets", language))
        self.targets_empty_label.setText(translate("permissions.targets_empty", language))
        self.add_target_button.setText(translate("permissions.add_target_button", language))
        self.remove_target_button.setText(translate("permissions.remove_target_button", language))

        current_object_type = self.object_type_combo.currentData()
        self.object_type_combo.blockSignals(True)
        self.object_type_combo.clear()
        for object_type in OBJECT_TYPES:
            self.object_type_combo.addItem(
                translate(f"permissions.object_type_{object_type}", language), object_type)
        index = self.object_type_combo.findData(current_object_type) if current_object_type else 0
        self.object_type_combo.setCurrentIndex(max(index, 0))
        self.object_type_combo.blockSignals(False)

        self.allow_radio.setText(translate("permissions.allow_label", language))
        self.deny_radio.setText(translate("permissions.deny_label", language))
        self.actions_title_label.setText(translate("permissions.field_actions", language))
        self.cancel_button.setText(translate("common.cancel", language))
        self.save_button.setText(translate("common.save", language))

        self._update_action_labels(language)
