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

"""Server discovery dialog and its off-thread worker.

Implements ``docs/DESIGN-CONNECTION-SETUP.md`` §7 and §9, and the threading
contract of §7.9 / ADR 0003 point 8, to the letter: :class:`_DiscoveryWorker`
is the one and only place ``sape_d_mcp.db.discovery`` is called from the GUI
process, it is always a :class:`QThread`, and this dialog never lets more
than one of them run at a time.

Nothing here saves a profile or opens a connection. Selecting a candidate
and pressing *Use this* hands the caller a frozen ``Candidate`` for the
connection dialog to pre-fill; the human still has to press Save there.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from sape_d_mcp.gui.i18n import translate

if TYPE_CHECKING:
    # Deferred at runtime (see _DiscoveryWorker.run()) so that importing this dialog
    # never pulls in sape_d_mcp.db.discovery's own platform-specific imports (winreg,
    # etc.) before a search actually runs; the type-only import here costs nothing at
    # runtime, since annotations are postponed (PEP 563, imported above).
    from sape_d_mcp.db.discovery import Candidate

logger = logging.getLogger(__name__)

# db/discovery.py bakes an English parenthetical straight into a Candidate's own
# ``label`` (§7.2) — that module has zero GUI dependencies, so wording lives there
# as plain text for consumers with no interface at all. ``Candidate.note_key``
# names, for those with one, which i18n key that same parenthetical corresponds
# to; this dialog uses it to strip the English fragment and splice in the
# translated note, rather than matching the English text itself, which would
# fail silently the moment db/discovery.py's own wording changed. The mapping
# below is exhaustive over every note_key db/discovery.py actually produces
# (see its module docstring and Candidate construction sites) — an entry here
# with no matching key on the other side, or vice versa, is a bug, not a choice.
_NOTE_MARKERS: dict[str, str] = {
    "discovery.dynamic_port_note": " (dynamic port — it changes when the service restarts)",
}

# The 1434/UDP broadcast is the one thing this dialog sends that the user did
# not name a destination for (ADR 0003, point 4). Everything else it calls —
# the registry, ODBC configuration, a loopback probe, a folder walk — reads
# local state and is offered without asking first.
_NETWORK_TIMEOUT_S = 2.0

# Attribute name used on the SAPEApplication instance to remember, for the
# life of this one process, that the operator has already been shown and has
# accepted the broadcast warning. Never written to config.json: a fresh
# launch asks again, by design (§7.7 point 2 and DESIGN-CONNECTION-SETUP.md
# §13 Q5's ruling to keep the friction).
_SESSION_CONFIRM_ATTR = "_dmcp_network_discovery_confirmed"


class _DiscoveryWorker(QThread):
    """Runs one round of :mod:`sape_d_mcp.db.discovery` off the GUI thread.

    Mirrors ``_ConnectionTestWorker`` in ``connections_page.py`` and is
    specified verbatim in ``DESIGN-CONNECTION-SETUP.md`` §7.9: one worker at
    a time, cooperative cancellation through a ``threading.Event``, never
    ``terminate()``. The dialog is responsible for the single-worker guard;
    this class only guarantees that *its own* run either completes, fails
    with a sentence, or is cancelled — never that a second one is not
    started elsewhere.
    """

    found = pyqtSignal(object)  # one Candidate, emitted as it is produced
    completed = pyqtSignal(object)  # DiscoveryResult
    failed = pyqtSignal(str)  # a sentence, never a traceback

    def __init__(self, mode: str, options: dict, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.mode = mode
        self.options = dict(options)
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:
        try:
            if self.mode == "local":
                from sape_d_mcp.db.discovery import discover_local

                result = discover_local(
                    budget_s=self.options.get("budget_s", 5.0),
                    sources=self.options.get("sources") or self.options.get("sources_default", ()) or (),
                    sqlite_roots=self.options.get("sqlite_roots"),
                    cancel=self._cancel,
                )
            elif self.mode == "network":
                from sape_d_mcp.db.discovery import discover_network

                result = discover_network(
                    timeout_s=self.options.get("timeout_s", _NETWORK_TIMEOUT_S),
                    targets=self.options.get("targets", ()),
                    cancel=self._cancel,
                )
            else:  # pragma: no cover - programming error, not a user-reachable path
                raise ValueError(f"unknown discovery mode {self.mode!r}")
        except Exception as exc:
            logger.warning("discovery (%s) failed: %s", self.mode, exc)
            self.failed.emit(str(exc))
            return

        # discover_local() has no per-candidate callback in the documented
        # contract (DESIGN-CONNECTION-SETUP.md §7.1), so "streamed" here means
        # every candidate is emitted individually the instant the blocking
        # call returns, rather than the dialog reading result.candidates
        # itself — the dialog's list-building code stays identical for both
        # modes, and a future streaming discover_local() needs no GUI change.
        for candidate in result.candidates:
            if self._cancel.is_set():
                break
            self.found.emit(candidate)
        self.completed.emit(result)


class DiscoveryDialog(QDialog):
    """Find a candidate server or SQLite file, for a human to review and use.

    ``candidate.confidence`` is one of three grades (see
    :data:`sape_d_mcp.db.discovery.CONFIDENCE`):

    * ``confirmed`` — the source inspected the service itself: a Windows
      registry entry, a known service name, a configured ODBC DSN, a
      verified SQLite header.
    * ``inferred`` — a bare ``connect()`` was accepted; the engine is
      guessed from the port number alone. This is what the local port probe
      now returns: through NAT, or behind anything proxying the connection,
      an accepted ``connect()`` does not prove the port itself is reachable
      or that the guessed engine is the one actually listening — measured
      empirically, not assumed.
    * ``reported`` — an unauthenticated network reply (SSRP).

    ``confirmed`` and ``inferred`` both come from searching this computer
    and share the local section; anything from ``discover_network`` is
    ``reported`` and is kept in a visually separate section headed
    accordingly, per ADR 0003 point 5: a candidate from the network is never
    presented as if it were a verified fact. Within the local section, the
    confidence column itself still spells out ``confirmed`` versus
    ``inferred`` — "found in the Windows registry" and "something answered
    on that port" are not the same claim, and conflating them is exactly
    the kind of mistake that leads to a profile configured against the
    wrong service.
    """

    def __init__(self, parent=None, language: str = "en-US", app=None) -> None:
        super().__init__(parent)
        self.language = language
        self.app = app
        self.result_candidate: Candidate | None = None
        self._worker: _DiscoveryWorker | None = None
        self._candidates_by_item: dict[int, Candidate] = {}
        # Which search kicked off the worker currently running (or the one that just
        # finished) — set by each _on_search_* method before .start(), read back in
        # _on_completed()/_on_failed() so that only a "network" sweep gets its own
        # audit.db row per run (see db.discovery.audit_network_discovery's docstring:
        # one row per invocation, regardless of whether consent was freshly asked or
        # already remembered from earlier in the session).
        self._search_mode: str | None = None

        self.setMinimumSize(560, 420)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(12)

        self.title_label = QLabel()
        layout.addWidget(self.title_label)
        self.subtitle_label = QLabel()
        self.subtitle_label.setWordWrap(True)
        layout.addWidget(self.subtitle_label)

        button_row = QHBoxLayout()
        button_row.setSpacing(8)
        self.search_local_button = QPushButton()
        self.search_local_button.clicked.connect(self._on_search_local)
        button_row.addWidget(self.search_local_button)
        self.search_network_button = QPushButton()
        self.search_network_button.clicked.connect(self._on_search_network)
        button_row.addWidget(self.search_network_button)
        self.search_folder_button = QPushButton()
        self.search_folder_button.clicked.connect(self._on_search_folder)
        button_row.addWidget(self.search_folder_button)
        button_row.addStretch()
        layout.addLayout(button_row)

        self.status_label = QLabel()
        layout.addWidget(self.status_label)

        self.tree = QTreeWidget()
        self.tree.setColumnCount(3)
        self.tree.setRootIsDecorated(True)
        self.tree.itemSelectionChanged.connect(self._on_selection_changed)
        layout.addWidget(self.tree, 1)

        self.notes_label = QLabel()
        self.notes_label.setWordWrap(True)
        layout.addWidget(self.notes_label)

        footer_row = QHBoxLayout()
        footer_row.addStretch()
        self.close_button = QPushButton()
        self.close_button.clicked.connect(self.reject)
        footer_row.addWidget(self.close_button)
        self.use_button = QPushButton()
        self.use_button.setEnabled(False)
        self.use_button.setDefault(True)
        self.use_button.clicked.connect(self._on_use)
        footer_row.addWidget(self.use_button)
        layout.addLayout(footer_row)

        self._local_group: QTreeWidgetItem | None = None
        self._network_group: QTreeWidgetItem | None = None
        self._build_groups()

        self._update_language(language)

    # -- group scaffolding -------------------------------------------------

    def _build_groups(self) -> None:
        self._local_group = QTreeWidgetItem(self.tree)
        self._local_group.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self._network_group = QTreeWidgetItem(self.tree)
        self._network_group.setFlags(Qt.ItemFlag.ItemIsEnabled)
        self.tree.expandAll()

    def _clear_results(self) -> None:
        self._candidates_by_item.clear()
        for group in (self._local_group, self._network_group):
            if group is not None:
                for i in reversed(range(group.childCount())):
                    group.removeChild(group.child(i))
        self.notes_label.clear()
        self.use_button.setEnabled(False)

    # -- local search -------------------------------------------------------

    def _on_search_local(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        self._clear_results()
        self.status_label.setText(translate("discovery.searching_local", self.language))
        self._set_buttons_enabled(False)
        self._search_mode = "local"
        self._worker = _DiscoveryWorker("local", {"budget_s": 5.0}, self)
        self._worker.found.connect(self._on_candidate_found)
        self._worker.completed.connect(self._on_completed)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _on_search_folder(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        folder = QFileDialog.getExistingDirectory(
            self, translate("discovery.folder_dialog_title", self.language))
        if not folder:
            return
        self._clear_results()
        self.status_label.setText(translate("discovery.searching_local", self.language))
        self._set_buttons_enabled(False)
        self._search_mode = "local"
        self._worker = _DiscoveryWorker(
            "local",
            {"budget_s": 10.0, "sources": ("sqlite-file",), "sqlite_roots": [folder]},
            self,
        )
        self._worker.found.connect(self._on_candidate_found)
        self._worker.completed.connect(self._on_completed)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    # -- network search, gated by a per-session confirmation ---------------

    def _on_search_network(self) -> None:
        if self._worker is not None and self._worker.isRunning():
            return
        if not self._confirm_network_search():
            return
        self._clear_results()
        self.status_label.setText(translate("discovery.searching_network", self.language))
        self._set_buttons_enabled(False)
        self._search_mode = "network"
        self._worker = _DiscoveryWorker("network", {"timeout_s": _NETWORK_TIMEOUT_S}, self)
        self._worker.completed.connect(self._on_completed)
        self._worker.failed.connect(self._on_failed)
        self._worker.finished.connect(self._on_worker_finished)
        self._worker.start()

    def _confirm_network_search(self) -> bool:
        """Ask before the one datagram this feature ever sends unsolicited.

        Asked again every time the application is relaunched — the flag
        lives only on the running ``SAPEApplication`` instance, never in
        ``config.json`` — mirroring the confirmation broker's own ruling
        that no destructive-operation approval is ever remembered
        (DESIGN-CONNECTION-SETUP.md §7.7 point 2, §13 Q5).
        """
        already_confirmed = bool(getattr(self.app, _SESSION_CONFIRM_ATTR, False)) if self.app else False
        if already_confirmed:
            return True

        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(translate("discovery.network_confirm_title", self.language))
        box.setText(translate("discovery.network_confirm_message", self.language))
        search_button = box.addButton(
            translate("discovery.network_confirm_search", self.language), QMessageBox.ButtonRole.AcceptRole)
        box.addButton(translate("common.cancel", self.language), QMessageBox.ButtonRole.RejectRole)
        box.exec()
        approved = box.clickedButton() is search_button

        # The consent decision only — not the sweep itself. See
        # audit_network_discovery_consent's own docstring: this is called at most once
        # per session (the flag set below short-circuits every later call before the
        # dialog is even shown again), and audit_network_discovery below is what covers
        # every actual sweep, whether the confirmation was just asked or remembered.
        from sape_d_mcp.db.discovery import audit_network_discovery_consent

        log_store = getattr(self.app, "log_store", None) if self.app else None
        audit_network_discovery_consent(log_store, "gui", confirmed=approved)

        if approved and self.app is not None:
            setattr(self.app, _SESSION_CONFIRM_ATTR, True)
        return approved

    # -- worker callbacks ----------------------------------------------------

    def _on_candidate_found(self, candidate) -> None:
        group = self._network_group if candidate.confidence == "reported" else self._local_group
        if group is None:
            return
        item = QTreeWidgetItem(group)
        item.setText(0, self._display_label(candidate))
        item.setText(1, self._origin_text(candidate))
        # The three CONFIDENCE grades are spelt out here rather than collapsed to a
        # binary "confirmed vs reported": 'confirmed' and 'inferred' both live in the
        # local section (grouped by _on_candidate_found's origin check above), and
        # without this the column would show 'confirmed' for both, hiding the one
        # distinction — registry-verified versus a bare accepted connect() — that
        # keeps someone from configuring a profile against the wrong service.
        item.setText(2, translate(f"discovery.confidence_{candidate.confidence}", self.language))
        if candidate.confidence == "inferred":
            item.setToolTip(2, translate("discovery.confidence_inferred_tooltip", self.language))
        self._candidates_by_item[id(item)] = candidate
        item.setData(0, Qt.ItemDataRole.UserRole, id(item))

    def _display_label(self, candidate) -> str:
        # ``note_key`` lands on ``Candidate`` after this dialog was first written
        # (see the class comment above); ``getattr`` with a ``None`` default keeps
        # this dialog working, note-less, against an older Candidate that does not
        # carry the field yet, rather than raising on every candidate found.
        label = candidate.label
        note_key = getattr(candidate, "note_key", None)
        if note_key is None:
            return label
        marker = _NOTE_MARKERS.get(note_key)
        if marker is not None and label.endswith(marker):
            label = label[: -len(marker)]
        # An unrecognised note_key still resolves to something displayable — see
        # translate()'s own fallback to the key itself — rather than raising and
        # taking the whole discovery list down over one unexpected value.
        note = translate(note_key, self.language)
        return f"{label} ({note})"

    def _origin_text(self, candidate) -> str:
        # The f-string is inlined into each translate() call, rather than built
        # once into a local variable, so that a key such as
        # 'discovery.origin_windows_registry' is visible as a literal call-site
        # prefix to static analysis (tests/test_i18n_catalogue.py) — a local
        # variable holding the same f-string hid every discovery.origin_* key
        # from that scan even though it resolves correctly at runtime.
        if candidate.origin == "listening-port":
            return translate(
                f"discovery.origin_{candidate.origin.replace('-', '_')}", self.language
            ).format(host=candidate.host, port=candidate.port)
        base = translate(f"discovery.origin_{candidate.origin.replace('-', '_')}", self.language)
        detail = candidate.origin_detail or ""
        return f"{base} — {detail}" if detail else base

    def _on_completed(self, result) -> None:
        self.status_label.setText("")
        notes = list(result.notes)
        self.notes_label.setText(
            (translate("discovery.notes_label", self.language) + " " + " · ".join(notes)) if notes else "")
        has_any = (
            self._local_group.childCount() or self._network_group.childCount()
            if self._local_group and self._network_group else 0
        )
        if not has_any:
            self.status_label.setText(translate("discovery.no_candidates", self.language))
        self.tree.expandAll()
        if self._search_mode == "network":
            self._audit_network_sweep(result=result)

    def _on_failed(self, message: str) -> None:
        self.status_label.setText("")
        box = QMessageBox(self)
        box.setIcon(QMessageBox.Icon.Warning)
        box.setWindowTitle(translate("discovery.failed_title", self.language))
        box.setText(message)
        box.addButton(translate("common.ok", self.language), QMessageBox.ButtonRole.AcceptRole)
        box.exec()
        if self._search_mode == "network":
            self._audit_network_sweep(error=message)

    def _audit_network_sweep(self, *, result=None, error: str | None = None) -> None:
        """One ``audit.db`` row for the sweep that just ran — not the consent that may
        (or, on a remembered session, may not) have preceded it.

        Called from ``_on_completed``/``_on_failed`` for every ``"network"`` worker run,
        regardless of whether ``_confirm_network_search`` just asked the operator or
        found the session already confirmed — see ``db.discovery.audit_network_discovery``'s
        own docstring, which makes this call mandatory on every sweep. This is the row
        QA found missing: a second (or later) search in the same session used to leave
        no trace at all once the confirmation was no longer being re-asked.
        """
        from sape_d_mcp.db.discovery import audit_network_discovery

        log_store = getattr(self.app, "log_store", None) if self.app else None
        if result is not None:
            candidates = getattr(result, "candidates", ())
            notes = getattr(result, "notes", ())
            replies = getattr(result, "replies", 0)
            accepted = len(candidates)
            audit_network_discovery(
                log_store,
                "gui",
                timeout_s=_NETWORK_TIMEOUT_S,
                accepted=accepted,
                discarded=max(0, replies - accepted),
                result_summary=" · ".join(notes) or None,
            )
        else:
            audit_network_discovery(
                log_store,
                "gui",
                timeout_s=_NETWORK_TIMEOUT_S,
                error=error,
            )

    def _on_worker_finished(self) -> None:
        self._worker = None
        self._set_buttons_enabled(True)

    def _set_buttons_enabled(self, enabled: bool) -> None:
        self.search_local_button.setEnabled(enabled)
        self.search_network_button.setEnabled(enabled)
        self.search_folder_button.setEnabled(enabled)

    # -- selection / use -----------------------------------------------------

    def _on_selection_changed(self) -> None:
        items = self.tree.selectedItems()
        candidate = None
        if items:
            key = items[0].data(0, Qt.ItemDataRole.UserRole)
            candidate = self._candidates_by_item.get(key)
        self.use_button.setEnabled(candidate is not None)

    def _on_use(self) -> None:
        items = self.tree.selectedItems()
        if not items:
            return
        key = items[0].data(0, Qt.ItemDataRole.UserRole)
        candidate = self._candidates_by_item.get(key)
        if candidate is None:
            return
        self.result_candidate = candidate
        self.accept()

    # -- lifecycle -------------------------------------------------------

    def _stop_worker(self) -> None:
        # f-MCP defect 9: a closeEvent that never stopped its thread. Here the
        # worker is cancelled cooperatively and given a bounded wait rather
        # than terminate()d, per DESIGN-CONNECTION-SETUP.md §7.9 point 3.
        if self._worker is not None and self._worker.isRunning():
            self._worker.cancel()
            self._worker.wait(3000)

    def closeEvent(self, event) -> None:
        self._stop_worker()
        super().closeEvent(event)

    def reject(self) -> None:
        self._stop_worker()
        super().reject()

    # -- i18n ----------------------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.language = language
        self.setWindowTitle(translate("discovery.title", language))
        self.title_label.setText(translate("discovery.title", language))
        self.subtitle_label.setText(translate("discovery.subtitle", language))
        self.search_local_button.setText(translate("discovery.search_local_button", language))
        self.search_network_button.setText(translate("discovery.search_network_button", language))
        self.search_folder_button.setText(translate("discovery.search_folder_button", language))
        self.close_button.setText(translate("common.close", language))
        self.use_button.setText(translate("discovery.use_button", language))
        self.tree.setHeaderLabels([
            translate("discovery.table_header_label", language),
            translate("discovery.table_header_origin", language),
            translate("discovery.table_header_confidence", language),
        ])
        if self._local_group is not None:
            self._local_group.setText(0, translate("discovery.section_confirmed", language))
        if self._network_group is not None:
            self._network_group.setText(0, translate("discovery.section_network", language))
