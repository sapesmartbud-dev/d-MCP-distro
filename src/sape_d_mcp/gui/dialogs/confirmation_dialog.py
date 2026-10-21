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

"""The human half of the destructive-operation broker: one modal per request.

This is the *only* GUI code that is allowed to call
:meth:`sape_d_mcp.confirmation.ConfirmationBroker.approve` and
:meth:`~sape_d_mcp.confirmation.ConfirmationBroker.refuse`, and it must only ever be
constructed on the Qt GUI thread — see :mod:`sape_d_mcp.gui.confirmation_bridge` for the
cross-thread hand-off that gets a :class:`~sape_d_mcp.confirmation.ConfirmationRequest`
here safely. Constructing or showing this dialog from any other thread is undefined
behaviour in Qt, full stop; nothing in this module does anything to make that safe, it
simply assumes the caller already has.

**What is shown, per DESIGN-MCP-TOOLS.md §8.2:** the connection's display name, the
statement text with placeholders intact — this widget never reformats, strips or
truncates ``request.sql``, since a human approving a *paraphrase* of the statement is not
the same as approving the statement — and the impact estimate. An impact string that is
empty or all whitespace is read as "the estimate failed" and rendered as the translated
``confirmation.impact_unknown`` fallback instead of a blank line, because a blank field
looks like a rendering bug, not like "approving blind" — the whole point of the
requirement is that the human notices.

**The countdown is cosmetic, not authoritative.** The real timeout lives in the broker's
own ``anyio.move_on_after`` clock, started the instant :meth:`ConfirmationBroker.request`
begins waiting — before this dialog even exists. The label and progress bar here are
constructed with the same ``confirmations.timeout_seconds`` value and simply count down in
parallel, so that a silent refusal some tens of seconds from now does not look like the
window ignoring the operator; when this dialog's own clock reaches zero it closes itself
*without* telling the broker anything; the broker's own timeout has, for all practical
purposes, already fired or is about to, and calling :meth:`ConfirmationBroker.refuse` here
too would risk mislabelling a genuine timeout as an operator refusal in the rare case this
side's timer fires a moment earlier (see :meth:`_on_countdown_expired`).
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QVBoxLayout,
)

from sape_d_mcp.confirmation import ConfirmationBroker, ConfirmationRequest
from sape_d_mcp.gui.i18n import translate
from sape_d_mcp.gui.styles.sape_design_tokens import (
    ACTION_DDL,
    ACTION_DELETE,
    ACTION_GRANT,
    ACTION_UPDATE,
    COLOR_WARNING,
)

logger = logging.getLogger(__name__)

# Tool name -> the database-verb hue it belongs to (DEVELOPMENT-PLAN.md's ACTION_*
# vocabulary), matching how NewRuleDialog colours the same verbs elsewhere in the GUI.
# Deliberately a closed map rather than a guess from the tool name's substring: an
# unrecognised tool name (a future brokered tool this dialog has not been taught about
# yet) falls back to ACTION_DELETE, the most severe colour, rather than to something
# reassuring — a dialog this module cannot classify is never allowed to look mild.
_TOOL_CATEGORY_COLOUR = {
    "drop-table": ACTION_DDL,
    "drop-view": ACTION_DDL,
    "drop-function": ACTION_DDL,
    "drop-procedure": ACTION_DDL,
    "edit-function": ACTION_DDL,
    "edit-procedure": ACTION_DDL,
    "delete-rows": ACTION_DELETE,
    "update-rows": ACTION_UPDATE,
    "revoke-role": ACTION_GRANT,
    "remove-user-from-group": ACTION_GRANT,
}


class ConfirmationDialog(QDialog):
    """One modal, bound to exactly one :class:`ConfirmationRequest`.

    Approving or refusing calls straight through to ``broker`` — there is no
    intermediate "pending decision" object for a caller to poll, matching the broker's
    own single-use, no-blanket-approval contract. The dialog does not know, and does not
    need to know, whether ``broker`` has a portal bound; that is
    :mod:`sape_d_mcp.gui.confirmation_bridge`'s and, ultimately, the server thread's
    concern.
    """

    def __init__(
        self,
        parent=None,
        language: str = "en-US",
        *,
        request: ConfirmationRequest,
        broker: ConfirmationBroker,
        timeout_seconds: float,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("confirmationDialog")
        self.language = language
        self.request = request
        self.broker = broker
        # A decision (approve, refuse, or the countdown expiring) has been acted on
        # exactly once. Guards every path that can close this dialog — button clicks,
        # Escape, the window's own close button, and the countdown — so none of them
        # can double-resolve the same request.
        self._resolved = False

        self._total_seconds = max(1, round(timeout_seconds))
        self._remaining_seconds = self._total_seconds

        self.setMinimumWidth(560)
        self.setModal(True)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        # ----- warning banner: text-and-icon, never colour alone -----
        self.banner_title_label = QLabel()
        self.banner_title_label.setObjectName("confirmationBannerTitle")
        title_font = self.banner_title_label.font()
        title_font.setPointSize(13)
        title_font.setBold(True)
        self.banner_title_label.setFont(title_font)

        self.banner_subtitle_label = QLabel()
        self.banner_subtitle_label.setObjectName("confirmationBannerSubtitle")
        self.banner_subtitle_label.setWordWrap(True)
        subtitle_font = self.banner_subtitle_label.font()
        subtitle_font.setItalic(True)
        self.banner_subtitle_label.setFont(subtitle_font)

        layout.addWidget(self._make_banner_frame())

        # ----- connection / operation -----
        field_grid = QVBoxLayout()
        field_grid.setSpacing(6)

        self.connection_row_label = QLabel()
        field_grid.addWidget(self.connection_row_label)

        self.operation_row_label = QLabel()
        self.operation_row_label.setObjectName("confirmationOperationLabel")
        operation_font = self.operation_row_label.font()
        operation_font.setBold(True)
        self.operation_row_label.setFont(operation_font)
        colour = _TOOL_CATEGORY_COLOUR.get(request.tool_name, ACTION_DELETE)
        self.operation_row_label.setStyleSheet(f"color: {colour.name()};")
        field_grid.addWidget(self.operation_row_label)

        layout.addLayout(field_grid)

        # ----- the exact SQL, placeholders intact -----
        self.sql_field_label = QLabel()
        layout.addWidget(self.sql_field_label)

        self.sql_view = QPlainTextEdit()
        self.sql_view.setObjectName("confirmationSqlView")
        self.sql_view.setReadOnly(True)
        self.sql_view.setPlainText(request.sql)
        self.sql_view.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.sql_view.setFixedHeight(120)
        layout.addWidget(self.sql_view)

        # ----- impact estimate -----
        self.impact_field_label = QLabel()
        layout.addWidget(self.impact_field_label)

        self.impact_value_label = QLabel()
        self.impact_value_label.setWordWrap(True)
        self._apply_impact_text(request.impact)
        layout.addWidget(self.impact_value_label)

        # ----- optional reason for refusing -----
        self.reason_label = QLabel()
        layout.addWidget(self.reason_label)
        self.reason_edit = QLineEdit()
        layout.addWidget(self.reason_edit)

        # ----- countdown -----
        countdown_row = QHBoxLayout()
        self.countdown_label = QLabel()
        self.countdown_label.setObjectName("confirmationCountdownLabel")
        countdown_row.addWidget(self.countdown_label)
        countdown_row.addStretch()
        layout.addLayout(countdown_row)

        self.countdown_bar = QProgressBar()
        self.countdown_bar.setObjectName("confirmationCountdownBar")
        self.countdown_bar.setRange(0, self._total_seconds)
        self.countdown_bar.setValue(self._remaining_seconds)
        self.countdown_bar.setTextVisible(False)
        layout.addWidget(self.countdown_bar)

        # ----- buttons -----
        button_row = QHBoxLayout()
        button_row.addStretch()
        self.refuse_button = QPushButton()
        self.refuse_button.setObjectName("confirmationRefuseButton")
        self.refuse_button.setDefault(True)  # the safe choice is the one Enter picks
        self.refuse_button.clicked.connect(self._on_refuse_clicked)
        button_row.addWidget(self.refuse_button)

        self.approve_button = QPushButton()
        self.approve_button.setObjectName("confirmationApproveButton")
        self.approve_button.setStyleSheet(
            f"background-color: {colour.name()}; color: #FFFFFF;"
        )
        self.approve_button.clicked.connect(self._on_approve_clicked)
        button_row.addWidget(self.approve_button)
        layout.addLayout(button_row)

        # A timer parented to this dialog: it is destroyed, and stops firing, the
        # moment the dialog is destroyed, rather than outliving it (see the project's
        # "parent every QTimer" rule).
        self._countdown_timer = QTimer(self)
        self._countdown_timer.setInterval(1000)
        self._countdown_timer.timeout.connect(self._tick)
        self._countdown_timer.start()

        self._update_language(language)

    # -- banner construction ------------------------------------------------------

    def _make_banner_frame(self) -> QFrame:
        """Build the coloured banner frame around the title/subtitle labels.

        A plain :class:`QFrame` carrying only an object name for the QSS to key off
        (see ``#confirmationBanner`` in both stylesheets) — its left border and fill
        are what read as "danger", but the bold title text and the ``⚠`` glyph next
        to it (set in :meth:`_update_language`) carry the same message for anyone who
        cannot distinguish the fill colour from the surrounding page.
        """
        frame = QFrame()
        frame.setObjectName("confirmationBanner")
        frame_layout = QVBoxLayout(frame)
        frame_layout.setContentsMargins(12, 10, 12, 10)
        frame_layout.setSpacing(2)
        frame_layout.addWidget(self.banner_title_label)
        frame_layout.addWidget(self.banner_subtitle_label)
        return frame

    # -- impact text -----------------------------------------------------------------

    def _apply_impact_text(self, impact: str) -> None:
        """Render ``impact``, substituting the translated fallback when it is blank.

        DESIGN-MCP-TOOLS.md §8.2: a failed estimate must not block the operation, but
        the human must be told they are approving blind rather than shown nothing.
        Whoever computes the impact string (the brokered tool's caller, not this
        dialog) is free to leave it empty on failure; blank-or-whitespace is this
        module's contract for "the estimate failed", so the fallback is always shown
        in the operator's own language regardless of what, if anything, the caller
        put in the field.
        """
        text = impact.strip() if impact else ""
        if text:
            self.impact_value_label.setText(text)
            self.impact_value_label.setStyleSheet("")
        else:
            self.impact_value_label.setText(translate("confirmation.impact_unknown", self.language))
            self.impact_value_label.setStyleSheet(f"color: {COLOR_WARNING.name()}; font-style: italic;")

    # -- countdown ---------------------------------------------------------------

    def _tick(self) -> None:
        if self._resolved:
            self._countdown_timer.stop()
            return
        self._remaining_seconds -= 1
        if self._remaining_seconds <= 0:
            self._remaining_seconds = 0
            self._update_countdown_display()
            self._on_countdown_expired()
            return
        self._update_countdown_display()

    def _update_countdown_display(self) -> None:
        self.countdown_bar.setValue(self._remaining_seconds)
        self.countdown_label.setText(
            translate("confirmation.time_remaining", self.language).format(seconds=self._remaining_seconds)
        )

    def _on_countdown_expired(self) -> None:
        """The GUI's own clock ran out. Close without notifying the broker.

        See the module docstring: the broker's own, independent timeout is the
        authoritative one and is either already resolving this same request or
        about to, on its own clock. Calling :meth:`ConfirmationBroker.refuse` from
        here as well risks nothing unsafe — a stale click is always a quiet no-op —
        but it does risk mislabelling the exception's ``reason`` as ``"operator"``
        instead of ``"timeout"`` if this side's timer happens to fire first, which
        is a worse answer for the tool caller than doing nothing here at all.
        """
        if self._resolved:
            return
        self._resolved = True
        self._countdown_timer.stop()
        self.approve_button.setEnabled(False)
        self.refuse_button.setEnabled(False)
        logger.info(
            "Confirmation dialog for '%s' on %s timed out client-side; the broker's own "
            "timeout is authoritative",
            self.request.tool_name,
            self.request.connection,
        )
        super().reject()

    # -- human decisions -----------------------------------------------------------

    def _on_approve_clicked(self) -> None:
        if self._resolved:
            return
        self._resolved = True
        self._countdown_timer.stop()
        try:
            self.broker.approve(self.request.connection, self.request.tool_name, self.request.sql)
        except Exception:
            logger.exception("Failed to deliver approval to the confirmation broker")
        self.accept()

    def _on_refuse_clicked(self) -> None:
        if self._resolved:
            return
        self._resolved = True
        self._countdown_timer.stop()
        reason = self.reason_edit.text().strip() or None
        try:
            self.broker.refuse(self.request.connection, self.request.tool_name, self.request.sql, reason=reason)
        except Exception:
            logger.exception("Failed to deliver a refusal to the confirmation broker")
        self.reject()

    def reject(self) -> None:
        """Escape, the window's close button, or any other dismissal.

        Anything that closes this dialog without going through
        :meth:`_on_approve_clicked` is a refusal — a human who closes the window
        without clicking Approve has not approved anything, and the fail-closed
        posture the broker itself documents (silence, absence and disconnection all
        mean "no") extends to "dismissed the modal" too.
        """
        if not self._resolved:
            self._resolved = True
            self._countdown_timer.stop()
            try:
                self.broker.refuse(self.request.connection, self.request.tool_name, self.request.sql)
            except Exception:
                logger.exception("Failed to deliver a refusal to the confirmation broker")
        super().reject()

    # -- i18n ------------------------------------------------------------------------

    def _update_language(self, language: str) -> None:
        self.language = language
        self.setWindowTitle(translate("confirmation.dialog_title", language))
        self.banner_title_label.setText(f"⚠ {translate('confirmation.warning_banner_title', language)}")
        self.banner_subtitle_label.setText(translate("confirmation.warning_banner_subtitle", language))

        self.connection_row_label.setText(
            f"{translate('confirmation.field_connection', language)}: {self.request.connection}"
        )
        self.operation_row_label.setText(
            f"{translate('confirmation.field_operation', language)}: {self.request.tool_name}"
        )
        self.sql_field_label.setText(translate("confirmation.field_statement", language))
        self.impact_field_label.setText(translate("confirmation.field_impact", language))
        self._apply_impact_text(self.request.impact)
        self.reason_label.setText(translate("confirmation.field_reason", language))
        self.reason_edit.setPlaceholderText(translate("confirmation.field_reason_placeholder", language))
        self.refuse_button.setText(translate("confirmation.refuse_button", language))
        self.approve_button.setText(translate("confirmation.approve_button", language))
        self._update_countdown_display()
