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

"""Thread-safe JSONL logging for MCP tool executions — the other half of dual logging.

``LogStore`` (``log_store.py``) is the durable, queryable half; this module is the
half that has to work with nothing else available. A d-MCP server is routinely
spawned as a subprocess by an MCP client (Claude Desktop, say), which owns stdout and
stdin, redirects or discards stderr, and can kill the process with no warning on
disconnect. If the only record of what happened lives in SQLite and the process is
killed mid-write, WAL can still leave a consistent file — but if the *disk itself* is
the problem (a container's overlay filesystem gone read-only, a network mount that
dropped), an append-only JSONL file next to ``audit.db`` is the one thing that keeps
being written right up to the last successful ``os.write()``.

Ported from f-MCP's ``tool_logger.py``, with sanitisation and credential scrubbing
delegated to :mod:`sape_d_mcp.log_store` rather than duplicated — f-MCP carries two
near-identical copies of ``_sanitize_params`` (one in each module, the second's
docstring literally reading "copied from ToolLogger to avoid circular imports"); here
there is one function, and no circular import, because this module is the one that
depends on ``log_store``, never the reverse.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import threading
from pathlib import Path
from typing import TYPE_CHECKING, Any

from sape_d_mcp.log_store import _sanitize_params

if TYPE_CHECKING:
    from sape_d_mcp.log_store import LogStore

logger = logging.getLogger(__name__)

#: Same filename f-MCP uses, kept identical because it is the one part of the pair
#: that a human might go looking for by name; only its neighbour changed
#: (``audit.db`` rather than ``permissions.db`` — DESIGN-DATA-MODEL.md §5.2).
LOG_FILENAME = "tool_log.jsonl"

# The four sqlite3.log_tool() keywords this module lifts out of **extra rather than
# forwarding blindly. Named here, once, so log_execution()'s body and its docstring
# cannot drift apart about which extra keys are recognised.
_LOG_TOOL_EXTRA_KEYS: tuple[str, ...] = (
    "connection_id",
    "decision",
    "rows_affected",
    "duration_ms",
    "matched_rule_id",
)


#: The four values `audit.db`'s ck_tool_calls_decision CHECK accepts.
_DECISIONS: frozenset[str] = frozenset({"allowed", "denied", "refused", "error"})


def _infer_decision(supplied: str | None, error: str | None) -> str:
    """The caller's ``decision``, or the honest reading of the call when it omitted one.

    A tool that finished without an error was allowed; one that raised is an error. A
    denial or a guard refusal always arrives explicit, because only the permission layer
    and the guard know which of the two it was.
    """

    if supplied in _DECISIONS:
        return supplied  # type: ignore[return-value]
    return "error" if error else "allowed"


class ToolLogger:
    """Thread-safe JSONL logger for MCP tool executions, with an optional SQLite fan-out.

    Location: ``{db_path.parent}/tool_log.jsonl`` — beside ``audit.db``, not inside
    it, so the file survives even if SQLite itself cannot be opened.

    Format: one JSON object per line —

    .. code-block:: json

        {"timestamp": "2026-09-02T14:23:45+02:00", "session_id": "cli",
         "tool_name": "select_rows", "params": {"...": "..."},
         "result": "12 rows", "error": null, "decision": "allowed",
         "connection_id": 3, "rows_affected": 12, "duration_ms": 8,
         "matched_rule_id": 7}
    """

    def __init__(
        self,
        db_path: str | os.PathLike[str],
        log_store: LogStore | None = None,
        session_id: str | None = None,
    ) -> None:
        """Create (or reopen) the JSONL sink, optionally paired with a ``LogStore``.

        Args:
            db_path: Path to ``audit.db`` (or any path in the same directory the
                JSONL file should live beside — only ``.parent`` is used). The file
                itself is never opened by this class; ``LogStore`` owns that.
            log_store: An already-open ``LogStore`` to fan writes out to, or ``None``
                for JSONL-only logging (the shape a component with no SQLite access
                at all — a pure CLI diagnostic, say — would use).
            session_id: Required if ``log_store`` is given, because every SQLite row
                needs one; ``"cli"`` is the well-known id for a headless subprocess
                server (DESIGN-DATA-MODEL.md §5.2).

        Raises:
            ValueError: ``log_store`` given without ``session_id``.
            OSError: Cannot create the log file or its parent directory.
        """
        if log_store is not None and session_id is None:
            raise ValueError("session_id is required if log_store is provided")

        resolved = Path(db_path).expanduser().resolve()
        self.log_path = resolved.parent / LOG_FILENAME
        self.lock = threading.Lock()  # protects writes within this process
        self.log_store = log_store
        self.session_id = session_id

        try:
            self.log_path.parent.mkdir(parents=True, exist_ok=True)
            self.log_path.touch(exist_ok=True)
        except OSError as exc:
            raise OSError(f"Cannot create log file at {self.log_path}: {exc}") from exc

    def log_execution(
        self,
        tool_name: str,
        params: dict[str, Any],
        result: str | None = None,
        error: str | None = None,
        **extra: Any,
    ) -> None:
        """Log one tool execution to the JSONL file and, if configured, to SQLite.

        Args:
            tool_name: The MCP tool name.
            params: The tool's own arguments; sanitised and credential-scrubbed by
                ``log_store._sanitize_params`` before either sink sees them, so a
                password passed as a parameter reaches neither file
                (DESIGN-DATA-MODEL.md §5.4; DATA-PROTECTION.md).
            result: Free-text outcome, truncated at 1000 characters, or ``None``.
            error: Free-text failure detail, truncated at 1000 characters, or ``None``.
            **extra: Recognised keys are ``connection_id``, ``decision``,
                ``rows_affected``, ``duration_ms`` and ``matched_rule_id`` — the
                remaining ``LogStore.log_tool`` arguments this call cannot supply on
                its own, because they vary per call rather than per logger instance.
                ``decision`` is required by ``LogStore.log_tool`` but is *not*
                required here: when the caller omits it, it is inferred from whether
                ``error`` is set. Skipping the SQLite row instead would leave the two
                sinks disagreeing — the JSONL complete and ``audit.db`` missing the
                call — and ``audit.db`` is what the Logs page reads, so a caller that
                forgot one keyword would silently empty the operator's audit trail.
                A denial always arrives with an explicit ``decision``, because the
                permission layer is what produced it.

        Notes:
            Never raises. A failure in either sink is caught and reported to stderr
            via the module logger; the caller — a tool body mid-execution — must
            never see a logging failure as its own failure.
        """
        timestamp = datetime.datetime.now().astimezone().isoformat(timespec="seconds")

        if result and len(result) > 1000:
            result = result[:1000] + "... (truncated)"
        if error and len(error) > 1000:
            error = error[:1000] + "... (truncated)"

        # Sanitised once, shared by both sinks — the bug this avoids is the two
        # sinks silently disagreeing about what "sanitised" means, which is exactly
        # what f-MCP's two independent copies of _sanitize_params risked.
        sanitised_params = _sanitize_params(params)

        log_entry: dict[str, Any] = {
            "timestamp": timestamp,
            "session_id": self.session_id,
            "tool_name": tool_name,
            "params": sanitised_params,
            "result": result,
            "error": error,
        }
        for key in _LOG_TOOL_EXTRA_KEYS:
            if key in extra:
                log_entry[key] = extra[key]

        try:
            json_line = json.dumps(log_entry, default=str)
        except (TypeError, ValueError):
            # Fallback if log_entry itself has serialisation issues that survived
            # _sanitize_params (an unexpected type nested inside result/error, say).
            log_entry["params"] = {"_error": "log entry serialisation failed"}
            json_line = json.dumps(log_entry, default=str)

        with self.lock:
            self._append_atomically(json_line)

        if self.log_store is not None and self.session_id is not None:
            try:
                self.log_store.log_tool(
                    extra.get("connection_id"),
                    self.session_id,
                    tool_name,
                    sanitised_params,
                    result=result,
                    error=error,
                    decision=_infer_decision(extra.get("decision"), error),
                    rows_affected=extra.get("rows_affected"),
                    duration_ms=extra.get("duration_ms"),
                    matched_rule_id=extra.get("matched_rule_id"),
                )
            except Exception as exc:
                # LogStore already swallows its own sqlite3.Error internally, so
                # reaching this branch is unusual. Whatever the cause, a logging
                # failure must not become a tool-execution failure: warn, never raise.
                logger.warning("Failed to log to SQLite audit store: %s", exc)

    def _append_atomically(self, line: str) -> None:
        """Append one line to the JSONL file using an atomic O_APPEND write.

        Ported from f-MCP unchanged: on POSIX, ``O_APPEND`` guarantees the kernel
        serialises concurrent appends from multiple processes without any locking
        of our own, which is exactly the property needed when the GUI and one or
        more MCP server processes can all be writing this file at once.
        """
        try:
            flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
            mode = 0o666  # rw-rw-rw-, respects umask
            fd = os.open(str(self.log_path), flags, mode)
            try:
                os.write(fd, (line + "\n").encode("utf-8"))
            finally:
                os.close(fd)
        except OSError as exc:
            logger.warning("Failed to write to %s: %s", self.log_path, exc)
        except Exception:  # pragma: no cover - defensive, mirrors log_store.py
            logger.exception("Unexpected error writing to %s", self.log_path)
