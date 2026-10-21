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

"""The safety net every SQLite table rebuild in this application runs behind."""

from __future__ import annotations

import contextlib
import logging
import os
import sqlite3
from collections.abc import Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# This module is deliberately free of any dependency on the three stores it serves.
# `permissions.py` must stay usable — and testable — with no connections database
# present at all (DESIGN-DATA-MODEL.md §7.2 step 3), so the shared rebuild machinery
# cannot live in `db/connection_store.py` where it was first written.  It sits beside
# `db_location.py`, which `permissions.py` already imports, for the same reason.


def _now() -> str:
    """ISO 8601 with the local offset, seconds precision — the house audit format."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def database_file(conn: sqlite3.Connection) -> Path | None:
    """The path behind the ``main`` schema, or ``None`` for an in-memory database."""
    for _, name, path in conn.execute("PRAGMA database_list"):
        if name == "main":
            return Path(path) if path else None
    return None  # pragma: no cover - SQLite always reports a main schema


class MigrationRecord:
    """The durable half of a migration's account of itself.

    A migration that rewrites a user's own data has to leave a record a human can
    check field by field, and that ruling was the condition on which the automatic
    host split in ``connection_store._split_compound_hosts`` was accepted at all.
    The logger alone cannot honour it: ``main.py`` sets the root logger to
    ``CRITICAL`` with a ``NullHandler`` on purpose, so that ``--cli`` never writes
    anything to the stdio channel an MCP client is speaking JSON-RPC over — and the
    ordinary GUI launch inherits that setting.  Starting the application therefore
    *ran* the migration and threw its whole account away, and a one-shot migration
    cannot be asked to repeat itself afterwards.

    So every line is written twice: to the logger, which is useful to whoever has
    configured logging, and to a plain text file beside the ``VACUUM INTO`` backup,
    which is where anyone asking "what did it change?" is already looking and which
    keeps the evidence and the safety net together.

    Two properties are load-bearing rather than tidy:

    * **Nothing here can fail the migration.**  The lines are held in memory and
      written once, at the end, to a temporary file that is then ``os.replace``\\ d
      into place, so a full disk leaves either the previous file or none — never a
      half-written record that reads as a complete one.  Every failure is swallowed
      and logged.
    * **No secret can reach it.**  Callers record only columns of the table being
      rebuilt, and neither ``connections`` nor ``rules`` has a column that can hold
      one — which is enforced by those stores' own validation and by the DDL, not
      merely intended here.

    An in-memory database has nowhere to put the file and gets the logger alone;
    it also has no backup and no data to lose, which is the same reasoning.

    Args:
        subject: What the upgrade rewrote, as it reads in a sentence — for example
            ``"your connection profiles"``.  Appears in the file's heading and in
            its closing instructions.
        user: Who was running the application.  Passed in rather than resolved
            here, because the two stores each own their own ``current_user()``
            fallbacks and this module has no business duplicating them.
        notes: Subject-specific paragraphs inserted before the closing rule — the
            place for a statement of what the backup does *not* contain.
    """

    #: Appended to the backup's own name, so the record and the backup sort together
    #: and the timestamped second-backup name carries its own record too.
    SUFFIX = ".log"

    def __init__(
        self, subject: str, *, user: str = "unknown", notes: Sequence[str] = ()
    ) -> None:
        self.path: Path | None = None
        self._subject = subject
        self._user = user
        self._notes = list(notes)
        self._lines: list[str] = []
        self._database: Path | None = None
        self._backup: Path | None = None
        self._version: int | None = None

    def attach(self, *, database: Path, backup: Path, version: int) -> None:
        """Bind the record to the backup it accompanies.  Until then it only logs."""
        self._database = database
        self._backup = backup
        self._version = version
        self.path = backup.with_name(backup.name + self.SUFFIX)

    def note(self, message: str, *args: Any, level: int = logging.WARNING) -> None:
        """Emit one line to the logger and keep the identical text for the file."""
        logger.log(level, message, *args)
        try:
            self._lines.append(message % args if args else message)
        except Exception:  # pragma: no cover - a %-format the logger would also reject
            logger.debug("A migration record line could not be rendered", exc_info=True)

    def write(self, outcome: str) -> None:
        """Write the record, atomically, and never raise.

        Args:
            outcome: The closing sentence — what the migration ended up doing.
        """
        if self.path is None or not self._lines:
            return
        temporary = self.path.with_name(self.path.name + ".partial")
        try:
            temporary.write_text(self._render(outcome), encoding="utf-8")
            os.replace(temporary, self.path)
        except Exception:
            logger.error(
                "The schema upgrade finished, but its record could not be written to %s. "
                "The account of it survives only in this log.",
                self.path,
                exc_info=True,
            )
            # Nothing more can be done about a leftover; it is named `.partial` so
            # it can never be mistaken for the record itself.
            with contextlib.suppress(OSError):
                temporary.unlink(missing_ok=True)

    def _render(self, outcome: str) -> str:
        body = [
            f"SAPÉ d-MCP — record of an automatic upgrade of {self._subject}",
            "=" * 78,
            "",
            f"Written    {_now()}",
            f"By         {self._user}",
            f"Database   {self._database}",
            f"Backup     {self._backup}",
            f"Schema     version {(self._version or 1) - 1} -> {self._version}",
            "",
            "This file exists because the upgrade rewrote data you had entered, and it",
            "runs once and only once: there is no way to ask it again afterwards what it",
            "did. Check every line below against the entry it names. If anything is not",
            "what you meant, the backup above is the database exactly as it was before —",
            "close d-MCP, put it back in place of the database above, and correct the",
            "entry by hand.",
            "",
            "Values appear as Python writes them, so a backslash is shown doubled",
            r"('PC-ARR\\SQLEXPRESS') and the surrounding quotes are not part of the value.",
        ]
        for note in self._notes:
            body.extend(["", note])
        body.extend(["", "-" * 78, ""])
        body.extend(self._lines)
        body.extend(["", "-" * 78, outcome, ""])
        return "\n".join(body)


def backup_before_rebuild(
    conn: sqlite3.Connection,
    version: int,
    record: MigrationRecord | None = None,
    *,
    subject: str = "this database",
) -> Path | None:
    """Copy the database beside itself before a table rebuild touches it.

    ``VACUUM INTO`` (SQLite >= 3.27, which every supported Python ships) rather
    than a file copy: it takes a read lock and writes a consistent database, where
    copying the file alone would miss the WAL and produce a backup missing the most
    recent writes.

    A failure here **aborts the migration**.  Refusing to start is recoverable; a
    half-rebuilt table is not, and losing ``connections.db`` costs the user every
    profile *and* strands every keyring entry, because the account name is derived
    from the row id.  Losing ``permissions.db`` is the same shape of harm pointed
    the other way: every rule an operator wrote by hand, gone, with default-deny
    then locking the LLM out of everything until they are all written again.

    Args:
        record: The durable account of the migration, bound here to the backup it
            will sit beside.  ``None`` — which is what a caller reaching this
            function directly gets — stands in an unattached record, so the lines
            still reach the logger and are then discarded.
        subject: What is being backed up, for the messages.

    Returns:
        Where the backup went, or ``None`` for an in-memory database, which has
        nothing on disk to lose.
    """
    record = record if record is not None else MigrationRecord(subject)
    path = database_file(conn)
    if path is None:
        logger.info(
            "This database is in memory, so the schema %s rebuild has nothing to back up.",
            version,
        )
        return None

    backup = path.with_name(f"{path.name}.v{version - 1}.backup")
    if backup.exists():
        # Never overwrite an earlier backup: it may be the only surviving copy of a
        # data set someone is still recovering.
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup = path.with_name(f"{path.name}.v{version - 1}.{stamp}.backup")

    conn.commit()
    try:
        conn.execute("VACUUM INTO ?", (str(backup),))
    except sqlite3.Error as exc:
        raise RuntimeError(
            f"Cannot back up {path} before upgrading it to schema version {version}: "
            f"{exc}. The upgrade has not started and {subject} are untouched. "
            "Free some disk space, or check the permissions on the directory, and "
            "start d-MCP again."
        ) from exc

    # Bind the record before the first line is noted, so the message naming the
    # backup is itself the first line of the file sitting beside it.
    record.attach(database=path, backup=backup, version=version)
    record.note(
        "Upgrading %s to schema version %s. A copy of the previous database was "
        "written to %s — keep it until you are satisfied %s survived.",
        path,
        version,
        backup,
        subject,
    )
    return backup
