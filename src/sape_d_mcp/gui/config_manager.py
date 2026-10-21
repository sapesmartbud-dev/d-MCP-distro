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

"""The single writer of ``~/.sape/d-mcp/config.json``.

f-MCP has five components racing to read-modify-write one file
(``ConfigManager``, ``ThemeManager``, ``LanguageManager``, ``MainWindow``,
and a private duplicate ``ConfigManager`` inside ``permissions_page.py``),
any of which can clobber a change another just made between its read and its
write. d-MCP has exactly one writer: this class. ``ThemeManager`` and
``LanguageManager`` hold a reference to a shared ``ConfigManager`` instance
and call its ``get_*``/``set_*`` methods rather than touching the file
themselves.

The config path is namespaced under ``~/.sape/d-mcp/`` rather than
``~/.sape/`` directly — f-MCP writes straight into the shared ``~/.sape/``,
so without the ``d-mcp/`` segment the two applications would overwrite each
other's ``config.json``.

Nothing is written at construction. The file only appears on the first
``set_*()`` call, exactly like f-MCP's manager — a clean checkout that only
ever reads configuration (e.g. a ``--show-permissions``-style inspection
command) should not leave a ``config.json`` behind it.
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


class ConfigManager:
    """Unified configuration manager for all GUI preferences."""

    # copy.deepcopy()'d on every load (see _load_config): f-MCP's
    # DEFAULT_CONFIG.copy() is a shallow copy, so mutating the nested
    # "permissions_rules_table_columns" dict of one instance mutated the class
    # attribute shared by every other instance — including the next process
    # that imported the module fresh and expected pristine defaults.
    DEFAULT_CONFIG: ClassVar[dict[str, Any]] = {
        "language": "en-US",
        "theme": "light",
        "minimize_on_startup": False,
        # False, so a released build opens on the true empty state — the
        # first thing anyone sees on a clean checkout must be what a real
        # first run looks like, not a screen dressed with fictitious rows.
        # A reviewer who wants to judge column widths and text overflow
        # against populated data can still flip this on from the Settings
        # page's "Mockup" group; it just no longer defaults that way.
        "show_sample_data": False,
        # Keyed "0"-"7": permissions_page._RULE_TABLE_COLUMNS is 8 (name, objects,
        # object type, effect, actions, created, user, edit) — a dict stopping short
        # leaves the last columns with no default width at all on a clean checkout.
        #
        # RENAMED to "..._v2" at schema version 3, and deliberately not migrated
        # again, for the same reason it was renamed once already (see below): adding
        # ``rule_name`` inserts a new first column, which shifts every column from
        # "0" up by one. Reusing the old key would apply an install's saved Objects
        # width to the new Name column, its Object type width to Objects, and so on
        # down the row — wrong, and wrong silently, which is worse than a user simply
        # getting fresh defaults once. An unrecognised key is preserved on round-trip
        # rather than dropped (§9.3), so the pre-rename widths sit harmlessly in
        # config.json under their old name.
        #
        # Originally "permissions_table_columns", renamed to
        # "permissions_rules_table_columns" at schema version 2 for the same class of
        # reason: that version merged the old Schema and Name-pattern columns into one
        # Objects column, so every saved index from "1" up denoted a different column
        # too.
        "permissions_rules_table_columns_v2": {
            "0": 140,
            "1": 240,
            "2": 120,
            "3": 220,
            "4": 90,
            "5": 90,
            "6": 100,
            "7": 90,
        },
        "window_state": {},
        "last_page": 0,
        # DESIGN-DATA-MODEL.md §9.1/§9.2. ``timeout_seconds`` is the wait the
        # confirmation broker gives a human before a brokered destructive call is
        # refused (``sape_d_mcp.confirmation.DEFAULT_TIMEOUT_S`` mirrors this same
        # default for callers with no config to read). ``remember_for_session`` is
        # carried for schema completeness only — DESIGN-MCP-TOOLS.md §8.2 is explicit
        # that there is no blanket approval, and confirmation.py has no code path
        # that could honour it; wiring it up is a future conversation, not a flag
        # this GUI flips today.
        "confirmations": {
            "timeout_seconds": 60,
            "remember_for_session": False,
        },
        # DESIGN-DATA-MODEL.md §9.1/§9.2 — the Logs page's own preferences.
        # ``max_rows_displayed`` is per tab and deliberately independent of
        # ``audit.db``'s 10 000-row global rotation (log_store.py's
        # ROTATE_ABOVE_ROWS): one caps what a query returns to one tab, the other
        # caps what the database keeps for every tab put together.
        "logs": {
            "poll_interval_ms": 500,
            "auto_refresh": True,
            "max_rows_displayed": 1000,
            "denied_only": False,
            "last_export_directory": None,
        },
        "logs_table_columns": {
            "0": 160,  # timestamp
            "1": 150,  # tool
            "2": 110,  # decision
            "3": 70,   # rows
            "4": 110,  # duration
            "5": 320,  # result / error
        },
    }

    # Fields removed from previous SAPÉ applications' config schemas. Kept as
    # its own list, mirroring f-MCP's deprecation-strip-on-load pattern, so a
    # config.json inherited or hand-edited from an older build gets cleaned
    # up automatically instead of carrying dead keys forever.
    _DEPRECATED_KEYS = ("auto_start_gui", "auto_start_server")

    def __init__(self) -> None:
        """Load existing configuration, if any. Writes nothing."""
        self.config_dir = Path.home() / ".sape" / "d-mcp"
        self.config_file = self.config_dir / "config.json"
        self._config = self._load_config()

    def _load_config(self) -> dict[str, Any]:
        """Load configuration from file, merged over the defaults."""
        config = copy.deepcopy(self.DEFAULT_CONFIG)

        if not self.config_file.exists():
            logger.info("No config file at %s, using defaults", self.config_file)
            return config

        try:
            with open(self.config_file, encoding="utf-8") as f:
                file_config = json.load(f)
            config.update(file_config)
            logger.info("Loaded configuration from %s", self.config_file)
        except Exception as exc:
            logger.error("Error loading configuration from %s: %s. Using defaults.", self.config_file, exc)
            return config

        removed = [key for key in self._DEPRECATED_KEYS if key in config]
        if removed:
            for key in removed:
                del config[key]
                logger.info("Removed deprecated config field: %s", key)
            self._config = config
            self._save_config()

        return config

    def _save_config(self) -> None:
        """Persist the in-memory configuration to disk.

        Creates ``self.config_dir`` on demand: it is not created at
        construction (see the module docstring), only the first time there
        is actually something to write.
        """
        try:
            self.config_dir.mkdir(parents=True, exist_ok=True)
            with open(self.config_file, "w", encoding="utf-8") as f:
                json.dump(self._config, f, indent=2, ensure_ascii=False)
            logger.info("Configuration saved to %s", self.config_file)
        except Exception as exc:
            logger.error("Error saving configuration to %s: %s", self.config_file, exc)

    # ================== Generic key/value access ==================

    def get(self, key: str, default: Any = None) -> Any:
        """Return a config value by key, or ``default`` if absent."""
        return self._config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set and persist a config value."""
        self._config[key] = value
        self._save_config()
        logger.debug("Config setting saved: %s=%r", key, value)

    def get_all(self) -> dict[str, Any]:
        """Return a deep copy of the complete configuration.

        Deep, not shallow, for the same reason ``DEFAULT_CONFIG`` is
        deep-copied on load: a caller mutating the nested
        ``permissions_rules_table_columns`` dict it got back must not be able to
        reach into this instance's own state without going through ``set()``.
        """
        return copy.deepcopy(self._config)

    # ================== Language ==================

    def get_language(self) -> str:
        """Return the saved language code (e.g. ``"en-US"``)."""
        return self._config.get("language", self.DEFAULT_CONFIG["language"])

    def set_language(self, code: str) -> None:
        """Set and persist the language code."""
        self.set("language", code)

    # ================== Theme ==================

    def get_theme(self) -> str:
        """Return the saved theme name (``"light"`` or ``"dark"``)."""
        return self._config.get("theme", self.DEFAULT_CONFIG["theme"])

    def set_theme(self, theme: str) -> None:
        """Set and persist the theme name."""
        self.set("theme", theme)

    # ================== Sample data toggle ==================

    def get_show_sample_data(self) -> bool:
        """Return whether empty pages should render mockup sample data."""
        return bool(self._config.get("show_sample_data", self.DEFAULT_CONFIG["show_sample_data"]))

    def set_show_sample_data(self, on: bool) -> None:
        """Set and persist the sample-data toggle."""
        self.set("show_sample_data", bool(on))

    # ================== Permissions table column widths ==================

    def get_permissions_rules_table_columns(self) -> dict[str, int]:
        """Return the saved permissions rule-table column widths.

        Reads the "_v2" key (see ``DEFAULT_CONFIG`` for why it was renamed again at
        schema version 3) — the public method name is unchanged so neither caller in
        ``permissions_page.py`` had to change, only the storage key underneath it.
        """
        return dict(
            self._config.get(
                "permissions_rules_table_columns_v2",
                self.DEFAULT_CONFIG["permissions_rules_table_columns_v2"],
            )
        )

    def set_permissions_rules_table_columns(self, widths: dict[str, int]) -> None:
        """Set and persist the permissions rule-table column widths."""
        self.set("permissions_rules_table_columns_v2", widths)

    # ================== Window geometry ==================

    def get_window_state(self) -> dict[str, Any]:
        """Return the saved window geometry/state."""
        return dict(self._config.get("window_state", self.DEFAULT_CONFIG["window_state"]))

    def set_window_state(self, state: dict[str, Any]) -> None:
        """Set and persist the window geometry/state.

        Callers debounce this through a 300 ms ``QTimer`` (house style) so a
        window drag does not turn into hundreds of disk writes.
        """
        self.set("window_state", state)

    # ================== Last visited sidebar page ==================

    def get_last_page(self) -> int:
        """Return the sidebar index of the page shown when the window last closed."""
        return int(self._config.get("last_page", self.DEFAULT_CONFIG["last_page"]))

    def set_last_page(self, index: int) -> None:
        """Set and persist the last-visited sidebar page index."""
        self.set("last_page", index)

    # ================== Confirmation broker ==================

    def get_confirmation_timeout_seconds(self) -> float:
        """Return how long the confirmation modal waits for a human before it
        must be treated as timed out, in seconds.

        Read from ``confirmations.timeout_seconds`` rather than hardcoded, so an
        operator can lengthen or shorten the window without a code change — see
        DESIGN-DATA-MODEL.md §9.2. Falls back to the schema default on a missing
        or malformed value rather than raising: a hand-edited config with a
        non-numeric entry here must not stop the GUI from starting.
        """
        default = self.DEFAULT_CONFIG["confirmations"]["timeout_seconds"]
        stored = self._config.get("confirmations", {})
        value = stored.get("timeout_seconds", default) if isinstance(stored, dict) else default
        try:
            seconds = float(value)
        except (TypeError, ValueError):
            logger.warning("Invalid confirmations.timeout_seconds %r; using default %s", value, default)
            return float(default)
        return seconds if seconds > 0 else float(default)

    # ================== Logs page ==================
    # DESIGN-DATA-MODEL.md §9.2. Every getter here falls back to the schema default
    # on a missing or malformed value, exactly like ``get_confirmation_timeout_seconds``
    # above: a hand-edited or older ``config.json`` must never stop the Logs page from
    # opening.

    _LOGS_POLL_FLOOR_MS = 200
    _LOGS_POLL_CEILING_MS = 10_000

    def _logs_config(self) -> dict[str, Any]:
        stored = self._config.get("logs", {})
        return stored if isinstance(stored, dict) else {}

    def get_logs_poll_interval_ms(self) -> int:
        """How often the Logs page re-reads ``audit.db``, in milliseconds.

        Clamped to the §9.2 floor of 200 ms and ceiling of 10 000 ms — the floor keeps
        a mistyped ``0`` from turning the poll into a busy loop, the ceiling keeps a
        mistyped huge value from making the page look frozen.
        """
        default = self.DEFAULT_CONFIG["logs"]["poll_interval_ms"]
        value = self._logs_config().get("poll_interval_ms", default)
        try:
            value = int(value)
        except (TypeError, ValueError):
            logger.warning("Invalid logs.poll_interval_ms %r; using default %s", value, default)
            value = default
        return min(max(value, self._LOGS_POLL_FLOOR_MS), self._LOGS_POLL_CEILING_MS)

    def set_logs_poll_interval_ms(self, value: int) -> None:
        """Set and persist the Logs page's poll interval, clamped as above."""
        clamped = min(max(int(value), self._LOGS_POLL_FLOOR_MS), self._LOGS_POLL_CEILING_MS)
        logs = dict(self._logs_config())
        logs["poll_interval_ms"] = clamped
        self.set("logs", logs)

    def get_logs_max_rows_displayed(self) -> int:
        """How many rows each tab's table shows at most.

        Per tab, and independent of ``audit.db``'s 10 000-row rotation
        (DESIGN-DATA-MODEL.md §9.2) — the two numbers are not the same policy and
        must never be conflated.
        """
        default = self.DEFAULT_CONFIG["logs"]["max_rows_displayed"]
        value = self._logs_config().get("max_rows_displayed", default)
        try:
            value = int(value)
        except (TypeError, ValueError):
            logger.warning("Invalid logs.max_rows_displayed %r; using default %s", value, default)
            return int(default)
        return value if value > 0 else int(default)

    def get_logs_denied_only(self) -> bool:
        """Whether the Logs page should show only ``denied`` rows."""
        return bool(self._logs_config().get("denied_only", self.DEFAULT_CONFIG["logs"]["denied_only"]))

    def set_logs_denied_only(self, on: bool) -> None:
        """Set and persist the "denied only" filter."""
        logs = dict(self._logs_config())
        logs["denied_only"] = bool(on)
        self.set("logs", logs)

    def get_logs_last_export_directory(self) -> str | None:
        """The directory the CSV export dialog last saved to, or ``None``."""
        value = self._logs_config().get("last_export_directory")
        return str(value) if value else None

    def set_logs_last_export_directory(self, directory: str) -> None:
        """Set and persist the CSV export dialog's remembered directory."""
        logs = dict(self._logs_config())
        logs["last_export_directory"] = str(directory)
        self.set("logs", logs)

    # ================== Logs table column widths ==================

    def get_logs_table_columns(self) -> dict[str, int]:
        """Return the saved Logs-table column widths, shared by every tab's table."""
        return dict(self._config.get("logs_table_columns", self.DEFAULT_CONFIG["logs_table_columns"]))

    def set_logs_table_columns(self, widths: dict[str, int]) -> None:
        """Set and persist the Logs-table column widths."""
        self.set("logs_table_columns", widths)
