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

"""Language persistence and the application-wide language-change signal.

Unlike f-MCP's ``LanguageManager``, which opens and rewrites
``~/.sape/config.json`` itself, this one holds a reference to the shared
:class:`~sape_d_mcp.gui.config_manager.ConfigManager` and calls its
``get_language()``/``set_language()`` — see that module's docstring for why
d-MCP insists on a single writer.
"""

from __future__ import annotations

import locale
import logging
import os

from PyQt6.QtCore import QObject, pyqtSignal

from sape_d_mcp.gui.config_manager import ConfigManager
from sape_d_mcp.gui.i18n import get_supported_languages

logger = logging.getLogger(__name__)


class LanguageManager(QObject):
    """Manage the active language and broadcast changes to the rest of the GUI."""

    # Emitted with the new language code (e.g. "en-US") whenever it changes.
    language_changed = pyqtSignal(str)

    def __init__(self, config_manager: ConfigManager) -> None:
        """Load the saved language, or auto-detect one on a genuinely first run.

        "First run" is distinguished from "language explicitly set to the
        default" by checking whether ``config_manager.config_file`` exists
        yet at all — ``get_language()`` alone cannot tell the two apart,
        because both return ``"en-US"``.
        """
        super().__init__()
        self._config_manager = config_manager
        self._current_language = config_manager.get_language()

        if self._current_language == "en-US" and not config_manager.config_file.exists():
            detected = self.detect_system_language()
            if detected != "en-US":
                self._current_language = detected
                config_manager.set_language(detected)
                logger.info("Auto-detected system language: %s", detected)

        logger.info("Language manager initialised with language: %s", self._current_language)

    def detect_system_language(self) -> str:
        """Guess a supported language code from the host's locale settings.

        ``locale.getdefaultlocale()`` is deprecated since Python 3.11 and
        scheduled for removal, so it is tried only as a fallback behind
        ``locale.getlocale()`` — which in turn only reports anything useful
        if ``locale.setlocale()`` was already called by someone, which a
        PyQt6 application does not do on our behalf. Between the two, and a
        final fallback to the ``LANG``/``LC_ALL`` environment variables (set
        on Linux and macOS, absent on Windows), this covers every platform
        d-MCP targets without depending on an API due for removal.

        Matching logic, in order:
        1. Exact match (e.g. ``de-DE`` -> ``de-DE``).
        2. Language-only match (e.g. ``pt-PT`` -> ``pt-BR``, the only
           Portuguese variant registered).
        3. ``en-US`` if nothing matches.
        """
        system_locale: str | None = None

        try:
            system_locale = locale.getlocale()[0]
        except Exception as exc:
            logger.debug("locale.getlocale() failed: %s", exc)

        if not system_locale:
            legacy_getter = getattr(locale, "getdefaultlocale", None)
            if legacy_getter is not None:
                try:
                    system_locale = legacy_getter()[0]
                except Exception as exc:
                    logger.debug("locale.getdefaultlocale() failed: %s", exc)

        if not system_locale:
            env_locale = os.environ.get("LANG") or os.environ.get("LC_ALL")
            if env_locale:
                system_locale = env_locale.split(".")[0]  # strip "en_US.UTF-8" -> "en_US"

        if not system_locale:
            logger.debug("No system locale detected, using en-US")
            return "en-US"

        normalized = system_locale.replace("_", "-")
        supported = get_supported_languages()

        if normalized in supported:
            logger.info("Exact locale match: %s", normalized)
            return normalized

        lang_part = normalized.split("-")[0]
        for code in supported:
            if code.split("-")[0] == lang_part:
                logger.info("Language match: %s -> %s", normalized, code)
                return code

        logger.warning("No supported language for system locale %s, using en-US", normalized)
        return "en-US"

    @property
    def current_language(self) -> str:
        """Return the currently active language code."""
        return self._current_language

    def set_language(self, code: str) -> None:
        """Set the active language, persist it and notify subscribers.

        Falls back to ``en-US`` for an unsupported code rather than raising:
        a stale or hand-edited config value should degrade gracefully, not
        crash startup.
        """
        supported = get_supported_languages()
        if code not in supported:
            logger.warning("Invalid language: %s. Using en-US instead.", code)
            code = "en-US"

        if code == self._current_language:
            logger.debug("Language already set to: %s", code)
            return

        self._current_language = code
        self._config_manager.set_language(code)
        self.language_changed.emit(code)
        logger.info("Language changed and persisted: %s", code)
