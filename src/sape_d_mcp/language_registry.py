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

"""Language registry with metadata for all 18 supported locales.

d-MCP registers the same 18 locales as f-MCP so the two applications' i18n
tooling, flag assets and translation generators stay directly comparable.
Unlike f-MCP's copy, :meth:`get_flag_path` resolves the flag file through
:mod:`sape_d_mcp.gui.resources` rather than hand-counting ``.parent`` hops —
that hand-counting is one of the defects this port fixes (see
``.claude/skills/fmcp-reference/SKILL.md``).
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar


class LanguageRegistry:
    """Registry of all 18 supported languages with metadata."""

    LANGUAGES: ClassVar[dict[str, dict[str, str]]] = {
        'en-US': {
            'native': 'English',
            'english': 'English',
            'region': 'North America',
            'flag_file': 'england.png',
        },
        'es-ES': {
            'native': 'Español',
            'english': 'Spanish',
            'region': 'Western Europe',
            'flag_file': 'spain.png',
        },
        'fr-FR': {
            'native': 'Français',
            'english': 'French',
            'region': 'Western Europe',
            'flag_file': 'france.png',
        },
        'de-DE': {
            'native': 'Deutsch',
            'english': 'German',
            'region': 'Western Europe',
            'flag_file': 'germany.png',
        },
        'it-IT': {
            'native': 'Italiano',
            'english': 'Italian',
            'region': 'Western Europe',
            'flag_file': 'italy.png',
        },
        'pt-BR': {
            'native': 'Português',
            'english': 'Portuguese',
            'region': 'South America',
            'flag_file': 'brazil.png',
        },
        'nl-NL': {
            'native': 'Nederlands',
            'english': 'Dutch',
            'region': 'Western Europe',
            'flag_file': 'netherlands.png',
        },
        'sv-SE': {
            'native': 'Svenska',
            'english': 'Swedish',
            'region': 'Northern Europe',
            'flag_file': 'sweden.png',
        },
        'da-DK': {
            'native': 'Dansk',
            'english': 'Danish',
            'region': 'Northern Europe',
            'flag_file': 'denmark.png',
        },
        'fi-FI': {
            'native': 'Suomi',
            'english': 'Finnish',
            'region': 'Northern Europe',
            'flag_file': 'finland.png',
        },
        'pl-PL': {
            'native': 'Polski',
            'english': 'Polish',
            'region': 'Eastern Europe',
            'flag_file': 'poland.png',
        },
        'cs-CZ': {
            'native': 'Čeština',
            'english': 'Czech',
            'region': 'Eastern Europe',
            'flag_file': 'czech.png',
        },
        'sk-SK': {
            'native': 'Slovenčina',
            'english': 'Slovak',
            'region': 'Eastern Europe',
            'flag_file': 'slovakia.png',
        },
        'hu-HU': {
            'native': 'Magyar',
            'english': 'Hungarian',
            'region': 'Eastern Europe',
            'flag_file': 'hungary.png',
        },
        'ro-RO': {
            'native': 'Română',
            'english': 'Romanian',
            'region': 'Eastern Europe',
            'flag_file': 'romania.png',
        },
        'ru-RU': {
            'native': 'Русский',
            'english': 'Russian',
            'region': 'Eastern Europe',
            'flag_file': 'russia.png',
        },
        'is-IS': {
            'native': 'Íslenska',
            'english': 'Icelandic',
            'region': 'Northern Europe',
            'flag_file': 'iceland.png',
        },
        'zh-CN': {
            'native': '中文',
            'english': 'Chinese (Simplified)',
            'region': 'Asia',
            'flag_file': 'china.png',
        },
    }

    @classmethod
    def get_all_languages_sorted(cls) -> list[tuple[str, str]]:
        """Return (code, native_name) tuples sorted alphabetically by native name.

        Example:
            >>> LanguageRegistry.get_all_languages_sorted()[0]
            ('zh-CN', '中文')
        """
        items = [(code, meta['native']) for code, meta in cls.LANGUAGES.items()]
        return sorted(items, key=lambda x: x[1])

    @classmethod
    def get_native_name(cls, lang_code: str) -> str:
        """Return the native language name, or the code itself if unknown."""
        return cls.LANGUAGES.get(lang_code, {}).get('native', lang_code)

    @classmethod
    def get_english_name(cls, lang_code: str) -> str:
        """Return the English language name, or the code itself if unknown."""
        return cls.LANGUAGES.get(lang_code, {}).get('english', lang_code)

    @classmethod
    def get_region(cls, lang_code: str) -> str:
        """Return the geographic region, or an empty string if unknown."""
        return cls.LANGUAGES.get(lang_code, {}).get('region', '')

    @classmethod
    def get_flag_path(cls, lang_code: str) -> Path | None:
        """Return the full path to the flag PNG for ``lang_code``.

        Routed through :func:`sape_d_mcp.gui.resources.resource_path` rather
        than a locally hand-counted ``Path(__file__).parent...`` chain — that
        chain is exactly what broke f-MCP's frozen builds, because it assumes
        a source checkout and is never ``sys._MEIPASS``-aware.

        The import is local to avoid a module-load-time dependency from a
        non-GUI module (``language_registry``) onto the GUI package; a
        ``--cli`` server that never imports ``sape_d_mcp.gui`` should not pay
        for or fail on a PyQt6-free environment because of a language lookup
        it never performs.
        """
        if lang_code not in cls.LANGUAGES:
            return None

        from sape_d_mcp.gui.resources import resource_path

        flag_file = cls.LANGUAGES[lang_code]['flag_file']
        try:
            return resource_path('flags', flag_file)
        except FileNotFoundError:
            return None

    @classmethod
    def is_valid_language(cls, lang_code: str) -> bool:
        """Return whether ``lang_code`` is one of the 18 registered locales."""
        return lang_code in cls.LANGUAGES

    @classmethod
    def get_language_count(cls) -> int:
        """Return the number of registered languages (18)."""
        return len(cls.LANGUAGES)

    @classmethod
    def get_languages_by_region(cls, region: str) -> list[tuple[str, str]]:
        """Return (code, native_name) tuples for ``region``, sorted by native name."""
        items = [
            (code, meta['native'])
            for code, meta in cls.LANGUAGES.items()
            if meta['region'] == region
        ]
        return sorted(items, key=lambda x: x[1])
