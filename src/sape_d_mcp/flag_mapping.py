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

"""Flag file mapping and validation helpers for the 18 supported locales.

f-MCP keeps ``FLAG_MAPPING`` as a second, hand-maintained copy of the very
same code-to-filename table already living in ``LanguageRegistry.LANGUAGES``
— two sources of truth that can (and did, in f-MCP's git history) drift
apart. Here ``FLAG_MAPPING`` is *derived* from ``LanguageRegistry`` instead of
restated, so there is only one place that can go stale. It also resolves
paths through :func:`sape_d_mcp.gui.resources.resource_path` rather than
hand-counting ``.parent`` hops, for the same reason ``language_registry.py``
does.
"""

from __future__ import annotations

from pathlib import Path

from sape_d_mcp.language_registry import LanguageRegistry

# Derived, not restated: see the module docstring.
FLAG_MAPPING: dict[str, str] = {
    code: meta['flag_file'] for code, meta in LanguageRegistry.LANGUAGES.items()
}


def get_flag_path(lang_code: str) -> Path | None:
    """Return the path to the flag PNG for ``lang_code``, or ``None``.

    Example:
        >>> get_flag_path('es-ES').name
        'spain.png'
    """
    flag_file = FLAG_MAPPING.get(lang_code)
    if not flag_file:
        return None

    from sape_d_mcp.gui.resources import resource_path

    try:
        return resource_path('flags', flag_file)
    except FileNotFoundError:
        return None


def flag_exists(lang_code: str) -> bool:
    """Return whether the flag file for ``lang_code`` exists on disk."""
    path = get_flag_path(lang_code)
    return path is not None and path.exists()


def get_all_flag_paths() -> dict[str, Path]:
    """Return a mapping of language code to flag path, for languages present on disk.

    Example:
        >>> len(get_all_flag_paths())
        18
    """
    result: dict[str, Path] = {}
    for lang_code in FLAG_MAPPING:
        path = get_flag_path(lang_code)
        if path is not None and path.exists():
            result[lang_code] = path
    return result


def get_missing_flags() -> list[str]:
    """Return the language codes whose flag files could not be found."""
    return [code for code in FLAG_MAPPING if not flag_exists(code)]


def validate_all_flags() -> tuple[bool, list[str]]:
    """Return ``(all_present, missing_codes)`` for the 18 registered flags."""
    missing = get_missing_flags()
    return len(missing) == 0, missing


def get_flag_file_size(lang_code: str) -> int | None:
    """Return the flag file's size in bytes, or ``None`` if it is missing."""
    path = get_flag_path(lang_code)
    if path is None or not path.exists():
        return None
    return path.stat().st_size


def get_flag_content(lang_code: str) -> bytes | None:
    """Return the flag PNG's raw bytes, or ``None`` if it is missing.

    Example:
        >>> get_flag_content('es-ES')[:4] == b'\\x89PNG'
        True
    """
    path = get_flag_path(lang_code)
    if path is None or not path.exists():
        return None
    return path.read_bytes()


def are_all_flags_present() -> bool:
    """Return whether every registered flag currently resolves to a file.

    Deliberately re-checks the filesystem on every call rather than caching
    the result at import time, unlike f-MCP's module-level
    ``_VALIDATION_RESULT``: resolving ``gui_resources/`` itself already
    raises at import time in :mod:`sape_d_mcp.gui.resources` if the tree is
    entirely absent, so the only thing left for this function to catch is an
    individual missing file, which can only be discovered by looking.
    """
    return validate_all_flags()[0]


def get_missing_flags_at_load_time() -> list[str]:
    """Return the same result as :func:`get_missing_flags`.

    Kept for parity with f-MCP's API; there is no load-time cache to report
    on here (see :func:`are_all_flags_present`), so this simply re-checks.
    """
    return get_missing_flags()
