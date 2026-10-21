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

"""Internationalisation package: re-exports the generated translation lookup.

See :mod:`sape_d_mcp.gui.i18n.translations` for the generated table itself,
and ``tools/generate_translations.py`` for how to regenerate it.
"""

from __future__ import annotations

from sape_d_mcp.gui.i18n.translations import get_supported_languages, translate

__all__ = ["get_supported_languages", "translate"]
