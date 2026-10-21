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

"""Sidebar pages: Connections, Permissions, Logs, Settings, Legal, Help and About.

The Explorer page f-MCP would have had is folded into Permissions as its
left-hand schema browser (DEVELOPMENT-PLAN.md's confirmed decision), so there
are seven pages here, not eight.
"""

from __future__ import annotations

from sape_d_mcp.gui.pages.about_page import AboutPage
from sape_d_mcp.gui.pages.connections_page import ConnectionsPage
from sape_d_mcp.gui.pages.help_page import HelpPage
from sape_d_mcp.gui.pages.legal_page import LegalPage
from sape_d_mcp.gui.pages.logs_page import LogsPage
from sape_d_mcp.gui.pages.permissions_page import PermissionsPage
from sape_d_mcp.gui.pages.settings_page import SettingsPage

__all__ = [
    "AboutPage",
    "ConnectionsPage",
    "HelpPage",
    "LegalPage",
    "LogsPage",
    "PermissionsPage",
    "SettingsPage",
]
