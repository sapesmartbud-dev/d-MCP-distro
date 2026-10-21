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

"""Modal dialogs: rule editor, MCP client configuration and confirmation prompts."""

from __future__ import annotations

from sape_d_mcp.gui.dialogs.confirmation_dialog import ConfirmationDialog
from sape_d_mcp.gui.dialogs.connection_dialog import ConnectionDialog
from sape_d_mcp.gui.dialogs.discovery_dialog import DiscoveryDialog
from sape_d_mcp.gui.dialogs.mcp_config_dialog import MCPConfigDialog
from sape_d_mcp.gui.dialogs.new_rule_dialog import NewRuleDialog

__all__ = [
    "ConfirmationDialog",
    "ConnectionDialog",
    "DiscoveryDialog",
    "MCPConfigDialog",
    "NewRuleDialog",
]
