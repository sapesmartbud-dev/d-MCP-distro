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

"""Build the exact JSON a client configuration file can hold, verbatim.

f-MCP has a namesake ``ConfigJSONGenerator``, and it is a model to fix rather than a model to
follow. It wraps the wizard's ``mcpServers`` entry in four more top-level keys
(``server``, ``tools``, ``permissions``, ``setup_instructions``) that no client understands —
a page showing that whole document to a user invites them to paste something a client would
reject. Worse, its ``tools``/``permissions`` sections are static lists that duplicate what
the server itself already knows and will drift the moment a tool is added or renamed, and its
``setup_instructions`` are 400-odd lines of hardcoded per-platform prose (model names, code
samples) that is nobody's job here to keep current. Its ``to_file(filepath)`` writes to
*any* path the caller names — a second config writer, sitting unused today but one dialog
button away from being pointed at the client's own file, which is precisely the mistake
DEVELOPMENT-PLAN.md's "f-MCP defects to fix" list item 4 (four writers that can clobber one
another) and the stage-9 brief's "never write the client's own config file" rule both warn
against. None of that is reproduced here.

This module does one thing: given a live server (or anything that quacks like one), return
the ``{"mcpServers": {"sape-d-mcp": {...}}}`` document — and only that document — ready to
copy into a client's configuration file. It never opens a file. The GUI's Settings/MCP-config
page is expected to show :meth:`ConfigJSONGenerator.to_client_config_string` in a read-only
text box next to a "Copy" button and :meth:`MCPConfigGenerator.client_config_path` telling the
user where to paste it — never a "Save" button that writes anywhere on this caller's behalf.

This is *not* a second writer for the GUI's own ``~/.sape/d-mcp/config.json``: that file
holds this application's own preferences (theme, language, window state, …) and has exactly
one writer, ``gui/config_manager.py``'s ``ConfigManager`` — a different file, a different
concern, and this module never touches it.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sape_d_mcp.mcp_config_generator import MCPConfigGenerator

logger = logging.getLogger(__name__)


class ConfigJSONGenerator:
    """Wrap :meth:`MCPConfigGenerator.generate_config` in the ``mcpServers`` envelope.

    Takes anything shaped like :class:`sape_d_mcp.mcp_server.DatabaseMCPServer` — an object
    with ``.connections``, ``.permissions`` and ``.log_store`` attributes each optionally
    carrying a ``.db_path`` — so the GUI can hand over its live server and get back the
    configuration for *that* server's actual databases. Every attribute lookup is a
    ``getattr`` with a ``None`` default, so a stub with only some of the three attributes
    (or none at all, as in a ``--show-permissions``-style inspection with no server running
    yet) still produces a configuration — but a database this object was not told about is
    *not* left out of the emitted environment. ``MCPConfigGenerator.generate_config``
    resolves that store's own ``default_db_path()`` itself for whichever one was missing,
    because a client-spawned subprocess's working directory is not guaranteed to match this
    process's, and each store's own default has resolved against the working directory since
    stage 9 (see that method's docstring, and ``sape_d_mcp.db_location``).
    """

    #: Server name written into client configuration files. The Settings page and the (not
    #: yet built) MCP-config dialog use the same one, so a user who visits both registers one
    #: server rather than two copies of it.
    CLIENT_SERVER_NAME = "sape-d-mcp"

    def __init__(self, server: Any, transport: str = "stdio") -> None:
        """Args:
            server: Typically a `sape_d_mcp.mcp_server.DatabaseMCPServer`; only duck-typed
                attribute access is required, so a test double works too.
            transport: Passed through to `MCPConfigGenerator.generate_config` unchanged.
        """
        self.server = server
        self.transport = transport

    @staticmethod
    def _db_path(server: Any, attribute: str) -> str | None:
        """The `.db_path` of `server.<attribute>`, or `None` if either is absent."""
        store = getattr(server, attribute, None)
        db_path = getattr(store, "db_path", None)
        return str(db_path) if db_path else None

    def entry(self) -> dict[str, Any]:
        """The bare `{"command": …, "args": […], "env": {…}}` dictionary, with no wrapper.

        Raises:
            ValueError: If the installation cannot be detected, in which case there is no
                command to launch and no configuration to show.
        """
        generator = MCPConfigGenerator()
        installation = generator.detect_installation()
        return generator.generate_config(
            installation,
            connections_db=self._db_path(self.server, "connections"),
            permissions_db=self._db_path(self.server, "permissions"),
            audit_db=self._db_path(self.server, "log_store"),
            transport=self.transport,
        )

    def client_config(self) -> dict[str, Any]:
        """The one document a client configuration file can hold verbatim.

        Returns:
            `{"mcpServers": {"sape-d-mcp": {...}}}` — nothing else. Pasting this into
            `claude_desktop_config.json` (merged with whatever `mcpServers` entries are
            already there, never replacing the file — see `MCPConfigGenerator
            .generate_instructions`) is the entire integration story.

        Raises:
            ValueError: If the installation cannot be detected.
        """
        return {"mcpServers": {self.CLIENT_SERVER_NAME: self.entry()}}

    def to_client_config_string(self, indent: int = 2) -> str:
        """`client_config()`, pretty-printed for a read-only text box or a copy button.

        Raises:
            ValueError: If the installation cannot be detected.
        """
        return json.dumps(self.client_config(), indent=indent, ensure_ascii=False)
