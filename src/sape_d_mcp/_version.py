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

"""Single source of truth for the project version.

Everything that reports a version reads it from here:

* ``pyproject.toml`` via ``[tool.setuptools.dynamic]``, which parses
  ``__version__`` statically — this is *why* it has to stay a bare literal
* :mod:`sape_d_mcp` (``__version__``, re-exported from ``__init__.py``)
* the CLI's ``--version`` flag and the version advertised to MCP clients in
  :class:`sape_d_mcp.mcp_server.DatabaseMCPServer` (``main.py``, ``mcp_server.py``)
* the About page, the Settings page, and the header bar's title, in the GUI
  (``about_page.py``, ``settings_page.py``,
  :class:`sape_d_mcp.gui.components.header.Header`)
* the legal documents, which quote it in their footer

``__version__`` is the packaging identifier: PEP 440 forbids spaces in it, so
no release stage (``"Beta"``, ``"RC1"``, …) can ever live inside this string —
doing so would break ``pyproject.toml``'s static parse at build time.
``RELEASE_STAGE`` carries that instead, as a separate piece of data, and
``VERSION_DISPLAY`` is the one pre-composed string every human-facing surface
should show so that no two of them invent a different way of gluing the two
together. Set ``RELEASE_STAGE = ""`` on release day — every consumer of
``VERSION_DISPLAY`` then shows the bare version with no code change anywhere
else.

Keep this module free of imports so it stays cheap to read and safe for
setuptools to parse statically at build time.
"""

__version__ = "0.1.0.8"

# The word shown next to the version everywhere a human reads it — not part of
# ``__version__`` itself, because PEP 440 has no room in that string for a
# space and a word. Flip this single line to "" (not None: consumers
# interpolate it, and f"{None}" prints the literal word "None") the day this
# build is released, and VERSION_DISPLAY below collapses to __version__
# without anyone else having to change anything.
RELEASE_STAGE = "Beta"

# The one ready-to-show string. Deliberately without a leading "v": of
# today's five call sites, two print it unmodified (main.py's --version, and
# the version advertised to MCP clients in mcp_server.py) and the other
# three add their own "v" at the point of display (about_page.py,
# settings_page.py, header.py) — baking "v" in here would force the first
# two to strip it back out, which is the very inconsistency this constant
# exists to avoid.
VERSION_DISPLAY = f"{__version__} {RELEASE_STAGE}" if RELEASE_STAGE else __version__
