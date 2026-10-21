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

"""The one place that decides where ``connections.db``, ``permissions.db`` and
``audit.db`` live, absent a more specific override.

**The defect this module replaces.** ``connection_store.py``, ``permissions.py`` and
``log_store.py`` each used to define their own ``project_root()`` as a fixed count of
``.parent`` hops off their own ``__file__`` — ``parents[3]``, ``parents[2]`` and
``parents[2]`` respectively, one count per module because each sits at a different
depth in the src-layout. In a source checkout that lands on the repository root and
everything works, which is exactly why it went unnoticed until stage 9, when the
built wheel was actually installed rather than read: from
``site-packages/sape_d_mcp/db/connection_store.py``, ``parents[3]`` resolves to
``venv/lib/python3.12/`` and the three databases were created inside the
interpreter's own ``lib/`` directory. Nothing raised — it just quietly worked in the
wrong, possibly unwritable, place.

The irony is that this project already has the fix for the general case:
:mod:`sape_d_mcp.gui.resources` exists *specifically* because f-MCP hand-counted
``.parent`` hops to find its asset trees and was not aware of ``sys._MEIPASS``, and
``DEVELOPMENT-PLAN.md`` lists that as a defect fixed rather than copied. The GUI
asset path was fixed; these three ``project_root()`` functions were not, and each
carried a docstring confidently explaining its own hop count right up until the
wheel install proved it wrong.

**Why one module, not three fixed ones.** Three modules independently answering
"where does my data live" is how the hop counts drifted apart in the first place.
This module is the single place that makes that decision; each store still decides
its own file name (``connections.db``, ``permissions.db``, ``audit.db``) and still
reads its own per-file environment variable first, but the directory the file lands
in — the ``DMCP_DB_DIR`` override, and the fallback if even that is unset — is
decided here once and imported everywhere.

**The decision, and why it is not the only reasonable one.** ``prompt.md`` requires
the three databases to live in the project root, which is well defined for a source
checkout and undefined for an installed package: there is no "project root" once the
code lives in ``site-packages``. Three candidates were put to the user — the
installed package's own directory, the user's home directory under
``~/.sape/d-mcp/``, and the current working directory — and the current working
directory was chosen. That means the three databases are resolved relative to
wherever the process was *launched from*, and a different launch directory
genuinely means different databases. The user was told this plainly and chose it
anyway; it is not this module's job to re-argue the point, only to implement it and
to say plainly, here and at the call sites, what it costs.

**The cost is asymmetric, and worth naming precisely.** ``permissions.py``'s
default-deny invariant means a fresh, empty ``permissions.db`` — the file this
resolver hands back when launched from an unexpected directory — authorises
*nothing*. So the visible failure mode is fail-closed: an LLM that suddenly may do
nothing, not an LLM that may do something it should not. That is the safe direction
for a security-relevant file to fail in. The genuine downside is ``audit.db``: a
split audit trail across several directories is worse for forensics than a missing
one would be, because each fragment still opens and still looks complete — nothing
about the file says "there were other rows, somewhere else". Anyone investigating an
incident has to know to ask where every past working directory was, not just look at
the one file in front of them.

**The escape hatch.** ``DMCP_DB_DIR`` (and the per-file ``DMCP_CONNECTIONS_DB`` /
``DMCP_PERMISSIONS_DB`` / ``DMCP_AUDIT_DB`` variables each store reads before ever
calling into this module) exists precisely so that a caller who cares — the GUI,
which knows exactly which databases it opened, or :mod:`sape_d_mcp.mcp_config_generator`,
which threads the GUI's own paths through to a client-spawned subprocess — never has
to rely on this fallback at all. See that module's ``generate_config`` for the
integration point this actually matters at: an MCP client spawns the server with
whatever working directory it likes, which is essentially never the user's project
directory, so a generated configuration that omitted these variables would silently
reproduce this exact defect on every single launch.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger(__name__)


def resolve_db_directory() -> Path:
    """The directory to use for a ``.db`` file, absent that file's own per-file override.

    Checked in order:

    1. ``DMCP_DB_DIR`` — one directory for all three databases, read by each store
       before it ever calls this function's fallback.
    2. The current working directory — ``prompt.md``'s "project root", reinterpreted
       for an installed package as "wherever this process happened to be launched
       from" (see the module docstring for what that costs and why the user chose it
       anyway).

    Deliberately *not* memoised: unlike :mod:`sape_d_mcp.gui.resources`' asset root,
    which cannot change once the interpreter has started, ``Path.cwd()`` can change
    within a process (a test suite's ``monkeypatch.chdir``, chiefly), and a cached
    answer here would silently stop tracking it.
    """
    directory = os.environ.get("DMCP_DB_DIR")
    if directory:
        return Path(directory).expanduser()
    return Path.cwd()
