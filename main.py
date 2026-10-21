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

"""Development convenience shim: run ``python main.py`` from a checkout.

This exists so the README's "clone and run" instructions work without an
install step. It is not the installed entry point — a ``pip install .`` puts
the real one on the path as the ``sape-d-mcp`` console script (see
``[project.scripts]`` in pyproject.toml), which calls the same
``sape_d_mcp.main.run()`` below. Unlike f-MCP, where the console script
points at this root file (which does not exist inside an installed wheel),
here the shim and the console script both resolve to the package.
"""

from __future__ import annotations

import sys
from pathlib import Path

# Put src/ on the path so `import sape_d_mcp` works from an unbuilt checkout,
# without needing an editable install.
sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from sape_d_mcp.main import run

if __name__ == "__main__":
    run()
