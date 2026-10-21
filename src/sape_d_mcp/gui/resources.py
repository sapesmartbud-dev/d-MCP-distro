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

"""Frozen-aware resolution of the ``gui_resources/`` and ``legal-documents/`` trees.

f-MCP has no equivalent of this module: every consumer hand-counts two, three
or four ``.parent`` hops off its own ``__file__`` to reach the asset trees,
and none of those call sites know about ``sys._MEIPASS``, so a PyInstaller
build silently looks in the wrong place. d-MCP centralises the lookup here so
there is exactly one place that knows how the trees are found, in each of the
three shapes the project can run in:

1. **Frozen** — PyInstaller sets ``sys._MEIPASS`` to the temporary extraction
   directory and bundles the two trees at its root.
2. **Development checkout** — this file lives at
   ``src/sape_d_mcp/gui/resources.py``, four ``.parent`` hops below the repo
   root (``gui`` -> ``sape_d_mcp`` -> ``src`` -> root). f-MCP's modules sit
   directly under ``src/``, which is why its equivalent hops are two or
   three; the src-layout here adds one more level, and getting that count
   wrong is precisely the class of bug this module exists to avoid repeating.
3. **Installed** — ``pyproject.toml``'s ``[tool.setuptools.data-files]``
   installs both trees under ``sys.prefix`` (verified against a real
   ``pip install .``), landing them at ``sys.prefix/gui_resources`` and
   ``sys.prefix/legal-documents``.

The resolved root is cached at import time: it cannot change over the life of
the process (the interpreter does not move filesystems mid-run), so resolving
it once and raising immediately if none of the three candidates exist is
preferable to a callable that might succeed on one call and fail mysteriously
on the next.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

logger = logging.getLogger(__name__)


def _candidate_roots() -> list[tuple[str, Path]]:
    """Return the (mode, path) pairs to try, in priority order.

    A list rather than a generator so a failed resolution can report every
    path it tried, not just the last one — the whole point of naming all
    three in the error message is to save whoever hits it a debugging
    session spent rediscovering this module's own docstring.
    """
    candidates: list[tuple[str, Path]] = []

    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidates.append(("frozen bundle", Path(meipass)))

    # gui/ -> sape_d_mcp/ -> src/ -> repo root. See the module docstring for
    # why this is four hops and not the two or three f-MCP's flatter layout
    # uses.
    dev_root = Path(__file__).resolve().parent.parent.parent.parent
    candidates.append(("development checkout", dev_root))

    candidates.append(("installed prefix", Path(sys.prefix)))

    return candidates


def _resolve_root() -> Path:
    """Find the first candidate that actually contains ``gui_resources/``."""
    tried: list[str] = []
    for mode, path in _candidate_roots():
        tried.append(f"{mode} ({path})")
        if (path / "gui_resources").is_dir():
            logger.debug("Resolved resource root via %s: %s", mode, path)
            return path

    raise FileNotFoundError(
        "Could not locate the gui_resources/ tree. Tried, in order: "
        + "; ".join(tried)
        + ". If this is a development checkout, run from the repository "
        "root (or somewhere below it); if this is a frozen build, the "
        "PyInstaller spec is missing the gui_resources/ data directory; if "
        "this is an installed package, reinstall it — data-files in "
        "pyproject.toml should have placed gui_resources/ next to the "
        "interpreter's sys.prefix."
    )


# Resolved once at import time and reused for the life of the process — see
# the module docstring for why re-resolving per call would not help.
_ROOT: Path = _resolve_root()

RESOURCES_DIR: Path = _ROOT / "gui_resources"


def resource_path(*parts: str) -> Path:
    """Return the absolute path to a resource under ``gui_resources/``.

    Raises ``FileNotFoundError`` naming the missing path rather than
    returning it anyway: a caller that hands a non-existent path to
    ``QIcon``/``QPixmap`` gets back a silently null image with no exception
    at all, which turns a typo'd filename into a blank icon discovered by a
    human days later instead of a traceback discovered in review.

    Example:
        >>> resource_path("icons", "dark.ico")
        PosixPath('.../gui_resources/icons/dark.ico')
    """
    path = RESOURCES_DIR.joinpath(*parts)
    if not path.exists():
        raise FileNotFoundError(f"Resource not found: {path} (resources root: {RESOURCES_DIR})")
    return path


def legal_documents_dir() -> Path:
    """Return the root of the ``legal-documents/`` tree.

    Locale-specific subdirectories and file names are the caller's concern
    (see :mod:`sape_d_mcp.legal_document_loader`) — this only resolves the
    tree itself, the same way ``RESOURCES_DIR`` resolves ``gui_resources/``
    without knowing which flag or icon will be requested from it.
    """
    path = _ROOT / "legal-documents"
    if not path.is_dir():
        raise FileNotFoundError(
            f"Resource not found: {path} (resolved root: {_ROOT}). "
            "See resource_path() for how this root was chosen."
        )
    return path
