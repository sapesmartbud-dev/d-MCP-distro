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

"""Generate the MCP client configuration for this installation.

The configuration has to name a command that starts a *server*. Two things make that easy
to get wrong: the command has to be an interpreter that can import this package (not
whatever ``python`` happens to mean in the client's environment), and it has to carry
``--cli``, or the process opens the GUI and never speaks the protocol.

Both are settled by looking at the running process instead of probing the environment: this
module runs inside the application, so ``sys.executable`` is by definition an interpreter
with the dependencies installed.

Ported from SAPÉ f-MCP's ``MCPConfigGenerator`` with two changes that matter:

1. **Namespacing.** f-MCP writes ``installation.json`` straight into ``~/.sape/``, where a
   second SAPÉ application's file of the same name would clobber it. This module writes
   ``~/.sape/d-mcp/installation.json`` — the same directory ``gui/config_manager.py``
   already uses for ``config.json`` — so the two applications cannot collide.
2. **Three databases, not one.** f-MCP has a single ``permissions.db`` and so a single
   ``db_path`` keyword. d-MCP has ``connections.db``, ``permissions.db`` and ``audit.db``,
   which do not have to live in the same directory (each has its own ``DMCP_*_DB``
   environment override — see ``connection_store.py``, ``permissions.py`` and
   ``log_store.py``). Rather than force them through one ``--db`` prefix argument (which
   only covers the case where all three share a parent directory), :meth:`generate_config`
   accepts the three paths separately and threads whichever ones it was given through the
   environment variables the stores already understand.

   **Every path is always emitted, whether the caller named it or not.** An MCP client
   spawns the server as a subprocess with whatever working directory *it* likes — Claude
   Desktop's is never the user's project directory — and since stage 9,
   ``connection_store.default_db_path()``, ``permissions.default_db_path()`` and
   ``log_store.default_db_path()`` all fall back to :func:`sape_d_mcp.db_location.
   resolve_db_directory`, which resolves against the *current working directory* when
   no environment variable says otherwise (see that module for why, and what it costs).
   A generated configuration that omitted a database's environment variable would rely
   on the spawned process's own, different, working directory landing on the same
   files — which happens by construction in a source checkout and essentially never
   otherwise. So for any path the caller did not supply explicitly,
   :meth:`generate_config` resolves that store's own ``default_db_path()`` itself, at
   generation time (i.e. relative to *this* process's working directory, which is the
   one the human actually launched the GUI from), and emits that instead of leaving the
   variable unset.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

#: The environment variable each store reads to override its default database path
#: (``connection_store.default_db_path()``, ``permissions.default_db_path()``,
#: ``log_store.default_db_path()``). Kept here as the single place that has to agree with
#: those three modules' spellings, rather than repeating the literal string at each call site.
_ENV_VAR_BY_STORE = {
    "connections_db": "DMCP_CONNECTIONS_DB",
    "permissions_db": "DMCP_PERMISSIONS_DB",
    "audit_db": "DMCP_AUDIT_DB",
}

#: The store each keyword's fallback is resolved through when ``generate_config`` was not
#: given that path explicitly. Imported lazily inside ``generate_config`` itself, not at
#: module level: ``permissions.py`` reaches into the dialect layer
#: (``db.dialects.base``), and this module must stay importable — and PyQt6-free, per
#: ``test_importing_this_module_never_pulls_in_pyqt6`` — on a machine that has not yet
#: installed every driver dependency, which is exactly the state a fresh ``--version``
#: probe can run in.
_DEFAULT_PATH_MODULE_BY_STORE = {
    "connections_db": "sape_d_mcp.db.connection_store",
    "permissions_db": "sape_d_mcp.permissions",
    "audit_db": "sape_d_mcp.log_store",
}


@dataclass
class InstallationInfo:
    """How this copy of SAPÉ d-MCP was started."""

    install_type: str  # "frozen", "entry_point", "source", "unknown"
    entry_point: str | None = None  # Executable or console script
    python_executable: str | None = None  # Interpreter to name in the config
    main_module: str | None = None  # Path to main.py (source only)
    venv_path: str | None = None  # Active virtual environment, for display
    is_valid: bool = False
    error_message: str | None = None


class MCPConfigGenerator:
    """Generate MCP server configuration with environment detection."""

    # Namespaced under d-mcp/ — see the module docstring's point 1.
    CONFIG_METADATA_FILE = Path.home() / ".sape" / "d-mcp" / "installation.json"

    @classmethod
    def detect_installation(cls) -> InstallationInfo:
        """Describe how to start the server, based on how this process started.

        Order: a frozen bundle, then a console script installed beside the running
        interpreter, then the source checkout — most self-contained first.

        A console script is only preferred once it has been *run*. An installed entry point
        can be present and broken (a packaging mistake leaves one that exits non-zero), and
        falling through to the source checkout then still produces a configuration that
        works, which is better than telling the user their installation is invalid while the
        application they are clicking in runs perfectly well.
        """
        if getattr(sys, "frozen", False):
            return InstallationInfo(
                install_type="frozen",
                entry_point=sys.executable,
                is_valid=True,
            )

        script = cls._console_script()
        script_error: str | None = None
        if script is not None:
            if cls._validate_command(str(script)):
                return InstallationInfo(
                    install_type="entry_point",
                    entry_point=str(script),
                    python_executable=str(cls._launcher()),
                    venv_path=cls._venv_path(),
                    is_valid=True,
                )
            script_error = f"Ignoring {script}: it is installed but does not run."
            logger.warning(script_error)

        main_module = cls._main_module()
        if main_module.exists():
            return InstallationInfo(
                install_type="source",
                python_executable=str(cls._launcher()),
                main_module=str(main_module),
                venv_path=cls._venv_path(),
                is_valid=True,
            )

        return InstallationInfo(
            install_type="unknown",
            is_valid=False,
            error_message=(
                script_error + " "
                if script_error
                else ""
            ) + (
                f"Could not find main.py (looked in {main_module.parent}) and no "
                "working sape-d-mcp command is installed."
            ),
        )

    @staticmethod
    def _main_module() -> Path:
        """Absolute path to the checkout's ``main.py`` shim.

        This file lives at ``src/sape_d_mcp/mcp_config_generator.py``, so three ``.parent``
        hops land on the project root. Unlike f-MCP, where the console script and the root
        ``main.py`` are two different files, d-MCP's root ``main.py`` is a thin shim that
        puts ``src/`` on ``sys.path`` and calls the very same ``sape_d_mcp.main.run()`` the
        console script calls (see that file's own docstring) — so this path only has to be
        right, not identical in shape to the installed entry point.

        Note this is unrelated to where the three ``.db`` files are resolved
        (:mod:`sape_d_mcp.db_location`): this method only ever runs once
        ``detect_installation`` has already established that the process is a source
        checkout, so a fixed ``.parent`` count is safe here in a way it never was for a
        database that also has to be found from an installed wheel.
        """
        return Path(__file__).resolve().parent.parent.parent / "main.py"

    @staticmethod
    def _launcher() -> Path:
        """The interpreter to name in the config.

        ``sys.executable`` runs this window, so its environment is known good. On Windows a
        GUI started through ``pythonw.exe`` still has to hand the client ``python.exe``: the
        server talks over stdio, and pythonw has no standard handles of its own.
        """
        exe = Path(sys.executable)
        if exe.name.lower() == "pythonw.exe":
            console = exe.with_name("python.exe")
            if console.exists():
                return console
        return exe

    @classmethod
    def _console_script(cls) -> Path | None:
        """The installed ``sape-d-mcp`` script, preferring this environment."""
        name = "sape-d-mcp.exe" if sys.platform == "win32" else "sape-d-mcp"
        candidate = Path(sys.executable).parent / name
        if candidate.exists():
            return candidate
        found = shutil.which("sape-d-mcp")
        return Path(found) if found else None

    @staticmethod
    def _venv_path() -> str | None:
        """The active virtual environment, for display."""
        if sys.prefix != sys.base_prefix:
            return sys.prefix
        return os.environ.get("VIRTUAL_ENV")

    @staticmethod
    def _validate_command(command: str) -> bool:
        """Check that ``command --version`` runs and exits cleanly."""
        try:
            result = subprocess.run(
                [command, "--version"], capture_output=True, timeout=15, text=True
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

    @staticmethod
    def client_config_path() -> Path:
        """Where Claude Desktop keeps its configuration on this platform.

        This is the client's own file, on every platform — nothing in this module ever
        opens it for writing (see :meth:`generate_config`'s docstring). It is returned so
        the caller can *tell the user where to paste*, which is the only thing d-MCP does
        with it.
        """
        if sys.platform == "win32":
            roaming = os.environ.get("APPDATA")
            base = Path(roaming) if roaming else Path.home() / "AppData" / "Roaming"
            return base / "Claude" / "claude_desktop_config.json"
        if sys.platform == "darwin":
            return (
                Path.home()
                / "Library"
                / "Application Support"
                / "Claude"
                / "claude_desktop_config.json"
            )
        return Path.home() / ".config" / "Claude" / "claude_desktop_config.json"

    def generate_config(
        self,
        installation: InstallationInfo,
        *,
        connections_db: str | os.PathLike[str] | None = None,
        permissions_db: str | os.PathLike[str] | None = None,
        audit_db: str | os.PathLike[str] | None = None,
        transport: str = "stdio",
    ) -> dict[str, Any]:
        """Build the ``mcpServers`` entry for ``installation``.

        ``--cli`` is what makes the process a server rather than the GUI, so it is never
        optional.

        ``connections_db``, ``permissions_db`` and ``audit_db`` should each be the database
        the GUI is actually using, where known: a client spawns a process of its own, and
        since that process's working directory is essentially never the same as the one the
        GUI was launched from, it would otherwise resolve each store's own
        ``default_db_path()`` fallback against the *wrong* directory and could enforce a
        different set of rules from the ones on screen. Each is threaded through as the
        environment variable its own store already reads (``DMCP_CONNECTIONS_DB`` etc.) —
        not a single ``--db`` prefix argument, because unlike f-MCP's one ``permissions.db``
        d-MCP has three databases that need not share a directory.

        A path left out here is **not** left out of the emitted configuration: this method
        resolves that store's own ``default_db_path()`` itself, at generation time — i.e.
        against the directory this process (the GUI) was actually launched from — and emits
        the result instead. Omitting the environment variable entirely would only be correct
        if the spawned process's working directory were guaranteed to match this one, which
        it is not; emitting a value that was merely *correct when generated* is the safer of
        the two wrong-input failure modes, because it is at least deterministic rather than
        silently depending on wherever the client happens to spawn the server from.

        Raises:
            ValueError: If ``installation`` was not detected — there is then no command to
                launch and no configuration to hand back.
        """
        if not installation.is_valid:
            raise ValueError(f"Invalid installation: {installation.error_message}")

        if installation.install_type in ("frozen", "entry_point"):
            command = installation.entry_point
            args: list[str] = []
        else:
            command = installation.python_executable
            args = [str(installation.main_module)]

        args += ["--cli", "--transport", transport]

        given = {
            "connections_db": connections_db,
            "permissions_db": permissions_db,
            "audit_db": audit_db,
        }
        env: dict[str, str] = {}
        for keyword, value in given.items():
            if value:  # noqa: SIM108 — the else branch carries a comment a ternary has nowhere to put
                resolved = Path(value)
            else:
                # Not named explicitly: resolve the store's own default *now*, against
                # this process's working directory, rather than leaving the environment
                # variable unset and letting the spawned process resolve it — possibly
                # very differently — against its own. See the docstring above and
                # sape_d_mcp.db_location for why the two need not agree.
                resolved = self._default_db_path(keyword)
            env[_ENV_VAR_BY_STORE[keyword]] = str(resolved)

        return {"command": command, "args": args, "env": env}

    @staticmethod
    def _default_db_path(keyword: str) -> Path:
        """Call the named store's own ``default_db_path()``, importing it lazily.

        Lazy so that importing this module never drags in the dialect layer
        ``permissions.py`` reaches through — see ``_DEFAULT_PATH_MODULE_BY_STORE``'s
        comment for why that matters here specifically.
        """
        from importlib import import_module

        module = import_module(_DEFAULT_PATH_MODULE_BY_STORE[keyword])
        return module.default_db_path()

    def save_installation_metadata(self, installation: InstallationInfo) -> None:
        """Save installation metadata to ``~/.sape/d-mcp/installation.json`` for future use."""
        self.CONFIG_METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)

        metadata = {
            "install_type": installation.install_type,
            "entry_point": installation.entry_point,
            "python_executable": installation.python_executable,
            "main_module": installation.main_module,
            "venv_path": installation.venv_path,
            "is_valid": installation.is_valid,
            "detected_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        }

        try:
            with open(self.CONFIG_METADATA_FILE, "w", encoding="utf-8") as f:
                json.dump(metadata, f, indent=2)
            logger.info("Saved installation metadata to %s", self.CONFIG_METADATA_FILE)
        except Exception as e:
            logger.error("Failed to save installation metadata: %s", e)

    @staticmethod
    def load_installation_metadata() -> InstallationInfo | None:
        """Load previously saved installation metadata."""
        config_file = MCPConfigGenerator.CONFIG_METADATA_FILE

        if not config_file.exists():
            return None

        try:
            with open(config_file, encoding="utf-8") as f:
                data = json.load(f)

            return InstallationInfo(
                install_type=data.get("install_type", "unknown"),
                entry_point=data.get("entry_point"),
                python_executable=data.get("python_executable"),
                main_module=data.get("main_module"),
                venv_path=data.get("venv_path"),
                is_valid=data.get("is_valid", False),
            )
        except Exception as e:
            logger.warning("Failed to load installation metadata: %s", e)
            return None

    def generate_instructions(self, installation: InstallationInfo) -> str:
        """Human-readable setup instructions for this installation."""
        if installation.install_type == "frozen":
            head = "SAPÉ d-MCP is running from a packaged build."
        elif installation.install_type == "entry_point":
            head = f"SAPÉ d-MCP is installed as a command:\n{installation.entry_point}"
        elif installation.install_type == "source":
            head = (
                "SAPÉ d-MCP is running from source. The configuration names the "
                f"interpreter this window is running on:\n{installation.python_executable}"
            )
        else:
            return installation.error_message or "Installation not detected."

        return (
            f"{head}\n\n"
            f"Paste the JSON below into:\n{self.client_config_path()}\n\n"
            "Merge it with any mcpServers you already have — do not replace the "
            "file — then restart Claude Desktop."
        )
