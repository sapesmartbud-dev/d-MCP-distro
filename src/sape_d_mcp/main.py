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

"""Entry point: launch the PyQt6 GUI, or run headless with --cli."""

from __future__ import annotations

import argparse
import logging
import sys

from sape_d_mcp._version import VERSION_DISPLAY

# The GUI is imported inside main(), never at module level: --cli is a
# headless server and must not need PyQt6 installed. Importing it here would
# make the server unstartable anywhere Qt is absent, which is the normal case
# on a server or in a minimal container — this is the mistake f-MCP avoided
# and d-MCP keeps avoiding.

# Hide the console window on Windows (GUI-only application). Not in --cli
# mode: there the process is a server, it inherits the console of whoever
# launched it, and hiding that would take the user's own terminal window
# with it.
if sys.platform == "win32" and "--cli" not in sys.argv:
    try:
        import ctypes

        whnd = ctypes.windll.kernel32.GetConsoleWindow()
        if whnd != 0:
            ctypes.windll.user32.ShowWindow(whnd, 0)  # SW_HIDE
    except (AttributeError, OSError):
        pass  # Not running on Windows, or no console to hide.

# Suppress console logging by default. This applies to --cli as well as the GUI:
# mcp_server.py does not configure its own logging, so a --cli server that wants
# diagnostics has to reconfigure this itself (or an operator edits this line).
logging.basicConfig(level=logging.CRITICAL, handlers=[logging.NullHandler()])
logger = logging.getLogger(__name__)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Build and parse the command line.

    Deliberately not a mirror of f-MCP's flag set: f-MCP takes a single ``--db``
    prefix argument for its one permissions.db, but d-MCP has three databases that
    need not share a directory, so there is no equivalent flag here at all — each
    database is resolved from its own environment variable instead (db_location.py,
    and mcp_config_generator.py's ``generate_config``, which is what actually sets
    them for a client-spawned process).
    """
    parser = argparse.ArgumentParser(
        description="SAPÉ d-MCP — controlled database access with granular permissions for LLMs"
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"SAPÉ d-MCP {VERSION_DISPLAY}",
        help="Print the version and exit.",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Run in CLI mode (start the MCP server immediately, no GUI).",
    )
    parser.add_argument(
        "--transport",
        default="stdio",
        choices=["stdio", "sse", "streamable-http"],
        help="Transport to serve the MCP server on (default: stdio).",
    )
    parser.add_argument(
        "--show-permissions",
        action="store_true",
        help="Print the permission rules and exit without launching the GUI.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Dispatch to the requested mode.

    ``--cli``, the GUI and ``--show-permissions`` are all live.
    """
    args = parse_args(argv)

    if args.show_permissions:
        # Opens the two stores directly rather than a whole DatabaseMCPServer: unlike
        # the show-permissions *tool* in mcp_server.py, which resolves a live database
        # session before it will answer (that resolution is the security boundary an
        # LLM's connection name is checked against), a human at a terminal asking "what
        # is configured" should get an answer even for an unreachable database — that
        # is one of the reasons to run this flag in the first place. No PyQt6 import
        # either: --show-permissions is a headless path exactly like --cli.
        #
        # No path is passed to either store: each resolves its own location from its
        # own environment variable (``DMCP_CONNECTIONS_DB``, ``DMCP_PERMISSIONS_DB``),
        # falling back to ``DMCP_DB_DIR`` and then db_location.resolve_db_directory() —
        # the same precedence --cli uses below, via DatabaseMCPServer's own defaults.
        from sape_d_mcp.db.connection_store import ConnectionStore
        from sape_d_mcp.permissions import PermissionStore, format_rule

        connections = ConnectionStore(None)
        permissions = PermissionStore(None)
        try:
            profiles = connections.all()
            if not profiles:
                # Default-deny, no seeding (permissions.py's module docstring): an
                # empty connections.db is not an error, it is the starting state, and
                # it authorises nothing at all.
                print("no database connections are configured; nothing is authorised")
                return 0
            for profile in profiles:
                print(f"connection: {profile['display_name']}")
                rules = permissions.rules(int(profile["id"]))
                if not rules:
                    print("  (no permission rules — nothing is authorised on this connection)")
                    continue
                for rule in rules:
                    shown = format_rule(rule)
                    allowed = ",".join(shown["allowed_actions"]) or "-none-"
                    # A rule names a collection since schema version 2, so its objects
                    # go one per indented line underneath rather than being squeezed
                    # into the header -- a rule over forty tables would otherwise print
                    # as a single unreadable line, which is the opposite of what
                    # --show-permissions is for.
                    # The operator's own label for the rule leads the line when there
                    # is one, because it is what they wrote to answer "what is this
                    # rule for" and is therefore the fastest way to find the rule they
                    # are looking for. A rule nobody has named prints exactly as it did
                    # before rather than carrying an empty field or a `name=None`.
                    label = f"{shown['rule_name']!r}  " if shown["rule_name"] else ""
                    print(
                        f"  {label}{shown['object_type']}  deny={shown['is_deny']}"
                        f"  allowed={allowed}"
                        f"  created_at={shown['created_at']} by {shown['user_created']}"
                    )
                    for target in shown["targets"]:
                        print(f"      {target['schema_pattern']}.{target['name_pattern']}")
        finally:
            # Best-effort, in the order opened: a failure closing one store must not
            # stop the other's handle from being released.
            try:
                connections.close()
            finally:
                permissions.close()
        return 0

    if args.cli:
        logger.info("CLI mode requested (transport=%s)", args.transport)
        # Imported here, not at module level: --cli must work in an environment with no
        # PyQt6, and the MCP SDK is a cost the --version path should not pay either.
        from sape_d_mcp.mcp_server import DatabaseMCPServer

        # No paths passed here either: DatabaseMCPServer's own connections_db/
        # permissions_db/audit_db keyword arguments default to None, which each store
        # resolves itself from its own environment variable (db_location.py, and each
        # store's own default_db_path()). An MCP client spawning this process sets
        # those variables from the config the GUI generated (mcp_config_generator.py);
        # a human running --cli by hand gets whatever DMCP_DB_DIR or the current
        # working directory resolves to, exactly like --show-permissions above.
        server = DatabaseMCPServer(
            # "cli" is the well-known session id for a server an MCP client spawned:
            # it has no GUI session to attribute its audit rows to.
            session_id="cli",
        )
        try:
            server.run(transport=args.transport)
        except KeyboardInterrupt:
            # Ctrl-C is how a hand-started server is stopped; it is not a failure, and
            # the stores still have to be closed cleanly.
            logger.info("Interrupted; shutting the MCP server down")
        finally:
            server.close()
        return 0

    # GUI mode (default). Import PyQt6 here, not at module level — see the
    # comment above main.py's imports for why.
    try:
        from sape_d_mcp.gui.app import SAPEApplication
        from sape_d_mcp.gui.splash_screen import SAPESplashScreen
    except ImportError as exc:
        print(
            f"error: the graphical interface needs PyQt6, which is not installed ({exc}).\n"
            "       Install it, or run the server headless with --cli.",
            file=sys.stderr,
        )
        return 1

    app = SAPEApplication(list(argv) if argv is not None else None)
    # SAPEApplication builds and owns the one MainWindow. Constructing a second one
    # here built the entire window twice and put both on screen, because a saved
    # "maximized" state made the first one show itself from its own constructor.
    window = app.main_window

    # The splash keeps its own reference alive through the returned timer;
    # dropping it would let Python collect the timer before it fires and
    # leave the splash on screen forever. That is f-MCP's bug, not ours.
    splash = SAPESplashScreen(theme=app.current_theme)
    splash_timer = splash.show_and_wait()  # noqa: F841 — kept alive deliberately

    window.show()
    return app.exec()


def run() -> None:
    """Entry point for the ``sape-d-mcp`` console script."""
    sys.exit(main())


if __name__ == "__main__":
    raise SystemExit(main())
