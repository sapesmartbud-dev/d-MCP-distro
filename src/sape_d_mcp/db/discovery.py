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

"""Finding a database server without a credential — local sources only, and never a guess
dressed up as an answer.

DESIGN-CONNECTION-SETUP.md §7 and ADR 0003 are the contract this module implements. What it
never does, first, because that is the property every other guarantee here rests on:

* **It never connects to a database, authenticates, or reads a credential.** No
  :class:`Candidate` field can hold a user name or a password — a test asserts that — and
  nothing here calls ``engine.connect()`` or opens a DB-API session.
* **It never emits a network packet, except from** :func:`discover_network`, **and only when
  called.** Every source in :func:`discover_local` reads the local machine only — the Windows
  registry, the service table, a loopback socket probe, the ODBC configuration, and a
  bounded, explicitly-scoped walk for SQLite files. :func:`discover_network` is the one
  source that leaves the machine (§7.7): it is a thin bridge onto ``sape_d_mcp.db.ssrp``
  (the hardened SSRP encoder/parser, with its own 169-strong test suite including a hostile
  corpus), converting each validated :class:`~sape_d_mcp.db.ssrp.SsrpInstance` into a
  :class:`Candidate` of the same shape :func:`discover_local` returns. It is called only from
  an explicit, GUI-confirmed action the caller gates — this module has no opinion on whether
  that confirmation happened, and does not ask for one.
* **It is synchronous, blocking and imports no PyQt6.** The `--cli` rule applies here as much
  as it applies to ``main.py``: a headless server must be able to import this package with no
  Qt installed. The Qt thread that wraps this for the GUI is specified in §7.9 and belongs to
  the ``uix-designer`` agent, not here.
* **It is never an MCP tool.** Exposing "enumerate what is listening on this machine" to a
  model would hand it a reconnaissance primitive the permission engine was never designed to
  gate (§7.1, §7.9 point 7). Nothing in this module is registered in the tool catalogue, and
  nothing should be.

Every candidate states its own provenance (``origin``, ``origin_detail``) rather than
asserting an engine it has not verified: a socket that merely accepted a TCP connection is
labelled as exactly that — a *candidate*, never a *finding* — because through NAT or any
proxying middlebox, ``connect()`` succeeding does not prove the port is really reachable
(confirmed empirically against a real SQL Server instance during the design's own research,
and again against VirtualBox's own NAT: the connection was accepted and a protocol handshake
still returned nothing, or would have had one been sent).

``confidence`` therefore describes the *service*, not the probe: whether this source actually
identifies which engine is out there, as against merely guessing from a port number. A bare
TCP accept on a loopback port with no protocol reply behind it is ``confidence='inferred'`` —
the engine is a guess from the port number alone, spelled out in full in ``label``, which is
what every consumer that must not overstate a finding already reads. Only a source that
inspects the *service itself* — the registry, a matching service name, an already-configured
ODBC DSN, a verified SQLite header — is marked ``confidence='confirmed'``. A reply from
:func:`discover_network`'s SSRP sweep is ``confidence='reported'``: it names an engine, but it
is unauthenticated network input, never a local observation, and is kept in its own class for
that reason. See :func:`discover_network` for exactly which ``Candidate`` field is, and is
not, trusted from that reply.
"""

from __future__ import annotations

import contextlib
import logging
import re
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from threading import Event
from typing import Any, cast

from sape_d_mcp.db.ssrp import (
    SsrpInstance,
    SsrpResult,
    instances_on_local_network,
    query_ssrp,
)

logger = logging.getLogger(__name__)

__all__ = [
    "CONFIDENCE",
    "ORIGINS",
    "ORIGINS_LOCAL",
    "Candidate",
    "DiscoveryResult",
    "audit_network_discovery",
    "audit_network_discovery_consent",
    "discover_local",
    "discover_network",
]


def _winreg() -> Any:
    """Import ``winreg``, typed as ``Any`` rather than through mypy's own stub.

    Typeshed's ``winreg.pyi`` wraps every single name in ``if sys.platform == "win32":`` —
    correctly, since the module does not exist anywhere else — which means mypy running on
    the Linux box every contributor and CI actually use (this project has no Windows runner)
    sees an *empty* module and reports every attribute below (``HKEY_LOCAL_MACHINE``,
    ``OpenKey``, ``QueryValueEx``, …) as undefined. That is the checker disagreeing with the
    platform it happens to be invoked on, not a defect in code that already gates every
    caller with its own ``sys.platform`` check (:func:`_discover_windows_registry`,
    :func:`_discover_windows_services`, :func:`_windows_odbc_dsns`) — the false positive is
    pinned by running mypy itself with ``--platform win32``, which makes it disappear
    without touching a line of this file, and ``tests/test_discovery_windows_registry.py``
    exercises every one of these call sites on Linux against an injected fake ``winreg`` in
    ``sys.modules``, so a real bug here would fail loudly rather than hide behind this cast.
    """

    import winreg

    return winreg

# ---------------------------------------------------------------------------
# The shared vocabulary
# ---------------------------------------------------------------------------
ORIGINS: tuple[str, ...] = (
    "windows-registry",  # HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL
    "windows-service",  # a registered service whose name matches a known pattern
    "odbc-dsn",  # a DSN already configured on this machine
    "listening-port",  # something answered a TCP connect on loopback
    "sqlite-file",  # a file whose first 16 bytes are the SQLite magic
    "sql-browser",  # an SSRP reply — UNTRUSTED, produced only by discover_network()
)

#: Every source :func:`discover_local` may run.  ``sql-browser`` is deliberately excluded:
#: it is the one source that leaves the machine, and it is never run except from an explicit,
#: confirmed :func:`discover_network` call.
ORIGINS_LOCAL: tuple[str, ...] = tuple(o for o in ORIGINS if o != "sql-browser")

#: ``'confirmed'``: this source inspected the service itself (the registry, a matching
#: service name, an already-configured ODBC DSN, a verified SQLite header).
#: ``'inferred'``: this source only observed something (a TCP accept) and is guessing the
#: engine from a port number, never from the service's own reply — see the module docstring
#: and :func:`_discover_listening_ports`.
#: ``'reported'``: this source is a reply from ``discover_network()``'s SSRP broadcast —
#: it names an engine, but it is unauthenticated network input, not a local observation.
CONFIDENCE: tuple[str, ...] = ("confirmed", "inferred", "reported")

#: The default driver the GUI pre-selects for a candidate, mirroring
#: ``connection_store.DRIVERS_BY_ENGINE``'s first entry per engine.  Restated rather than
#: imported: this module keeps its own, minimal dependency surface so it stays importable
#: (and testable) with nothing else in ``db/`` touched, the same discipline
#: ``connection_store.py`` documents for its own ``ENGINES``/``DRIVERS_BY_ENGINE`` tuple.
_DEFAULT_DRIVER: dict[str, str] = {
    "mssql": "pyodbc",
    "postgresql": "psycopg",
    "mysql": "pymysql",
    "sqlite": "sqlite3",
}

_ENGINE_LABEL: dict[str, str] = {
    "mssql": "SQL Server",
    "postgresql": "PostgreSQL",
    "mysql": "MySQL/MariaDB",
    "sqlite": "SQLite",
}


@dataclass(frozen=True, slots=True)
class Candidate:
    """One discovered address, never a credential, always attributed to a source.

    ``label`` is what the discovery dialog's list shows; the GUI never composes its own
    wording for a candidate, so the same sentence a developer reads in a test is what the
    user reads on screen. ``confidence`` describes how solid the *identification* is — see
    :data:`CONFIDENCE` — not how solid the network observation behind it was.

    ``note_key`` exists solely so the GUI can translate a fragment of ``label`` without
    string-matching it. ``discovery.py`` has no i18n dependency by design (it must import
    under ``--cli`` with no PyQt6 installed), so it cannot hand back a translation itself;
    it hands back an opaque key instead, and ``label`` keeps the English fragment inline as
    the fallback a CLI or a log line reads. ``None`` means "nothing in this label wants
    translating".
    """

    engine: str
    host: str  # 'localhost' for everything this module finds
    port: int | None
    instance: str | None
    database: str | None  # a file path for sqlite, else None — never guessed
    driver_hint: str | None
    auth_hint: str  # one of AUTH_MODES: what this source implies, never verified
    origin: str  # one of ORIGINS
    origin_detail: str
    confidence: str  # one of CONFIDENCE
    label: str
    note_key: str | None = None  # e.g. 'discovery.dynamic_port_note'; see the class docstring


@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    """What one :func:`discover_local` or :func:`discover_network` call produced.

    ``replies`` is ``0`` for a :func:`discover_local` result — nothing counts a "reply"
    when nothing was asked over a wire — and is otherwise the number of SSRP datagrams
    :func:`discover_network` accepted from an asked source, *before* per-record
    validation and deduplication collapse them into ``candidates``. It exists so a
    caller auditing a sweep (:func:`audit_network_discovery`) can report how many
    replies were discarded along the way (``replies - len(candidates)``) without this
    module reaching into ``audit.db`` itself — see :func:`discover_network`'s own
    docstring for why that boundary is drawn where it is.
    """

    candidates: tuple[Candidate, ...]
    notes: tuple[str, ...]
    elapsed_ms: float
    truncated: bool
    replies: int = 0


# ---------------------------------------------------------------------------
# §7.2 — Windows registry: local SQL Server instances
# ---------------------------------------------------------------------------
_SQL_ROOT = r"SOFTWARE\Microsoft\Microsoft SQL Server"
_INSTANCE_KEY = _SQL_ROOT + r"\Instance Names\SQL"

#: SQL Server instance names are at most 16 characters, start with a letter or underscore.
#: Trusted here (the registry is not hostile input), but kept identical to the pattern
#: applied to an SSRP reply so the two code paths cannot silently drift apart.
_INSTANCE_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_$#]{0,15}$")


def _registry_views() -> tuple[int, ...]:
    """Both registry views, 64-bit first.

    A 32-bit SQL Server 2008 R2 Express install (still not rare on old machines) writes to
    the 32-bit view; a single process sees only its own unless it asks for both explicitly,
    and a hard-coded ``WOW6432Node`` path only works from a 64-bit process.
    """

    winreg = _winreg()

    return (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY)


def _first_port(raw: str) -> int | None:
    """First valid port in a `TcpPort`/`TcpDynamicPorts` value, which may be a comma list.

    `TcpDynamicPorts` holds `"0"` to mean "a dynamic port will be chosen at start-up, none
    assigned yet" — not a port, and must not be offered as one.
    """

    for part in (raw or "").split(","):
        part = part.strip()
        if part.isdigit():
            port = int(part)
            if 1 <= port <= 65535:
                return port
    return None


def _reg_str(key: Any, name: str) -> str:
    winreg = _winreg()

    try:
        value, kind = winreg.QueryValueEx(key, name)
    except FileNotFoundError:
        return ""
    return str(value) if kind in (winreg.REG_SZ, winreg.REG_EXPAND_SZ) else ""


def _describe_registry_instance(internal: str, name: str, view: int) -> Candidate:
    winreg = _winreg()

    instance = None if name.upper() == "MSSQLSERVER" else name
    tcp_path = rf"{_SQL_ROOT}\{internal}\MSSQLServer\SuperSocketNetLib\Tcp"
    port: int | None = None
    dynamic = False
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, tcp_path + r"\IPAll", 0, winreg.KEY_READ | view
        ) as key:
            static = _reg_str(key, "TcpPort")
            dyn = _reg_str(key, "TcpDynamicPorts")
            # TcpPort wins when both are set — SQL Server Configuration Manager clears
            # TcpDynamicPorts when a static port is assigned, but a hand-edited registry can
            # leave both, and the static one is what the server actually listens on.
            static_port = _first_port(static)
            port = static_port or _first_port(dyn)
            dynamic = bool(_first_port(dyn)) and not static_port
    except FileNotFoundError:
        pass  # the TCP protocol was never configured for this instance
    except OSError:
        logger.debug("cannot read TCP settings for %s", internal, exc_info=True)

    server_display = "localhost" if instance is None else f"localhost\\{instance}"
    label = f"SQL Server — {server_display}"
    # This exact English fragment is also what the GUI used to string-match before
    # 'note_key' existed (DESIGN-CONNECTION-SETUP.md §7.2). It stays here, unchanged, as the
    # fallback a CLI or a log line reads; the GUI now reads 'note_key' instead of the string.
    note_key = None
    if dynamic:
        label += " (dynamic port — it changes when the service restarts)"
        note_key = "discovery.dynamic_port_note"
    origin_detail = (
        rf"HKLM\{_INSTANCE_KEY} ({name} -> {internal})"
    )
    return Candidate(
        engine="mssql",
        host="localhost",
        port=port,
        instance=instance,
        database=None,
        driver_hint="pyodbc",
        # A locally registered SQL Server on Windows is overwhelmingly reached by a
        # trusted connection, and pyodbc is the only shipped driver that can make one
        # (DESIGN-CONNECTION-SETUP.md §4.1-§4.2).
        auth_hint="integrated",
        origin="windows-registry",
        origin_detail=origin_detail,
        confidence="confirmed",
        label=label,
        note_key=note_key,
    )


def _discover_windows_registry() -> list[Candidate]:
    """Named and default MS-SQL instances installed on this machine.

    Installed is not the same as running — see :func:`_discover_windows_services` — but the
    registry is the only source that ever reveals a *dynamic* port before a connection
    attempt, which is precisely the user's own reported ``PC-ARR\\SQLEXPRESS:56879`` case.
    """

    if sys.platform != "win32":
        return []

    winreg = _winreg()

    found: dict[str, Candidate] = {}
    for view in _registry_views():
        try:
            with winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, _INSTANCE_KEY, 0, winreg.KEY_READ | view
            ) as key:
                count = winreg.QueryInfoKey(key)[1]
                for i in range(count):
                    name, internal, kind = winreg.EnumValue(key, i)
                    if kind != winreg.REG_SZ or not _INSTANCE_NAME_RE.match(name):
                        continue
                    if name in found:  # the 64-bit view wins on a tie
                        continue
                    found[name] = _describe_registry_instance(str(internal), name, view)
        except FileNotFoundError:
            continue  # no SQL Server registered in this view — normal
        except OSError:
            logger.debug("cannot read %s in view %#x", _INSTANCE_KEY, view, exc_info=True)
    return list(found.values())


# ---------------------------------------------------------------------------
# §7.3 — Windows services (presence only; the port comes from §7.2/§7.4, never the service)
# ---------------------------------------------------------------------------
_SERVICES_ROOT = r"SYSTEM\CurrentControlSet\Services"

#: Deliberately excludes the MSSQL* patterns: the registry source above already names every
#: SQL Server instance with its real port, and re-walking ~700 service keys to confirm the
#: same instances again buys nothing (the research this module is built from measured it).
_SERVICE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^postgresql", re.IGNORECASE), "postgresql"),
    (re.compile(r"^mysql", re.IGNORECASE), "mysql"),
    (re.compile(r"^mariadb", re.IGNORECASE), "mysql"),
)


def _discover_windows_services() -> list[Candidate]:
    """PostgreSQL/MySQL/MariaDB services registered on this machine, port unknown.

    No subprocess and no ``psutil``: shelling out to ``sc query`` means parsing localised
    console output, and ``psutil`` is a compiled dependency this feature does not earn — the
    registry alone answers "is something installed", which is what this source promises.
    """

    if sys.platform != "win32":
        return []

    winreg = _winreg()

    found: list[Candidate] = []
    try:
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _SERVICES_ROOT, 0, winreg.KEY_READ
        ) as key:
            count = winreg.QueryInfoKey(key)[0]
            for i in range(count):
                try:
                    name = winreg.EnumKey(key, i)
                except OSError:
                    continue
                for pattern, engine in _SERVICE_PATTERNS:
                    if not pattern.match(name):
                        continue
                    found.append(
                        Candidate(
                            engine=engine,
                            host="localhost",
                            port=None,
                            instance=None,
                            database=None,
                            driver_hint=_DEFAULT_DRIVER.get(engine),
                            auth_hint="password",
                            origin="windows-service",
                            origin_detail=rf"HKLM\{_SERVICES_ROOT}\{name}",
                            confidence="confirmed",
                            label=(
                                f"{_ENGINE_LABEL[engine]} — service {name!r} is registered "
                                "(port unknown; see the listening-port results)"
                            ),
                        )
                    )
                    break
    except FileNotFoundError:
        pass
    except OSError:
        logger.debug("cannot enumerate %s", _SERVICES_ROOT, exc_info=True)
    return found


# ---------------------------------------------------------------------------
# §7.4 — listening ports on loopback, bounded and non-blocking
# ---------------------------------------------------------------------------
#: Port -> engine.  33060 (MySQL X Protocol) is deliberately not probed as its own
#: candidate — the design's own table treats it as a footnote on the 3306 entry, since d-MCP
#: never speaks X Protocol.
_LOOPBACK_PORTS: tuple[tuple[int, str], ...] = (
    (1433, "mssql"),
    (5432, "postgresql"),
    (3306, "mysql"),
)

_LOOPBACK_HOSTS: tuple[str, ...] = ("127.0.0.1", "::1")


def _tcp_probe(
    targets: list[tuple[str, int]], *, deadline: float, cancel: Any = None
) -> set[tuple[str, int]]:
    """The subset of ``targets`` that accepted a TCP connection before ``deadline``.

    One selector, no thread pool: non-blocking ``connect_ex`` plus ``selectors`` finishes in
    whatever time is left on the shared discovery budget regardless of how many addresses
    black-hole the SYN — a naive ``settimeout()`` loop over the same handful of addresses
    would not (measured at 2.01 s for a full /24 in the design's own research; a handful of
    loopback probes is a rounding error against the same code path).

    An accepted connection is a *candidate*, not a finding (module docstring) — the caller
    labels it accordingly and never asserts an engine beyond "something is listening here".
    """

    import errno
    import selectors
    import socket

    # WSAEWOULDBLOCK/WSAEINVAL have no `errno` constant on POSIX, so the numbers are
    # spelled out — the same list the verified research prototype used.
    in_progress = {errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY, 10035, 10036}

    open_targets: set[tuple[str, int]] = set()
    pending: dict[Any, tuple[str, int]] = {}
    queue = list(targets)
    selector = selectors.DefaultSelector()
    try:
        while (queue or pending) and (cancel is None or not cancel.is_set()):
            while queue:
                host, port = queue.pop(0)
                try:
                    family = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)[0][0]
                    sock = socket.socket(family, socket.SOCK_STREAM)
                except OSError:
                    continue  # unresolvable (e.g. no IPv6 stack) — not a discovery failure
                sock.setblocking(False)
                code = sock.connect_ex((host, port))
                if code == 0:
                    open_targets.add((host, port))
                    sock.close()
                    continue
                if code not in in_progress:
                    sock.close()
                    continue
                selector.register(sock, selectors.EVENT_WRITE)
                pending[sock] = (host, port)
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not pending:
                break
            for key, _mask in selector.select(min(remaining, 0.25)):
                # `SelectorKey.fileobj` is typed `int | HasFileno` because a selector can
                # register a bare descriptor, but this one only ever registers the sockets
                # it created two lines above — the cast says exactly that, rather than
                # widening every use below back out to the union.
                sock = cast(socket.socket, key.fileobj)
                target = pending.pop(sock)
                selector.unregister(sock)
                if sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR) == 0:
                    open_targets.add(target)
                sock.close()
    finally:
        for sock in list(pending):
            with contextlib.suppress(KeyError):
                selector.unregister(sock)
            sock.close()
        selector.close()
    return open_targets


def _discover_listening_ports(*, deadline: float, cancel: Any = None) -> list[Candidate]:
    targets = [(host, port) for host in _LOOPBACK_HOSTS for port, _ in _LOOPBACK_PORTS]
    open_targets = _tcp_probe(targets, deadline=deadline, cancel=cancel)

    candidates: list[Candidate] = []
    for host in _LOOPBACK_HOSTS:
        for port, engine in _LOOPBACK_PORTS:
            if (host, port) not in open_targets:
                continue
            candidates.append(
                Candidate(
                    engine=engine,
                    host="localhost",
                    port=port,
                    instance=None,
                    database=None,
                    driver_hint=_DEFAULT_DRIVER.get(engine),
                    # Nothing about an open socket implies an identity.
                    auth_hint="password",
                    origin="listening-port",
                    origin_detail=f"{host}:{port}",
                    # The socket accept is real, but that is not what 'confidence' records
                    # (module docstring, §7.0/§7.4): no protocol reply was ever read, so the
                    # engine is a guess from the port number alone, never confirmed.
                    confidence="inferred",
                    label=(
                        f"Something answered on {host}:{port} — probably "
                        f"{_ENGINE_LABEL[engine]}, but not verified (d-MCP sends no "
                        "protocol handshake during discovery)"
                    ),
                )
            )
    return candidates


# ---------------------------------------------------------------------------
# §7.5 — ODBC data sources already configured
# ---------------------------------------------------------------------------
#: Substring -> engine, longest/most specific first: 'mariadb' must be tried before 'mysql'.
_DRIVER_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("odbc driver 18 for sql server", "mssql"),
    ("odbc driver 17 for sql server", "mssql"),
    ("odbc driver 13 for sql server", "mssql"),
    ("sql server native client", "mssql"),
    ("freetds", "mssql"),
    ("sql server", "mssql"),
    ("mariadb", "mysql"),
    ("mysql", "mysql"),
    ("postgresql", "postgresql"),
    ("psqlodbc", "postgresql"),
    ("sqlite", "sqlite"),
)


def _engine_for_driver(driver: str) -> str | None:
    """The d-MCP engine behind an ODBC driver name, or ``None`` if d-MCP has no dialect for it.

    ``None`` is returned rather than guessed for Oracle, DB2 or a desktop driver: offering a
    connection profile for an engine with no dialect module produces a failure at connect
    time and a support question, which is worse than simply not listing that DSN.
    """

    haystack = driver.casefold()
    tail = haystack.rsplit("\\", 1)[-1].rsplit("/", 1)[-1]
    for needle, engine in _DRIVER_SIGNATURES:
        if needle in haystack or needle in tail:
            return engine
    return None


def _odbc_candidate(dsn: str, driver: str, server: str, port: str, database: str, scope: str) -> Candidate | None:
    engine = _engine_for_driver(driver)
    if engine is None or engine == "sqlite":
        # A DSN pointing at a SQLite file has no host/port to offer; the file itself is
        # found (or not) by the sqlite-file source instead, with its header verified.
        return None
    host = "localhost"
    resolved_port: int | None = None
    instance: str | None = None
    if engine == "mssql" and server:
        # The same normaliser the user's own typing goes through — a DSN is exactly as
        # capable of holding a compound 'HOST\INSTANCE,PORT' value as a hand-typed field.
        try:
            from sape_d_mcp.db.targets import parse_mssql_target

            target = parse_mssql_target(server)
            host = target.server
            instance = target.instance
            resolved_port = target.port
        except ValueError:
            host = server
    elif server:
        host = server
    if resolved_port is None and port.isdigit():
        maybe = int(port)
        if 1 <= maybe <= 65535:
            resolved_port = maybe
    label = f"{_ENGINE_LABEL.get(engine, engine)} — ODBC DSN {dsn!r} ({scope})"
    return Candidate(
        engine=engine,
        host=host,
        port=resolved_port,
        instance=instance,
        database=database or None,
        driver_hint=_DEFAULT_DRIVER.get(engine),
        auth_hint="password",
        origin="odbc-dsn",
        origin_detail=f"{scope}: {dsn}",
        confidence="confirmed",
        label=label,
    )


def _windows_odbc_dsns() -> list[Candidate]:
    """User and system ODBC DSNs from both registry views.

    Both registry views are read, because a 32-bit DSN is real even to a 64-bit process
    that cannot use it — unlike ``pyodbc.dataSources()``, which sees only its own bitness.
    Password-shaped keys (``PWD``, ``Password``) are never read: only ``Driver``, ``Server``,
    ``Port`` and ``Database`` are allowlisted.
    """

    winreg = _winreg()

    out: list[Candidate] = []
    for hive, scope in (
        (winreg.HKEY_CURRENT_USER, "user DSN"),
        (winreg.HKEY_LOCAL_MACHINE, "system DSN"),
    ):
        for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
            try:
                with winreg.OpenKey(
                    hive, r"SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources", 0,
                    winreg.KEY_READ | view,
                ) as index_key:
                    count = winreg.QueryInfoKey(index_key)[1]
                    for i in range(count):
                        try:
                            dsn, driver, kind = winreg.EnumValue(index_key, i)
                        except OSError:
                            continue
                        if kind != winreg.REG_SZ:
                            continue
                        server = port = database = ""
                        try:
                            with winreg.OpenKey(
                                hive, rf"SOFTWARE\ODBC\ODBC.INI\{dsn}", 0,
                                winreg.KEY_READ | view,
                            ) as detail:
                                server = _reg_str(detail, "Server")
                                port = _reg_str(detail, "Port")
                                database = _reg_str(detail, "Database")
                        except OSError:
                            pass
                        candidate = _odbc_candidate(
                            str(dsn), str(driver), server, port, database, scope
                        )
                        if candidate is not None:
                            out.append(candidate)
            except FileNotFoundError:
                continue
            except OSError:
                logger.debug("cannot enumerate ODBC DSNs (%s)", scope, exc_info=True)
    return out


def _posix_odbc_dsns() -> list[Candidate]:
    """DSNs from the unixODBC ini files, honouring ``$ODBCINI`` and ``$ODBCSYSINI``."""

    import configparser
    import os

    paths = [
        os.environ.get("ODBCINI", ""),
        os.path.expanduser("~/.odbc.ini"),
        os.path.join(os.environ.get("ODBCSYSINI", "/etc"), "odbc.ini"),
    ]
    out: list[Candidate] = []
    seen: set[str] = set()
    for path in filter(None, paths):
        parser = configparser.ConfigParser(interpolation=None, strict=False)
        try:
            if not parser.read(path, encoding="utf-8"):
                continue
        except (OSError, UnicodeDecodeError, configparser.Error):
            continue
        for section in parser.sections():
            if section.strip().upper() == "ODBC DATA SOURCES" or section in seen:
                continue
            seen.add(section)
            values = {k.lower(): v for k, v in parser.items(section)}
            candidate = _odbc_candidate(
                section,
                values.get("driver", ""),
                values.get("server", ""),
                values.get("port", ""),
                values.get("database", ""),
                path,
            )
            if candidate is not None:
                out.append(candidate)
    return out


def _discover_odbc_dsns() -> list[Candidate]:
    if sys.platform == "win32":
        return _windows_odbc_dsns()
    return _posix_odbc_dsns()


# ---------------------------------------------------------------------------
# §7.6 — SQLite files, bounded and header-verified
# ---------------------------------------------------------------------------
_SQLITE_MAGIC = b"SQLite format 3\x00"
_SQLITE_SUFFIXES = frozenset({".db", ".sqlite", ".sqlite3", ".db3"})
_SIDECAR_SUFFIXES = ("-wal", "-shm", "-journal")
_PRUNED_DIR_NAMES = frozenset(
    {"node_modules", ".git", "venv", ".venv", "__pycache__", "site-packages", ".cache"}
)

#: d-MCP's own databases, excluded by name regardless of directory — DESIGN-CONNECTION-
#: SETUP.md §7.6: offering to "discover" the tool's own state file is not useful, and the
#: user's own connections.db is quite likely to sit in the very cwd being walked.
_OWN_DATABASE_NAMES = frozenset({"connections.db", "permissions.db", "audit.db"})

_SQLITE_MAX_DEPTH = 2  # the user's own ruling (§13 Q4): cwd and two levels below, no more
_SQLITE_MAX_ENTRIES = 20_000
_SQLITE_MAX_RESULTS = 200


def _looks_like_sqlite(path: Path) -> bool:
    """The file's own 16-byte header, never its extension and never ``sqlite3.connect()``.

    Opening an untrusted file with the SQLite library is itself an attack surface — a
    corrupt or hostile file can leave a ``-journal`` beside data the user never authorised
    a write against. Reading 16 bytes and comparing them answers the only question asked.
    """

    try:
        with open(path, "rb") as handle:
            header = handle.read(len(_SQLITE_MAGIC))
    except OSError:
        return False
    return header == _SQLITE_MAGIC


def _discover_sqlite_files(
    roots: list[Path], *, deadline: float, cancel: Any = None
) -> tuple[list[Candidate], bool]:
    """SQLite files under ``roots``, walked to depth :data:`_SQLITE_MAX_DEPTH`.

    ``os.scandir`` rather than ``Path.rglob``: ``rglob`` cannot be pruned mid-walk, so it
    would descend into ``node_modules`` before anything gets a chance to reject it.
    """

    import os

    results: list[Candidate] = []
    examined = 0
    truncated = False
    seen_identity: set[tuple[int, int]] = set()
    stack: list[tuple[str, int]] = [(str(root), 0) for root in roots]

    while stack and len(results) < _SQLITE_MAX_RESULTS:
        if cancel is not None and cancel.is_set():
            break
        if time.monotonic() > deadline or examined > _SQLITE_MAX_ENTRIES:
            truncated = True
            break
        directory, depth = stack.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    examined += 1
                    if examined > _SQLITE_MAX_ENTRIES or time.monotonic() > deadline:
                        truncated = True
                        break
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            name = entry.name
                            if depth < _SQLITE_MAX_DEPTH and not name.startswith(".") and (
                                name not in _PRUNED_DIR_NAMES
                            ):
                                try:
                                    stat = entry.stat(follow_symlinks=False)
                                except OSError:
                                    continue
                                identity = (stat.st_dev, stat.st_ino)
                                if identity not in seen_identity:
                                    seen_identity.add(identity)
                                    stack.append((entry.path, depth + 1))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    name = entry.name
                    if name in _OWN_DATABASE_NAMES:
                        continue
                    lowered = name.casefold()
                    if lowered.endswith(_SIDECAR_SUFFIXES):
                        continue
                    if os.path.splitext(lowered)[1] not in _SQLITE_SUFFIXES:
                        continue
                    path = Path(entry.path)
                    if not _looks_like_sqlite(path):
                        continue
                    results.append(
                        Candidate(
                            engine="sqlite",
                            host="localhost",
                            port=None,
                            instance=None,
                            database=str(path),
                            driver_hint="sqlite3",
                            auth_hint="none",
                            origin="sqlite-file",
                            origin_detail=str(path),
                            confidence="confirmed",
                            label=f"SQLite file — {path}",
                        )
                    )
                    if len(results) >= _SQLITE_MAX_RESULTS:
                        break
        except (OSError, PermissionError):
            continue
    return results, truncated


def search_sqlite_folder(
    folder: str | Path, *, budget_s: float = 2.0, cancel: Any = None
) -> DiscoveryResult:
    """The GUI's "Search in folder…" entry point (§13 Q4): one user-chosen root, on demand.

    The default sweep in :func:`discover_local` never looks outside the current working
    directory — the user's own ruling was "no wider default; offer a folder picker instead"
    — so this is that picker's other half: the same bounded, header-verified walk, rooted
    wherever the human just pointed it.
    """

    started = time.monotonic()
    deadline = started + max(0.1, budget_s)
    root = Path(folder).expanduser()
    if not root.is_dir():
        return DiscoveryResult(
            candidates=(),
            notes=(f"{root} is not a directory that can be searched.",),
            elapsed_ms=(time.monotonic() - started) * 1000,
            truncated=False,
        )
    candidates, truncated = _discover_sqlite_files([root], deadline=deadline, cancel=cancel)
    return DiscoveryResult(
        candidates=tuple(candidates),
        notes=(),
        elapsed_ms=(time.monotonic() - started) * 1000,
        truncated=truncated,
    )


# ---------------------------------------------------------------------------
# The public entry point
# ---------------------------------------------------------------------------
def discover_local(
    *,
    budget_s: float = 5.0,
    sources: Any = ORIGINS_LOCAL,
    sqlite_roots: list[Path] | None = None,
    cancel: Any = None,
) -> DiscoveryResult:
    """Everything this machine can say about itself, with no packet sent and no login tried.

    Every source is individually wrapped: a ``PermissionError`` reading a registry key, an
    unparsable ``odbc.ini``, an unreachable socket — each becomes one line in ``notes`` and
    is never allowed to raise out of this function. Discovery that half-works is useful;
    discovery that raises is a dialog showing a traceback.

    Args:
        budget_s: The whole sweep's wall-clock budget, shared across every source — not a
            per-source timeout. A slow registry read leaves less time for the port probe,
            rather than each source getting its own five seconds.
        sources: Which of :data:`ORIGINS_LOCAL` to run. Restricting this is how a "search
            again, faster" affordance in the GUI could skip the SQLite walk, say.
        sqlite_roots: Extra roots for the SQLite file search, beyond the current working
            directory. The user's ruling (§13 Q4) is that this module never widens its own
            default to the home directory; a caller that wants that passes it explicitly, or
            calls :func:`search_sqlite_folder` for the GUI's "Search in folder…" affordance.
        cancel: A ``threading.Event`` polled between sources and between socket probes, so
            a caller (a ``QThread`` worker) can stop a slow sweep early.

    Returns:
        Every candidate found, in no particular order — the GUI groups them by ``origin``.
    """

    started = time.monotonic()
    deadline = started + max(0.1, budget_s)
    candidates: list[Candidate] = []
    notes: list[str] = []
    truncated = False

    def _cancelled() -> bool:
        return cancel is not None and cancel.is_set()

    if _cancelled():
        return DiscoveryResult((), ("cancelled before it started",), 0.0, False)

    if "windows-registry" in sources and not _cancelled():
        try:
            candidates.extend(_discover_windows_registry())
        except Exception as exc:
            logger.debug("windows-registry source failed", exc_info=True)
            notes.append(f"the Windows registry could not be read for SQL Server instances: {exc}")

    if "windows-service" in sources and not _cancelled():
        try:
            candidates.extend(_discover_windows_services())
        except Exception as exc:
            logger.debug("windows-service source failed", exc_info=True)
            notes.append(f"the Windows service registry could not be read: {exc}")

    if "odbc-dsn" in sources and not _cancelled():
        try:
            candidates.extend(_discover_odbc_dsns())
        except Exception as exc:
            logger.debug("odbc-dsn source failed", exc_info=True)
            notes.append(f"the configured ODBC data sources could not be read: {exc}")

    if "listening-port" in sources and not _cancelled():
        try:
            candidates.extend(_discover_listening_ports(deadline=deadline, cancel=cancel))
        except Exception as exc:
            logger.debug("listening-port source failed", exc_info=True)
            notes.append(f"the loopback port probe failed: {exc}")

    if "sqlite-file" in sources and not _cancelled():
        roots = [Path.cwd(), *list(sqlite_roots or [])]
        try:
            found, was_truncated = _discover_sqlite_files(roots, deadline=deadline, cancel=cancel)
            candidates.extend(found)
            truncated = truncated or was_truncated
        except Exception as exc:
            logger.debug("sqlite-file source failed", exc_info=True)
            notes.append(f"the SQLite file search failed: {exc}")

    if not candidates and not notes:
        notes.append(
            "nothing was found. This machine may simply have no local server, or the "
            "account running d-MCP may not have permission to read the registry."
        )

    return DiscoveryResult(
        candidates=tuple(candidates),
        notes=tuple(notes),
        elapsed_ms=(time.monotonic() - started) * 1000,
        truncated=truncated,
    )


# ---------------------------------------------------------------------------
# §7.7 — the local network: SQL Server Browser (SSRP), the one source that
# leaves the machine, and the one this module cannot itself confirm or audit.
# ---------------------------------------------------------------------------
#: SQL Server Browser has no notion of a database engine other than its own — the whole
#: protocol is "which SQL Server instances live here" — so, unlike every local source, there
#: is no per-reply engine inference to get wrong.
_SSRP_ENGINE = "mssql"


def _candidate_from_ssrp_instance(instance: SsrpInstance) -> Candidate:
    """One :class:`Candidate` built from one *unauthenticated* SSRP reply.

    The one rule this function exists to enforce, restated from ``ssrp.py``'s own docstring
    on :attr:`SsrpInstance.peer` because getting it wrong here is exactly the vulnerability
    that docstring warns about: **``host`` is built from ``instance.peer``, never from
    ``instance.server``.** ``peer`` is the address the datagram actually arrived from;
    ``server`` is a name the *sender* typed into its own reply and is exactly as trustworthy
    as anything else in an unauthenticated UDP datagram. A ``Candidate.host`` is what the
    connection dialog pre-fills and what a human may then press *Save* against without ever
    re-reading it — building it from ``server`` would let a forged reply redirect a login to
    an address the reply's actual sender chose, not the address that answered.

    ``instance.server`` and ``instance.instance`` still reach the human, because the whole
    point of SSRP is to report a name a raw IP address cannot — but they reach it only inside
    ``label``, spelled out as a claim ("reported by the network"), never inside a field a
    caller might reasonably treat as address material. ``ssrp.py`` has already validated both
    against a strict character class (no backslash, no ``;``, no control character); this
    function repeats none of that validation and does not widen it — it only decides which
    validated field goes where.
    """

    server_display = f"{instance.server}\\{instance.instance}"
    label = f"SQL Server (reported by the network) — {server_display}"
    if instance.version:
        label += f", version {instance.version}"
    if not instance.name_matches_peer:
        # §7.8: a mismatch is kept, not dropped — a server may legitimately advertise a name
        # that does not resolve from here — but it is labelled so a human sees exactly what
        # ssrp.py's own docstring warns about: the claim and the actual source disagree.
        label += f" (reported by {instance.peer})"

    origin_detail = f"broadcast reply from {instance.peer}"
    if instance.port is not None:
        origin_detail += f":{instance.port}"

    return Candidate(
        engine=_SSRP_ENGINE,
        host=instance.peer,
        port=instance.port,
        instance=instance.instance,
        database=None,
        driver_hint=_DEFAULT_DRIVER.get(_SSRP_ENGINE),
        # Nothing about an unauthenticated network reply implies who may connect or how —
        # unlike a registry entry read on this same machine, an SSRP reply carries no
        # evidence at all about a trust relationship with the replying host.
        auth_hint="password",
        origin="sql-browser",
        origin_detail=origin_detail,
        confidence="reported",
        label=label,
    )


def discover_network(
    *,
    timeout_s: float = 2.0,
    targets: Sequence[str] = (),
    cancel: Event | None = None,
) -> DiscoveryResult:
    """Ask the local network's SQL Server Browser service which instances it can see.

    The one :mod:`discovery` source that puts a datagram on the wire, and a thin bridge onto
    ``sape_d_mcp.db.ssrp`` — the hardened, separately tested SSRP encoder/parser — rather than
    a reimplementation: every byte this function ever looks at has already been through
    :func:`sape_d_mcp.db.ssrp.parse_ssrp_response`'s validation, and nothing here widens what
    that parser narrowed (see :func:`_candidate_from_ssrp_instance`).

    **This function does not ask permission and does not write an audit row.** Both belong to
    the caller, by design, not by omission:

    * the §7.7 confirmation must be raised *before* this runs, on the GUI thread, because a
      worker thread that blocks on a modal is a worker thread blocking on the wrong thread
      (§7.9 point 6) — asking here, inside a function documented as synchronous and callable
      from a script or a test with no GUI attached, is not a place a confirmation dialog can
      live;
    * the sweep audit row (:func:`audit_network_discovery`) is documented, at its own
      definition, as the GUI worker layer's responsibility, called "immediately after
      [``discover_network``] returns (or raises)" — precisely so that row exists exactly
      once per invocation regardless of which of this function's two branches ran, and
      regardless of whether the confirmation was freshly asked or remembered from earlier in
      the session. Moving that call in here would not change *that* contract, only hide it
      one layer down; it stays at the call site, where the session, the log store and the
      confirmation all already live together.

    Args:
        timeout_s: The sweep's wall-clock budget, clamped exactly as
            :func:`sape_d_mcp.db.ssrp.query_ssrp` clamps it — to at least 0.1 s and at most
            :data:`sape_d_mcp.db.ssrp.MAX_TIMEOUT_S`. There is one deadline for the whole
            sweep, never one per target, so this never blocks longer than that ceiling
            regardless of how many targets are given or how many peers answer.
        targets: Hosts to ask directly, by name or dotted quad — the design's own contract
            for this parameter (``DESIGN-CONNECTION-SETUP.md`` §7.1): *"unicast hosts; empty
            = broadcast"*. Empty (the default) sends the one limited-broadcast datagram this
            module's policy is written about, through
            :func:`sape_d_mcp.db.ssrp.instances_on_local_network`. One or more hosts sends a
            unicast question to each of them instead, through
            :func:`sape_d_mcp.db.ssrp.query_ssrp` directly (not the single-host
            :func:`~sape_d_mcp.db.ssrp.instances_on_host`, precisely so several targets still
            share the one deadline above rather than each getting its own budget) — a
            question addressed to a host the caller named, which carries no broadcast policy
            obligation of its own (§9: the connection dialog's *Resolve port* button is this
            exact path, and needs no confirmation because nothing leaves the machine for an
            address nobody typed).
        cancel: Polled between datagrams, exactly as :func:`discover_local` polls its own
            ``cancel`` between sources — cooperative, because the alternative is killing a
            thread that owns a socket.

    Returns:
        Every candidate an SSRP reply named, each with ``confidence='reported'`` and
        ``origin='sql-browser'``, plus ``replies`` — the raw, pre-validation datagram count —
        so a caller building the :func:`audit_network_discovery` row can report
        ``accepted=len(result.candidates)`` and an approximate
        ``discarded=max(0, result.replies - len(result.candidates))``. **An empty result is
        not an error and is not evidence of absence** (``ssrp.py``'s own docstring): a
        firewall, a stopped Browser service, or a network that does not forward broadcasts
        all look exactly like "nobody is there".
    """

    started = time.monotonic()

    if cancel is not None and cancel.is_set():
        return DiscoveryResult(
            candidates=(), notes=("cancelled before it started",), elapsed_ms=0.0,
            truncated=False, replies=0,
        )

    try:
        if targets:
            ssrp_result: SsrpResult = query_ssrp(
                tuple(targets), broadcast=False, timeout_s=timeout_s, cancel=cancel
            )
        else:
            ssrp_result = instances_on_local_network(timeout_s=timeout_s, cancel=cancel)
    except Exception as exc:
        # query_ssrp() already catches OSError around its own socket work and reports it as
        # a note rather than a raise; this is the same discipline discover_local() applies to
        # every one of its sources, kept here against whatever this bridge itself could still
        # raise (a bad 'targets' value, for one) rather than trusting that nothing ever will.
        logger.debug("SSRP sweep failed", exc_info=True)
        return DiscoveryResult(
            candidates=(),
            notes=(f"the network search could not run on this machine ({exc}).",),
            elapsed_ms=(time.monotonic() - started) * 1000.0,
            truncated=False,
            replies=0,
        )

    candidates = tuple(
        _candidate_from_ssrp_instance(instance) for instance in ssrp_result.instances
    )
    return DiscoveryResult(
        candidates=candidates,
        notes=ssrp_result.notes,
        elapsed_ms=(time.monotonic() - started) * 1000.0,
        truncated=ssrp_result.truncated,
        replies=ssrp_result.replies,
    )


# ---------------------------------------------------------------------------
# Task 13 — audit rows for the network search (allowed AND refused), and their
# QA-reported gap: a session-remembered consent is not the same event as a sweep, and
# each sweep is what actually puts a datagram on the wire, so each sweep gets its own
# row regardless of whether the confirmation was freshly asked this time or not.
# ---------------------------------------------------------------------------
def audit_network_discovery_consent(
    log_store: Any,
    session_id: str,
    *,
    confirmed: bool,
) -> None:
    """One ``audit.db`` row for the operator's answer to the §7.7 broadcast warning.

    This is **not** the row for the sweep itself — see :func:`audit_network_discovery` for
    that, and read its docstring first, because the two used to be conflated and that
    conflation was a bug. This one exists only because "the operator was asked and
    declined" is worth more to a security review than silence (ADR 0003 decision 4), the
    same reasoning ``confirmation.py`` applies to a declined destructive-operation prompt,
    and because the consent decision and the traffic it authorises are two different facts
    that a reviewer may want to correlate rather than assume are the same event.

    Call this **only** at the moment the confirmation dialog is actually shown and
    answered — once per process at most, since §13 Q5 has the GUI remember an ``approved``
    answer for the rest of the session. A ``confirmed=False`` here means the sweep this
    prompt was gating never ran at all, so no corresponding :func:`audit_network_discovery`
    call follows it. A remembered approval on a later search, by contrast, calls neither
    this function again (the operator was not asked again) nor is exempt from
    :func:`audit_network_discovery` (the sweep still happened and still needs its own row).

    Best-effort: an audit failure must never turn a completed (or declined) confirmation
    into a raised exception, and a caller with no log store (a script, a unit test) is
    unaffected.
    """

    if log_store is None:
        return
    try:
        log_store.log_tool(
            None,
            session_id,
            "discover-network",
            {"scope": "broadcast"},
            result=None if confirmed else "the operator declined the network search",
            decision="allowed" if confirmed else "refused",
        )
    except Exception:
        logger.debug("Could not audit a network-discovery confirmation", exc_info=True)


def audit_network_discovery(
    log_store: Any,
    session_id: str,
    *,
    scope: str = "broadcast",
    target: str | None = None,
    timeout_s: float = 2.0,
    accepted: int = 0,
    discarded: int = 0,
    result_summary: str | None = None,
    error: str | None = None,
) -> None:
    """One ``audit.db`` row for one actual §7.7 network sweep — the act, not the consent.

    Fixes a real gap: the GUI used to write this row only from the confirmation dialog
    (see :func:`audit_network_discovery_consent`), and because §13 Q5 has that dialog ask
    only once per session, every sweep *after* the first ran with no audit trail at all —
    an unauthenticated UDP broadcast going out to the whole subnet, silently, as far as
    ``audit.db`` was concerned. What is audited is what left the machine, not whether a
    dialog was shown, so this call is mandatory on **every** completed (or failed) sweep:

    * the GUI worker layer must call this exactly once per :func:`discover_network`
      invocation, immediately after it returns (or raises) — whether or not the
      confirmation was freshly asked or remembered from earlier in the session;
    * :func:`audit_network_discovery_consent` above is called *in addition* on the
      sessions where the dialog is actually shown, never instead of this one.

    Args:
        scope: What went out — ``'broadcast'`` today (the limited-broadcast SSRP
            datagram); reserved for a future unicast-sweep mode.
        target: The subnet or interface the broadcast was sent on, where the caller can
            name one (e.g. ``'192.168.1.255/24'`` or an adapter name) — best-effort, since
            a limited broadcast is routed by the kernel and the exact link is not always
            known to the caller. ``None`` is recorded rather than guessed.
        timeout_s: The wall-clock budget given to the sweep — "how long did this run for"
            is as much a part of "what happened" as "what answered".
        accepted: How many replies were kept as candidates after validation (§7.7,
            ``ssrp.query_ssrp``'s own accept/reject split).
        discarded: How many datagrams arrived but were dropped — an unparsable reply, one
            from an unexpected source, or one past the reply cap — distinct from
            ``accepted`` because "something answered but was rejected" is a different
            security fact from "nothing answered".
        result_summary: A free-text human summary, as ``log_tool`` already supports.
        error: Set when the sweep itself failed (a socket error, an unroutable broadcast)
            rather than being merely empty of replies; recorded as ``decision='error'``
            instead of ``'allowed'`` so a failed sweep is not misread as a quiet one.

    Best-effort: an audit failure must never turn a completed (or failed) search into a
    raised exception, and a caller with no log store (a script, a unit test) is unaffected.
    """

    if log_store is None:
        return
    try:
        log_store.log_tool(
            None,
            session_id,
            "discover-network",
            {
                "scope": scope,
                "target": target,
                "timeout_s": timeout_s,
                "accepted": accepted,
                "discarded": discarded,
            },
            result=result_summary,
            error=error,
            decision="error" if error else "allowed",
        )
    except Exception:
        logger.debug("Could not audit a network discovery sweep", exc_info=True)
