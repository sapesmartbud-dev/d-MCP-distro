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

"""Opening a database connection: driver import, DSN assembly, health check, version probe."""

from __future__ import annotations

import logging
import os
import re
import socket
from collections.abc import Iterator, Mapping
from concurrent.futures import ThreadPoolExecutor
from concurrent.futures import TimeoutError as FutureTimeout
from contextlib import contextmanager
from dataclasses import dataclass
from time import perf_counter
from types import TracebackType
from typing import Any, Protocol

from sape_d_mcp.db.connection_store import (
    DEFAULT_STATEMENT_TIMEOUT_S,
    canonical_driver,
    canonical_engine,
)
from sape_d_mcp.db.dialects import (
    Dialect,
    DialectError,
    DialectNotConfiguredError,
    DriverNotInstalledError,
    Engine,
    Query,
    ReadOnlySession,
    SecretStr,
    ServerTraits,
    UnknownDriverError,
    dialect_for,
    import_driver,
    reads_as_read_only,
)
from sape_d_mcp.db.ssrp import instances_on_host
from sape_d_mcp.db.targets import parse_mssql_target

logger = logging.getLogger(__name__)

# The one method engine.py needs from LogStore, typed as a Protocol so this module
# never has to import log_store.py — the two audited actions here (an instance-port
# re-resolution and a database-list click, §13 Q2 and §8.5) are both best-effort:
# a caller with no log store at all (a unit test, a script) still gets a working
# connection, just no audit row.
class _AuditSink(Protocol):
    def log_tool(
        self,
        connection_id: int | None,
        session_id: str,
        tool_name: str,
        params: dict[str, Any],
        *,
        result: str | None = None,
        error: str | None = None,
        decision: str,
        rows_affected: int | None = None,
        duration_ms: int | None = None,
        matched_rule_id: int | None = None,
    ) -> None: ...

# How long to wait for the TCP connect and login before giving up.  Separate from
# statement_timeout_s, which bounds how long a *statement* may run once the
# session exists: a server that is down should be reported in seconds, whatever
# the connection's analytical query budget happens to be.
DEFAULT_CONNECT_TIMEOUT_S = 10

# Added to the driver's own timeout to give the wall-clock guard in
# _with_deadline() room to let the driver report its own, better-worded error
# first.  The guard exists because not every driver honours its timeout on every
# platform — pymssql on a black-holed address is the classic case — and
# test_connection() must always return.
_WALL_CLOCK_MARGIN_S = 5

# Where each driver takes its connect/login timeout.  This table lives in
# engine.py rather than in a dialect because it is a property of the DB-API
# package, not of the SQL the dialect writes, and because engine.py is the only
# module that ever calls connect().  A value already present in the profile's
# options_json wins: the operator asked for it explicitly.
_CONNECT_TIMEOUT_KEY: dict[str, str | None] = {
    "psycopg": "connect_timeout",
    "pymysql": "connect_timeout",
    "mysql-connector-python": "connection_timeout",
    "pymssql": "login_timeout",
    "sqlite3": "timeout",
    "pyodbc": None,  # string DSN; passed as the `timeout` keyword to pyodbc.connect()
}

# The seven buckets the GUI switches on.  Coarse on purpose — the sentence in
# `error` is what a human reads, and the kind is only there to choose an icon and
# a "what to try next" hint:
#
#   driver_missing  the Python package is not installed on this machine
#   auth            the server answered and rejected the credentials
#   network         the server could not be reached at all; for SQLite, the file
#                   could not be opened
#   tls             the TCP connection was made and the TLS handshake failed —
#                   almost always a certificate the client will not trust, which
#                   is a different repair from anything under `network`
#   timeout         the attempt exceeded its budget
#   protocol        the server was reached and accepted us, but it is not
#                   something d-MCP can drive — wrong product, unsupported
#                   version, or no such database
#   unknown         everything else, including a malformed profile
ERROR_KINDS: tuple[str, ...] = (
    "driver_missing",
    "auth",
    "network",
    "tls",
    "timeout",
    "protocol",
    "unknown",
)


@dataclass(frozen=True, slots=True)
class ConnectionTestResult:
    """What the Connections page's Test button shows.

    ``error`` is rendered verbatim, so it is always a sentence a human can act on
    and never a traceback, a driver error code on its own, or anything that could
    contain the password.  ``error_kind`` is one of :data:`ERROR_KINDS` when
    ``ok`` is ``False`` and the empty string when it is ``True``.
    """

    ok: bool
    server_version: str | None = None
    traits: ServerTraits | None = None
    latency_ms: float | None = None
    error: str | None = None
    error_kind: str = ""


# ---------------------------------------------------------------------------
# Error classification
# ---------------------------------------------------------------------------
# Ordered: the first pattern that matches wins, so the specific ones come before
# the general ones.  Matching is on the lower-cased exception text because the
# four driver families expose their codes in four incompatible ways and the text
# is the only thing all of them have.  Codes are consulted first where the driver
# does offer them, in _sqlstate() and _errno().
_TEXT_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        # First, because a failed TLS handshake is reported under SQLSTATE 08001 and
        # carries the vocabulary of a transport failure with it. Classified as
        # 'network' it produced the reported defect: an untrusted certificate was
        # explained to the user as a stopped SQL Server Browser, sending them to a
        # service that was running and a UDP port that was open.
        #
        # The SChannel/OpenSSL status codes are matched as well as the words because
        # the words are localised — msodbcsql18 on a German Windows says
        # "SSL-Anbieter: Die Zertifikatkette wurde von einer nicht vertrauenswürdigen
        # Zertifizierungsstelle ausgestellt" — while the code in the same message is
        # not. -2146893019 is SEC_E_UNTRUSTED_ROOT, -2146762487 CERT_E_UNTRUSTEDROOT,
        # -2146762481 CERT_E_CN_NO_MATCH (a certificate whose name is not the host
        # you dialled), -2146893016 SEC_E_CERT_EXPIRED.
        "tls",
        re.compile(
            r"-2146893019|-2146762487|-2146762481|-2146893016|"
            r"ssl provider|ssl-anbieter|schannel|"
            r"certificate chain|certificate verify failed|self[- ]signed certificate|"
            r"certificate is not trusted|untrusted certificate|"
            r"certificate authority|certificate has expired|"
            r"zertifikatkette|zertifizierungsstelle"
        ),
    ),
    (
        "timeout",
        re.compile(
            r"timeout expired|timed out|timeout period elapsed|connection timed out|"
            r"query timeout|login timeout|lock wait timeout"
        ),
    ),
    (
        "auth",
        re.compile(
            r"password authentication failed|authentication failed|login failed|"
            r"access denied for user|role .* does not exist|no password supplied|"
            r"password supplied is not correct|invalid authorization|"
            r"the user is not associated with a trusted|"
            # A trusted-connection attempt through a driver that has no SSPI/GSSAPI path
            # (or one whose ticket is missing) reports the caller as this well-known
            # anonymous principal — DESIGN-CONNECTION-SETUP.md §4.1/§6.4. It is an
            # authentication failure, not a network one, even though DB-Lib's own
            # transport code (20009, matched below) often accompanies it.
            r"nt authority\\anonymous logon"
        ),
    ),
    (
        "network",
        re.compile(
            r"could not connect|connection refused|could not translate host name|"
            r"name or service not known|nodename nor servname|no such host|"
            r"unknown mysql server host|can't connect to mysql server|"
            r"unable to open database file|unable to open the database file|"
            r"is the server running|network-related or instance-specific|"
            r"tcp provider|connection reset|host is unreachable|no route to host|"
            r"server closed the connection unexpectedly|socket|econnrefused|"
            # pymssql/FreeTDS's wording for DB-Lib 20002/20009 — "unavailable or does
            # not exist" reads like a typo in the database name, but it is what a
            # named instance whose Browser is not answering looks like, and also what
            # a trusted-connection attempt through pymssql looks like (§4.2, §6.4).
            r"adaptive server is unavailable or does not exist"
        ),
    ),
    (
        "protocol",
        re.compile(
            r"does not exist on server|database .* does not exist|unknown database|"
            r"cannot open database|file is not a database|file is encrypted|"
            r"unsupported|not supported by sap|is not a supported"
        ),
    ),
)

# SQLSTATE classes, which two of the four families report reliably.
_SQLSTATE_KINDS: dict[str, str] = {
    "28": "auth",       # invalid authorisation specification
    "08": "network",    # connection exception
    "HY": "timeout",    # HYT00/HYT01 are ODBC's timeout states
    "3D": "protocol",   # invalid catalogue name
    "0A": "protocol",   # feature not supported
}

# Driver-specific numeric codes worth recognising by hand.
_MYSQL_AUTH_ERRNOS = frozenset({1044, 1045, 1698, 1130})
_MYSQL_UNKNOWN_DB_ERRNO = 1049
_MSSQL_LOGIN_FAILED = 18456

# DB-Lib transport failures. 20009 is what a named instance whose Browser is not
# answering looks like, and it is also what a trusted-connection attempt looks
# like — it says "unavailable or does not exist", which sends people to the
# firewall. Both real causes are named in the sentence instead (§6.4). 20002 is
# the sibling "server connection failed" DB-Lib code and is bucketed the same way,
# for the same reason.
_MSSQL_TRANSPORT_ERRNOS = frozenset({20002, 20009})


def _sqlstate(exc: BaseException) -> str | None:
    state = getattr(exc, "sqlstate", None)
    if isinstance(state, str) and len(state) >= 2:
        return state
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], str) and re.fullmatch(r"[0-9A-Z]{5}", args[0]):
        return args[0]
    return None


def _errno(exc: BaseException) -> int | None:
    for attribute in ("errno", "number"):
        value = getattr(exc, attribute, None)
        if isinstance(value, int):
            return value
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], int):
        return args[0]
    return None


def classify_error(exc: BaseException) -> str:
    """Map a driver exception to one of :data:`ERROR_KINDS`.

    Deliberately not a chain of ``isinstance`` checks: the five DB-API packages
    d-MCP ships against have five unrelated exception hierarchies, and three of
    them raise the same ``OperationalError`` for a refused connection and a
    refused password.
    """
    if isinstance(exc, DriverNotInstalledError):
        return "driver_missing"
    if isinstance(exc, ImportError):
        return "driver_missing"
    if isinstance(exc, (TimeoutError, FutureTimeout)):
        return "timeout"

    errno = _errno(exc)
    if errno in _MYSQL_AUTH_ERRNOS or errno == _MSSQL_LOGIN_FAILED:
        return "auth"
    if errno == _MYSQL_UNKNOWN_DB_ERRNO:
        return "protocol"
    if errno in _MSSQL_TRANSPORT_ERRNOS:
        return "network"

    text = " ".join(str(a) for a in getattr(exc, "args", ()) or ()) + " " + str(exc)
    text = text.lower()
    for kind, pattern in _TEXT_PATTERNS:
        if pattern.search(text):
            return kind

    state = _sqlstate(exc)
    if state:
        mapped = _SQLSTATE_KINDS.get(state[:2])
        if mapped:
            return mapped

    if isinstance(exc, DialectError):
        return "protocol"
    if isinstance(exc, OSError):
        return "network"
    return "unknown"


def _sentence(exc: BaseException, kind: str, profile: Mapping[str, Any], timeout_s: int) -> str:
    """A sentence the Connections page can show, per kind.

    The driver's own text is appended in brackets where it adds anything, because
    a DBA reading "login failed for user 'sa'" learns more than from any wording
    we could invent — but it is never the whole message, because on its own it
    tells a non-DBA nothing about what to do.  The password is never part of it:
    it is never in the profile, and ``with_password()``'s output is never allowed
    to reach an exception.
    """
    detail = str(exc).strip().replace("\n", " ")
    detail = re.sub(r"\s+", " ", detail)
    if len(detail) > 300:
        detail = detail[:297] + "…"

    target = _describe_target(profile)
    engine = str(profile.get("engine") or "the database")

    if kind == "driver_missing":
        # DriverNotInstalledError already names the pip requirement, and that is
        # the whole point of it, so it is passed through unchanged.
        return detail
    if kind == "auth":
        user = profile.get("username") or "the configured user"
        return (
            f"{target} rejected the credentials for {user!r}. Check the username and "
            f"the stored password, and that the account may sign in to this database. "
            f"({detail})"
        )
    if kind == "network":
        if engine == "sqlite":
            # 'network' is the bucket for "the database could not be reached",
            # and for SQLite that means the file: the advice has to differ or it
            # sends the user looking for a firewall in front of a local file.
            return (
                f"Could not open {target}. Check that the file exists, that the path is "
                f"right, and that this account may read and write it. ({detail})"
            )
        if engine == "mssql" and (profile.get("instance") or _mssql_host_is_compound(profile)):
            # §6.4: a named instance turns "network error" into three real, distinct
            # causes, none of which a firewall rule for the wrong port would fix.
            return (
                f"Could not reach {target}. Because this profile names a SQL Server "
                f"instance, this usually means one of three things: the SQL Server "
                f"Browser service is stopped, UDP port 1434 is blocked, or the instance "
                f"name is wrong. Use \"Resolve port\" to ask the Browser again. ({detail})"
            )
        return (
            f"Could not reach {target}. Check that the server is running, that the host "
            f"and port are right, and that no firewall is in the way. ({detail})"
        )
    if kind == "tls":
        return (
            f"{target} answered, but its TLS certificate was not trusted, so the "
            f"connection was refused before any credentials were sent. ODBC Driver 18 "
            f"encrypts by default and verifies the certificate. If this is an internal "
            f"server with a self-signed certificate, tick \"Trust the server certificate\" "
            f"on the profile; if it should have a certificate your machine trusts, install "
            f"the issuing authority instead. ({detail})"
        )
    if kind == "timeout":
        return (
            f"Connecting to {target} took longer than {timeout_s} s and was abandoned. "
            f"Raise the timeout if the server is simply slow, otherwise check that it is "
            f"reachable. ({detail})"
        )
    if kind == "protocol":
        return (
            f"{target} answered, but SAPÉ d-MCP cannot drive it as a {engine} server. "
            f"({detail})"
        )
    return f"Connecting to {target} failed: {detail}"


def _mssql_host_is_compound(profile: Mapping[str, Any]) -> bool:
    """Whether ``host`` still carries an instance or a port §3.5 migrated verbatim.

    A profile whose ``host`` column parses into more than a bare server name is the
    exact shape of the reported ``PC-ARR\\SQLEXPRESS:56879`` row, and it deserves the
    same "resolve the port" sentence a named-instance profile gets, even though the
    ``instance`` column itself is still empty.
    """
    host = profile.get("host")
    if not isinstance(host, str) or not host.strip():
        return False
    try:
        return parse_mssql_target(host).compound
    except ValueError:
        # Unparsable is not a bare server name either — treat it the same way.
        return True


def _describe_target(profile: Mapping[str, Any]) -> str:
    """Name the server in a way that reads in a sentence, without leaking anything."""
    engine = str(profile.get("engine") or "")
    database = profile.get("database")
    if engine == "sqlite":
        return f"the SQLite file {database}"
    host = profile.get("host")
    port = profile.get("port")
    if host and port:
        return f"{host}:{port}/{database}"
    return str(database or "the database")


# ---------------------------------------------------------------------------
# Connecting
# ---------------------------------------------------------------------------


class DatabaseConnection:
    """One live DB-API connection, its dialect and the traits its probe found.

    Thin on purpose.  It gives the later stages a single object to hold — the
    connection cannot be separated from the dialect that knows how to speak to
    it, nor from the ``ServerTraits`` every capability answer derives from — and
    nothing more.  Row capping, statement classification and the audit record
    belong to the layers above.
    """

    __slots__ = ("_closed", "_read_only_depth", "dialect", "profile", "raw", "traits")

    def __init__(
        self,
        profile: Mapping[str, Any],
        dialect: Dialect,
        raw: Any,
        traits: ServerTraits | None = None,
    ) -> None:
        self.profile = dict(profile)
        self.dialect = dialect
        self.raw = raw
        self.traits = traits
        self._closed = False
        # How many nested read_only_session() blocks are currently holding this session
        # hardened.  Zero means the session may write; anything above zero means the
        # hardening statements have run and have not been undone.  See read_only_session().
        self._read_only_depth = 0

    def __repr__(self) -> str:
        # Explicit: the default would show self.profile, and while a profile can
        # never hold a password, an explicit repr is what keeps that true after
        # someone adds a field.
        state = "closed" if self._closed else "open"
        return (
            f"<DatabaseConnection {self.profile.get('display_name')!r} "
            f"{self.profile.get('engine')}/{self.profile.get('driver')} {state}>"
        )

    @property
    def closed(self) -> bool:
        return self._closed

    @property
    def read_only(self) -> bool:
        """Whether a :func:`read_only_session` block currently holds this session hardened."""

        return self._read_only_depth > 0

    def cursor(self) -> Any:
        """A DB-API cursor from the underlying connection."""
        if self._closed:
            raise RuntimeError("this connection has been closed")
        return self.raw.cursor()

    def execute(self, sql: str, params: Any = ()) -> Any:
        """Run one statement and return the cursor.

        There is no statement classification here: this is the plumbing the guard
        sits on top of, not a route around it.  Everything reaching the LLM goes
        through ``sql_guard`` first, and a test in stage 7 asserts that no MCP
        tool calls this directly.

        Parameters are forwarded only when there are any — the same rule
        :func:`_run_session_statement` documents, applied here because ``Script``
        steps come through this method and every one of them is parameterless.
        Three of the five drivers read a supplied-but-empty parameter container as
        "please interpolate", so ``cursor.execute(sql, {})`` runs ``sql % {}`` and
        a lone ``%`` in the statement raises a formatting error instead of running.
        That is not hypothetical: a MySQL account name is ``'user'@'host'`` and the
        host half is very often ``%``, so ``REVOKE ... FROM `bob`@`%` `` — the
        statement that *narrows* an account's access — is exactly the one that
        would have failed.
        """
        cursor = self.cursor()
        if params:
            cursor.execute(sql, params)
        else:
            cursor.execute(sql)
        return cursor

    def close(self) -> None:
        """Close the underlying connection.  Safe to call twice."""
        if self._closed:
            return
        self._closed = True
        try:
            self.raw.close()
        except Exception:
            logger.debug("Error while closing %r", self, exc_info=True)

    def __enter__(self) -> DatabaseConnection:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


def resolve_dialect(profile: Mapping[str, Any]) -> Dialect:
    """The unconfigured dialect for a profile.  Imports no DB-API package.

    Separate from :func:`connect` because the Connections page needs a dialect to
    build a DSN preview and to label its fields long before anything is
    installed, let alone reachable.
    """
    engine = canonical_engine(str(profile.get("engine") or ""))
    driver = canonical_driver(engine, str(profile.get("driver") or ""))
    return dialect_for(Engine(engine), driver)


def _connect_timeout(profile: Mapping[str, Any], timeout_s: int | None) -> int:
    if timeout_s is not None:
        return max(1, int(timeout_s))
    return DEFAULT_CONNECT_TIMEOUT_S


def _refuse_password_for_non_password_profile(
    profile: Mapping[str, Any], password: str | None
) -> None:
    """§5.2: the mode decides whether a password is meaningful, never the presence of one.

    A profile whose ``auth_mode`` left ``'password'`` has its keyring entry deleted by
    ``ConnectionStore.update()`` (§5.1), but a purge can fail — a locked AES vault with
    no master password available, most plausibly — and the row survives as an orphan.
    Refusing here, before ``build_dsn()`` is ever called, is what stops that orphan from
    ever being *used*: a stale ``PWD=`` would otherwise ride along on a Windows trusted
    connection or a PostgreSQL ``peer`` login and nobody would notice, because both
    succeed regardless of what was sent.  ``auth_mode`` defaults to ``'password'`` for a
    profile written before this column existed, so an existing caller is unaffected.
    """
    if password is None:
        return
    auth_mode = str(profile.get("auth_mode") or "password")
    if auth_mode != "password":
        raise ValueError(
            f"connection {profile.get('display_name')!r} authenticates through the "
            "operating system and takes no password."
        )


def _open_raw(
    dialect: Dialect,
    driver: str,
    module: Any,
    profile: Mapping[str, Any],
    password: str | None,
    timeout_s: int,
) -> Any:
    """Build the DSN, add the secret and call ``module.connect()``.

    The secret enters the process's memory here and leaves it in the ``finally``.
    ``build_dsn()`` returns a password-free value that is safe to log; only
    ``with_password()``'s output is sensitive, it is held in exactly one local
    name, and that name is cleared whether or not the connect succeeded.
    """
    dsn = dialect.build_dsn(profile)

    timeout_key = _CONNECT_TIMEOUT_KEY.get(driver)
    if isinstance(dsn, dict) and timeout_key and timeout_key not in dsn:
        # Only when the dialect has not already taken it from options_json: an
        # explicit operator setting outranks our default.
        dsn = {**dsn, timeout_key: timeout_s}

    if driver == "sqlite3" and isinstance(dsn, str) and dsn != ":memory:" and not os.path.exists(dsn):
        # sqlite3.connect() creates a missing file rather than refusing it, so a
        # mistyped path would report a healthy connection to an empty database
        # the user has never seen — and the Explorer page would then honestly
        # show it as having no tables.  d-MCP attaches to databases; it does not
        # bring them into existence.
        raise FileNotFoundError(
            f"there is no SQLite database at {dsn}. Check the path — d-MCP will not "
            "create a database file, because a typo would otherwise look like an "
            "empty but healthy connection."
        )

    authenticated: Any = None
    try:
        authenticated = dialect.with_password(dsn, SecretStr(password)) if password else dsn
        if isinstance(authenticated, Mapping):
            return module.connect(**dict(authenticated))
        if driver == "pyodbc":
            # pyodbc is the one driver whose DSN is a string and whose login
            # timeout is a connect() keyword rather than a DSN attribute.
            return module.connect(authenticated, timeout=timeout_s)
        return module.connect(authenticated)
    finally:
        # Drop the only reference to the secret-bearing value.  It cannot be
        # scrubbed from CPython's heap, but it must not survive as a local that a
        # traceback frame would render.
        del authenticated


# ---------------------------------------------------------------------------
# §13 Q2 — one automatic retry after re-resolving a named instance's dynamic port
# ---------------------------------------------------------------------------
# The user's ruling departs from the design's own recommendation (which was "no automatic
# retry, offer a button instead"): on a network failure for an MS-SQL profile that names an
# instance, d-MCP DOES re-resolve the port through the SQL Server Browser and retry —
# exactly once, never a loop, and only a *unicast* query to the profile's own host, never a
# broadcast to the network. This is the same protocol §7.7 uses for the network-wide search,
# but a unicast query to a host the profile already names needs none of that feature's
# confirmation, because nothing leaves the machine that was not already going to (the
# profile's own connect attempt just did).
#
# The wire format — the datagram out, the untrusted datagram back, and every character
# class a reply is validated against — lives in `sape_d_mcp.db.ssrp` and nowhere else. It
# used to be reimplemented here, before that module existed; it no longer is, because two
# parsers of hostile bytes off the wire is exactly the thing that cannot be kept in step,
# and only one of them would ever receive the next security fix. This retry now differs
# from `sape_d_mcp.db.ssrp.instances_on_host()`'s own default caller only in policy, not in
# parsing: it asks about one host (never `instances_on_local_network()`, never a broadcast)
# and it asks with a short timeout, because this runs inline on a failed connect attempt and
# must not turn one slow failure into a second, equally slow one.
_SSRP_RESOLVE_TIMEOUT_S = 1.5


def _resolved_addresses(host: str) -> frozenset[str]:
    """The IPv4 literals ``host`` resolves to, or an empty set on any failure.

    Exists for one reason: an SSRP candidate's ``instance`` and ``server`` fields are
    exactly what a forged datagram controls, so matching on them tells you nothing about
    who actually answered. The one field a forger cannot choose is the source address the
    kernel stamps on the UDP datagram — ``candidate.peer`` — which is why the retry ties
    its trust to that instead, against the address(es) the profile's own ``host`` resolves
    to. ``instances_on_host`` (via :mod:`sape_d_mcp.db.ssrp`) only ever opens an ``AF_INET``
    socket, so only IPv4 literals are asked for here; a ``host`` that resolves solely to
    IPv6 simply never matches, which is the safe (default-deny) side of that gap and not a
    bug to work around.

    A name that fails to resolve — typo, a DNS hiccup, an offline host — yields an empty
    set rather than an exception: this is a security gate, and a gate that cannot decide
    must close, not fall back to trusting the claim.
    """

    try:
        # `getaddrinfo`'s `sockaddr` element is typed as a union of the 2-tuple (IPv4) and
        # 4-tuple (IPv6, with scope id) shapes, so mypy widens `info[4][0]` to `str | int`
        # across the union rather than tracking that `AF_INET` here means it is always the
        # former. The `str(...)` is a no-op at runtime — the value already is one — and
        # says so to the checker without hiding a genuine type mismatch behind an ignore.
        return frozenset(
            str(info[4][0]) for info in socket.getaddrinfo(host, None, socket.AF_INET)
        )
    except OSError:
        return frozenset()


def _resolve_instance_port_via_ssrp(
    host: str,
    instance: str,
    *,
    timeout_s: float = _SSRP_RESOLVE_TIMEOUT_S,
    rejected_peers: list[str] | None = None,
) -> int | None:
    """Ask the SQL Server Browser on ``host`` what port ``instance`` currently listens on.

    Delegates entirely to :func:`sape_d_mcp.db.ssrp.instances_on_host`, which sends one
    unicast `CLNT_UCAST_EX` datagram to ``host`` — never a broadcast — and returns every
    instance that host claims to run, each already validated against SSRP's character
    classes (DESIGN-CONNECTION-SETUP.md §7.8). The policy that stays here is twofold: pick
    out the one instance this profile names, by a case-insensitive match against the name
    already stored, never against fresh input — and then require that the reply actually
    came from ``host``, by comparing ``candidate.peer`` (the address the datagram arrived
    from, never attacker-chosen) against the address(es) ``host`` itself resolves to.

    That second check is the fix for a real finding: a reply naming the right instance but
    a *different* ``ServerName`` and arriving from a *different* address used to be accepted
    regardless, because only ``candidate.instance`` was ever compared. A forged datagram
    from anywhere on the segment could then redirect the retry — and hence the next
    connection attempt, with the operator's own credentials — to a port of the attacker's
    choosing. ``candidate.server`` is deliberately *not* part of this check: it is the name
    the peer chose to advertise, exactly as forgeable as the instance name, and a legitimate
    server is entitled to advertise a name that does not resolve from here at all (a CNAME,
    a short name against an FQDN, ``localhost`` against ``127.0.0.1``) without that being
    grounds for suspicion. Only ``peer`` — set by the kernel from the packet that actually
    arrived, never by anything in the payload — is solid enough to gate a credentialed
    connection on.

    This does not depend on `sape_d_mcp.db.ssrp.query_ssrp` also filtering by source address
    for a unicast probe (a separate, complementary hardening); it holds even if that one
    were absent, because it never trusts anything `query_ssrp` merely passed through
    unchecked.

    Args:
        rejected_peers: When given, the address of every candidate discarded for arriving
            from somewhere other than ``host`` is appended here, so a caller with access to
            the audit trail can record the rejection — a forged reply is a signal an
            operator should be able to see, not a detail this function should swallow.

    Returns ``None`` on any failure — a closed UDP port, a stopped Browser service, no
    reply within the deadline, a reply that does not mention this instance, one that
    mentions it with no TCP port, or one that mentions it but did not come from ``host`` —
    because "could not re-resolve" and "re-resolved to nothing trustworthy" are the same
    outcome from the retry's point of view: keep the original error either way.
    """
    result = instances_on_host(host, timeout_s=timeout_s)
    resolved = _resolved_addresses(host)
    for candidate in result.instances:
        if candidate.instance.casefold() != instance.casefold() or candidate.port is None:
            continue
        if candidate.peer not in resolved:
            logger.warning(
                "Ignoring an SSRP reply for instance %r: it arrived from %r, which does not "
                "resolve to the host asked (%r). This is what a forged or misdirected "
                "datagram looks like, not an ordinary miss.",
                instance,
                candidate.peer,
                host,
            )
            if rejected_peers is not None:
                rejected_peers.append(candidate.peer)
            continue
        return candidate.port
    return None


def _audit_instance_port_reresolution(
    log_store: _AuditSink | None,
    session_id: str | None,
    profile: Mapping[str, Any],
    old_port: Any,
    new_port: int | None,
    rejected_peers: list[str] | None = None,
) -> None:
    """One audit row recording that a re-resolution happened, and from what port to what.

    ``rejected_peers`` is folded in here rather than logged separately, because a candidate
    discarded for not coming from the profile's own host is not a routine miss like "the
    Browser did not answer" — it is evidence that something on the segment answered on the
    host's behalf, and an operator reading the trail after the fact needs that surfaced
    alongside the resolution attempt it belongs to, not buried in a debug log nobody reads
    unless they already suspect something.

    Best-effort and never fatal: an audit failure must not turn a successful retry into a
    failed connection, and a missing log store (a script, a unit test) must not either.
    """
    if log_store is None:
        return
    try:
        result = (
            f"re-resolved port {old_port!r} -> {new_port!r}"
            if new_port is not None
            else "the SQL Server Browser did not answer, or reported no change"
        )
        if rejected_peers:
            result += (
                f"; discarded {len(rejected_peers)} reply(ies) that did not arrive from the "
                f"host asked: {rejected_peers!r}"
            )
        log_store.log_tool(
            profile.get("id"),
            session_id or "cli",
            "resolve-instance-port",
            {
                "_connection": profile.get("display_name"),
                "instance": profile.get("instance"),
                "old_port": old_port,
                "new_port": new_port,
                "rejected_peers": list(rejected_peers) if rejected_peers else [],
            },
            result=result,
            decision="allowed",
        )
    except Exception:
        logger.debug("Could not audit an instance-port re-resolution", exc_info=True)


def _retry_after_ssrp_reresolution(
    profile: Mapping[str, Any],
    exc: BaseException,
    *,
    password: str | None,
    timeout_s: int | None,
    probe: bool,
    log_store: _AuditSink | None,
    session_id: str | None,
) -> DatabaseConnection | None:
    """The §13 Q2 retry.  Returns a live connection, or ``None`` to let ``exc`` propagate.

    Every one of these conditions must hold, and each is one of the user's own: the engine
    is MS-SQL, the profile names an instance, the failure classifies as a network failure
    (not an auth failure — retrying a login that has already been refused would only annoy
    the server), and the Browser's answer actually names a different port. Anything else
    and this returns ``None`` so the caller re-raises the original exception unchanged.
    """
    try:
        engine = canonical_engine(str(profile.get("engine") or ""))
    except ValueError:
        return None
    if engine != "mssql":
        return None
    instance = profile.get("instance")
    if not instance:
        return None
    if classify_error(exc) != "network":
        return None
    host = str(profile.get("host") or "").strip()
    if not host:
        return None

    old_port = profile.get("port")
    rejected_peers: list[str] = []
    new_port = _resolve_instance_port_via_ssrp(
        host, str(instance), rejected_peers=rejected_peers
    )
    _audit_instance_port_reresolution(
        log_store, session_id, profile, old_port, new_port, rejected_peers
    )

    if new_port is None or new_port == old_port:
        return None

    logger.info(
        "Retrying %r once after the SQL Server Browser re-resolved instance %r from port "
        "%r to %r",
        profile.get("display_name"),
        instance,
        old_port,
        new_port,
    )
    retried_profile = dict(profile)
    retried_profile["port"] = new_port
    return connect(
        retried_profile,
        password,
        timeout_s=timeout_s,
        probe=probe,
        _ssrp_retried=True,
        log_store=log_store,
        session_id=session_id,
    )


def connect(
    profile: Mapping[str, Any],
    password: str | None = None,
    *,
    timeout_s: int | None = None,
    probe: bool = True,
    _ssrp_retried: bool = False,
    log_store: _AuditSink | None = None,
    session_id: str | None = None,
) -> DatabaseConnection:
    """Open a connection, health-check it, probe the server and apply its statement budget.

    Raises rather than returning a result object: the callers that want a verdict
    call :func:`test_connection`, which wraps this.  ``probe=False`` skips the
    version probe for a caller that already holds ``ServerTraits`` for this
    server and only needs another session.

    **No pooling.** DESIGN-MCP-TOOLS.md §3.1 puts pooling in an ``EngineRegistry``
    owned by the MCP server, with per-connection in-flight counters and a
    two-phase drain on delete (§2.7); that lands with the server in stage 6, and
    it needs the retire/drain semantics rather than a plain pool.  Building a
    pool here now would be a second, subtly different one to throw away.  What
    this module provides is the primitive that registry will hold: open, health
    check, probe, close.
    """
    _refuse_password_for_non_password_profile(profile, password)

    connect_timeout = _connect_timeout(profile, timeout_s)
    engine = canonical_engine(str(profile.get("engine") or ""))
    driver = canonical_driver(engine, str(profile.get("driver") or ""))
    dialect = dialect_for(Engine(engine), driver)
    module = import_driver(driver)

    try:
        raw = _open_raw(dialect, driver, module, profile, password, connect_timeout)
    except Exception as exc:
        if not _ssrp_retried:
            retried = _retry_after_ssrp_reresolution(
                profile,
                exc,
                password=password,
                timeout_s=timeout_s,
                probe=probe,
                log_store=log_store,
                session_id=session_id,
            )
            if retried is not None:
                return retried
        raise
    wrapper = DatabaseConnection(profile, dialect, raw)
    try:
        cursor = raw.cursor()
        try:
            cursor.execute(dialect.health_check_sql())
            cursor.fetchall()
            if probe:
                cursor.execute(dialect.version_probe_sql())
                rows = cursor.fetchall()
                traits = type(dialect).parse_traits([list(r) for r in rows])
                dialect.configure(traits)
                wrapper.traits = traits
        finally:
            try:
                cursor.close()
            except Exception:
                logger.debug("Error while closing the probe cursor", exc_info=True)
        # Once per session, out of the profile and never out of a tool argument
        # (DESIGN-MCP-TOOLS.md §6.1, §13 decision 2).  After the probe, because MySQL
        # cannot name its own timeout variable until it knows which of the two families
        # it is talking to.  Inside the try, so a server that refuses the budget the
        # operator configured closes the connection instead of serving unbounded reads.
        apply_statement_timeout(wrapper)
    except BaseException:
        wrapper.close()
        raise
    return wrapper


@contextmanager
def connection(
    profile: Mapping[str, Any],
    password: str | None = None,
    *,
    timeout_s: int | None = None,
    probe: bool = True,
) -> Iterator[DatabaseConnection]:
    """``with connection(profile, password) as db:`` — always closed on the way out."""
    handle = connect(profile, password, timeout_s=timeout_s, probe=probe)
    try:
        yield handle
    finally:
        handle.close()


# ---------------------------------------------------------------------------
# The read-only session, and the statement budget
# ---------------------------------------------------------------------------


class ReadOnlySessionError(RuntimeError):
    """The session could not be hardened against writing, so the read was refused.

    Deliberately not a subclass of :class:`DialectError`: this is not a fault in the SQL a
    dialect wrote, it is the second line of defence failing to come up, and the caller must
    treat it as a refusal rather than as a driver hiccup to retry around.
    """


def _run_session_statement(db: DatabaseConnection, query: Query) -> list[tuple[Any, ...]]:
    """Execute one statement of a session plan and return whatever it produced.

    Parameters are passed only when there are any.  Every statement in every plan is
    parameterless, and three of the five drivers treat a supplied-but-empty parameter
    container as "please interpolate", which turns a stray ``%`` in a future plan into a
    formatting error rather than a statement.

    Returns:
        The rows, or an empty list where the statement produced no result set.  A ``SET`` or a
        ``ROLLBACK`` returns nothing on every driver and asking for rows raises on most of
        them, so the fetch is attempted and its failure treated as "no rows" rather than
        predicted per driver.
    """

    cursor = db.cursor()
    try:
        if query.params:
            cursor.execute(query.sql, query.params)
        else:
            cursor.execute(query.sql)
        try:
            fetched = cursor.fetchall()
        except Exception:
            return []
        return [tuple(row) for row in (fetched or ())]
    finally:
        try:
            cursor.close()
        except Exception:  # pragma: no cover - close is best effort
            logger.debug("Error closing a session-plan cursor", exc_info=True)


def _release_read_only(db: DatabaseConnection, plan: ReadOnlySession) -> bool:
    """Undo the hardening.  Never raises; closes the connection if it cannot.

    Closing is the fallback because it is the one restore every engine performs for us:
    session variables, connection pragmas and open transactions all die with the connection,
    and :meth:`DatabaseConnection.close` cannot itself fail in a way the caller must handle.
    A closed session is reopened transparently the next time it is asked for — the MCP
    server's ``_resolve_connection()`` already checks ``cached.db.closed`` — whereas a session
    left read-only would come back, look healthy, and fail every write tool that touched it.

    Returns:
        ``True`` where the session is fit to be reused, ``False`` where it had to be closed.
    """

    try:
        for statement in plan.release:
            _run_session_statement(db, statement)
        if plan.verify_released is not None:
            rows = _run_session_statement(db, plan.verify_released)
            if rows and rows[0] and reads_as_read_only(rows[0][0]):
                raise ReadOnlySessionError(
                    f"the release statements ran but the session still reports itself "
                    f"read-only ({plan.note})"
                )
    except Exception:
        logger.error(
            "Could not restore %r to a writable session; closing it so nothing reuses it "
            "in that state",
            db,
            exc_info=True,
        )
        db.close()
        return False
    return True


@contextmanager
def read_only_session(db: DatabaseConnection) -> Iterator[ReadOnlySession]:
    """Harden one session against writing for the duration of the block, then restore it.

    The second line of defence behind ``sql_guard`` on every read path (DESIGN-MCP-TOOLS.md
    §9.1 step 11).  A context manager and not a flag on ``connect()`` for one reason: the
    connections d-MCP opens are the same ones stage 7's write tools use, so the hardening has
    to be scoped to the read that needs it and undone before anything else is allowed near the
    session.  A "read-only connection" would either need a second pool, doubling the number of
    logins d-MCP holds against a production server, or would have to be reasoned about at
    every future call site; a block that begins and ends is reasoned about once, here.

    **It fails closed.**  If any hardening statement raises, or if the verify statement says
    the hardening did not take, this raises :class:`ReadOnlySessionError` and the caller's
    block never runs.  There is no path on which the body executes against a session that can
    write.  The verify step is what makes that claim true rather than hopeful: PostgreSQL
    answers `SET TRANSACTION READ ONLY` outside a transaction block with a warning and no
    effect, and a warning is not something a DB-API driver raises on.

    **The restore is guaranteed three deep.**  The release statements run in a ``finally``, so
    they run whether the body returned, raised, or was abandoned through ``GeneratorExit``.  If
    a release statement itself fails, :func:`_release_read_only` closes the connection, which
    discards the session state and the transaction with it — a closed session is reopened on
    next use, a silently read-only one is not detectable from outside.  And the release is
    verified with the same statement as the hardening, in reverse, so "the statement ran" is
    never mistaken for "the session is writable again".

    Re-entrant by depth: nesting two blocks on one connection hardens once and releases once,
    at the outermost exit.  An inner block that released on its own exit would leave the outer
    read running unprotected, which is the sort of hole that only appears when a helper is
    refactored to be shared.

    Args:
        db: The open connection to harden.  It is hardened in place, not copied.

    Yields:
        The :class:`ReadOnlySession` plan in force, whose ``enforcement`` says whether this
        engine refuses a write outright or merely cannot keep it (SQL Server).

    Raises:
        ReadOnlySessionError: The session could not be proved read-only.  The read must not
            proceed.
    """

    if db.closed:
        raise ReadOnlySessionError("this connection is closed; it cannot be hardened for a read")

    plan = db.dialect.read_only_session()

    if db.read_only:
        # Already hardened by an enclosing block.  Count in, hand over the same plan, and
        # leave both the hardening and the release to the block that owns them.
        db._read_only_depth += 1
        try:
            yield plan
        finally:
            db._read_only_depth -= 1
        return

    try:
        for statement in plan.harden:
            _run_session_statement(db, statement)
        if plan.verify is not None:
            rows = _run_session_statement(db, plan.verify)
            cell = rows[0][0] if rows and rows[0] else None
            if not reads_as_read_only(cell):
                raise ReadOnlySessionError(
                    f"{plan.verify.sql} reported {cell!r} after hardening, which does not "
                    f"mean read-only, so the read was refused ({plan.note})"
                )
    except ReadOnlySessionError:
        _release_read_only(db, plan)
        raise
    except Exception as exc:
        _release_read_only(db, plan)
        raise ReadOnlySessionError(
            f"the session could not be made read-only, so the read was refused: {exc}"
        ) from exc

    db._read_only_depth = 1
    try:
        yield plan
    finally:
        db._read_only_depth = 0
        _release_read_only(db, plan)


def apply_statement_timeout(db: DatabaseConnection, seconds: int | None = None) -> int:
    """Give one session the connection's own statement budget.  Called once, at connect.

    Per-connection and never per-call: DESIGN-MCP-TOOLS.md §6.1 and §13 decision 2 put the
    budget on the profile precisely so the model has no lever over how long its own statement
    may tie up someone's production server.  Nothing above this function takes a timeout
    argument, and nothing should grow one.

    Two engines have a real session-level control (`SET statement_timeout` on PostgreSQL,
    `max_execution_time`/`max_statement_time` on MySQL/MariaDB) and two do not, so SQL Server
    and SQLite fall back to whatever the driver offers — see :func:`_apply_driver_timeout`.

    Args:
        db: The freshly opened connection.
        seconds: An override, for a caller that has already resolved the budget.  Defaults to
            :func:`statement_timeout_for` over the connection's own profile.

    Returns:
        The budget in seconds that was applied.

    Raises:
        Exception: Whatever the driver raised.  A server that refuses to set the budget the
            operator configured is not a server d-MCP should carry on talking to, so this is
            left to propagate out of :func:`connect` and close the connection.
    """

    budget = int(seconds) if seconds is not None else statement_timeout_for(db.profile)
    try:
        statements = db.dialect.statement_timeout_statements(budget)
    except DialectNotConfiguredError:
        # MySQL alone cannot name its own timeout variable before the version probe, and
        # connect(probe=False) is a documented way to reach here.  Skipping is right: the
        # budget is an availability control, not an access control, and refusing the
        # connection over it would be a worse failure than not having it.
        logger.warning(
            "No statement timeout was applied to %r: the dialect needs the version probe to "
            "know which variable to set",
            db,
        )
        statements = ()

    for statement in statements:
        _run_session_statement(db, statement)
    _apply_driver_timeout(db, budget)
    return budget


def _apply_driver_timeout(db: DatabaseConnection, seconds: int) -> bool:
    """Set the driver's own query timeout, where the driver has one.  Best effort.

    Client-side and server-side timeouts are not the same promise and the difference is worth
    stating: a server-side `statement_timeout` cancels the statement on the server, whereas
    pyodbc's `Connection.timeout` abandons it on the client and leaves the server free to keep
    running it until it notices nobody is listening.  The client one is what SQL Server leaves
    us, and half a bound is better than none.

    Failure is logged and swallowed.  Unlike the SQL path this reaches into a driver attribute
    whose spelling is a property of the installed package version, and a connection that works
    must not be refused because a private attribute moved.
    """

    driver = db.dialect.driver
    try:
        if driver == "pyodbc":
            db.raw.timeout = seconds
            return True
        if driver == "pymssql":
            # pymssql exposes no timeout on its DB-API Connection; the underlying
            # _mssql connection carries it, and build_dsn() only sets it at connect
            # time when the profile named one, which leaves the default uncovered.
            inner = getattr(db.raw, "_conn", None)
            if inner is not None and hasattr(inner, "query_timeout"):
                inner.query_timeout = seconds
                return True
    except Exception:
        logger.debug("Could not set the driver query timeout on %r", db, exc_info=True)
        return False
    return False


def test_connection(
    profile: Mapping[str, Any],
    password: str | None = None,
    *,
    timeout_s: int | None = None,
) -> ConnectionTestResult:
    """Resolve, connect, health-check, probe — and never raise.

    Every failure comes back as a :class:`ConnectionTestResult` with an
    ``error_kind`` and a sentence, because the caller is a button in a dialog and
    a traceback there is a defect.
    """
    connect_timeout = _connect_timeout(profile, timeout_s)
    started = perf_counter()

    try:
        # A malformed profile is caught before anything is imported or dialled,
        # so the message names the field rather than the driver's confusion.
        engine = canonical_engine(str(profile.get("engine") or ""))
        canonical_driver(engine, str(profile.get("driver") or ""))
    except ValueError as exc:
        return ConnectionTestResult(
            ok=False,
            error=f"This connection profile cannot be used: {exc}",
            error_kind="unknown",
        )

    def attempt() -> DatabaseConnection:
        return connect(profile, password, timeout_s=connect_timeout, probe=True)

    handle: DatabaseConnection | None = None
    executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="dmcp-connect")
    try:
        future = executor.submit(attempt)
        try:
            handle = future.result(timeout=connect_timeout + _WALL_CLOCK_MARGIN_S)
        except FutureTimeout:
            # The driver ignored its own timeout.  The worker thread is left to
            # finish and die on its own — cancelling a blocked socket connect is
            # not something Python can do — but test_connection() still returns.
            executor.shutdown(wait=False, cancel_futures=True)
            return ConnectionTestResult(
                ok=False,
                latency_ms=round((perf_counter() - started) * 1000, 1),
                error=_sentence(
                    TimeoutError("the driver did not answer"),
                    "timeout",
                    profile,
                    connect_timeout,
                ),
                error_kind="timeout",
            )
    except UnknownDriverError as exc:
        return ConnectionTestResult(
            ok=False,
            error=(
                f"This connection profile names a driver SAPÉ d-MCP does not know: {exc}"
            ),
            error_kind="unknown",
        )
    except BaseException as exc:
        kind = classify_error(exc)
        logger.info(
            "Connection test failed for %r: %s (%s)",
            profile.get("display_name"),
            kind,
            type(exc).__name__,
        )
        return ConnectionTestResult(
            ok=False,
            latency_ms=round((perf_counter() - started) * 1000, 1),
            error=_sentence(exc, kind, profile, connect_timeout),
            error_kind=kind,
        )
    else:
        latency = round((perf_counter() - started) * 1000, 1)
        traits = handle.traits
        return ConnectionTestResult(
            ok=True,
            server_version=traits.raw_version if traits else None,
            traits=traits,
            latency_ms=latency,
        )
    finally:
        if handle is not None:
            handle.close()
        executor.shutdown(wait=False)


def statement_timeout_for(profile: Mapping[str, Any]) -> int:
    """The connection's own statement budget, defaulted.

    Read through a function so no caller has to remember that a profile written
    before the column existed has no key for it.
    """
    value = profile.get("statement_timeout_s")
    try:
        seconds = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return DEFAULT_STATEMENT_TIMEOUT_S
    return seconds if seconds > 0 else DEFAULT_STATEMENT_TIMEOUT_S


# ---------------------------------------------------------------------------
# Database enumeration (DESIGN-CONNECTION-SETUP.md §8)
# ---------------------------------------------------------------------------
# The Database field becomes an editable combo box with a "Find databases" button beside
# it; this is what the button calls. §8.5 is explicit that this is a GUI affordance for a
# human who already holds the credential, not a gated MCP tool, so nothing here consults
# permissions.db — but §8.5 also asks for one audit row, because opening a connection to a
# server should be visible in the trail afterwards regardless of who authorised it.

# §8.3: an interactive click, not an analytical query, so the connection's own (possibly
# very generous) statement_timeout_s never applies here — it is always clamped down.
MAX_ENUMERATION_TIMEOUT_S = 10


@dataclass(frozen=True, slots=True)
class DatabaseListResult:
    """What ``list_server_databases`` hands the Connections dialog.

    §8.4's central finding is that the list is *never authoritative*: all three
    server-backed engines answer a permission-restricted account with a short list, not an
    exception, so ``error`` is populated only when every bootstrap candidate itself failed
    to connect or to run the enumeration statement — never merely because the list came
    back short. The dialog is told to keep the combo editable and Save enabled regardless.
    """

    databases: tuple[str, ...]
    system: frozenset[str]
    error: str | None = None
    error_kind: str = ""


# Used only when the dialect's own `bootstrap_database` cannot be read — see
# `_bootstrap_candidates()`. Kept as a documented fallback, not the primary source of
# truth, because `Dialect.bootstrap_database` (DESIGN-CONNECTION-SETUP.md §8.3) is meant to
# be the one place that name lives; this dict exists only so a dialect mid-migration (an
# abstract method not yet implemented on every concrete class) cannot take the enumeration
# button down with it.
_FALLBACK_BOOTSTRAP_DATABASE: dict[str, str] = {
    "mssql": "master",
    "postgresql": "postgres",
    "mysql": "information_schema",
}


def _bootstrap_candidates(profile: Mapping[str, Any], engine: str) -> list[str]:
    """The ordered list of databases to try opening before the target is known (§8.3).

    The value already typed is tried *first*: a contained-database user cannot open the
    dialect's own bootstrap catalogue at all and must be allowed to open its own database
    first. The dialect's `bootstrap_database` supplies the next candidate; PostgreSQL's
    extra psql-convention fallbacks (`template1`, then the login's own name — `datallowconn`
    is true for `template1` by default, `template0` never) are this function's own addition
    on top of that, because the dialect's contract exposes one bootstrap name, not a chain.
    """
    typed = str(profile.get("database") or "").strip()
    candidates = [typed] if typed else []

    try:
        primary = resolve_dialect(profile).bootstrap_database
    except Exception:
        # A malformed profile, or a dialect whose `bootstrap_database` is not implemented
        # yet — either way, the documented default keeps this function useful rather than
        # letting the whole enumeration fail before a single connection was even tried.
        logger.debug(
            "Could not read %r's own bootstrap_database; using the documented default",
            engine,
            exc_info=True,
        )
        primary = _FALLBACK_BOOTSTRAP_DATABASE.get(engine)
    if primary and primary not in candidates:
        candidates.append(primary)

    if engine == "postgresql":
        username = str(profile.get("username") or "").strip()
        for name in ("template1", username):
            if name and name not in candidates:
                candidates.append(name)
    return candidates


def _split_system_rows(rows: list[tuple[Any, ...]]) -> tuple[tuple[str, ...], frozenset[str]]:
    """Split ``list_databases()``'s rows into names and the ones flagged as the engine's own.

    Every concrete ``list_databases()`` returns an ``is_system`` flag as its *last* column
    (the base class's own contract), but this is read defensively — a single-column result
    is still a legal shape, it just carries no per-row flag — so a dialect mid-migration
    cannot take the whole enumeration button down with it.
    """
    names: list[str] = []
    system: set[str] = set()
    for row in rows:
        if not row:
            continue
        name = str(row[0])
        names.append(name)
        if len(row) > 1:
            try:
                if bool(row[-1]):
                    system.add(name)
            except Exception:
                pass
    return tuple(names), frozenset(system)


def _audit_database_enumeration(
    log_store: _AuditSink | None,
    session_id: str | None,
    profile: Mapping[str, Any],
    *,
    ok: bool,
    count: int,
    error: str | None,
) -> None:
    if log_store is None:
        return
    try:
        log_store.log_tool(
            profile.get("id"),
            session_id or "gui",
            "list-databases",
            {"_connection": profile.get("display_name")},
            result=f"{count} database(s)" if ok else None,
            error=error,
            decision="allowed" if ok else "error",
            rows_affected=count if ok else None,
        )
    except Exception:
        logger.debug("Could not audit a database enumeration", exc_info=True)


def list_server_databases(
    profile: Mapping[str, Any],
    password: str | None = None,
    *,
    timeout_s: int = MAX_ENUMERATION_TIMEOUT_S,
    include_system: bool = False,
    log_store: _AuditSink | None = None,
    session_id: str | None = None,
) -> DatabaseListResult:
    """The databases a "Find databases" click may offer, from whichever bootstrap connects.

    §8.3's bootstrap chain: every engine but SQLite needs *some* initial catalogue before
    the user has chosen a target database, so this tries, in order, the value already typed
    (a contained-database user cannot open ``master`` at all and must be allowed to try its
    own database first) and then the engine's own fallback names, stopping at the first
    connection that both opens and runs the enumeration statement. Every attempt is a full
    ``connect(probe=False)`` — the version probe is irrelevant to a database list and the
    round trip is not free — opened read-only and closed in every case.

    Args:
        profile: The connection profile, as typed in the dialog (not yet saved).
        password: The password currently in the dialog's field, for a ``password`` profile.
        timeout_s: Clamped to :data:`MAX_ENUMERATION_TIMEOUT_S` regardless of what is asked
            for or what the profile's own ``statement_timeout_s`` says (§8.3).
        include_system: Whether the dialect's system databases should be included.
        log_store: Where to write the one audit row §8.5 asks for. ``None`` skips it.
        session_id: The GUI session id the audit row is filed under.

    Returns:
        A :class:`DatabaseListResult`. ``error`` is set only when every candidate failed;
        a short (even empty) list with no error is the ordinary shape of a least-privilege
        account and is not a failure (§8.4).
    """
    engine = canonical_engine(str(profile.get("engine") or ""))
    if engine == "sqlite":
        # A SQLite profile has exactly one database, the file itself; the button is
        # hidden for SQLite in the dialog, and this is the same "canonicalised to
        # 'main'" answer the rest of the codebase already gives.
        return DatabaseListResult(databases=("main",), system=frozenset())

    budget = min(max(int(timeout_s), 1), MAX_ENUMERATION_TIMEOUT_S)
    candidates = _bootstrap_candidates(profile, engine)

    last_exc: BaseException | None = None
    for database in candidates:
        bootstrap_profile = dict(profile)
        bootstrap_profile["database"] = database
        try:
            with connection(bootstrap_profile, password, timeout_s=budget, probe=False) as db:
                apply_statement_timeout(db, budget)
                with read_only_session(db):
                    query: Query = db.dialect.list_databases(include_system=include_system)
                    rows = _run_session_statement(db, query)
                names, system = _split_system_rows(rows)
                system = system | frozenset(getattr(type(db.dialect), "SYSTEM_DATABASES", ()))
        except Exception as exc:  # every candidate gets a fair try; only the last matters
            last_exc = exc
            continue
        _audit_database_enumeration(
            log_store, session_id, profile, ok=True, count=len(names), error=None
        )
        return DatabaseListResult(databases=names, system=system)

    if last_exc is None:
        message = "no bootstrap database is known for this engine."
        kind = "unknown"
    else:
        kind = classify_error(last_exc)
        message = _sentence(last_exc, kind, profile, budget)
    _audit_database_enumeration(
        log_store, session_id, profile, ok=False, count=0, error=message
    )
    return DatabaseListResult(databases=(), system=frozenset(), error=message, error_kind=kind)
