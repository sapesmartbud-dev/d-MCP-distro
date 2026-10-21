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

"""How a connection proves who it is — the closed ``auth_mode`` domain and the support matrix.

Three modes, and no fourth (``DESIGN-CONNECTION-SETUP.md`` §3.1):

``password``
    d-MCP presents a user name and a secret it holds in the credential store.
``integrated``
    The operating system supplies the identity — SSPI, Kerberos/GSSAPI, or PostgreSQL
    ``peer``.  d-MCP presents no name and no secret, so ``username`` is NULL and no
    keyring entry may exist.
``none``
    There is no authentication step at all.  SQLite only: the access control is the
    file's own permissions.

PostgreSQL's ``trust`` method is modelled as ``integrated`` rather than as ``none``,
because from this application's side the two are one behaviour — nothing is sent — and a
domain with two values meaning the same thing is a domain that gets chosen from wrongly.

**Support is data, not branching.**  :data:`INTEGRATED_SUPPORT` states, per
``(engine, driver)`` pair, whether system authentication is possible, on which platforms,
by which mechanism, and — when it is not — the one sentence that explains why.  The GUI
greys out the combo item with that sentence as its tooltip and ``ConnectionStore._validate()``
raises with the same sentence, so the message a user meets when the control is disabled and
the message they meet if they save the profile from a script are the same string.

Two "no" answers are worth reading before they are changed:

* **pymssql cannot make a trusted connection, on any platform.**  FreeTDS can perform NTLM
  with an explicit ``DOMAIN\\user`` *and a password* — which is password authentication with
  a domain-qualified name, not integrated authentication.  It has no SSPI path, and its
  GSSAPI support is a build-time option absent from the published wheels.  Left unblocked
  the attempt fails with DB-Lib **20009**, *"Adaptive Server is unavailable or does not
  exist"* — a transport error that sends the user hunting a firewall problem that is not
  there.  That is the failure this module exists to make unrepresentable.
* **MySQL and MariaDB have no mode d-MCP can use.**  ``auth_socket`` requires a Unix domain
  socket *and* an account name equal to the OS account name, and the tagged union reserves
  ``host IS NULL`` for SQLite so a socket path has no column to live in;
  ``authentication_windows`` ships only with MySQL Enterprise.

This module imports no driver and no dialect, so it stays importable on a machine where
nothing at all is installed — which is exactly the machine whose GUI most needs to explain
why an option is unavailable.
"""

from __future__ import annotations

import logging
import platform
from dataclasses import dataclass, replace

logger = logging.getLogger(__name__)

__all__ = [
    "AUTH_MODES",
    "INTEGRATED_SUPPORT",
    "MESSAGES",
    "AuthSupport",
    "allowed_auth_modes",
    "canonical_auth_mode",
    "default_auth_mode",
    "message_for",
    "support_for",
]

#: The closed domain, and the single source of truth for it.  This tuple renders the
#: ``ck_connections_auth_mode`` CHECK, drives ``_validate()``, fills the GUI's combo box and
#: parametrises the tests — exactly as ``ACTIONS`` does in ``permissions.py``.  Adding a
#: mode is one edit here, and the constraint cannot drift from the validator.
AUTH_MODES: tuple[str, ...] = ("password", "integrated", "none")

#: The engine whose only legal mode is ``none``.  Restated rather than imported from
#: ``connection_store`` so this module keeps no dependency of its own; a conformance test
#: asserts the two agree.
_FILE_ENGINE = "sqlite"

#: ``platform.system()`` spellings.  Nothing here calls it at import time: a support entry
#: is a fact about a driver, and the *current* platform is an argument to
#: :func:`support_for`, so the matrix can be rendered for another machine in a test.
_PLATFORMS: frozenset[str] = frozenset({"Windows", "Linux", "Darwin"})


@dataclass(frozen=True, slots=True)
class AuthSupport:
    """Whether one ``(engine, driver)`` pair can authenticate through the operating system.

    Frozen and slotted because instances cross a Qt signal into the dialog, and a mutable
    record handed to another thread is a record two owners can disagree about.
    """

    #: True only where a trusted/GSSAPI/peer connection genuinely works.  Never a guess.
    supported: bool
    #: ``platform.system()`` values on which it works.  Empty when it works nowhere.
    platforms: frozenset[str]
    #: ``'sspi' | 'kerberos' | 'peer' | 'filesystem' | ''`` — what actually carries the
    #: identity, for the note the dialog shows.
    mechanism: str
    #: True when the user must arrange something d-MCP does not manage: a Kerberos ticket,
    #: a ``krb5.conf``, a ``pg_hba.conf`` entry.  Drives a note, never a block.
    needs_setup: bool
    #: i18n key.  Why it is blocked, or what it needs.  Rendered by the GUI through the
    #: generated catalogue and by the store through :data:`MESSAGES`, so both say the same
    #: sentence.
    message_key: str


#: English text for every key in the matrix.  The GUI translates the key through its
#: generated catalogue; ``connection_store`` cannot — it must never import ``gui`` — so it
#: renders these, and they are therefore the authoritative wording the catalogue is
#: generated from rather than a second, drifting copy.
MESSAGES: dict[str, str] = {
    "connections.auth_integrated_mssql_pyodbc": (
        "This connection will authenticate with your Windows account. d-MCP sends no user "
        "name and no password: the ODBC driver presents the token of the process it runs in."
    ),
    "connections.auth_integrated_mssql_pyodbc_kerberos": (
        "System authentication on Linux and macOS uses Kerberos. You need a valid ticket — "
        "run kinit — and a krb5.conf that names your realm, and the server must be "
        "registered with an SPN. Without one the server reports a login failure for the user "
        "NT AUTHORITY\\ANONYMOUS LOGON."
    ),
    "connections.auth_integrated_unsupported_pymssql": (
        "The pymssql driver cannot use Windows (trusted) authentication — FreeTDS has no way "
        "to present your Windows account to the server, and the attempt fails with error "
        "20009, which looks like a network problem but is not one. Choose the pyodbc driver "
        "for system authentication, or keep pymssql and sign in with a SQL Server user name "
        "and password."
    ),
    "connections.auth_integrated_postgresql_psycopg": (
        "d-MCP will send no user name, so libpq falls back to PGUSER and then to your "
        "operating-system account, and the server's pg_hba.conf decides the method. It works "
        "with peer over a Unix socket — put the socket directory in Host — and with gss or "
        "sspi over TCP, given a ticket or a domain-joined machine."
    ),
    "connections.auth_integrated_unsupported_mysql": (
        "MySQL and MariaDB have no system-authentication mode d-MCP can use. The auth_socket "
        "plugin works only over a local Unix socket, and the Windows plugin ships only with "
        "MySQL Enterprise. Use a user name and password."
    ),
    "connections.auth_sqlite_no_authentication": (
        "A SQLite database is a file. Access is controlled by the file's own permissions, so "
        "there is no user name and no password."
    ),
    "connections.auth_integrated_unsupported_platform": (
        "System authentication is not available for this driver on this operating system. "
        "Use a user name and password."
    ),
}


#: Keyed ``(engine, driver)``, and a conformance test requires one entry for every pair in
#: ``DRIVERS_BY_ENGINE``.  A fifth driver therefore cannot be added without an explicit
#: ruling on whether it supports system authentication, and the default is never
#: "yes, probably".
#:
#: The entries hold the *platform-independent* fact.  :func:`support_for` refines them for
#: one machine — which is where pyodbc's "no setup on Windows, a Kerberos ticket everywhere
#: else" lives, because it is a property of the platform and not of the driver.
INTEGRATED_SUPPORT: dict[tuple[str, str], AuthSupport] = {
    ("mssql", "pyodbc"): AuthSupport(
        supported=True,
        platforms=_PLATFORMS,
        mechanism="sspi",
        needs_setup=False,
        message_key="connections.auth_integrated_mssql_pyodbc",
    ),
    ("mssql", "pymssql"): AuthSupport(
        supported=False,
        platforms=frozenset(),
        mechanism="",
        needs_setup=False,
        message_key="connections.auth_integrated_unsupported_pymssql",
    ),
    ("postgresql", "psycopg"): AuthSupport(
        supported=True,
        platforms=_PLATFORMS,
        # 'peer' over a Unix socket, SSPI or GSSAPI over TCP.  One mechanism name is
        # recorded because the profile cannot tell which will apply: pg_hba.conf decides,
        # server-side, per connection.
        mechanism="peer",
        needs_setup=True,
        message_key="connections.auth_integrated_postgresql_psycopg",
    ),
    ("mysql", "pymysql"): AuthSupport(
        supported=False,
        platforms=frozenset(),
        mechanism="",
        needs_setup=False,
        message_key="connections.auth_integrated_unsupported_mysql",
    ),
    ("mysql", "mysql-connector-python"): AuthSupport(
        supported=False,
        platforms=frozenset(),
        mechanism="",
        needs_setup=False,
        message_key="connections.auth_integrated_unsupported_mysql",
    ),
    ("sqlite", "sqlite3"): AuthSupport(
        # Not "unsupported" in the sense the other two "no" rows are: a SQLite profile is
        # pinned to auth_mode 'none', so integrated authentication is not refused, it is
        # inapplicable.  The GUI hides the Authentication row entirely rather than showing
        # a single-valued control, and shows this sentence where the credential fields sat.
        supported=False,
        platforms=frozenset(),
        mechanism="filesystem",
        needs_setup=False,
        message_key="connections.auth_sqlite_no_authentication",
    ),
}


def support_for(engine: str, driver: str, *, system: str | None = None) -> AuthSupport:
    """The matrix entry for one pair, refined for one operating system.

    ``system`` defaults to :func:`platform.system` and is an argument rather than a lookup
    so a test can ask what a Windows machine would be told without being one — which is the
    only way the Windows half of this matrix is exercised at all on the development VM.

    Raises:
        ValueError: for a pair the matrix does not cover.  Refusing to answer is the point:
            an unknown pair must not default to "supported", and it must not default to
            "unsupported" either, because that would let a real driver be added silently and
            then quietly fail to offer a mode it has.
    """

    key = (str(engine).strip().lower(), str(driver).strip().lower())
    entry = INTEGRATED_SUPPORT.get(key)
    if entry is None:
        raise ValueError(
            f"no system-authentication ruling exists for engine {engine!r} with driver "
            f"{driver!r}. Add an INTEGRATED_SUPPORT entry saying yes or no, with a reason."
        )
    if not entry.supported:
        return entry

    current = system if system is not None else platform.system()
    if current not in entry.platforms:
        return replace(
            entry,
            supported=False,
            message_key="connections.auth_integrated_unsupported_platform",
        )
    if key == ("mssql", "pyodbc") and current != "Windows":
        # Windows borrows the process token and needs nothing arranged.  Everywhere else
        # msodbcsql18 goes through GSSAPI, which needs a ticket, a krb5.conf and an SPN —
        # none of which d-MCP manages.  It is offered with a note rather than blocked,
        # because it genuinely works and blocking it would be paternalistic.
        return replace(
            entry,
            mechanism="kerberos",
            needs_setup=True,
            message_key="connections.auth_integrated_mssql_pyodbc_kerberos",
        )
    return entry


def message_for(support: AuthSupport) -> str:
    """The English sentence behind an entry's ``message_key``.

    The GUI does not call this — it translates the key through the generated catalogue.
    ``connection_store`` does, because a ``ValueError`` it raises has to carry words, and it
    must never import the GUI.
    """

    return MESSAGES.get(
        support.message_key,
        f"system authentication is not available here ({support.message_key}).",
    )


def default_auth_mode(engine: str) -> str:
    """``'none'`` for SQLite, ``'password'`` everywhere else.

    The shipped behaviour, restated as a function so an omitted ``auth_mode`` means the same
    thing in the store, in the dialog and in a test.
    """

    return "none" if str(engine).strip().lower() == _FILE_ENGINE else "password"


def canonical_auth_mode(value: object) -> str:
    """Map an ``auth_mode`` spelling to the one canonical form, or raise.

    No aliases: unlike engines and drivers, this domain was born with one spelling per
    value, and inventing synonyms for it now would create the drift the tuple exists to
    prevent.
    """

    if not isinstance(value, str):
        raise ValueError(f"auth_mode must be a string, got {type(value).__name__}")
    mode = value.strip().lower()
    if mode not in AUTH_MODES:
        raise ValueError(
            f"unknown auth_mode {value!r}; expected one of {', '.join(AUTH_MODES)}"
        )
    return mode


def allowed_auth_modes(
    engine: str, driver: str, *, system: str | None = None
) -> tuple[str, ...]:
    """The modes a given pair may legally hold on a given platform.

    The GUI builds its combo from :data:`AUTH_MODES` in full and disables what is not in
    this tuple — an option that is hidden is one the user searches for, an option that is
    present and greyed with a reason is one they understand.
    """

    engine_key = str(engine).strip().lower()
    if engine_key == _FILE_ENGINE:
        return ("none",)
    modes = ["password"]
    if support_for(engine_key, driver, system=system).supported:
        modes.append("integrated")
    return tuple(modes)
