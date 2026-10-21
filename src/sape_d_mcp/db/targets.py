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

"""Parsing and resolving an MS-SQL server target — the direct fix for `PC-ARR\\SQLEXPRESS:56879`.

A leaf module: no import of `connection_store`, no dialect import, no driver import, so it
stays usable on a machine with nothing installed at all and `connection_store.py` may call it
while keeping its own stated property of working with no driver present.

``parse_mssql_target()`` accepts every way people actually type a SQL Server address and either
parses it into a server, an instance name and a port, or raises ``ValueError`` naming exactly
what was wrong. **It never repairs.** A host string that carries an instance, a port, both, or
neither is legal input; a host string that is ambiguous — two backslashes, a comma *and* a
colon, an unsupported protocol prefix, a LocalDB pipe name — is refused rather than guessed at,
the same fail-closed instinct as `permissions.rule_for()` refusing a non-absolute path.

``resolve_mssql_target()`` reads the already-validated *columns* of a stored profile
(``host``, ``port``, ``instance``) and applies the one precedence rule DESIGN-CONNECTION-SETUP.md
§3.3 documents: where a port is present, the port is used to reach the server and the instance
name is not — that is what ODBC does for ``Server=HOST\\INSTANCE,PORT``, so `pyodbc` needs no
help, and this function is what makes `pymssql` behave the same way instead of leaving FreeTDS
to guess.  Both MS-SQL dialect branches call this one function so they cannot diverge.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

__all__ = [
    "MsSqlTarget",
    "parse_mssql_target",
    "reconcile_mssql_profile",
    "resolve_mssql_target",
]

# Only 'tcp:' is accepted and stripped; the other three are recognised only so the error
# names the actual reason instead of failing later as a mangled server name.  d-MCP speaks
# TCP to every driver it ships, so silently accepting 'np:' (named pipes) or 'lpc:' (shared
# memory) would connect somewhere the user did not ask for, and 'admin:' is the dedicated
# admin connection, which neither pyodbc nor pymssql is configured to use here.
_TCP_PREFIX = "tcp:"
_REJECTED_PREFIXES: tuple[str, ...] = ("np:", "lpc:", "admin:")

# SQL Server instance names: DESIGN-CONNECTION-SETUP.md §3.6.  Far more permissive than what
# Microsoft actually allows (16 characters, no leading digit) — the regex exists to keep a
# delimiter (a backslash, a comma, a colon) out of the string that is about to be concatenated
# into a DSN, not to second-guess Microsoft's own naming rules.
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_$#][A-Za-z0-9_$#\-]{0,127}$")

# A bare server name or IP literal, outside brackets.
_SERVER_RE = re.compile(r"^[A-Za-z0-9._\-]{1,253}$")

# Inside a bracketed IPv6 literal: hex groups, dots (an IPv4-mapped tail), '%' plus a zone id.
_IPV6_BODY_RE = re.compile(r"^[0-9A-Fa-f:.]+(%[A-Za-z0-9._\-]+)?$")

_LOCALDB_PREFIX = "(localdb)"
_LOCAL_ALIASES = frozenset({".", "(local)"})


@dataclass(frozen=True, slots=True)
class MsSqlTarget:
    """A parsed or resolved MS-SQL address: a server, an optional instance and an optional port.

    ``compound`` is ``True`` whenever the input carried more than a bare server name — that is
    the flag the Connections page's ``needs_review()`` and the GUI's "Split it for me" affordance
    key off, and it is ``False`` for a target built by :func:`resolve_mssql_target`, whose input
    is already the split columns rather than free text.
    """

    server: str
    instance: str | None
    port: int | None
    compound: bool


def _strip_protocol_prefix(text: str) -> str:
    lowered = text.lower()
    if lowered.startswith(_TCP_PREFIX):
        return text[len(_TCP_PREFIX) :]
    for prefix in _REJECTED_PREFIXES:
        if lowered.startswith(prefix):
            raise ValueError(
                f"the host {text!r} names the {prefix.rstrip(':')!r} protocol, which SAPÉ "
                "d-MCP does not speak — it always connects over TCP. Remove the prefix, or "
                "give a TCP address."
            )
    return text


def _split_port(remainder: str) -> tuple[str, str | None]:
    """Split ``remainder`` on the one port separator it carries, if any.

    Rule 4 of §6.1: a comma *and* a colon both appearing is an error, never a guess at which
    one was meant.
    """

    has_comma = "," in remainder
    has_colon = ":" in remainder
    if has_comma and has_colon:
        raise ValueError(
            f"{remainder!r} carries both a comma and a colon; give the port with only one of "
            "them."
        )
    if has_comma:
        name_part, port_text = remainder.split(",", 1)
        return name_part, port_text
    if has_colon:
        name_part, port_text = remainder.split(":", 1)
        return name_part, port_text
    return remainder, None


def _parse_port(port_text: str, *, original: str) -> int:
    if not port_text.isdigit():
        raise ValueError(f"{original!r} names a port that is not a whole number: {port_text!r}.")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise ValueError(f"{original!r} names a port out of range (1-65535): {port}.")
    return port


def _parse_bracketed_ipv6(text: str) -> MsSqlTarget:
    """Rule 2 of §6.1: brackets are parsed before anything is split on a colon.

    Doing this first is the whole reason IPv6 works at all — `[::1]:1433` would otherwise be
    split on its first colon and destroyed.
    """

    close = text.find("]")
    if close < 0:
        raise ValueError(f"{text!r} has an opening '[' with no matching ']'.")
    body = text[1:close]
    if not _IPV6_BODY_RE.match(body):
        raise ValueError(f"{text!r} does not hold a valid bracketed IPv6 literal.")
    server = text[: close + 1]
    remainder = text[close + 1 :]

    port: int | None = None
    if remainder:
        if remainder[0] not in ",:":
            raise ValueError(
                f"{text!r} has trailing text after the bracketed address that is neither a "
                "port introducer (',' or ':') nor empty."
            )
        _, port_text = _split_port(remainder)
        if port_text is None:
            # remainder[0] was ',' or ':' but _split_port only recognises a separator inside
            # its own argument — reconstruct so the same digit check applies below.
            port_text = remainder[1:]
        port = _parse_port(port_text, original=text)

    return MsSqlTarget(server=server, instance=None, port=port, compound=port is not None)


def parse_mssql_target(raw: str) -> MsSqlTarget:
    """Parse a user-typed MS-SQL host string.  Parses or raises; never repairs.

    Args:
        raw: Exactly what someone typed into a Host field, or what a v1 profile's ``host``
            column already holds (DESIGN-CONNECTION-SETUP.md §3.5 migrates it verbatim).

    Returns:
        The server, instance and port that string names.

    Raises:
        ValueError: The string is empty after stripping, carries an unsupported protocol
            prefix, two backslashes, both a comma and a colon, a `LocalDB` pipe name, an
            unterminated `[`, an out-of-range port, or a server/instance that does not match
            the allowed character class.
    """

    if not isinstance(raw, str):
        raise ValueError(f"a host must be a string, got {type(raw).__name__}.")

    text = raw.strip()
    text = _strip_protocol_prefix(text)

    if text.startswith("["):
        return _parse_bracketed_ipv6(text)

    if text.count("\\") > 1:
        raise ValueError(
            f"the host {raw!r} carries two backslashes; give one server and one instance "
            "name, e.g. 'HOST\\INSTANCE'."
        )

    if "\\" in text:
        server_part, instance_raw = text.split("\\", 1)
    else:
        server_part, instance_raw = text, None

    if instance_raw is not None:
        instance_name, port_text = _split_port(instance_raw)
        server_value = server_part
    else:
        server_value, port_text = _split_port(server_part)
        instance_name = None

    if server_value.strip().lower() == _LOCALDB_PREFIX:
        raise ValueError(
            f"the host {raw!r} names a LocalDB instance. LocalDB is a named-pipe-only, "
            "per-user instance that neither pyodbc nor pymssql reaches over TCP; install a "
            "regular SQL Server instance, or connect to it from a tool that speaks named "
            "pipes."
        )

    port: int | None = None
    if port_text is not None:
        port = _parse_port(port_text, original=raw)

    if server_value.lower() in _LOCAL_ALIASES or server_value == "":
        server_value = "localhost"

    if not _SERVER_RE.match(server_value):
        raise ValueError(
            f"the host {raw!r} names a server ({server_value!r}) that is not a plain host "
            "name or IP address."
        )

    instance: str | None = None
    if instance_name is not None:
        instance = instance_name.strip()
        if not _INSTANCE_RE.match(instance):
            raise ValueError(
                f"the host {raw!r} names an instance ({instance_name!r}) that is not a "
                "valid SQL Server instance name."
            )

    compound = instance is not None or port is not None
    return MsSqlTarget(server=server_value, instance=instance, port=port, compound=compound)


def resolve_mssql_target(profile: Mapping[str, Any]) -> MsSqlTarget:
    """The already-split ``host``/``port``/``instance`` columns, with the port-wins precedence.

    This is the *only* place that precedence lives (DESIGN-CONNECTION-SETUP.md §3.3, §6.2), so
    that `pyodbc` and `pymssql` cannot come to disagree about which one is used to reach the
    server. It does not re-parse ``host`` — a stored profile's ``host`` is already a bare
    server name, by construction of ``connection_store._validate()`` — so a compound value
    reaching here is a defect in the caller, not something to be silently split.

    Args:
        profile: A connection profile mapping with ``host``, ``port`` and ``instance`` keys —
            or anything that behaves like one, so a dialect's own DSN builder can pass a plain
            ``dict`` while testing.

    Returns:
        The target to dial.  ``target.port is not None`` is the caller's cue to build the
        ``host,port`` form; otherwise ``target.instance`` (if any) is the ``host\\instance``
        form, per the §6.3 table.

    Raises:
        ValueError: ``host`` is missing or blank.
    """

    host = str(profile.get("host") or "").strip()
    if not host:
        raise ValueError("resolve_mssql_target() needs a non-blank host.")

    raw_port = profile.get("port")
    port: int | None = None
    if raw_port not in (None, ""):
        port = int(raw_port)

    raw_instance = profile.get("instance")
    instance: str | None = None
    if raw_instance not in (None, ""):
        instance = str(raw_instance).strip() or None

    # `compound=False`: the columns are already split, so this target does not itself carry
    # the "needs review" signal that a raw, unparsed string would.
    return MsSqlTarget(server=host, instance=instance, port=port, compound=False)


def reconcile_mssql_profile(profile: Mapping[str, Any]) -> MsSqlTarget:
    """Absorb a compound ``host`` into the instance and port columns, then resolve.

    ``host`` reaching here as ``10.129.203.19\\NRP`` beside ``port = 1435`` is the shape an
    environment file has always used, and refusing it made a working address unusable in the
    dialog. The user's D6 ruling — split automatically rather than flag and wait — is applied
    here to typed input as the migration already applies it to stored rows.

    A value carried in the host and a value already in its own column that *disagree* are not
    reconciled: that is an ambiguity with no documented precedence, and the person who typed
    both is on screen to resolve it.

    Raises:
        ValueError: ``host`` is blank or unparseable, or it names an instance or a port that
            contradicts the corresponding column.
    """

    host = str(profile.get("host") or "").strip()
    if not host:
        raise ValueError("an MS-SQL connection needs a non-blank host.")

    parsed = parse_mssql_target(host)

    raw_instance = profile.get("instance")
    column_instance = str(raw_instance).strip() if raw_instance not in (None, "") else None
    if parsed.instance and column_instance and parsed.instance.casefold() != column_instance.casefold():
        raise ValueError(
            f"the host {host!r} names the instance {parsed.instance!r} while the Instance "
            f"field holds {column_instance!r}. Clear one of the two."
        )

    raw_port = profile.get("port")
    column_port = int(raw_port) if raw_port not in (None, "") else None
    if parsed.port is not None and column_port is not None and parsed.port != column_port:
        raise ValueError(
            f"the host {host!r} names port {parsed.port} while the Port field holds "
            f"{column_port}. Clear one of the two."
        )

    return MsSqlTarget(
        server=parsed.server,
        instance=column_instance or parsed.instance,
        port=column_port if column_port is not None else parsed.port,
        compound=False,
    )
