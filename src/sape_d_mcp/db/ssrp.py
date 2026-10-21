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

"""The SQL Server Resolution Protocol — one UDP datagram out, hostile bytes back.

SSRP (UDP 1434, the SQL Server Browser) is the only mechanism that finds SQL Server
instances on *other* machines, and the only one that resolves a **dynamic** port — the
56879 that moves at every service restart and that no registry read on this machine can
know.  One datagram out, one datagram back, no authentication, no session.

**This is never an MCP tool, now or later.**  It is a GUI affordance for the human
operator, and it is stated here so that nobody wires it into the catalogue as a
convenience: "identify every SQL Server on this network" is a reconnaissance primitive
the permission engine was never designed to gate.

**Everything a reply contains is untrusted input.**  Anything on the segment can send a
datagram claiming to be a SQL Server; the payload is unauthenticated and trivially forged,
and it ends up in a host name and a port number.  So every field is validated against a
strict character class and **rejected, never repaired** (DESIGN-CONNECTION-SETUP.md §7.8),
because a sanitised name is a name nobody typed:

* a ``ServerName`` carrying a backslash would reconstruct a compound host and defeat the
  whole of §6;
* one carrying a ``;`` could forge extra fields;
* one carrying an ANSI escape or a right-to-left override could misrepresent itself in a
  list widget;
* a 400-character one could push the real entries off the screen.

Which address a datagram came *from* is untrusted too, and is the one thing a sweep can
check for itself: a unicast probe accepts an answer only from the addresses it resolved and
asked, because a reply from anywhere else is a stranger answering a question addressed to
somebody else.  A broadcast cannot make that check and does not pretend to — it asks the
whole link, so every peer that answers is one it asked.

The caller's policy obligations, which this module cannot enforce for itself and which
`discovery.py` and the GUI own (§7.7): a broadcast runs only on an explicit button press,
behind a confirmation asked *every time* with no "don't ask again", and it is audited —
including when the operator declines.  Nothing here is automatic, nothing here retries,
and every wait is bounded by a clock that is set once.
"""

from __future__ import annotations

import logging
import re
import selectors
import socket
import struct
import time
from collections.abc import Sequence
from dataclasses import dataclass
from threading import Event

logger = logging.getLogger(__name__)

__all__ = [
    "BROADCAST_ADDRESS",
    "DEFAULT_TIMEOUT_S",
    "MAX_DATAGRAM_BYTES",
    "MAX_REPLIES",
    "MAX_TIMEOUT_S",
    "SSRP_PORT",
    "SsrpInstance",
    "SsrpResult",
    "instances_on_host",
    "instances_on_local_network",
    "parse_ssrp_response",
    "query_ssrp",
]

#: The SQL Server Browser's well-known port.  d-MCP binds an ephemeral *source* port and
#: never 1434 itself: binding the well-known port would need privileges on some systems and
#: would make this process look like a browser service to everything else on the link.
SSRP_PORT = 1434

#: `CLNT_BCAST_EX`: "every instance on the link, identify yourself".  One byte, no payload.
CLNT_BCAST_EX = b"\x02"
#: `CLNT_UCAST_EX`: the same question asked of one host.  In practice a server answers with
#: every instance it hosts, which is what the unicast probe wants.
CLNT_UCAST_EX = b"\x03"
#: `SVR_RESP`: the first byte of anything worth parsing.  Anything else is not a reply.
SVR_RESP = 0x05

BROADCAST_ADDRESS = "255.255.255.255"

DEFAULT_TIMEOUT_S = 2.0
#: Hard ceiling.  A longer wait does not find more servers; it finds the same servers later,
#: with a dialog that looks hung.
MAX_TIMEOUT_S = 5.0
#: At most this many datagrams are accepted, and at most this many bytes are read from each.
#: Beyond either the result is marked truncated and the loop stops — a flood on the segment
#: must cost a bounded amount of work, not an unbounded list.
MAX_REPLIES = 64
MAX_DATAGRAM_BYTES = 4096

#: Host names only — no backslash, no comma, no colon, no space, no control character and
#: nothing outside ASCII.  Deliberately narrower than DNS allows: this value is destined for
#: a `Server=` field, and the characters left out are exactly the ones that would turn it
#: into something else once it got there.
_SERVER_RE = re.compile(r"^[A-Za-z0-9._\-]{1,63}$")
#: SQL Server's own instance-name rule, near enough: 16 characters, and none of them a
#: delimiter.
_INSTANCE_RE = re.compile(r"^[A-Za-z0-9_$#][A-Za-z0-9_$#\-]{0,15}$")
#: Display only, and never used to decide anything.  Truncated as well as matched, because a
#: version string is shown in a list widget beside names a human is comparing.
_VERSION_RE = re.compile(r"^[0-9]{1,2}(\.[0-9]{1,5}){0,3}$")
_VERSION_MAX = 32


@dataclass(frozen=True, slots=True)
class SsrpInstance:
    """One instance a browser service claimed to host.  A claim, never a finding.

    Frozen, slotted, and carrying only `str`, `int`, `bool` and `None`, because it crosses a
    queued Qt signal from the discovery worker to the dialog — a mutable record handed to
    another thread is a record two owners can disagree about.
    """

    #: The name the peer *advertised*.  Validated, and still only a claim.
    server: str
    instance: str
    #: The TCP port, present only when the instance is actually listening on TCP.  This is
    #: the dynamic port that can be learned no other way.
    port: int | None
    clustered: bool
    #: Display only, and empty when the peer sent something that did not look like a
    #: version.  Never parsed for a feature decision.
    version: str
    #: The address the datagram actually arrived from.  A profile must be built from this
    #: and not from `server`: connecting to the claim rather than to the peer is precisely
    #: how a forged reply redirects a login.
    peer: str

    @property
    def name_matches_peer(self) -> bool:
        """Whether the advertised name resolves back to the address that sent the reply.

        A mismatch is kept and labelled *"reported by <ip>"* rather than dropped: a server
        may legitimately advertise a name that does not resolve from here — a different DNS
        suffix, a machine on another segment — and dropping it would hide a real instance.
        """

        try:
            return self.peer in {
                info[4][0] for info in socket.getaddrinfo(self.server, None, socket.AF_INET)
            }
        except OSError:
            return False


@dataclass(frozen=True, slots=True)
class SsrpResult:
    """What one bounded sweep produced, with the reasons for anything it did not."""

    instances: tuple[SsrpInstance, ...]
    #: Sentences fit to show: "the broadcast could not be sent on this network".  Never a
    #: traceback, and never any part of a datagram.
    notes: tuple[str, ...]
    #: True when the reply cap or the datagram cap stopped the loop early, so the GUI can
    #: say the list is partial instead of implying it is complete.
    truncated: bool
    replies: int
    elapsed_ms: float


def parse_ssrp_response(payload: bytes, *, peer: str) -> tuple[SsrpInstance, ...]:
    """Instances declared by one `SVR_RESP` datagram, invalid records dropped.

    The framing is checked before anything is decoded — the header byte, then the declared
    length against the real one — because a length prefix that disagrees with the datagram
    is the cheapest sign that this is not a browser reply at all, and trusting it is how a
    parser reads past what it was given.

    Args:
        payload: The datagram exactly as received, at most `MAX_DATAGRAM_BYTES`.
        peer: The address it came from, recorded on every record produced.

    Returns:
        Zero or more validated instances.  Zero is an ordinary answer: a datagram whose
        every record fails validation is a datagram from something that is not a SQL Server
        Browser, or from something pretending to be one.

    Raises:
        ValueError: The datagram is not a well-formed `SVR_RESP`.  Callers sweeping a
            network catch this per datagram and carry on; the loop keeps its own deadline,
            so a flood of malformed replies still ends on time.
    """

    if len(payload) > MAX_DATAGRAM_BYTES:
        raise ValueError(
            f"an SSRP datagram of {len(payload)} bytes exceeds the {MAX_DATAGRAM_BYTES}-byte "
            "ceiling"
        )
    if len(payload) < 3 or payload[0] != SVR_RESP:
        raise ValueError("not an SSRP SVR_RESP datagram")
    declared = struct.unpack("<H", payload[1:3])[0]
    body = payload[3 : 3 + declared]
    if len(body) != declared:
        raise ValueError("the SSRP length prefix disagrees with the datagram size")
    try:
        # Strict: SSRP is ASCII, and a byte outside it means this is not a browser reply.
        # Decoding leniently would let a UTF-8 look-alike name reach a list widget.
        text = body.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError("the SSRP payload is not ASCII") from None

    records: list[SsrpInstance] = []
    for chunk in text.split(";;"):
        if not chunk.strip():
            continue
        fields = chunk.split(";")
        pairs: dict[str, str] = {}
        for index in range(0, len(fields) - 1, 2):
            key = fields[index]
            if key:
                # First occurrence wins, so a second `ServerName` later in the record
                # cannot overwrite the one already validated.
                pairs.setdefault(key, fields[index + 1])
        record = _validated_record(pairs, peer=peer)
        if record is not None:
            records.append(record)
    return tuple(records)


def _validated_record(pairs: dict[str, str], *, peer: str) -> SsrpInstance | None:
    """One `key;value` record, or `None` when any field fails its character class.

    Dropped rather than sanitised, and dropped as a whole rather than field by field: a
    record with a plausible name and an implausible port is a record whose remaining fields
    have not earned any trust either — and that holds for a `tcp` value that is not a number
    just as much as for one that is a number outside the range.  Unknown keys — `np`, `via`, `rpc`, `bv` — are ignored
    rather than carried, because d-MCP speaks TCP and a named pipe is not an address it can
    use.
    """

    server = pairs.get("ServerName", "")
    instance = pairs.get("InstanceName", "")
    if not _SERVER_RE.match(server) or not _INSTANCE_RE.match(instance):
        return None

    port: int | None = None
    if "tcp" in pairs:
        # Either the key is absent — a genuinely pipe-only instance, and the only honest way
        # to say "no TCP port" — or it spells a port in 1..65535.  Anything else (`-1`,
        # `+1433`, `0x59f`, `1433.0`, whitespace) is a malformed field and takes the record
        # with it, exactly as an impossible port number does: the two used to differ, which
        # left `port=None` standing for both "not listening on TCP" and "sent something this
        # parser could not read", and a caller cannot tell those apart.
        raw_port = pairs["tcp"]
        if not raw_port.isdigit():
            return None
        candidate = int(raw_port)
        if not 1 <= candidate <= 65535:
            return None
        port = candidate

    version = pairs.get("Version", "")[:_VERSION_MAX]
    if not _VERSION_RE.match(version):
        version = ""

    return SsrpInstance(
        server=server,
        instance=instance,
        port=port,
        clustered=pairs.get("IsClustered", "").casefold() == "yes",
        version=version,
        peer=peer,
    )


def query_ssrp(
    hosts: Sequence[str] = (),
    *,
    broadcast: bool = False,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    max_replies: int = MAX_REPLIES,
    cancel: Event | None = None,
) -> SsrpResult:
    """Ask the named hosts — and optionally the whole link — which instances they host.

    One socket, one deadline for the entire sweep rather than one per host.  UDP has no
    failure signal: a host with no browser service is indistinguishable from a host that is
    not there, so the only bound available is the clock, and it is set once.

    The socket is opened with an ephemeral source port, a receive timeout and — for a
    broadcast — `SO_BROADCAST`, and it is closed in a `finally`.  Nothing here retries,
    because a retry doubles the traffic a corporate network may be logging in exchange for
    an answer that did not come the first time.

    **Replies to a unicast sweep are accepted only from the addresses it asked.**  Each host
    is resolved once, before anything is sent, and a datagram from anywhere else is dropped
    unread and uncounted (`_is_expected_source`).  A sweep that includes a broadcast has to
    accept every peer that answers, so it applies no such filter — which is why the two
    public entry points never mix the two kinds of probe.

    Args:
        hosts: Hosts to ask directly, by name or as a dotted quad.  A host the user typed is
            a host the user named, which is why a unicast probe needs no confirmation while
            a broadcast does.  Each is resolved to IPv4 once; one that resolves nowhere, or
            only to IPv6, is skipped with a note rather than asked.
        broadcast: Additionally send one datagram to the limited broadcast address.  The
            caller must have obtained the operator's confirmation first, every time, and
            must audit the outcome — this module cannot check that and does not pretend to.
        timeout_s: Clamped to `MAX_TIMEOUT_S`, and to a positive value.
        max_replies: The reply cap; reaching it marks the result truncated.
        cancel: Polled between datagrams so a dialog that is closing stops promptly.
            Cooperative, because the alternative is killing a thread that owns a socket.

    Returns:
        The deduplicated, sorted instances plus the reasons for whatever did not happen.
        **An empty result is not an error and is not evidence of absence**: a firewall, a
        stopped SQL Browser service or a network that does not forward broadcasts all look
        exactly like "nobody is there".
    """

    budget = min(max(float(timeout_s), 0.1), MAX_TIMEOUT_S)
    notes: list[str] = []
    named = [host for host in (_validated_host(h) for h in hosts) if host]
    if len(named) != len(tuple(hosts)):
        notes.append("Some of the hosts given were not usable as addresses and were skipped.")

    # Resolve every named host **once**, before the socket exists, for two reasons.  The
    # datagram has to go somewhere, and the reply has to be checked against the same answer
    # that decided where it went: resolving again at reception time would compare against a
    # second lookup, which a DNS answer that changed in between could make disagree with the
    # first.  See `_resolve_ipv4` and `_is_expected_source` for what "the same answer" means
    # for a name that has several.
    targets: list[str] = []
    accepted: set[str] = set()
    for host in named:
        addresses = _resolve_ipv4(host)
        if not addresses:
            notes.append(f"The host {host} could not be resolved to an IPv4 address.")
            continue
        # One datagram per host, not one per address: several A records are one host, and
        # sending to each would multiply the traffic a corporate network may be logging.
        targets.append(addresses[0])
        accepted.update(addresses)

    if broadcast:
        targets.append(BROADCAST_ADDRESS)
    if not targets:
        return SsrpResult((), tuple(notes) or ("No host was given to ask.",), False, 0, 0.0)

    started = time.monotonic()
    deadline = started + budget
    found: dict[tuple[str, str, int | None], SsrpInstance] = {}
    replies = 0
    truncated = False

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        if broadcast:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # An ephemeral source port, explicitly: never 1434.
        sock.bind(("", 0))

        for host in targets:
            request = CLNT_BCAST_EX if host == BROADCAST_ADDRESS else CLNT_UCAST_EX
            try:
                sock.sendto(request, (host, SSRP_PORT))
            except OSError as exc:
                notes.append(
                    f"The SQL Server Browser request to {host} could not be sent "
                    f"({exc.strerror or exc})."
                )
                logger.debug("SSRP send to %s failed", host, exc_info=True)

        selector = selectors.DefaultSelector()
        selector.register(sock, selectors.EVENT_READ)
        try:
            while True:
                if cancel is not None and cancel.is_set():
                    notes.append("The search was cancelled.")
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                if not selector.select(min(remaining, 0.25)):
                    continue
                try:
                    # Read at most the ceiling: a hostile 64 KB datagram costs one bounded
                    # read and is then dropped, rather than one allocation the sender chose.
                    payload, address = sock.recvfrom(MAX_DATAGRAM_BYTES)
                except OSError:
                    continue
                if not _is_expected_source(address, accepted=accepted, broadcast=broadcast):
                    # Not counted as a reply: it is not one.  Counting it would let anything
                    # on the segment spend this sweep's budget of 64 datagrams for it.
                    logger.debug("Ignoring an SSRP datagram from an unasked source %s", address)
                    continue
                replies += 1
                try:
                    records = parse_ssrp_response(payload, peer=address[0])
                except ValueError as exc:
                    logger.debug("Ignoring a datagram from %s: %s", address[0], exc)
                    records = ()
                for record in records:
                    found[(record.server, record.instance, record.port)] = record
                if replies >= max_replies:
                    truncated = True
                    notes.append(
                        f"More than {max_replies} replies arrived; the list was cut short."
                    )
                    break
        finally:
            selector.close()
    except OSError as exc:
        logger.debug("SSRP sweep failed", exc_info=True)
        notes.append(f"The SQL Server Browser search could not run on this machine ({exc}).")
    finally:
        sock.close()

    instances = tuple(sorted(found.values(), key=lambda i: (i.server.lower(), i.instance.lower())))
    elapsed_ms = (time.monotonic() - started) * 1000.0
    logger.info(
        "SSRP: %s datagram(s) received, %s instance(s) accepted after validation",
        replies,
        len(instances),
    )
    return SsrpResult(instances, tuple(notes), truncated, replies, elapsed_ms)


def instances_on_host(
    host: str, *, timeout_s: float = DEFAULT_TIMEOUT_S, cancel: Event | None = None
) -> SsrpResult:
    """Ask one named host which instances it hosts, and on which ports.

    The dependable half of SSRP, and the one behind the dialog's **Resolve port** button:
    broadcast is best-effort, while a unicast question to a host the user typed either gets
    an answer or does not.

    Unicast, and therefore filtered: only the host asked can answer it.
    """

    return query_ssrp([host], broadcast=False, timeout_s=timeout_s, cancel=cancel)


def instances_on_local_network(
    *, timeout_s: float = DEFAULT_TIMEOUT_S, cancel: Event | None = None
) -> SsrpResult:
    """Broadcast once and collect whatever answers within the deadline.

    The caller must already have the operator's confirmation (§7.7) and must audit the run,
    allowed or refused.  Two limits worth repeating in the GUI: a limited broadcast reaches
    only the link the kernel routes it to, so a machine with several interfaces will miss
    the others, and many networks do not forward it at all — in which case the honest
    outcome is "no replies", with no way to tell blocked from absent.
    """

    return query_ssrp((), broadcast=True, timeout_s=timeout_s, cancel=cancel)


def _resolve_ipv4(host: str) -> tuple[str, ...]:
    """Every IPv4 address a validated host name resolves to, in the resolver's own order.

    IPv4 only, and deliberately: the sweep socket is `AF_INET`, because SSRP as SQL Server
    speaks it is an IPv4 protocol and a link-local broadcast has no IPv6 equivalent.  A host
    that resolves only to IPv6 therefore cannot be asked at all, and is reported as
    unresolvable rather than half-asked — which is also why the source check below never has
    to reason about an IPv4-mapped `::ffff:` form or about comparing addresses across
    families, the two places where a filter of this shape usually leaks.

    A literal dotted quad resolves to itself without a lookup; `_validated_host` has already
    refused anything containing a colon, so no IPv6 literal ever reaches here.

    Returns:
        The addresses, deduplicated and ordered, or an empty tuple when the name does not
        resolve.  Several addresses are one multi-homed or round-robin host, not several
        hosts: all of them are legitimate senders of the answer to the one datagram sent to
        the first, which is why the reply check tests membership of the whole set rather
        than equality with the address that was dialled.
    """

    try:
        infos = socket.getaddrinfo(host, SSRP_PORT, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError:
        logger.debug("SSRP could not resolve %s", host, exc_info=True)
        return ()
    ordered: dict[str, None] = {}
    for info in infos:
        # `getaddrinfo` is typed as returning either shape of sockaddr, so the first
        # element is `str | int` to a type checker even though an AF_INET address is
        # always the dotted quad.  Narrowed rather than cast: the set built here is
        # the one every reply is checked against, and an entry of the wrong type
        # would compare unequal to every address and silently drop good answers.
        address = info[4][0]
        if not isinstance(address, str):  # pragma: no cover - AF_INET says otherwise
            continue
        ordered.setdefault(address, None)
    return tuple(ordered)


def _is_expected_source(address: tuple[str, int], *, accepted: set[str], broadcast: bool) -> bool:
    """Whether a datagram came from somewhere this sweep actually asked.

    A unicast probe knows exactly which address it asked, so a reply from any other address
    is a forgery or a mistake and is dropped: without this, anything able to put a datagram
    on the wire could answer a question it was never asked, and the record it carries — a
    host name and a TCP port — is the record a connection profile is then built from.

    A broadcast is the opposite by nature: it asks the whole link and cannot know in advance
    which peers will answer, so **no source filter is applied to a sweep that includes a
    broadcast**, not even to the unicast targets in the same sweep, because one socket
    receives both and a datagram carries nothing that says which probe it answers.  The
    module's two entry points keep those apart — `instances_on_host` is unicast only and
    `instances_on_local_network` is broadcast only — and a caller mixing them in one
    `query_ssrp` call is choosing the broadcast's trust level for the whole sweep.  Note
    that this branch is the one no test in a single-host environment can exercise: "many
    peers answer a broadcast" and multi-interface behaviour are reasoned about, not measured.

    The source *port* is checked too, for a unicast sweep: the SQL Server Browser answers
    from UDP 1434, so a datagram from an arbitrary port on the right host is some other
    process there.  It is a consistency check and not a boundary — anything able to forge a
    source address can forge a source port — but it costs one comparison.
    """

    if broadcast:
        return True
    return bool(address) and address[0] in accepted and address[1] == SSRP_PORT


def _validated_host(host: object) -> str | None:
    """A host string fit to hand to `sendto`, or `None`.

    The same discipline as the reply parser, in the other direction: a target may arrive
    from a discovery record or from a text field, and a value carrying whitespace, a NUL or
    a port suffix is refused rather than trimmed into something the user did not write.
    """

    if not isinstance(host, str):
        return None
    text = host.strip()
    if not text or len(text) > 253:
        return None
    if any(ch.isspace() or ord(ch) < 0x20 or ord(ch) > 0x7E for ch in text):
        return None
    if not re.match(r"^[A-Za-z0-9._\-]{1,253}$", text):
        return None
    return text
