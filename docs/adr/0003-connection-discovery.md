# ADR 0003 — Server discovery: local by default, the local network only when asked

- **Status:** accepted and implemented; the user's rulings are recorded in `DESIGN-CONNECTION-SETUP.md` §13
- **Implemented by:** `src/sape_d_mcp/db/discovery.py` (new),
  `src/sape_d_mcp/gui/dialogs/discovery_dialog.py` (new)
- **Detail:** `docs/DESIGN-CONNECTION-SETUP.md` §7

## Context

Every field of the connection form is free text, so configuring a connection requires knowing a
host, a port and a database name before starting. Most of that is already discoverable on the
machine itself without a credential and without a packet: a local SQL Server registers its
instances and their TCP ports in the Windows registry, a PostgreSQL is listening on loopback, an
ODBC DSN has already been configured, a SQLite database is a file.

The user asked for auto-detection covering **local and the local network**. Those two halves are
not the same kind of act. Reading `HKLM` is a local read. Broadcasting to the LAN is emitting
traffic, to hosts that did not ask, on a network the application does not own, from a desktop
application that a corporate security team has no reason to expect it from.

## Decision

**1. Discovery is a pure, synchronous, Qt-free module** at `src/sape_d_mcp/db/discovery.py`
returning frozen `Candidate` records. It never connects to a database, never authenticates, never
reads a credential, and no `Candidate` field can hold one. A test asserts that.

**2. Every candidate states its provenance, and an accepted TCP connection is a candidate rather
than a finding.** `origin` (`windows-registry`, `windows-service`, `odbc-dsn`, `listening-port`,
`sqlite-file`, `sql-browser`) plus a human `origin_detail`, so the GUI can distinguish *"found in
the Windows registry"* from *"something answered on 127.0.0.1:5432"*.

This is the point on which the whole feature's vocabulary rests, and the implementation research
made it concrete rather than theoretical: **through NAT, or through any intermediary that proxies
— a container port-forward, a VPN concentrator, an SSH tunnel, a load balancer, a transparent
corporate proxy — a successful `connect()` does not prove the port is reachable.** The
intermediary accepts the connection and the server behind it is never consulted. This was
observed against a real SQL Server during the design's own research: the TCP connection was
accepted and a protocol exchange over it returned nothing at all.

**Only the protocol's own greeting confirms**, and d-MCP deliberately does not send one (see the
rejected alternatives below). So a `listening-port` candidate is a socket that accepted a
connection and *nothing more*; its engine is inferred **from the port number alone**; and the
label carries that honestly — *"Something answered on 127.0.0.1:5432 — probably PostgreSQL, but
not verified (d-MCP sends no protocol handshake during discovery)"* — rather than asserting an
engine that was never verified. The only thing in the product entitled to say a server is really
there is the connection test, which completes a real handshake with a credential the human
supplied.

**3. Local discovery runs on demand, and needs no network at all.** Windows registry through
stdlib `winreg` (`KEY_READ`, both registry views); services from the registry, never a subprocess
and never `psutil`; TCP probes on **loopback only**; ODBC DSNs with a four-key allowlist that does
not read `PWD`; SQLite files identified by their 16-byte header, under bounded roots, with no SQL
ever executed against a discovered file.

**4. The SQL Server Browser broadcast is a separate, explicit, confirmed and audited action.**
Never on dialog open, never on a timer, never as a fallback when local discovery finds nothing. It
requires a button press and then a confirmation stating what will be sent, that no credential is
included, and that some networks log or block it — asked **once per session, and never persisted**
(§13 D5: the user relaxed this ADR's original "every time" to once per run, on the argument that a
paragraph re-shown on every click is a paragraph people learn to dismiss unread). The acceptance
lives on one attribute of the running application and dies with the process; `config.json` never
learns of it and there is no "don't ask again" checkbox, because that phrase means *persisted* and
persisting it is exactly what was refused. The confirmation broker's rule that no approval
survives a restart therefore stands verbatim. One `0x02`
datagram to port 1434, a 2-second default timeout hard-capped at 5, at most 64 replies of at most
4096 bytes, an ephemeral source port. One row lands in `audit.db` — and a *refused* confirmation
lands there too, because "the operator was asked and declined" is worth more than silence.

**5. Everything a broadcast returns is untrusted input.** An SSRP reply is an unauthenticated
datagram from an unauthenticated source. Server names, instance names and ports are validated
against strict character classes and **rejected, never repaired**; version strings are truncated
and used for display only; replies are deduplicated and capped. Those candidates are marked
`confidence='reported'`, shown in a separate section headed *"Reported by the network — not
verified"*, and selecting one **pre-fills the form for review — it never saves and never
connects.** A human presses Save.

**6. No LAN port sweeping, ever.** The single Browser datagram is the only thing d-MCP sends to an
address the user did not name. Probing a host the user has already typed is offered, because that
host was named.

**7. Discovery is never an MCP tool.** Stated in the module docstring so nobody wires it into the
catalogue as a convenience. Exposing "enumerate the databases on this network" to a model hands it
a reconnaissance primitive the permission engine was not designed to gate — the permission model
covers what a model may do *to a configured connection*, not what it may find.

**8. The GUI threading contract is specified here, not improvised.** One `QThread` worker at a
time, cooperative cancellation through a `threading.Event` polled between sources,
`closeEvent`/`reject` cancelling and waiting, never `terminate()`, frozen slotted dataclasses over
queued signals, and the confirmation raised on the GUI thread before the worker exists.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| Scan the local subnet for open 1433/5432/3306 | A port scan from a desktop application is a security incident on most corporate networks, and it is slow and unreliable besides. |
| Run local discovery automatically when the dialog opens | Tempting and mostly harmless — but the same code path carries the network source, and a default that is safe today is a default someone widens tomorrow. On demand for both keeps one rule. |
| Remember the network-search confirmation **across runs** | The confirmation broker's ruling is that no approval is ever remembered, and a second, weaker policy for a second kind of consent is how the first one erodes. Remembering it *within* one run was ruled acceptable (§13 D5) precisely because nothing is written to disk and a restart asks again. |
| `psutil` for process and service enumeration | A dependency this feature does not earn; the registry and a loopback probe answer the same question with the standard library. |
| Send a protocol handshake to identify what is on an open port | It is a connection attempt to a service the user has not chosen, and it would appear in that server's logs as a failed login. The port number plus an honest label is enough — and see the row below, where this was tried anyway and did not even work. |
| **Parse a TDS PRELOGIN response** to identify a SQL Server behind an open port and read its version without authenticating | **Tried, and abandoned on the evidence.** It was the one handshake that looked defensible: PRELOGIN is the first packet of the TDS exchange, it precedes any login, and it advertises the server's version — so it promised to turn a "something answered on 1433" candidate into a confirmed SQL Server with a version, at the cost of one packet and no credential. Four well-formed variants of the PRELOGIN packet were sent to a **real** SQL Server instance during implementation, and **every one of them returned zero bytes.** No error, no reset, no partial response — silence. The reasons a server may decline to answer are several (encryption negotiation policy, a driver-version gate, an intermediary swallowing it — see decision 2 on NAT) and none of them is under d-MCP's control, so a feature built on it would be one that works on the developer's machine and nowhere reliably. It also earns nothing that is not already available: **SSRP already names the instances** (decision 4), and the **version arrives from `SERVERPROPERTY('ProductVersion')`** once a connection is authenticated, which is where the traits probe already reads it. A hand-rolled parser for a binary wire protocol, fed by an unauthenticated remote, for information obtainable twice over elsewhere, is not a trade worth making. |
| Open a discovered SQLite file to confirm it | Opening an untrusted SQLite file with the library is itself an attack surface. The 16-byte magic answers the question that was asked. |
| Auto-fill the connection form from a network reply | It is the one input source under someone else's control. Review-then-save is the whole point. |

## Consequences

**The Windows-only sources cannot be proved from the development VM.** `winreg`, the service
table and SSPI are exercised against fakes on Linux; a real registry and a real trusted connection
become new numbered sections in `docs/CROSS-PLATFORM-SMOKE-TEST.md`, alongside the existing honest
record of what the VM could not prove.

**Local discovery will sometimes find nothing and still be right** — a locked-down machine where
`HKLM` is unreadable, a server that is not local. The `notes` field carries the reason
(*"the registry key is not readable by this account"*) so the empty list is explained rather than
just empty.

**The broadcast will sometimes be blocked** by a firewall or by a network that does not forward
directed broadcasts, and the honest outcome is "no replies" with no way to distinguish blocked
from absent. The dialog says as much and offers a unicast probe against a named host, which is the
more reliable path anyway.

**A dynamic port found today may be wrong tomorrow.** SQL Express commonly moves its port on
restart, which is exactly why the `instance` column of ADR 0002 exists, and the candidate is
labelled *"dynamic port — it changes when the service restarts"*.

The user ruled (§13 D2, against this document's own recommendation) that a failed connection **does**
re-resolve it automatically and retry — exactly once, unicast to the profile's own host and never
a broadcast, with a 1.5 s timeout, an audit row naming the old port and the new one, no retry when
the port is unchanged, and never after an authentication failure. That retry is in `engine.py`, it
shares this ADR's SSRP parser rather than owning a second one, and it needs no confirmation
because nothing leaves the machine that the failed connect attempt was not already sending to the
same host.

**The "dynamic port" note travels as an English string literal, and that couples `db/` to `gui/`.**
`discovery.py` bakes the fragment `" (dynamic port — it changes when the service restarts)"` into
`Candidate.label`, and `discovery_dialog.py` holds the identical literal as
`_DYNAMIC_PORT_MARKER`, strips it and substitutes the translated text. This is a consequence of
decision 1 — `discovery.py` has no i18n dependency by design, so it cannot return a translation
key and must still produce a `label` that reads correctly for the CLI. **It fails silently:** edit
the literal on either side and the GUI simply stops matching, leaving raw English inside an
otherwise translated list in all eighteen languages, with no test, type or import connecting the
two halves. The proper fix, if this is revisited, is a `note_key` field on `Candidate` carrying
the i18n key with `label` kept as the CLI-readable fallback; until then the two literals must be
edited together. `DESIGN-CONNECTION-SETUP.md` §7.2 has the full note.

**`confidence` means less than its name suggests.** As implemented, `_discover_listening_ports()`
marks its candidates `'confirmed'` — the *probe* is confirmed — while this ADR's decision 1 and
`discovery.py`'s own module docstring reserve that word for a source that inspected the service
itself. Nothing depends on the difference today, because every consumer that must not overstate a
finding reads `label` and `origin`; it is recorded so that whoever first gives `confidence` a
load-bearing job settles the question in one place instead of inheriting the ambiguity.

**SQLite discovery never leaves the working directory on its own.** §13 D4: the automatic walk is
the current working directory plus two levels, and anything wider is a manual *"Search a folder…"*
supplying one root for one run. The home directory is never walked automatically, because a list
of every SQLite file a user owns is a privacy consideration and not merely a slow scan.

## Documented where a reader will meet it

- `docs/DESIGN-CONNECTION-SETUP.md` §7, at length, including the untrusted-input table.
- `src/sape_d_mcp/db/discovery.py`'s module docstring — what it never does, first.
- `DATA-PROTECTION.md`: local discovery reads the registry, ODBC configuration and file names, and
  what it does *not* read.
- `DISCLAIMER.md`: the network search emits traffic on the user's network at the user's request.
- `README.md`, and `docs/CROSS-PLATFORM-SMOKE-TEST.md` for the platform gaps.
