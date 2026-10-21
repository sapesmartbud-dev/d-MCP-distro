# ADR 0002 — System authentication as a first-class connection property

- **Status:** accepted and implemented; the user's rulings are recorded in `DESIGN-CONNECTION-SETUP.md` §13
- **Supersedes:** `ck_connections_sqlite_shape` and the "`username` is always required off SQLite"
  assumption of `DESIGN-DATA-MODEL.md` §3.3
- **Implemented by:** `src/sape_d_mcp/db/auth_modes.py` (new), `db/targets.py` (new),
  `db/connection_store.py` (schema version 2), `db/dialects/mssql.py`, `db/dialects/postgres.py`,
  `db/engine.py`
- **Detail:** `docs/DESIGN-CONNECTION-SETUP.md` §§3–6

## Context

The shipped `connections` table encodes, in a CHECK constraint, the belief that every non-SQLite
connection has a user name this application supplies:

```sql
OR (engine <> 'sqlite' AND host IS NOT NULL AND port IS NOT NULL AND username IS NOT NULL)
```

That belief is false for the most common way a Windows desktop reaches a local SQL Server. A
trusted connection presents the caller's own process token; ODBC ignores `UID` entirely when
`Trusted_Connection=yes` is set. It is equally false for PostgreSQL `peer` authentication over a
Unix socket, and for GSSAPI.

Because the model cannot say *"the operating system supplies the identity"*, the user did the only
thing the form allowed: typed the Windows account `PC-ARR\larre` into the user-name box, chose
`pymssql`, and got DB-Lib error **20009 — "Unable to connect: Adaptive Server is unavailable or
does not exist"**. That message names a transport failure. The actual causes were that `pymssql`
cannot make a trusted connection at all, and that the host field carried
`PC-ARR\SQLEXPRESS:56879` — a server, an instance and a port in one column — straight through to
FreeTDS. Nothing in the application said either thing.

The general defect is that an unsupported combination failed **at connect time, in the driver's
vocabulary**, when it could have been refused **at configuration time, in the user's**.

## Decision

**1. `auth_mode` is a column with a closed three-value domain** — `password`, `integrated`,
`none` — driven by an `AUTH_MODES` tuple that renders the CHECK, the validator, the GUI combo and
the parametrised tests, in the way `ACTIONS` already does in `permissions.py`.

**2. Under `integrated`, `username` must be NULL — not optional, NULL.** A stored user name that
the driver ignores is a profile that displays one identity while connecting as another. If the
value cannot be used, it is not kept, and `_validate()` says so rather than dropping it silently.
This is the same fail-closed instinct as `rule_for()` refusing a non-absolute path.

**3. `none` belongs to SQLite alone.** PostgreSQL's `trust` method is modelled as `integrated`,
because from d-MCP's side "no name and no secret is sent" is one behaviour, and a domain with two
values meaning the same thing is a domain that gets chosen from wrongly.

**4. Support is a table, not a branch.** `INTEGRATED_SUPPORT[(engine, driver)]` states, per pair,
whether integrated authentication is possible, on which platforms, by which mechanism, and — when
it is not — the single sentence explaining why. A conformance test requires an entry for every
`(engine, driver)` in `DRIVERS_BY_ENGINE`, so a new driver cannot be added without an explicit
ruling, and the default is never "probably yes".

**5. `pymssql` + `integrated` is unrepresentable at three layers** — the GUI disables it, the
store refuses it, the DSN builder raises. FreeTDS has no SSPI path and its GSSAPI support is
absent from the published wheels; the combination could never work, and left open it fails as a
network error that sends the user to look for a firewall problem that is not there.

**6. `instance` is a first-class column, and the host field holds a bare server.**
`parse_mssql_target()` accepts every form people actually type — `HOST\INSTANCE`, `HOST,PORT`,
`HOST:PORT`, `tcp:HOST,PORT`, `.`, `(local)`, bracketed IPv6 — and either parses or raises. It
never repairs. Where a port and an instance are both present, the port wins and the instance is
not used to reach the server; that precedence is what ODBC documents, it is implemented once in
`resolve_mssql_target()`, and both drivers are given the same treatment.

**7. Schema version 2 is a full table rebuild.** SQLite cannot drop a CHECK constraint, and
`pragma writable_schema` edits `sqlite_master` under a live schema cache — a corrupted
`connections.db` costs every profile *and* strands every keyring entry, since the account name is
derived from the row id. The rebuild is `VACUUM INTO` backup → new table → `INSERT..SELECT` →
**parametrised `UPDATE`s** → drop → rename → `foreign_key_check` → `user_version = 2`. The
`INSERT..SELECT` maps `engine = 'sqlite'` to `'none'` and everything else to `'password'`, which
every legal v1 row satisfies by construction, so the migration cannot fail on data.

The `UPDATE` step is not an implementation detail that could have been folded into the `SELECT`.
The user overruled this ADR's original position and required the migration to **split a compound
host automatically** rather than only flag it, and the split is `parse_mssql_target()` — Python,
with no SQL equivalent worth writing. Reimplementing its precedence in `CASE`/`instr()`
expressions would put a second parser on the user's stored data that could disagree with the
first. So the rebuild reads the rows back inside the *same* transaction and issues one
parametrised `UPDATE` per row that needs one. The safeguards that made accepting that ruling
reasonable are `DESIGN-CONNECTION-SETUP.md` §13 D6 and are load-bearing: the unconditional
`VACUUM INTO` backup taken before anything is rebuilt, a WARNING log of the before and the after
of every split field by field, `needs_review()` rather than invention wherever the parser refuses,
and — for the conflict the design never anticipated, a v1 row whose `port` column is `NOT NULL`
while its host also carries an embedded port — the embedded port wins, with a WARNING naming both
values.

**8. The `auth_mode` CHECK is unreachable, and it stays.** `ck_connections_shape` is declared
first and pins `auth_mode` to a value inside the domain in every one of its branches, and SQLite
reports the first CHECK that fails in DDL order — so an out-of-domain mode is always refused by
the shape constraint and `ck_connections_auth_mode` can never be observed firing. It is kept as
genuine defence in depth: it is what holds the domain closed if the shape constraint is ever
relaxed, and relaxing a shape constraint is precisely what this ADR did. No test can exercise it
and none should be written; see `DESIGN-CONNECTION-SETUP.md` §3.2.

**9. A profile whose `auth_mode` leaves `password` has its keyring entry deleted**, and
`engine.connect()` raises `ValueError` if handed a password for a profile that does not
authenticate with one. The mode decides, never the presence of a secret.

## Alternatives rejected

| Alternative | Why not |
|---|---|
| A boolean `integrated` flag | Cannot express SQLite's "there is no authentication step", which today is smuggled in as "SQLite has no user name". A third state would have to be added within a release. |
| Keep `auth_mode` in `options_json` | It participates in a CHECK constraint and in a validator. `options_json` is for per-driver extras, and a security-relevant discriminator hidden in a JSON blob is a discriminator nobody greps for. |
| Allow `username` under `integrated`, ignored | The Connections page and the audit trail would name an identity the server never saw. |
| Let `pymssql` + `integrated` fail at connect time | It already does, and that is the bug being fixed. |
| `ALTER TABLE ADD COLUMN` and leave the old constraints | SQLite would accept both columns happily, and the table would keep enforcing `username IS NOT NULL` — the exact constraint the change exists to relax. |
| An XOR constraint on port/instance | Makes the migration of an existing `PC-ARR\SQLEXPRESS:56879` row lossy, and does not remove the question, only relocates it to the migration. |

## Consequences

**Existing profiles keep working.** `auth_mode` defaults to `'password'`, and every v1 non-SQLite
row has a user name, so nothing that connects today stops connecting — except a row whose `host`
is compound, which now fails with a sentence naming the three fields to fill instead of with error
20009. That is a behaviour change on a profile that was already failing.

**A `connections.db` written by this build cannot be opened by an older one.** `_migrate()`'s
existing guard raises with a sentence telling the user to upgrade. The `VACUUM INTO` backup is what
makes a downgrade possible at all, and its path is logged at WARNING.

**Kerberos moves into the support surface.** `pyodbc` + `integrated` on Linux and macOS needs a
ticket, a `krb5.conf` and a registered SPN — none of which d-MCP manages. It is offered with a
persistent note rather than blocked, because it genuinely works and blocking it would be
paternalistic; the cost is a support path that is a system-administration problem, not a bug.

**A headless server whose profiles are all `integrated` never needs the credential vault**, never
reads `DMCP_MASTER_PASSWORD` and never prompts. That is a real reduction in the risk surface
`DISCLAIMER.md` §11 documents, and it should be said there.

**MySQL system authentication is documented as unsupported** rather than half-attempted. That is a
"Known limitations" entry in the README, and a user with `auth_socket` configured will be
disappointed by a sentence rather than by a timeout.

**`AuthSupport.platforms` carries no live exclusion yet.** Both supported pairs — pyodbc on MS-SQL
and psycopg on PostgreSQL — genuinely work on Windows, Linux and macOS, so both list all three,
and the four unsupported pairs are returned before `support_for()` ever consults the field. The
platform-rejection branch and its message key
`connections.auth_integrated_unsupported_platform` are therefore **unreachable with the shipped
matrix**: provision for a driver whose support is platform-dependent, so that adding one is a data
edit rather than a code edit. What *is* live is the branch beneath it, which keeps pyodbc
`supported=True` off Windows and swaps the mechanism to Kerberos with `needs_setup=True` — a note,
never a block. Recorded so nobody deletes the field as unused or writes a test that claims to
exercise it from `INTEGRATED_SUPPORT`.

**A failed MS-SQL connection to a named instance now emits a UDP datagram.** The user overruled
the recommendation in `DESIGN-CONNECTION-SETUP.md` §13 Q2: on a *network* failure for a profile
that names an instance, `engine.connect()` re-resolves the port through the SQL Server Browser and
retries. The conditions are narrow and each of them is a safeguard rather than an optimisation —
exactly one retry with no loop, unicast to the profile's own host and never a broadcast, a 1.5 s
timeout, an audit row naming the old port and the new one, no retry when the port is unchanged,
and never on an authentication failure. See §13 D2. The consequence to hold in mind is simply
that a failing connect is no longer silent on the network, and that `audit.db` is where that shows
up.

## Documented where a reader will meet it

- `docs/DESIGN-CONNECTION-SETUP.md` §§3–6, at length.
- `src/sape_d_mcp/db/auth_modes.py`'s module docstring — the matrix and why each "no" is a no.
- `DESIGN-DATA-MODEL.md` §3.3, rewritten to the v2 DDL.
- `README.md` Known limitations: MySQL, and the dynamic-port caveat.
- `docs/CROSS-PLATFORM-SMOKE-TEST.md`: a real trusted connection is Windows-only and cannot be
  proved from the development VM.
