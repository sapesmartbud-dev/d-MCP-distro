# SAPÉ d-MCP — Connection setup: system authentication, discovery and database enumeration

Design document. **No production code is written by this document**; it specified what the
`db-specialist`, `uix-designer`, `python-senior`, `qa-specialist` and `deployment-specialist`
agents implemented, and §12 lists those tasks in order.

**This document has been reconciled with the code that shipped.** Where the first draft and the
implementation disagreed, the code is the truth and the text below has been corrected to match it;
each such correction says so where it sits. §13 is no longer a list of questions — the user has
ruled on all six, two of them against this document's own recommendation, and §13 now records the
rulings and the safeguards attached to accepting them.

- **Status:** implemented; §12 complete, all §13 rulings taken
- **Supersedes:** `DESIGN-DATA-MODEL.md` §3.3 (the `connections` DDL) and §3.4 (domains) —
  both of which have since been **re-issued at schema version 2** to match, so the two documents
  now agree and either may be read first
- **Extends:** `DESIGN-DIALECTS.md` §3.7 (Connection), §5 (Driver matrix), §7 (profile → driver)
- **Companion ADRs:** `docs/adr/0002-system-authentication.md`,
  `docs/adr/0003-connection-discovery.md`

---

## 1. Why

The user's verdict on the shipped connection subsystem is that it is *"muy pobre"* — very poor.
That verdict is fair, and it is worth naming precisely what is missing rather than treating it as
a matter of taste, because each gap has a distinct cause.

**It cannot express how most Windows SQL Server installations actually authenticate.**
`ck_connections_sqlite_shape` reads:

```sql
(engine =  'sqlite' AND host IS     NULL AND port IS     NULL AND username IS     NULL)
OR (engine <> 'sqlite' AND host IS NOT NULL AND port IS NOT NULL AND username IS NOT NULL)
```

`username IS NOT NULL` for every non-SQLite engine encodes an assumption — that a login always
has a name this application supplies — which is false for a Windows trusted connection, false for
PostgreSQL peer authentication, and false for GSSAPI. There is no way to say *"the operating
system supplies the identity"*, so a user who wants that types their Windows account into the
user-name box, which is not the same thing at all and is where the reported failure begins.

**It offers no help finding a server.** Every field is free text. The application knows nothing
about the SQL Server instance registered in the local machine's own registry, the PostgreSQL
listening on `localhost:5432`, or the ODBC DSN the user already configured — even though all three
are readable without a credential and without a network packet.

**It cannot answer "which databases are on this server?"** The database name is free text, so a
typo is indistinguishable from a permission problem, and both surface as the same red banner.

**And it lets an ambiguous host through to the driver.** The user's screenshot shows a host typed
as `PC-ARR\SQLEXPRESS:56879` with the user name `PC-ARR\larre`, driver `pymssql`, failing with
DB-Lib error **20009**, *"Unable to connect: Adaptive Server is unavailable or does not exist"*.
Three separate defects meet in that one screenshot:

1. `pymssql` cannot make a Windows trusted connection at all (§4.2), so the intent was
   unsatisfiable before a packet was sent — and nothing said so.
2. The host string carries a server, a named instance **and** a port in one field. `build_dsn()`
   passes it through verbatim as `server=`, and FreeTDS then has to guess (§6).
3. `classify_error()` has no rule for 20009, so the sentence shown to the user names none of this.

The house rule is that an unnormalised or ambiguous identifier raises `ValueError` rather than
being guessed at. A host that carries three values in one field is exactly that, and it currently
reaches a driver instead of a validator.

## 2. Scope

In scope, all three ruled by the user:

1. **System authentication** — integrated / trusted / OS authentication as a first-class property
   of a profile, with a per-`(engine, driver, platform)` support matrix that blocks the impossible
   combinations in the GUI rather than at connect time.
2. **Auto-detection** of database servers, **local and local-network**, as structured candidates
   with a stated provenance.
3. **Database enumeration** from a reachable server into an *editable* combo box.

Explicitly out of scope, and each for a reason:

| Not doing | Why |
|---|---|
| Any new MCP tool | Discovery and enumeration are **GUI affordances for the human operator**. Exposing "map the local network" or "list every database on the server" to a model would hand it a reconnaissance primitive the permission engine was never designed to gate. The MCP catalogue stays at 38 tools. |
| LAN port sweeping | The only datagram d-MCP ever sends to an address it was not given is the single SQL Server Browser broadcast of §7.5. Sweeping a /24 for open 5432s is a port scan, and a port scan from a desktop application is a security incident on most corporate networks. |
| Credential discovery | Nothing in §7 reads a `.pgpass`, a `~/.my.cnf`, a saved ODBC password or a Windows credential vault. Discovery finds *addresses*, never secrets. |
| Storing a Kerberos ticket or keytab | The OS owns the ticket cache. d-MCP uses it and never manages it. |
| Unix-socket MySQL (`auth_socket`) | Requires `host IS NULL`, which the tagged union reserves for SQLite. §4.4. |

---

## 3. Data model

### 3.1 The two new columns

```sql
    auth_mode     TEXT    NOT NULL DEFAULT 'password',
    instance      TEXT,            -- MS-SQL named instance; NULL on every other engine
```

`auth_mode` is a closed domain of three values, and the tuple that defines it is the single
source of truth for the CHECK, the runtime validation, the GUI combo box and the parametrised
tests, exactly as `ACTIONS` is in `permissions.py`:

```python
# src/sape_d_mcp/db/auth_modes.py
AUTH_MODES: tuple[str, ...] = ("password", "integrated", "none")
```

| Value | Meaning | `username` | Keyring entry | Offered for |
|---|---|---|---|---|
| `password` | d-MCP presents a user name and a password it holds in the credential store. | **NOT NULL** | **required** | every engine but SQLite |
| `integrated` | The operating system supplies the identity: SSPI, Kerberos/GSSAPI, or PostgreSQL `peer`. d-MCP presents no name and no secret. | **NULL** | **must not exist** | see the matrix in §4 |
| `none` | There is no authentication step. Access is whatever the filesystem grants. | **NULL** | **must not exist** | SQLite only |

**`username` must be NULL under `integrated`, not merely optional.** This is the fail-closed
reading and it is the direct fix for the screenshot. When a trusted connection is made, ODBC
ignores `UID` entirely; a profile that stores `PC-ARR\larre` while connecting as whoever launched
the process is a profile that *lies to the person reading it* — the Connections page would show one
identity and the server would see another, and the audit trail would inherit the wrong one. If the
value cannot be used, it is not stored. `_validate()` raises `ValueError` rather than silently
dropping it, so the mistake is corrected on screen instead of forgotten.

**`none` is reserved for SQLite.** PostgreSQL's `trust` method is genuinely "no authentication",
and it is tempting to give it `none`; it is modelled as `integrated` instead, because from
d-MCP's side the two are indistinguishable — no name is sent, no secret is sent — and a domain
with two values meaning "send nothing" is a domain that will be chosen from wrongly. One value,
one behaviour.

`instance` is a first-class column rather than a key in `options_json` because it participates in
a CHECK constraint, drives a validator, and is one of the two ways to *address* a server, which is
what the columns of this table are for. `options_json` remains for genuine per-driver extras.

### 3.2 The revised DDL

Changed lines only; everything else in `SCHEMA` is untouched.

```sql
    host          TEXT,            -- NULL iff engine = 'sqlite'
    port          INTEGER,         -- NULL iff engine = 'sqlite', or an MS-SQL named instance
                                   --   supplies the port through the SQL Server Browser
    instance      TEXT,            -- MS-SQL named instance ('SQLEXPRESS'); NULL elsewhere
    username      TEXT,            -- NULL iff auth_mode <> 'password'
    auth_mode     TEXT    NOT NULL DEFAULT 'password',

    -- The engine is the discriminator of a tagged union and auth_mode is a second,
    -- narrower one. Exactly one null pattern is legal per (engine, auth_mode) pair,
    -- so a NULL here always means "structurally absent", never "not filled in yet".
    --
    -- Renamed from ck_connections_sqlite_shape: it no longer governs only the SQLite
    -- row shape, and a constraint whose name says less than it does is a constraint
    -- someone will relax for the wrong reason.
    CONSTRAINT ck_connections_shape CHECK (
        (engine =  'sqlite'
            AND host     IS NULL AND port     IS NULL
            AND username IS NULL AND instance IS NULL
            AND auth_mode = 'none')
     OR (engine <> 'sqlite'
            AND host IS NOT NULL
            AND (port IS NOT NULL OR instance IS NOT NULL)
            AND ( (auth_mode = 'password'   AND username IS NOT NULL)
               OR (auth_mode = 'integrated' AND username IS     NULL) ))
    ),

    CONSTRAINT ck_connections_auth_mode CHECK (
        auth_mode IN ('password', 'integrated', 'none')     -- rendered from AUTH_MODES
    ),

    CONSTRAINT ck_connections_instance CHECK (
        instance IS NULL
        OR (engine = 'mssql' AND length(trim(instance)) > 0)
    ),
```

The `auth_mode IN (...)` list is **generated** from `AUTH_MODES` by a `_auth_mode_check()` helper
alongside the existing `_engine_driver_check()`, for the same stated reason: adding a mode must be
one edit, and the constraint must not be able to drift from the validator that runs before the
INSERT.

**`ck_connections_auth_mode` is unreachable in practice, and it stays.** This is recorded because
it is the kind of constraint a later reader deletes as dead code, and because it is the kind of
constraint a later tester tries to write an impossible test against. Both would be mistakes, for
the same reason:

- `ck_connections_shape` is declared **first**, and every one of its branches already pins
  `auth_mode` to a value inside the domain — `= 'none'` on the SQLite side, `= 'password'` or
  `= 'integrated'` on the other. A row carrying `auth_mode = 'kerberos'` therefore satisfies no
  branch of the shape constraint and is rejected by it.
- SQLite reports the **first** CHECK that fails in DDL declaration order. So the `IntegrityError`
  an out-of-domain mode produces always names `ck_connections_shape`, never
  `ck_connections_auth_mode`, and no test can observe the second one firing. The mapping in
  `_friendly_integrity_error()` keeps a sentence for it anyway, for the same reason.
- It is nevertheless **genuine defence in depth, not decoration**: it is the constraint that keeps
  the domain closed if `ck_connections_shape` is ever relaxed — and §3.2's whole subject is a
  shape constraint being relaxed. Its cost is one line of generated DDL; its value is that the
  next relaxation cannot silently open the domain as a side effect.

Do not test it directly, do not delete it, and do not reorder the two constraints in order to make
it observable — the ordering is what gives the user the more useful of the two messages.

Two guarantees are preserved exactly:

- **A `password` profile still cannot be saved without a user name.** The old constraint's real
  content survives, moved inside the `auth_mode = 'password'` branch.
- **Every non-SQLite profile is still addressable.** The old `port IS NOT NULL` becomes
  `port IS NOT NULL OR instance IS NOT NULL`, and since `instance` is NULL on every engine but
  MS-SQL (`ck_connections_instance`), PostgreSQL and MySQL still require a port, unchanged.

`ck_connections_port` (`port IS NULL OR port BETWEEN 1 AND 65535`) needs no change.

### 3.3 Port and instance together

A named instance and a port may both be present. They are not mutually exclusive in the schema,
and this is deliberate rather than lax, because the alternative — an XOR constraint — would make
the migration of an existing row lossy (§3.5) and would not remove the question, only move it.

**Precedence is documented, single-place and identical for both drivers: when a port is present,
the port is used and the instance name is not used to reach the server.** That is what the ODBC
driver documents for `Server=HOST\INSTANCE,PORT`, so for `pyodbc` it is what would happen anyway;
`resolve_mssql_target()` (§6.2) makes `pymssql` behave the same way instead of letting FreeTDS
decide. The instance name is retained on the profile because it is how the port is *re-derived*
when a dynamic port moves, and because it is how a human recognises the server.

This is a documented precedence, not an ambiguity: fail-closed applies to identifiers whose
meaning cannot be determined, and this one has exactly one meaning, tested. The GUI states it
under the fields, and the user ruled (§13 D1) that the *dialog* additionally clears the port when
an instance is typed, so the precedence cannot be tripped over on screen. The schema is unchanged
and still permits both; the precedence above is what decides a row that carries them.

### 3.4 `_PROFILE_COLUMNS`

```python
_PROFILE_COLUMNS: tuple[str, ...] = (
    "display_name", "engine", "driver", "host", "port", "instance",
    "database", "username", "auth_mode", "options_json", "colour_tag",
    "statement_timeout_s",
)
```

That tuple already drives the INSERT, the UPDATE, the row → dict mapping and `_migrate_schema()`.
Adding the two names to it is the whole of the read/write plumbing change; nothing else enumerates
columns.

### 3.5 Migration: `user_version` 1 → 2

`connections.db` exists on the user's disk with real rows in it. SQLite has no
`ALTER TABLE ... DROP CONSTRAINT`, and `ck_connections_shape` replaces a constraint, so the
twelve-step table rebuild is required. `pragma writable_schema = 1` is rejected: it edits
`sqlite_master` text under a live schema cache, it is documented as a foot-gun, and a corrupted
`connections.db` costs the user every profile *and* strands every keyring entry, whose account
name is derived from the row id.

**The version mechanism already exists** and needs only to grow a step chain. `ConnectionStore.__init__`
reads `PRAGMA user_version` *before* `executescript(SCHEMA)` — which is the ordering that makes
this possible at all, since `CREATE TABLE IF NOT EXISTS` is a no-op against the v1 table — then
calls `_migrate(existing_version)`. Today `_migrate()` bumps the version and does nothing else,
with a comment saying the chain goes there when version 2 arrives. It has arrived:

```python
SCHEMA_VERSION = 2

# One entry per version step, applied in ascending order, each idempotent and each
# committed before the next. The key is the version the step produces.
_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    2: _migrate_1_to_2,
}
```

`_migrate()` keeps its "refuse a newer file" guard verbatim, then applies every step in
`sorted(_MIGRATIONS)` whose key is `> existing_version`, setting `user_version` after each.

`_migrate_1_to_2(conn)`, following SQLite's own documented procedure:

1. **Back up first.** `VACUUM INTO '<db>.v1.backup'` (SQLite ≥ 3.27; every supported Python ships
   it). If the file already exists, suffix with the UTC timestamp. A failure here **aborts the
   migration** — refusing to start is recoverable, a half-rebuilt profile table is not. The path is
   logged at WARNING so the user can find it, and the Connections page reports it once.
2. `PRAGMA foreign_keys = OFF` — outside any transaction. `connections.db` holds no foreign key
   (the rules in `permissions.db` are a different file and are swept by `_revoke_rules()`, not by
   SQLite), so this is procedure rather than necessity, and is done anyway because the next
   maintainer will not know that.
3. `BEGIN IMMEDIATE`.
4. `CREATE TABLE connections_v2 (...)` — the §3.2 DDL under a temporary name.
5. The data step, which is two statements and not one:

```sql
INSERT INTO connections_v2
      (id, display_name, engine, driver, host, port, instance, database,
       username, auth_mode, options_json, colour_tag, statement_timeout_s,
       created_at, user_created, updated_at, user_updated)
SELECT id, display_name, engine, driver, host, port, NULL,     database,
       username,
       CASE WHEN engine = 'sqlite' THEN 'none' ELSE 'password' END,
       options_json, colour_tag, statement_timeout_s,
       created_at, user_created, updated_at, user_updated
  FROM connections;
```

   Every v1 row satisfies the v2 constraint by construction: a v1 SQLite row has the three NULLs
   the `'none'` branch demands, and every v1 non-SQLite row has a non-NULL `username` and port,
   which is exactly the `'password'` branch. **The migration therefore cannot fail on data**, and
   a test asserts that for a fixture v1 file holding one row per engine.

   `colour_tag` and `statement_timeout_s` are read where the source table has them and defaulted
   where it does not: both arrived after the first pre-release build and are repaired by
   `_migrate_schema()`, which runs *after* this chain, so naming them unconditionally would fail
   with *no such column* on exactly the oldest file this migration exists to rescue.

   Then, **in the same transaction and before the rename**, `_split_compound_hosts(conn,
   'connections_v2')` separates the MS-SQL hosts that carry more than a server name (§13 D6). It
   is a `SELECT id, display_name, host, port` followed by one **parametrised `UPDATE` per row** —
   *not* part of the `INSERT..SELECT` — because the separation is `parse_mssql_target()`, which is
   Python and has no SQL equivalent worth writing: the parser is the same one the validator and
   the dialect use, and reimplementing its precedence in `CASE`/`instr()` expressions would be a
   second parser that could disagree with the first about a value already on the user's disk.

```sql
UPDATE connections_v2 SET host = ?, instance = ?, port = ? WHERE id = ?;
```

   The safeguards on this ruling are stated in §13 D6 and implemented here: the `VACUUM INTO`
   backup of step 1 has already been taken unconditionally, every split is logged line by line
   with the value before and the value after, and a host the parser refuses is copied **verbatim**
   and left to `needs_review()` — nothing is invented.

   **The port conflict the original design did not cover.** Every v1 non-SQLite row has
   `port NOT NULL`, so a compound host such as `PC-ARR\SQLEXPRESS:56879` arrives with *two* ports:
   one embedded in the host string and one in the `port` column. The rule is that **the port
   embedded in the host wins**, and when the two differ the migration logs at **WARNING** naming
   both values, so the operator can see exactly which one was kept:

   > *the port 56879 that was typed into the host field supersedes the port column's 1433; check
   > the profile if that is not what you meant.*

   The embedded value wins because it is the more recent and the more specific statement of
   intent: it is what the user typed into the field they were actually looking at, and it is what
   the driver would have tried to use had it managed to parse the string at all. A `HOST\INSTANCE`
   with **no** embedded port keeps the port from its column unchanged — nothing is cleared, and
   the instance name is simply moved into the column that now exists for it (§3.3's precedence
   then decides which of the two is used to dial, at connect time, not here).

6. `DROP TABLE connections;` then `ALTER TABLE connections_v2 RENAME TO connections;`
7. Recreate `idx_connections_engine`.
8. `PRAGMA foreign_key_check` — must return no rows.
9. `COMMIT`, then `PRAGMA foreign_keys = ON`, then `PRAGMA user_version = 2`.

The whole step is **idempotent**, because a migration chain must be safe to re-enter: it returns
at once when the table already carries `auth_mode` and `instance`, which is also the case for a
brand-new file whose `SCHEMA` has just created the table in the version 2 shape.

**A host string the parser cannot read is still migrated verbatim.** Two backslashes, a comma
*and* a colon, `np:`, `(localdb)\NAME` — these are refused rather than guessed at, exactly as they
are at every other layer, and the row is copied through untouched. For those, and for anything a
user types later:

- `ConnectionStore.needs_review(profile) -> str | None` returns a sentence when an MS-SQL host
  string parses into more than a bare server name, or does not parse at all, and the Connections
  page shows an amber marker on that row. It is computed, never stored, so a profile repaired by
  hand — or by the automatic split above — stops being flagged the moment it is correct.
- Opening such a profile in the dialog pre-fills the split fields and offers **"Split it for me"**,
  so the repair is one click and the user sees the before and after.
- `MsSqlDialect` raises `ValueError` on a compound host when it builds the target (§6.3), so the
  row cannot quietly keep failing at 20009.

`_migrate_schema()` — the `PRAGMA table_info` diff that repairs a missing column with
`ALTER TABLE ADD COLUMN` — is left as it is, and `_MIGRATABLE_COLUMNS` deliberately does **not**
gain `auth_mode` or `instance`, with a comment saying why: SQLite would happily add both by ALTER,
and the resulting table would carry the v1 constraints, which is the failure this migration
exists to prevent. Only the rebuild may introduce them.

### 3.6 Validation changes in `_validate()`

The non-SQLite branch, restated:

```
engine == 'sqlite'  →  auth_mode is forced to 'none'; a supplied 'password' or
                       'integrated' raises ValueError naming the filesystem as the
                       access control.
otherwise           →  auth_mode defaults to 'password' when absent (the shipped
                       behaviour, so an existing caller is unaffected).
    'password'      →  username required and non-blank, as today.
    'integrated'    →  username must be absent or blank; a value raises ValueError:
                       "this profile authenticates through the operating system, so
                       it does not take a user name — remove it, or switch
                       Authentication to 'User name and password'."
                       Also checked against auth_modes.support_for(engine, driver,
                       platform); an unsupported pair raises with that entry's own
                       sentence (§4.6).
```

`instance`: accepted only for `mssql`, stripped, validated against
`^[A-Za-z0-9_$#][A-Za-z0-9_$#\-]{0,127}$` (SQL Server instance names are far narrower than that,
but the regex exists to keep a delimiter out of the connection string, not to second-guess
Microsoft). `host` for MS-SQL is parsed by `parse_mssql_target()` (§6.1); where it carries an
instance or a port, `reconcile_mssql_profile()` (§6.2a) moves those into their own columns
rather than rejecting the profile. Only a value that *contradicts* a column the user also
filled in is refused.

`port` becomes optional for MS-SQL when an instance is given, and stays mandatory otherwise, with
a message naming the way out: *"give a port, or a named instance for the SQL Server Browser to
resolve."*

---

## 4. What "system authentication" means, per engine and driver

This matrix is the design's central artefact and is implemented as **data, not as branching**:

```python
# src/sape_d_mcp/db/auth_modes.py — no driver imports, importable with no driver installed,
# so the GUI can grey out a combo item on a machine where nothing is installed at all.

@dataclass(frozen=True, slots=True)
class AuthSupport:
    supported: bool
    platforms: frozenset[str]      # from platform.system(): Windows, Linux, Darwin
    mechanism: str                 # 'sspi' | 'kerberos' | 'peer' | 'filesystem' | ''
    needs_setup: bool              # a ticket or a pg_hba entry the user must arrange
    message_key: str               # i18n key: why it is blocked, or what it needs

INTEGRATED_SUPPORT: dict[tuple[str, str], AuthSupport] = { ... }   # keyed (engine, driver)

def support_for(engine: str, driver: str, *, system: str | None = None) -> AuthSupport: ...
```

A conformance test asserts `set(INTEGRATED_SUPPORT) == set of every (engine, driver)` in
`DRIVERS_BY_ENGINE` — so a fifth driver cannot be added without an explicit ruling on whether it
supports system authentication, and the default is never "yes, probably".

**`platforms` excludes nothing today, and that is worth stating plainly.** As implemented, the two
entries that support integrated authentication — `('mssql', 'pyodbc')` and
`('postgresql', 'psycopg')` — both carry all three of `Windows`, `Linux` and `Darwin`, because
both genuinely work on all three: pyodbc through SSPI on Windows and GSSAPI elsewhere, psycopg
through SSPI/GSSAPI over TCP and `peer` over a Unix socket. The four unsupported entries carry the
empty set, but `support_for()` returns those before it ever looks at the platform.

The consequence is that `support_for()`'s platform-rejection branch —

```python
    if current not in entry.platforms:
        return replace(entry, supported=False,
                       message_key="connections.auth_integrated_unsupported_platform")
```

— **cannot be reached by any pair in the shipped matrix**, and its i18n key
`connections.auth_integrated_unsupported_platform` is a string no user can currently be shown.
Both are deliberate provision for a driver whose support is platform-dependent (a Windows-only
SSPI wrapper, say, or a driver whose GSSAPI build exists on Linux and not on macOS), and the field
is what makes adding such a driver a data edit rather than a code edit. What it is *not* is live
behaviour, and a test that claims to exercise it has to construct its own `AuthSupport` rather
than pull one out of `INTEGRATED_SUPPORT`.

What *is* live, and what does the platform-dependent work today, is the branch below it: on
`('mssql', 'pyodbc')` off Windows, `support_for()` keeps `supported=True` and swaps the mechanism
to `kerberos`, sets `needs_setup=True` and returns the Kerberos message key. That is a note, never
a block (§4.1).

| Engine | Driver | Integrated supported | Mechanism | What is actually sent | Platform notes |
|---|---|---|---|---|---|
| MS-SQL | **pyodbc** | **Yes** | SSPI on Windows, Kerberos elsewhere | `Trusted_Connection=yes`, **no** `UID`, **no** `PWD` | Windows: the process token, no setup. Linux/macOS: `msodbcsql18` uses GSSAPI — needs a valid ticket (`kinit user@REALM`), a `krb5.conf` naming the realm and KDC, and the server registered with an SPN. `needs_setup=True` off Windows. |
| MS-SQL | **pymssql** | **No — blocked in the GUI** | — | — | See §4.2. This is the reported failure. |
| PostgreSQL | **psycopg** | **Yes** | `peer`/`ident` over a Unix socket; SSPI or GSSAPI over TCP | the `user` key is **omitted**; libpq falls back to `PGUSER`, then to the OS account name | Unix socket: put the socket **directory** in `host` (`/var/run/postgresql`) and the port stays 5432; libpq builds the socket name from the two, so the tagged union is satisfied without a special case, and `sslmode` is ignored by libpq for Unix-domain sockets. TCP: needs `gss`/`sspi` in `pg_hba.conf`. `needs_setup=True`. |
| MySQL / MariaDB | **PyMySQL** | **No** | — | — | §4.4 |
| MySQL / MariaDB | **mysql-connector-python** | **No** | — | — | §4.4 |
| SQLite | **sqlite3** | **n/a — `auth_mode` is `'none'`** | filesystem | nothing | The access control is the file's own permissions. §4.5 |

### 4.1 MS-SQL + pyodbc

`build_dsn()` grows one branch. Under `auth_mode = 'integrated'` it emits
`Trusted_Connection=yes` and emits **no** `UID` field at all, rather than an empty one — an empty
`UID=` is a different thing to ODBC and has been known to defeat the trusted path. `Encrypt=yes`
and `TrustServerCertificate=no` are unchanged: a trusted connection is not an encrypted one.

`with_password()` is never reached, because `engine.connect()` refuses to hold a password for a
non-`password` profile at all (§5.2).

Off Windows the dialog shows a persistent, non-blocking note rather than a block, because Kerberos
against SQL Server from Linux does work and is a legitimate configuration:

> *System authentication on Linux and macOS uses Kerberos. You need a valid ticket — run `kinit`
> — and a `krb5.conf` that names your realm. Without one the server reports a login failure for
> the user `NT AUTHORITY\ANONYMOUS LOGON`.*

`classify_error()` gains that anonymous-logon text as an `auth` pattern, so the message is
actionable rather than mystifying.

### 4.2 MS-SQL + pymssql — blocked, and why

`pymssql` is a wrapper over FreeTDS. FreeTDS can perform NTLM with an explicit
`DOMAIN\user` **and a password**, which is not integrated authentication — it is password
authentication with a domain-qualified name. It has no SSPI path: it cannot borrow the calling
process's Windows token, and its GSSAPI support is a build-time option absent from the published
wheels d-MCP depends on. There is no reliable way to make a trusted connection through it, on any
platform.

Left unblocked, the failure surfaces exactly as it did in the user's screenshot: no password to
send, a login that cannot complete, and DB-Lib reporting **20009 — "Unable to connect: Adaptive
Server is unavailable or does not exist"**, a *transport* error that says nothing about
authentication and sends the user looking for a firewall problem that is not there.

**The combination is therefore unrepresentable, at three layers:**

1. **GUI.** Choosing `pymssql` disables the "Windows / system authentication" item in the
   Authentication combo (`setEnabled(False)` on the model item, not removal — a hidden option is
   one the user searches for). If the profile already had `integrated`, the mode reverts to
   `password`, the user-name field is enabled and focused, and the tooltip and an inline warning
   label give the reason.
2. **Store.** `_validate()` raises `ValueError` with the same sentence, so a profile written by a
   script or a test cannot hold the combination either.
3. **Engine.** `MsSqlDialect.build_dsn()` raises `DialectError` if it is ever reached with
   `driver='pymssql'` and `auth_mode='integrated'` — the belt-and-braces layer, so a hand-edited
   `connections.db` fails with a sentence instead of a 20009.

The message, in one place, `connections.auth_integrated_unsupported_pymssql`:

> *The pymssql driver cannot use Windows (trusted) authentication — FreeTDS has no way to present
> your Windows account to the server, and the attempt fails with error 20009, which looks like a
> network problem but is not one. Choose the **pyodbc** driver for system authentication, or keep
> pymssql and sign in with a SQL Server user name and password.*

### 4.3 PostgreSQL + psycopg

Omitting `user` from the keyword mapping is all of it; libpq then resolves the user name in its
documented order (`PGUSER`, then the OS account), and the server's `pg_hba.conf` decides which
method applies to that connection. The three realistic configurations:

| `pg_hba` method | Connection | Works with `integrated`? |
|---|---|---|
| `peer` | Unix socket (`host = /var/run/postgresql`) | Yes — the kernel reports the caller's uid. |
| `gss` / `sspi` | TCP | Yes, given a ticket (Unix) or a domain-joined machine (Windows). |
| `trust` | either | Yes — nothing is checked. Modelled as `integrated`, per §3.1. |

`sslmode` stays at its `require` default; libpq ignores it on a Unix-domain socket, so the socket
case needs no special handling and the TCP case keeps its current posture.

### 4.4 MySQL / MariaDB — not supported, stated plainly

MySQL's system-authentication plugin is `auth_socket` (`unix_socket` on MariaDB). It has two hard
requirements: the connection must arrive over a **Unix domain socket**, and the MySQL account name
must equal the OS account name — the client still sends a user name, it simply is not allowed to
choose it. Windows has `authentication_windows`, which is a commercial MySQL Enterprise plugin,
absent from MySQL Community and from MariaDB.

d-MCP's tagged union reserves `host IS NULL` for SQLite, so a socket path has no column to live
in (unlike PostgreSQL, where libpq accepts a directory in `host`; MySQL drivers take a distinct
`unix_socket` keyword instead). Between "not available in the product the user is likely to have"
and "not addressable by this schema", the honest answer is no:

> `connections.auth_integrated_unsupported_mysql`:
> *MySQL and MariaDB have no system-authentication mode d-MCP can use. The `auth_socket` plugin
> works only over a local Unix socket, and the Windows plugin ships only with MySQL Enterprise.
> Use a user name and password.*

The combo item is disabled for both MySQL drivers, with that tooltip. A future `unix_socket`
option was put to the user and declined for now (§13 D3); it is not designed here.

### 4.5 SQLite

`auth_mode` is `'none'`, forced by `_validate()` and pinned by `ck_connections_shape`. The
Authentication row in the dialog is hidden entirely for SQLite rather than shown disabled, since a
single-valued control is noise. The dialog gains one sentence of explanation where the user name
and password fields used to sit:

> *A SQLite database is a file. Access is controlled by the file's own permissions, so there is no
> user name and no password.*

### 4.6 How a blocked combination reaches the user

One rule, one place. `support_for(engine, driver)` returns the `AuthSupport`; both the dialog and
`_validate()` render `translate(support.message_key, language)`. The GUI never composes its own
sentence, so the message the user sees when the combo is disabled and the message they see if they
somehow save the profile anyway are the same string. New i18n keys are added to the **generated**
catalogue (`gui/i18n/`) by regenerating it — never by hand-editing the 154 KB line.

---

## 5. Credentials

### 5.1 Transitions

`auth_mode` is the sole determinant of whether a keyring entry may exist for a connection id.
`ConnectionStore.update()` already reads the row before writing (for the audit columns), so it can
compare the old and new modes:

| From | To | Action |
|---|---|---|
| `password` | `integrated` / `none` | **Delete the keyring entry** — `self._purge_secret(id)`, the mechanism `delete()` already uses. Logged at INFO as *"removed the stored password for connection 3: it no longer authenticates with one"*, never with any part of the value. |
| `integrated` / `none` | `password` | Nothing to delete. `has_password(id)` is false, so the dialog requires a password before Save enables, and the Connections page marks the profile *"password not set"* until one is stored. |
| unchanged | unchanged | Nothing. |

An orphaned credential is not a leak in itself — it sits in the same OS keyring it always did — but
it is a credential nothing can now address, kept alive by an application that has stopped needing
it. Deleting it is the same discipline `delete()` already applies when a profile is removed.

**If the purge fails** — a locked AES vault with no master password available, most plausibly —
the save still succeeds and the page shows a non-fatal warning naming the connection and telling
the user the password is unused but still stored. Mirrors the existing `delete()` behaviour rather
than inventing a second policy: refusing to change the authentication mode because a *secret we
no longer want* cannot be deleted would be a worse failure than the one it prevents.

### 5.2 The engine refuses a password it should not have

```python
def connect(profile, password=None, *, timeout_s=None, probe=True):
    if password is not None and profile.get("auth_mode", "password") != "password":
        raise ValueError(
            f"connection {profile.get('display_name')!r} authenticates through the "
            "operating system and takes no password."
        )
```

and, symmetrically, the callers (`connections_page`, `mcp_server`, `test_connection`) do not even
read the credential store for a non-`password` profile. Three consequences worth stating:

- A stale keyring entry that survived a failed purge is **never used**. The mode decides, not the
  presence of a secret.
- A headless MCP server whose profiles are all `integrated` never needs the AES vault, never reads
  `DMCP_MASTER_PASSWORD`, and never prompts. That is a real reduction in the risk surface
  `DISCLAIMER.md` §11 documents, and it is worth saying so there.
- The `ValueError` is raised before any DSN is built, so no secret can reach a driver by accident.

---

## 6. Host normalisation for MS-SQL

The direct fix for `PC-ARR\SQLEXPRESS:56879`.

### 6.1 `parse_mssql_target()`

New leaf module `src/sape_d_mcp/db/targets.py` — no dialect import, no driver import, so
`connection_store.py` may use it while keeping its stated property of being usable on a machine
with no driver installed at all.

```python
@dataclass(frozen=True, slots=True)
class MsSqlTarget:
    server: str            # bare host name, IP, or bracketed IPv6 literal
    instance: str | None
    port: int | None
    compound: bool         # True when the input carried more than a bare server

def parse_mssql_target(raw: str) -> MsSqlTarget: ...
```

Accepted input, all of which people really type, and what each yields:

| Input | server | instance | port |
|---|---|---|---|
| `db.example.com` | `db.example.com` | — | — |
| `PC-ARR\SQLEXPRESS` | `PC-ARR` | `SQLEXPRESS` | — |
| `PC-ARR,1433` (SSMS/ODBC) | `PC-ARR` | — | 1433 |
| `PC-ARR:1433` (FreeTDS) | `PC-ARR` | — | 1433 |
| `PC-ARR\SQLEXPRESS:56879` | `PC-ARR` | `SQLEXPRESS` | 56879 |
| `PC-ARR\SQLEXPRESS,56879` | `PC-ARR` | `SQLEXPRESS` | 56879 |
| `tcp:PC-ARR,1433` | `PC-ARR` | — | 1433 |
| `.` , `(local)` , `(LOCAL)` | `localhost` | — | — |
| `.\SQLEXPRESS` | `localhost` | `SQLEXPRESS` | — |
| `[::1]:1433` | `[::1]` | — | 1433 |
| `[fe80::1%eth0]` | `[fe80::1%eth0]` | — | — |

Rules, in order, and each one exists because of a way the naïve version gets it wrong:

1. Strip surrounding whitespace; strip a leading protocol prefix from
   `{tcp:, np:, lpc:, admin:}` case-insensitively. A prefix other than `tcp:` is an error —
   d-MCP speaks TCP, and silently ignoring `np:` would connect somewhere the user did not ask for.
2. **Bracketed IPv6 first.** An opening `[` means everything to the matching `]` is the address,
   including its colons and any `%zone`; only what follows the `]` is scanned for a port. Doing
   this before the colon split is the whole reason IPv6 works here.
3. Split the *first* `\` — the left side is the server, the right side begins the instance. A
   second `\` is an error (`ValueError`), not something to guess at.
4. On the remainder, split on `,` or `:`, whichever appears; **both appearing is an error**.
5. The port must be all digits and in 1–65535, else `ValueError` naming the offending text.
6. `.`, `(local)` and an empty server all normalise to `localhost`. `(localdb)\NAME` is
   rejected with its own sentence: LocalDB is a named-pipe-only, per-user instance that neither
   driver reaches over TCP, and pretending otherwise produces the same 20009.
7. `compound` is true whenever an instance or a port was extracted — that is the flag the GUI and
   `needs_review()` use.
8. Every returned component is re-validated against the allowed character class before it is
   returned: server `^[A-Za-z0-9._\-]{1,253}$` or a bracketed literal, instance as in §3.6. Anything
   else raises. **The parser never repairs; it either parses or raises.**

### 6.2 `resolve_mssql_target(profile) -> MsSqlTarget`

Reads the *columns* — `host`, `port`, `instance` — applies the §3.3 precedence (a port wins; the
instance is not used to reach the server), and is called by both MS-SQL DSN branches so the two
drivers cannot diverge. A single function, one set of tests, both drivers.

**It does not parse `host`, and it does not reject a compound one.** Its contract is that the
columns arrive already separated — which `connection_store._validate()` guarantees for anything
this application wrote — so it takes `host` as a bare server name and only raises `ValueError`
when that value is missing or blank. A compound host reaching it is a defect in its caller, not
an input for it to split, and splitting it here would put a second, silent parser behind the one
in §6.1. `compound` on the target it returns is therefore always `False`: the returned record
describes columns, and columns cannot be compound.

### 6.2a `reconcile_mssql_profile(profile) -> MsSqlTarget`

The one place a *compound* host meets the columns. It parses `host` with §6.1, then merges what
that yields with the `instance` and `port` columns and returns a target whose `compound` is
`False` — the same shape §6.2 returns, so every caller downstream is unchanged.

**Why it exists.** `DB_HOST=10.129.203.19\NRP` beside `DB_PORT=1435` is how an environment file
has always been written, and it is how the reporting user's working application is configured.
Refusing it made a correct address unusable: the dialog parsed the host, said in a note exactly
what it had understood, and then still refused to enumerate databases with it. Splitting it is
the same ruling the user already gave for stored rows in §13 D6 — split, do not flag and wait —
applied to typed input.

**What it still refuses.** An instance or a port present in *both* the host and its own column
with different values. That is an ambiguity with no documented precedence, and unlike the
migration case the person who typed both is on screen to resolve it. (§3.3's port-wins precedence
settles a port beside an *instance*, which is a different question and is not affected.)

`_validate()` calls it, so a stored profile still holds separated columns and `needs_review()`
still has nothing to flag; `MSSQLDialect._connection_target()` calls it too, because the dialog's
"Find databases" builds a DSN from an unsaved snapshot that has not been through `_validate()`.

### 6.3 What the drivers are given

```
pyodbc,  port:      Server=tcp:PC-ARR,1433
pyodbc,  instance:  Server=PC-ARR\SQLEXPRESS
pymssql, port:      server="PC-ARR", port=1433
pymssql, instance:  server="PC-ARR\\SQLEXPRESS"      (no port keyword at all)
```

The `tcp:` prefix is emitted only in the port form. With a named instance the driver must reach the
SQL Server Browser on UDP 1434 to learn the port, and pinning the protocol prefix in front of an
instance name is the kind of detail that behaves differently between driver versions; leaving it
off is the documented form.

**Where the compound-host refusal actually lives.** The first draft of this section could be read
as putting the check in `targets.py`; it is not there, and the difference matters to anyone
tracing the error. As implemented:

| Layer | What it does with `PC-ARR\SQLEXPRESS:56879` in `host` |
|---|---|
| `targets.parse_mssql_target()` | **Parses it**, returning `server='PC-ARR'`, `instance='SQLEXPRESS'`, `port=56879`, `compound=True`. It reports; it never refuses a value it understood, and it never repairs one it did not. |
| `targets.resolve_mssql_target()` | **Never sees it.** It reads columns, not a host string, and has no opinion on compoundness (§6.2). |
| `MsSqlDialect._connection_target()` | **Raises `ValueError`.** It calls `parse_mssql_target(host)` first and refuses when the result has `compound=True`, naming each piece it found. Then, and only on a bare server, it calls `resolve_mssql_target()` for the §3.3 precedence. |
| `MsSqlDialect.build_dsn()` | Inherits the refusal, because `_connection_target()` is the one place both driver branches obtain a target. |

The reason the raise sits in the dialect rather than in the leaf module is the leaf module's own
stated property: `targets.py` has no dialect and no driver import so that `connection_store.py`
can use it on a machine with nothing installed, and `connection_store` needs the parser's *result*
— it fills the split fields in the dialog, and it powers `needs_review()`, both of which require
parsing a compound host without treating it as fatal. A parser that raised on `compound=True`
could serve neither. The refusal belongs at the point where the value is about to become a
connection string and there is no longer any honest thing to do with it, which is
`_connection_target()`.

The sentence, with the split values in it:

> *The host `PC-ARR\SQLEXPRESS:56879` carries a server, an instance and a port in one field. Set
> Host to `PC-ARR`, Instance to `SQLEXPRESS` and Port to `56879`, or open the profile and choose
> "Split it for me".*

That is the difference between the old behaviour and the new one: a sentence naming the fix,
instead of error 20009. A host the *parser* rejects outright — two backslashes, a comma and a
colon together, `np:`, `(localdb)\NAME` — is re-raised by `_connection_target()` as *"the host
… cannot be used as a server address: <reason>"*, so the two failure paths read differently and
the user can tell "you typed three things in one box" from "this is not an address at all".

### 6.4 Error classification

`engine.py` gains, with the reason stated at the definition:

```python
# DB-Lib transport failures. 20009 is what a named instance whose Browser is not
# answering looks like, and it is also what a trusted-connection attempt looks
# like — it says "unavailable or does not exist", which sends people to the
# firewall. Both real causes are named in the sentence instead.
_MSSQL_TRANSPORT_ERRNOS = frozenset({20002, 20009})
```

plus a `network` text pattern for `adaptive server is unavailable` and an `auth` pattern for
`nt authority\\anonymous logon`. `_sentence()` gains a branch: when the profile names an instance,
or the host string is compound, the `network` sentence lists the three real causes — the SQL Server
Browser service is stopped, UDP 1434 is blocked, or the instance name is wrong — and offers
**"Resolve port"** as the way out.

#### 6.4a `tls`, the seventh kind

A failed TLS handshake arrives under SQLSTATE **08001** with the vocabulary of a transport
failure, so it landed in `network` — and, on a profile with a named instance, was explained to the
user as a stopped SQL Server Browser. The reported case had the Browser running and UDP 1434 open;
the actual message, under the invented one, read *"the certificate chain was issued by an
untrusted certification authority"*.

`tls` is therefore its own kind, matched **first** in `_TEXT_PATTERNS` so the transport vocabulary
in the same string cannot win. It matches on the SChannel/OpenSSL status codes as well as the
words, because msodbcsql18 localises the words and not the codes: `-2146893019`
(`SEC_E_UNTRUSTED_ROOT`), `-2146762487` (`CERT_E_UNTRUSTEDROOT`), `-2146762481`
(`CERT_E_CN_NO_MATCH`), `-2146893016` (`SEC_E_CERT_EXPIRED`).

Its sentence says what happened (the server answered; no credential was sent), why (Driver 18
encrypts and verifies by default), and the two real repairs — tick **"Trust the server
certificate"** for an internal server with a self-signed certificate, or install the issuing
authority. The Connections page paints it **amber**, not red: the server was reached, and the
profile carries the tick box that settles it.

### 6.5 `TrustServerCertificate`, and why it is a tick box

`Encrypt=yes` and `TrustServerCertificate=no` were emitted unconditionally, *before* `options_json`
was appended — so a profile that set the key got it into the ODBC string twice, with the winner
left to the driver. They are now defaults that `options_json` **replaces**.

Reaching them needed a control, because `options_json` has never been exposed in the GUI at all.
The user ruled: **one checkbox, "Trust the server certificate", MS-SQL only, stored in
`options_json`** — not a three-state encryption combo, and not a new column with a schema version 3
behind it. Unticked is the default and is today's behaviour. Ticked writes
`{"TrustServerCertificate": "yes"}`, and an italic note under it states the trade plainly: the
connection stays encrypted, but the server's identity is not checked.

`ConnectionDialog` keeps every *other* key of an edited profile's `options_json` in
`_other_options` and writes it back untouched, so ticking the box cannot silently drop a driver
option somebody set by hand, and neither can an edit that came here only to change the display
name.

---

## 7. Discovery — `src/sape_d_mcp/db/discovery.py`

### 7.0 The finding that governs this whole section

Everything below inherits one result from the implementation research, and it is stated first
because it decides the *vocabulary* of the entire feature rather than the behaviour of one source:

> **A successful `connect()` does not prove the port is reachable.** Through NAT, or through any
> proxying middlebox — a container port-forward, a VPN concentrator, an SSH tunnel, a load
> balancer, a corporate transparent proxy — a TCP connection is accepted by the *intermediary*
> and the server behind it is never consulted. This was confirmed empirically against a real SQL
> Server during the design's own research: the connection was accepted, and a protocol handshake
> over it returned nothing at all.

So an accepted TCP connection is a **candidate, never a finding**. Only the protocol's own
greeting confirms that something speaking that protocol is there, and d-MCP deliberately does not
send one (§7.4, and the rejected alternative in ADR 0003) — a handshake is a connection attempt
to a service the user has not chosen, and it lands in that server's log as a failed login.

Three consequences run through the rest of §7 and must not be quietly undone:

1. The **`label` is where the honesty lives**, and it is the field every consumer reads before it
   presents anything. A `listening-port` candidate's engine is inferred **from the port number
   alone**, and its label says exactly that: *"Something answered on 127.0.0.1:5432 — probably
   PostgreSQL, but not verified (d-MCP sends no protocol handshake during discovery)."*
   "PostgreSQL found" is not a sentence this feature is allowed to produce.
2. `confidence` is a weaker signal than its name suggests, and §7.4 documents the one place the
   code and its own docstring disagree about it. Do not build a behaviour on it without settling
   that first.
3. Nothing discovered is ever saved without a human. Selecting a candidate pre-fills the form; the
   user presses Save, and the connection test — which *does* complete a protocol handshake, with a
   credential the user supplied — is the only thing in the product allowed to say a server is
   really there.

### 7.1 Placement and shape

`src/sape_d_mcp/db/discovery.py`. In `db/` because a candidate is a database-addressing concept
and because `connections_page` is not the only plausible consumer; **it imports no PyQt6** (the
`--cli` rule) and imports no driver at module level.

```python
ORIGINS: tuple[str, ...] = (
    "windows-registry",   # HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL
    "windows-service",    # a registered service whose name matches a known pattern
    "odbc-dsn",           # a DSN already configured on this machine
    "listening-port",     # something answered a TCP connect on loopback
    "sqlite-file",        # a file whose first 16 bytes are the SQLite magic
    "sql-browser",        # an SSRP reply — UNTRUSTED, see §7.6
)

CONFIDENCE = ("confirmed", "reported")

@dataclass(frozen=True, slots=True)
class Candidate:
    engine: str                  # one of ENGINES
    host: str                    # 'localhost' for everything local
    port: int | None
    instance: str | None
    database: str | None         # a file path for sqlite, else None — never guessed
    driver_hint: str | None      # the default driver for the engine, or the DSN's own
    auth_hint: str               # one of AUTH_MODES: what this source implies
    origin: str                  # one of ORIGINS
    origin_detail: str           # 'HKLM\...\Instance Names\SQL', '127.0.0.1:5432', the DSN name
    confidence: str
    label: str                   # what the list shows: 'SQL Server — PC-ARR\SQLEXPRESS'
```

`origin` and `origin_detail` exist so the GUI can say *"found in the Windows registry"* against
*"answered on 127.0.0.1:5432"* — the user's stated requirement, and also the honest way to present
a guess. A `listening-port` candidate is a socket that accepted a connection, nothing more:
d-MCP does **not** send a protocol handshake to identify it, so 5432 means "something is there"
and the engine is inferred from the port number alone. The label says so.

```python
def discover_local(*, budget_s: float = 5.0,
                   sources: Sequence[str] = ORIGINS_LOCAL,
                   sqlite_roots: Sequence[Path] | None = None,
                   cancel: threading.Event | None = None) -> DiscoveryResult
def discover_network(*, timeout_s: float = 2.0,
                     targets: Sequence[str] = (),      # unicast hosts; empty = broadcast
                     cancel: threading.Event | None = None) -> DiscoveryResult

@dataclass(frozen=True, slots=True)
class DiscoveryResult:
    candidates: tuple[Candidate, ...]
    notes: tuple[str, ...]        # 'the registry key is not readable by this account'
    elapsed_ms: float
    truncated: bool
```

**Nothing in this module connects to a database, authenticates, or reads a credential.** No
`Candidate` ever carries a user name or a password. That property is worth a test of its own.

Every source is individually wrapped: a `PermissionError` reading a registry key, an unparsable
`odbc.ini`, an unreachable socket — each appends to `notes` and is never raised. Discovery that
half-works is useful; discovery that raises is a dialog that shows a traceback.

### 7.2 Windows registry — SQL Server instances

Stdlib `winreg`, `KEY_READ` only, never a write handle.

```
HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL
    value name  = instance name   ('MSSQLSERVER' is the default instance, 'SQLEXPRESS' a named one)
    value data  = internal key    ('MSSQL16.SQLEXPRESS')

HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<internal key>\MSSQLServer\SuperSocketNetLib\Tcp\IPAll
    TcpPort           = static port, or empty
    TcpDynamicPorts   = the current dynamic port, or empty
```

- `MSSQLSERVER` yields `instance=None, port=1433`; anything else yields the instance name.
- `TcpPort` when non-empty wins; else `TcpDynamicPorts` supplies the port **and** the candidate is
  labelled *"dynamic port — it changes when the service restarts"*, which is precisely the user's
  56879 and the reason the `instance` column exists.

  > **A string-literal coupling between `db/` and `gui/`, documented here because it exists in the
  > code and nowhere else.** `discovery.py` appends that note to `Candidate.label` as a **literal
  > English fragment**, `" (dynamic port — it changes when the service restarts)"`, and
  > `gui/dialogs/discovery_dialog.py` holds the same literal as `_DYNAMIC_PORT_MARKER`, detects
  > the suffix, strips it and substitutes the translated text before the row is shown.
  >
  > This is deliberate, and it is the least bad of the options available. `discovery.py` has **no
  > i18n dependency by design** — it is in `db/`, it must import under `--cli` with no PyQt6, and
  > `gui.i18n` is a GUI module — so it cannot hand back a translation, and it must still produce a
  > `label` that reads correctly for the CLI and for a log line. What it cannot do is announce
  > which part of that label is a translatable note, other than by the note's own text.
  >
  > **The failure mode is silent.** Edit the literal on either side — change the em dash to a
  > hyphen, drop the leading space, reword it — and nothing raises: the GUI simply stops matching,
  > and an English fragment appears inside an otherwise translated list, in every one of the
  > eighteen languages. There is no type, no test and no import that connects the two halves.
  >
  > **If this is ever revisited, the right fix is a field, not a better string.** Give `Candidate`
  > an explicit `note_key: str | None` (or a `dynamic_port: bool`) carrying the i18n key, keep
  > `label` as the human-readable fallback the CLI prints, and let the dialog render the key. That
  > is a one-field change to a frozen dataclass and removes the coupling entirely. It was not done
  > during implementation, so until it is, **the two literals must be edited together**, and a
  > test that asserts `_DYNAMIC_PORT_MARKER` is a suffix of a fixture candidate's label is the
  > cheapest guard available today.
- Opened with `KEY_WOW64_64KEY` as well as the default view, because a 32-bit interpreter
  otherwise reads `WOW6432Node` and finds nothing on a normal 64-bit install.
- `auth_hint='integrated'` and `driver_hint='pyodbc'`: a locally registered SQL Server on Windows
  is overwhelmingly reached by a trusted connection, and `pyodbc` is the only driver that can.
- On every non-Windows platform the source is skipped silently — `import winreg` inside the
  function, not at module top.

### 7.3 Windows services

Same `winreg`, `HKLM\SYSTEM\CurrentControlSet\Services`, matching a small table of name patterns:
`MSSQLSERVER`, `MSSQL$*`, `SQLBrowser`, `postgresql*`, `MySQL*`, `MariaDB*`. Yields the engine and
whether the service is set to start; the port comes from §7.2 or §7.4, never from the service.

**No subprocess and no `psutil`.** Shelling out to `sc query` or `systemctl` from a GUI is a
portability and quoting problem for information the registry and a socket probe already give, and
`psutil` is a dependency this feature does not earn. On Linux and macOS this source is skipped and
§7.4 covers it.

### 7.4 Listening ports on loopback

`socket.connect_ex` against `127.0.0.1` and `::1`, 250 ms each, at most 8 concurrent through a
`ThreadPoolExecutor`, over a fixed table:

| Port | Engine inferred |
|---|---|
| 1433 | mssql |
| 1434/udp | — the SQL Server Browser; noted, not itself a candidate |
| 5432 | postgresql |
| 3306 | mysql |
| 33060 | mysql (X Protocol — noted, the candidate is still offered on 3306) |

**Loopback only.** Two extra ports may be probed on demand: when the user has already typed a host,
the dialog offers *"check this host"*, which probes those four ports on that one host — a host the
user named, which is not a scan.

`confidence='confirmed'` — **and read §7.0 before assuming that means what it looks like.** As
implemented, `confidence` records how solid the *observation* is, not how solid the *identification*
is: a socket really did accept a connection, so the observation is confirmed, while the engine
attached to it is inferred from the port number alone and may be wrong, and through NAT or a
proxying middlebox the acceptance may not even have come from the machine the port is on.

That distinction is carried entirely by the **label**, which is written to be read as the finding
itself:

> *Something answered on 127.0.0.1:5432 — probably PostgreSQL, but not verified (d-MCP sends no
> protocol handshake during discovery).*

`auth_hint='password'`, because nothing about an open socket implies an identity.

> **A known inconsistency, recorded rather than papered over.** `discovery.py`'s own module
> docstring says `'confirmed'` is given only to a source that *"inspects the service itself — the
> registry, an already-configured ODBC DSN, a verified SQLite header"*, and then
> `_discover_listening_ports()` assigns `'confirmed'` too. Both readings are defensible — "the
> probe is confirmed" against "the service is confirmed" — but only one can be true of the field,
> and the code and its own docstring currently disagree about which. **Nothing depends on it
> today:** every consumer that must not overstate a finding reads the `label` and the `origin`,
> not `confidence`, and the label is unambiguous. It is written down here so that whoever gives
> `confidence` a load-bearing job — sorting the list, hiding the weak entries, colouring a row —
> settles the question first, in one place, rather than inheriting the ambiguity.

### 7.5 ODBC DSNs

- **Windows:** `HKCU\Software\ODBC\ODBC.INI` and `HKLM\Software\ODBC\ODBC.INI` — each subkey is a
  DSN, with `Driver`, `Server`, `Port`, `Database` values. The MS-SQL `Server` value goes through
  `parse_mssql_target()`, which is the same normaliser the user's typing goes through.
- **Linux/macOS:** `configparser` over `~/.odbc.ini` and `/etc/odbc.ini` (plus `ODBCINI` when set).
- **Never** `pyodbc.dataSources()` at import time; it is tried inside a `try/except ImportError`
  and skipped when pyodbc or the driver manager is absent.
- Password-shaped keys in a DSN section (`PWD`, `Password`) are **not read** — not stored, not
  logged, not put in `origin_detail`. The reader allowlists the four keys it wants.
- The driver string is mapped to an engine by keyword (`sql server` → mssql, `postgres` → postgresql,
  `mysql`/`mariadb` → mysql, `sqlite` → sqlite); an unrecognised driver yields no candidate.

### 7.6 SQLite files

`.db`, `.sqlite`, `.sqlite3`, `.db3` under a bounded set of roots — the current working directory
and `~/.sape/d-mcp/` by default, plus whatever the caller passes in `sqlite_roots` — walked to
**depth 2** (`_SQLITE_MAX_DEPTH`), skipping dot-directories, `node_modules`, `.git`, `venv`,
`__pycache__`, and capped at **200 results** (`_SQLITE_MAX_RESULTS`), 20 000 directory entries
examined (`_SQLITE_MAX_ENTRIES`) and one second.

**This scope is the user's own ruling (§13 D4), not a default awaiting review.** The automatic
search never widens beyond the working directory and two levels below it; reaching anywhere else
is a deliberate act, through the dialog's **"Search a folder…"** button, which supplies the chosen
directory as a `sqlite_roots` entry for that one run and remembers nothing. The home directory is
never walked automatically. A candidate is emitted only when the first 16 bytes are `SQLite format 3\0`; the file is
opened `'rb'`, read, closed. **No SQL is executed against a discovered file** — not even
`PRAGMA schema_version`, since opening an untrusted SQLite file with the library is itself an
attack surface, and the header check answers the question asked.

d-MCP's own `connections.db`, `permissions.db` and `audit.db` are excluded by name.

Walking the whole home directory is deliberately not done: it is slow, and a list of every SQLite
file a user owns is a small privacy problem to put on screen.

### 7.7 The local network: SQL Server Browser

The one source that emits traffic beyond this machine, and the one with a policy attached.

**Protocol.** One UDP datagram containing the single byte `0x02` (CLNT_UCAST_EX / CLNT_BCAST_EX)
sent to port 1434, at the IPv4 broadcast address — `255.255.255.255` and each interface's directed
broadcast where they can be enumerated from `socket` alone. Each responding instance replies with a
`0x05` header and a `;`-delimited payload:

```
ServerName;PC-ARR;InstanceName;SQLEXPRESS;IsClustered;No;Version;16.0.1000.6;tcp;56879;;
```

`tcp;<port>` is present only when the instance is listening on TCP — which is exactly the dynamic
port that cannot be known any other way.

**Policy — this is the part that matters.**

1. **Never automatic.** Not on dialog open, not on page load, not on a timer, not as a fallback
   when local discovery finds nothing. It runs when a human presses *"Search the local network"*
   and at no other time.
2. **A confirmation first, once per session.** A `QMessageBox` constructed explicitly (so its
   buttons are translated) states what is about to happen, in the user's language:

   > *d-MCP will send one small UDP message to the local network's broadcast address, port 1434,
   > asking any Microsoft SQL Server to identify itself. It sends no user name and no password.
   > Some corporate networks log or block this kind of message. It will wait about 2 seconds for
   > replies.*
   > **[ Search ] [ Cancel ]**

   **Asked once per process, and the acceptance is never written to disk** (§13 D5 — the user
   ruled against this document's original "every single time"). The acceptance lives on one
   attribute of the running `SAPEApplication`, `_dmcp_network_discovery_confirmed`, and dies with
   the process: a fresh launch asks again, and `config.json` never learns that anyone ever agreed.
   There is no "don't ask again" checkbox, because that phrase means *persisted*, and persisting
   it is the thing that was refused.

   The line this draws is the one that matters: the confirmation broker's ruling is that no
   approval is ever remembered **across runs**, and that is upheld exactly. Within one run, a
   human who has read the warning and pressed *Search* has consented to that action in that
   session, and re-reading the same paragraph on every click trains people to dismiss it unread —
   which is a worse security outcome than asking once and meaning it. A `DROP` is different
   because each `DROP` destroys a different thing; each broadcast sends the identical datagram.
3. **Short and bounded.** `timeout_s` defaults to 2.0, hard-capped at 5.0. The socket is opened
   with `SO_BROADCAST`, a receive timeout, `bind(('', 0))` — an ephemeral port, never 1434 — and is
   closed in a `finally`. At most **64** replies are accepted and at most **4096 bytes** per
   datagram are read; beyond either, the result is marked `truncated` and the loop stops.
4. **Audited.** One row in `audit.db` through the existing `LogStore.log_tool()`, with
   `connection_id=None` (the Logs page's System tab), `session_id='gui'`,
   `tool_name='discover-network'`, `params_json={'timeout_s': 2.0, 'scope': 'broadcast'}`,
   `decision='allowed'` and `result='7 replies from 3 hosts'`. **A cancelled confirmation is logged
   too**, with `decision='refused'` — "the operator was asked and said no" is worth more in an
   audit trail than silence.
5. **Not an MCP tool, now or later.** Stated in the module docstring, so nobody wires it into the
   catalogue as a convenience.

### 7.8 Everything from the network is untrusted input

An SSRP reply is an unauthenticated UDP datagram from an unauthenticated source. Anything on the
segment can send one, and can send many. Every field is validated before it becomes a `Candidate`,
and validation **rejects** rather than repairs:

| Field | Rule |
|---|---|
| `ServerName` | `^[A-Za-z0-9._\-]{1,63}$` — no backslash, no comma, no colon, no space, no control character, no non-ASCII |
| `InstanceName` | `^[A-Za-z0-9_$#][A-Za-z0-9_$#\-]{0,15}$` |
| `tcp` port | all digits, 1–65535 |
| `Version` | printable ASCII, truncated to 32 characters, **display only** |
| unknown keys | ignored |
| the datagram | ≤ 4096 bytes, must start with `0x05`, must decode as ASCII |

Rationale, item by item, because each is a real vector: a `ServerName` carrying a backslash would
reconstruct a compound host and defeat §6; one carrying a `;` could forge extra fields; one
carrying an ANSI escape or a right-to-left override could misrepresent itself in a list widget; a
long one could push the real entries off screen. Replies are deduplicated on
`(server, instance, port)` and sorted, and the source address of the datagram is compared with the
advertised `ServerName` — a mismatch is kept but labelled *"reported by <ip>"*, since a server may
legitimately advertise a name that does not resolve from here.

`confidence` is always `'reported'` for this source. The GUI shows those candidates in a separate,
visually distinct section headed *"Reported by the network — not verified"*, and **selecting one
fills the form for review; it never saves a profile and never connects.** The human presses Save.

### 7.9 Threading contract for the GUI

`discovery.py` is synchronous and blocking. The Qt layer is specified here so the `uix-designer`
implements one agreed shape:

```python
class _DiscoveryWorker(QThread):
    """Mirrors _ConnectionTestWorker in connections_page.py."""

    found     = pyqtSignal(object)   # one Candidate, emitted as it is produced
    completed = pyqtSignal(object)   # DiscoveryResult
    failed    = pyqtSignal(str)      # a sentence, never a traceback

    def __init__(self, mode: str, options: dict, parent=None): ...
    def cancel(self) -> None: self._cancel.set()
    def run(self) -> None: ...
```

Binding rules, each traceable to a defect this project has already met:

1. **One worker at a time.** The dialog holds `self._worker: _DiscoveryWorker | None`, guards on
   `isRunning()`, and disables the button while it runs — stage 9 fixed three concurrent
   `_SchemaLoadWorker` threads started by three quick combo changes, and this is the same shape.
2. **Cancellation is cooperative.** A `threading.Event` is passed into `discover_*` and polled
   between sources and between socket probes. `QThread.terminate()` is never called.
3. **`closeEvent` and `reject()` cancel and `wait(3000)`** before the dialog is destroyed — f-MCP
   defect 9 is a `closeEvent` that never stopped its thread.
4. **`Candidate` is `frozen=True, slots=True`** and carries only `str`, `int` and `None`, so a
   queued cross-thread signal cannot hand the GUI a mutable object the worker still holds.
5. **The worker touches no widget, no `ConnectionStore` and no `CredentialStore`.** It computes and
   emits; the dialog decides what to show and the page decides what to save.
6. **The confirmation for §7.7 is raised on the GUI thread, before the worker is created** — a
   worker that asks permission is a worker that can block on a modal from the wrong thread.
7. Local discovery is streamed (`found` per candidate) so the list fills as it goes and a slow
   source cannot make the dialog look frozen; network discovery emits `completed` once, after its
   fixed timeout.

---

## 8. Database enumeration

### 8.0 The finding that governs this whole section

As §7.0 is to discovery, this is to enumeration, and it is stated first because it decides what
the feature is *allowed to claim*:

> **An account without the privilege to see every database gets a SHORT LIST, not an error.** All
> three server engines filter their catalogue silently, server-side, for the connected principal.
> Nothing raises. Nothing is flagged. The query succeeds and simply returns fewer rows.

The consequence is the one that catches people: **there is no exception to catch, so the graceful
degradation cannot be driven off an error path.** There is no `try/except` that could distinguish
"this login may not see the other databases" from "this server really has three databases", and
adding a privilege probe to tell them apart would be asking the server a question the user did not
authorise. Both look identical from the client, and they always will.

So the design does not try. It makes the *uncertainty* the permanent, unconditional state of the
control:

- The combo is **editable at all times**, and a name the list does not contain is fully valid. That
  is the design, not a fallback (§8.4).
- The sentence under the combo is shown **always**, not only after a suspected failure — because
  the moment it is conditional, the condition is a guess.
- Enumeration failing, or returning nothing at all, **never blocks Save**. The connection test is
  the gate; this is a convenience.

Per engine: MS-SQL's `sys.databases` is permission-filtered, so a login without `VIEW ANY
DATABASE` sees `master`, `tempdb` and what it owns or is mapped into. MySQL's
`information_schema.schemata` shows only schemas the account holds a privilege on — frequently
just `information_schema` itself, which is a correctly configured account and not a broken one.
PostgreSQL is the odd one: `pg_database` is world-readable so the *list* is complete, but
`datallowconn` does not mean *this* role may connect, which is why `has_database_privilege(...)`
is a returned column and never a `WHERE` clause.

### 8.1 The user-visible behaviour

The Database field becomes a `QComboBox` with `setEditable(True)`, with a **"Find databases"**
button beside it. Pressing it uses the host, port, instance, authentication mode and — for a
`password` profile — the password currently typed in the dialog, connects, asks the server, and
fills the drop-down. The field stays editable throughout, and typing a name the list does not
contain remains valid. That is not a fallback; it is the design (§8.4).

The button is disabled for SQLite (the Browse button already covers it) and while the host, or a
required password, is empty.

### 8.2 The query, per dialect

New abstract members on `Dialect`, so all four engines stay symmetric and the
`DESIGN-DIALECTS.md` §8 conformance checklist grows four rows:

```python
@abstractmethod
def list_databases(self, *, include_system: bool = False) -> Query: ...

@property
@abstractmethod
def bootstrap_database(self) -> str | None: ...

SYSTEM_DATABASES: ClassVar[frozenset[str]]
```

**The result shape is a contract, not an illustration.** As implemented — and as
`engine._split_system_rows()` reads it — every `list_databases()` on every engine returns:

- **the first column is the database name**, and it is the only column a caller may rely on
  positionally for the name;
- **the last column is an `is_system` flag**, `1`/`true` for a database the engine installed for
  itself and `0`/`false` otherwise;
- **between them, whatever metadata that engine can report for free** — state, collation, owner,
  encoding, character set, a connect-privilege test. It is deliberately *not* a single-column
  `SELECT name`: the research prototype these statements come from already returned metadata plus
  the flag, both implementers coded against that, and the columns are what let the dialog show
  *why* a database is offered and disabled rather than silently dropping it.

`include_system` is a **filter added on top of that shape**, never a change of shape. `False` (the
default) appends the engine's system predicate to the `WHERE`; `True` drops the predicate and
nothing else. The `is_system` column is present either way, because system databases are *marked*
rather than hidden — a user administering `msdb` must be able to select it — and because the flag
also drives the `ORDER BY is_system, <name>` every engine ends with, so the user's own databases
sort first.

`SYSTEM_DATABASES` is the same knowledge as a Python frozen set, for a caller holding a name it
did not get from a query. `engine.list_server_databases()` unions the two, so a database that
`include_system=False` filtered out is still recognised as a system one if it arrives from
elsewhere.

The first column is aliased `database_name` on **all four** engines, so a caller that prefers to
read the result by name rather than by position can do so with one name; `is_system` is the alias
of the last. The engines differ only in what sits between them.

| Engine | Columns returned, in order | System filter when `include_system=False` | `SYSTEM_DATABASES` |
|---|---|---|---|
| MS-SQL | `d.name AS database_name`, `state_desc`, `collation_name`, `is_read_only`, `is_system` | `database_id > 4` **and** the conventional set (`distribution`, `SSISDB`, `ReportServer`, `ReportServerTempDB`), on top of the always-applied `state_desc = 'ONLINE' AND HAS_DBACCESS(d.name) = 1` | `master, model, msdb, tempdb` |
| PostgreSQL | `d.datname AS database_name`, `owner`, `encoding`, `datcollate`, `can_connect`, `is_system` | `datname <> 'postgres'` — the templates are already excluded by the always-applied `datallowconn AND NOT datistemplate`, which is catalogue fact rather than a name list | `postgres, template0, template1` |
| MySQL / MariaDB | `s.SCHEMA_NAME AS database_name`, `DEFAULT_CHARACTER_SET_NAME`, `DEFAULT_COLLATION_NAME`, `is_system` | `SCHEMA_NAME NOT IN ('mysql', 'information_schema', 'performance_schema', 'sys')` | the same four |
| SQLite | `'main' AS database_name`, `0 AS is_system` — one synthetic row, and the only two-column result | none; the flag is constant `0` | empty |

`engine._split_system_rows()` is the reference reader of this contract, and it reads it
**defensively on purpose**: it takes `row[0]` as the name and `row[-1]` as the flag, and where a
row has only one column it takes the name and records no flag rather than treating the name as its
own system marker. A dialect caught mid-change therefore degrades to "names, no flags" instead of
taking the Find-databases button down with it — which is why the SQLite row above, the narrowest
of the four, is still two columns and not one.

Notes that survive from the first draft, because they are still the reasons:

- **MS-SQL.** `state_desc = 'ONLINE'` comes first because `HAS_DBACCESS` returns `NULL` for a
  database that is offline or restoring, and `NULL = 1` is not true; the explicit state test is
  what lets the GUI explain an absence instead of dropping a name the user expected. `sys.databases`
  is itself permission-filtered, so a login without `VIEW ANY DATABASE` gets a short list and
  **not** an error.
- **PostgreSQL.** `has_database_privilege(current_user, oid, 'CONNECT')` is a *returned column*,
  never a `WHERE` clause: a database the role can see but not open should be listed and disabled,
  so the user learns it exists and who to ask.
- **MySQL / MariaDB.** **Not `SHOW DATABASES`.** `SHOW` is a dialect statement `sql_guard` has no
  reason to learn to classify, and teaching a security chokepoint a new statement family to fill a
  combo box is a bad trade. `information_schema.schemata` is ordinary SQL, already classified as a
  read, and the server filters it to what the account may see.
- **SQLite.** `PRAGMA database_list` is **not** used: it reports `temp` and anything `ATTACH`ed,
  neither of which a profile may name (decision D9). The method exists — returning `main`, matching
  the "canonicalised to `main`" ruling — only so that every caller above it stays written against
  four engines; the GUI never calls it and the Find-databases button is hidden for SQLite.

Each statement is fixed and parameterless. It runs through the same `read_only_session()` and
`apply_statement_timeout()` path as anything else, and — because it is a plain `SELECT` — through
the same `SqlGuard` classification. Nothing here is a special case in the guard, which is the point
of choosing `information_schema.schemata`.

### 8.3 What it connects to when the target database is unknown

`engine.list_server_databases(profile, password=None, *, timeout_s=10)` builds a **bootstrap
profile**: a copy of the profile with `database` replaced, since every driver needs *some* initial
catalogue.

| Engine | Bootstrap `database` | Fallback chain |
|---|---|---|
| MS-SQL | `master` | the typed value, if any, is tried first: a contained-database user cannot open `master` and can open only their own database |
| PostgreSQL | the typed value if non-empty, else `postgres` | `postgres` → `template1` → the OS/`PGUSER` name (the `psql` convention) |
| MySQL | `information_schema` | none needed; every account may see it |
| SQLite | n/a | the button is hidden |

Each attempt is a full `connect()` with `probe=False` (no version probe — the traits are irrelevant
here and the round trip is not free), the query, then close. The chain stops at the first success;
if all fail, the *last* error is classified and shown, since it is the most specific.

The connection is opened `read_only`, its statement timeout is clamped to 10 s regardless of the
profile's own budget (this is an interactive click, not an analytical query), and it is closed in a
`finally`. The password, when there is one, lives only on the worker object, exactly as
`_ConnectionTestWorker` already does.

### 8.4 When the user may not enumerate

**The list is never authoritative, and the UI says so.** All three engines answer a
permission-restricted enumeration by returning *fewer rows*, not by raising:

- MS-SQL: without `VIEW ANY DATABASE`, `sys.databases` returns only `master`, `tempdb` and the
  databases the login owns or is mapped into.
- PostgreSQL: `pg_database` is world-readable, so the list is complete — but `datallowconn` does
  not mean *this* role may connect.
- MySQL: `information_schema.schemata` shows only schemas the account has a privilege on.

So the failure mode is a short list, which is indistinguishable from a small server. The dialog
therefore always shows, under the combo:

> *This list shows only the databases this account is allowed to see. You can type a name that is
> not listed.*

And the combo stays editable. If the query itself raises — the login cannot open the bootstrap
database, or the account lacks `SELECT` on `information_schema` — the error is classified by
`classify_error()`, shown as a sentence, the combo is left with whatever the user typed, and Save
stays enabled. **Enumeration failing never blocks saving a profile**; the connection test is the
gate, not this.

### 8.5 Permissions and the read-only model

Stated explicitly because it will be asked:

- Enumeration is performed **by the GUI, for the human**, using a credential that human supplied,
  before any permission rule for the profile need exist. It is not gated by `permissions.db`,
  because `permissions.db` gates *the model*, and the model is not involved. The human could
  already type any name into the field.
- **No MCP tool is added.** `list-databases` is not in the catalogue and is not proposed for it.
  The 38-tool surface is unchanged, and `tests/test_generated_config.py`'s literal name list stays
  as it is.
- The session is opened read-only through the existing `read_only_session()`, and the statement is
  a `SELECT` that the guard classifies as a read. Nothing in this feature can write.
- The audit trail gets one row (`tool_name='list-databases'`, `session_id='gui'`,
  `connection_id` where known, `decision='allowed'`), for the same reason §7.7 does: an action
  that opens a connection to a server should be visible afterwards.

---

## 9. GUI changes, specified for the `uix-designer`

**`gui/dialogs/connection_dialog.py`.** New Authentication combo between Driver and Host, holding
`AUTH_MODES` filtered by `support_for()`; an unsupported item is present but disabled, with the
matrix's message as its tooltip and echoed in an inline warning label. A new Instance field, shown
only for MS-SQL, with a **Resolve port** button that runs a unicast SSRP query against the typed
host (§7.7's confirmation is **not** required for a unicast query to a host the user typed — no
broadcast leaves the machine — but it is still audited). The Database line becomes an editable
combo plus **Find databases**. The user-name and password rows are enabled by the authentication
mode, not hidden, so the form does not jump. All of it driven by one `_apply_engine_layout()`
extended to `_apply_shape(engine, driver, auth_mode)`.

**`gui/pages/connections_page.py`.** A **Discover** button on the toolbar; an amber marker and
tooltip on any row `needs_review()` flags; the existing single-worker guard reused.

**`gui/dialogs/discovery_dialog.py`** (new). A tree with one group per origin, the network group
visually separated and headed *"Reported by the network — not verified"*, a **Search the local
network** button carrying the §7.7 confirmation (raised once per session, held on
`SAPEApplication._dmcp_network_discovery_confirmed`, never persisted), a **"Search a folder…"**
button that adds one user-chosen root to the SQLite walk for that run only (§13 D4), a cancel that
actually cancels, and *Use this* which closes and returns a `Candidate` for the connection dialog
to pre-fill. It saves nothing.

It also owns `_DYNAMIC_PORT_MARKER`, the second half of the string-literal coupling documented in
§7.2: it strips that exact English fragment off a candidate's `label` and substitutes the
translated note. **The two literals must be edited together**, and neither side has any way to
notice if they are not.

All new strings go into the **generated** i18n catalogue by regeneration, with `en-US` and `es-ES`
authored and the other sixteen carrying English, as the shipped catalogue already does.

---

## 10. Testing

The `qa-specialist`'s brief, in the project's own style — names are sentences and the module
docstring narrates the bug being pinned.

**Migration.** A checked-in v1 fixture `connections.db` holding one row per engine, including one
MS-SQL row with `host = 'PC-ARR\SQLEXPRESS:56879'`. Assert: it opens; `user_version` becomes 2;
every row survives with the right `auth_mode`; the backup file exists; opening it a second time is
a no-op; a v3 file is refused; a read-only file fails with the existing sentence, not a traceback.
`test_a_v1_row_cannot_violate_the_v2_constraint` runs the INSERT..SELECT against a generated set of
every legal v1 shape.

**Constraints, at the SQLite level, not through `_validate()`** — the CHECK is the second line of
defence and must be tested as one: `integrated` with a user name is rejected; `password` without
one is rejected; `none` on MS-SQL is rejected; an `instance` on PostgreSQL is rejected; a
non-SQLite row with neither port nor instance is rejected.

**The matrix.** Parametrised over `INTEGRATED_SUPPORT`, itself checked to cover every
`(engine, driver)` in `DRIVERS_BY_ENGINE`. `test_pymssql_can_never_hold_integrated_authentication`
asserts the refusal at all three layers — validator, DSN builder, and the GUI's disabled item.

**DSN.** Golden strings for all eight `(driver × auth_mode × port/instance)` MS-SQL combinations;
`Trusted_Connection=yes` present with no `UID`; no `PWD` ever; psycopg omitting `user` under
`integrated`.

**Host parsing.** The whole §6.1 table as a parametrised test, plus the rejections: two
backslashes, a comma *and* a colon, `np:`, `(localdb)\X`, a port of 0, a port of 70000, an
unterminated `[`, an embedded newline, an embedded NUL.

**Credentials.** `password` → `integrated` deletes the keyring entry (mocked keyring, as the
existing tests do); `connect()` with a password on an `integrated` profile raises `ValueError`;
a stale entry is never read.

**Discovery.** Registry, ODBC and socket sources faked. The SSRP parser gets its own hostile
corpus: over-long datagram, missing header byte, `ServerName` with a backslash, with a `;`, with
a NUL, with an ANSI escape, with 400 characters, with non-ASCII; 500 replies from one host;
replies after the timeout. `test_a_discovered_candidate_never_carries_a_credential` asserts no
`Candidate` field ever holds one. `test_network_discovery_is_never_started_without_confirmation`
and `test_a_refused_network_search_is_still_audited`.

**Enumeration.** Per dialect, the exact statement and the system filter; the bootstrap fallback
chain (a fake connect that fails on `master` and succeeds on the typed database); a permission
error leaving the combo editable and Save enabled.

**Threading.** `pytest-qt`: two rapid clicks start one worker; closing mid-run cancels and does not
hang; `terminate()` is never called.

**And the invariant that must not move:** an empty `permissions.db` still authorises nothing. None
of this touches the permission engine, and a test asserts the tool catalogue is still exactly 38
names.

Integration tests against a real MS-SQL follow the existing `DMCP_TEST_PROFILE_MSSQL` convention
and skip with a named variable. Windows-only paths are marked and skipped elsewhere — which means
§7.2, §7.3 and the SSPI half of §4.1 are **verified on Linux only by fake**, and that belongs in
`docs/CROSS-PLATFORM-SMOKE-TEST.md` as a new numbered section rather than being quietly assumed.

---

## 11. Dependencies

**None are added.** `winreg`, `socket`, `configparser`, `struct`, `threading` and `pathlib` are all
standard library; `winreg` exists on Windows only and is imported inside the function that needs
it. Kerberos for §4.1 on Linux is a *system* prerequisite (`krb5-user`, a `krb5.conf`, a ticket),
not a Python package, and belongs in the README's install notes beside the existing `msodbcsql18`
instructions — not in `requirements.txt`.

The `deployment-specialist` still has work: `sape-d-mcp.spec` must be checked for the new module,
and the PyInstaller warning that fires when `collect_submodules()` drops a driver should be
extended to notice a dropped `winreg` on a Windows build.

---

## 12. Implementation tasks, in order

Each task names the agent that owns it. Nothing here was started before the user ruled on §13;
**all twenty-two are now complete**, and the whole suite passes. Two tasks landed differently from
the plan and the differences are recorded where they belong rather than here: task 4 applies the
compound-host split as parametrised `UPDATE`s rather than inside the `INSERT..SELECT` (§3.5), and
task 9's `list_databases()` returns the metadata-plus-flag shape rather than a single `name`
column (§8.2). In both cases the code is the contract and this document has been corrected to it.

| # | Task | Owner | Depends on |
|---|---|---|---|
| 1 | `db/auth_modes.py`: `AUTH_MODES`, `AuthSupport`, `INTEGRATED_SUPPORT`, `support_for()`, and the conformance test against `DRIVERS_BY_ENGINE` | **db-specialist** | — |
| 2 | `db/targets.py`: `MsSqlTarget`, `parse_mssql_target()`, `resolve_mssql_target()` | **python-senior** | — |
| 3 | `connection_store.py`: the v2 `SCHEMA`, `_auth_mode_check()`, `_PROFILE_COLUMNS`, `_validate()` for `auth_mode`/`instance`/host parsing, `needs_review()` | **db-specialist** | 1, 2 |
| 4 | `connection_store.py`: `SCHEMA_VERSION = 2`, `_MIGRATIONS`, `_migrate_1_to_2()` with the `VACUUM INTO` backup, and the `_MIGRATABLE_COLUMNS` comment | **db-specialist** | 3 |
| 5 | v1 fixture database + the migration test suite | **qa-specialist** | 4 |
| 6 | Dialects: `build_dsn()` for `integrated` on `mssql`/`postgres`, the `pymssql` refusal, both MS-SQL server forms through `resolve_mssql_target()`, the compound-host `ValueError` | **db-specialist** | 2, 3 |
| 7 | `engine.py`: refuse a password on a non-`password` profile; `_MSSQL_TRANSPORT_ERRNOS`; the anonymous-logon and 20009 patterns; the named-instance sentence | **python-senior** | 6 |
| 8 | `connection_store.update()` purges an orphaned credential on a transition away from `password`, and its test with a mocked keyring | **db-specialist** | 3 |
| 9 | Dialects: `list_databases()`, `bootstrap_database`, `SYSTEM_DATABASES` on all four; `DESIGN-DIALECTS.md` §8 checklist rows | **db-specialist** | — |
| 10 | `engine.list_server_databases()` with the bootstrap fallback chain, read-only session, 10 s clamp | **python-senior** | 9 |
| 11 | `db/discovery.py`: `Candidate`, `DiscoveryResult`, `discover_local()` and the four local sources | **python-senior** | 2 |
| 12 | `db/discovery.py`: `discover_network()`, the SSRP encoder/parser and the §7.8 validation | **db-specialist** | 11 |
| 13 | Audit rows for network discovery (allowed **and** refused) and for enumeration, through the existing `LogStore` | **python-senior** | 11, 12 |
| 14 | Hostile-input corpus for the SSRP parser; the no-credential-in-a-candidate test; the no-new-MCP-tool test | **qa-specialist** | 12 |
| 15 | `connection_dialog.py`: Authentication combo, Instance field + Resolve port, editable Database combo + Find databases, `_apply_shape()` | **uix-designer** | 1, 3, 10 |
| 16 | `discovery_dialog.py` + `_DiscoveryWorker` to the §7.9 contract, including the §7.7 confirmation | **uix-designer** | 11, 12 |
| 17 | `connections_page.py`: Discover button, review markers, single-worker guard | **uix-designer** | 15, 16 |
| 18 | Regenerate the i18n catalogue with the new keys, `en-US` and `es-ES` authored | **uix-designer** | 15, 16, 17 |
| 19 | GUI tests: threading contract, the confirmation gate, the disabled `pymssql` item | **qa-specialist** | 15–17 |
| 20 | `DESIGN-DATA-MODEL.md` §3.3/§3.4 updated to v2; `DESIGN-DIALECTS.md` §5 gains the auth column; `CHANGELOG.md`; README "Known limitations" gains MySQL system authentication and the dynamic-port caveat | **software-architect** | all |
| 21 | `sape-d-mcp.spec` checked for `discovery.py`/`targets.py`/`auth_modes.py`; the `winreg` warning on Windows builds; README install note for Kerberos on Linux | **deployment-specialist** | 11 |
| 22 | `CROSS-PLATFORM-SMOKE-TEST.md`: new sections for Windows registry discovery, a real trusted connection, and the LAN broadcast — the three things the Linux VM cannot prove | **qa-specialist** | all |

---

## 13. Decisions taken by the user

This section began as six questions, each with a recommendation and each explicitly *not* decided
unilaterally. The user has ruled on all six. **Two of the rulings went against this document's own
recommendation**, and those two are recorded at length — not to relitigate them, but because a
decision that overrides a stated objection has to carry the safeguards that made accepting it
reasonable, and those safeguards are now load-bearing code that must not be simplified away by
someone who never read the argument.

Each entry keeps the original question and recommendation so the trade-off stays visible, then
states the ruling and what implements it.

### D1 — Instance and port in the dialog *(recommendation accepted)*

**Asked:** the schema permits both an instance and a port (§3.3), with the port taking precedence.
Should the dialog additionally clear the port when an instance is typed, making the two exclusive
on screen? **Recommended:** yes.

**Ruled:** yes. The dialog makes them exclusive so the precedence cannot be tripped over, and
**Resolve port** puts a port back explicitly, as a visible act. The schema is unchanged and still
permits both — a hand-edited row, or one arriving from the migration, is legal and §3.3's
precedence decides it at connect time.

### D2 — A dynamic port that has moved *(recommendation OVERRULED)*

**Asked:** SQL Express commonly uses a dynamic port; the user's own 56879 changes at the next
service restart. When a connection to a pinned port fails and the profile also names an instance,
should d-MCP **automatically** re-resolve the port through the SQL Server Browser and retry?
**Recommended: no.** The objection was that it is unsolicited network traffic on a failure path,
and a **"Re-resolve port"** button in the error banner was offered instead.

**Ruled: yes — retry automatically.** The user's counter-argument is the one the recommendation
under-weighted: a user whose connection worked yesterday and does not today should not have to
understand SSRP, dynamic ports and the Browser service in order to press the right button. The
application knows exactly what happened and can fix it.

**The safeguards imposed in accepting it**, all in `engine.py` and all of them conditions on the
retry rather than decorations around it:

1. **Exactly one retry, never a loop.** The retried `connect()` is called with `_ssrp_retried=True`
   and that flag suppresses any further attempt. There is no back-off, no second try and no
   recursion, because the failure this exists to fix is a stale port, and a stale port is fixed on
   the first correct answer or not at all.
2. **Unicast only, to the profile's own host.** `ssrp.instances_on_host(host)`, never
   `instances_on_local_network()`, never a broadcast. Nothing leaves the machine that was not
   already leaving it: the connect attempt that just failed went to that same host. This is why
   the §7.7 confirmation is *not* required here and why requiring it would be theatre.
3. **A bounded timeout.** `_SSRP_RESOLVE_TIMEOUT_S = 1.5`, deliberately shorter than the discovery
   default, because this runs inline on an already-failed connect and must not turn one slow
   failure into a second, equally slow one.
4. **An audit row naming the port it came from and the port it went to.** One
   `log_tool(..., 'resolve-instance-port', {'instance': …, 'old_port': …, 'new_port': …})` per
   re-resolution, written whether or not the Browser answered, so an operator reading `audit.db`
   can see that the application changed the port it dialled and can see both values. Auditing is
   best-effort and never fatal: a failed log write must not turn a successful retry into a failed
   connection.
5. **No retry if the port did not change.** `new_port is None or new_port == old_port` returns
   `None` and the original exception propagates unchanged. Re-dialling the identical address would
   produce the identical failure one and a half seconds later, and would replace a correct error
   message with a slower one.
6. **Narrowly gated besides.** MS-SQL only, the profile must name an `instance`, and
   `classify_error(exc)` must be `'network'` — an authentication failure is never retried, because
   a login the server has already refused does not become acceptable on a different port, and
   retrying one is how an account gets locked out.

Where a re-resolution succeeds, the new port is used for that connection only; the stored profile
is not silently rewritten.

### D3 — MySQL over a Unix socket *(recommendation accepted)*

**Asked:** should an `options_json` key `unix_socket` be added to enable `auth_socket` on Linux?
**Recommended: not now.** **Ruled: not now.** It needs its own honest relaxation of the host/port
constraint and it serves a narrow case. §4.4 stands, MySQL system authentication is documented as
unsupported, and that is a "Known limitations" entry in the README rather than a silent gap.

### D4 — SQLite discovery scope *(recommendation accepted)*

**Asked:** §7.6 searches the working directory and `~/.sape/d-mcp/`. Should the home directory, or
a user-chosen folder, be offered too? **Recommended:** a folder the user points at, rather than a
wider default.

**Ruled:** the automatic scope is **the working directory plus two levels below it and no more**
(`_SQLITE_MAX_DEPTH = 2`), and anything further is a **manual "Search a folder…"** in the
discovery dialog, which supplies that directory as an extra root for one run and remembers
nothing. The home directory is never walked automatically. A list of every SQLite file a user owns
is a privacy consideration and not merely a slow scan.

### D5 — The network-search confirmation *(recommendation OVERRULED, narrowly)*

**Asked:** §7.7 asked for confirmation on every single search, with no "don't ask again", by
analogy with the confirmation broker. **Recommended:** keep it every time.

**Ruled: confirm once per session, and never persist the acceptance to disk.** The first press in
a given run of the application shows the warning; subsequent presses in that same run do not. The
acceptance lives on one attribute of the running `SAPEApplication`
(`_dmcp_network_discovery_confirmed`) and dies with the process.

**The safeguard is the second half of the ruling, and it is the whole of it:** *nothing is
written to disk*. `config.json` never learns that anyone agreed, there is no "don't ask again"
checkbox — that phrase means persisted, and persisting it is exactly what was refused — and a
fresh launch asks again. The confirmation broker's rule that no approval survives a restart is
therefore upheld verbatim; what was relaxed is only the repetition **within** a session, on the
argument that re-showing an identical paragraph on every click trains people to dismiss it unread,
which is a worse security outcome than asking once and meaning it. A `DROP` is genuinely different:
each one destroys a different thing, whereas each broadcast sends the identical datagram.

### D6 — Migrating a compound host *(recommendation OVERRULED)*

**Asked:** should the version 1 → 2 migration split `PC-ARR\SQLEXPRESS:56879` automatically, or
copy it verbatim and flag the row for review? **Recommended: flag, do not rewrite** — a migration
that edits user data is invisible when it guesses wrong.

**Ruled: split it automatically.** The counter-argument the recommendation under-weighted is that
"flag and wait" leaves a profile broken until the user happens to open it, and the profile in
question is the one from the bug report — the user would be shipped a migration that knew what was
wrong and declined to fix it.

**The safeguards imposed in accepting it**, all in `_split_compound_hosts()` and
`_migrate_1_to_2()`:

1. **A backup, taken first and taken unconditionally.** `VACUUM INTO '<db>.v1.backup'` runs before
   anything is rebuilt, whether or not any row turns out to need splitting, and a failure to take
   it **aborts the migration** — refusing to start is recoverable, a half-rebuilt profile table is
   not. Its path is logged at WARNING and reported once by the Connections page. This is what makes
   "the migration guessed wrong" a recoverable event rather than a permanent one, and it is the
   single condition on which the whole ruling rests.
2. **A line-by-line record of the before and the after, at WARNING.** Each split logs the original
   host, then the new host, the new instance, and the old and new port, on one line each — so a
   human can check the result field by field rather than being told only that "hosts were
   migrated".
3. **`needs_review()`, never invention, when the parser refuses.** A host `parse_mssql_target()`
   will not accept — two backslashes, a comma *and* a colon, `np:`, `(localdb)\NAME` — is copied
   **verbatim**, logged with the reason it could not be split, and left for
   `ConnectionStore.needs_review()` to flag with an amber marker on the Connections page. The
   automatic split applies **only** to what the parser accepts unambiguously; the refusal path is
   still the original recommendation, and it is where anything doubtful goes.
4. **Python per row, inside the migration's own transaction.** The split cannot ride on the
   `INSERT..SELECT`, because it *is* `parse_mssql_target()` and that has no SQL equivalent worth
   writing; reimplementing its precedence in `CASE`/`instr()` would create a second parser that
   could disagree with the first about a value already on the user's disk. §3.5 documents the
   resulting two-statement shape.
5. **The port conflict is resolved one way, loudly.** §3.5 has it in full: the port embedded in
   the host wins over the `port` column, with a WARNING naming both values; a `HOST\INSTANCE`
   carrying no embedded port keeps its column's port unchanged.

---

## 14. What this document does not cover

Three things were found or settled during implementation and are recorded here so nobody looks for
them in a section that predates them:

- **TDS PRELOGIN parsing was tried and abandoned.** It would have identified a SQL Server behind an
  open port and read its version without authenticating. Four well-formed variants were sent to a
  real server and every one returned zero bytes. It is a rejected alternative in
  `docs/adr/0003-connection-discovery.md`, with the reasoning; SSRP already names the instances,
  and the version arrives from `SERVERPROPERTY('ProductVersion')` once a connection is
  authenticated, which is where the traits probe already reads it.
- **`ck_connections_auth_mode` cannot be observed firing** (§3.2), and no test should be written
  that claims to.
- **`AuthSupport.platforms` excludes nothing today** (§4), and its rejection branch is provision
  for a future driver rather than live behaviour.
