# SAPÉ d-MCP — Data Model

Stage 1 deliverable. Logical design of the three SQLite databases and the GUI configuration
file. This document is the contract the DB-Specialist and Python Senior implement against;
where it conflicts with an implementation, the implementation is wrong.

**Two exceptions, each recorded rather than assumed.** §4 has been re-issued at
**`permissions.db` schema version 2**: a rule's target patterns have moved to a new `rule_targets`
table, so one rule names a *collection* of objects. `src/sape_d_mcp/permissions.py` is the
authority for those two tables, and `docs/adr/0004-permission-rule-targets.md` records the
decision, the restated ordering proof and the four schema-level defences the shape needs.

And: §3.3 and §3.4 have been re-issued at **`connections.db` schema version 2** to match what
shipped: `DESIGN-CONNECTION-SETUP.md` §3 and ADR 0002 added
the `auth_mode` and `instance` columns and replaced `ck_connections_sqlite_shape`, and the code
in `src/sape_d_mcp/db/connection_store.py` is the authority for that table. §3.4b summarises the
version 1 → 2 migration. Everything else in this document still stands as originally written.

British English throughout. No production Python is created here — the signatures shown carry
no bodies.

---

## 1. Overview

Four persistence artefacts, none of which exists in a clean checkout. All are created on first
write, never at import time.

| Artefact | Location | Purpose | Written by |
|---|---|---|---|
| `connections.db` | current working directory | Connection profiles. **Never a password.** | GUI (Connections page), CLI |
| `permissions.db` | current working directory | Permission rules per connection | GUI (Permissions page) |
| `audit.db` | current working directory | One row per MCP tool call, all connections | MCP server, GUI reads |
| `config.json` | `~/.sape/d-mcp/` | GUI preferences | GUI only (`ConfigManager`) |

**Revised after stage 9.** This table originally said "project root", resolved from a module
inside the package as `Path(__file__).resolve().parent.parent.parent`. That is well defined
for a source checkout and undefined for an installed package: a real `pip install` puts
`__file__` under `site-packages/`, and a fixed `.parent` count from there silently landed
inside the interpreter's own `lib/` directory — found only by installing the built wheel
rather than by reading the code. Three candidates were put to the user for the installed
case; **the current working directory** was chosen. `sape_d_mcp.db_location.
resolve_db_directory()` is now the one place that decides this, imported by all three
stores, replacing their three independent (and, it turned out, inconsistently
hand-counted) `project_root()` functions. Two things to hold in mind about the choice:

* It is fail-closed for `permissions.db` — a fresh, empty file authorises nothing, so
  launching from an unexpected directory looks like "the LLM can suddenly do nothing", not
  like a privilege leak.
* It is *not* fail-closed for `audit.db` — a split audit trail across working directories
  is worse for forensics than a missing file, because each fragment still opens and still
  looks complete.

Each path is overridable by an environment variable so the test suite can point at a
`tmp_path` without touching the developer's real databases, and so a GUI-launched MCP
server generates a client configuration that pins the exact paths it is using rather than
letting a client-spawned subprocess's own (essentially always different) working directory
decide:

| Variable | Effect |
|---|---|
| `DMCP_DB_DIR` | Directory holding all three `.db` files |
| `DMCP_CONNECTIONS_DB` | Full path, overrides `DMCP_DB_DIR` for this file |
| `DMCP_PERMISSIONS_DB` | ditto |
| `DMCP_AUDIT_DB` | ditto |
| `DMCP_CONFIG_DIR` | Directory holding `config.json`, `log.db`, `installation.json` |

Three separate files rather than one, deliberately: they have different durability
requirements (§6), different write frequencies, and different blast radii if one is corrupted.
`audit.db` is written on every tool call and is the file most likely to be truncated by a hard
power loss; keeping it out of the same file as the permission rules means an audit-write
failure can never damage the security state.

---

## 2. ER model

Dashed edges are **logical** references. SQLite cannot enforce a foreign key whose parent lives
in a different database file — even after `ATTACH`, `REFERENCES` resolves only within the
schema that declares it — so these are maintained by the application. §7 says exactly how.

```
   connections.db                    permissions.db                     audit.db
 ┌────────────────────────┐      ┌──────────────────────────┐      ┌────────────────────────┐
 │ connections            │      │ rules                    │      │ tool_calls             │
 ├────────────────────────┤      ├──────────────────────────┤      ├────────────────────────┤
 │ PK id           INTEGER│◄╌╌╌╌╌┤ FK connection_id  INTEGER│      │ PK id          INTEGER │
 │ UQ display_name TEXT   │  1:N │ UQ schema_pattern TEXT   │      │ FK connection_id INT ∅ │╌╌╮
 │    engine       TEXT   │      │ UQ object_type    TEXT   │      │    session_id  TEXT    │  ┆
 │    driver       TEXT   │      │ UQ name_pattern   TEXT   │      │    timestamp   TEXT    │  ┆
 │    host         TEXT ∅ │      │    is_deny        INTEGER│      │    tool_name   TEXT    │  ┆
 │    port         INT  ∅ │      │    can_assign_group  INT │      │    params_json TEXT    │  ┆
 │    database     TEXT   │      │    can_assign_role   INT │      │    rows_affected INT ∅ │  ┆
 │    username     TEXT ∅ │      │    can_create        INT │      │    duration_ms   INT ∅ │  ┆
 │    options_json TEXT   │      │    can_create_group  INT │      │    result      TEXT  ∅ │  ┆
 │    colour_tag   TEXT ∅ │      │    can_create_role   INT │      │    error       TEXT  ∅ │  ┆
 │    created_at   TEXT   │      │    can_create_user   INT │      │    decision    TEXT    │  ┆
 │    user_created TEXT   │      │    can_delete        INT │      │ FK matched_rule_id INT∅│╌╌┼╌╮
 │    updated_at   TEXT   │      │    can_drop          INT │      └────────────────────────┘  ┆ ┆
 │    user_updated TEXT   │      │    can_edit          INT │                                  ┆ ┆
 └────────────────────────┘      │    can_insert        INT │◄╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┼╌╯
            ▲                    │    can_list          INT │                                  ┆
            └╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌╌┤    can_read_catalogue INT│                                  ┆
              logical, unenforced│    can_read_definition IN│                                  ┆
              across files       │    can_read_structure INT│                                  ┆
                                 │    can_run_query     INT │                                  ┆
                                 │    can_select        INT │                                  ┆
                                 │    can_update        INT │                                  ┆
                                 │    created_at     TEXT   │                                  ┆
                                 │    user_created   TEXT   │                                  ┆
                                 │    updated_at     TEXT   │                                  ┆
                                 │    user_updated   TEXT   │                                  ┆
                                 └──────────────────────────┘                                  ┆
                                                                                               ┆
   ~/.sape/d-mcp/                    OS keyring / AES vault                                    ┆
 ┌────────────────────────┐      ┌──────────────────────────┐        connection_id may be NULL ┘
 │ config.json  (GUI only)│      │ service "SAPE-d-MCP"     │        for non-connection tools
 │ log.db       (session) │      │ account "conn:<id>"      │        (see §5.3)
 │ installation.json      │      │ secret  <password>       │
 └────────────────────────┘      └──────────────────────────┘
                                   ▲ keyed by connections.id,
                                   ╰ never stored in any .db
```

`∅` marks a column that may be `NULL`. Every other column is `NOT NULL`.

**Cardinalities.** One connection has zero-or-more rules and zero-or-more audit rows. One rule
is cited by zero-or-more audit rows via `matched_rule_id`. A connection has at most one keyring
secret, addressed by `id`, held outside every database.

---

## 3. `connections.db`

### 3.1 How SQLite fits the same table

A SQLite profile is a file path with no host, no port and no user; the other three engines
require all three. The naïve resolutions are both bad: a second table duplicates the audit
columns, the unique name constraint and every CRUD path, and forces the GUI to branch before it
can even list profiles; blanket-nullable columns give an undisciplined table where nothing
constrains which combinations are legal.

**Decision: one table, with the engine acting as a discriminator and a table-level `CHECK`
turning the null pattern into an enforced invariant.** The three columns that do not apply to
SQLite are nullable *at the type level* but their nullability is a function of `engine`, so
there is exactly one legal shape per engine and the database rejects everything else. This is a
tagged union expressed in the only way SQLite offers, and it is not null sprawl: a null in this
table is never "unknown", it is always "structurally absent for this engine".

`database` stays `NOT NULL` for every engine and carries the one thing every engine has: a
database *name* for the three servers, an **absolute file path** for SQLite. The Connections
page relabels that single field per engine ("Database" / "Database file"), which is a one-line
change rather than a second form.

Anything genuinely engine-specific and open-ended — the ODBC driver string, `sslmode`,
`ApplicationIntent`, `charset`, a SQLite `?mode=ro` URI flag, a Postgres `search_path` — lives
in `options_json`, so the table never grows a column for one engine's quirk.

### 3.2 `AUTOINCREMENT` is load-bearing

`id` is declared `INTEGER PRIMARY KEY AUTOINCREMENT`, not the cheaper plain
`INTEGER PRIMARY KEY`. Without `AUTOINCREMENT`, SQLite reuses the largest free rowid after a
deletion. Because `permissions.db` and `audit.db` reference `connection_id` across file
boundaries with no enforcement, a reused id would let a surviving orphan rule silently reattach
itself to a brand-new, unrelated connection — a rule the user wrote for a development database
would start authorising a production one. `AUTOINCREMENT` makes ids strictly monotonic and
never recycled, which is the single guarantee that makes the cross-file design safe.

### 3.3 DDL — schema version 2

**Superseded and re-issued.** The version 1 table below has been replaced by version 2, specified
in `DESIGN-CONNECTION-SETUP.md` §3.2 and ADR 0002 and shipped as the `SCHEMA` string in
`src/sape_d_mcp/db/connection_store.py`. Three things changed: the `instance` column, the
`auth_mode` column, and `ck_connections_sqlite_shape` giving way to `ck_connections_shape`. The
`statement_timeout_s` column of `DESIGN-MCP-TOOLS.md` §13.2 is shown here too, so that this
section is the whole table rather than most of it.

The DDL below is a *rendering*: in the code, the engine/driver and `auth_mode` `IN` lists are
generated from `DRIVERS_BY_ENGINE` and `AUTH_MODES` by `_engine_driver_check()` and
`_auth_mode_check()`, and the whole `CREATE TABLE` body comes from `_connections_ddl(table)`,
parameterised on the table name so that the version 1 → 2 migration builds `connections_v2` from
the same text rather than from a hand-retyped copy.

```sql
-- connections.db
--
-- Connection profiles. There is deliberately NO password column, and no column
-- that could hold one: credentials go to the OS keyring under service
-- "SAPE-d-MCP", account "conn:<id>", with the AES vault as the fallback where no
-- keyring backend exists. A password must never reach this file, an error
-- message, a log line or a generated MCP client config. If a future change
-- appears to need a secret here, the change is wrong.
--
-- Only "SQL-standard" values are stored: options_json carries every
-- engine-specific extra, so this table never grows a column for one driver.

PRAGMA journal_mode = WAL;          -- set BEFORE the first CREATE TABLE
PRAGMA synchronous  = FULL;         -- see §6: profile loss is a usability failure
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA user_version = 2;            -- 1 -> 2 is a full table rebuild; see §3.6

CREATE TABLE IF NOT EXISTS connections (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,   -- AUTOINCREMENT: ids are never
                                                       -- recycled, so an orphan rule in
                                                       -- permissions.db can never be adopted
                                                       -- by a different connection (§3.2)
    display_name  TEXT    NOT NULL COLLATE NOCASE UNIQUE,
    engine        TEXT    NOT NULL,
    driver        TEXT    NOT NULL,
    host          TEXT,            -- NULL iff engine = 'sqlite'; a bare server name for
                                   --   MS-SQL, never 'HOST\INSTANCE' or 'HOST,PORT'
    port          INTEGER,         -- NULL iff engine = 'sqlite', or an MS-SQL named
                                   --   instance supplies the port through the Browser
    instance      TEXT,            -- MS-SQL named instance ('SQLEXPRESS'); NULL elsewhere
    database      TEXT    NOT NULL,-- database name, or the absolute file path for sqlite
    username      TEXT,            -- NULL iff auth_mode <> 'password'

    -- How the connection proves who it is: 'password', 'integrated' (the operating
    -- system supplies the identity — SSPI, Kerberos/GSSAPI, PostgreSQL peer) or
    -- 'none' (SQLite, where the file's own permissions are the access control).
    -- The default keeps every profile written before version 2 behaving exactly as
    -- it did.
    auth_mode     TEXT    NOT NULL DEFAULT 'password',

    options_json  TEXT    NOT NULL DEFAULT '{}',
    colour_tag    TEXT,            -- '#RRGGBB' shown as the tab and sidebar accent, or NULL

    -- Per-connection statement timeout (DESIGN-MCP-TOOLS.md §6.1, §13.2). It is a
    -- property of the connection and not of the call: the model gets no lever
    -- over how long its own statement may tie up the server.
    statement_timeout_s INTEGER NOT NULL DEFAULT 30,

    created_at    TEXT    NOT NULL,
    user_created  TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL,
    user_updated  TEXT    NOT NULL,

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

    -- Rendered from AUTH_MODES. Unreachable in practice and kept deliberately:
    -- see the note below.
    CONSTRAINT ck_connections_auth_mode CHECK (
        auth_mode IN ('password', 'integrated', 'none')
    ),

    -- An instance name belongs to MS-SQL alone. Without this, a PostgreSQL row
    -- could carry one and would then satisfy ck_connections_shape with no port,
    -- which is a profile nothing can reach.
    CONSTRAINT ck_connections_instance CHECK (
        instance IS NULL
        OR (engine = 'mssql' AND length(trim(instance)) > 0)
    ),

    -- The engine/driver pairing is a closed product decision, not routine schema
    -- evolution, so it is safe to pin in a CHECK: adding a fifth engine is a
    -- user_version bump with a full table rebuild, which is proportionate.
    CONSTRAINT ck_connections_engine_driver CHECK (
        (engine = 'mssql'      AND driver IN ('pyodbc', 'pymssql'))
     OR (engine = 'postgresql' AND driver  = 'psycopg')
     OR (engine = 'mysql'      AND driver IN ('pymysql', 'mysql-connector-python'))
     OR (engine = 'sqlite'     AND driver  = 'sqlite3')
    ),

    CONSTRAINT ck_connections_port      CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
    CONSTRAINT ck_connections_options   CHECK (json_valid(options_json)),
    CONSTRAINT ck_connections_name      CHECK (length(trim(display_name)) > 0),
    CONSTRAINT ck_connections_database  CHECK (length(trim(database)) > 0),
    CONSTRAINT ck_connections_colour    CHECK (
        colour_tag IS NULL
        OR colour_tag GLOB '#[0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f][0-9A-Fa-f]'
    ),
    CONSTRAINT ck_connections_timeout   CHECK (
        statement_timeout_s BETWEEN 1 AND 300
    ),
    CONSTRAINT ck_connections_audit     CHECK (
        length(created_at) >= 19 AND length(updated_at) >= 19
        AND length(user_created) > 0 AND length(user_updated) > 0
    )
);

-- display_name is already UNIQUE (implicit index). This second index serves the
-- Connections page's default ordering and the Logs page's tab construction.
CREATE INDEX IF NOT EXISTS idx_connections_engine ON connections(engine, display_name);
```

**What version 1 said, for anyone reading an old file.** The shape constraint was:

```sql
    CONSTRAINT ck_connections_sqlite_shape CHECK (
        (engine =  'sqlite' AND host IS     NULL AND port IS     NULL AND username IS     NULL)
     OR (engine <> 'sqlite' AND host IS NOT NULL AND port IS NOT NULL AND username IS NOT NULL)
    ),
```

`username IS NOT NULL` for every non-SQLite engine encoded the belief that a login always has a
name this application supplies — false for a Windows trusted connection, for PostgreSQL `peer` and
for GSSAPI. Replacing it is the whole reason version 2 exists (ADR 0002). Both of the old
constraint's real guarantees survive inside `ck_connections_shape`: a `password` profile still
cannot be saved without a user name, and every non-SQLite profile is still addressable — the old
`port IS NOT NULL` became `port IS NOT NULL OR instance IS NOT NULL`, and since `instance` is NULL
on every engine but MS-SQL, PostgreSQL and MySQL still require a port exactly as before.

**`ck_connections_auth_mode` is unreachable, and it stays.** `ck_connections_shape` is declared
first and every one of its branches already pins `auth_mode` to a value inside the domain, so a
row carrying `auth_mode = 'kerberos'` fails the shape constraint — and SQLite reports the *first*
CHECK that fails in DDL order, so the `IntegrityError` always names `ck_connections_shape` and
`ck_connections_auth_mode` can never be observed firing. It is kept because it is what holds the
domain closed if the shape constraint is ever relaxed again, at a cost of one generated line. No
test can exercise it directly, none should be written, and the two constraints must not be
reordered to make it observable — the order is what gives the user the more useful message.
`DESIGN-CONNECTION-SETUP.md` §3.2 has the argument in full.

### 3.4 Domains

| Column | Domain | Notes |
|---|---|---|
| `engine` | `mssql` · `postgresql` · `mysql` · `sqlite` | source tuple `ENGINES` in `src/sape_d_mcp/db/connection_store.py`, matching `Engine` in `dialects/types.py` |
| `driver` | `pyodbc` · `pymssql` · `psycopg` · `pymysql` · `mysql-connector-python` · `sqlite3` | source mapping `DRIVERS_BY_ENGINE`; the driver key is the pip package name, as `dialects/registry.py` requires |
| `auth_mode` | `password` · `integrated` · `none` | source tuple `AUTH_MODES` in `src/sape_d_mcp/db/auth_modes.py`. `none` is SQLite's and SQLite's alone; PostgreSQL `trust` is modelled as `integrated`, because from d-MCP's side "no name and no secret is sent" is one behaviour. Which pairs may hold `integrated` is `INTEGRATED_SUPPORT`, not this domain |
| `host` | server name, IP, or bracketed IPv6 literal | **A bare server**, never `HOST\INSTANCE`, `HOST,PORT`, `HOST:PORT` or a `tcp:` prefix. `parse_mssql_target()` in `db/targets.py` is the one normaliser, and it either parses or raises — it never repairs |
| `instance` | MS-SQL named instance, `^[A-Za-z0-9_$#][A-Za-z0-9_$#\-]{0,127}$` | NULL on every other engine, by `ck_connections_instance`. Both `port` and `instance` may be present; **the port wins** and the instance is not used to reach the server (`resolve_mssql_target()`) |
| `port` default | mssql 1433 · postgresql 5432 · mysql 3306 | supplied by the dialect, stored explicitly. Optional for MS-SQL when an `instance` is given, since the SQL Server Browser resolves it |
| `username` | login name | NULL unless `auth_mode = 'password'`. Under `integrated` a value is a `ValueError`, not something to store and ignore: a profile that displays one identity while connecting as another misleads the Connections page and the audit trail alike |
| `database` | name, or absolute path for `sqlite` | the path is stored resolved and `expanduser`-ed |
| `options_json` | JSON object | keys are validated per dialect; unknown keys rejected at write time |
| `colour_tag` | `#RRGGBB` | from the design-token palette; the Logs tab accent |
| `statement_timeout_s` | 1–300, default 30 | a property of the connection, never of the call; DESIGN-MCP-TOOLS.md §6.1 |
| timestamps | ISO 8601 with offset, `timespec='seconds'` | `datetime.now().astimezone().isoformat(timespec="seconds")`, as f-MCP |
| `user_created`/`user_updated` | login name | `current_user()`, the f-MCP helper, ported verbatim |

`options_json` recognised keys, per engine — validated against a per-dialect allow-list so a
typo is an error rather than a silently ignored setting:

| Engine | Keys |
|---|---|
| `mssql` | `odbc_driver`, `encrypt`, `trust_server_certificate`, `application_intent`, `login_timeout`, `tds_version` |
| `postgres` | `sslmode`, `sslrootcert`, `search_path`, `connect_timeout`, `application_name` |
| `mysql` | `charset`, `ssl_disabled`, `ssl_ca`, `connect_timeout`, `sql_mode` |
| `sqlite` | `read_only`, `timeout`, `journal_mode` |

`search_path` matters to the permission model: see DESIGN-PERMISSIONS.md §4, where a
`search_path` with more than one entry makes an unqualified name ambiguous and raises
`ValueError` rather than being guessed at.

### 3.4a No credential column, at any version

Restated here because §3.3 grew and the point must not get lost in it: there is no password
column, and `auth_mode` is what decides whether a secret may exist *at all*. Under `integrated`
and under `none`, a keyring entry for that connection id **must not exist** — `update()` deletes
one when a profile leaves `password`, and `engine.connect()` raises `ValueError` if it is handed a
password for a profile that does not authenticate with one. The mode decides; the presence of a
secret never does.

### 3.4b Migration, version 1 → 2

Specified in full in `DESIGN-CONNECTION-SETUP.md` §3.5; summarised here because this is the
section a reader arrives at with an old file in their hand.

SQLite has no `ALTER TABLE ... DROP CONSTRAINT` and version 2 *replaces* a CHECK, so it is
SQLite's own table-rebuild procedure and not an `ALTER`. `pragma writable_schema` is rejected: a
corrupted `connections.db` costs every profile **and** strands every keyring entry, since the
account name is derived from the row id. The order is:

1. `VACUUM INTO '<db>.v1.backup'`, **unconditionally and first**; a failure here aborts the
   migration, because refusing to start is recoverable and a half-rebuilt table is not.
2. `PRAGMA foreign_keys = OFF`, then `BEGIN IMMEDIATE`.
3. `CREATE TABLE connections_v2` from the same `_connections_ddl()` text as §3.3.
4. `INSERT INTO connections_v2 ... SELECT ... FROM connections`, mapping `engine = 'sqlite'` to
   `auth_mode = 'none'` and everything else to `'password'`, with `instance` NULL. Every legal v1
   row satisfies the v2 constraint by construction, so this **cannot fail on data**.
5. **Then, in the same transaction, one parametrised `UPDATE` per row that needs one**, splitting
   an MS-SQL `host` that carries more than a server name. This is not part of the `INSERT..SELECT`
   and could not be: the split is `parse_mssql_target()`, which is Python, and expressing its
   precedence in `CASE`/`instr()` would create a second parser able to disagree with the first
   about a value already on the user's disk.
6. `DROP TABLE connections`, `ALTER TABLE connections_v2 RENAME TO connections`, recreate
   `idx_connections_engine`, `PRAGMA foreign_key_check`, `COMMIT`, `PRAGMA foreign_keys = ON`,
   `PRAGMA user_version = 2`.

The whole step is idempotent — it returns immediately when the table already carries `auth_mode`
and `instance`, which is also true of a brand-new file — and `_MIGRATABLE_COLUMNS` deliberately
does **not** gain the two new names, because `ALTER TABLE ADD COLUMN` would add them under the
*version 1* constraints, which is the exact failure this migration exists to prevent.

**Two behaviours of step 5 that a v1 file will meet.** The user ruled that the migration splits a
compound host automatically rather than only flagging it, and the safeguards on that ruling
(`DESIGN-CONNECTION-SETUP.md` §13 D6) are the backup of step 1, a WARNING log of the before and
after of every split field by field, and `needs_review()` rather than invention wherever
`parse_mssql_target()` refuses — a host with two backslashes, or a comma *and* a colon, or `np:`,
or `(localdb)\NAME`, is copied **verbatim** and flagged on the Connections page.

And the conflict version 1's own DDL guarantees: every v1 non-SQLite row has `port NOT NULL`, so a
compound host such as `PC-ARR\SQLEXPRESS:56879` arrives carrying **two** ports, one embedded in
the host string and one in the column. **The embedded port wins**, and when the two differ the
migration logs at WARNING naming both values — it is the more specific and more recent statement
of intent, being what the user typed into the field they were looking at. A `HOST\INSTANCE` with
**no** embedded port keeps its column's port unchanged; nothing is cleared, and the instance name
simply moves into the column that now exists for it.

### 3.5 Credential linkage

The keyring account is `conn:<id>`, derived from the primary key rather than the display name,
so renaming a connection does not orphan its password. On delete, the cascade in §7.2 removes
the keyring entry first — before the row that tells us the account name.

---

## 4. `permissions.db`

### 4.1 The shape question, resolved

Action sets differ per object type:

| Object type | Actions | Count |
|---|---|---|
| `table` | `list, read_structure, select, insert, update, delete, create, drop` | 8 |
| `view` | `list, read_definition, select, create, drop` | 5 |
| `function` | `list, read_definition, create, edit, drop` | 5 |
| `procedure` | `list, read_definition, create, edit, drop` | 5 |
| `database` | `read_catalogue, create_role, create_user, create_group, assign_group, assign_role, run_query` | 7 |

The union is 17 distinct action names. `function` and `procedure` share a set exactly.

**Decision: (a) one wide `rules` table carrying the union of 17 `can_*` columns.** Rejected: (b)
one table per object type, (c) a narrow `(rule_id, action, allowed)` child table.

**Why (a).**

1. *It is the f-MCP idiom, and the idiom is the migration.* f-MCP's `ACTIONS` tuple generates
   the column list, the `INSERT`, the `ON CONFLICT DO UPDATE`, the `PRAGMA table_info` diff and
   the parametrised test from one place. d-MCP keeps that with `ACTIONS_BY_TYPE` generating the
   union. The migration machinery is a copy-verbatim item in the house style; option (b) would
   need it run five times over five near-identical tables, and (c) would discard it for a
   different, unproven mechanism.
2. *Resolution reads one row.* `rule_for()` returns a single `sqlite3.Row` and `is_allowed` is
   `bool(rule[f"can_{action}"])` — one indexed dict lookup, no join, no second query. This is
   not a performance argument (rule counts are in the tens); it is a *semantic* one. The model
   says the single most specific rule wins **wholesale**: its action set is applied in its
   entirety and lower-specificity rules contribute nothing. A wide row makes that structurally
   obvious. A child table invites the opposite reading — that per-action rows from several
   rules might be merged — and that reading is a silent privilege escalation waiting to be
   written by the next maintainer.
3. *It is the shape the GUI already wants.* f-MCP's `permissions_page.py` renders the rule
   table in six columns with an `f"{len(allowed_actions)}/{len(ACTIONS)}"` summary (line 402),
   and the `NewRuleDialog` builds checkboxes by iterating the action tuple and reading
   `rule[f"can_{a}"]`. Both want a dict-shaped row keyed by action. The wide row *is* that dict.
   d-MCP's dialog iterates `ACTIONS_BY_TYPE[object_type]` instead of a flat tuple, so it shows
   five checkboxes for a view and eight for a table, driven by the same source of truth.
4. *`matched_rule_id` stays a single integer.* `audit.db` cites the deciding rule by id. Under
   (b) that id is only meaningful together with which of the five tables it came from, so the
   audit row would need a `matched_rule_table` column and every join becomes conditional. This
   alone disqualifies (b).

**The cost, and how it is paid.** For any given row, 9 to 12 of the 17 columns are meaningless.
They are `NOT NULL DEFAULT 0`, so they are provably zero rather than unknown, and
`PermissionStore._validate_actions()` — driven by `ACTIONS_BY_TYPE`, the same tuple that
generated the columns — rejects any attempt to set an action outside the object type's set.
The wasted storage is 12 bytes per row on a table with tens of rows.

**Why the validation is in Python and not a `CHECK`.** A `CHECK` naming `can_*` columns would
be the stronger guarantee, but SQLite's `ALTER TABLE … ADD COLUMN` cannot extend an existing
`CHECK`. The first new action added to `ACTIONS_BY_TYPE` would leave a silently stale
constraint that no longer covers the new column — worse than no constraint, because it looks
enforced. So the schema's `CHECK`s cover only *tuple-independent* invariants (the `object_type`
domain, the `is_deny` domain, pattern well-formedness, audit columns), and everything derived
from the action tuple is enforced by one Python function used by `grant`, `deny` and a
parametrised test. This is the deliberate division of labour between the two mechanisms.

**A child table of TARGETS is not option (c), and §4 now has one.** Schema version 2 moves a
rule's `schema_pattern` and `name_pattern` into `rule_targets`, which looks at a glance like the
shape rejected here. The distinction is the whole safety argument, so it is stated rather than
left to be re-derived:

- An option (c) row is a fragment of an **answer** — "what may be done". Resolution over fragments
  of an answer has an obvious, tempting and wrong implementation, namely to union them, and that
  implementation is a privilege escalation with nothing in the shape of the data arguing against
  it. That is precisely point 2's objection.
- A target row is a fragment of a **question** — "does this rule apply here?". The decision
  surface is untouched: the winner is still exactly one `rules` row carrying all 17 `can_*`
  columns, and `is_allowed` is still `bool(rule[f"can_{action}"])` with no join at decision time.

The theorem, which is what makes it safe rather than merely different: *the resolver takes `max`
over the matched set, never a union, so merging targets across rules can change **which** rule
wins but can never produce an action set that no single rule authorises.* Option (c) has no such
theorem available.

The objection below does not transfer either: (c)'s `action` column has no enforceable domain,
whereas `schema_pattern` and `name_pattern` have one that is both enforceable and
tuple-independent — the two `instr()` CHECKs move across unchanged, which is exactly the class of
invariant this section says belongs in the schema.

Point 4 survives intact: `matched_rule_id` is still a single integer naming a `rules.id`, and the
target id is deliberately never cited in the audit row.

**Why option (c) is not merely worse but subtly unsafe.** It escapes the column migration, its
one real advantage. But an action name in a `TEXT` column has no schema-level domain (SQLite
has no `ENUM`; a `CHECK … IN (…)` list would need regenerating from the tuple and would rot in
exactly the same way), so a typo is storable and reads as "not granted" — failing closed, but
invisibly, and a rule the user believes grants `select` grants nothing. Combined with the
merging hazard in point 2, it loses on every axis except the one it wins.

### 4.2 The uniqueness key

At schema version 2 it sits on the child table, with the same four columns:

```sql
-- on rule_targets
UNIQUE (connection_id, object_type, schema_pattern, name_pattern)
```

This is what makes the specificity ordering provably total (DESIGN-PERMISSIONS.md §2.4): two
matching targets can tie only if their patterns are identical, and identical targets within one
connection and object type are what this forbids.

**`rule_id` is deliberately not part of it.** Scoping the uniqueness per rule reads as the more
natural constraint and is what a later maintainer would "correct" it to — and it would let two
rules own the same target, so the ordering would tie for real, silently.

`is_deny` is likewise not part of it, and at version 2 that needs no argument at all: a target
carries no decision, so an allow target and a deny target on one key is unrepresentable rather
than merely forbidden. (Under version 1 it had to be excluded by hand, because a rule *was* its
target.)

`rules` carries `UNIQUE (id, connection_id, object_type)`. That constrains no data — `id` is
already unique — and exists only because SQLite requires a composite foreign key's parent columns
to carry a UNIQUE index over exactly those columns in exactly that order.

There is also no `object_type = '*'`, and a rule carries exactly one object type. Action sets
differ per type, so a wildcard or mixed type would have no coherent set of `can_*` columns to
interpret.

**A second, unrelated uniqueness arrived at version 3**, and the two must not be confused. The
key above is about *reach* — which rule owns an object — and is load-bearing for the resolution
order. `uq_rules_name_per_connection` is about *reading the list*:

```sql
-- on rules
CREATE UNIQUE INDEX uq_rules_name_per_connection
    ON rules(connection_id, rule_name COLLATE NOCASE) WHERE rule_name IS NOT NULL;
```

It is scoped **per connection** because the rules list is shown one connection at a time, so two
databases each holding a rule called `Reporting` have nothing to tell apart. It is **partial**
because the name is optional and "unique" here must mean "no two rules on one connection carry
the same name", never "at most one rule may be unnamed" — every rule written before version 3 is
unnamed, so the latter reading would lock an operator out of their own file on first launch. And
it folds case, following `connections.display_name`; the ASCII-only limit of SQLite's `NOCASE` is
recorded beside the index in the DDL.

No permission decision reads `rule_name`, so a collision here is an inconvenience where a
collision on `uq_rule_targets_key` would be an ambiguity in the ordering. It is enforced in the
schema rather than only in Python for the ordinary reason: a constraint the database does not
hold is a constraint that a second process, or a later caller, does not hold either.

### 4.3 DDL

Reproduced from `src/sape_d_mcp/permissions.py`, which renders both tables from
`_rules_ddl()` and `_rule_targets_ddl()` — parameterised on the table name so the version 1 -> 2
migration builds `rules_v2` from the same text rather than a hand-retyped copy. The PRAGMAs are
applied in Python by `_apply_pragmas()` on every open rather than typed into the script, so they
are re-asserted rather than set once on a fresh file.

```sql
-- permissions.db, schema version 3
PRAGMA journal_mode = WAL;          -- set BEFORE the first CREATE TABLE
PRAGMA synchronous  = FULL;         -- see §6: a lost revoke fails OPEN
PRAGMA foreign_keys = ON;           -- VERIFIED, not merely requested: see below
PRAGMA busy_timeout = 5000;
PRAGMA user_version = 3;
```

```sql
CREATE TABLE IF NOT EXISTS rules (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,  -- cited by audit.matched_rule_id
    connection_id           INTEGER NOT NULL,   -- logical FK -> connections.db connections(id);
                                                -- unenforceable across files, see §7
    object_type             TEXT    NOT NULL,   -- table | view | function | procedure | database
    is_deny                 INTEGER NOT NULL DEFAULT 0,

    -- ── generated from ACTIONS_BY_TYPE, sorted ────────────────────────────────
    can_assign_group        INTEGER NOT NULL DEFAULT 0,
    can_assign_role         INTEGER NOT NULL DEFAULT 0,
    can_create              INTEGER NOT NULL DEFAULT 0,
    can_create_group        INTEGER NOT NULL DEFAULT 0,
    can_create_role         INTEGER NOT NULL DEFAULT 0,
    can_create_user         INTEGER NOT NULL DEFAULT 0,
    can_delete              INTEGER NOT NULL DEFAULT 0,
    can_drop                INTEGER NOT NULL DEFAULT 0,
    can_edit                INTEGER NOT NULL DEFAULT 0,
    can_insert              INTEGER NOT NULL DEFAULT 0,
    can_list                INTEGER NOT NULL DEFAULT 0,
    can_read_catalogue      INTEGER NOT NULL DEFAULT 0,
    can_read_definition     INTEGER NOT NULL DEFAULT 0,
    can_read_structure      INTEGER NOT NULL DEFAULT 0,
    can_run_query           INTEGER NOT NULL DEFAULT 0,
    can_select              INTEGER NOT NULL DEFAULT 0,
    can_update              INTEGER NOT NULL DEFAULT 0,
    -- ──────────────────────────────────────────────────────────────────────────

    created_at              TEXT    NOT NULL,
    user_created            TEXT    NOT NULL,
    updated_at              TEXT    NOT NULL,
    user_updated            TEXT    NOT NULL,

    -- The operator's own label for the rule, added at schema version 3 because the
    -- rules list showed only patterns, a type and an effect, and nothing on the row
    -- said what the rule was FOR.  Last in the column list on purpose: a version 2
    -- file gains it by ALTER TABLE ... ADD COLUMN, which can only append, so putting
    -- it anywhere else here would make a fresh database and a migrated one disagree
    -- about column order for no gain.
    --
    -- NULLABLE, and that is the decision rather than an omission: every rule written
    -- before version 3 keeps no name until a human gives it one, which is what makes
    -- the upgrade an ALTER instead of a rebuild and means no placeholder was ever
    -- invented on an operator's behalf.  NULL is the ONLY spelling of "no name" --
    -- the store folds '' to NULL on write -- because two spellings of absence under a
    -- UNIQUE index would be two rules that look unnamed and collide, or two that look
    -- identical and do not.
    rule_name               TEXT,

    -- This is NOT uq_rules_key, which has moved to rule_targets unchanged in its
    -- columns.  It exists for exactly one purpose: SQLite requires a composite
    -- foreign key's parent columns to carry a UNIQUE index over precisely those
    -- columns in precisely that order, and rule_targets declares
    -- (rule_id, connection_id, object_type) -> rules(id, connection_id, object_type).
    -- That foreign key is what stops a target's denormalised connection_id and
    -- object_type drifting away from its rule's.  `id` is already unique on its own,
    -- so this constrains no data that was not constrained before -- it only supplies
    -- the index the foreign key needs.
    CONSTRAINT uq_rules_identity UNIQUE (id, connection_id, object_type),

    CONSTRAINT ck_rules_object_type CHECK (
        object_type IN ('table', 'view', 'function', 'procedure', 'database')
    ),
    CONSTRAINT ck_rules_is_deny CHECK (is_deny IN (0, 1)),
    CONSTRAINT ck_rules_connection CHECK (connection_id > 0),
    -- 80 is MAX_RULE_NAME_LENGTH, interpolated from permissions.py rather than typed
    -- here, so the schema and the Python cannot disagree about the limit.  trim() is
    -- a backstop only: the store normalises before writing, so a blank name is
    -- already NULL by the time SQLite sees it, and this catches a hand-edited file.
    CONSTRAINT ck_rules_name CHECK (
        rule_name IS NULL
        OR (length(trim(rule_name)) > 0 AND length(rule_name) <= 80)
    ),
    CONSTRAINT ck_rules_audit CHECK (
        length(created_at) >= 19 AND length(updated_at) >= 19
        AND length(user_created) > 0 AND length(user_updated) > 0
    )
);

CREATE TABLE IF NOT EXISTS rule_targets (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id        INTEGER NOT NULL,
    -- connection_id and object_type are copied down from the parent rule because a
    -- UNIQUE constraint cannot reach into another table, and the constraint below is
    -- the whole security argument.  The composite foreign key at the foot of this
    -- table is what keeps the copies honest.
    connection_id  INTEGER NOT NULL,
    object_type    TEXT    NOT NULL,
    schema_pattern TEXT    NOT NULL,   -- exact | 'prefix*' | '*'
    name_pattern   TEXT    NOT NULL,   -- exact | 'prefix*' | '*'

    -- NOT NULL on every column above is load-bearing, not housekeeping.  SQLite
    -- counts NULLs as DISTINCT in a UNIQUE index; a CHECK that evaluates to NULL
    -- PASSES, and instr(NULL,'*') IN (0, length(NULL)) is NULL rather than 0; and a
    -- composite foreign key whose child carries a NULL is satisfied vacuously.  One
    -- nullable column here would therefore switch off the uniqueness, the pattern
    -- grammar and the parent check all at once, and a rule could carry a target that
    -- matches by rules nobody wrote.

    -- DESIGN-DATA-MODEL.md §4.2's uq_rules_key, moved here intact.  rule_id is
    -- deliberately NOT part of it.  Scoping the uniqueness per rule reads as the
    -- more natural constraint, and is what a later maintainer would "correct" this
    -- to -- but it would let two rules own the same target, and the specificity
    -- ordering would then tie for real, silently, with only the defensive tiebreak
    -- in rule_for() standing between that and an arbitrary decision
    -- (DESIGN-PERMISSIONS.md §2.4).
    CONSTRAINT uq_rule_targets_key UNIQUE (connection_id, object_type, schema_pattern, name_pattern),

    -- Pattern grammar: a literal, or a literal followed by exactly one trailing
    -- '*', or a bare '*'. instr() returns the FIRST '*', so requiring it to be
    -- absent or final rejects '*x', 'a*b' and '**' in one expression.
    CONSTRAINT ck_rule_targets_schema_pattern CHECK (
        length(schema_pattern) > 0
        AND instr(schema_pattern, '*') IN (0, length(schema_pattern))
    ),
    CONSTRAINT ck_rule_targets_name_pattern CHECK (
        length(name_pattern) > 0
        AND instr(name_pattern, '*') IN (0, length(name_pattern))
    ),
    CONSTRAINT ck_rule_targets_connection CHECK (connection_id > 0),

    FOREIGN KEY (rule_id, connection_id, object_type)
        REFERENCES rules(id, connection_id, object_type) ON DELETE CASCADE
);

-- The resolver narrows to a connection and an object type in SQL, then matches
-- patterns in Python: a LIKE/GLOB pattern held in a COLUMN cannot use an index,
-- so pushing the match into SQL would buy nothing and would put the security
-- decision inside SQLite's pattern semantics instead of our own tested code.
CREATE INDEX IF NOT EXISTS idx_rule_targets_lookup ON rule_targets(connection_id, object_type);

-- SQLite does not index the child side of a foreign key by itself, so without this
-- every ON DELETE CASCADE -- and every listing of one rule's targets, which the
-- Permissions page does once per row -- is a full table scan.
CREATE INDEX IF NOT EXISTS idx_rule_targets_rule ON rule_targets(rule_id);

-- Serves the join's parent side and the §7.3 orphan sweep.
CREATE INDEX IF NOT EXISTS idx_rules_lookup ON rules(connection_id, object_type);

-- A `database` rule is scoped to the connection and never pattern-matched
-- (DESIGN-PERMISSIONS.md §5.6), so "at most one per connection" IS the meaning of
-- the type.  Under version 1 that came free with uq_rules_key plus the forced
-- '*'/'*'; with the patterns gone from this table it has to be said outright, or two
-- database rules could coexist and rule_for() would pick between them by storage
-- order -- which is to say, arbitrarily.
CREATE UNIQUE INDEX IF NOT EXISTS uq_rules_one_database_per_connection
    ON rules(connection_id) WHERE object_type = 'database';

-- A rule's own name, unique per connection and over the names actually SET.  Partial
-- for the same reason the index above is: "unique" must mean "no two rules on one
-- connection carry the same name", never "at most one rule may be unnamed".  SQLite
-- counts NULLs as DISTINCT in a UNIQUE index, so a plain index would in fact allow
-- any number of unnamed rules -- but only by accident of NULL semantics, and the
-- first person to normalise a blank name to '' rather than NULL would silently turn
-- it into "one unnamed rule per connection".  The WHERE clause says what is meant.
--
-- COLLATE NOCASE follows connections.display_name, the house precedent for a
-- user-facing unique label: 'Sales' and 'sales' in one list defeat the purpose of
-- naming a rule.  Known limit, recorded rather than discovered later: SQLite's NOCASE
-- folds ASCII only, so 'CAFÉ' and 'café' would NOT collide.  That is a permissive
-- failure on a field no permission decision reads -- rule_for() matches on patterns
-- alone -- so it costs a confusing list, not an unintended grant.
CREATE UNIQUE INDEX IF NOT EXISTS uq_rules_name_per_connection
    ON rules(connection_id, rule_name COLLATE NOCASE) WHERE rule_name IS NOT NULL;
```

`PRAGMA foreign_keys` is now read back and checked, the way `journal_mode` already is. A SQLite
built without foreign key support accepts the statement, sets nothing and reports `0` — harmless
while this file declared no foreign key, and security-relevant now that one holds every target to
the right connection.

`idx_rules_connection` from version 1 is gone rather than recreated: it indexed the two columns
the rebuild removed, and `idx_rule_targets_lookup` does its work.

### 4.4 The deny row

`is_deny = 1` requires every `can_*` column to be 0 — a deny is exactly "a rule that matches and
grants nothing". Enforced in Python for the reason in §4.1, and pinned by
`test_a_deny_rule_cannot_carry_a_granted_action`.

That makes a deny row *behaviourally* identical to an allow row with nothing ticked, which is
worth admitting plainly. `is_deny` earns its column for two other reasons: it records **intent**
— the GUI and the denial message must distinguish "I explicitly blocked this" from "I made a
rule and have not ticked anything yet" — and it is the final tiebreak that makes the ordering
provably total even against a hand-edited database (DESIGN-PERMISSIONS.md §2.4).

### 4.5 Migration

Two mechanisms, complementary:

- **`PRAGMA user_version`** for structural change (a new table, a changed `CHECK`, a renamed
  column). Bumping it triggers a hand-written migration step. Currently `3`.

  **Version 1 -> 2** (`_migrate_1_to_2`) moves each rule's two pattern columns into
  `rule_targets`, one target per version 1 row, so no rule's reach changes by a single object.
  SQLite cannot drop a column named in a UNIQUE constraint, a CHECK and an index —
  `schema_pattern` is in all three — and no `ALTER` can add the `uq_rules_identity` the child's
  foreign key needs, so the table rebuild is the only route. It mirrors `connection_store`'s v1->2
  step: unconditional `VACUUM INTO` backup first, `MigrationRecord` written beside it,
  `PRAGMA foreign_keys = OFF` outside the transaction, `BEGIN IMMEDIATE`, rebuild, then
  `PRAGMA foreign_key_check` — which here is the *proof* that every target's denormalised
  `connection_id` and `object_type` match its rule's, not the formality it is in `connections.db`.

  Three details are load-bearing. **`rules.id` is carried across explicitly**, because
  `audit.db`'s `matched_rule_id` is a logical foreign key to it and a renumbered rule silently
  re-points every historical denial. **`DROP` precedes `RENAME`**, so the `sqlite_sequence` row
  moves with the new table and the `AUTOINCREMENT` high-water mark stays at `max(id)`. And **a
  `can_*` column for an action since withdrawn is carried over into a column added for it**, since
  §4.5 below promises those are never silently forgotten.

  The chain runs **before** `executescript(SCHEMA)` in `PermissionStore.__init__` — the opposite
  of `connection_store`'s order. Version 2 adds a second table whose foreign key names `rules`;
  running the script first would create `rule_targets` against the version 1 `rules`, which has no
  `uq_rules_identity` for that key to reference.

  **Version 2 -> 3** (`_migrate_2_to_3`) adds `rules.rule_name`, the operator's own label for a
  rule, because the rules list showed an object type, some patterns and an effect and nothing on
  the row said what the rule was *for*. It is **one `ALTER TABLE rules ADD COLUMN` and one
  `CREATE UNIQUE INDEX`**, with no table rebuild anywhere in it — which is the whole reason the
  field was ruled optional. The column is nullable, so every existing rule is already a valid
  version 3 row the moment the column exists: there is no value to compute, no row to rewrite and
  nothing to verify afterwards. **Nothing is backfilled**, and that is a decision rather than an
  omission: the alternative to a nullable column is a `NOT NULL` one satisfied by inventing a
  name for every rule the operator ever wrote, which is to say by writing text into their own
  rules list that they never wrote.

  The `VACUUM INTO` backup and the `MigrationRecord` are taken **all the same**, producing
  `permissions.db.v2.backup` and `permissions.db.v2.backup.log` through the same
  `db_migrations.backup_before_rebuild()` every other step uses. A cheap upgrade that skipped its
  own account because it judged itself safe is exactly the one nobody can check afterwards.

  Two details are load-bearing. The **index is created inside the step**, before
  `PRAGMA user_version = 3` is committed, so a file can never sit at version 3 carrying the
  column without the uniqueness that gives it meaning. And the step is **idempotent on the column,
  not on the version**: a file coming up from version 1 is rebuilt by `_migrate_1_to_2` from the
  *current* `_rules_ddl()` and therefore already has `rule_name`, so this step correctly does
  nothing — and takes no second backup — on the way past.

  `rule_name` takes no part in resolution. Nothing in `rule_for()`, `is_allowed()` or `require()`
  reads it, and `tests/test_permissions.py::test_naming_a_rule_cannot_change_a_permission_decision`
  is what keeps it that way.
- **`PRAGMA table_info(rules)` diffed against the union of `ACTIONS_BY_TYPE`** for the routine
  case of a new action, ported from f-MCP's `_migrate_schema()`: for each missing column, in
  sorted order for determinism,
  `ALTER TABLE rules ADD COLUMN can_<a> INTEGER NOT NULL DEFAULT 0`. A read-only database
  raises `RuntimeError` with an actionable message, as f-MCP does.

Adding an action therefore means editing exactly one tuple. Removing one is *not* automatic:
the column is left in place and ignored, because dropping it would need a table rebuild and
would destroy a record of what had been granted.

---

## 5. `audit.db`

### 5.1 One file, decided

One file with a `connection_id` column, not one file per connection. Confirmed. The consequences
worth recording: rotation is a single global policy rather than N drifting ones; the Logs page's
per-connection tabs are a `WHERE connection_id = ?` filter over one WAL connection rather than N
open handles and N poll timers; a connection deleted today keeps its history (§5.3); and the
cross-file `connection_id` reference is the same unenforced-but-monotonic one as
`permissions.db`, so there is one story to tell, not two.

### 5.2 DDL

```sql
-- audit.db
--
-- One row per MCP tool call, whether it succeeded, failed or was denied. The
-- Logs page renders one QTabWidget tab per connection over this single table,
-- filtered on connection_id.
--
-- This is the durable half of the dual-logging pair; the other is the
-- append-only JSONL sink beside it, which survives being spawned as a Claude
-- Desktop subprocess. A logging failure NEVER propagates into a tool result.

PRAGMA journal_mode = WAL;          -- set BEFORE the first CREATE TABLE
PRAGMA synchronous  = NORMAL;       -- see §6: throughput; JSONL is the belt and braces
PRAGMA foreign_keys = ON;
PRAGMA busy_timeout = 5000;
PRAGMA user_version = 1;

CREATE TABLE IF NOT EXISTS tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    connection_id   INTEGER,            -- logical FK -> connections.db connections(id).
                                        -- NULL for tools that touch no connection
                                        -- (list_connections, server status): those
                                        -- render under the Logs page's "System" tab.
    session_id      TEXT    NOT NULL,   -- 'cli' is the well-known id for an externally
                                        -- spawned server, as in f-MCP
    timestamp       TEXT    NOT NULL,   -- ISO 8601 with offset
    tool_name       TEXT    NOT NULL,
    params_json     TEXT    NOT NULL,   -- sanitised, size-capped; see §5.4
    rows_affected   INTEGER,            -- NULL where the verb has no row count
    duration_ms     INTEGER,            -- NULL if the call never started
    result          TEXT,               -- truncated at 1000 chars, as f-MCP
    error           TEXT,               -- truncated at 1000 chars
    decision        TEXT    NOT NULL,
    matched_rule_id INTEGER,            -- logical FK -> permissions.db rules(id); the rule
                                        -- CITED in the outcome. NULL on default-deny and on
                                        -- a multi-object allow, where no single rule decides.

    CONSTRAINT ck_tool_calls_decision CHECK (
        decision IN ('allowed', 'denied', 'refused', 'error')
    ),
    CONSTRAINT ck_tool_calls_params CHECK (json_valid(params_json)),
    CONSTRAINT ck_tool_calls_rows   CHECK (rows_affected IS NULL OR rows_affected >= 0),
    CONSTRAINT ck_tool_calls_ms     CHECK (duration_ms   IS NULL OR duration_ms   >= 0)
);

-- The Logs page's only query shape: one connection's tail, newest first.
CREATE INDEX IF NOT EXISTS idx_tool_calls_conn_ts ON tool_calls(connection_id, timestamp);

-- Clearing one session's rows, as f-MCP's clear_session does.
CREATE INDEX IF NOT EXISTS idx_tool_calls_session ON tool_calls(session_id);

-- The Logs page's "denied only" filter, and the security review's first query.
CREATE INDEX IF NOT EXISTS idx_tool_calls_decision ON tool_calls(decision, timestamp);
```

`decision` domain:

| Value | Meaning |
|---|---|
| `allowed` | Every referenced object was authorised and the call ran |
| `denied` | A permission rule (or default-deny) refused it; `error` carries the citing message |
| `refused` | Permitted by rule, but the destructive-operation confirmation was declined — or no confirmation subscriber was attached |
| `error` | Authorised and attempted, but the driver or the SQL failed |

Separating `refused` from `denied` is what lets the Logs page and the security review tell
"the rules say no" from "a human said no", which are very different findings.

### 5.3 A deleted connection keeps its history

**Audit rows are never deleted by a connection deletion.** Only rotation removes them. Deleting
the trail along with the profile would destroy the evidence of what that connection was used
for at exactly the moment someone is most likely to want it, and it would make "delete the
connection" an audit-erasure primitive available to anyone with the GUI.

The consequence is that `tool_calls` can hold rows whose `connection_id` no longer resolves.
That is intended, and `AUTOINCREMENT` guarantees the id is never re-issued, so a historical row
can never be misattributed to a later connection.

The Logs page needs a name for that tab, and cannot join to a row that is gone. The fix is the
ordinary audit-log one: **denormalise at write time.** `params_json` carries a reserved
`_connection` key holding the display name *as it was when the call was made*. This is more
correct than joining even for live connections — a renamed profile must not retroactively
rewrite what the log says happened — and it adds no column. Orphaned ids group under a tab
labelled `«name» (deleted)`, or `#<id> (deleted)` if no row carries a name.

### 5.4 Reserved `params_json` keys

`params_json` is the tool's own arguments, sanitised by the ported `_sanitize_params` (drops to
the important keys above 500 characters), plus three reserved keys the logger adds. They are
underscore-prefixed so they cannot collide with a tool parameter.

| Key | Contents |
|---|---|
| `_connection` | Connection display name at call time (§5.3) |
| `_objects` | The normalised `schema.name` identifiers the statement was found to touch, with the action required of each — the audit record of the multi-object authorisation in DESIGN-PERMISSIONS.md §5 |
| `_sql` | The exact statement submitted, truncated at 2000 characters, **never** with values interpolated — placeholders stay as placeholders so a bound secret cannot land in the log |

Putting the touched-object list here rather than in a new column keeps the mandated column set
intact while preserving the one piece of evidence a multi-object denial needs.

Credentials are never written to this file. `_sql` carries placeholders; bound parameter
*values* are not logged at all.

### 5.5 Rotation

Above 10 000 rows, delete the oldest 1 000 by `id` — by id, not by timestamp, because the id is
monotonic and a clock is not. **No `VACUUM`**: it takes an exclusive lock and defeats the
cross-process access WAL exists to provide.

```sql
DELETE FROM tool_calls
 WHERE id IN (SELECT id FROM tool_calls ORDER BY id LIMIT 1000);
```

f-MCP calls its trim only at start-up, which lets a long-running server grow without bound.
d-MCP runs it at start-up **and** every 1 000 inserts, tracked by a process-local counter so
the common path never pays for a `COUNT(*)`. Rotation failures are swallowed and reported to
stderr, like every other logging failure.

Rotation is blind to `connection_id`: a chatty connection can age out a quiet one's history.
That is accepted — the alternative is a per-connection quota, which needs a policy the user has
not asked for. It is a documented limitation in the README's `### Known limitations`.

---

## 6. `PRAGMA` settings

Set on **every** open, immediately after `sqlite3.connect(..., check_same_thread=False)` and
**before** the first `CREATE TABLE`. `journal_mode` is persistent in the file header, but
setting it every time is what makes a hand-copied or restored file behave; the others are
per-connection and must be re-set.

| Pragma | connections.db | permissions.db | audit.db | Why |
|---|---|---|---|---|
| `journal_mode` | `WAL` | `WAL` | `WAL` | GUI and MCP server are separate processes reading the same files concurrently |
| `synchronous` | `FULL` | `FULL` | `NORMAL` | see below |
| `foreign_keys` | `ON` | `ON`, **verified** | `ON` | `permissions.db` now has a real intra-file FK (`rule_targets` -> `rules`) that holds a target to the right connection, so the read-back matters: a SQLite built without FK support accepts the statement, sets nothing and reports `0` |
| `busy_timeout` | `5000` | `5000` | `5000` | the GUI's 500 ms poll must not collide with a server write |
| `user_version` | `2` | `3` | `1` | structural schema version (§4.5) |

**Why `synchronous` differs.** Under WAL, `NORMAL` can lose the most recent transactions on a
power failure without corrupting the file. For `audit.db` that is acceptable: the lost tail is a
handful of log rows, and the JSONL sink holds the same records. For `permissions.db` it is not,
and the reason is asymmetric. Losing the last transaction fails *closed* if it was a grant — the
grant simply did not happen — but fails **open** if it was a revoke: the operator revoked
access, the machine lost power, and on restart the access is back. A security store must not
have a failure mode that silently restores a withdrawn permission, so `permissions.db` is
`FULL`. `connections.db` is `FULL` for the far duller reason that a lost profile strands a
keyring entry no one can now address.

Verify WAL took effect and raise if it did not, as f-MCP's `LogStore` does — a filesystem
without shared-memory locking (some network mounts) silently falls back to `delete` mode, and
the cross-process design would then be quietly broken.

---

## 7. Referential integrity across files

### 7.1 Why there are no foreign keys

`rules.connection_id` and `tool_calls.connection_id` name a row in a *different database file*.
SQLite resolves a `REFERENCES` clause only within the schema that declares it; even with both
files `ATTACH`ed, a foreign key cannot cross the boundary, and declaring one produces a
constraint that is never checked. So there are none, and the columns are documented as logical
references.

Merging all three tables into one file would let SQLite enforce them, and was considered and
rejected: it would put the audit table — the highest-write, most corruption-exposed table, and
the one whose durability requirement is *lower* than the others — in the same file as the
security state, and it would make every `synchronous` decision in §6 a single compromise. The
integrity is cheap to maintain by hand; the durability separation is not.

### 7.2 What holds it together

**1. Ids are never recycled.** `AUTOINCREMENT` on `connections.id` (§3.2). This is the load-
bearing guarantee: a surviving orphan can be ignored or swept, but it can never be *adopted*.

**2. Deletion is an application-level cascade in a fixed order.** `ConnectionStore.delete(cid)`
performs, in this sequence:

1. `CredentialStore.delete(cid)` — remove the keyring/vault secret. First, because it is the
   only step that needs data the later steps destroy, and because a stranded secret is the one
   residue with a security cost.
2. `PermissionStore.revoke_connection(cid)` — `DELETE FROM rules WHERE connection_id = ?`,
   committed.
3. `DELETE FROM connections WHERE id = ?`, committed.
4. **Nothing** is done to `audit.db` (§5.3).

The order is chosen so that every interruption leaves a fail-closed state:

| Interrupted after | Surviving state | Safe? |
|---|---|---|
| step 1 | Profile and rules intact, no password | Cannot connect. **Closed.** |
| step 2 | Profile intact, zero rules | Default-deny authorises nothing. **Closed.** |
| step 3 | Complete | — |

The reverse order (profile first) would leave live rules pointing at a vanished profile. That
is also unreachable, because the MCP server can only obtain a `connection_id` by opening a
profile — but it leaves litter that the sweep then has to reason about, and it has a window in
which the *intent* of the state is ambiguous. Rules-before-profile has no such window.

There is no cross-file transaction, and there cannot be one; the ordering is the substitute.

**3. A start-up reconciliation sweep repairs an interrupted cascade.**
`PermissionStore.reconcile(known_connection_ids)` deletes every rule whose `connection_id` is
not in the supplied set and returns the count, logged at `WARNING` when non-zero. The GUI and
the CLI server both run it once at start-up, after `ConnectionStore` has opened and can supply
the id set. It is a `DELETE … WHERE connection_id NOT IN (…)`, not an `ATTACH`-based anti-join:
passing the ids in keeps `permissions.py` free of any knowledge of where the connection store
lives, which is the module boundary that lets the permission engine be tested with no
connections database present at all.

The sweep never touches `audit.db`.

**4. The resolver never consults `connections.db`.** `is_allowed` takes a `connection_id` as
given. An orphan id is therefore not a security hole even between the crash and the sweep: no
caller can produce it, because producing one means opening a profile that no longer exists.

### 7.3 Summary — what happens on delete

| Artefact | On connection delete |
|---|---|
| Keyring / vault secret | **Deleted**, first |
| `permissions.db` rules | **Deleted**, all rows for that `connection_id`, and their `rule_targets` rows explicitly first — the `ON DELETE CASCADE` would do it, but the sweep must not depend on a pragma being on in whichever process is deleting, and an orphaned target would later collide with a fresh `create_rule()` on `uq_rule_targets_key` |
| `connections.db` row | **Deleted**, last |
| `audit.db` rows | **Retained.** Only rotation removes them. Tab shows `«name» (deleted)` |
| `config.json` references | `explorer.last_connection_id` and any per-connection column widths are cleared by `ConfigManager` |

---

## 8. First-run creation sequence

A clean checkout has no `.db` and no `~/.sape/d-mcp/`. Exact order, GUI path:

1. **`main.py`** parses arguments. Nothing is created at import time — no store constructs a
   file as a side effect of being imported.
2. **`ConfigManager()`** constructs. It creates `~/.sape/d-mcp/` (`mkdir(parents=True,
   exist_ok=True)`) and *reads* `config.json` if present, but does **not** write it. The file
   appears on the first `set_*()`, which in practice is the first theme, language or geometry
   change. A session that changes nothing leaves no file, and the defaults in §9 are what runs.
3. **`ConnectionStore()`** constructs, resolving `connections.db` from `DMCP_CONNECTIONS_DB`,
   else `DMCP_DB_DIR`, else the current working directory
   (`sape_d_mcp.db_location.resolve_db_directory()` — see §1's revision note). Then, per
   file, the invariant sequence:
   1. `db_path.parent.mkdir(parents=True, exist_ok=True)`
   2. `sqlite3.connect(db_path, check_same_thread=False)`; `row_factory = sqlite3.Row`
   3. `PRAGMA busy_timeout = 5000`
   4. `PRAGMA journal_mode = WAL`, **verify the returned mode is `wal`**, raise `RuntimeError`
      naming the path if not
   5. `PRAGMA synchronous`, `PRAGMA foreign_keys` per §6
   6. `conn.executescript(SCHEMA)` — every statement is `CREATE … IF NOT EXISTS`, so this is
      idempotent — then `commit()`
   7. read `PRAGMA user_version`; if `0`, set it to the current version; if lower than current,
      run the structural migration chain; if **higher**, raise `RuntimeError` rather than
      proceeding — an older binary must refuse a newer file, not silently mis-read it
   8. `_migrate_schema()` where the store has tuple-driven columns (`permissions.db` only)
4. **`PermissionStore()`** constructs over `permissions.db`, same sequence.
5. **`AuditStore()`** constructs over `audit.db`, same sequence, then runs the start-up
   rotation (§5.5).
6. **`PermissionStore.reconcile(ConnectionStore.all_ids())`** — the §7.2 sweep. First run: both
   sets empty, zero rows deleted.
7. **No seeding, of anything.** No sample connection, no default rule, no "allow list on
   everything" starter. The application opens with an empty Connections page and a Permissions
   page that authorises nothing, and `test_a_new_database_grants_nothing` pins it.
8. The GUI shows. The MCP server is **not** started automatically.

The `--cli` path is steps 1 and 3–7 only: `ConfigManager` is not constructed, PyQt6 is never
imported, and `~/.sape/d-mcp/` is created only when the JSONL sink and `log.db` open.

Concurrency at first run: the GUI and an externally spawned `--cli` server can race to create
the same file. Every statement is `IF NOT EXISTS`, `busy_timeout` covers the lock contention,
and the `ALTER TABLE` migration is serialised by SQLite's own locking and is idempotent. The
race is safe; it is not merely unlikely.

---

## 9. `config.json`

`~/.sape/d-mcp/config.json`. The `d-mcp/` segment is not cosmetic: f-MCP writes `config.json`,
`log.db` and `installation.json` straight into `~/.sape/`, so without the namespace the two
applications would overwrite each other's preferences on the same machine. `~/.sape/d-mcp/` also
holds `log.db` (the per-session GUI log) and `installation.json`.

Everything the GUI persists lives here. Nothing else writes it: one `ConfigManager` instance per
process is the sole writer, fixing f-MCP's five racing writers.

### 9.1 Defaults

```json
{
  "schema_version": 1,
  "language": "en-US",
  "theme": "light",
  "minimize_on_startup": false,
  "window_state": {
    "geometry": { "x": null, "y": null, "width": 1280, "height": 800 },
    "is_maximized": false
  },
  "last_page_index": 0,
  "tables": {
    "connections":       { "0": 220, "1": 110, "2": 130, "3": 180, "4": 160, "5": 120 },
    "permissions_rules": { "0": 180, "1": 110, "2": 220, "3": 90,  "4": 100, "5": 150 },
    "logs":              { "0": 160, "1": 130, "2": 90,  "3": 90,  "4": 300, "5": 100 },
    "explorer":          { "0": 260, "1": 140, "2": 120, "3": 200 }
  },
  "logs": {
    "poll_interval_ms": 500,
    "auto_refresh": true,
    "max_rows_displayed": 1000,
    "denied_only": false,
    "last_export_directory": null
  },
  "explorer": {
    "last_connection_id": null,
    "expand_depth": 1
  },
  "server": {
    "transport": "streamable-http",
    "preferred_port": 8089
  },
  "confirmations": {
    "timeout_seconds": 60,
    "remember_for_session": false
  }
}
```

### 9.2 Key semantics

| Key | Type | Default | Notes |
|---|---|---|---|
| `schema_version` | int | `1` | A **higher** value than the binary knows is a hard error, not a merge; the binary refuses rather than silently discarding a newer key |
| `language` | BCP-47 | `en-US` | Must be a key of `LanguageRegistry.LANGUAGES`; an unknown value falls back to `en-US` with a `WARNING`, never a crash |
| `theme` | `light` \| `dark` | `light` | Anything else falls back to `light` |
| `minimize_on_startup` | bool | `false` | |
| `window_state.geometry` | object | 1280×800, position `null` | `null` x/y means "let the window manager place it". Restored geometry is clamped to the available screen so a profile from a disconnected monitor cannot open the window off-screen |
| `window_state.is_maximized` | bool | `false` | |
| `last_page_index` | int | `0` | Clamped to the page count; a stale index from a version with more pages must not crash the shell |
| `tables.*` | `{column index: width}` | per table | String keys, because JSON object keys are strings; f-MCP's convention, kept |
| `logs.poll_interval_ms` | int | `500` | f-MCP's timer interval, kept; floor 200, ceiling 10000 |
| `logs.max_rows_displayed` | int | `1000` | Per tab. Independent of the 10 000-row rotation in `audit.db` |
| `logs.denied_only` | bool | `false` | |
| `explorer.last_connection_id` | int \| null | `null` | Cleared when that connection is deleted (§7.3) |
| `server.transport` | `stdio` \| `sse` \| `streamable-http` | `streamable-http` | The GUI rewrites `stdio` to `streamable-http` at start, because stdio hangs on stdin inside a `QThread` |
| `server.preferred_port` | int | `8089` | Probing walks 8089–8098 by attempting `socket.bind()` |
| `confirmations.timeout_seconds` | int | `60` | A confirmation that times out is **`refused`**, never allowed |
| `confirmations.remember_for_session` | bool | `false` | Off by default and deliberately per-session only; never persisted across restarts |

**There are no credentials here, and no key that could hold one.** Nothing in this file is
security state — the whole file could be deleted between runs and the only loss would be window
geometry.

### 9.3 Writer behaviour

- **Deep-copied defaults.** `copy.deepcopy(DEFAULT_CONFIG)`, not `.copy()`. f-MCP's shallow copy
  aliases the nested `permissions_table_columns` dict with the class attribute, so one instance
  mutating it changes the default for every other.
- **Recursive merge**, file over defaults, at every level. f-MCP's `dict.update()` replaces
  nested objects wholesale and then hand-patches one key back, which does not generalise; a
  proper recursive merge means adding a key to `DEFAULT_CONFIG` is enough for an existing config
  file to pick up its default.
- **Unknown keys are preserved** on round-trip, so an older binary run against a newer config
  degrades to ignoring what it does not understand rather than deleting it. (A newer
  `schema_version` still refuses outright — the distinction is between unknown *keys*, which are
  harmless, and a declared structural change, which is not.)
- **Atomic write**: serialise to `config.json.tmp` in the same directory, `flush`, `os.fsync`,
  then `os.replace`. A crash mid-write must not leave a truncated file that fails to parse and
  loses every preference.
- **Unparseable file**: log the error, rename it to `config.json.corrupt-<timestamp>`, continue
  on defaults. Never crash the GUI over a preferences file, and never silently overwrite
  something the user might want to recover.
- **Debounced writes**: geometry changes go through the 300 ms `QTimer`, as f-MCP does; the
  timer is parented to the widget so it is not garbage-collected before it fires (f-MCP defect
  9). All other `set_*()` calls write immediately.
- `json.dump(..., indent=2, ensure_ascii=False)` — the file is meant to be readable and edited
  by hand, and `ensure_ascii=False` keeps a native-script window title legible.

---

## 10. Cross-references and open items

- The permission-resolution algorithm over `rules`, identifier normalisation, and multi-object
  authorisation: **`docs/DESIGN-PERMISSIONS.md`**.
- The MCP tool catalogue and the dialect abstraction interface are the remaining Stage 1
  deliverables and are specified elsewhere.
- The plan's remaining stage-1 open item — one tool set taking a `connection` argument versus a
  namespaced tool set per connection — is **not decided by this document**, and does not need
  to be: both shapes key permissions and audit rows on `connection_id`, so the data model is
  neutral. It belongs to the MCP tool catalogue.
