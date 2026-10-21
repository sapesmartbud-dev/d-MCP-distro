# SAPÉ d-MCP

**Permission-gated database access for LLMs, with a rule database you actually manage.**

SAPÉ d-MCP is a [Model Context Protocol](https://modelcontextprotocol.io) server that exposes MS-SQL, PostgreSQL, MySQL/MariaDB and SQLite operations to an LLM client — Claude Desktop, or anything else that speaks MCP — and refuses any table, view, function or procedure that isn't covered by an explicit rule. It ships with a desktop GUI for writing those rules, approving destructive operations as they happen, and reading back what the model actually did, one tab per connection.

It is the database counterpart to [SAPÉ f-MCP](https://github.com/sapebud/f-mcp), which does the same job for the file system, and reuses its visual language, its structural conventions and its habit of documenting its own defects rather than hiding them.

**This is version 0.1.0.8 Beta.** The permission model and the 38-tool catalogue are final; what is still open is cross-engine and cross-platform coverage — see [Known limitations](#known-limitations) before pointing it at a database you cannot afford to lose.

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)

---

## What it does

38 MCP tools over a required `connection` argument — one catalogue, whatever the number of configured connections. Eighteen of them read, thirteen write, seven manage roles, users and groups. Adding a database does not grow the catalogue; it adds a value to the `connection` enum.

| Group | Tools | What it covers |
|---|---|---|
| Meta | 2 | List configured connections; show the permission rules in force for one of them |
| Database / security | 12 | Read the catalogue, schemas, roles, users and groups; create roles, users and groups; manage group membership and role assignment |
| Tables | 8 | List, describe structure, read rows, insert, update, delete, create, drop† |
| Views | 5 | List, read definition, read rows, create, drop† |
| Functions | 5 | List, read definition, create, edit†, drop† |
| Stored procedures | 5 | List, read definition, create, edit†, drop† |
| Query | 1 | `run-read-query` — one free-form read-only statement, gated and object-checked like every structured tool |

† `drop` and `edit` are named in the catalogue and reachable by an MCP client, but no permission
rule can ever authorise either one — every call to `drop-table`, `drop-view`, `drop-function`,
`drop-procedure`, `edit-function` or `edit-procedure` is refused unconditionally. See
[Known limitations](#known-limitations).

**Objects no rule covers are refused, and an empty permission database authorises nothing.** A rule is `(connection, schema pattern, object type, name pattern) → allowed actions`; the most specific match wins, and an explicit deny beats an allow at equal specificity. There is no implicit grant, and configuring a connection only makes it reachable — it authorises nothing by itself.

### Views, and what a query really reads

Reading a view requires permission on the **view** *and* on **every base object it reads**, recursively through nested views and through any function called along the way. A grant on a view is not a grant on what is underneath it.

This is deliberately the stricter of two readings. In ordinary SQL practice a view is exactly the tool for exposing a filtered subset of a table without granting the table itself — d-MCP takes that away, because the connection behind a rule may hold far broader credentials than the operator wants exposed, and `create-view` is itself in the catalogue: a lenient rule would let a view the model was permitted to create become a channel to everything the connection can see. An operator who genuinely wants view-only exposure gets it one layer below d-MCP, by pointing the connection at a database user that can see only the view.

The same principle runs through the whole design: `select-rows` and `run-read-query` authorise every object a `WHERE` subquery reaches, `create-function` and `create-procedure` authorise every object their bodies reference, and an object the guard cannot fully resolve is refused rather than guessed at.

---

## Requirements

- Python **3.10** or newer
- **PyQt6 ≥ 6.6.1** — only for the GUI. Headless (`--cli`) operation never imports it.
- `mcp` **≥ 2.0** — the 2.x SDK renamed `FastMCP` to `MCPServer`; 1.x fails at import.

### Platform support

| Platform | Status |
|---|---|
| **Linux** | The test suite, the GUI and the PyInstaller bundle all run here. The only platform anything has been verified on — though the GUI has only ever been driven offscreen, so none of its visual checks is proved anywhere |
| **Windows 10+** | Target platform, nothing verified. No build, no GUI launch, no console-window check has been run |
| **macOS** | Target platform, nothing verified |

All three are first-class targets and the code is written for all three, but only Linux has been exercised. The manual checklist for the other two is [`docs/CROSS-PLATFORM-SMOKE-TEST.md`](docs/CROSS-PLATFORM-SMOKE-TEST.md), which also records exactly what the Linux VM could *not* prove — chiefly that `pyodbc` cannot even be imported there, and that PyInstaller's `.ico` embedding path has never run on any machine.

### Platform prerequisites

What follows is what each platform needs beyond Python itself. **Instructions are not evidence.** A recipe below being confident says only that it follows from the code and the packaging — the table above still stands, and only the Linux one has been run.

#### Linux

| Need | Why |
|---|---|
| `python3-venv` | On Debian and Ubuntu this is a **separate package** from `python3`. Without it `python3 -m venv .venv` fails with a message about `ensurepip` that does not name the package you are missing |
| `python3-pip` | Also separate, for the same reason and with the same unhelpful error |
| `libxcb-cursor0` | Qt 6's `xcb` platform plugin links it. Without it the GUI does not fail, it **aborts**: Qt calls `abort()`, so the process dies on `SIGABRT` with exit code 134 and a core dump, and there is no Python traceback to read. Do not go looking for one. Read the *first* line of Qt's output — `From 6.5.0, xcb-cursor0 or libxcb-cursor0 is needed to load the Qt xcb platform plugin` — which names the package; the two lines after it, `Could not load the Qt platform plugin "xcb" ... even though it was found`, are the ones people quote and search for, and they mislead, because the plugin file genuinely is found and a library *it* needs is what is missing |
| `unixodbc` | Only for `pyodbc`, which links `libodbc.so.2`; without it `import pyodbc` raises `ImportError` before any connection is attempted. On Ubuntu 24.04 the library itself is `libodbc2` and `unixodbc` pulls it in; the split differs by distribution. `pymssql` needs none of this — see [Database drivers](#database-drivers) |

```bash
sudo apt install python3-venv python3-pip libxcb-cursor0
sudo apt install unixodbc          # only if you want the pyodbc driver
```

All four were absent on the Ubuntu 24.04 guest this was checked on — `dpkg -l` reported none of them, so the list is measured rather than assumed. Your distribution may differ in the package names but not, in practice, in the fact that these are separate from `python3`.

**Credentials.** `gnome-keyring` and `libsecret-1-0` ship with a normal desktop, and the keyring genuinely works there — the probe resolves to `keyring.backends.SecretService.Keyring`. `credential_store.py` does not trust that name: it performs a real set/get/delete round trip with a random token under a reserved account, because on a headless box `keyring` reports the same backend and then fails at runtime with a D-Bus error, having no session bus and no `gnome-keyring-daemon`. Only when that round trip fails does it fall back to the AES vault at `~/.sape/d-mcp/credentials.vault`.

**Launching from a desktop entry bites hardest here.** A `.desktop` file or a dock icon hands the process whatever working directory the desktop environment felt like, and the three databases are resolved against it — so d-MCP starts, finds an empty `permissions.db` somewhere you never chose, and refuses every tool call while looking perfectly healthy. Launching from a menu is normal on Linux in a way it is not on Windows, so set `DMCP_DB_DIR` in the `.desktop` entry's `Exec=` line, or launch from a terminal in the directory you mean.

**System (integrated) authentication needs Kerberos here.** Ticking "Windows account" (`auth_mode=integrated`) on an MS-SQL/`pyodbc` profile works off Windows too — `msodbcsql18` goes through GSSAPI instead of SSPI — but it needs three things arranged outside d-MCP, none of which the application manages or checks for you:

1. A valid Kerberos ticket for your account, obtained with `kinit`.
2. A `krb5.conf` naming the Active Directory realm the SQL Server belongs to.
3. The server itself registered with a Service Principal Name (`MSSQLSvc/host:port`) in that realm — ask whoever administers the domain controller, this is not something a client machine can set up.

Without a ticket the connection does not fail quietly: the server reports a login for `NT AUTHORITY\ANONYMOUS LOGON`, which reads like a permissions problem on the SQL Server side and is actually a missing ticket on this one. Pasteable for a Debian/Ubuntu box already joined to the domain:

```bash
sudo apt install krb5-user                 # provides kinit and klist
kinit youraccount@YOUR.REALM.EXAMPLE       # realm is upper-case by Kerberos convention
klist                                      # confirm the ticket is there before connecting
```

`/etc/krb5.conf` needs a `[libdefaults]` `default_realm` and a `[realms]` entry pointing at the domain controller's KDC — both are usually generated for you if the machine was joined to the domain with `realm join`/`sssd`; if it was not, ask your Active Directory administrator for the realm name and KDC address rather than guessing them. PostgreSQL's `gss`/`sspi` methods over TCP need the same ticket; a Unix-socket `peer` connection needs none of this at all.

#### Windows 10+

Nothing extra is required to run the GUI: the PyQt6 wheel carries its own Qt. The sequence under [Running it](#running-it) is the whole of it, with `.venv\Scripts\activate` in place of `source .venv/bin/activate`, and `.venv\Scripts\python.exe` as the interpreter you name in the client configuration.

| Need | Why |
|---|---|
| **Microsoft ODBC Driver 18** | Only for `pyodbc`, and installed separately — see [Database drivers](#database-drivers). `pymssql` exists precisely so this is optional |

**Credentials** go to Windows Credential Manager through `keyring`, with the same round-trip probe and the same AES fallback as everywhere else.

**System (integrated) authentication needs nothing set up here.** Choosing "Windows account" on an MS-SQL/`pyodbc` profile presents the token of the process d-MCP itself runs as, through SSPI — no ticket, no configuration file, nothing to install. This is the one platform where it just works; see the Linux prerequisites above for what the same option needs everywhere else, through Kerberos.

**Server discovery reads the registry, read-only, with no administrator rights.** Clicking "Discover" on the Connections page looks for a locally installed SQL Server by opening two registry locations under `HKEY_LOCAL_MACHINE`, both with `KEY_READ` only — d-MCP never writes to the registry and never asks for elevation:

- `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL` — every named instance registered on the machine, mapped to its internal instance ID.
- `HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\<internal ID>\MSSQLServer\SuperSocketNetLib\Tcp\IPAll` — that instance's configured TCP port, including a dynamic one SQL Server Express assigns at every service restart, which is precisely the value a free-text host field can never keep up with. Both the 32-bit and 64-bit registry views are checked, because a 32-bit SQL Server 2008 R2 Express install (still not rare on older machines) writes to the 32-bit view alone.

A locked-down machine that denies read access to `HKEY_LOCAL_MACHINE` for a standard user account (unusual, but seen on some managed estates) makes "Discover" simply find nothing there — it fails closed to an empty result, never to an error dialog, and every other discovery source (listening TCP ports, ODBC DSNs, SQLite files) still runs normally. `src/sape_d_mcp/db/discovery.py` §7.2/§7.3 is the implementation; nothing under this heading needs a system administrator's involvement before deployment, only their awareness that it happens.

**None of this has been run.** No build, no GUI launch, no check of the console-window behaviour `main.py` and the PyInstaller spec between them depend on. `docs/CROSS-PLATFORM-SMOKE-TEST.md` §4 is what proves it when you get to a Windows machine.

#### macOS

The sequence is the Linux one — `python3 -m venv`, `source .venv/bin/activate`, `pip install -r requirements.txt`, `python main.py` — with no Qt system packages needed, because the PyQt6 wheel carries Qt here too.

**Credentials** go to the macOS Keychain, again through `keyring` and again behind the same round-trip probe.

**Drivers:** `pymssql` avoids the ODBC install the same way it does on Windows. If you want `pyodbc` instead you need unixODBC and Microsoft's macOS ODBC Driver 18, which is a separate download from Microsoft.

**System (integrated) authentication needs Kerberos here too**, exactly as on Linux — see that section above for the full explanation of what a ticket, a `krb5.conf` and an SPN are for. macOS ships its own Kerberos (Heimdal, not MIT's), so `kinit` is already on the machine with no package to install:

```bash
kinit youraccount@YOUR.REALM.EXAMPLE
klist
```

`/etc/krb5.conf` is the same file with the same syntax; a Mac already bound to Active Directory through Directory Utility usually has one generated already. Nobody has verified this against a real domain-joined Mac while writing d-MCP — it follows from Heimdal accepting the same `kinit`/`krb5.conf` contract MIT Kerberos does on Linux, not from a session at a terminal, which is exactly the caveat the paragraph below states about this section more generally.

**This section is deliberately thin, and that is not modesty.** Nobody has run d-MCP on macOS, and no macOS machine was available while it was written; everything above follows from the code and the packaging rather than from a session at a terminal. Anything more specific — a Homebrew formula name, an Xcode command-line-tools requirement, a code-signing or Gatekeeper step for the frozen bundle — would be invention, so it is omitted rather than guessed. Expect to hit at least one thing this section does not mention.

### Database drivers

Both MS-SQL drivers ship together on purpose, so multi-platform support never depends on an external installer being reachable. The connection profile records which one a given connection uses.

| Engine | Driver | Package | Host requirement |
|---|---|---|---|
| MS-SQL | pyodbc *(default)* | `pyodbc>=5.0` | **Microsoft ODBC Driver 18**, installed separately — pyodbc does not bundle it |
| MS-SQL | pymssql | `pymssql>=2.3` | none — FreeTDS is compiled into the wheel |
| PostgreSQL | psycopg | `psycopg[binary]>=3.1` | none — the `binary` extra bundles `libpq` |
| MySQL / MariaDB | PyMySQL | `PyMySQL>=1.1` | none — pure Python |
| MySQL / MariaDB | mysql-connector-python | `mysql-connector-python>=8.3` | none |
| SQLite | `sqlite3` | standard library | none — always present |

A connection profile records which driver to use per engine. A missing package is reported as a named `DriverNotInstalledError` carrying the pip requirement to install, not a bare traceback.

---

## Status

**All nine stages of a staged, user-gated build are complete.** Everything below describes what
this checkout does, not what it intends to. What has *not* happened is a release: there is no
tag, no published wheel, and no build anyone has run on Windows or macOS.

What works today:

- **The MCP server**, with all 38 tools: 18 read, 13 write, 7 security. `python main.py --cli`
  starts it on stdio without importing PyQt6.
- **Four engines** through one dialect abstraction — MS-SQL, PostgreSQL, MySQL/MariaDB, SQLite —
  and six drivers, both MS-SQL drivers included.
- **The permission engine**, default-deny and never seeded, and the **SQL guard** that classifies
  every statement, refuses what it cannot classify, and resolves every object a statement
  actually reaches before authorising any of them.
- **The credential store** (OS keyring, AES/master-password fallback), the **confirmation broker**
  and its modal, and the **audit log** with one Logs tab per connection.
- **The GUI**: seven pages, both themes, 18 selectable languages, the legal documents rendering,
  and the MCP configuration wizard under Settings.
- **3 178 passing tests**, 29 skipped. Every skip names what it wants: a live MS-SQL, PostgreSQL
  or MySQL server (`DMCP_TEST_PROFILE_*`), or, in one case, a `pyodbc` that will import.
  `pytest tests/test_generated_config.py` is the sharpest of them: it asks the wizard for the
  configuration it would hand you, **launches that command as a subprocess**, speaks real JSON-RPC
  to it and asserts `tools/list` returns exactly those 38 names.
- **A PyInstaller bundle**: `pyinstaller sape-d-mcp.spec` produces `dist/sape-d-mcp/`, and it has
  been built and smoke-tested — **on Linux only**.
- **`ruff` and `mypy` both clean**, against the rulesets `pyproject.toml` configures. Neither had
  ever been run against one before this stage.

What is not done:

- **Windows and macOS are unverified.** Not the build, not the GUI, not the console-window
  behaviour, not the taskbar icon. [`docs/CROSS-PLATFORM-SMOKE-TEST.md`](docs/CROSS-PLATFORM-SMOKE-TEST.md)
  is the checklist that closes this, and its last section lists what the Linux VM could not prove.
- **The GUI's visual checks are not in the test suite** and cannot be. The suite drives the
  widgets headlessly, which proves the wiring, the translations and the shutdown, and proves
  nothing about whether an icon is blank or a message is stranded at the bottom of a panel. Those
  are §3 of the same checklist, and they have not been run on any platform.
- **`pyodbc` has never been imported on the development machine**, let alone connected with: it
  needs `libodbc.so.2`, which is not installed there. Every Linux bundle is therefore built
  *without* it and the spec prints a warning saying so. `pymssql` covers MS-SQL in the meantime.
- **Sixteen of the eighteen languages are untranslated** and fall back to English.
- **`black` is configured and deliberately not satisfied.** It would reformat 68 of 92 files,
  and running it would land a formatting-only diff across three quarters of the tree in the same
  commit as stage 9's real fixes. `ruff` already enforces import order and the same 120-column
  limit, so nothing is unguarded meanwhile. Satisfying `black` is its own future commit, by
  decision rather than by neglect — see [Running the checks](#running-the-checks).
- **`mypy --strict` does not pass**: 34 errors across 18 files, chiefly missing parameter and
  return annotations. The floor `pyproject.toml` configures does pass; `--strict` is the
  remaining gap, and it is a target rather than a regression.

The stage list and what each stage delivered are in
[`DEVELOPMENT-PLAN.md`](DEVELOPMENT-PLAN.md) and [`CHANGELOG.md`](CHANGELOG.md); the user
authorises each stage before it starts.

---

## Running it

```bash
git clone https://github.com/sapebud/d-mcp.git
cd d-mcp
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

python main.py
```

That launches the GUI. `python main.py --cli` starts the server headless, on stdio, without importing PyQt6 — so it runs on a machine with no Qt installed:

```bash
pip install "mcp>=2.0" anyio keyring cryptography sqlparse   # plus the drivers you need
python main.py --cli
```

`pip install .` puts the same entry point on the path as the `sape-d-mcp` console script; `python main.py` is a development shim so the clone-and-run sequence above needs no install step.

### Running inside a virtual machine

A guest OS is an ordinary OS, so the [prerequisites](#platform-prerequisites) for whichever one you run apply unchanged — including `libxcb-cursor0` on a Linux guest, which a VM reader is likelier than anyone to hit, because a minimal guest install is exactly where it is missing. What follows is the **extra** layer, and it applies only if the project itself lives on a VirtualBox shared folder: that folder is a `vboxsf` mount, and it cannot do several things an ordinary filesystem can.

**This section exists because every symptom below presents as a broken application and none of them is one.** That is the sentence worth an hour of your time. Check which filesystem you are on before you debug anything:

```bash
stat -f -c '%T' .          # vboxsf  -> this section applies
                           # ext2/ext3, xfs, apfs, ... -> it does not
```

| Symptom | Cause | What to do |
|---|---|---|
| `python3 -m venv .venv` fails with `Error: [Errno 1] Operation not permitted: 'lib' -> '.../.venv/lib64'` | `venv` creates `lib64` as a symlink to `lib`, and `vboxsf` refuses symlinks outright | Put the environment outside the share. The code may stay on it |
| `ruff` fails with `Failed to rename temporary cache file ... Text file busy (os error 26)` | `vboxsf` cannot do the atomic rename ruff persists its cache with | Run `ruff check --no-cache` |
| `pyinstaller sape-d-mcp.spec` with its default `build/` and `dist/` inside the project | PyInstaller's build tree uses symlinks, and the share **cannot create one at all** — the same refusal as the `venv` row above, and it is worth proving to yourself once: `ln -s /tmp ./probe` fails with `Operation not permitted` on the share and succeeds anywhere off it | Direct the build off the share with `--workpath` and `--distpath`, as below. Stage 9's Linux bundle was built that way for this reason |

**The venv.** Build it on a real filesystem and point it at the project, rather than moving the project:

```bash
python3 -m venv ~/venvs/d-mcp
~/venvs/d-mcp/bin/pip install -r requirements.txt

cd /path/to/d-mcp                      # on the share, as normal
~/venvs/d-mcp/bin/python main.py
```

Run it from the project directory, not from the venv's: the three databases resolve against the working directory (see [Command line](#command-line)), so `cd` still decides where your rules live.

VirtualBox can be told to allow symlinks on a shared folder — `VBoxManage setextradata "<VM>" VBoxInternal2/SharedFoldersEnableSymlinksCreate/<share> 1`, on the host, with the VM stopped — which should make a venv on the share work. **Untested here**, and it needs a host with elevated privileges, so the out-of-share venv above is the route that is actually known to work.

**Building the bundle:**

```bash
pyinstaller --workpath ~/build/dmcp --distpath ~/dist/dmcp sape-d-mcp.spec
```

The rest of the build procedure, including the driver warning to grep for, is in [`docs/CROSS-PLATFORM-SMOKE-TEST.md`](docs/CROSS-PLATFORM-SMOKE-TEST.md) §1.

None of this is specific to VirtualBox as such. Any share that cannot create symlinks or rename atomically — some network mounts, some container bind mounts — behaves the same way, and the `stat -f` check above is the way to tell.

### Command line

```
python main.py [--cli] [--transport {stdio,sse,streamable-http}] [--show-permissions] [--version]
```

| Flag | Meaning |
|---|---|
| `--cli` | Start the server immediately, no GUI. This is what an MCP client spawns |
| `--transport` | Transport `--cli` serves on: `stdio`, `sse` or `streamable-http`. Default `stdio`. It has no effect without `--cli` |
| `--show-permissions` | Print every configured connection and the rules in force on it, then exit. Headless — no PyQt6 import, and no target database is contacted, so it answers even for a server that is currently unreachable, which is one of the reasons to run it |
| `--version` | Print the version and exit |

**There is no `--db` flag.** f-MCP has one, for its single `permissions.db`; d-MCP has three databases that need not share a directory, and a flag taking a single prefix would have to assume they do. Each is resolved from its own environment variable instead:

| Variable | Selects |
|---|---|
| `DMCP_CONNECTIONS_DB` | `connections.db`, by full path |
| `DMCP_PERMISSIONS_DB` | `permissions.db`, by full path |
| `DMCP_AUDIT_DB` | `audit.db`, by full path |
| `DMCP_DB_DIR` | The directory for all three at once, where no per-file variable is set |

**With none of them set, all three are resolved against the current working directory** — not against the checkout, not against your home directory. That is a user decision with a consequence worth stating plainly: launching from two different directories genuinely gives you two different sets of rules and two separate audit trails. [`docs/adr/0001-database-location.md`](docs/adr/0001-database-location.md) records the three candidates and why this one was chosen; `src/sape_d_mcp/db_location.py` implements it; the Known limitations section below states what it costs.

The safe direction is at least the one it fails in: an unexpected directory means a fresh, empty `permissions.db`, and an empty permission database authorises nothing.

The GUI can also run the server in-process, from the status bar. It serves `streamable-http` rather than `stdio` there — stdio inside a Qt thread would block on standard input — probing ports 8089 to 8098 for a free one. `--cli` is the stdio path.

### Connecting an MCP client

The GUI generates this for you: **Settings → MCP Configuration**. It detects how this copy is installed, names the interpreter it is itself running on, and pins all three database paths to the ones you are editing — so the process your client spawns enforces the rules you are looking at, rather than resolving its own against whatever directory the client happened to spawn it from.

| Client | Config file |
|---|---|
| Claude Desktop (Windows) | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Desktop (macOS) | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Desktop (Linux) | `~/.config/Claude/claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "sape-d-mcp": {
      "command": "/absolute/path/to/.venv/bin/python",
      "args": [
        "/absolute/path/to/d-mcp/main.py",
        "--cli", "--transport", "stdio"
      ],
      "env": {
        "DMCP_CONNECTIONS_DB": "/absolute/path/to/d-mcp/connections.db",
        "DMCP_PERMISSIONS_DB": "/absolute/path/to/d-mcp/permissions.db",
        "DMCP_AUDIT_DB": "/absolute/path/to/d-mcp/audit.db"
      }
    }
  }
}
```

On Windows the command is `...\.venv\Scripts\python.exe`. **Merge** this into the file — don't replace it, or you will drop the other servers you have configured. Restart the client afterwards. d-MCP never writes the client's configuration file itself; it shows you the JSON and copies it to the clipboard.

The `env` block is not optional decoration. Leave it out and the spawned server resolves its three databases against the client's own working directory, which is essentially never yours — it will start, find an empty permission database, and refuse everything, with nothing on screen explaining why.

Use an absolute path to a Python that has `mcp` installed. A bare `"python"` is resolved in the client's environment, which is usually not the one you installed into.

---

## First run

No `.json` and no `.db` exists in a clean checkout, and none is seeded. On first run the application creates `connections.db`, `permissions.db` and `audit.db` in whatever directory it was launched from (see [Command line](#command-line)), and `~/.sape/d-mcp/config.json` on the first preference change. **The permission list starts empty, and an empty list authorises nothing** — not a default connection, not a default schema, not a default anything. Until a rule is added through the Permissions page, every tool call is refused. There is a test that pins exactly this, so it cannot be softened by accident.

Configuring a connection does not grant anything either. It makes a database *reachable*; the rules decide what may be done with it.

Database passwords never go into `connections.db`. They go to the OS keyring, with an AES/master-password fallback where no keyring backend exists — the connection profile never stores a credential, and no tool ever accepts, returns or logs one. `create-user` takes no password on any engine, deliberately: there is then no path by which a model can introduce a credential.

---

## The GUI

Seven pages, ported from f-MCP's shell with database-domain content:

| Page | What it does |
|---|---|
| **Connections** | Connection profiles, engine and driver pickers, keyring-backed credential entry, a test-connection button. Sidebar index 0, and what a first run opens on — without a connection there is nothing to permission, browse or log. Later runs reopen whichever page you left |
| **Permissions** | Per-connection rule table with actions grouped by object type, plus a schema-browser panel beside it showing the connection's real catalogue, with a padlock on everything no rule reaches |
| **Logs** | One tab per connection over `audit.db`, plus a tab for each deleted connection and a System tab for rows belonging to no connection. Filterable, with CSV export |
| **Settings** | Theme, language, the sample-data toggle, the three resolved database paths, and the MCP configuration wizard |
| **Legal** | The four legal documents, rendered as formatted text rather than raw markdown |
| **Help** | Usage documentation |
| **About** | Version, author, licence |

There is **no Explorer page**. It was folded into Permissions as that schema-browser panel, so an object and the rule covering it are seen together and there is only one tree to keep in sync.

PyQt6, dark and light themes, 18 selectable interface languages.

**On the languages:** all 18 are selectable, but only English and Spanish are genuinely authored — the same as f-MCP. The other sixteen carry the English source text until someone translates them. Treat anything other than English and Spanish as unfinished, whatever the selector offers.

**On sample data:** every page can be filled with fictitious rows from a Settings toggle, so density, column widths and text overflow can be judged. It defaults to **off**, because the empty state is what a first-run user actually sees and it has to look as finished as the populated one. Nothing on a sample-data screen can write to a real store.

**On the audit log:** `audit.db` is a rotating store, not an archive — above 10 000 rows the oldest 1 000 are deleted, with no `VACUUM`. If you need durable history, export from the Logs page before it rotates past what you need.

---

## What this is not

**It's a permission system, not a sandbox.** It enforces object-based access control inside its own tool calls. It does not give you kernel-level enforcement, protection against privilege escalation, or a security boundary against an adversarial LLM client. The server runs with the credentials of whatever database user the connection profile names: everything *inside* the rules you write stays reachable through it. Grant narrowly.

See [DISCLAIMER.md](DISCLAIMER.md) for the full risk notice and [DATA-PROTECTION.md](DATA-PROTECTION.md) for what is stored locally and what a connected LLM client can see.

### Known limitations

Things worth knowing before you rely on this. None of them is a secret; they are recorded here rather than left to be discovered later.

- **This is a permission system, not a sandbox** — restated because it is the limitation everything else follows from.
- **`drop` and `edit` are never granted, on any rule, under any configuration.** Of the ten tools historically described as destructive, six — `drop-table`, `drop-view`, `drop-function`, `drop-procedure`, `edit-function`, `edit-procedure` — stay in the catalogue so an MCP client can still see and call them, but the permission engine refuses every one of them unconditionally, before the call ever reaches the confirmation dialog below. No rule, however broadly or narrowly written, can turn either action on. The consequence is stated plainly because it changes what d-MCP is for: **every table, view, function and procedure it creates is create-once.** A table cannot be dropped. A view can neither be dropped nor replaced. A function or a stored procedure can neither be dropped nor have its body replaced — there is no surviving "edit" path once `edit` is refused. Fixing a mistake, or removing an object you no longer want, is a job for a database client connecting directly to the server; d-MCP has no way back. See [`docs/adr/0005-drop-and-edit-are-never-granted.md`](docs/adr/0005-drop-and-edit-are-never-granted.md) for the full reasoning.
- **The other four destructive tools still need the GUI.** `delete-rows`, `revoke-role`, `remove-user-from-group`, and `update-rows` when the composed statement has no effective `WHERE`, wait on a live confirmation dialog in the d-MCP window. With no GUI attached, which is the normal state of a `--cli` server spawned by a client with the window closed, the operation is denied immediately and the denial is logged. A headless server can read whatever its rules allow, and — with an operator watching — can still remove rows or revoke access; it cannot drop or replace an object under any circumstances, GUI or none (see above). There is no "remember this decision" and no "approve all": every approval is single-use, bound to one exact statement, which across a run of repeated deletions is real friction and is meant to be.
- **A `permissions.db` from this build will not open in an older one.** The schema moved to version 4 to enforce the `drop`/`edit` prohibition above; a build that still expects version 3 refuses to open a version 4 file outright, rather than silently honouring `can_drop`/`can_edit` as real grants again. Keep the database file's schema version in step with the build reading it, particularly if you ever roll back to an earlier release.
- **Database location follows the working directory.** With none of the `DMCP_*` variables set, the three databases are resolved against wherever the process was launched from. A frozen application started from a desktop shortcut therefore resolves them against a directory you never chose — on Windows, typically the folder the executable sits in — and launching from two different directories genuinely means two different sets of rules. The permission half of that fails closed (an empty `permissions.db` authorises nothing), but the audit half does not: a split audit trail is worse than a missing one, because each fragment still opens and still looks complete, with nothing in the file to say there were other rows somewhere else. Set `DMCP_DB_DIR`, or let the Settings wizard pin the paths for you.
- **`pyodbc` can go missing from a frozen bundle without an error.** PyInstaller's `collect_submodules("pyodbc")` has to import the package to confirm it has no submodules, and when that import fails it returns an empty list — no exception, no warning. A bundle built that way simply has no ODBC MS-SQL driver, discovered the first time someone picks that engine. `sape-d-mcp.spec` now prints an explicit `sape-d-mcp.spec: WARNING` line when it happens, so **grep the build output for it**. On Windows and macOS that warning is a real defect to fix before shipping; on the Linux build machine used here it is expected, because `libodbc.so.2` is not installed there, and `pymssql` covers MS-SQL instead.
- **The audit log rotates and is not an archive.** `audit.db` is capped and the oldest rows are deleted once it passes 10 000; it is a working log, not a compliance record. Export what you need to keep.
- **The HTTP transports (`sse`, `streamable-http`) are unauthenticated.** Any local process that can reach the port can call every tool the rules allow. `stdio` has no such exposure — prefer it.
- **Identifier case-folding differs per engine.** SQL Server and MySQL fold unquoted identifiers differently from PostgreSQL and SQLite, and a permission rule that matches on one engine's folding may not match the same name on another. Rules are matched against the connection's own introspected catalogue for this reason, but a name typed by hand into a rule should still be checked against the object as that engine actually names it.
- **Rows returned to the client may be transmitted to a hosted model provider.** Granting `select` on a table containing personal data does not keep that data on your machine: the matched rows go to the MCP client, and from there, typically, to a third-party LLM provider's infrastructure — see [DATA-PROTECTION.md](DATA-PROTECTION.md) for what that implies under GDPR/RGPD.
- **Translation coverage.** All 18 languages are selectable, but only `en-US` and `es-ES` are genuinely authored. The other sixteen are registered, flagged and translatable, and every one of their strings is the English source text copied verbatim — so a locale you pick will simply show English, not an error. `gui_resources/flags/mapping.txt` lists which is which.
- **There is no system tray.** Closing the window quits the application; there is no icon to restore it from and no way to keep the confirmation broker alive with the window shut. That is not an abandoned feature — no tray was ever designed, and `QSystemTrayIcon` appears nowhere in the codebase; the sentence claiming one was inherited from f-MCP's README, which does not have a tray either. The consequence follows from the entries above: a d-MCP with no window open denies every destructive operation — the six that are refused outright whether or not a window exists, and the four that need a confirmation dialog with no window left to show it in — and there is no tray to keep it running out of sight from.
- **Only SQLite has been exercised against a real database on the development machine.** MS-SQL, PostgreSQL and MySQL are covered by unit tests over each dialect's composed SQL and by proving their drivers import; the integration tests that would connect to a live server skip, naming the `DMCP_TEST_PROFILE_*` variable they wanted. Twenty-nine tests are in that state. See [`docs/CROSS-PLATFORM-SMOKE-TEST.md`](docs/CROSS-PLATFORM-SMOKE-TEST.md) §7.

---

## Development

Src-layout: the installable package is `src/sape_d_mcp/`, imported as `sape_d_mcp.*`. `setuptools.packages.find` walks `src/`, so every subpackage — including the GUI ones — lands in the wheel. f-MCP's `packages = ["src"]` omits them and produces a broken install; that is not repeated here.

```
main.py                                Development shim: GUI by default, --cli headless, never imports PyQt6
pyproject.toml  requirements.txt       Packaging and runtime dependencies
requirements-dev.txt                   Test and lint tooling, kept identical to the `dev` extra
sape-d-mcp.spec                        PyInstaller build spec — one-directory bundle
Stack.md                               One-page view of the approved stack
DEVELOPMENT-PLAN.md  CHANGELOG.md      Stage list, decisions table, agents and models; what each stage shipped
LICENSE  DISCLAIMER.md                 GPL-3.0-only text; risk notice
DATA-PROTECTION.md  LEGAL-README.md    Privacy notice; plain-language guide to the above
docs/                                  The logical design, and the contract the code implements
docs/CROSS-PLATFORM-SMOKE-TEST.md      The manual Windows/Linux/macOS checklist
docs/adr/0001-database-location.md     Architecture decision records
legal-documents/en-US/*.md             Root-mirrored legal documents shown inside the GUI
gui_resources/                         Flags, icons, logos
tools/generate_translations.py         Regenerates gui/i18n/translations.py — never hand-edit that file
src/sape_d_mcp/
├── _version.py                        Single source of truth for the version, import-free
├── db_location.py                     Where the three databases live, and only there
├── db/
│   ├── dialects/                      base.py, mssql.py, postgres.py, mysql.py, sqlite.py,
│   │                                    registry.py, types.py
│   ├── connection_store.py            Connection profile CRUD — never a secret
│   ├── credential_store.py            Keyring, with an AES/master-password fallback
│   ├── engine.py                      Connect, health check, read-only session, statement timeout
│   ├── introspection.py               List/describe tables, views, functions, procedures
│   ├── sql_guard.py                   Statement parsing, classification, referenced objects
│   └── security.py                    Roles, users, groups, grants
├── permissions.py                     Pattern-matching rule engine; ACTIONS_BY_TYPE is the
│                                        single source of truth for every action
├── confirmation.py                    Destructive-operation approval broker, single-use
├── log_store.py  tool_logger.py       Session log storage; JSONL + SQLite tool-call logging
├── mcp_server.py                      DatabaseMCPServer and the 38 tools
├── mcp_config_generator.py            Client configuration for this installation
├── config_json_generator.py           config.json defaults and migration
├── language_registry.py               The 18 supported locales
├── flag_mapping.py  legal_document_loader.py
└── gui/                               resources, app, main_window, managers, server_thread,
                                         splash_screen, confirmation_bridge, components/,
                                         dialogs/, i18n/, styles/, pages/
tests/                                 30 modules, 3 207 tests
```

The logical design is four documents, written in stage 1 and still the contract every later stage implements against: [`DESIGN-DATA-MODEL.md`](docs/DESIGN-DATA-MODEL.md), [`DESIGN-PERMISSIONS.md`](docs/DESIGN-PERMISSIONS.md), [`DESIGN-DIALECTS.md`](docs/DESIGN-DIALECTS.md) and [`DESIGN-MCP-TOOLS.md`](docs/DESIGN-MCP-TOOLS.md). Where the code has since departed from them, `DEVELOPMENT-PLAN.md`'s decisions table says so and which one supersedes the other.

### Running the checks

```bash
pip install -r requirements-dev.txt

pytest                                 # 3 178 pass, 29 skip
ruff check src tests                   # clean
mypy                                   # clean at its configured floor
black --check src tests                # deliberately not clean — see below
```

On a headless Linux machine, prefix the test run with `QT_QPA_PLATFORM=offscreen`. On a VirtualBox shared folder, `ruff` needs `--no-cache` — it cannot persist its cache there; see [Running inside a virtual machine](#running-inside-a-virtual-machine). The full command that was actually used to produce the numbers below is:

```bash
QT_QPA_PLATFORM=offscreen pytest -q -p no:cacheprovider
ruff check --no-cache src tests
```

`pytest`'s own cache does write to a `vboxsf` share, so `-p no:cacheprovider` is belt-and-braces rather than a requirement; `ruff`'s `--no-cache` is not optional there.

All four were configured for the first time in stage 9; every setting and every exclusion is justified in `pyproject.toml` beside the setting itself. Three of the four are green:

| Tool | State |
|---|---|
| `pytest` | 3 178 pass, 29 skip |
| `ruff check src tests` | **Clean.** It opened stage 9 at 279 findings |
| `mypy` | **Clean** at the floor `pyproject.toml` configures — 62 source files, no issues. `mypy --strict` is a separate matter: 34 errors across 18 files, almost all of them missing parameter and return annotations on functions that predate the configuration. That is the stated target, not a floor this codebase claims to meet |
| `black --check src tests` | 68 of 92 files would be reformatted — **on purpose, for now** |

**On `black`.** It is configured, it is not satisfied, and that is a decision rather than an oversight. Running it would put a formatting-only diff across three quarters of the tree into the same commit as stage 9's actual fixes, and this tree is reviewed and committed by hand: a reviewer would have to find the real changes inside it. `ruff` already enforces import ordering and the same 120-column limit `black` is configured with, so nothing goes unguarded in the meantime, and the two cannot fight over line length. Satisfying `black` is its own future commit, on its own.

`pyinstaller` is not in `requirements-dev.txt` on purpose — it is a release tool, not a test dependency. Install it separately to build a bundle.

---

## License

**GPL-3.0-only.** SAPÉ d-MCP is free software: you may run, study, modify, and redistribute it, including commercially, provided you pass on the same freedoms under the same licence and make corresponding source available. The full text is in [LICENSE](LICENSE); [LEGAL-README.md](LEGAL-README.md) has a plain-language guide.

"Version 3 only" — the "or any later version" clause is not granted.

This program links **PyQt6**, which is itself GPL-licensed. A fork therefore cannot be relicensed under permissive or proprietary terms while keeping PyQt6.

**SAPÉ** and **SAPÉ d-MCP** are the author's marks. The GPL is a copyright licence and doesn't transfer them — fork freely, but give your fork its own name.

Legal documents are maintained in English only: the GNU GPL is legally authoritative in English and the FSF publishes no binding translations, so a translated licence would carry no legal force. The interface itself is localised; only the document bodies are not.

See also [DISCLAIMER.md](DISCLAIMER.md) and [DATA-PROTECTION.md](DATA-PROTECTION.md).

---

## Author

**SAPÉ smart bud** — [sapebud.com](https://sapebud.com)

Copyright © 2026 Luciano Arrezze. This program comes with ABSOLUTELY NO WARRANTY; see sections 15–17 of the [LICENSE](LICENSE).
