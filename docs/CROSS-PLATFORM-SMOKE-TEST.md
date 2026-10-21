# Cross-platform smoke test — the manual checklist

`DEVELOPMENT-PLAN.md`'s Verification section requires a smoke test on **Windows 10+**, **Linux**
and **macOS** before the stage-9 gate. Only Linux can be proved from the development VM, so the
remaining two are run by hand, by you, and this is the list.

It lives in its own file rather than inside `DEVELOPMENT-PLAN.md` for one reason: the plan
records *what must be true*, and this records *what you type to find out*. It is executed once
per platform per release, on three different machines, with a terminal open beside it — a
hundred-line runbook folded into one bullet of the plan's Verification list would bury the other
seven bullets it sits among, and would be re-read far more often than the plan around it. The
plan's Verification section links here instead.

**How to use it.** Work top to bottom on each platform. Every step says what to type and what a
pass looks like. Where a step cannot pass on a given platform, that is stated — an expected
failure is still a result, and skipping it silently is not.

**What this VM could not prove** is recorded in the last section. Read it before you start:
several of the steps below have never been executed anywhere, and you are the first person who
will run them.

**Sections 0-9 are the application's baseline; sections 10-16 cover the connection-setup
remodelling**, and they are the harder half. Every one of them needs something this development
VM does not have — the Windows registry, a domain, a real LAN, a real server of each engine, or
the user's own `connections.db`. Each section's heading states what it needs. Where a section
needs a **real network** or a **real server**, it says so, and there is no way to fake it that
would tell you anything.

---

## 0. Before you begin, on each platform

| | |
|---|---|
| Python | 3.10 or newer — `python --version` |
| Checkout | A clean one, with **no** `connections.db`, `permissions.db`, `audit.db` or `~/.sape/d-mcp/config.json` |
| Virtualenv | Fresh, per platform. Do not reuse one across steps 5 and 6 — step 6 depends on the venv being clean |
| MS-SQL | A reachable instance for step 7, and the **Microsoft ODBC Driver 18** installed for the `pyodbc` half of it |

Sections 10-16 need more than a checkout, and gathering it takes longer than the checks do. Read
this before you book the machine time:

| For | You need |
|---|---|
| §10, §16 | A **Windows** machine with at least one SQL Server instance installed, and permission to restart its service and to edit its TCP settings in SQL Server Configuration Manager |
| §11.1 | An MS-SQL instance where your **Windows account is a login**, and ODBC Driver 18 |
| §11.3 | A **domain-joined** MS-SQL server, a Kerberos realm, and an account in it — plus `kinit` on the Linux or macOS machine |
| §12, §13 | A **real LAN segment** with two or more SQL Server instances on different machines, the SQL Server Browser running on each, a packet capture tool (`tcpdump` or Wireshark), a second machine that can send UDP, and your network administrator's agreement to a broadcast |
| §14 | A reachable **MS-SQL, PostgreSQL and MySQL** server, and on each one a least-privilege account as well as an administrative one |
| §15 | The user's **own `connections.db`**, still at schema version 1, and a copy of it kept somewhere else |

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements-dev.txt
pip install pyinstaller
```

`pyinstaller` is deliberately not in `requirements-dev.txt` or the `dev` extra: it is a release
tool, not a test dependency, and every developer who runs the test suite should not have to
build a bundle to do it. Install it by hand for step 1.

---

## 1. Build the bundle, and read the build log

```bash
pyinstaller sape-d-mcp.spec
```

Produces `dist/sape-d-mcp/`, with the executable at `dist/sape-d-mcp/sape-d-mcp`
(`sape-d-mcp.exe` on Windows) and the two data trees under `dist/sape-d-mcp/_internal/`.

**Then grep the output for the spec's own warning.** `sape-d-mcp.spec`'s `_collect_driver()`
prints it when `collect_submodules()` comes back empty, which is what happens when a driver
cannot be imported in the build environment — PyInstaller does not raise, so without this grep
you get a bundle that is silently missing a driver:

```bash
pyinstaller sape-d-mcp.spec 2>&1 | tee build.log
grep "sape-d-mcp.spec: WARNING" build.log
```

| Platform | Expected |
|---|---|
| **Windows** | **No output at all.** Every warning here is a real defect. `pyodbc` links the OS's own `odbc32.dll` on Windows and must import cleanly; if it warns, the bundle ships with no ODBC MS-SQL driver and you will not find out until a user picks that engine |
| **macOS** | **No output at all**, same reading. `pyodbc` needs unixODBC (`brew install unixodbc`) before the build, not after |
| **Linux (this VM)** | Exactly one warning, naming `pyodbc` — the known `libodbc.so.2` gap. `pymssql` is the MS-SQL driver that bundle carries. Any *second* warning is a real defect |

Also check the icon line while you are in the log (see §1a below).

One further line to look for, on **Linux only**:

```
WARNING: Library not found: could not resolve 'libxcb-cursor.so.0', dependency of
         '.../PyQt6/Qt6/plugins/platforms/libqxcb.so'
```

It appears on this VM (four times, for `libqxcb.so` and the three xcbgl integrations) and is
survivable only because the bundle is exercised with `QT_QPA_PLATFORM=offscreen`. A frozen build
carrying that warning **will fail to start a real X11 window** on a machine that does not itself
provide `libxcb-cursor0`. Either install `libxcb-cursor0` before building so PyInstaller can
collect it, or document it as a runtime prerequisite of the Linux bundle. It is not a Windows or
macOS concern.

### 1a. The `.ico` embedding — Windows and macOS only

The spec passes `icon=gui_resources/icons/trans.ico` to `EXE()`. On Linux PyInstaller prints

```
Ignoring icon; supported only on Windows and macOS!
```

and carries on. That means **the icon path has never been exercised** — no build has ever
embedded that file. On Windows and macOS:

- The build must **not** print that line.
- The build must not error on the `.ico` either. A malformed or missing icon is a hard failure
  at this step, and `trans.ico` has only ever been read by Qt at runtime, never by PyInstaller's
  resource editor.
- Check the resulting executable's icon in Explorer/Finder before running it.

---

## 2. `--version`

```bash
dist/sape-d-mcp/sape-d-mcp --version
```

Must print exactly `SAPÉ d-MCP <VERSION_DISPLAY>` — `SAPÉ d-MCP 0.1.0.8 Beta` at the time of
writing, but check `_version.py` for the live value, since it moves with every release and
whenever `RELEASE_STAGE` changes — and exit 0. Two things are actually being checked: the version
string reached the frozen bundle from `_version.py`, and the **É** survived the platform's
console encoding — not the exact digits or release-stage word, which change every release and
are not this step's concern. A mojibake `SAP├ë` is a failure, not a cosmetic issue — it means the
same encoding will mangle every other accented string the GUI shows.

Repeat from the source checkout for comparison:

```bash
python main.py --version
```

---

## 3. The GUI, on a real display

Launch the **frozen** executable by double-clicking it, not from a terminal — the point is to
see what a user sees.

```bash
dist/sape-d-mcp/sape-d-mcp
```

Do **not** set `QT_QPA_PLATFORM=offscreen`. Every check below is a thing offscreen rendering
cannot answer.

| # | Check | Pass looks like |
|---|---|---|
| 3.1 | Taskbar / dock icon | The window's icon appears in the Windows taskbar / macOS dock / Linux panel, and is the SAPÉ mark, not a generic Python or Qt feather. `gui/app.py` and `gui/main_window.py` both call `setWindowIcon()` from `resource_path("icons", ...)`; a blank icon means `resources.py` resolved the wrong root inside the bundle |
| 3.2 | Splash screen | It appears **and disappears**. A splash that never closes is f-MCP's garbage-collected-`QTimer` bug, which `main.py` keeps a reference specifically to avoid |
| 3.3 | Header logo | Present, correct for the current theme, and swaps when you toggle the theme |
| 3.4 | All 18 flags | Open the language selector. Every one of the 18 locales shows its flag — no blank squares. A blank flag is `resource_path()` finding `gui_resources/flags/` but not the file, which `QIcon` will not raise about |
| 3.5 | All 18 languages | Select each one in turn. The window must not crash, and the sidebar, header and status bar must all re-render. Only `en-US` and `es-ES` are genuinely translated — the other sixteen showing English is **expected**, not a failure (see the README's Known limitations) |
| 3.6 | Both themes | Light and dark, from Settings. The whole window restyles, including the page you are not looking at |
| 3.7 | The four legal documents | Legal page: `LICENSE`, `DISCLAIMER`, `DATA-PROTECTION` and `LEGAL-README` all render as **formatted text**, not raw markdown. Raw `##` and `**` on screen is f-MCP's defect 8, which d-MCP fixes with `QTextBrowser.setMarkdown()`. All four are English-only by policy whatever language the GUI is in |
| 3.8 | Seven sidebar entries | Connections · Permissions · Logs · Settings · Legal · Help · About. There is no Explorer entry — it is the schema-browser panel inside Permissions |
| 3.9 | Empty states | On a clean checkout every page shows its empty state, and each looks finished — the message centred in the panel, not stranded at the bottom under a stretched title block. `show_sample_data` defaults to False, so this is the screen a first-run user actually gets |
| 3.10 | Close the window | The process exits. It does not linger in the process list, and it does **not** minimise to a system tray — there is no tray icon, by design |

---

## 4. The Windows console-window behaviour

**Windows only.** The spec builds `console=True` and `main.py` hides the console itself, but only
when `--cli` is absent. Both halves need checking, because building windowed instead would break
the `--cli` half and nothing else would notice.

| Launch | Expected |
|---|---|
| `sape-d-mcp.exe` (double-click) | A console window may flash briefly, then **disappears**. The GUI window remains. A console window that stays open behind the GUI is a failure |
| `sape-d-mcp.exe --cli` from `cmd`/PowerShell | The console **stays**. You keep your prompt, the server reads stdio, and Ctrl-C stops it. A vanished console here means the process lost the stdio a client would speak JSON-RPC over |
| `sape-d-mcp.exe --version` | Prints to the console you launched it from and exits |

On Linux and macOS there is no console to hide; `main.py`'s `sys.platform == "win32"` guard makes
the whole block a no-op. Nothing to check.

---

## 5. The databases follow the working directory

This is the user ruling `db_location.py` implements, and it is the step most likely to surprise
someone later. Run it on every platform.

```bash
mkdir /tmp/dmcp-a /tmp/dmcp-b          # md %TEMP%\dmcp-a on Windows

cd /tmp/dmcp-a && /path/to/dist/sape-d-mcp/sape-d-mcp --show-permissions
ls                                     # dir, on Windows

cd /tmp/dmcp-b && /path/to/dist/sape-d-mcp/sape-d-mcp --show-permissions
ls
```

**Pass:** each directory now holds its own `connections.db` and `permissions.db`, and both runs
printed `no database connections are configured; nothing is authorised`. Two directories, two
independent sets of rules, exactly as documented. `audit.db` and `tool_log.jsonl` appear the same
way once a server actually runs (`--cli`).

**Then prove the override works**, because it is the escape hatch everything else relies on:

```bash
cd /tmp/dmcp-b
DMCP_DB_DIR=/tmp/dmcp-a /path/to/dist/sape-d-mcp/sape-d-mcp --show-permissions
ls                                     # no new .db files here
```

On Windows: `set DMCP_DB_DIR=%TEMP%\dmcp-a` first, then run.

Finally, launch the frozen GUI from a **desktop shortcut** and look at Settings → Data, which
shows the three resolved paths. Note where they landed. On Windows a shortcut's working
directory defaults to the executable's own folder, so the three databases will be created
*inside* `dist/sape-d-mcp/` — which is correct behaviour for the ruling, and is precisely the
case the README's Known limitations entry warns about. Confirm it, do not be surprised by it.

---

## 6. A clean `pip install .` into a fresh venv

This exercises the **installed-prefix** branch of `resources.py`'s three-shape lookup, which
nothing has ever tested: the frozen branch is covered by step 1, the development-checkout branch
is what every test run uses, and the third has only ever been reasoned about.

```bash
python -m venv /tmp/dmcp-install          # a NEW venv, not the build one
/tmp/dmcp-install/bin/pip install /path/to/d-MCP
cd /tmp                                   # anywhere outside the checkout — this matters
/tmp/dmcp-install/bin/sape-d-mcp --version
/tmp/dmcp-install/bin/sape-d-mcp
```

On Windows the paths are `\Scripts\pip.exe` and `\Scripts\sape-d-mcp.exe`.

| # | Check | Pass looks like |
|---|---|---|
| 6.1 | `--version` | `SAPÉ d-MCP <VERSION_DISPLAY>` — `SAPÉ d-MCP 0.1.0.8 Beta` at the time of writing — exit 0. See §2 for what is actually checked |
| 6.2 | The GUI opens | Which means `resources.py` found `gui_resources/` under `sys.prefix`. A `FileNotFoundError` naming all three candidate roots is the failure this step exists to catch, and its message tells you which paths it tried |
| 6.3 | Flags and logo render | Same as 3.3/3.4, from the installed location this time |
| 6.4 | The legal documents render | `legal_document_loader.py` reads `legal-documents/` from the same resolved root — it is a separate data-files tree from `gui_resources/` and can fail independently |
| 6.5 | No `src` in site-packages | `ls /tmp/dmcp-install/lib/python3.*/site-packages/` shows `sape_d_mcp/`, and **no** top-level `src/`. That leak is f-MCP's packaging defect 5, which this layout exists to avoid |
| 6.6 | Import from outside | `cd /tmp && /tmp/dmcp-install/bin/python -c "import sape_d_mcp; print(sape_d_mcp.__file__)"` resolves inside site-packages, not the checkout |

Run it from `/tmp`, not the checkout: inside the checkout the development-checkout branch of the
lookup would answer first and the installed branch would never be reached, which would make this
whole step pass without testing anything.

---

## 7. MS-SQL, against both drivers

Both MS-SQL drivers ship on purpose, and the reason is exactly this pair of runs. Do them on each
platform where you have a reachable instance.

| # | Driver | Prerequisite | Steps |
|---|---|---|---|
| 7.1 | `pyodbc` | **Microsoft ODBC Driver 18** installed on the host — pyodbc does not bundle it | Connections → new profile → engine `mssql`, driver `pyodbc` → Test connection |
| 7.2 | `pymssql` | none — FreeTDS is compiled into the wheel | The same profile with driver `pymssql` → Test connection |

Both must succeed against the same server. Then, for at least one of them:

- Grant a narrow rule on the Permissions page — one table, `select` only.
- Confirm the schema-browser tree shows the padlock on everything else.
- From an MCP client (step 8), read the permitted table, and confirm a non-permitted read is
  refused with an error citing the rule.

Then, for the failure path, **uninstall or hide ODBC Driver 18** and retry 7.1. The refusal must
be a named `DriverNotInstalledError` naming what to install, not a bare traceback.

---

## 8. End to end, through a real client

```
GUI → Settings → MCP Configuration → Copy
```

Merge the JSON into the client's own config file — the wizard never writes it for you — and
restart the client.

| # | Check | Pass looks like |
|---|---|---|
| 8.1 | The client lists the tools | All 38. `tests/test_generated_config.py` already proves this by subprocess on Linux; this proves the client, the path quoting and the platform's process spawning |
| 8.2 | The `env` block is present | The generated JSON carries `DMCP_CONNECTIONS_DB`, `DMCP_PERMISSIONS_DB` and `DMCP_AUDIT_DB` as absolute paths. Without them the client-spawned server resolves its databases against the client's working directory and quietly enforces a different rule set from the one on screen |
| 8.3 | A permitted read succeeds | And appears in that connection's tab on the Logs page |
| 8.4 | A non-permitted read is refused | With an error naming the rule, and it also appears in the log |
| 8.5 | A `DROP` raises the GUI confirmation | With the d-MCP window open. Refuse it; the tool must report the refusal, and the refusal must be logged |
| 8.6 | A `DROP` with the window closed is denied | The `--cli` server has no confirmation subscriber, so it denies immediately. A headless server can read what its rules allow; it cannot destroy anything |

---

## 9. The test suite

On each platform, from the checkout:

```bash
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

On Windows and macOS, drop the `QT_QPA_PLATFORM` prefix if you would rather see the windows
appear; offscreen is a Linux-CI convenience, not a requirement.

Expect **3 646 passed, 29 skipped** on all three, the Linux figure. A platform-specific failure
is worth more than a passing run here — it is the only signal in the whole checklist that comes
from the test suite rather than from your own eyes. A *different skip count* is also a finding:
the 29 skips are integration tests naming a `DMCP_TEST_PROFILE_*` variable, plus one wanting an
importable `pyodbc`, so on a Windows box with ODBC Driver 18 installed you should see 28.

On **Windows** the count moves for a second reason, and upwards:
`tests/test_discovery_windows_registry.py` ends with two cases guarded by
`skipif(sys.platform == "win32")` — the guard that keeps the registry sources silent off Windows
is exactly what those two assert, and it cannot be asserted on Windows. So expect **30** skips
there (29, minus the `pyodbc` one that now runs, plus those two), or **31** if ODBC Driver 18 is
absent. The rest of that module is not skipped anywhere: it fakes `winreg`, so it runs on all
three platforms and pins the same behaviour §10 asks you to confirm against the real hive.

While you are there, the other three gates. `black --check src tests` reports 68 of 92 files and
is expected to — see the ruling in `DEVELOPMENT-PLAN.md`'s decisions table.

`ruff check src tests` and `mypy` are a different matter, and this paragraph used to claim both
passed. **As of the connection-setup remodelling they do not**, on Linux, before any platform
question arises: 27 ruff findings (10 `RUF100`, 5 `B017`, 3 `RUF001`, and the rest scattered) and
30 mypy errors across five files — 20 of them in `db/discovery.py`, the remainder in `db/engine.py`,
`db/ssrp.py`, `gui/dialogs/connection_dialog.py` and `gui/dialogs/discovery_dialog.py`. None of
them is platform-dependent, so there is nothing here for a Windows or macOS tester to discover:
they will reproduce exactly, and reproducing them is not a finding. **Do not spend smoke-test
time on this gate until it is green on Linux again** — a red baseline hides the platform-specific
failure this step exists to catch, which is the only reason it is in the checklist at all.

---

## 10. Registry discovery — **Windows only**

The connection-setup remodelling (`DESIGN-CONNECTION-SETUP.md` §7.2, §7.3, §7.5) added three
discovery sources that read the Windows registry through `winreg`. On this VM `winreg` does not
exist as a module at all, so `sys.platform != "win32"` returns early and **not one line inside
them ever ran here**.

`tests/test_discovery_windows_registry.py` now fakes a registry and pins the *decisions* d-MCP
makes from registry contents — the port truth table below is parametrised there, so a
disagreement between this section and the code is a test failure, not an opinion. What a fake
cannot prove, and what you are here for, is that a **real** hive holds those values at those
paths and that the account d-MCP runs as may read them.

Run the discovery sources directly first, from the source checkout, because the GUI shows you a
label and this shows you the fields the label was built from:

```powershell
python -c "from sape_d_mcp.db.discovery import discover_local; r = discover_local(); [print(c) for c in r.candidates]; print(r.notes)"
```

### 10.1 The `TcpPort` / `TcpDynamicPorts` truth table

For one instance, read the two values yourself before you trust d-MCP's answer:

```powershell
reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL"
reg query "HKLM\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.SQLEXPRESS\MSSQLServer\SuperSocketNetLib\Tcp\IPAll"
```

Substitute the internal name (`MSSQL16.SQLEXPRESS` here) the first command printed — it is the
*value data*, not the value name, and it differs per SQL Server version. Then edit the two values
with **SQL Server Configuration Manager** (not `regedit` — Configuration Manager is what a real
user's machine will have been configured with) and restart the instance for each row:

| # | `TcpPort` | `TcpDynamicPorts` | Candidate's `port` | Label must say |
|---|---|---|---|---|
| 10.1a | `1433` | *(empty)* | `1433` | nothing about a dynamic port |
| 10.1b | *(empty)* | `56879` | `56879` | `(dynamic port — it changes when the service restarts)` |
| 10.1c | *(empty)* | `0` | `None` | nothing — `0` means "one will be chosen at start-up, none assigned yet", and offering it as a port would be a fabrication |
| 10.1d | `1433` | `56879` | `1433` | nothing about a dynamic port |

Row 10.1d is the one worth being careful about, and only a hand-edited hive produces it —
Configuration Manager clears `TcpDynamicPorts` when you assign a static port, so use `regedit`
for this row alone. **The static value wins.** If d-MCP offers 56879 there, the precedence is
reversed, and the failure mode is a profile that connects on the day it is discovered and fails
after the next service restart.

**How to know it failed:** the candidate's `port` disagrees with what `netstat -ano | findstr
<PID of sqlservr.exe>` says the instance is actually listening on. That, not the registry, is the
ground truth.

### 10.2 The user's own instance: `PC-ARR\SQLEXPRESS` on 56879

This is the case the whole remodelling started from, and it needs running on the real machine
with its real configuration, unmodified, **before** you start editing values for §10.1.

1. Connections → **Discover** → Search this computer.
2. The instance appears with `SQL Server — localhost\SQLEXPRESS`, `confidence='confirmed'`,
   `origin='windows-registry'`, `auth_hint='integrated'`, `driver_hint='pyodbc'`.
3. Read the label. It either says `(dynamic port — it changes when the service restarts)` or it
   does not, and **which one decides what you do next**:

| The port is | What the saved profile must hold | Why |
|---|---|---|
| **Static** (`TcpPort=56879`) | Host `PC-ARR`, Instance blank or `SQLEXPRESS`, **Port 56879** | The number is stable; storing it skips the Browser round trip |
| **Dynamic** (`TcpDynamicPorts=56879`) | Host `PC-ARR`, **Instance `SQLEXPRESS`**, **Port blank** | The number is valid only until the service restarts. A profile pinning it works today and fails on Monday morning with a transport error nobody will connect to a reboot |

4. If it is dynamic, save the profile with Port blank, **restart the SQL Server service**
   (`net stop MSSQL$SQLEXPRESS` / `net start …`, or Configuration Manager), confirm with
   `reg query` that the dynamic port changed to a different number, and then Test connection.

**Pass:** the connection succeeds after the restart without you touching the profile, and the
Logs page's **System** tab holds a `resolve-instance-port` row whose result reads
`re-resolved port <old> -> <new>`.

**Fail:** the connection fails with a transport error, or it succeeds but no `resolve-instance-port`
row was written — the second case means it connected for some other reason and the re-resolution
path is still unproved.

Do not skip the restart. A dynamic port that has not moved proves nothing: the profile would
connect either way, and the restart is the only thing that distinguishes "d-MCP re-resolved it"
from "the old number still happened to work".

### 10.3 The service table

**Windows only.** `_discover_windows_services()` walks `HKLM\SYSTEM\CurrentControlSet\Services`
and reports PostgreSQL, MySQL and MariaDB by service-name pattern.

Install (or find) a PostgreSQL or MySQL service on the machine, then run the `discover_local`
snippet above.

| # | Check | Pass looks like |
|---|---|---|
| 10.3a | The service is found | A candidate with `origin='windows-service'` and `origin_detail` naming `HKLM\SYSTEM\CurrentControlSet\Services\<service>` |
| 10.3b | It claims **no** port | `port=None`, and the label ends `(port unknown; see the listening-port results)`. A service key does not say what port the daemon bound, and inventing 5432 would be a guess dressed up as a finding |
| 10.3c | SQL Server is not reported twice | No `windows-service` candidate for `MSSQLSERVER` or `MSSQL$SQLEXPRESS`. Those instances are already named by §10.1 *with their real port*; a second, portless row for the same server is a regression |
| 10.3d | Unrelated services are not offered | Nothing for `Spooler`, `wuauserv` or any service whose name merely contains "postgres" without starting with it |

### 10.4 ODBC DSNs from the registry

**Windows only.** Create one DSN of each scope in the ODBC Data Source Administrator — a **User
DSN** and a **System DSN** — pointing at any MS-SQL or PostgreSQL server. Include a password in
at least one of them, which the Administrator will offer to save.

| # | Check | Pass looks like |
|---|---|---|
| 10.4a | Both are found | Two candidates with `origin='odbc-dsn'`, one whose `origin_detail` starts `user DSN:` and one `system DSN:` |
| 10.4b | **No password is read** | The candidate's repr contains neither the saved password nor the DSN's user name. Only `Driver`, `Server`, `Port` and `Database` are allowlisted, and ODBC DSNs really do hold plain-text credentials — this is the check that matters most in this section |
| 10.4c | A 32-bit DSN is seen from a 64-bit d-MCP | Create one with `C:\Windows\SysWOW64\odbcad32.exe`; it must still appear. `pyodbc.dataSources()` would not see it, which is why d-MCP reads both registry views itself |
| 10.4d | A compound `Server` is split | Set a DSN's Server to `PC-ARR\SQLEXPRESS,56879`. The candidate must come back as host `PC-ARR`, instance `SQLEXPRESS`, port `56879` — **not** as a host containing backslashes. Passing it through whole would recreate, from a freshly discovered profile, the exact defect §15's migration exists to repair in a stored one |
| 10.4e | A DSN d-MCP has no dialect for is ignored | An Access or Excel DSN produces no candidate at all |

---

## 11. Integrated authentication, against a real server

Three different mechanisms hide behind one checkbox, and the automated tests prove only that
`auth_modes.py` returns the right `AuthSupport` record for each. Whether the mechanism then
*works* has never been observed on any machine.

### 11.1 Windows: SSPI, with nothing configured — **Windows + a real MS-SQL server**

Prerequisite: an MS-SQL instance where your Windows account is a login. **ODBC Driver 18**
installed.

1. Connections → new profile → engine `mssql`, driver `pyodbc`.
2. Authentication → **Windows account**. The user-name and password fields must disappear or grey
   out, and the explanatory line must read: *"This connection will authenticate with your Windows
   account. d-MCP sends no user name and no password: the ODBC driver presents the token of the
   process it runs in."*
3. Test connection.

**Pass:** it connects, and `SELECT SUSER_SNAME()` through an MCP client returns your domain
account (`DOMAIN\you`), not a SQL login.

**Fail, and how to read it:** a login failure naming `NT AUTHORITY\ANONYMOUS LOGON` means the
token did not reach the server — usually a missing or duplicated SPN, or a second hop. That is a
domain problem, not a d-MCP one, but d-MCP must *say so*: the error must carry the anonymous-logon
sentence `engine.py` adds, not a bare pyodbc traceback.

### 11.2 pymssql is refused in the dialog, not at connect time — **any platform, no server needed**

This is the case the whole encargo started from, and it is the cheapest check in this document.
Run it on every platform.

1. New profile → engine `mssql` → driver **pymssql**.
2. Open the Authentication combo.

| # | Check | Pass looks like |
|---|---|---|
| 11.2a | The item is present | "Windows account" is **listed** — not hidden. An option that vanishes looks like a bug; one that is present and greyed with a reason is understood |
| 11.2b | The item is **disabled** | You cannot select it |
| 11.2c | The reason is on screen | *"The pymssql driver cannot use Windows (trusted) authentication — FreeTDS has no way to present your Windows account to the server, and the attempt fails with error 20009, which looks like a network problem but is not one. Choose the pyodbc driver for system authentication, or keep pymssql and sign in with a SQL Server user name and password."* |
| 11.2d | Switching driver re-enables it | Change the driver to `pyodbc` with the dialog still open: the item becomes selectable, and on Windows the message changes to the SSPI sentence, off Windows to the Kerberos one |

**Fail:** the item is selectable and Test connection returns a DB-Lib **20009** — that is the
original defect, unchanged. A 20009 is indistinguishable from "the host is unreachable", and the
entire point of this gate is that the user is told the real reason before they spend an afternoon
on their firewall.

### 11.3 Kerberos off Windows — **Linux or macOS + a domain-joined MS-SQL server**

The README's platform sections already give the setup (`kinit`, `krb5.conf`, the SPN). **Do not
follow them from memory — follow them as written and report any step that is wrong or missing**,
because nobody has ever executed them end to end. That verification is this step's real purpose.

| # | Do this | Expected |
|---|---|---|
| 11.3a | `kinit you@YOUR.REALM.EXAMPLE`, then `klist` | A ticket-granting ticket, unexpired, for the realm the SQL Server belongs to |
| 11.3b | Open the Authentication combo on an `mssql`/`pyodbc` profile | "Windows account" selectable, and the message is the **Kerberos** one — *"System authentication on Linux and macOS uses Kerberos. You need a valid ticket — run kinit — …"* — not the Windows SSPI one. A platform-blind message here means `support_for()` ignored `system` |
| 11.3c | Test connection | Connects; `SELECT SUSER_SNAME()` returns your domain account |
| 11.3d | `kdestroy`, then Test connection again | It **fails**, with the anonymous-logon sentence. This is the negative half, and without it 11.3c proves only that *something* let you in |
| 11.3e | PostgreSQL, same machine | An `integrated` `postgresql`/`psycopg` profile: `peer` over a Unix socket (put the socket directory, e.g. `/var/run/postgresql`, in **Host**) and `gss` over TCP with the same ticket. Both are covered by the one explanatory line the dialog shows for this pair |
| 11.3f | MySQL | The Authentication combo offers no "Windows account" item at all, or offers it disabled with the MySQL message. There is no system-authentication mode d-MCP can use for MySQL or MariaDB, and the README's Known limitations says so |

---

## 12. The broadcast, on a real LAN — **needs a real network**

Every automated SSRP test speaks to loopback. "Many peers answer a broadcast" and multi-interface
behaviour are, in `ssrp.py`'s own words, *reasoned about, not measured*. This section is where
they get measured. Run it on a network segment carrying **at least two** SQL Server instances on
different machines, with the **SQL Server Browser** service running on each.

Ask your network administrator before you run this. The confirmation dialog says corporate
networks log or block this kind of message, and that sentence is not decorative.

### 12.1 The confirmation is asked once per session and is never persisted

| # | Do this | Expected |
|---|---|---|
| 12.1a | Connections → Discover → **Search the network** | A confirmation dialog appears, naming UDP, the broadcast address, port 1434, "no user name and no password", and roughly 2 seconds of waiting |
| 12.1b | Decline it | No packet is sent — confirm with `tcpdump -n -i any udp port 1434` or Wireshark, which must show **nothing**. The Logs page's **System** tab gains a `discover-network` row with decision **refused**. A declined search that leaves no trace is a failure: "the operator was asked and said no" is worth more to a security review than silence |
| 12.1c | Press Search the network again, and accept | The dialog is asked again (12.1b's refusal is not remembered as consent), the sweep runs, and a `discover-network` row with decision **allowed** is written |
| 12.1d | Press Search the network a third time | **No dialog.** One approval covers the rest of the session. Note what the audit trail does here, and record it rather than judging it: the `discover-network` row is written when the *confirmation* is answered, so this third sweep — a real broadcast, really leaving the machine — adds **no** row. If that is not what the release wants, it is a decision for the architect, not a failure of this step |
| 12.1e | Close d-MCP entirely and start it again, then Search the network | **The dialog is asked again.** This is the check that matters. Grep `~/.sape/d-mcp/config.json` (and `%APPDATA%` equivalent) for anything resembling a remembered approval — there must be none. A consent that outlives the process is a consent nobody gave |

### 12.2 Many peers, and more than one network interface

| # | Check | Pass looks like | Fail looks like |
|---|---|---|---|
| 12.2a | Every instance on the segment answers | The dialog's network group lists **each** instance found, each with `confidence='reported'` and its own peer address. Cross-check the count against `tcpdump`'s reply count | Fewer rows than replies on the wire — a parser or de-duplication defect. More rows than replies — worse: something is being invented |
| 12.2b | Nothing is marked `confirmed` | An SSRP reply is a **claim by an unauthenticated peer**. Every network candidate must be `reported`, and the dialog must group them apart from the local, confirmed ones | A network candidate rendered in the confirmed group |
| 12.2c | No candidate carries a credential | Read the candidates' fields. There is no user name, no password, and no field one could be hidden in | — |
| 12.2d | Two interfaces | On a machine with two NICs (or a NIC plus an active VPN or a VirtualBox host-only adapter), run the sweep and watch **both** interfaces in `tcpdump`. Record which interface the datagram actually left by, and whether instances on the *other* segment were found | The result is the finding here: a limited broadcast (`255.255.255.255`) goes out **one** interface, chosen by the routing table. If instances on the second segment are missed, that is expected behaviour to be documented, not a defect to be fixed by widening anything |
| 12.2e | A segment with no SQL Server | An empty result with a note, never an error dialog. A stopped Browser service, a blocked broadcast and an empty segment are indistinguishable from here, and the note must not claim otherwise |

---

## 13. The forged-datagram fix, on a real network — **needs a LAN and a second machine**

A verified vulnerability was fixed during the remodelling: a **forged SSRP datagram could make
d-MCP reconnect to an attacker's port carrying the operator's credentials**. The fix is two
layers — `query_ssrp()` filters by source address on a unicast sweep, and `engine.py` additionally
requires that `candidate.peer` be among the addresses the profile's own host resolves to.

Both layers are unit-tested with sockets on loopback. Neither has been exercised where the two
addresses genuinely differ, which on loopback they cannot.

**Setup.** Machine A runs d-MCP with a saved MS-SQL profile naming a host and an **instance** and
**no port** (the §10.2 shape). Machine B is anything that can send a UDP datagram — a second
laptop on the same segment.

### 13.1 A reply from the wrong address is discarded

1. On A, take the real SQL Server down, or block its port, so the first connection attempt fails
   with a transport error and the retry path is entered.
2. On B, respond to A's SSRP query — or simply spray unsolicited SSRP replies at A's ephemeral
   port — advertising the profile's instance name on a port B controls.
3. Watch A.

| # | Check | Pass looks like |
|---|---|---|
| 13.1a | The retry does not follow B | d-MCP does **not** connect to B's port. The original transport error propagates unchanged |
| 13.1b | The rejection is in the audit trail | Logs page → the connection's tab → a `resolve-instance-port` row whose result contains `discarded 1 reply(ies) that did not arrive from the host asked` **and B's address**. Verify it landed in the database, not only on screen: `sqlite3 audit.db "SELECT timestamp, tool_name, params_json, result FROM tool_calls WHERE tool_name='resolve-instance-port' ORDER BY id DESC LIMIT 5;"` — the `rejected_peers` list in `params_json` must hold B's address |
| 13.1c | It is legible as an attack | The row is readable by an operator who was not there. "Something on this segment answered on another host's behalf" must be recoverable from the row alone, without a debug log |

**Fail, and treat it as a security defect, not a bug:** d-MCP connects to B, or the retry is
merely silently abandoned with **no** audit row. A silent rejection is a functioning defence with
a broken alarm, and it is the second half that turns an incident into an unexplained outage.

### 13.2 The accepted consequences, confirmed on real hardware

These are not defects. They are prices the fix pays, and the point of checking them on a real
machine is that the *user-visible symptom* must be an honest failure rather than a hang or a
mystery.

| # | Case | Set-up | Expected |
|---|---|---|---|
| 13.2a | An **IPv6-only** host never pairs | A profile whose host resolves to AAAA records only (check with `nslookup -type=AAAA`) — no A record at all | The SSRP socket is `AF_INET`, so the host resolves to no IPv4 address, so `candidate.peer` can never match. **The automatic retry never fires for that profile.** The ordinary connection attempt is still made exactly as before and, if the server is up, still succeeds — the loss is confined to the dynamic-port retry. Confirm both halves: the connection works when the server is up, and when it is down the failure is the original transport error, promptly, with no retry |
| 13.2b | A host that does not resolve | A profile naming a typo'd or decommissioned host | The retry is refused. The error the user sees is about the host, and the wait is short — this must not hang for the SSRP timeout before failing |
| 13.2c | A CNAME or a differently-named server | A profile whose host is an alias for the real server | It must still work: the check compares the *peer address the kernel stamped on the datagram* against the addresses the profile's host resolves to — never the name the peer advertised, which a legitimate server is entitled to state differently. A working alias that stops working here is a regression in the fix, not in DNS |

---

## 14. Enumeration against real servers — **needs MS-SQL, PostgreSQL and MySQL**

`engine.list_server_databases()` and the dialects' `list_databases()` are proved against doubles.
What a double fixes is **how d-MCP treats a short list**, not that a real server returns one. The
finding to confirm against real hardware is this, on all three engines:

> A least-privilege account receives a **short list, in silence** — not an error.

Create, on each server, a login with no server-wide catalogue privilege (an MS-SQL contained user
or a login mapped to one database; a PostgreSQL role with no `pg_read_all_stats`; a MySQL user
granted on one schema only). Then, in the connection dialog, press **Find databases** with that
account's credentials.

| # | Engine | Check | Pass looks like |
|---|---|---|---|
| 14.1 | all three | An admin account | The Database combo fills with the full list, system databases filtered out unless asked for |
| 14.2 | all three | The least-privilege account | A **short list** — possibly one entry, possibly empty — and **no error dialog**. `DatabaseListResult.error` unset. An error here would tell the user their credentials are wrong when they are not |
| 14.3 | mssql | A contained database user | The bootstrap chain tries the database already typed in the field **before** `master`. A contained user cannot open `master` at all, so if the chain reaches it first this account can never enumerate anything. Type the user's own database into the combo first, then press Find databases |
| 14.4 | all three | The combo stays editable | Whatever comes back, you can still type a database name the list did not offer. The list is an aid, never a gate |
| 14.5 | all three | The 10-second clamp | Point a profile at a host that black-holes packets (a firewalled IP, not a refused one) and press Find databases. It gives up in about ten seconds, whatever the profile's own statement timeout says, and the GUI stays responsive throughout |
| 14.6 | all three | One audit row | `sqlite3 audit.db "SELECT tool_name, decision, result FROM tool_calls ORDER BY id DESC LIMIT 3;"` — the enumeration is logged. It is a read of server metadata under the operator's credentials and belongs in the trail |

---

## 15. Migrating a **real** `connections.db` — **any platform, needs the user's own file**

The migration suite runs against a fixture. A fixture contains what its author thought of; a real
file contains what a year of typing produced. Do this once, on the actual `connections.db` the
user has been using, before the release reaches them.

**Take your own copy of the file first, outside the working directory.** The migration writes its
own backup and that mechanism is exactly what is under test here, which is a poor reason to have
only one copy.

```bash
cp connections.db ~/connections.db.before-upgrade
sqlite3 connections.db "PRAGMA user_version;"      # expect 1
sqlite3 connections.db "SELECT id, display_name, engine, host, port FROM connections;" > ~/before.txt
```

Then run the migration **with logging switched on**, from that directory:

```bash
python -c "
import logging
logging.basicConfig(level=logging.INFO, format='%(levelname)s %(message)s')
from sape_d_mcp.db.connection_store import ConnectionStore
ConnectionStore('connections.db').close()
" 2>&1 | tee ~/migration.log
```

The `logging.basicConfig` line is not decoration and you cannot leave it out. `main.py`
configures the root logger to `CRITICAL` with a `NullHandler`, deliberately — a `--cli` server
must not write anything to the stdio a client speaks JSON-RPC over. The consequence is that
**launching the application normally performs the migration and discards its entire record**: the
backup path, the before-and-after of every host that was split, all of it. The migration is
correct either way, but the evidence §15.2 and §15.4 ask you to check exists only in a run that
enables logging first. Do this run *before* you ever start the GUI in that directory — once the
migration has happened there is nothing left to observe, and you would have to restore the copy
you took above and start again.

| # | Check | Pass looks like | Fail looks like |
|---|---|---|---|
| 15.1 | The backup exists | `connections.db.v1.backup` sits beside the original, and `sqlite3 connections.db.v1.backup "PRAGMA user_version;"` prints **1** — it really is the old file, not a copy of the new one | No backup, or a backup already at version 2. Stop here and restore; the safety net is the feature |
| 15.2 | The log says where it went | `~/migration.log` names the backup's full path at WARNING level, with the "keep it until you are satisfied the profiles survived" sentence. A backup nobody can find is not a backup | The path is absent, or only in a debug log |
| 15.3 | Every profile survived | `sqlite3 connections.db "SELECT id, display_name FROM connections;"` matches `~/before.txt` row for row. No row lost, no row duplicated | Any discrepancy at all |
| 15.4 | Compound hosts were split, line by line | For each profile whose host held `HOST\INSTANCE` or `HOST,PORT`, the log holds five lines: `the host was split`, `host was …`, `host is now …`, `instance is now …`, and `port was … is now …`. A host field that also carried a port *and* a port column that disagreed adds a sixth, saying which of the two won. Check each against `~/before.txt` yourself — the migration's own claim is not the evidence, the comparison is | A split that happened with no log line, or a log line whose "is now" disagrees with the database |
| 15.5 | A host the parser rejects is **copied verbatim** | Deliberately arrange one: before migrating, set a profile's host to something the parser refuses, e.g. `sqlite3 connections.db "UPDATE connections SET host='A\\B\\C' WHERE id=<n>;"`. After the migration that host is **unchanged**, byte for byte | The host was "repaired" into something plausible. Guessing at an address nobody can verify is worse than leaving it alone, because a silent guess is a connection to somewhere unintended |
| 15.6 | …and is flagged for review | The Connections page shows an **amber review marker** on that row, and its tooltip is the `needs_review()` sentence naming the host and telling the user which fields to set by hand | No marker: the profile is broken and nothing on screen says so |
| 15.7 | Fixing it clears the marker | Open the profile, set Host, Instance and Port separately, save. The marker disappears immediately, with no restart. It is computed, not stored | The marker persists after a correct edit |
| 15.8 | Credentials still resolve | For a `password` profile, Test connection **without re-typing the password**. The keyring account name is derived from the row id, so a migration that renumbered rows would strand every stored password | A password prompt, or an authentication failure on a profile that worked before |
| 15.9 | It is idempotent | Start d-MCP a second time. `PRAGMA user_version` stays 2, no second migration runs, and **the existing `.v1.backup` is not overwritten** — a second backup, if any, carries a timestamp in its name | The original backup was clobbered |

---

## 16. Registry discovery inside the frozen bundle — **Windows only, and the last gate**

`sape-d-mcp.spec` carries no `hiddenimports` entry for `winreg`. The reasoning is sound —
`import winreg` is a literal import behind a platform guard, which PyInstaller's static analysis
follows — and it was checked with a real PyInstaller run **on Linux**, where `winreg` does not
exist and the guarded branch is never taken. That build cannot confirm anything about a Windows
one.

This step closes that gap, and it must be run from the **frozen executable**, not the checkout.
Running discovery from source on Windows proves the code; it says nothing about the bundle.

1. Build on Windows (§1), then:

```powershell
cd dist\sape-d-mcp
.\sape-d-mcp.exe
```

2. Connections → **Discover** → Search this computer.

| # | Check | Pass looks like |
|---|---|---|
| 16.1 | The registry source runs | The instances found in §10.1 and §10.2 appear, **from the frozen executable**, with the same ports and the same labels |
| 16.2 | No import failure hides in a note | `DiscoveryResult.notes` carries nothing resembling `No module named 'winreg'`. This is the specific failure mode a missing `hiddenimports` produces, and `discover_local()` catches every source's exception into a note — so the bundle would *appear* to work while finding nothing. **A discovery that returns zero candidates on a machine with SQL Server installed is this failure until proved otherwise** |
| 16.3 | Services and DSNs too | §10.3 and §10.4 repeated from the bundle. All three sources import `winreg` independently |
| 16.4 | The network sweep works frozen | §12.1 and §12.2 from the bundle — `socket` and the SSRP encoder are pure Python, so this is a formality, but it is a cheap one |

If 16.2 fails, the fix is a `hiddenimports=['winreg']` entry in the spec, and this step becomes
its regression test. Until this has been run on Windows, the spec's omission is a well-argued
assumption, not a verified fact — and it is recorded as such in the last section.

---

## What the development VM could not prove

Recorded so that nobody mistakes an unexercised path for a verified one.

- **The `.ico` embedding path is completely unexercised.** Every build on this VM printed
  `Ignoring icon; supported only on Windows and macOS!` and carried on. `trans.ico` has never
  been read by PyInstaller's resource editor, on any machine. Step 1a is the first time it will
  be. If it fails there, the failure is in the build, not in the application.
- **`pyodbc` cannot be imported here at all.** `import pyodbc` raises
  `ImportError: libodbc.so.2: cannot open shared object file`. unixODBC is not installed and
  installing it needs a `sudo` this environment does not have. Consequently: the `pyodbc` half of
  step 7 has never run, and every Linux build carries the spec's warning and ships without it.
  `pymssql` imports and works.
- **No Windows and no macOS run of anything.** Not the build, not the GUI, not the console-window
  behaviour, not the taskbar icon, not the installed-prefix lookup on those platforms' `sys.prefix`
  layouts. The Linux results say nothing about them.
- **The installed-prefix branch of `resources.py` has never been exercised on any platform.**
  `pip install .` was verified once, for the console script and the import, before the GUI
  existed; no run since has opened a window from an installed package. Step 6 is its first.
- **No real MS-SQL, PostgreSQL or MySQL server was reachable.** The dialect layer is proved by
  unit tests and by SQLite integration tests; the other three engines' drivers have been proved
  to *import*, not to connect.
- **The Linux bundle has never opened a real window.** It builds, `--version` prints, and
  `--show-permissions` creates its two databases in the launch directory; the GUI was only ever
  started with `QT_QPA_PLATFORM=offscreen`, because the build's own `libxcb-cursor.so.0` warning
  says a real X11 window would not open here. Every visual check in §3 is therefore unproved on
  every platform, including this one.

### And what the connection-setup remodelling added to that list

The remodelling passes 3 646 tests and none of them ran any of the following. Each entry names
the section that closes it.

- **No line of the three Windows registry sources has ever run against a real hive** (§10).
  `winreg` does not exist on Linux. `tests/test_discovery_windows_registry.py` fakes the module
  and pins the `TcpPort`/`TcpDynamicPorts` precedence, the two registry views, the service
  patterns and the DSN allowlist — so the *decisions* are covered on every platform — but a fake
  cannot say that a real Windows hive holds those values at those paths, nor that the account
  d-MCP runs as may read them.
- **The user's own `PC-ARR\SQLEXPRESS:56879` has never been discovered by the code written for
  it** (§10.2). Whether that port is static or dynamic is unknown here, and it is the single fact
  that decides whether the saved profile survives a service restart.
- **Integrated authentication has never authenticated anything** (§11). Not SSPI on Windows, not
  Kerberos anywhere. `auth_modes.py` is proved to return the right `AuthSupport` record for each
  `(engine, driver, platform)`; no ticket has ever been presented to a server. The README's
  Kerberos instructions were written from the driver documentation and have never been followed
  on a machine — §11.3 exists as much to verify those instructions as to verify the code.
- **The pymssql refusal is proved in the model, not on screen against a real server** (§11.2).
  A test asserts the combo item is present and disabled with its reason; nobody has watched a
  real pymssql profile *not* produce a DB-Lib 20009.
- **Every SSRP packet ever sent by this project went to loopback** (§12, §13). "Many peers answer
  a broadcast" and multi-interface behaviour are reasoned about in `ssrp.py`'s own docstring, not
  measured. A limited broadcast leaving the machine by one interface and not the other has never
  been observed.
- **The forged-datagram fix has never been tested where the two addresses genuinely differ**
  (§13). On loopback, "the peer address" and "the address the host resolves to" are the same
  value, which is precisely the case the fix does not need to handle. The vulnerability was real
  and verified; the fix is unit-tested and unobserved in the field.
- **The accepted consequences of that fix are unobserved** (§13.2): an IPv6-only host never
  pairing, and an unresolvable host denying the retry. Both follow from `AF_INET` and from
  `_resolved_addresses()` returning an empty set, and both are argued rather than seen.
- **The enumeration degradation was proved against doubles, not servers** (§14). What is fixed is
  how d-MCP treats a short list. That a real MS-SQL, PostgreSQL or MySQL server hands a
  least-privilege account a short list *in silence* rather than an error is a claim about three
  products, made here on the strength of their documentation.
- **The migration has only ever run against fixtures** (§15). No real `connections.db` — with a
  year of real typing in its `host` column — has been through it, and the `.v1.backup` has never
  been the thing standing between a user and a lost profile set.
- **`winreg` inside a frozen Windows bundle is an assumption** (§16). The deployment specialist's
  reasoning that it needs no `hiddenimports` entry — a literal import behind a platform guard,
  which PyInstaller's static analysis follows — is sound, and it was checked with a real
  PyInstaller run **on Linux**, where the guarded branch is never taken and `winreg` does not
  exist. That build could not have caught the failure it was meant to rule out. Note the shape of
  the failure if the assumption is wrong: `discover_local()` catches each source's exception into
  a note, so the bundle would find nothing and report no error.

### What it did prove

For contrast, so the list above is not read as "nothing works". On Linux, from a real
`pyinstaller sape-d-mcp.spec` run: the build completes; the spec's driver warning fires for
`pyodbc` and for nothing else; both data trees land at
`dist/sape-d-mcp/_internal/{gui_resources,legal-documents}/` with all 18 flags and all four legal
documents present; `--version` prints `SAPÉ d-MCP` followed by the version string with the
**É** intact;
`--show-permissions` from an empty directory prints
`no database connections are configured; nothing is authorised` and creates `connections.db` and
`permissions.db` there and nowhere else; and the frozen GUI starts offscreen and stays up.
