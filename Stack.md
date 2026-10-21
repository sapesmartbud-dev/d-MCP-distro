# SAPÉ d-MCP — Stack

Summary of the technology stack, dependencies and layout. The authoritative detail lives in
`DEVELOPMENT-PLAN.md` and `docs/DESIGN-DIALECTS.md`; this document is the one-page view.

**Version 0.1.0.8 Beta** — the initial published release.

---

## 1. Runtime

| | |
|---|---|
| Language | Python **≥ 3.10** — `match`/`case` and `X \| Y` type unions are used throughout |
| GUI | **PyQt6 ≥ 6.6.1** |
| MCP framework | **`mcp` ≥ 2.0** |
| Platforms | Windows 10+, Linux, macOS — all first-class |
| Licence | **GPL-3.0-only** |

Two floors that are not arbitrary and must not be relaxed:

- **`mcp>=2.0`.** The 2.x SDK renamed `FastMCP` to `MCPServer`. The server does
  `from mcp.server import MCPServer`, which fails at import on 1.x, so a resolver allowed to
  pick 1.x produces a package that cannot start.
- **`PyQt6>=6.6.1`.** Needed by the GUI only. `main.py --cli` runs headless and never imports
  it, so the server is usable on a machine with no Qt installed.

---

## 2. Runtime dependencies

```
mcp>=2.0                      # 2.x MCPServer API; 1.x fails at import
PyQt6>=6.6.1                  # GUI only — main.py --cli never imports it
anyio>=4.0                    # used directly: BlockingPortal bridges the Qt thread
                              # and the server's event loop for the confirmation broker
keyring>=24.0                 # OS credential stores
cryptography>=42.0            # AES fallback where no keyring backend exists;
                              # also required by both MySQL drivers for caching_sha2_password
sqlparse>=0.5                 # statement classification in sql_guard
pyodbc>=5.0                   # MS-SQL, default — needs system ODBC Driver 18
pymssql>=2.3                  # MS-SQL, self-contained alternative
psycopg[binary]>=3.1          # PostgreSQL
PyMySQL>=1.1                  # MySQL/MariaDB, pure Python
mysql-connector-python>=8.3   # MySQL/MariaDB, Oracle driver alternative
# sqlite3 — Python standard library
```

Every pin carries an inline comment justifying its floor, following f-MCP's convention.

**`anyio` is declared explicitly**, unlike in f-MCP. Both projects call `anyio` APIs directly —
`CancelScope` for shutdown, and in d-MCP a `BlockingPortal` for the confirmation broker — but
f-MCP relies on it arriving transitively through `mcp`. That works until `mcp` changes async
backend or loosens its own pin, and then it breaks with nothing in the project explaining why.
If you import it, you declare it.

---

## 3. Database drivers

Both MS-SQL drivers ship together on purpose, so the multi-platform promise never depends on an
external installer being reachable. The connection profile records which one to use.

| Engine | Driver | pip package | Param style | Host requirement |
|---|---|---|---|---|
| MS-SQL | pyodbc *(default)* | `pyodbc>=5.0` | `qmark` | Microsoft ODBC Driver 18, installed separately |
| MS-SQL | pymssql | `pymssql>=2.3` | `pyformat` | none — FreeTDS is compiled into the wheel |
| PostgreSQL | psycopg | `psycopg[binary]>=3.1` | `pyformat` | none — the `binary` extra bundles `libpq` |
| MySQL/MariaDB | PyMySQL | `PyMySQL>=1.1` | `pyformat` | none — pure Python |
| MySQL/MariaDB | mysql-connector-python | `mysql-connector-python>=8.3` | `pyformat` | none |
| SQLite | `sqlite3` | stdlib | `qmark` | none — always present |

`src/sape_d_mcp/db/dialects/registry.py` maps `(engine, driver)` to a concrete `Dialect`. It imports only
the dialect module, never the DB-API package, so the Connections page can display a fully-built
profile and show a clear "driver not installed" state rather than failing before the user has
even tried to connect. The actual import happens in `engine.py.connect()`, and a missing
package raises `DriverNotInstalledError` naming the exact pip requirement — never a bare
traceback.

Full matrix, per-engine caveats and catalogue SQL: `docs/DESIGN-DIALECTS.md` §4–§5.

---

## 4. Development dependencies

```
-r requirements.txt

pytest>=7.0          # test runner
pytest-cov>=4.0      # coverage
pytest-qt>=4.2       # GUI tests
ruff>=0.1.0          # linting
mypy>=1.0            # type checking
black>=23.0          # formatting
```

`requirements-dev.txt` and the `[project.optional-dependencies] dev` extra are kept
**identical**. In f-MCP they drifted apart, so `ruff` and `pytest-cov` appear in one and not the
other.

---

## 5. Packaging

setuptools backend, `requires-python = ">=3.10"`, version read dynamically from
`sape_d_mcp._version.__version__`, which stays import-free so setuptools can parse it statically at
build time. PEP 639 licence metadata (`license = "GPL-3.0-only"` plus `license-files`), which
needs `setuptools>=77.0`.

```toml
name            = "sape-d-mcp"
authors         = [{name = "SAPÉ smart bud", email = "info@sapebud.com"}]
license         = "GPL-3.0-only"
[project.scripts]
sape-d-mcp = "..."
```

**f-MCP's packaging is broken and is not copied.** Its `packages = ["src"]` omits the GUI and
console-script subpackages, and its console script points at a module that does not exist in an
installed wheel. d-MCP declares every subpackage and its package data (`gui_resources/`,
`legal-documents/`, `styles/*.qss`), and a clean `pip install .` into a fresh virtualenv is
verified to produce a working console script.

---

## 6. Layout

```
d-MCP/
├── main.py                     # GUI by default; --cli headless, never imports PyQt6
├── pyproject.toml  requirements.txt  requirements-dev.txt
├── Stack.md  DEVELOPMENT-PLAN.md  README.md
├── LICENSE  LEGAL-README.md  DISCLAIMER.md  DATA-PROTECTION.md
├── legal-documents/en-US/*.md
├── docs/                       # DESIGN-DATA-MODEL, -PERMISSIONS, -DIALECTS, -MCP-TOOLS
├── gui_resources/              # flags, icons, logos
├── connections.db  permissions.db  audit.db     # created on first run
├── src/sape_d_mcp/          # the installable package, imported as sape_d_mcp.*
│   ├── _version.py             # single source of truth, import-free
│   ├── db/                     # dialects/, connection_store, credential_store,
│   │                           # engine, introspection, sql_guard, security
│   ├── permissions.py  confirmation.py
│   ├── log_store.py  tool_logger.py
│   ├── mcp_server.py  mcp_config_generator.py  config_json_generator.py
│   ├── language_registry.py  flag_mapping.py  legal_document_loader.py
│   └── gui/                    # resources, app, main_window, managers,
│                               # components/, dialogs/, i18n/, styles/, pages/
└── tests/
```

---

## 7. Persistence

| What | Where |
|---|---|
| GUI config | `~/.sape/d-mcp/config.json` |
| Session log | `~/.sape/d-mcp/log.db` |
| Install metadata | `~/.sape/d-mcp/installation.json` |
| Connection profiles | `connections.db` — project root, **no passwords** |
| Permission rules | `permissions.db` — project root |
| Access audit | `audit.db` — project root |
| Database passwords | OS keyring, or AES fallback where no backend exists |

The `d-mcp/` path segment matters: f-MCP writes straight into `~/.sape/`, so without the
namespace the two applications would clobber each other's config and logs.

Nothing is created at import time. A clean checkout has no `.json` and no `.db`, and the
application creates what it needs on first run.

---

## 8. Running it

```bash
git clone https://github.com/sapebud/d-mcp.git
cd d-mcp
python -m venv .venv
# Windows:      .venv\Scripts\activate
# macOS/Linux:  source .venv/bin/activate
pip install -r requirements.txt

python main.py
```

Headless, for a machine with no Qt:

```bash
pip install "mcp>=2.0" anyio keyring cryptography sqlparse   # plus the drivers you need
python main.py --cli
```

Transports: `stdio` (default, for a client that spawns the process), `streamable-http` and
`sse`. The GUI rewrites `stdio` to `streamable-http` when starting the server in-process,
because stdio would hang on stdin inside a thread.

---

## 9. Conventions

Every `.py` file opens with the same 16-line GPL-3.0-only header, strapline
`SAPÉ d-MCP — controlled database access with granular permissions for LLMs`,
`Copyright (C) 2026 Luciano Arrezze`. Code, identifiers and comments in **British English**.
The interface is localised into 18 languages; legal document bodies stay English-only.

Full detail: `.claude/skills/sape-house-style/SKILL.md`.
