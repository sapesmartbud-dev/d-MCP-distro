# ADR 0001 — Where `connections.db`, `permissions.db` and `audit.db` live

- **Status:** accepted (stage 9), by user ruling
- **Supersedes:** the implicit "project root" of stages 2–8
- **Implemented by:** `src/sape_d_mcp/db_location.py`, and each store's own `default_db_path()`

## Context

`prompt.md` requires the three databases to live in the project root. That is well defined for a
source checkout and undefined for an installed package: once the code is in `site-packages`,
there is no project root to speak of.

Stages 2 through 8 never had to answer this, because nothing was ever run from anywhere but the
checkout. Three modules each solved it locally and differently, by counting `.parent` hops off
their own `__file__`:

| Module | Hops | Where that lands in a checkout | Where it lands in a wheel install |
|---|---|---|---|
| `db/connection_store.py` | `parents[3]` | repository root | `venv/lib/python3.12/` |
| `permissions.py` | `parents[2]` | repository root | `venv/lib/python3.12/site-packages/` |
| `db/log_store.py` | `parents[2]` | repository root | `venv/lib/python3.12/site-packages/` |

The hop counts differ because the three modules sit at different depths in the src-layout, and
each carried a docstring confidently explaining its own count. In a checkout all three agree and
everything works, which is exactly why it survived seven stages. The first real
`pip install .` created all three databases inside the interpreter's own `lib/` directory.
Nothing raised; it quietly worked in the wrong, possibly unwritable, place.

The irony is that the project already had the fix for the general case. `gui/resources.py` exists
*specifically* because f-MCP hand-counted `.parent` hops to find its asset trees and knew nothing
of `sys._MEIPASS`, and `DEVELOPMENT-PLAN.md` lists that as a defect fixed rather than copied. The
asset path was fixed; these three were not.

## Decision

Three candidates were put to the user:

| Candidate | For | Against |
|---|---|---|
| The installed package's own directory | Always the same place for a given install | Often unwritable; puts mutable state inside a directory a reinstall replaces |
| `~/.sape/d-mcp/` | One canonical location per user; matches where `config.json` and `log.db` already go | Departs furthest from `prompt.md`'s "project root"; a user with two unrelated projects gets one merged rule set |
| **The current working directory** | Closest reading of "project root" that still means something for an installed package; a user who runs from their project directory gets exactly what they asked for | Two launch directories mean two rule sets and two audit trails |

**The user chose the current working directory.** `--db` — f-MCP's single prefix argument — was
dropped rather than adapted: it assumes one database, and d-MCP's three need not share a
directory. The overrides are environment variables instead, checked in this order by each store:

1. That store's own variable — `DMCP_CONNECTIONS_DB`, `DMCP_PERMISSIONS_DB`, `DMCP_AUDIT_DB` — a
   full path to the file.
2. `DMCP_DB_DIR` — one directory for all three.
3. `Path.cwd()`.

One module, `db_location.py`, owns step 2 and step 3. Each store still owns its own file name and
its own step 1, because three modules independently answering "where does my data live" is how
the hop counts drifted apart in the first place.

## Consequences

**The cost is asymmetric, and worth naming precisely.**

`permissions.py`'s default-deny invariant means a fresh, empty `permissions.db` — the file this
resolver hands back when launched from an unexpected directory — authorises *nothing*. The
visible failure mode is therefore fail-closed: an LLM that suddenly may do nothing, not an LLM
that may do something it should not. That is the safe direction for a security-relevant file to
fail in.

`audit.db` is the genuine downside. A split audit trail across several directories is worse for
forensics than a missing one, because each fragment still opens and still looks complete —
nothing about the file says "there were other rows, somewhere else". Anyone investigating an
incident has to know to ask where every past working directory was, not just look at the one file
in front of them.

**A frozen application makes this concrete.** Launched from a desktop shortcut, the working
directory is whatever the shortcut says — on Windows, by default, the folder the executable sits
in. The user never chose it and is never shown it, except on the Settings page, which displays
all three resolved paths for exactly this reason.

**The escape hatch is not optional at the integration point.** An MCP client spawns the server
with whatever working directory it likes, which is essentially never the user's project
directory. `mcp_config_generator.generate_config()` therefore always emits all three environment
variables, resolving each store's own default at generation time when the caller does not name
one — because a configuration that omitted them would silently reproduce this exact defect on
every single launch, and would do so invisibly: the server starts, finds an empty permission
database, and refuses everything.

**Not memoised.** Unlike `gui/resources.py`'s asset root, which cannot change once the
interpreter has started, `Path.cwd()` can change within a process — a test suite's
`monkeypatch.chdir`, chiefly — and a cached answer would silently stop tracking it.

## Documented where a reader will meet it

- `src/sape_d_mcp/db_location.py`'s module docstring, at length.
- `README.md` — [Command line](../../README.md#command-line) for the mechanism, Known limitations
  for the cost.
- `DEVELOPMENT-PLAN.md`'s decisions table, as a user ruling.
- `docs/CROSS-PLATFORM-SMOKE-TEST.md` §5, as something to verify by hand on each platform.
