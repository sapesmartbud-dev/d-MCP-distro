# SAPÉ d-MCP — Disclaimer & Risk Notice

**Version 1.0**
**Effective Date:** 2026-09-02
**Scope:** This notice applies to **SAPÉ d-MCP** (the program), version 0.1.0.8 Beta, not to SAPÉ (the brand) or any other SAPÉ products.

---

## The Authoritative Disclaimer Is in the License

SAPÉ d-MCP is free software licensed under the **GNU General Public License, version 3 only (GPL-3.0-only)**. The binding warranty disclaimer and liability limitation are **sections 15, 16 and 17 of that license**, which you can read in the [`LICENSE`](LICENSE) file at the root of the source distribution.

In summary, as GPL-3.0 §15 puts it:

> THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY APPLICABLE LAW. […] THE PROGRAM IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE. THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM IS WITH YOU.

And as §16 puts it:

> IN NO EVENT UNLESS REQUIRED BY APPLICABLE LAW […] WILL ANY COPYRIGHT HOLDER, OR ANY OTHER PARTY WHO MODIFIES AND/OR CONVEYS THE PROGRAM AS PERMITTED ABOVE, BE LIABLE TO YOU FOR DAMAGES, INCLUDING ANY GENERAL, SPECIAL, INCIDENTAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OR INABILITY TO USE THE PROGRAM.

**This document adds nothing to and takes nothing away from those terms.** Nothing here restricts the rights the GPL grants you — to run, study, modify, and redistribute this program. Where anything in this document could be read as conflicting with the license, the license governs.

---

## No Obligation to Support or Maintain

SAPÉ d-MCP is offered without any commitment to provide:

- technical support
- bug fixes or patches
- feature updates
- security updates
- long-term compatibility with future database engines, drivers, operating systems or LLM clients

Updates, when they happen, are at the author's discretion and carry no warranty or continuing obligation. Because this is free software, you are also entitled to fix, maintain, or fork it yourself — see the license for the terms.

---

## What This Program Actually Does — Read This Part

The sections below are not legal boilerplate. They describe real, specific ways SAPÉ d-MCP can lead to data loss or unauthorised access if you misconfigure it. Read them before granting permissions.

### 1. It grants an LLM controlled write access to your databases

`DROP TABLE`, `DELETE`, and DDL on functions and procedures are all in the tool catalogue. Every one of them is checked against the permission rules in the local SQLite database before any work happens, and objects no rule covers are refused. But **the rules are only as good as you write them.** A rule you tick is a capability you have handed to a model.

### 2. It is a permission system, not a sandbox

This is the single most important thing to understand. d-MCP's rules narrow what the connection can do; they cannot widen it, and they are not a substitute for the database server's own grants. d-MCP does **not** provide:

- kernel-level enforcement or mandatory access control
- protection against privilege escalation on the database server
- a security boundary against a compromised or adversarial LLM client
- a replacement for connecting as a least-privileged database user

Connect it as a least-privileged user. If the connection's own database-level grants allow more than your d-MCP rules do, d-MCP's rules are the only thing standing between the model and the rest — grant narrowly on both sides.

### 3. Views do not launder access

Reading a view requires permission on the view *and* on every base object it reads, recursively. This is deliberate and it means a view is not a way to expose a subset of a table you have not granted. If you intend a view as a narrower window onto a wider table, you must still grant the underlying table for the view to be readable through d-MCP.

### 4. `DROP` and routine replacement are never permitted; other destructive operations still need the GUI

`drop-table`, `drop-view`, `drop-function`, `drop-procedure`, `edit-function` and `edit-procedure` stay in the tool catalogue, but no permission rule, however broadly written, can authorise any of them. Every call is refused by the permission engine itself, before it ever reaches the confirmation dialog described below — there is no tick, no rule and no GUI action that turns one of these six on. The practical consequence: **every table, view, function and procedure d-MCP creates is create-once.** A table cannot be dropped. A view can be neither dropped nor replaced. A function or a stored procedure can be neither dropped nor have its body replaced. If you create one with the wrong columns, or write a routine with a bug, undoing or fixing it is a job for a database client connecting directly to the server — d-MCP itself has no way back.

The remaining destructive operations are a different matter and still work as before: `DELETE` (removing rows from a table that continues to exist), and an `UPDATE`/`DELETE` with no effective `WHERE`, are brokered through a live confirmation dialog in the d-MCP window. With no GUI attached they are denied — so a headless server cannot perform them at all, regardless of what the permission rules say. Do not confuse the two: `DELETE` removes rows and is still available; `DROP` removes the object itself and never is.

### 5. Free-form SQL is gated, not trusted

`run-read-query` needs its own `run_query` permission, is refused unless the guard can classify every statement as read-only, and authorises every object the statement touches. Anything the guard cannot fully attribute is refused rather than attempted. This is a conservative guard, not a SQL sandbox — treat a refusal as the guard declining to reason about the statement, not as proof the statement was safe.

### 6. The audit log is not an archive

`audit.db` rotates: above 10 000 rows the oldest 1 000 are deleted. If you need retention for forensics or compliance, export before the rotation threshold is reached. See [`DATA-PROTECTION.md`](DATA-PROTECTION.md) for what the audit log can contain and why that matters.

### 7. Identifier case-folding differs per engine

PostgreSQL folds unquoted names to lower case; MS-SQL depends on collation; MySQL depends on `lower_case_table_names`; SQLite is ASCII-only case-insensitive. A rule can fail to match for reasons that are the server's, not d-MCP's. Non-ASCII identifiers that would need folding are refused rather than guessed — do not rely on such an identifier being reachable through d-MCP.

### 8. Third-party LLM clients are outside this program's control

SAPÉ d-MCP may be used with Claude, ChatGPT, or any other MCP client. What the client does with rows it receives is the client's behaviour, not this program's. See [`DATA-PROTECTION.md`](DATA-PROTECTION.md) for what this program itself stores and where, and for the transfer implications of returning query results to a hosted LLM.

### 9. The HTTP transports are unauthenticated

`streamable-http` and `sse` bind to localhost and carry no authentication. Anyone who can reach the port can drive the server within whatever the rules permit. Prefer `stdio` unless you specifically need HTTP.

### 10. Credentials live in the operating system's keyring, or an encrypted fallback

Connection passwords are stored in the OS keyring, or, where no keyring backend exists, in an AES-encrypted store unlocked by a master password. d-MCP never writes a password into its own databases. The security of the keyring is the operating system's, not this program's — if the OS account is compromised, so is anything the keyring holds.

### 11. `DMCP_MASTER_PASSWORD` trades secrecy for unattended operation

Where no keyring backend exists — a headless Linux box with no D-Bus session is the usual case — the encrypted fallback normally has to be unlocked by a person typing the master password. That makes an MCP server spawned unattended by a client unable to reach any database at all.

The environment variable `DMCP_MASTER_PASSWORD` exists to break that deadlock, and you should understand exactly what it costs before you set it. The master password then sits in the process environment, where it is readable from `/proc/<pid>/environ` by anything running as the same user, and it tends to leak into systemd units, `.env` files, container images and shell history. Whoever obtains it opens **the whole vault**, not one connection.

It is opt-in, it is used only when no keyring backend is available, and every use logs a warning. If you can run a keyring, run a keyring instead.

---

## What You Are Responsible For

- **Permission configuration** — understanding the scope of each rule you create, and granting the narrowest scope that works
- **Database-level grants** — connecting with a least-privileged user so d-MCP's rules are the binding constraint, not an afterthought on top of a permissive account
- **Backups** — of anything you grant write, DDL or delete access to
- **Audit log retention** — exporting `audit.db` before rotation, if you need a durable trail
- **System security** — OS patches, keyring integrity, account hygiene
- **Your LLM client** — vetting what you connect this server to, and what jurisdiction its provider processes data in

---

## Governing Law

To the extent any part of this document is enforceable separately from the license, it is governed by Spanish law, jurisdiction of Arenys de Mar, Spain. This does not affect the GPL's own terms, which apply as written.

If any provision of this document is found invalid or unenforceable, it is severed and the rest remains in effect.

---

## Contact

**SAPÉ smart bud**
Email: info@sapebud.com
Location: Arenys de Mar, Spain
