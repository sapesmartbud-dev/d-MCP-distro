# SAPÉ d-MCP — Data Protection Declaration

**Last Updated:** 2026-09-02
**Scope:** This declaration applies exclusively to **SAPÉ d-MCP** (the product), version 0.1.0.8 Beta, not to SAPÉ (the brand) or any other SAPÉ products.

---

## Overview

SAPÉ d-MCP gives a Large Language Model permission-gated access to databases you connect it to. That is a materially different privacy position from a file-system tool: the data it touches is, by construction, structured and often personal. This declaration says plainly what the program does and does not do with it.

**Important:** This privacy policy applies only to SAPÉ d-MCP. Other SAPÉ products may have different data protection practices.

## Core Principle: No Data Collection

**The author operates no servers for SAPÉ d-MCP, receives no telemetry from it, and has no access to anything it does.**

The application operates entirely on your own machine. It does not:
- Send data to servers operated by the author
- Collect usage statistics
- Track user behaviour or activities
- Report crashes or errors to external services
- Require account creation or login
- Use cookies or tracking mechanisms
- Connect to third-party analytics services

All query execution, permission evaluation and logging happens locally, inside the process you started. The only data leaving your machine is what you explicitly authorise an MCP client to receive — see "Rows Leave the Machine When the LLM Client Sends Them" below.

## Local Operation Only

SAPÉ d-MCP:
- Runs entirely on your computer
- Stores all connections, permissions, audit records and configuration locally
- Does not require an internet connection to operate against a local database
- Connects to remote database servers only when you configure a connection that points at one — that traffic goes to the database server you named, not to the author
- Communicates with LLM clients over the Model Context Protocol (MCP); this communication is not monitored or recorded by anyone other than the audit logging built into d-MCP itself, described below

## What d-MCP Stores Locally, and Where

| Store | Location | Contents |
|---|---|---|
| Connections | `connections.db` (project root) | Host, port, database name, username, driver, connection options. **No passwords** are stored here. |
| Permissions | `permissions.db` (project root) | The access rules you have configured — object patterns and granted actions. No query results, no row data. |
| Audit log | `audit.db` (project root) | The access log: tool calls, parameters, row counts, error text. See the section below — this is the store most likely to contain personal data. |
| Application settings | `~/.sape/d-mcp/config.json` | Theme, language, window geometry and other GUI preferences. |
| Credentials | OS keyring, or an AES-encrypted fallback store unlocked by a master password | Connection passwords. Never written into `connections.db` or any other d-MCP database. |
| Master password | Supplied by you at unlock time, or — only where no keyring exists — read from the `DMCP_MASTER_PASSWORD` environment variable | Never written to disk. See the warning below before using the environment variable. |

> **A warning about `DMCP_MASTER_PASSWORD`.** Setting it puts your master password in the
> process environment so an unattended server can unlock the encrypted credential store. It is
> then readable from `/proc/<pid>/environ` by any process running as the same user, and it
> commonly leaks into systemd units, `.env` files and shell history. It unlocks every stored
> credential, not one. Use it only where no OS keyring is available, and treat the machine
> accordingly.

**All of this data remains on your computer** (or wherever you have configured these stores to live). d-MCP does not upload, transmit, or share any of it with the author or with anyone else.

## The Audit Log May Contain Personal Data

This is the sharpest point in this document, and it has no equivalent in a file-system tool.

`audit.db` records, for every tool call: the tool name, the parameters passed to it, the number of rows affected or returned, and error text on failure. Parameters and error messages are drawn from the operator's own tables — a `WHERE` clause containing a customer's name, an error message quoting a row's content, a logged filter value. **The audit log can therefore itself become a store of personal data, and you must treat it as one.**

Concretely:
- Treat `audit.db` with the same access controls you would apply to the databases it logs against.
- If a data subject exercises a right (access, erasure, rectification) over data that has passed through a query you ran via d-MCP, check whether that data is also sitting in the audit log, not only in the source database.
- To purge the audit log, stop the application and delete or truncate `audit.db`. There is no in-application "forget this row" tool; the log is a flat operational record, not a data-subject-request workflow. Rotation happens automatically above 10 000 rows (the oldest 1 000 are deleted), but that is a size cap, not a retention or privacy control, and you should not rely on it for either.

## Who the Controller Is

**You are the data controller** for any personal data in a database you connect to d-MCP. d-MCP is a tool you run on your own equipment, under your own configuration, against data you chose to expose to it. The author of d-MCP is neither a controller nor a processor with respect to that data — the author never receives it, never sees it, and has no channel through which it could reach them.

This means the ordinary GDPR obligations of a controller — lawful basis, data minimisation, subject rights, breach notification — sit with you, the operator, for whatever d-MCP is configured to touch. d-MCP does not discharge any of them on your behalf; it only gives you the permission tooling to narrow what a connected LLM can reach.

## Rows Leave the Machine When the LLM Client Sends Them

This is the single most important privacy consequence of using this program, and it deserves its own section rather than a bullet point.

d-MCP returns query results to the MCP client that called it. The client is typically a hosted LLM — Claude, ChatGPT, or another provider's model running on that provider's infrastructure. Authorising a `select`-shaped rule on a table containing personal data does not keep that data on your machine: it means the rows matched by that query may be transmitted to the client, and from there to a third-party model provider, and processed outside your own infrastructure — possibly outside the European Economic Area, depending on the provider and the deployment you have connected.

That is an international data transfer under GDPR (Chapter V) if personal data is involved, and it is triggered by your permission configuration, not by anything d-MCP does automatically. Before granting a rule that exposes personal data:
- Identify which LLM provider will receive the results and where it processes data.
- Confirm you have an appropriate transfer mechanism if the provider processes outside the EEA (standard contractual clauses, an adequacy decision, or another lawful basis).
- Consider whether the query needs to return the personal fields at all, or whether a narrower view or column-level rule would do the job with less exposure.

d-MCP has no visibility into what the LLM client or its provider subsequently does with rows it receives, and no control over it — see "Third-Party Integrations" below.

## Data Minimisation by Design

d-MCP's permission model is built to narrow exposure by default, not to widen it:
- **Default-deny.** An empty permissions database authorises nothing. Every object a rule does not name is refused.
- **Per-object rules.** Permissions are granted at the level of individual tables, views, functions and procedures, not at the level of a whole database or server.
- **Mandatory row caps.** Every SELECT-shaped tool enforces a maximum row count, so a broad or unbounded query cannot return an entire table in one call.
- **Parameter sanitisation in the log.** Logging is designed to record what happened without needlessly amplifying exposure, though as noted above it cannot guarantee that no personal data ever appears in a parameter or error message — that risk is inherent to logging query parameters at all.

None of this substitutes for granting narrowly in the first place; it limits the damage when a grant turns out to be broader than intended.

## GDPR / RGPD Compliance

Under the EU General Data Protection Regulation (GDPR) and its Spanish implementation (RGPD):

- The author of SAPÉ d-MCP is **not a data controller** with respect to data you process through the program — see "Who the Controller Is" above.
- The author of SAPÉ d-MCP is **not a data processor** — the author never receives, stores, or has access to any data your instance of d-MCP touches.
- **You**, as the operator, are the controller for any personal data in the databases you connect and the queries you authorise, and you bear the associated obligations.
- Where a connected LLM client transmits results to a third-party provider, that provider is typically a processor (or a separate controller, depending on its terms) in its own right — assess this per client and provider.

## Data Retention

d-MCP retains, on your machine, exactly what is listed in the table above, for as long as you keep the files. There is no retention imposed by the author, because the author never receives the data in the first place. You control:
- `connections.db` and `permissions.db` — delete or edit at will; there is no scheduled expiry.
- `audit.db` — rotates automatically above 10 000 rows (oldest 1 000 deleted); export before that point if you need durability, and purge it deliberately if it must not persist.
- Credentials in the OS keyring or the encrypted fallback store — removed by removing the connection, or by clearing the keyring/master-password store directly.

## User Responsibilities

- **You are the controller** for personal data in any database you connect — see above. Establish your own lawful basis and data-subject-rights process before exposing such data through d-MCP.
- **The audit log can hold personal data** drawn from your own tables. Secure it, retain it deliberately, and purge it when it should not persist.
- **Rows sent to an LLM client leave your infrastructure.** Assess the transfer implications before granting `select` on tables containing personal data.
- **Credential security** is delegated to the OS keyring or the encrypted fallback; you are responsible for the security of the account and master password that protect it.
- If you share a machine or its backups, you are responsible for protecting `connections.db`, `permissions.db`, `audit.db` and the keyring from unauthorised access, exactly as you would protect the databases themselves.

## Third-Party Integrations

SAPÉ d-MCP is used as an MCP server alongside third-party LLM applications (Claude Desktop, ChatGPT, or others). **d-MCP does not monitor or control what those applications do with the data it returns to them.** If you use d-MCP with a third-party LLM client:
- Consult that application's and its provider's privacy policy and data processing terms.
- That application's data-handling practices are independent of SAPÉ and are not covered by this declaration.
- d-MCP does not share data with, or receive data from, the LLM provider directly — all such traffic passes through the MCP client you have configured, under its own terms.

## Contact for Privacy Inquiries

If you have questions about data protection or privacy, contact:

**SAPÉ smart bud**
Email: info@sapebud.com
Location: Arenys de Mar, Spain
