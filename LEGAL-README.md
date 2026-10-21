# SAPÉ d-MCP — Legal Documents Guide

**SAPÉ d-MCP is free software** licensed under the **GNU General Public License, version 3 only (GPL-3.0-only)**.

You may run it, study it, modify it, and redistribute it — including commercially — provided you pass on the same freedoms under the same license and make the corresponding source available. The full terms are in [`LICENSE`](LICENSE).

**Scope note:** the GPL covers the *program*. It does not transfer the **SAPÉ** name or logo — those remain the author's marks. You are free to fork and redistribute the code; use your own name for a fork so users can tell the two apart. See "Trademarks" below.

---

## The Documents

### 1. [`LICENSE`](LICENSE) — GNU General Public License v3.0
**Read this if:** you want to know your rights, or you intend to modify or redistribute the program.

This is the verbatim, unmodified text of the GNU GPL version 3, as published by the Free Software Foundation. It is the **only** document that grants or limits rights in this program. It is authoritative in English; the FSF does not publish legally binding translations.

Key points, in plain language — the license text governs, not this summary:

- **Run it** for any purpose, personal or commercial, no fee, no attribution required.
- **Study and modify** the source however you like.
- **Redistribute** copies or your modified versions — provided you license them under GPL-3.0, keep the copyright and license notices intact, state your changes, and make the corresponding source available to whoever receives the binary.
- **No additional restrictions** may be imposed on downstream recipients (§7). Any such restriction is void.
- **No warranty** (§§15–17).

"Version 3 only" means the "or any later version" clause is **not** granted; recipients are licensed under GPL-3.0 specifically.

### 2. [`DISCLAIMER.md`](DISCLAIMER.md) — Risk Notice
**Read this if:** you are about to configure permissions and grant an LLM access to your databases.

Points to the license's own warranty disclaimer (§§15–17) and then describes the concrete operational risks: that this is a permission system rather than a sandbox, that views require permission on every base object they read, that dropping an object or replacing a routine's body is never permitted at all while the remaining destructive operations are brokered through the GUI and denied outright when headless, that free-form SQL is gated by a guard that refuses anything it cannot fully attribute, that the audit log rotates rather than accumulates, that identifier case-folding differs per database engine, that the HTTP transports are unauthenticated, and how credentials are stored. **This is the one document with genuinely practical content — read it.**

### 3. [`DATA-PROTECTION.md`](DATA-PROTECTION.md) — Privacy & GDPR/RGPD
**Read this if:** you have privacy or data-protection questions, especially before connecting d-MCP to a database containing personal data.

Covers the zero-collection policy, local-only operation, what is stored on your machine (connections, permissions, audit log, settings, credentials), why the audit log itself can become a store of personal data, who the GDPR data controller is, the international-transfer implications of an LLM client receiving query results, data minimisation by design, and GDPR/RGPD status.

### 4. This file — orientation
Where to start and what each document is for.

---

## Trademarks

The GPL is a copyright license; it does not grant trademark rights. **SAPÉ** and **SAPÉ d-MCP** are the author's marks. You may:

- state accurately that your work is derived from or compatible with SAPÉ d-MCP
- redistribute unmodified copies under the SAPÉ d-MCP name

You should **not** present a modified version as though it were the original. Name your fork something of your own. This is the ordinary courtesy the GPL itself asks for in §5(a)–(b) (marking modified versions) and costs you none of the freedoms above.

---

## For Redistributors — A Short Checklist

If you ship SAPÉ d-MCP or a fork of it:

- [ ] Include the full `LICENSE` file
- [ ] Keep all copyright and license notices intact
- [ ] Mark your modified files with a change notice and date (§5(a))
- [ ] License the whole work under GPL-3.0-only (§5(c))
- [ ] Provide the corresponding source to anyone receiving a binary (§6)
- [ ] Add no further restrictions (§7) — no EULA on top, no "you may not modify" clause
- [ ] Keep the program's own legal notices intact if you distribute the GUI (§5(d))

Note the dependency implication: this program links **PyQt6**, which is itself GPL-licensed. That is fine for a GPL-3.0 work. It does mean a fork cannot be relicensed under permissive or proprietary terms while keeping PyQt6.

---

## Language

These documents are maintained in **English only**. The GPL is legally authoritative in English, and the Free Software Foundation does not publish binding translations — so a translated license would carry no legal force and could mislead. The application's interface is localised across multiple languages; the legal document text is English only.

---

## Contact

**SAPÉ smart bud**
Email: info@sapebud.com
Location: Arenys de Mar, Spain


Source: https://github.com/sapebud/d-mcp
