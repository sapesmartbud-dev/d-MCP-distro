# ADR 0004 — A permission rule names a collection of objects

**Status:** accepted
**Date:** 2026-09-12
**Supersedes part of:** DESIGN-DATA-MODEL.md §4.2, DESIGN-PERMISSIONS.md §2.1
**Schema:** `permissions.db` `user_version` 1 → 2

---

## Context

A version 1 rule was keyed by exactly one `(connection_id, schema_pattern, object_type,
name_pattern)` tuple. One rule therefore reached several objects only when they shared
a name prefix, which the three-form pattern grammar could express (`rpt_*`).

For an arbitrary set — `Customers`, `Invoices`, `Payments` — there was no expression at
all. The operator wrote three rules, and then had to keep three action sets in step by
hand for as long as they lived. Two further consequences followed from the same key,
and both were felt as defects rather than as design:

- **A rule's reach could not be edited.** `grant()` upserted on the key, so changing
  the schema, type or name would have written a *different* rule and silently left the
  original in place. `NewRuleDialog` froze all three fields on an existing rule to stop
  that, which meant a rule that reached one object too few had to be deleted and
  rewritten.
- **The schema browser selected one leaf at a time**, because one leaf was all a rule
  could take.

The user raised this as a structural problem, and it is one.

## Decision

A rule's target patterns move to a child table, `rule_targets`. One rule carries one
object type, one allow-or-deny, one action set, and **one or more** targets.

- **One object type per rule.** Action sets differ per type, so a mixed rule would have
  no coherent set of `can_*` columns to interpret — the same reason DESIGN-DATA-MODEL.md
  §4.2 gives for there being no `object_type = '*'`. This constrains *storage*, not the
  gesture: the Permissions page fans a selection spanning kinds out into one rule per
  kind, after saying so. The first cut instead disabled the button, which turned out to
  be the wrong call — see the note at the foot of this file.
- **Per connection, no shared library.** A collection belongs to one connection,
  matching `prompt.md`'s rule that each database has its own separate permission
  assignment. There is no cross-connection template, so no edit can widen access on a
  database the operator was not looking at.
- **The pattern grammar is unchanged.** A target is still exactly one of an exact
  literal, a `prefix*`, or a bare `*`. A collection is a set of those, not a richer
  language.

New API: `create_rule()`, `update_rule()`, `delete_rule()`, `targets_for()`.
`grant()`, `deny()` and `revoke()` survive with their signatures, as single-target
wrappers (see *Consequences*).

## Why the ordering proof survives

DESIGN-PERMISSIONS.md §2.4 proved the specificity ordering total from `uq_rules_key`.
That constraint moves to `rule_targets` with the same four columns, and the proof moves
with it:

> Suppose targets `T_A` (rule A) and `T_B` (rule B) both match, with equal specificity
> in both dimensions. §2.2 is a statement about *patterns*, not rows, so the patterns
> are pairwise identical. Both targets were reached through
> `WHERE connection_id = ? AND object_type = ?`, so all four columns of
> `uq_rule_targets_key` agree; therefore `T_A = T_B`; a target has one `rule_id`;
> therefore `A = B`. ∎

It is in fact *stronger* than version 1's. There, `is_deny` had to be excluded from the
key by hand so that an allow row and a deny row could not coexist on one key. A target
carries no decision at all, so that contradiction is not merely forbidden — it is
unrepresentable.

**`rule_id` is deliberately not in the uniqueness key.** Scoping it per rule reads as
the more natural constraint and is what a later maintainer would "correct" it to. It
would let two rules own the same target, and the ordering would then tie for real,
silently, with only the defensive tiebreak between that and an arbitrary decision.

**Within one rule**, several targets may match one object (`dbo`/`*` and `dbo`/`Cust*`
both match `dbo.Customers`). The narrowest wins: *a rule's specificity at an object is
the specificity of its narrowest matching target.* §3's one-sentence model is unchanged.

## Why this is not the child table §4.1 rejected

DESIGN-DATA-MODEL.md §4.1 rejected option (c), a `(rule_id, action, allowed)` child
table, partly because it "invites the opposite reading — that per-action rows from
several rules might be merged". The distinction, which is now recorded in §4.1 itself:

- A (c) row is a fragment of an **answer** — "what may be done". Resolution over
  fragments of an answer has an obvious, tempting and wrong implementation, namely to
  union them, and that implementation is a privilege escalation with nothing in the
  shape of the data arguing against it.
- A target row is a fragment of a **question** — "does this rule apply here?". The
  decision surface is untouched: the winner is still exactly one `rules` row carrying
  all 17 `can_*` columns, and `is_allowed()` is still one dict lookup with no join.

The theorem that makes it safe: *the resolver takes `max` over the matched set, never a
union, so merging targets across rules can change **which** rule wins but can never
produce an action set that no single rule authorises.* Option (c) has no such theorem
available.

§4.1's second objection also fails to transfer. (c)'s `action` column had no enforceable
domain, so a typo stored and read as "not granted" — failing closed, but invisibly.
`schema_pattern` and `name_pattern` have a domain that *is* enforceable and
tuple-independent: the two `instr()` CHECKs move across unchanged.

## Four defences the shape needs, and why each is load-bearing

1. **`NOT NULL` on every column of `rule_targets`.** SQLite counts NULLs as distinct in
   a UNIQUE index; a CHECK that evaluates to NULL *passes*, and
   `instr(NULL,'*') IN (0, length(NULL))` is NULL; and a composite foreign key whose
   child carries a NULL is satisfied vacuously. One nullable column would switch off the
   uniqueness, the pattern grammar and the parent check at once.
2. **A partial unique index for `database` rules.** "At most one per connection" *is*
   the meaning of the type (§5.6). Version 1 got it free from `uq_rules_key` plus the
   forced `'*'/'*'`; with the patterns gone from `rules` it has to be stated, or
   `rule_for()` would pick between two by storage order.
3. **The join repeats `connection_id` and `object_type` on both sides.** The composite
   foreign key forbids a drifted target, but only while `PRAGMA foreign_keys` is on — so
   `_apply_pragmas()` now *verifies* that pragma took, the way it already verifies WAL,
   and the join makes a drifted row inert rather than authoritative.
4. **An explicit projection, never `SELECT r.*, t.*`.** `id` would appear twice and
   `sqlite3.Row` keeps the last, so `mcp_server._rule_id()` would write a *target* id
   into `audit.matched_rule_id` and the Logs page would link every historical denial to
   the wrong rule, with nothing failing to say so.

## Consequences

**`grant()` refuses a target whose rule names others.** Three cases: no such target →
a new one-target rule; a single-target rule → version 1's upsert exactly; a
multi-target rule → `ValueError`. Neither alternative is safe. *Mutating the siblings*
would give the call a blast radius wider than its own arguments —
`grant(..., "Customers", ["drop"])` against a rule that also targets `dbo`/`*` hands
`drop` to every table in the schema — and a permission call whose reach cannot be read
off its call site is not auditable. *Silently splitting the target out* fails the other
way and more quietly: the operator's next tightening of the rule they believe covers
that object leaves a hole they think they closed. `revoke()` is symmetric.

**`show-permissions` changed shape.** `schema_pattern` and `name_pattern` are replaced
by `targets`. No scalar alias holding "the first target" is kept: a half-truth about a
rule's reach is worse for an LLM deciding what it may touch than a shape it must read
properly.

**The saved rule-table column widths were renamed, not migrated.** The table went from
eight columns to seven, so every saved index from `"1"` up denotes a different column.
Reusing `permissions_table_columns` would apply old widths to new meanings and leave
every existing install looking subtly wrong with nothing raising; the key became
`permissions_rules_table_columns` and the old one sits harmlessly in `config.json`,
which is what the "unknown keys are preserved" policy is for. Schema version 3 then
did the same thing again for the same reason — `rules.rule_name` inserts a Name column
at index 0, shifting every saved index up by one — so the key the code reads today is
`permissions_rules_table_columns_v2`, and both superseded names are still in the file.

**`audit.db` is unaffected.** `matched_rule_id` is still a single integer naming a
`rules.id`, and the migration carries every id across explicitly for that reason.

## Alternatives rejected

- **Named, reusable collections** (`object_groups` + membership, referenced by rules).
  Equivalent power for the stated problem plus reuse across connections, at the cost of
  a second concept, an extra indirection in every denial message, and one edit that can
  change access on several databases at once. Reuse within a connection is impossible
  by construction anyway — a target may belong to only one rule — so the only thing it
  buys is the cross-connection case, which the per-database rule in `prompt.md` argues
  against. Recorded as a candidate refinement, not built on speculation.
- **Materialising a collection into N version 1 rows** with a `source_group_id`. Zero
  risk to the resolver, but the collection becomes a GUI fiction: generated rules must
  be made read-only, an overlap between two collections surfaces as a conflict while
  editing an unrelated one, and the rule list grows a row per object.
- **No model change, GUI writes N rules in one gesture.** Solves the typing, not the
  problem: the collection has no identity, so editing it later means finding and
  re-editing N rows with nothing keeping them in step — which is the defect.


---

## Addendum — the mixed selection, corrected

The first implementation disabled "New rule from selection" when the tree selection
spanned object types, with a tooltip giving the reason. That was wrong twice over, and
was reported as "New rule from selection performs nothing".

It was wrong in the **mechanism**: the page listened on the tree's `currentItemChanged`,
which is not the same event as `itemSelectionChanged` once the tree is
`ExtendedSelection` — a shift-click range, a rubber-band drag and Ctrl+A all change the
selection while moving the current item once or not at all. The enabled state therefore
described a selection that was no longer there, and the handler's own re-check then
disagreed with it and returned. It now listens on `itemSelectionChanged`.

It was wrong in the **policy**: a rule carrying one object type is a fact about storage,
not about what an operator's gesture may mean. Selecting thirty rows and being told the
button is unavailable — with no indication of which rows are the odd ones — is worse than
being asked twice for actions. A mixed selection now fans out into one rule per kind, in
the tree's own type order, announced before the first dialog.

The general lesson worth keeping: **no path out of that handler may return silently.**
An enabled control that does nothing is indistinguishable from a crash, and it is worse
than an error message, because there is nothing to read and nothing to act on. Pinned by
`tests/test_permissions_page.py`.
