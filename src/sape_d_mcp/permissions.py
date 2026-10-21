# SAPÉ d-MCP — controlled database access with granular permissions for LLMs
# Copyright (C) 2026 Luciano Arrezze
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-only

"""Pattern-based permission rules over ``permissions.db`` — the security-critical core.

Default-deny, and never seeded: a fresh database authorises nothing at all, and there
is no starter rule an operator has to remember to delete (DESIGN-PERMISSIONS.md §4).
Every object an LLM may reach was granted explicitly, by a human, through the GUI.

The resolution order is the one thing in this module that must never be got backwards:
rules are ranked by ``(specificity(name_pattern), specificity(schema_pattern))`` — the
*name* dominates the *schema* — and the single most specific matching rule wins
wholesale, allow or deny alike, with no merging of action sets across rules
(DESIGN-PERMISSIONS.md §2–§3). Pattern matching happens here, in Python, rather than
in a SQLite ``GLOB``: a pattern held in a column cannot use an index anyway, so pushing
it into SQL would buy nothing and would move the security decision into SQLite's
pattern semantics instead of our own tested code (§7).

Schema version 3 added ``rules.rule_name``, the operator's own label for a rule so the
rules list says what each one is *for*.  It is metadata and only metadata: it is
optional, it is unique per connection among the names actually set, and **no part of
resolution reads it**.  A rule authorises exactly what it authorised before it was
named, which is the property that lets a label be edited freely by whoever is looking
after the rules.

Since schema version 4, ``drop`` and ``edit`` are categorical prohibitions
(``FORBIDDEN_ACTIONS``, ``docs/adr/0005-drop-and-edit-are-never-granted.md``): no rule,
however it is written, can make either action authorised.  ``edit`` is the same act as
``drop`` under another name for a function or a procedure, because replacing a routine
body destroys the previous one to install the new one.  Both remain in
``ACTIONS_BY_TYPE`` deliberately — the six MCP tools that ask for them stay in the
catalogue and must be refused cleanly rather than crash — but :meth:`PermissionStore.is_allowed`
and :meth:`PermissionStore.require` return the same answer for either regardless of what
any rule's ``can_drop`` / ``can_edit`` column holds.
"""

from __future__ import annotations

import logging
import os
import sqlite3
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime
from pathlib import Path
from types import TracebackType
from typing import Any

# The resolver's identifier type is NormalisedRef, minted only by the dialect layer
# (src/sape_d_mcp/db/dialects/base.py, DESIGN-DIALECTS.md §2). Accepting only a type
# the dialect can mint is what makes a missed normalisation a type error instead of a
# permission hole — this module never accepts a bare string or a raw ObjectRef.
from sape_d_mcp.db.dialects.base import NormalisedRef
from sape_d_mcp.db.dialects.types import ObjectType
from sape_d_mcp.db_location import resolve_db_directory
from sape_d_mcp.db_migrations import MigrationRecord, backup_before_rebuild

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Action tuples, per object type — THE single source of truth
# ---------------------------------------------------------------------------
# These generate the can_* columns, the PRAGMA table_info migration, grant()/deny()
# validation, the GUI's checkbox grid and a parametrised test. Adding an action means
# editing exactly one entry here (DESIGN-PERMISSIONS.md §9).
ACTIONS_BY_TYPE: dict[str, tuple[str, ...]] = {
    "table": (
        "list", "read_structure", "select", "insert",
        "update", "delete", "create", "drop",
    ),
    "view": ("list", "read_definition", "select", "create", "drop"),
    "function": ("list", "read_definition", "create", "edit", "drop"),
    "procedure": ("list", "read_definition", "create", "edit", "drop"),
    "database": (
        "read_catalogue", "create_role", "create_user", "create_group",
        "assign_group", "assign_role", "run_query",
    ),
}

#: The one object type whose actions belong to the connection rather than to an object in
#: it. DESIGN-PERMISSIONS.md §5.6: there is nothing to pattern-match, so a rule of this type
#: is resolved by connection alone and is always written with '*' for both patterns.
DATABASE_TYPE: str = "database"

OBJECT_TYPES: tuple[str, ...] = tuple(ACTIONS_BY_TYPE)
ALL_ACTIONS: tuple[str, ...] = tuple(sorted({a for s in ACTIONS_BY_TYPE.values() for a in s}))

#: Actions no rule may ever authorise, whatever its ``can_*`` columns say (ADR 0005,
#: ``docs/adr/0005-drop-and-edit-are-never-granted.md``). ``drop`` destroys an object
#: outright. ``edit`` is the same act under another name for a function or a
#: procedure: where the dialect has no ``CREATE OR REPLACE`` for routines,
#: ``edit_routine()`` falls through to dropping the routine and recreating it
#: (``db/dialects/base.py:2422``), so an operator who withheld ``drop`` and granted
#: ``edit`` had withheld nothing. The user ruled that a box ticked by mistake in
#: ``NewRuleDialog`` must not be able to authorise the destruction of an object, so
#: the prohibition is a property of the verb, enforced once in
#: ``PermissionStore.is_allowed()`` and ``PermissionStore.require()``, and not a
#: per-object-type tuple that six places would have to remember to keep in step.
#:
#: A flat set over verbs, not restated per object type: `[(t, a) for t, acts in
#: ACTIONS_BY_TYPE.items() for a in acts if a in FORBIDDEN_ACTIONS]` gives exactly
#: `(table, drop) (view, drop) (function, drop) (function, edit) (procedure, drop)
#: (procedure, edit)` — the six pairs the invariant governs.
#:
#: **Both verbs deliberately stay in ACTIONS_BY_TYPE above, rather than being
#: removed now that neither can be granted.** Removing "drop" from `table` would
#: make `_validate_action("drop", "table")` raise `ValueError` for every caller,
#: including `mcp_server.py`'s `drop-table` tool — which the user insisted stay in
#: the tool catalogue, denied rather than absent. A `ValueError` there would be
#: filed by the audit layer as an `error`, not a `denied`, and the six tools kept
#: exposed for exactly this reason would crash instead of refusing cleanly. A drop
#: or an edit must remain a well-formed question with a permanent answer of "no".
FORBIDDEN_ACTIONS: frozenset[str] = frozenset({"drop", "edit"})

#: Why each forbidden action is forbidden, cited in the denial message so the
#: sentence is true rather than generic (ADR 0005 §4). Checked below against
#: `FORBIDDEN_ACTIONS` rather than read with `.get(action, "")`: the lesson already
#: paid for elsewhere in this house is that a member added to a set and forgotten
#: here must fail at import, at the table check, not at the first denial an
#: operator reads under pressure.
_FORBIDDEN_REASON: dict[str, str] = {
    "drop": "destroying an object is never granted",
    "edit": "replacing a routine body destroys the previous one, so it is never granted",
}

# A plain `assert` was rejected here for the same reason it was rejected below, at
# the `_MIGRATIONS` guard: `python -O` strips it, and a check that exists to catch a
# silent failure must not itself have a silent way of being switched off. Under -O
# a member added to `FORBIDDEN_ACTIONS` without a matching `_FORBIDDEN_REASON` entry
# would not fail here at import -- it would fail inside `_forbidden_message()` with
# an unhandled `KeyError`, on the very first denial of that action, which is the
# first thing an operator reads under pressure. `raise RuntimeError` cannot be
# compiled away, so the build that is missing a reason never starts at all.
if set(_FORBIDDEN_REASON) != FORBIDDEN_ACTIONS:
    raise RuntimeError(
        "_FORBIDDEN_REASON must give a reason for exactly the actions in "
        "FORBIDDEN_ACTIONS -- this must be fixed before the application runs at "
        "all, or a forbidden action added without a reason would raise a bare "
        "KeyError from _forbidden_message() at the first denial of it instead"
    )

#: How long an operator's own name for a rule may be.  80 characters is a table
#: column an operator can read at a glance rather than a second description field:
#: the Permissions page renders the name in one cell beside the object patterns, and
#: anything longer is prose that would be elided there anyway.  Interpolated into the
#: DDL's CHECK, into :func:`_validate_rule_name` and into its message, so the schema
#: and the Python cannot disagree about the limit — the discipline
#: ``connection_store.MAX_STATEMENT_TIMEOUT_S`` uses.
MAX_RULE_NAME_LENGTH = 80

#: 1 — one rule, one target pattern pair.
#: 2 — a rule's targets moved to ``rule_targets``, so one rule names a collection of
#:     objects.  See :func:`_migrate_1_to_2` and DESIGN-PERMISSIONS.md §2.4.
#: 3 — a rule carries an optional ``rule_name``, the operator's own label for it,
#:     unique per connection among the names actually set.  See :func:`_migrate_2_to_3`:
#:     an ``ALTER TABLE ... ADD COLUMN``, deliberately not a rebuild.
#: 4 — ``drop`` and ``edit`` become categorical prohibitions the resolver itself
#:     enforces (ADR 0005): no rule can grant them, regardless of its ``can_drop`` /
#:     ``can_edit`` columns. See :func:`_migrate_3_to_4`, which zeroes those columns
#:     on any rule still carrying either — hygiene, since ``is_allowed()`` has
#:     already ignored them from the moment this version ships, not enforcement.
#:     A version 4 file will not open on a build that only understands version 3;
#:     that build would honour both columns, which is the correctness this bump
#:     protects.
SCHEMA_VERSION = 4


class PermissionDenied(PermissionError):
    """Raised by ``require()`` when a rule does not authorise the action."""


class ActionForbidden(PermissionDenied):
    """Raised by ``require()`` for ``drop`` or ``edit``: no rule can ever authorise them.

    A subclass of ``PermissionDenied`` rather than a sibling, for the same reason
    ``ConfirmationRefused`` is a ``PermissionError``: every existing
    ``except PermissionDenied`` handler stays fail-closed without being told about
    this class, while the audit layer and the tests that need to tell the two
    apart can still catch ``ActionForbidden`` specifically (ADR 0005 §4). It serves
    both forbidden verbs unchanged — nothing about the exception itself is
    ``drop``-specific; the discriminator is the action already carried in the
    message.
    """


def current_user() -> str:
    """Best-effort login name of the user running the application.

    Ported from f-MCP's ``permissions.current_user`` with its documented fallbacks:
    ``getpass.getuser()`` raises where there is no password entry and no LOGNAME,
    which happens inside slim containers and some service accounts.
    """
    import getpass

    try:
        return getpass.getuser()
    except Exception:  # no password entry / no LOGNAME in some containers
        fallback = os.environ.get("USER") or os.environ.get("USERNAME")
        if fallback:
            return fallback
        getuid = getattr(os, "getuid", None)
        return f"uid:{getuid()}" if getuid is not None else "unknown"


def _now() -> str:
    """ISO 8601 with the local offset, seconds precision — f-MCP's audit format."""
    return datetime.now().astimezone().isoformat(timespec="seconds")


def default_db_path() -> Path:
    """Resolve ``permissions.db`` from the environment, else the current working directory.

    Precedence: ``DMCP_PERMISSIONS_DB`` (this file, exactly), then ``DMCP_DB_DIR``
    (all three files, one directory), then whatever :func:`resolve_db_directory`
    falls back to — see that module for why the fallback is the *current working
    directory* rather than a hard-coded ``.parent`` count off ``__file__``.

    A stray fallback here is fail-closed and not fail-open: this is the
    permission engine's own default-deny invariant (module docstring above), so
    launching from an unexpected directory produces a fresh, *empty* database
    that authorises nothing, not one that authorises something it should not.
    That still matters enough to get right, because the visible symptom — an LLM
    that suddenly may do nothing — is easy to mistake for a different bug
    entirely if nobody thinks to check the working directory.

    Overridable so the test suite can point at a ``tmp_path`` without touching the
    developer's real databases (DESIGN-DATA-MODEL.md §1).
    """
    explicit = os.environ.get("DMCP_PERMISSIONS_DB")
    if explicit:
        return Path(explicit).expanduser()
    return resolve_db_directory() / "permissions.db"


def _can_columns_sql() -> str:
    """Render the 17 ``can_*`` columns from ``ALL_ACTIONS``, alphabetically.

    ``ALL_ACTIONS`` is itself ``sorted(...)``, so this reproduces
    DESIGN-DATA-MODEL.md §4.3's column list without anyone hand-copying SQL text —
    the same discipline ``connection_store.py`` uses for its engine/driver ``CHECK``.
    """
    return ",\n".join(f"    can_{action:<19} INTEGER NOT NULL DEFAULT 0" for action in ALL_ACTIONS)


#: The domain of ``rules.rule_name``, written once because it is asserted twice: as a
#: table constraint in :func:`_rules_ddl` on a fresh database, and as a column
#: constraint on the ``ALTER TABLE`` of :func:`_migrate_2_to_3`.  Two hand-typed
#: copies of a CHECK are two constraints that drift, and the migrated file is the one
#: nobody looks at afterwards.  ``trim()`` here is a *backstop* only — the store
#: normalises before writing (see :func:`_validate_rule_name`), so a blank name is
#: already NULL by the time SQLite sees it, and this catches a hand-edited file.
_RULE_NAME_CHECK = (
    "rule_name IS NULL OR ("
    f"length(trim(rule_name)) > 0 AND length(rule_name) <= {MAX_RULE_NAME_LENGTH})"
)

# DESIGN-DATA-MODEL.md §4.3 at schema version 3, but for the generated can_* column
# block above and the PRAGMAs, which are applied in Python by _apply_pragmas() rather
# than typed into the script text — the same split connection_store.py uses, so the
# PRAGMA is re-asserted on every open rather than only on a fresh file.
#
# Both tables are rendered by a function taking the table name, for one reason only:
# the version 1 -> 2 migration builds `rules` as `rules_v2` before renaming it, and a
# schema the migration retypes by hand is a schema whose two copies drift apart.
# connection_store.py's `_connections_ddl()` does the same, for the same reason.


def _rules_ddl(table: str, *, if_not_exists: bool) -> str:
    """The ``rules`` table body — a decision, no longer a target.

    Schema version 2 moved the two pattern columns out to ``rule_targets``, so that
    one rule authorises a *collection* of objects.  What is left here is purely the
    decision: an object type, an allow-or-deny, and the 17 ``can_*`` columns.

    That split is the whole safety argument for the change, and it is why this is not
    the child table DESIGN-DATA-MODEL.md §4.1 rejected as option (c).  A ``(rule_id,
    action, allowed)`` row is a fragment of an *answer* — "what may be done" — and
    resolution over fragments of an answer has an obvious, tempting and wrong
    implementation, namely to union them, which is a privilege escalation with
    nothing in the shape of the data arguing against it.  A target row is a fragment
    of a *question*: "does this rule apply here?".  The decision surface is unchanged
    — the winner is still exactly one row of this table, carrying all 17 columns, and
    ``is_allowed()`` is still one dict lookup with no join — so merging targets across
    rules can change *which* rule wins but can never produce an action set that no
    single rule authorises.
    """
    clause = "IF NOT EXISTS " if if_not_exists else ""
    return f"""
CREATE TABLE {clause}{table} (
    id                      INTEGER PRIMARY KEY AUTOINCREMENT,  -- cited by audit.matched_rule_id
    connection_id           INTEGER NOT NULL,   -- logical FK -> connections.db connections(id);
                                                -- unenforceable across files, see §7
    object_type             TEXT    NOT NULL,   -- table | view | function | procedure | database
    is_deny                 INTEGER NOT NULL DEFAULT 0,

    -- ── generated from ACTIONS_BY_TYPE, sorted ────────────────────────────────
{_can_columns_sql()},
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
    -- NULLABLE, and that is the decision rather than an omission (see
    -- _migrate_2_to_3): every rule written before version 3 keeps no name until a
    -- human gives it one, which is what makes the upgrade an ALTER instead of a
    -- rebuild and means no placeholder was ever invented on an operator's behalf.
    -- NULL is the ONLY spelling of "no name" -- the store folds '' to NULL on write
    -- -- because two spellings of absence in a column with a UNIQUE index over it
    -- would be two rules that look unnamed and collide, or two that look identical
    -- and do not.
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
    CONSTRAINT ck_rules_name CHECK ({_RULE_NAME_CHECK}),
    CONSTRAINT ck_rules_audit CHECK (
        length(created_at) >= 19 AND length(updated_at) >= 19
        AND length(user_created) > 0 AND length(user_updated) > 0
    )
);
"""


def _rule_targets_ddl(table: str, *, if_not_exists: bool) -> str:
    """The objects one rule reaches — one row per pattern pair, one rule per target.

    This is the table that makes a rule a *collection*.  Its uniqueness constraint is
    DESIGN-DATA-MODEL.md §4.2's ``uq_rules_key`` moved across unchanged, and it is
    what keeps the specificity ordering provably total: two matching targets can tie
    only if their patterns are identical (DESIGN-PERMISSIONS.md §2.2), and identical
    patterns within one connection and object type are exactly what this forbids.
    """
    clause = "IF NOT EXISTS " if if_not_exists else ""
    return f"""
CREATE TABLE {clause}{table} (
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
"""


#: Uniqueness for a rule's name, per connection and over the names actually set.
#:
#: A *partial* index, the way `uq_rules_one_database_per_connection` below is one, and
#: for a reason that has to be stated or it reads as an optimisation: the rule's name
#: is optional, and "unique" must mean "no two rules on one connection carry the same
#: name", never "at most one rule may be unnamed".  SQLite counts NULLs as DISTINCT in
#: a UNIQUE index, so a plain index would in fact allow any number of unnamed rules —
#: but only by accident of NULL semantics, and the first person to normalise a blank
#: name to '' rather than NULL would silently turn it into "one unnamed rule per
#: connection".  The WHERE clause says outright what is meant.
#:
#: COLLATE NOCASE, following `connections.display_name`, which is the house precedent
#: for a user-facing unique label: 'Sales reports' and 'sales reports' in one list
#: defeat the entire purpose of naming a rule.  The known limit, recorded here rather
#: than discovered later: SQLite's NOCASE folds ASCII only, so 'CAFÉ' and 'café' would
#: NOT collide.  That is a permissive failure on a field no permission decision ever
#: reads — `rule_for()` matches on patterns alone — so it costs an operator a
#: confusing list, not an unintended grant.
UQ_RULES_NAME_PER_CONNECTION = (
    "CREATE UNIQUE INDEX IF NOT EXISTS uq_rules_name_per_connection\n"
    "    ON rules(connection_id, rule_name COLLATE NOCASE) WHERE rule_name IS NOT NULL"
)

#: Applied after both tables exist, and re-applied on every open.  Version 1's
#: `idx_rules_connection` is deliberately absent: it indexed the two columns the
#: version 2 rebuild removed, and `idx_rule_targets_lookup` does its work now.
INDEXES = f"""
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

-- A rule's own name, unique per connection among the names actually set; see
-- UQ_RULES_NAME_PER_CONNECTION above for why it is partial and why it folds case.
{UQ_RULES_NAME_PER_CONNECTION};
"""

SCHEMA = (
    _rules_ddl("rules", if_not_exists=True)
    + _rule_targets_ddl("rule_targets", if_not_exists=True)
    + INDEXES
)


# ---------------------------------------------------------------------------
# Schema migration (DESIGN-DATA-MODEL.md §4.5)
# ---------------------------------------------------------------------------

#: What an upgrade of this file rewrote, as it reads in a sentence.
_MIGRATION_SUBJECT = "your permission rules"

#: The thing a reader of a ``permissions.db`` record most needs told plainly.  Losing
#: these rows is not a cosmetic failure: default-deny means an emptied file locks the
#: LLM out of everything until every rule is written again by hand.
_MIGRATION_NOTES_1_TO_2 = (
    (
        "No permission was widened by this upgrade. Every rule still reaches exactly\n"
        "the objects it reached before -- the change is structural, so that one rule can\n"
        "now name several objects rather than exactly one."
    ),
)

#: Version 2 -> 3.  The second paragraph is the one an operator opening this file
#: actually needs: the upgrade added an empty column and nothing else, so there is no
#: list of rewritten values below it to check, and the absence of one is not a fault.
_MIGRATION_NOTES_2_TO_3 = (
    (
        "No permission was widened by this upgrade, and no rule was rewritten. Every\n"
        "rule still reaches exactly the objects it reached before, with exactly the\n"
        "actions it carried before."
    ),
    (
        "The upgrade added one empty column: a name you can give a rule, so the rules\n"
        "list says what each rule is for. Your existing rules have no name until you\n"
        "give them one -- deliberately, because inventing a name on your behalf would\n"
        "have put words in the list that you never wrote."
    ),
)


def _migrate_1_to_2(conn: sqlite3.Connection) -> None:
    """Move each rule's target patterns out to ``rule_targets``.

    Version 1 keyed a rule by one ``(connection_id, schema_pattern, object_type,
    name_pattern)`` tuple, so a set of objects with no shared name prefix needed one
    rule each, kept in step by hand, and a rule's reach could not be edited at all
    afterwards.  Version 2 gives a rule many targets.

    SQLite cannot drop a column named in a UNIQUE constraint, in a CHECK and in an
    index — ``schema_pattern`` is in all three — and no ``ALTER`` can add the new
    ``uq_rules_identity`` the child table's foreign key needs, so the twelve-step
    table rebuild is the only honest route.  ``pragma writable_schema = 1`` is
    rejected for the reason ``connection_store`` rejects it: it edits
    ``sqlite_master`` text under a live schema cache, and a corrupted
    ``permissions.db`` costs the operator every rule they wrote.

    Idempotent, because the migration chain must be safe to re-enter: a database
    whose ``rules`` table has already lost ``schema_pattern`` is left alone, and so is
    a brand-new file, whose tables ``SCHEMA`` is about to create in the version 2
    shape.

    **This transfers permissions verbatim.**  Every version 1 row becomes one rule
    with exactly one target holding the same two patterns, so no rule's reach changes
    by a single object.  The rebuild cannot fail on data either: ``uq_rules_key`` was
    exactly ``uq_rule_targets_key``'s four columns, and the pattern CHECKs move across
    as the same two expressions.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(rules)")}
    if not columns or "schema_pattern" not in columns:
        return

    record = MigrationRecord(
        _MIGRATION_SUBJECT, user=current_user(), notes=_MIGRATION_NOTES_1_TO_2
    )
    # The sqlite3 driver's legacy implicit transaction must be closed before the
    # explicit BEGIN IMMEDIATE below, or SQLite refuses it as a nested transaction.
    conn.commit()
    backup_before_rebuild(conn, 2, record, subject=_MIGRATION_SUBJECT)

    # Both pragmas are silent no-ops inside a transaction, which is why they sit
    # outside one.  It is switched off for the rebuild because `rule_targets` is
    # created against the *renamed* table, and back on in the `finally` regardless of
    # how this ends -- the resolver's join depends on it (see _apply_pragmas).
    conn.execute("PRAGMA foreign_keys = OFF")
    try:
        conn.execute("BEGIN IMMEDIATE")

        # A pre-release file may lack a can_* column that ACTIONS_BY_TYPE now has,
        # because _migrate_schema() -- which repairs that by ALTER -- runs *after*
        # this chain; naming such a column in the SELECT would fail with "no such
        # column" and take the whole upgrade down on exactly the oldest file it
        # exists to rescue.  It may equally carry a can_* column for an action since
        # withdrawn, and DESIGN-DATA-MODEL.md §4.5 promises those are never silently
        # forgotten.  So: read what is present, default what is not, and carry
        # anything unrecognised across into a column added for it.
        wanted = [f"can_{action}" for action in ALL_ACTIONS]
        extra = sorted(c for c in columns if c.startswith("can_") and c not in wanted)
        conn.execute(_rules_ddl("rules_v2", if_not_exists=False))
        for column in extra:
            conn.execute(f"ALTER TABLE rules_v2 ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
            record.note(
                "Column %s is kept although no current action uses it, so a grant "
                "made by an older build is not silently forgotten.",
                column,
                level=logging.INFO,
            )
        carried = wanted + extra
        projection = ", ".join(c if c in columns else "0" for c in carried)

        # The targets are read out BEFORE the drop, and written back after the
        # rename, because rule_targets' foreign key names `rules` and that name
        # belongs to the version 1 table until the rename has happened.
        targets = conn.execute(
            "SELECT id, connection_id, object_type, schema_pattern, name_pattern FROM rules"
        ).fetchall()

        # `id` is carried explicitly: audit.db's tool_calls.matched_rule_id is a
        # logical foreign key to it, so a re-numbered rule silently re-points every
        # historical denial in the Logs page at the wrong rule.
        conn.execute(
            f"""
            INSERT INTO rules_v2
                  (id, connection_id, object_type, is_deny, {", ".join(carried)},
                   created_at, user_created, updated_at, user_updated)
            SELECT id, connection_id, object_type, is_deny, {projection},
                   created_at, user_created, updated_at, user_updated
              FROM rules
            """
        )
        # DROP before RENAME, in that order: dropping `rules` takes its sqlite_sequence
        # row with it, and the rename then moves rules_v2's onto the name, preserving
        # the AUTOINCREMENT high-water mark at max(id) rather than resetting it.
        conn.execute("DROP TABLE rules")
        conn.execute("ALTER TABLE rules_v2 RENAME TO rules")
        conn.execute(_rule_targets_ddl("rule_targets", if_not_exists=False))
        conn.executemany(
            "INSERT INTO rule_targets (rule_id, connection_id, object_type, "
            "schema_pattern, name_pattern) VALUES (?, ?, ?, ?, ?)",
            [tuple(row) for row in targets],
        )
        conn.executescript(INDEXES)

        # Not ceremonial here, unlike in connections.db: this is the proof that every
        # target's denormalised connection_id and object_type line up with its rule's,
        # which is the invariant the composite foreign key exists to hold.
        broken = conn.execute("PRAGMA foreign_key_check").fetchall()
        if broken:
            raise RuntimeError(
                "The schema version 2 rebuild left a target whose connection or object "
                f"type does not match its rule ({len(broken)} row(s)); the change has "
                "been rolled back."
            )
        conn.commit()
    except Exception as exc:
        conn.rollback()
        # Written even here.  A rolled-back rebuild changed nothing, but the run that
        # failed is exactly the one whose account someone will want, and the record
        # already names the backup to restore from if the rollback itself is in doubt.
        record.write(
            f"The upgrade FAILED ({exc}) and was rolled back. Nothing above was kept; "
            "the database is as it was, and the backup named at the top is a copy of it."
        )
        raise
    finally:
        conn.execute("PRAGMA foreign_keys = ON")

    record.note(
        "%s rule(s) were moved to the version 2 shape, each keeping its single object "
        "and its exact action set. A rule can now be given further objects from the "
        "Permissions page.",
        len(targets),
        level=logging.INFO,
    )
    record.write("The upgrade completed and every change it made is listed above.")


def _migrate_2_to_3(conn: sqlite3.Connection) -> None:
    """Give ``rules`` the operator's own name for a rule.  An ALTER, not a rebuild.

    The rules list showed an object type, some patterns and an effect, and nothing on
    the row said what the rule was *for*.  Version 3 adds ``rule_name``.

    **Why this is one statement and not a twelve-step rebuild.**  The column is
    nullable, so every existing rule is already a valid version 3 row the moment the
    column exists: there is no value to compute, no row to rewrite and nothing to
    verify afterwards.  That was the point of ruling the field optional.  A rebuild
    would have been the same work as ``_migrate_1_to_2`` above, with the same risk to
    a file that costs the operator every rule they ever wrote, in exchange for a NOT
    NULL constraint that could only be satisfied by inventing a name for each of them
    — which is to say, by writing text into the operator's own rules list that the
    operator never wrote.  **Nothing is backfilled.**

    The backup is taken all the same, and that is not ceremony either.  It is the
    house promise that any automatic change to ``permissions.db`` leaves a copy of
    what was there first (``db_migrations.backup_before_rebuild``), and the operator
    reading ``permissions.db.v2.backup.log`` beside it should find the same kind of
    record for a cheap upgrade as for an expensive one — an upgrade that quietly
    skipped its own account because it judged itself safe is exactly the one nobody
    can check afterwards.

    The partial unique index is created *inside* this step rather than being left to
    ``executescript(SCHEMA)`` a moment later, so that a version 2 file cannot commit
    ``PRAGMA user_version = 3`` carrying the column without the uniqueness that gives
    it meaning.  A version 1 file reaches the index by the other road: the early
    return below skips this step entirely, and ``executescript(SCHEMA)`` supplies the
    index *after* the version has been bumped.  That is safe rather than merely
    lucky — the script runs on every open, before ``__init__`` returns and therefore
    before the store can accept a single write — but it is a different guarantee
    arriving from different code, and it is pinned separately by
    ``test_a_version_one_file_arrives_with_the_name_uniqueness_enforced_too``.

    Idempotent, like every step in the chain: a database whose ``rules`` table already
    has the column is left alone — which includes a file that has just come up from
    version 1, because ``_migrate_1_to_2`` rebuilds ``rules`` from the *current*
    ``_rules_ddl()`` and therefore hands this step a table already in the version 3
    shape — and so is a brand-new file, whose tables ``SCHEMA`` is about to create.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(rules)")}
    if not columns or "rule_name" in columns:
        return

    record = MigrationRecord(
        _MIGRATION_SUBJECT, user=current_user(), notes=_MIGRATION_NOTES_2_TO_3
    )
    # The sqlite3 driver's legacy implicit transaction must be closed before
    # VACUUM INTO, which SQLite refuses inside one, and before the BEGIN IMMEDIATE.
    conn.commit()
    backup_before_rebuild(conn, 3, record, subject=_MIGRATION_SUBJECT)

    try:
        conn.execute("BEGIN IMMEDIATE")
        # The CHECK is the shared _RULE_NAME_CHECK text, so the constraint a migrated
        # file carries is the same expression a fresh one carries. SQLite allows a
        # CHECK on ADD COLUMN; it does not allow UNIQUE, which is the other half of
        # why the uniqueness is an index rather than a column constraint.
        conn.execute(f"ALTER TABLE rules ADD COLUMN rule_name TEXT CHECK ({_RULE_NAME_CHECK})")
        conn.execute(UQ_RULES_NAME_PER_CONNECTION)
        conn.commit()
    except Exception as exc:
        conn.rollback()
        # Written even here, for the reason the version 2 step gives: the run that
        # failed is the one whose account someone will want, and the record already
        # names the backup to restore from if the rollback itself is in doubt.
        record.write(
            f"The upgrade FAILED ({exc}) and was rolled back. Nothing above was kept; "
            "the database is as it was, and the backup named at the top is a copy of it."
        )
        raise

    record.note(
        "A 'name' column was added to your %s rule(s). No rule was rewritten and no "
        "name was invented: every one of them is unnamed until you name it from the "
        "Permissions page.",
        conn.execute("SELECT count(*) FROM rules").fetchone()[0],
        level=logging.INFO,
    )
    record.write("The upgrade completed and every change it made is listed above.")


#: Version 3 -> 4 (ADR 0005).  Deliberately thin: unlike the two paragraphs above,
#: there is no widened structure to explain, only a column that stops holding a
#: value the application no longer honours.
_MIGRATION_NOTES_3_TO_4 = (
    (
        "No permission changed as a result of this upgrade, in either direction. "
        "'drop' and 'edit' were already refused for every rule, whatever its own "
        "can_drop / can_edit columns said -- see docs/adr/0005-drop-and-edit-are-"
        "never-granted.md. What changed is that the database stopped recording an "
        "authorisation the application does not honour."
    ),
)


def _migrate_3_to_4(conn: sqlite3.Connection) -> None:
    """Zero ``can_drop`` / ``can_edit`` on every rule that still carries either.

    ADR 0005: ``drop`` and ``edit`` can never be granted, and that is enforced in
    :meth:`PermissionStore.is_allowed` itself -- a hand-edited ``can_drop = 1`` is
    already inert the moment that check exists, so this migration adds no safety.
    What it buys is that ``permissions.db`` stops saying something untrue to the
    three readers that go straight to the columns instead of through
    ``is_allowed()``: :func:`format_rule`, the Permissions page's
    ``_object_covered()``, and whoever next opens the file in a SQLite browser to
    ask what a rule was allowed to do. **This is hygiene, not a second line of
    defence** -- see the ADR before changing that judgement.

    ``UPDATE ... WHERE can_drop = 1 OR can_edit = 1``, not a rebuild: there is no
    constraint to add and no column to remove, the same shape as
    :func:`_migrate_2_to_3` rather than :func:`_migrate_1_to_2`'s twelve steps.
    The predicate and the ``SET`` clause are both generated from
    ``FORBIDDEN_ACTIONS`` rather than typed out, so a third member added to that
    set on some later day is migrated here without this function needing an edit.

    ``created_at``, ``user_created``, ``updated_at`` and ``user_updated`` are not
    touched, for the reason :func:`_migrate_1_to_2` gives: no human edited these
    rules, and writing ``current_user()`` into ``user_updated`` would attribute a
    change to a person who did not make it.

    The :class:`MigrationRecord` names, by id and ``rule_name``, every rule this
    step touches -- not only the ones left granting nothing. A rule that keeps
    something is told exactly what it lost and what it kept (ADR 0005 §3's own
    worked example is the operator's rule 4, "Lectura": a ``table`` rule that
    loses ``drop`` and keeps ``create, delete, insert, list, read_structure,
    select, update``); the total count alone had left the operator with no way to
    tell which rule that was. A rule granting ``list, read_definition, edit``
    keeps two actions and is merely narrower than its author meant, which is a
    different sentence from a rule left granting nothing at all -- that is worth
    an operator's attention on its own, and it is named without being deleted --
    removing it would itself be a drop, and this ADR is the one place that word is
    not allowed to mean that. The criterion that tells the two apart -- the whole
    granted set was inside ``FORBIDDEN_ACTIONS``, not merely some of it -- is
    unchanged; only what each case is told has grown.

    Idempotent: a file with nothing set in either column -- including a version 3
    file that never carried the grant, and a brand-new file whose ``rules`` table
    does not exist yet -- is left alone; there is nothing to back up and nothing
    to record.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(rules)")}
    forbidden_columns = sorted(f"can_{a}" for a in FORBIDDEN_ACTIONS if f"can_{a}" in columns)
    if not columns or not forbidden_columns:
        return

    predicate = " OR ".join(f"{column} = 1" for column in forbidden_columns)
    affected = conn.execute(f"SELECT * FROM rules WHERE {predicate}").fetchall()
    if not affected:
        return

    record = MigrationRecord(
        _MIGRATION_SUBJECT, user=current_user(), notes=_MIGRATION_NOTES_3_TO_4
    )
    # The sqlite3 driver's legacy implicit transaction must be closed before
    # VACUUM INTO, which SQLite refuses inside one, and before the BEGIN IMMEDIATE.
    conn.commit()
    backup_before_rebuild(conn, 4, record, subject=_MIGRATION_SUBJECT)

    try:
        conn.execute("BEGIN IMMEDIATE")
        # What each affected rule granted has to be read BEFORE the UPDATE zeroes
        # it: this is the only moment "the whole granted set was forbidden" can be
        # told apart from "every can_* column is 0 now that this step has run",
        # which every affected row would satisfy afterwards regardless of what it
        # granted before. Kept per rule id, not just partitioned into emptied/kept,
        # because the per-rule note below (added after QA read the record against
        # the operator's own rule 4 and found only a total count -- the ADR's own
        # worked example, "it is a table rule, so it loses drop and keeps create,
        # delete, insert, list, read_structure, select, update", was nowhere in the
        # file) needs each row's own granted set to say what it lost and what it kept.
        granted_before = {
            row["id"]: {a for a in ALL_ACTIONS if f"can_{a}" in columns and row[f"can_{a}"]}
            for row in affected
        }

        set_clause = ", ".join(f"{column} = 0" for column in forbidden_columns)
        conn.execute(f"UPDATE rules SET {set_clause} WHERE {predicate}")
        conn.commit()
    except Exception as exc:
        conn.rollback()
        # Written even here, for the reason the earlier steps give: the run that
        # failed is the one whose account someone will want, and the record
        # already names the backup to restore from if the rollback itself is in
        # doubt.
        record.write(
            f"The upgrade FAILED ({exc}) and was rolled back. Nothing above was kept; "
            "the database is as it was, and the backup named at the top is a copy of it."
        )
        raise

    record.note(
        "%s rule(s) had 'drop' and/or 'edit' cleared from their granted actions. "
        "Neither was ever actually usable through d-MCP -- both are refused "
        "regardless of a rule's own columns -- so nothing you could do through "
        "d-MCP has changed.",
        len(affected),
        level=logging.INFO,
    )
    # One line per affected rule, named by id and rule_name, so the operator does
    # not have to guess which rule the count above refers to or what became of it.
    # The criterion is unchanged from before this fix -- "the whole granted set was
    # forbidden" (nothing left) versus "some of it survives" -- only what is
    # reported for each case differs: a narrowed rule is told what it lost and what
    # it kept (ADR 0005 §3's own example, for rule 4 "Lectura": a table rule that
    # loses 'drop' and keeps 'create, delete, insert, list, read_structure, select,
    # update'); an emptied rule is told plainly that it now grants nothing.
    for row in affected:
        granted = granted_before[row["id"]]
        name = row["rule_name"] or "unnamed"
        kept = sorted(granted - FORBIDDEN_ACTIONS)
        if kept:
            record.note(
                "Rule %s (%s) is a '%s' rule; it loses '%s' and keeps '%s'.",
                row["id"],
                name,
                row["object_type"],
                ", ".join(sorted(granted & FORBIDDEN_ACTIONS)),
                ", ".join(kept),
                level=logging.INFO,
            )
        else:
            record.note(
                "Rule %s (%s) granted only 'drop' and/or 'edit', and now grants "
                "nothing at all. It has not been deleted -- give it other actions, "
                "or remove it yourself, from the Permissions page.",
                row["id"],
                name,
                level=logging.WARNING,
            )
    record.write("The upgrade completed and every change it made is listed above.")


#: One entry per version step, applied in ascending order, each idempotent and each
#: committed before the next.  The key is the version the step *produces*.
_MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    2: _migrate_1_to_2,
    3: _migrate_2_to_3,
    4: _migrate_3_to_4,
}

# A live incident, not a hypothetical: SCHEMA_VERSION was bumped to 4 in this file
# before _migrate_3_to_4 existed and _MIGRATIONS still ended at 3. Every open of
# the operator's own permissions.db in that window ran _migrate()'s step loop —
# which does nothing beyond 3, because there was no 4: entry to run — and then
# hit the unconditional `PRAGMA user_version = SCHEMA_VERSION` that used to close
# this function, which stamped the file as version 4 anyway. That PRAGMA is gone
# (see _migrate() below); this assertion is the other half of closing the hole.
# It must fail at *import*, not at the first operator's file: a build that raises
# here never starts, so it cannot silently stamp anyone's database with a version
# whose migration it does not carry. A plain `assert` was rejected on purpose —
# `python -O` strips it, and a check that exists to catch a silent failure must
# not itself have a silent way to be switched off.
if max(_MIGRATIONS) != SCHEMA_VERSION:
    raise RuntimeError(
        f"SCHEMA_VERSION is {SCHEMA_VERSION} but _MIGRATIONS' highest step is "
        f"{max(_MIGRATIONS)}; a step is missing. This must be fixed before the "
        "application runs at all -- _migrate() no longer trusts SCHEMA_VERSION "
        "to mean 'a version this build knows how to reach', precisely because a "
        "mismatch here once stamped a real permissions.db as a version whose "
        "migration had never run (see _migrate())."
    )



# ---------------------------------------------------------------------------
# Pattern grammar and specificity (DESIGN-PERMISSIONS.md §2)
# ---------------------------------------------------------------------------


def _validate_pattern(value: str, label: str) -> str:
    """Enforce the same grammar as ``ck_rules_schema_pattern`` / ``ck_rules_name_pattern``.

    A literal, a literal followed by exactly one trailing ``*``, or a bare ``*``.
    Checked here too, in Python, so ``grant()``/``deny()`` reject a bad pattern with a
    sentence rather than a bare ``sqlite3.IntegrityError`` from the CHECK — the same
    division of labour ``connection_store.py`` uses.
    """
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{label} must be a non-empty string")
    idx = value.find("*")
    if idx not in (-1, len(value) - 1):
        raise ValueError(
            f"{label} {value!r} is not a valid pattern: only an exact literal, a "
            "'prefix*' wildcard or a bare '*' are allowed — no infix or suffix "
            "wildcard, no regular expression (DESIGN-PERMISSIONS.md §2.1)"
        )
    return value


def _validate_rule_name(value: str | None) -> str | None:
    """Normalise and check the operator's own name for a rule.  ``None`` means unnamed.

    **There is exactly one spelling of "no name", and it is ``None`` / SQL NULL.**  An
    empty string is folded to it rather than stored, because the GUI's line edit hands
    back ``''`` for a field nobody touched and a column carrying both would have two
    values that mean the same thing under a UNIQUE index that cannot see they do.  A
    string that is not empty but *strips* to empty — ``'   '`` — is refused instead of
    folded: it is a name the operator typed and would then see vanish, which is the
    kind of silent normalisation this module refuses everywhere else (§5.4).

    The stripped text is what gets stored, and what the length is measured against.
    Storing ``'  Sales  '`` verbatim would let it sit in the list beside ``'Sales'``
    looking identical while the unique index, which compares the raw text, saw two
    different names — the uniqueness would then not mean what the operator reads.

    Control characters are refused for a plain rendering reason: the name is shown as
    one cell of one row, and a name carrying a newline would break that line in the
    Permissions page and in ``show-permissions`` alike.  This subsumes the null byte,
    which SQLite would store and several C string APIs would truncate at.

    Raises:
        ValueError: with the same voice the rest of this store uses for bad input, so
            the GUI can put ``str(exc)`` straight into a message box.
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"rule_name must be a string or None, got {type(value).__name__}")
    if value == "":
        return None
    name = value.strip()
    if not name:
        raise ValueError(
            "rule_name cannot be only whitespace; leave it empty to give the rule no name"
        )
    if any(character < " " or character == "\x7f" for character in name):
        raise ValueError(
            "rule_name cannot contain control characters (including tabs and line "
            "breaks): it is shown as a single line in the rules list"
        )
    if len(name) > MAX_RULE_NAME_LENGTH:
        raise ValueError(
            f"rule_name must be at most {MAX_RULE_NAME_LENGTH} characters, but "
            f"{name!r} is {len(name)}; it labels a rule in the list, so it is a name "
            "rather than a description"
        )
    return name


def _specificity(pattern: str) -> tuple[int, int]:
    """``spec(p)`` from DESIGN-PERMISSIONS.md §2.2.

    ``(2, len(p))`` for an exact literal, ``(1, len(p) - 1)`` for ``prefix*`` scored
    by prefix length, ``(0, 0)`` for the bare wildcard. Compared as an ordinary tuple,
    so an exact match always beats every prefix, which always beats the wildcard.
    """
    if pattern == "*":
        return (0, 0)
    if pattern.endswith("*"):
        return (1, len(pattern) - 1)
    return (2, len(pattern))


def _glob_match(pattern: str, value: str | None) -> bool:
    """Does ``pattern`` match ``value``, under the three-form grammar of §2.1?

    ``value`` may be ``None`` — SQLite has no schema layer, so a table's
    ``key_schema`` is legitimately absent (DESIGN-DIALECTS.md, ``ObjectRef.schema``).
    Only the bare wildcard can match "no schema": there is nothing for an exact or
    prefix pattern to compare literal text against, so a rule that names a schema
    can never accidentally reach a SQLite object, and one that means "everywhere"
    has to say so with ``*``.
    """
    if pattern == "*":
        return True
    if value is None:
        return False
    if pattern.endswith("*"):
        return value.startswith(pattern[:-1])
    return value == pattern


# ---------------------------------------------------------------------------
# Identifier validation (DESIGN-PERMISSIONS.md §5.4) — fail closed, never guess
# ---------------------------------------------------------------------------


def _validate_component(label: str, value: str | None, *, allow_none: bool) -> None:
    """One piece of a ``NormalisedRef`` — raises exactly the way §5.4 requires.

    Not fully qualified, a wildcard character, a null byte, or an empty component
    all raise ``ValueError`` here rather than being guessed at or silently denied:
    a silent normalisation is the same bug reaching production as a permission hole
    (this mirrors f-MCP's ``rule_for()`` refusing a non-absolute path).
    """
    if value is None:
        if allow_none:
            return
        raise ValueError(
            f"{label} is missing: the identifier is not fully qualified (DESIGN-PERMISSIONS.md §5.4)"
        )
    if not isinstance(value, str) or value == "":
        raise ValueError(f"{label} is empty; every identifier component must be non-empty")
    if "\x00" in value:
        raise ValueError(f"{label} contains a null byte")
    if "*" in value:
        raise ValueError(
            f"{label} {value!r} contains a wildcard character; an object reference is "
            "never a pattern"
        )


def _validate_ref(ref: NormalisedRef) -> None:
    """Fail closed on anything malformed, per DESIGN-PERMISSIONS.md §5.4.

    Only a ``NormalisedRef`` is accepted — never a bare string, never a raw
    ``ObjectRef`` — because that is what turns "someone forgot to normalise" into a
    type error caught in review rather than a permission hole caught in production.
    """
    if not isinstance(ref, NormalisedRef):
        raise ValueError(
            f"expected a NormalisedRef, got {type(ref).__name__}; the resolver never "
            "accepts a bare string or a raw ObjectRef"
        )
    _validate_component("key_name", ref.key_name, allow_none=False)
    _validate_component("canonical_name", ref.canonical_name, allow_none=False)
    # SQLite has no schema layer, so both spellings are legitimately None there
    # (DESIGN-DIALECTS.md, ObjectRef.schema) — but they must agree with each other;
    # one present and the other absent is a malformed NormalisedRef, not a case this
    # resolver can make a security decision about.
    if (ref.key_schema is None) != (ref.canonical_schema is None):
        raise ValueError(
            "key_schema and canonical_schema disagree on whether a schema exists "
            f"(key_schema={ref.key_schema!r}, canonical_schema={ref.canonical_schema!r}); "
            "this is a malformed NormalisedRef"
        )
    _validate_component("key_schema", ref.key_schema, allow_none=True)
    _validate_component("canonical_schema", ref.canonical_schema, allow_none=True)


def _validate_action(action: str, object_type: str) -> None:
    """``ValueError`` if ``action`` is not in ``object_type``'s own tuple.

    Actions do not merely differ in *count* between object types — ``select`` on a
    ``function`` is meaningless — so this is a correctness check, not a courtesy.
    """
    if object_type not in ACTIONS_BY_TYPE:
        raise ValueError(f"unknown object_type {object_type!r}; expected one of {', '.join(OBJECT_TYPES)}")
    if action not in ACTIONS_BY_TYPE[object_type]:
        raise ValueError(
            f"{action!r} is not a valid action for {object_type!r}; "
            f"expected one of {', '.join(ACTIONS_BY_TYPE[object_type])}"
        )


def _qualified(ref: NormalisedRef) -> str:
    """The canonical spelling for a denial message — never the key spelling.

    §5.3: the audit trail and every message show the object as the server's own
    catalogue names it, not the folded form the resolver happened to compare.
    """
    if ref.canonical_schema is None:
        return ref.canonical_name
    return f"{ref.canonical_schema}.{ref.canonical_name}"


def _denial_message(action: str, ref: NormalisedRef, rule: dict[str, Any] | None) -> str:
    """Format matching f-MCP's, per DESIGN-PERMISSIONS.md §7.1.

    The matched rule is always cited, because the operator's next question is
    invariably *which rule did that* — distinguishing "no rule" from a matched allow
    lacking the tick from an explicit deny is what makes this actionable.
    """
    # A database-scoped action is not "on" an object; naming one would read as though a
    # table called Sales had been refused. §5.6.
    if str(ref.object_type) == DATABASE_TYPE:
        target = f"database {ref.canonical_name}" if ref.canonical_name else "this database"
        rule_desc = "the database rule"
    else:
        target = _qualified(ref)
        rule_desc = ""
    if rule is None:
        return f"'{action}' is not permitted on {target} (no rule)"
    if not rule_desc:
        rule_desc = f"{rule['schema_pattern']}.{rule['name_pattern']}"
    if rule["is_deny"]:
        return f"'{action}' is not permitted on {target} (rule: {rule_desc}, explicit deny)"
    return f"'{action}' is not permitted on {target} (rule: {rule_desc})"


def _forbidden_message(action: str, ref: NormalisedRef) -> str:
    """Format the denial of a ``FORBIDDEN_ACTIONS`` member (ADR 0005 §4).

    Keeps ``_denial_message()``'s grammar — the same
    ``'{action}' is not permitted on {qualified}`` prefix —
    so an operator's grep and the Logs page read alike for every denial, allowed or
    forbidden. The parenthetical is the part that differs, and it must not contain
    the substring ``no rule``: that phrase belongs to default-deny and means "write
    a rule and this will work" — for ``drop`` and ``edit`` it never will, and saying
    so plainly (``no permission rule can authorise it``) is the whole point of a
    wording that does not contain the shorter phrase.

    Deliberately takes no ``rule`` argument, unlike :func:`_denial_message`: by the
    time this is called, ``require()`` has not looked one up, because no rule
    decided anything and none should be cited by accident.
    """
    # drop and edit never reach a `database` object (ACTIONS_BY_TYPE has neither for
    # that type), but the same "not 'on' an object" phrasing as _denial_message is
    # kept here rather than assumed unreachable, so this function still reads
    # correctly if that ever changes.
    if str(ref.object_type) == DATABASE_TYPE:  # pragma: no cover - unreachable while ACTIONS_BY_TYPE stands
        target = f"database {ref.canonical_name}" if ref.canonical_name else "this database"
    else:
        target = _qualified(ref)
    return (
        f"'{action}' is not permitted on {target} "
        f"(forbidden by d-MCP: {_FORBIDDEN_REASON[action]}; no permission rule can authorise it)"
    )


def _targets_of(rule: dict[str, Any]) -> list[dict[str, str]]:
    """The objects a rule row names, whichever of the two row shapes it is.

    ``rules()`` attaches a ``targets`` list to every row.  ``rule_for()`` returns one
    joined row carrying the single target that *matched*, because that is what the
    denial message must cite.  Both reach :func:`format_rule`, so rather than letting
    the second shape ``KeyError`` the first time somebody renders a resolver row, the
    difference is settled here, once, and stated.
    """
    targets = rule.get("targets")
    if targets is not None:
        return [
            {"schema_pattern": t["schema_pattern"], "name_pattern": t["name_pattern"]}
            for t in targets
        ]
    return [{"schema_pattern": rule["schema_pattern"], "name_pattern": rule["name_pattern"]}]


def format_rule(rule: dict[str, Any]) -> dict[str, Any]:
    """Render one rule for a human or an LLM to read.

    Since schema version 2 a rule names a *collection*, so the two scalar
    ``schema_pattern`` / ``name_pattern`` keys are gone and ``targets`` carries the
    list.  No single-target alias is kept beside it on purpose: a scalar holding "the
    first target" would be a half-truth about a rule's reach, and a half-truth is
    worse for an LLM deciding what it may touch than a changed shape it must read
    properly.

    The single source of truth for "what does a rule look like from outside": the
    ``show-permissions`` MCP tool (``mcp_server.py``) and ``main.py``'s
    ``--show-permissions`` flag both build their output by calling this on every row
    ``rules()`` returns, rather than each re-deriving ``allowed_actions`` from the
    ``can_*`` columns independently — which is exactly how f-MCP's flat
    ``",".join(a for a in ACTIONS if rule[f"can_{a}"])`` and its GUI checkbox grid
    would have drifted apart, had f-MCP had two callers asking the same question.

    ``allowed_actions`` excludes ``FORBIDDEN_ACTIONS`` even where the row's own
    ``can_drop`` / ``can_edit`` column is still ``1`` — a rule migrated before
    schema version 4, or hand-edited directly in a SQLite browser (ADR 0005 §2).
    Reporting either here would tell an LLM asking ``show-permissions`` that it may
    drop an object or replace a routine body when :meth:`PermissionStore.require`
    will refuse the attempt outright; the two must never disagree about what a
    rule can actually do.
    """
    object_type = str(rule["object_type"])
    return {
        # First, because it is what a human reads first: the operator's own answer to
        # "what is this rule for". ``.get`` rather than ``[]`` so a row dict built by
        # an older caller, or hand-assembled in a test, still renders — an absent name
        # and no name are the same thing, and neither is worth a KeyError.
        "rule_name": rule.get("rule_name"),
        "object_type": object_type,
        "targets": _targets_of(rule),
        "is_deny": bool(rule["is_deny"]),
        "allowed_actions": [
            action
            for action in ACTIONS_BY_TYPE.get(object_type, ())
            if action not in FORBIDDEN_ACTIONS
            and not rule["is_deny"]
            and rule.get(f"can_{action}")
        ],
        "created_at": rule["created_at"],
        "user_created": rule["user_created"],
        "updated_at": rule["updated_at"],
        "user_updated": rule["user_updated"],
    }


def database_scope_ref(database_name: str) -> NormalisedRef:
    """The reference used to check a connection-scoped action (§5.6).

    Exists so the GUI, the MCP tool layer and the tests all build the same thing. The name is
    carried only so a denial can say which database was refused; the resolver never compares
    it, because a `database` rule is resolved by connection alone.
    """

    return NormalisedRef(
        canonical_schema=None,
        canonical_name=database_name,
        key_schema=None,
        key_name=database_name,
        object_type=ObjectType.DATABASE,
    )


def _database_scope_patterns(object_type: str, schema_pattern: str, name_pattern: str) -> tuple[str, str]:
    """Force '*'/'*' on a `database` rule, which is scoped to the connection (§5.6).

    Silently rewriting a caller's patterns would normally be wrong, but here any other value
    is meaningless rather than merely unusual: the resolver never compares them for this
    object type, so a rule stored as `dbo`/`Sales` would read as if it were scoped when it
    is not. Normalising on write keeps the table honest about what it actually enforces.
    """

    if object_type != DATABASE_TYPE:
        return schema_pattern, name_pattern
    return "*", "*"


class PermissionStore:
    """Rule storage and resolution for ``permissions.db``.

    Default-deny: an empty store authorises nothing, and no rules are ever seeded.
    The most specific matching rule wins wholesale — allow or deny alike — with no
    merging of action sets across rules (DESIGN-PERMISSIONS.md §2–§3).
    """

    def __init__(self, db_path: str | os.PathLike[str] | None = None, user: str | None = None) -> None:
        self.db_path = Path(db_path).expanduser() if db_path is not None else default_db_path()
        self.user = user or current_user()

        # Nothing is created at import time; the file appears here, on the first
        # construction of a store (DESIGN-DATA-MODEL.md §8 step 4).
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._apply_pragmas()

        # Read the version *before* anything else runs: after executescript a fresh
        # file is indistinguishable from a current one.
        existing_version = int(self.conn.execute("PRAGMA user_version").fetchone()[0])

        # The chain runs BEFORE the schema script, which is the opposite of
        # connection_store's order and is not a style choice. Version 2 adds a second
        # table whose foreign key names `rules`; running executescript first would
        # create `rule_targets` against the version 1 `rules`, which has no
        # uq_rules_identity for that key to reference, and the rebuild would then be
        # working around a table it was supposed to create. After the chain,
        # executescript is a no-op on a migrated file and creates everything on a
        # fresh one.
        self._migrate(existing_version)
        self.conn.executescript(SCHEMA)
        self.conn.commit()
        self._migrate_schema()

    # -- lifecycle ---------------------------------------------------------

    def _apply_pragmas(self) -> None:
        """DESIGN-DATA-MODEL.md §6, applied on every open and before the first CREATE."""
        self.conn.execute("PRAGMA busy_timeout = 5000")
        mode = self.conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            # Some network mounts have no shared-memory locking and silently fall
            # back to 'delete', which would quietly break the GUI/server
            # cross-process design rather than fail.
            raise RuntimeError(
                f"Cannot enable WAL journalling on {self.db_path}: SQLite reported "
                f"journal_mode={mode!r}. The d-MCP GUI and MCP server read this file "
                "concurrently and need WAL. Move the databases off the network share, "
                "or set DMCP_DB_DIR to a local directory."
            )
        # FULL, not NORMAL: losing the last transaction fails *closed* if it was a
        # grant (the grant simply did not happen) but fails **open** if it was a
        # revoke (the operator revoked access, the machine lost power, and on
        # restart the access is back). A security store must not have a failure
        # mode that silently restores a withdrawn permission (DESIGN-DATA-MODEL.md §6).
        self.conn.execute("PRAGMA synchronous = FULL")
        # Verified rather than merely asked for, the way WAL is above. A SQLite built
        # without foreign key support accepts this statement, sets nothing and reports
        # 0 -- which was harmless while this file declared no foreign key, and is not
        # now: rule_targets' composite key to rules(id, connection_id, object_type) is
        # what stops a target's denormalised connection_id and object_type drifting
        # away from its rule's, and a drifted target is a rule applied to the wrong
        # connection.
        self.conn.execute("PRAGMA foreign_keys = ON")
        enforced = self.conn.execute("PRAGMA foreign_keys").fetchone()
        if not enforced or not int(enforced[0]):
            raise RuntimeError(
                f"Cannot enable foreign key enforcement on {self.db_path}: SQLite "
                "reported foreign_keys=0. This build of SQLite was compiled without "
                "foreign key support, and d-MCP relies on it to keep a permission "
                "rule's targets attached to the right connection. Use a standard "
                "CPython build rather than letting rules resolve unchecked."
            )

    def _migrate(self, existing_version: int) -> None:
        """The ``user_version`` hook: run the step chain, bump a fresh file, refuse a newer one.

        The version is read in ``__init__`` *before* this runs and before
        ``executescript(SCHEMA)``, which is the ordering that makes any of this
        possible: once the script has run, a fresh file is indistinguishable from a
        current one, and ``CREATE TABLE IF NOT EXISTS`` is a silent no-op against the
        version 1 table.

        **Seals the file with the last version the loop below actually applied,
        never with ``SCHEMA_VERSION`` directly.** This used to close with an
        unconditional ``PRAGMA user_version = SCHEMA_VERSION`` after the loop, on
        the reasoning that a fresh file or a file whose remaining steps were all
        no-ops still needed the version set. That line is exactly what turned a
        one-line mistake into a corrupted permissions.db: for a window during
        this ADR's development, ``SCHEMA_VERSION`` read ``4`` while ``_MIGRATIONS``
        still ended at ``3``, and every open of the operator's own file ran the
        loop — which advanced nothing, because there was no ``4:`` entry to run —
        and then hit this line, which stamped the file as version 4 regardless.
        The next open took the early return above, forever, with
        ``_migrate_3_to_4`` never having run and never going to. The module-level
        check beside ``_MIGRATIONS`` now makes that particular mismatch fail at
        import, but this function does not lean on that guarantee a second time:
        tracking and sealing with ``applied`` means a file can never claim a
        version whose step did not execute against it, whatever this module's
        other invariants do or do not hold at the time.
        """
        if existing_version > SCHEMA_VERSION:
            raise RuntimeError(
                f"{self.db_path} was written by a newer version of SAPÉ d-MCP "
                f"(schema {existing_version}, this build understands {SCHEMA_VERSION}). "
                "Upgrade the application rather than letting an older build mis-read it."
            )
        if existing_version >= SCHEMA_VERSION:
            return

        applied = existing_version
        # One step per version, each idempotent, each committed before the next.
        for version in sorted(_MIGRATIONS):
            if version <= existing_version:
                continue
            _MIGRATIONS[version](self.conn)
            applied = version
            self.conn.execute(f"PRAGMA user_version = {version}")
            self.conn.commit()

        # Redundant with the loop's own last write in the ordinary case -- it is
        # what actually seals a fresh file, or one whose remaining steps were all
        # no-ops, so the next open takes the early return above -- but it writes
        # `applied`, the version the loop actually reached, and not the
        # `SCHEMA_VERSION` constant. See the docstring above for why that
        # difference is load-bearing rather than cosmetic.
        self.conn.execute(f"PRAGMA user_version = {applied}")
        self.conn.commit()

    def _migrate_schema(self) -> None:
        """Add a ``can_*`` column for any action in ``ALL_ACTIONS`` the table lacks.

        ``PRAGMA table_info`` diffed against the tuple, ported from f-MCP's
        ``_migrate_schema()``: adding an action to ``ACTIONS_BY_TYPE`` is then the
        only edit needed anywhere, and an older file catches up automatically the
        next time it is opened. Removing an action is deliberately *not* automatic
        (DESIGN-DATA-MODEL.md §4.5) — the column stays, so a stale grant is never
        silently forgotten.
        """
        existing = {row[1] for row in self.conn.execute("PRAGMA table_info(rules)")}
        missing = sorted(f"can_{a}" for a in ALL_ACTIONS if f"can_{a}" not in existing)
        for column in missing:
            try:
                self.conn.execute(f"ALTER TABLE rules ADD COLUMN {column} INTEGER NOT NULL DEFAULT 0")
                self.conn.commit()
            except sqlite3.OperationalError as exc:
                # SQLite's own wording is "attempt to write a readonly database" — no
                # hyphen — so a literal "read-only" search (f-MCP's original spelling,
                # copied into connection_store.py too) never matches and this branch
                # would silently fall through to the bare `raise` below, losing the
                # actionable message §4.5 promises. Stripping hyphens before the
                # search catches both spellings regardless of which one a future
                # SQLite build uses.
                if "readonly" in str(exc).lower().replace("-", ""):
                    raise RuntimeError(
                        f"Cannot migrate {self.db_path}: the database is read-only. "
                        "Check the file permissions."
                    ) from exc
                raise
            logger.info("Added missing column %s to rules", column)

    def close(self) -> None:
        """Close the SQLite handle. Safe to call twice."""
        try:
            self.conn.close()
        except Exception:  # pragma: no cover - closing twice, or already gone
            logger.debug("permissions.db was already closed", exc_info=True)

    def __enter__(self) -> PermissionStore:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # -- writes --------------------------------------------------------------

    def create_rule(
        self,
        connection_id: int,
        object_type: str,
        targets: Sequence[tuple[str, str]],
        actions: Sequence[str] | str = "all",
        *,
        is_deny: bool = False,
        rule_name: str | None = None,
    ) -> int:
        """Write one rule over a *collection* of objects.  Returns its id.

        This is the primitive schema version 2 exists for: ``targets`` is a sequence
        of ``(schema_pattern, name_pattern)`` pairs, each under the three-form grammar
        of §2.1, and the rule's single action set applies to all of them.  Five tables
        with nothing in common but the operator's intention are now one rule rather
        than five that have to be kept in step by hand.

        One object type per rule, because action sets differ per type and a mixed rule
        would have no coherent set of ``can_*`` columns to interpret — the same reason
        DESIGN-DATA-MODEL.md §4.2 gives for there being no ``object_type = '*'``.

        A target may belong to only one rule per connection and object type
        (``uq_rule_targets_key``).  That is not a storage detail: it is what keeps the
        specificity ordering provably total (DESIGN-PERMISSIONS.md §2.4).  A collision
        is therefore reported as the operator's own contradiction — two rules claiming
        the same object — rather than as a bare ``IntegrityError``.

        Args:
            rule_name: The operator's own label for the rule, shown in the rules list
                so the row says what it is *for*.  Optional: ``None`` or ``''`` both
                store NULL and the rule stays unnamed.  A name that is set must be
                unique within ``connection_id``, case-insensitively, and a collision
                raises ``ValueError`` naming the rule that already holds it — never a
                bare ``sqlite3.IntegrityError``.  It is metadata and nothing else: no
                part of resolution ever reads it.
        """
        connection_id = self._validate_connection_id(connection_id)
        targets = self._validate_targets(object_type, targets)
        granted = self._validate_actions(object_type, actions, is_deny=is_deny)
        rule_name = _validate_rule_name(rule_name)

        now = _now()
        can_columns = ", ".join(f"can_{a}" for a in ALL_ACTIONS)
        can_placeholders = ", ".join("?" for _ in ALL_ACTIONS)
        try:
            cursor = self.conn.execute(
                f"""
                INSERT INTO rules
                    (connection_id, object_type, is_deny, rule_name, {can_columns},
                     created_at, user_created, updated_at, user_updated)
                VALUES (?, ?, ?, ?, {can_placeholders}, ?, ?, ?, ?)
                """,
                [
                    connection_id, object_type, int(is_deny), rule_name,
                    *[int(a in granted) for a in ALL_ACTIONS],
                    now, self.user, now, self.user,
                ],
            )
            rule_id = int(cursor.lastrowid or 0)
            self._write_targets(rule_id, connection_id, object_type, targets)
        except sqlite3.IntegrityError as exc:
            self.conn.rollback()
            raise ValueError(
                self._integrity_message(
                    connection_id, object_type, targets, exc, rule_name=rule_name
                )
            ) from None
        self.conn.commit()
        logger.info(
            "Rule %s %s %s on %s target(s) for connection %s",
            rule_id,
            "denies" if is_deny else "grants",
            sorted(granted) or "(nothing)",
            len(targets),
            connection_id,
        )
        return rule_id

    def update_rule(
        self,
        rule_id: int,
        targets: Sequence[tuple[str, str]],
        actions: Sequence[str] | str = "all",
        *,
        is_deny: bool = False,
        rule_name: str | None = None,
    ) -> None:
        """Replace a rule's targets, its action set *and* its name, all wholesale.

        Never merges with what was there before, for the reason ``grant()`` never did:
        the GUI's edit dialog always sends the complete state, and a caller that meant
        to add one object or one action to an existing rule would otherwise depend
        silently on what this method happened to do last time.

        This is also what makes a rule's reach editable at all.  Under version 1 the
        rule *was* its target, so the dialog had to freeze schema, type and name once
        a rule existed; addressed by ``rule_id``, a rule can now be given objects and
        have them taken away.

        ``connection_id`` and ``object_type`` are fixed at creation.  They are
        denormalised into every target row, and the composite foreign key's implicit
        ``ON UPDATE NO ACTION`` would reject the parent change in any case; delete the
        rule and write another rather than looking for a way round that.

        Args:
            rule_name: The rule's name **after** this call, not a name to add.
                Omitting it leaves the rule unnamed, exactly as omitting an action
                leaves it ungranted: every caller of this method sends the rule's
                complete state, and a parameter that silently kept whatever was there
                before would make the result depend on what the last caller happened
                to do.  An edit dialog must therefore put the current name back.
                :meth:`grant` and :meth:`deny` are the exception and say so — they
                upsert one action set, not a whole rule, so they carry the existing
                name across themselves.
        """
        rule_id = self._validate_rule_id(rule_id)
        row = self.conn.execute(
            "SELECT connection_id, object_type FROM rules WHERE id = ?", (rule_id,)
        ).fetchone()
        if row is None:
            raise ValueError(f"there is no rule {rule_id}")
        connection_id, object_type = int(row["connection_id"]), str(row["object_type"])

        targets = self._validate_targets(object_type, targets)
        granted = self._validate_actions(object_type, actions, is_deny=is_deny)
        rule_name = _validate_rule_name(rule_name)

        now = _now()
        can_updates = ", ".join(f"can_{a} = ?" for a in ALL_ACTIONS)
        try:
            # created_at / user_created are deliberately absent: an update never
            # disturbs who first wrote the rule, which is f-MCP's upsert discipline.
            self.conn.execute(
                f"UPDATE rules SET is_deny = ?, rule_name = ?, {can_updates}, "
                "updated_at = ?, user_updated = ? WHERE id = ?",
                [
                    int(is_deny), rule_name,
                    *[int(a in granted) for a in ALL_ACTIONS],
                    now, self.user, rule_id,
                ],
            )
            self.conn.execute("DELETE FROM rule_targets WHERE rule_id = ?", (rule_id,))
            self._write_targets(rule_id, connection_id, object_type, targets)
        except sqlite3.IntegrityError as exc:
            self.conn.rollback()
            raise ValueError(
                self._integrity_message(
                    connection_id, object_type, targets, exc,
                    rule_name=rule_name, rule_id=rule_id,
                )
            ) from None
        self.conn.commit()
        logger.info(
            "Rule %s now %s %s on %s target(s)",
            rule_id,
            "denies" if is_deny else "grants",
            sorted(granted) or "(nothing)",
            len(targets),
        )

    def delete_rule(self, rule_id: int) -> bool:
        """Delete a rule and every target it names.  ``False`` if it was not there."""
        rule_id = self._validate_rule_id(rule_id)
        # Explicit rather than left to ON DELETE CASCADE. The cascade does fire — the
        # pragma is asserted and verified on every open — but an orphaned target would
        # collide with a later create_rule() on uq_rule_targets_key and read as a
        # phantom conflict with a rule that no longer exists, so the sweep does not
        # depend on a pragma being on in some future caller's connection.
        self.conn.execute("DELETE FROM rule_targets WHERE rule_id = ?", (rule_id,))
        cursor = self.conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
        self.conn.commit()
        return cursor.rowcount > 0

    def targets_for(self, rule_id: int) -> list[dict[str, Any]]:
        """One rule's targets, in a deterministic order the GUI can render."""
        rows = self.conn.execute(
            "SELECT schema_pattern, name_pattern FROM rule_targets WHERE rule_id = ? "
            "ORDER BY schema_pattern, name_pattern",
            (self._validate_rule_id(rule_id),),
        ).fetchall()
        return [dict(row) for row in rows]

    def _write_targets(
        self,
        rule_id: int,
        connection_id: int,
        object_type: str,
        targets: Sequence[tuple[str, str]],
    ) -> None:
        """Insert a rule's target rows, denormalising the parent's two key columns."""
        self.conn.executemany(
            "INSERT INTO rule_targets (rule_id, connection_id, object_type, "
            "schema_pattern, name_pattern) VALUES (?, ?, ?, ?, ?)",
            [(rule_id, connection_id, object_type, schema, name) for schema, name in targets],
        )

    def _integrity_message(
        self,
        connection_id: int,
        object_type: str,
        targets: Sequence[tuple[str, str]],
        exc: sqlite3.IntegrityError,
        *,
        rule_name: str | None = None,
        rule_id: int | None = None,
    ) -> str:
        """Turn a UNIQUE violation into the sentence the operator needs.

        Two collisions are reachable through this API — a target already claimed by
        another rule, and a name already worn by another rule on this connection — and
        for both the operator's next question is *which one*, so the message names it
        rather than leaving them to read the rule list looking.  Anything that reached
        here without matching either is reported with SQLite's own text, which is worse
        than a sentence but far better than a caller catching nothing.

        The name is checked first, because it is the cheaper query and because a call
        that collides on both should say the thing the operator most recently typed.
        """
        if rule_name is not None:
            # COLLATE NOCASE here or the lookup would miss exactly the collision
            # uq_rules_name_per_connection just raised on, and the message would fall
            # through to the raw IntegrityError.
            parameters: list[Any] = [connection_id, rule_name]
            clause = (
                "SELECT id, rule_name FROM rules "
                "WHERE connection_id = ? AND rule_name = ? COLLATE NOCASE"
            )
            if rule_id is not None:
                clause += " AND id <> ?"
                parameters.append(rule_id)
            owner = self.conn.execute(clause, parameters).fetchone()
            if owner is not None:
                # The OWNER's spelling, not the one just attempted: 'SALES' colliding
                # with 'Sales' is the case the sentence below has to explain, and a
                # message quoting back what the operator typed explains nothing.
                return (
                    f"rule #{owner['id']} on this connection is already called "
                    f"{owner['rule_name']!r}. A rule's name has to be unique within its "
                    "connection — upper and lower case count as the same name — "
                    "because it is what tells the two rules apart in the list. "
                    "Choose another name, or leave the name empty."
                )

        for schema, name in targets:
            owner = self.conn.execute(
                "SELECT rule_id FROM rule_targets WHERE connection_id = ? AND "
                "object_type = ? AND schema_pattern = ? AND name_pattern = ?",
                (connection_id, object_type, schema, name),
            ).fetchone()
            if owner is not None:
                return (
                    f"{schema}.{name} is already named by rule #{owner['rule_id']}. A "
                    f"{object_type} can be named by only one rule per connection, "
                    "because two rules claiming the same object would have no defined "
                    "order between them. Edit that rule, or remove the object from it "
                    "first."
                )
        return f"the rule was rejected by the database: {exc}"

    def grant(
        self,
        connection_id: int,
        schema_pattern: str,
        object_type: str,
        name_pattern: str,
        actions: Sequence[str] | str = "all",
    ) -> None:
        """Upsert a single-target allow rule.  Replaces that rule's whole action set.

        The version 1 signature, kept because it is the shape the Permissions page's
        "Database and security" section speaks and the shape the `database` object
        type wants — one connection, one rule, no patterns to choose.

        Three cases, and the third is a deliberate refusal:

        * **no such target** — a new one-target rule;
        * **the target's rule has only that target** — the version 1 upsert exactly:
          the action set is replaced, ``created_at``/``user_created`` untouched;
        * **the target's rule names other objects too** — ``ValueError``.

        The third case refuses because neither alternative is safe. *Mutating the
        siblings* would give this call a blast radius wider than its arguments —
        ``grant(..., "Customers", ["delete"])`` against a rule that also targets
        ``dbo``/``*`` would hand ``delete`` to every table in the schema — and a
        permission call whose reach cannot be read off its own call site is not
        auditable. *Silently splitting the target out* into a rule of its own fails
        the other way and more quietly: the operator's next tightening of the rule
        they believe covers this object would leave a hole they think they closed.
        Callers that mean to change a collection say so, through
        :meth:`update_rule`.

        A rule's **name is carried across untouched**, and this is the one place the
        wholesale discipline of :meth:`update_rule` is deliberately not applied. This
        method upserts an action set, not a rule: the Permissions page's "Database and
        security" section calls it from a checkbox, with no name in its hand to send,
        and clearing the operator's label for the rule because they ticked a box would
        be a change nobody asked for. Use :meth:`update_rule` to change a name.
        """
        connection_id = self._validate_connection_id(connection_id)
        schema_pattern, name_pattern = self._single_target(
            connection_id, object_type, schema_pattern, name_pattern
        )
        existing = self._rule_owning(connection_id, object_type, schema_pattern, name_pattern)
        if existing is None:
            self.create_rule(
                connection_id, object_type, [(schema_pattern, name_pattern)], actions
            )
        else:
            self.update_rule(
                existing, [(schema_pattern, name_pattern)], actions,
                rule_name=self._name_of(existing),
            )
        logger.info(
            "Granted %s on %s/%s/%s for connection %s",
            actions, schema_pattern, object_type, name_pattern, connection_id,
        )

    def deny(self, connection_id: int, schema_pattern: str, object_type: str, name_pattern: str) -> None:
        """Upsert a single-target rule that matches and grants nothing.

        Behaviourally identical to an allow rule with nothing ticked — ``is_deny``
        exists to record *intent*, not to change what is granted (DESIGN-PERMISSIONS.md
        §3).  Same three-way contract as :meth:`grant`, including the refusal and
        including carrying an existing rule's name across untouched.
        """
        connection_id = self._validate_connection_id(connection_id)
        schema_pattern, name_pattern = self._single_target(
            connection_id, object_type, schema_pattern, name_pattern
        )
        existing = self._rule_owning(connection_id, object_type, schema_pattern, name_pattern)
        if existing is None:
            self.create_rule(
                connection_id, object_type, [(schema_pattern, name_pattern)], (), is_deny=True
            )
        else:
            self.update_rule(
                existing, [(schema_pattern, name_pattern)], (), is_deny=True,
                rule_name=self._name_of(existing),
            )
        logger.info(
            "Denied %s/%s/%s for connection %s",
            schema_pattern, object_type, name_pattern, connection_id,
        )

    def revoke(self, connection_id: int, schema_pattern: str, object_type: str, name_pattern: str) -> bool:
        """Delete a single-target rule.  Returns ``False`` if it was not there.

        Symmetric with :meth:`grant`, refusal included: a target whose rule names
        other objects raises rather than quietly narrowing them all, or quietly
        narrowing just this one.  Use :meth:`update_rule` to drop one object from a
        collection, or :meth:`delete_rule` to remove the whole rule.
        """
        connection_id = self._validate_connection_id(connection_id)
        schema_pattern, name_pattern = _database_scope_patterns(
            object_type, schema_pattern, name_pattern
        )
        rule_id = self._rule_owning(connection_id, object_type, schema_pattern, name_pattern)
        if rule_id is None:
            return False
        self._refuse_if_shared(rule_id, schema_pattern, name_pattern)
        return self.delete_rule(rule_id)

    def _single_target(
        self, connection_id: int, object_type: str, schema_pattern: str, name_pattern: str
    ) -> tuple[str, str]:
        """Validate, normalise and refuse-if-shared, for the three wrappers above."""
        if object_type not in ACTIONS_BY_TYPE:
            raise ValueError(f"unknown object_type {object_type!r}; expected one of {', '.join(OBJECT_TYPES)}")
        schema_pattern, name_pattern = _database_scope_patterns(
            object_type,
            _validate_pattern(schema_pattern, "schema_pattern"),
            _validate_pattern(name_pattern, "name_pattern"),
        )
        rule_id = self._rule_owning(connection_id, object_type, schema_pattern, name_pattern)
        if rule_id is not None:
            self._refuse_if_shared(rule_id, schema_pattern, name_pattern)
        return schema_pattern, name_pattern

    def _rule_owning(
        self, connection_id: int, object_type: str, schema_pattern: str, name_pattern: str
    ) -> int | None:
        """The id of the rule naming this exact target, or ``None``."""
        row = self.conn.execute(
            "SELECT rule_id FROM rule_targets WHERE connection_id = ? AND object_type = ? "
            "AND schema_pattern = ? AND name_pattern = ?",
            (int(connection_id), str(object_type), schema_pattern, name_pattern),
        ).fetchone()
        return int(row["rule_id"]) if row is not None else None

    def _name_of(self, rule_id: int) -> str | None:
        """One rule's name, or ``None`` — what :meth:`grant` and :meth:`deny` carry across."""
        row = self.conn.execute(
            "SELECT rule_name FROM rules WHERE id = ?", (int(rule_id),)
        ).fetchone()
        return None if row is None else row["rule_name"]

    def _refuse_if_shared(self, rule_id: int, schema_pattern: str, name_pattern: str) -> None:
        """Raise if this target's rule names others — see :meth:`grant`'s third case."""
        others = [
            f"{row['schema_pattern']}.{row['name_pattern']}"
            for row in self.conn.execute(
                "SELECT schema_pattern, name_pattern FROM rule_targets WHERE rule_id = ? "
                "AND NOT (schema_pattern = ? AND name_pattern = ?) "
                "ORDER BY schema_pattern, name_pattern",
                (rule_id, schema_pattern, name_pattern),
            ).fetchall()
        ]
        if not others:
            return
        shown = ", ".join(others[:3]) + (", ..." if len(others) > 3 else "")
        raise ValueError(
            f"{schema_pattern}.{name_pattern} belongs to rule #{rule_id}, which also "
            f"names {len(others)} other object(s) ({shown}). Changing it here would "
            "change those too, so it is refused: use update_rule() to change the whole "
            "rule, or take this object out of it first."
        )

    # There is deliberately no seeding of default rules anywhere in this class.
    # A new database starts empty, and an empty database authorises nothing:
    # every object the operator wants an LLM to reach has to be granted
    # explicitly, through the GUI, by a human who looked at it.

    # -- reads -----------------------------------------------------------

    def rules(self, connection_id: int | None = None) -> list[dict[str, Any]]:
        """Every rule with its targets attached, newest first, optionally for one connection.

        "Newest" is ``id DESC``: ``id`` is ``AUTOINCREMENT`` and therefore strictly
        monotonic, so it orders rules by creation time even across a WAL-mode file
        where ``created_at``'s one-second resolution cannot break a tie.

        Two queries and a grouping in Python, never one per rule: the Permissions page
        renders every rule of a connection on every refresh, and an N+1 here would put
        a query per row behind a redraw.

        Each row is the whole ``rules`` row, so it carries ``rule_name`` — the
        operator's own label, or ``None`` for a rule nobody has named — alongside
        ``is_deny``, the 17 ``can_*`` columns and the four audit columns.  That is what
        the Permissions page and ``show-permissions`` read to say what a rule is *for*;
        :func:`format_rule` renders it under the same key.
        """
        if connection_id is None:
            rows = self.conn.execute("SELECT * FROM rules ORDER BY id DESC").fetchall()
            targets = self.conn.execute(
                "SELECT rule_id, schema_pattern, name_pattern FROM rule_targets "
                "ORDER BY rule_id, schema_pattern, name_pattern"
            ).fetchall()
        else:
            connection_id = int(connection_id)
            rows = self.conn.execute(
                "SELECT * FROM rules WHERE connection_id = ? ORDER BY id DESC", (connection_id,)
            ).fetchall()
            targets = self.conn.execute(
                "SELECT rule_id, schema_pattern, name_pattern FROM rule_targets "
                "WHERE connection_id = ? ORDER BY rule_id, schema_pattern, name_pattern",
                (connection_id,),
            ).fetchall()

        grouped: dict[int, list[dict[str, str]]] = {}
        for target in targets:
            grouped.setdefault(int(target["rule_id"]), []).append(
                {"schema_pattern": target["schema_pattern"], "name_pattern": target["name_pattern"]}
            )
        result = []
        for row in rows:
            rule = dict(row)
            rule["targets"] = grouped.get(int(row["id"]), [])
            result.append(rule)
        return result

    def rule_for(self, connection_id: int, ref: NormalisedRef) -> dict[str, Any] | None:
        """The single most specific matching rule, or ``None``.

        Raises ``ValueError`` on a malformed identifier rather than guessing
        (DESIGN-PERMISSIONS.md §5.4, §7).

        Since schema version 2 the candidates are ``(rule, target)`` pairs, and the
        row this returns carries the **matched target's** two patterns — which is what
        the denial message should cite, and what ``format_rule()`` renders. Ties remain
        impossible: two matching targets can only score equal if their patterns are
        identical (§2.2), and ``uq_rule_targets_key`` forbids two identical targets
        within one connection and object type, so they would have to be the same row
        and therefore the same rule (§2.4). Within *one* rule several targets may match
        — ``dbo``/``*`` and ``dbo``/``Cust*`` both match ``dbo.Customers`` — and the
        narrowest wins, which is the definition of a rule's specificity at an object.

        The defensive tiebreak below — deny first, then the lower ``rule_id``, then the
        lower ``target_id`` — is unreachable through this API and implemented anyway,
        for a database hand-edited with the constraint dropped.

        The row carries ``rule_name`` too, because ``r.*`` selects it and because a
        denial an operator is reading should be traceable to the rule as they labelled
        it.  **It takes no part in the decision**: nothing below reads it, the ordering
        key does not mention it, and naming a rule can therefore never change what it
        authorises (pinned by ``test_naming_a_rule_cannot_change_a_permission_decision``).
        """
        _validate_ref(ref)
        # r.* FIRST and t.id ALIASED, never `SELECT r.*, t.*`: `id` would then appear
        # twice, sqlite3.Row keeps the last, and _rule_id() in mcp_server.py would
        # write a *target* id into audit.matched_rule_id — pointing every historical
        # denial in the Logs page at the wrong rule, with nothing failing to say so.
        #
        # The join repeats connection_id and object_type on BOTH sides rather than
        # joining on rule_id alone. The composite foreign key already forbids a target
        # whose two denormalised columns disagree with its rule's, but only while the
        # pragma is on; a row that drifted while it was off is then inert here instead
        # of authoritative, which is the difference between a bug and a rule applied to
        # the wrong connection.
        candidates = self.conn.execute(
            """
            SELECT r.*, t.id AS target_id,
                   t.schema_pattern AS schema_pattern, t.name_pattern AS name_pattern
              FROM rule_targets t
              JOIN rules r
                ON r.id = t.rule_id
               AND r.connection_id = t.connection_id
               AND r.object_type = t.object_type
             WHERE t.connection_id = ? AND t.object_type = ?
            """,
            (int(connection_id), str(ref.object_type)),
        ).fetchall()

        # A `database` rule is scoped to the connection, not to an object in it, so
        # there is nothing to pattern-match: read_catalogue, run_query and the
        # role/user/group verbs belong to the whole connection (§5.6). Its single
        # '*'/'*' target is still joined through, so the row shape is uniform, but the
        # patterns are not compared. uq_rules_one_database_per_connection makes "at
        # most one" a fact of the schema; the tiebreak below is what happens anyway if
        # a hand-edited file has two.
        if str(ref.object_type) != DATABASE_TYPE:
            candidates = [
                row
                for row in candidates
                if _glob_match(row["schema_pattern"], ref.key_schema)
                and _glob_match(row["name_pattern"], ref.key_name)
            ]
        elif len({row["id"] for row in candidates}) > 1:
            logger.error(
                "Connection %s has %s 'database' rules, which the schema forbids; "
                "resolving to the deny, or else the earliest. Repair permissions.db.",
                connection_id,
                len({row["id"] for row in candidates}),
            )
        if not candidates:
            return None
        best = max(
            candidates,
            key=lambda r: (
                _specificity(r["name_pattern"]),  # name dominates, §2.3
                _specificity(r["schema_pattern"]),
                r["is_deny"],  # defensive tiebreak, §2.4: deny wins an impossible tie
                -r["id"],  # ... then the lower rule id
                -r["target_id"],  # ... then the lower target id
            ),
        )
        return dict(best)

    def is_allowed(self, connection_id: int, ref: NormalisedRef, action: str) -> bool:
        """Whether ``action`` on ``ref`` is authorised for ``connection_id``.

        Raises ``ValueError`` — never returns ``False`` — for an action outside
        ``ref.object_type``'s own tuple or a malformed identifier: those are
        programming errors, not permission decisions (§7).

        ``ref`` is validated *before* the action, even though a malformed ``ref``
        would eventually be caught inside ``rule_for()`` too — that ordering used
        to let something other than a ``NormalisedRef`` reach ``ref.object_type``
        first and fail with a bare ``AttributeError`` instead of the ``ValueError``
        §5.4 promises, which is the wrong exception for a caller to catch.

        ``drop`` and ``edit`` return ``False`` unconditionally, after both checks
        above but before any rule is consulted (ADR 0005 §1). This is the one
        choke point where a ``can_drop`` / ``can_edit`` column stored as ``1`` — by
        a rule written before schema version 4, or by a hand edit of
        ``permissions.db`` — is turned into an authorisation, and it is turned into
        ``False`` regardless: no per-object-type mapping and no rule row can
        override it, because nothing downstream asks anywhere else.
        """
        _validate_ref(ref)
        _validate_action(action, str(ref.object_type))
        if action in FORBIDDEN_ACTIONS:
            return False
        rule = self.rule_for(connection_id, ref)
        if rule is None or rule["is_deny"]:
            return False
        return bool(rule[f"can_{action}"])

    def require(self, connection_id: int, ref: NormalisedRef, action: str) -> None:
        """Raise ``PermissionDenied``, citing the matched rule, unless allowed.

        A forbidden action (ADR 0005) raises the narrower ``ActionForbidden``
        instead, and does so *without* calling :meth:`rule_for` — by the time this
        branch is reached ``is_allowed()`` has already returned ``False`` for the
        same reason, so no rule decided anything and none must be cited by
        accident. The check sits after the ``is_allowed()`` call rather than
        before it precisely so that call's own validation — a malformed ``ref``,
        or an action outside ``ref.object_type``'s tuple — still raises
        ``ValueError`` as DESIGN-PERMISSIONS.md §5.4 promises, rather than being
        pre-empted by a prohibition message that would be answering the wrong
        question.
        """
        if self.is_allowed(connection_id, ref, action):
            return
        if action in FORBIDDEN_ACTIONS:
            raise ActionForbidden(_forbidden_message(action, ref))
        rule = self.rule_for(connection_id, ref)
        raise PermissionDenied(_denial_message(action, ref, rule))

    def require_all(self, connection_id: int, references: Iterable[tuple[NormalisedRef, str]]) -> None:
        """Authorise every ``(identifier, action)`` before any of them is acted on.

        This method itself never executes anything — it only raises — so the first
        denial (or the first malformed identifier, which raises ``ValueError``)
        stops the caller before it has run a single statement against the object it
        was iterating. That is what makes "authorise everything, then act" hold:
        the caller must not begin acting until this returns without raising
        (DESIGN-PERMISSIONS.md §6.3).
        """
        for ref, action in references:
            self.require(connection_id, ref, action)

    # -- connection lifecycle (DESIGN-DATA-MODEL.md §7.2, §7.2 step 3) ---

    def delete_rules_for_connection(self, connection_id: int) -> int:
        """Cascade for a deleted connection; see DESIGN-DATA-MODEL.md §7."""
        connection_id = self._validate_connection_id(connection_id)
        # Targets go first and explicitly, rather than being left to ON DELETE CASCADE.
        # The cascade does fire, but this sweep must not depend on a pragma being on in
        # whichever process is doing the deleting, and an orphaned target would later
        # collide with a fresh create_rule() on uq_rule_targets_key -- reading as a
        # conflict with a rule that no longer exists.
        self.conn.execute("DELETE FROM rule_targets WHERE connection_id = ?", (connection_id,))
        cur = self.conn.execute("DELETE FROM rules WHERE connection_id = ?", (connection_id,))
        self.conn.commit()
        removed = cur.rowcount
        if removed:
            logger.info("Removed %s rule(s) for deleted connection %s", removed, connection_id)
        return removed

    def revoke_connection(self, connection_id: int) -> int:
        """``ConnectionStore.delete()``'s step 2 — ``DELETE FROM rules WHERE
        connection_id = ?``, committed, returning the number of rules removed
        (DESIGN-DATA-MODEL.md §7.2). Identical to ``delete_rules_for_connection()``;
        this is the name ``connection_store.py`` calls, kept as a separate method
        rather than an alias so the two call sites in the data-model document each
        have a method whose name matches the prose next to it.
        """
        return self.delete_rules_for_connection(connection_id)

    def reconcile(self, live_connection_ids: Iterable[int]) -> int:
        """Start-up orphan sweep: delete every rule whose connection no longer exists.

        ``DELETE ... WHERE connection_id NOT IN (...)``, not an ``ATTACH``-based
        anti-join — passing the ids in keeps this module free of any knowledge of
        where the connection store lives, which is the module boundary that lets
        the permission engine be tested with no connections database present at
        all (DESIGN-DATA-MODEL.md §7.2 step 3). An empty ``live_connection_ids``
        (the first-run case, or a caller that has not opened any connection yet)
        deletes every rule, which is correct: no connection means no rule can be
        legitimately attached to one.
        """
        ids = sorted({int(i) for i in live_connection_ids})
        if ids:
            placeholders = ", ".join("?" for _ in ids)
            self.conn.execute(
                f"DELETE FROM rule_targets WHERE connection_id NOT IN ({placeholders})", ids
            )
            cur = self.conn.execute(f"DELETE FROM rules WHERE connection_id NOT IN ({placeholders})", ids)
        else:
            self.conn.execute("DELETE FROM rule_targets")
            cur = self.conn.execute("DELETE FROM rules")
        self.conn.commit()
        removed = cur.rowcount
        if removed:
            logger.warning("Start-up reconciliation removed %s orphaned rule(s)", removed)
        return removed

    # -- validation --------------------------------------------------------

    def _validate_targets(
        self, object_type: str, targets: Sequence[tuple[str, str]]
    ) -> list[tuple[str, str]]:
        """Check a rule's collection of targets, and settle its order and duplicates.

        Empty is refused rather than treated as "matches nothing". "Every rule has at
        least one target" cannot be a SQLite constraint — no CHECK can count rows in
        another table — so this is the only place it can be enforced, and a rule with
        no targets would be a decision that applies to nothing while still occupying
        the rule list as though it applied to something.

        Duplicates within one call are collapsed rather than rejected: the GUI builds
        this list from a multi-selection in the schema tree, where the same object can
        legitimately be reached twice, and a duplicate says nothing the operator did
        not already say once.
        """
        if object_type not in ACTIONS_BY_TYPE:
            raise ValueError(f"unknown object_type {object_type!r}; expected one of {', '.join(OBJECT_TYPES)}")
        if isinstance(targets, (str, bytes)):
            raise ValueError("targets must be a sequence of (schema_pattern, name_pattern) pairs")

        seen: dict[tuple[str, str], None] = {}
        for target in targets:
            try:
                schema_pattern, name_pattern = target
            except (TypeError, ValueError):
                raise ValueError(
                    f"{target!r} is not a (schema_pattern, name_pattern) pair"
                ) from None
            schema_pattern = _validate_pattern(schema_pattern, "schema_pattern")
            name_pattern = _validate_pattern(name_pattern, "name_pattern")
            schema_pattern, name_pattern = _database_scope_patterns(
                object_type, schema_pattern, name_pattern
            )
            seen[(schema_pattern, name_pattern)] = None

        if not seen:
            raise ValueError(
                "a rule must name at least one object; to grant nothing, write a deny "
                "rule over the objects it should cover, or delete the rule entirely"
            )
        if object_type == DATABASE_TYPE and len(seen) > 1:
            # Every pair has already been rewritten to '*'/'*' above, so more than one
            # distinct entry is impossible; this is a guard against that rewrite being
            # removed by someone who has not read §5.6.
            raise ValueError(  # pragma: no cover - unreachable while _database_scope_patterns stands
                "a 'database' rule is scoped to the connection and takes exactly one target"
            )
        return sorted(seen)

    def _validate_actions(
        self, object_type: str, actions: Sequence[str] | str, *, is_deny: bool
    ) -> set[str]:
        """The action set a rule may carry, checked against its own object type.

        Actions do not merely differ in *count* between object types — ``select`` on a
        ``function`` is meaningless — so this is a correctness check, not a courtesy.
        Kept in Python rather than as a CHECK because SQLite's ``ALTER TABLE ... ADD
        COLUMN`` cannot extend a CHECK, and the first action added to
        ``ACTIONS_BY_TYPE`` would leave a stale constraint that merely looks enforced
        (DESIGN-DATA-MODEL.md §4.1).

        A member of ``FORBIDDEN_ACTIONS`` in ``actions`` is dropped silently rather
        than rejected with ``ValueError`` (ADR 0005 §3). Rejecting was considered
        and costs more than it buys: ``grant(..., "all")`` and any operator script
        that copies the same four lists a test does would start raising far from
        where the mistake actually is, over a value that is merely meaningless
        rather than a caller error — the same precedent
        :func:`_database_scope_patterns` sets for a `database` rule's patterns. The
        one place this *cannot* be silent is :meth:`PermissionStore.is_allowed`
        itself, which never sees this filtered set at all: it re-checks
        ``FORBIDDEN_ACTIONS`` against the raw ``can_*`` columns, so a row written
        before this filtering existed, or edited directly in the database file,
        still authorises nothing.
        """
        if is_deny:
            # A deny is exactly "a rule that matches and grants nothing"; the DDL's own
            # comment and test_a_deny_rule_cannot_carry_a_granted_action both depend on
            # every can_* column being 0 on such a row.
            granted = set() if actions in ("all", (), [], None) else set(actions)
            if granted:
                raise ValueError(
                    f"a deny rule cannot carry granted actions, but {sorted(granted)} "
                    "were passed; a deny matches and grants nothing (DESIGN-PERMISSIONS.md §3)"
                )
            return set()

        allowed = set(ACTIONS_BY_TYPE[object_type]) if actions == "all" else set(actions)
        unknown = allowed - set(ACTIONS_BY_TYPE[object_type])
        if unknown:
            raise ValueError(
                f"unknown action(s) for {object_type!r}: {sorted(unknown)}; "
                f"expected a subset of {ACTIONS_BY_TYPE[object_type]}"
            )

        forbidden = allowed & FORBIDDEN_ACTIONS
        if forbidden:
            logger.info(
                "Dropping %s from a %s rule's granted actions: never granted, "
                "whatever a rule says (ADR 0005) -- %s stays a well-formed "
                "argument to grant()/create_rule() rather than raising, so a "
                "caller passing 'all' or the same list a test does is not turned "
                "into an error over a value that is merely meaningless",
                sorted(forbidden), object_type, sorted(forbidden),
            )
        return allowed - FORBIDDEN_ACTIONS

    @staticmethod
    def _validate_rule_id(rule_id: int) -> int:
        try:
            value = int(rule_id)
        except (TypeError, ValueError):
            raise ValueError(f"rule_id must be a whole number, got {rule_id!r}") from None
        if value <= 0:
            raise ValueError(f"rule_id must be positive, got {value}")
        return value

    @staticmethod
    def _validate_connection_id(connection_id: int) -> int:
        try:
            value = int(connection_id)
        except (TypeError, ValueError):
            raise ValueError(f"connection_id must be a whole number, got {connection_id!r}") from None
        if value <= 0:
            raise ValueError(f"connection_id must be positive, got {value}")
        return value
