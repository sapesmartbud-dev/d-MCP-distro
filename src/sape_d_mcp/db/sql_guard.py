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

"""Classifies one SQL statement, names every object it reads or writes, refuses the rest."""

from __future__ import annotations

import logging
import re
from collections.abc import Iterator, Sequence
from dataclasses import dataclass, field

import sqlparse
from sqlparse import tokens as T

from .dialects.base import Dialect, DialectError
from .dialects.types import Engine, GuardTraits, ObjectType, StrEnum, WritingCTEShape

logger = logging.getLogger(__name__)

__all__ = [
    "Classification",
    "GuardRefusal",
    "Reference",
    "SqlGuard",
    "StatementPlan",
]


# --------------------------------------------------------------------------------------
# Vocabulary
# --------------------------------------------------------------------------------------


class Classification(StrEnum):
    """What a statement does, as far as the guard is prepared to commit to it.

    Deliberately five-valued and deliberately *not* `StatementKind`, which carries a sixth
    member, `DESTRUCTIVE`.  That distinction is a property of a statement the dialect layer
    *built* — `update()` with no predicate — and the confirmation broker reads it off
    `Query.kind`.  The guard classifies text it did not write, where "is this destructive"
    is a second question that only arises once the first has answered `WRITE`; folding the
    two into one enum would let a caller test `is READ` against a value that means neither.

    `UNKNOWN` exists so the guard has something to return that is not a lie.  It is never
    executed: unknown is denied, never allowed.
    """

    READ = "read"
    WRITE = "write"
    DDL = "ddl"
    SECURITY = "security"
    UNKNOWN = "unknown"

    @property
    def is_read(self) -> bool:
        """The one question the read tools ask.  Written as a property so no call site has
        to spell the comparison itself and get the sense of it inverted."""

        return self is Classification.READ


@dataclass(frozen=True, slots=True, order=True)
class Reference:
    """One object a statement touches, and what it does to it.

    `object_type` is `None` for every reference the guard extracts from free-form SQL, and
    that is not laziness — it is the honest answer.  `FROM dbo.Customers` is a relation; only
    the catalogue knows whether it is a table or a view, and the two are *different rows* in
    the permission table (`object_type` is part of the rule key).  Guessing `TABLE` would
    authorise a view against a table rule, and guessing `VIEW` would do the reverse.  The MCP
    layer therefore settles the kind through `Introspector`, which it must consult anyway to
    recurse a view into its base objects (DESIGN-PERMISSIONS.md §6.2), and refuses when the
    catalogue does not know the name either.

    `schema` and `name` are **canonical** spellings — what the engine's catalogue holds,
    obtained through `dialect.normalise_identifier()` with the quoting the statement actually
    used.  A caller minting a `NormalisedRef` from one must therefore take the *quoted* path
    (`normalise_identifier(name, quoted=True)`, as `Introspector._ref_for()` does), because
    folding a canonical name a second time turns PostgreSQL's `"Foo"` into `foo` and
    authorises a different table.
    """

    object_type: ObjectType | None
    schema: str | None
    name: str
    action: str


class GuardRefusal(Exception):
    """The guard will not run this statement, and says in one sentence why.

    Carries `unresolved`: the identifiers, keywords or constructs it could not attribute, so
    the tool result can name them rather than leaving the operator to guess which part of a
    forty-line query was the problem.  A refusal is not a permission denial — nothing has
    been checked against the rule table yet — so it is deliberately not a `PermissionError`,
    and the audit row records it as a refusal with its own message.
    """

    def __init__(self, message: str, *, unresolved: Sequence[str] = ()) -> None:
        super().__init__(message)
        self.unresolved: tuple[str, ...] = tuple(unresolved)


#: The action a read statement requires of every object it reads (DESIGN-PERMISSIONS.md
#: §6.5).  One name, one place, so a typo cannot silently authorise nothing.
_SELECT_ACTION = "select"

#: The action a *write* statement requires of the object it writes, keyed by the verb the
#: statement leads with.  Read sources inside that same statement carry `_SELECT_ACTION`
#: instead, and that split is the whole reason `Reference.action` exists: `UPDATE T SET a =
#: (SELECT x FROM Other)` needs `update` on `T` and `select` on `Other`, and a set that
#: named both under one action would either under-authorise the write or over-authorise the
#: read (DESIGN-MCP-TOOLS.md §5).
_WRITE_ACTIONS: dict[str, str] = {
    "INSERT": "insert",
    "UPDATE": "update",
    "DELETE": "delete",
}

#: The two DDL actions the guard ever asks for.  `edit` is deliberately absent: replacing a
#: routine body is `edit-*`, whose tool authorises the routine from its own arguments, and
#: the guard refuses routine DDL outright because it cannot read a procedural body and so
#: cannot say what that body will go on to read (DESIGN-MCP-TOOLS.md §5).
_CREATE_ACTION = "create"
_DROP_ACTION = "drop"

#: The object kinds a `CREATE`/`DROP` may name, and the permission type each maps to.
#: Unlike a reference pulled out of a `FROM` clause, a DDL reference *does* carry its
#: `object_type`: the statement itself says which kind it addresses, the engine refuses the
#: statement if the catalogue disagrees (`DROP VIEW` will not drop a table), and — the
#: deciding reason — a `CREATE` names an object that is not in the catalogue yet, so there
#: is nothing for the MCP layer to look the kind up in.  Leaving it `None` there would make
#: `create-table` unauthorisable rather than cautious.
_DDL_OBJECT_TYPES: dict[str, ObjectType] = {
    "TABLE": ObjectType.TABLE,
    "VIEW": ObjectType.VIEW,
    "FUNCTION": ObjectType.FUNCTION,
    "PROCEDURE": ObjectType.PROCEDURE,
}

#: Keywords that end a `WHERE` predicate.  `has_effective_where` must not read `ORDER BY x`
#: as part of the predicate, or `DELETE ... WHERE 1=1 ORDER BY id` would count `id` as the
#: column that makes the tautology a filter.
_PREDICATE_TERMINATORS = frozenset(
    {
        "GROUP BY",
        "HAVING",
        "ORDER BY",
        "LIMIT",
        "OFFSET",
        "FETCH",
        "WINDOW",
        "QUALIFY",
        "RETURNING",
        "UNION",
        "UNION ALL",
        "INTERSECT",
        "EXCEPT",
    }
)

#: Words that make a predicate's truth value undecidable by the reading `has_effective_where`
#: performs.  A `CASE` expression can be a tautology whose arms mention columns
#: (`CASE WHEN 1=1 AND a=1 THEN 1 ELSE 1 END = 1`), and the boolean split below would find
#: the column and call it a filter.  Rather than model expression evaluation, the guard
#: declines to answer, which reads as False — ask the human.
_UNDECIDABLE_IN_PREDICATE = frozenset({"CASE", "WHEN", "THEN", "ELSE", "END"})

#: What may appear inside a `RETURNING` list.  Anything else — a function call, a subquery —
#: could read an object the statement never names, and the guard would attribute the write
#: while missing the read.
_RETURNING_KEYWORDS = frozenset({"AS"})

@dataclass(frozen=True, slots=True)
class StatementPlan:
    """One statement, classified and attributed in full: what a write tool authorises from.

    `require_read_only()` returns a bare tuple because the read path asks exactly one
    question and already knows the answer to the rest.  A write tool asks three at once —
    what class of statement is this, what must be authorised and against which action, and
    does the confirmation broker have to be woken — and it must ask them of *one* parse, so
    the three answers cannot describe three different readings of the same text.  The field
    names are `DESIGN-MCP-TOOLS.md` §5's, so the tool layer reads what the document says.

    `references` is a single sequence rather than two, because the caller's loop is
    `for reference in plan.references: permissions.require(reference.action, ...)` and a
    split would let a caller authorise one list and forget the other.  `writes` and `reads`
    are views over it for the places that genuinely need the distinction — an impact
    estimate counts rows on what is written, not on what is read.
    """

    sql: str
    classification: Classification
    verb: str
    references: tuple[Reference, ...]
    has_effective_where: bool

    @property
    def is_read_only(self) -> bool:
        """Whether nothing here writes.  Always `False` for a plan `require_write()` built."""

        return self.classification.is_read

    @property
    def writes(self) -> tuple[Reference, ...]:
        """The objects this statement changes, with the action each change requires."""

        return tuple(r for r in self.references if r.action != _SELECT_ACTION)

    @property
    def reads(self) -> tuple[Reference, ...]:
        """The objects this statement reads on its way to writing something else."""

        return tuple(r for r in self.references if r.action == _SELECT_ACTION)


#: Characters that render as nothing, or reorder what is rendered, and therefore let a
#: statement read to a human as something other than what the server will execute — the
#: Trojan Source class of attack.  Refused anywhere in the text, inside string literals
#: included: no legitimate query d-MCP needs to run contains one.
_INVISIBLE_CHARACTERS = frozenset(
    "\u0000"      # NUL: truncates the statement inside several C client libraries
    "\u200b\u200c\u200d"    # zero-width space, non-joiner, joiner
    "\u200e\u200f"        # left-to-right and right-to-left marks
    "\u202a\u202b\u202c\u202d\u202e"  # the bidirectional embedding and override set
    "\u2066\u2067\u2068\u2069"    # the bidirectional isolate set
    "\ufeff"            # zero-width no-break space, the BOM in the middle of a line
)

#: Every keyword a read statement may contain.  Anything outside this set is refused by
#: name — that is the whole mechanism by which "refuse what you cannot model" is enforced,
#: rather than being an aspiration.  `INTO` is absent on purpose (`SELECT ... INTO` creates
#: a table on MS-SQL and writes a file on MySQL), as are `FOR` (`FOR UPDATE` takes write
#: locks), `VALUES`, `SET`, `EXPLAIN`, `PRAGMA` and every `APPLY`/`PIVOT` extension.
_ALLOWED_KEYWORDS = frozenset(
    {
        "ALL",
        "AND",
        "ANY",
        "AS",
        "ASC",
        "BETWEEN",
        "BY",
        "CASE",
        "COLLATE",
        "CURRENT",
        "CURRENT_DATE",
        "CURRENT_TIME",
        "CURRENT_TIMESTAMP",
        "DESC",
        "DISTINCT",
        "DISTINCTROW",
        "ELSE",
        "END",
        "ESCAPE",
        "EXCEPT",
        "EXISTS",
        "FALSE",
        "FETCH",
        "FILTER",
        "FIRST",
        "FOLLOWING",
        "FROM",
        "GROUP BY",
        "GROUPS",
        "HAVING",
        "ILIKE",
        "IN",
        "INTERSECT",
        "INTERVAL",
        "IS",
        "LAST",
        "LIKE",
        "LIMIT",
        "LOCALTIME",
        "LOCALTIMESTAMP",
        "NEXT",
        "NOT",
        # `sqlparse` lexes `IS NOT NULL` as `IS` followed by the single keyword token
        # `NOT NULL`, not as three tokens, so the allowlist needs the pair spelled out or
        # the commonest predicate in SQL is refused. Admitting it cannot widen anything:
        # a statement is classified by its leading verb before a keyword is ever looked up
        # here, so the DDL sense of `NOT NULL` — a column constraint — is already gone with
        # the `CREATE` that carried it.
        "NOT NULL",
        "NULL",
        "NULLS",
        "OFFSET",
        "ON",
        "ONLY",
        "OR",
        "ORDER BY",
        "OVER",
        "PARTITION",
        "PARTITION BY",
        "PRECEDING",
        "QUALIFY",
        "RANGE",
        "RECURSIVE",
        "ROW",
        "ROWS",
        "SELECT",
        "SOME",
        "THEN",
        "TIES",
        "TRUE",
        "UNBOUNDED",
        "UNION",
        "UNION ALL",
        "UNKNOWN",
        "USING",
        "WHEN",
        "WHERE",
        "WINDOW",
        "WITHIN GROUP",
    }
)

#: The words a join keyword may be built from.  `sqlparse` hands back the whole phrase as
#: one token (`LEFT OUTER JOIN`), and enumerating every legal permutation is both tedious
#: and easy to leave a hole in, so the phrase is decomposed instead.
_JOIN_WORDS = frozenset({"CROSS", "FULL", "INNER", "JOIN", "LEFT", "NATURAL", "OUTER", "RIGHT", "STRAIGHT_JOIN"})

#: Keywords that close the `FROM` list, after which a comma separates something other than
#: table sources and must not be read as introducing one.
_FROM_TERMINATORS = frozenset(
    {
        "WHERE",
        "GROUP BY",
        "HAVING",
        "ORDER BY",
        "LIMIT",
        "OFFSET",
        "FETCH",
        "UNION",
        "UNION ALL",
        "INTERSECT",
        "EXCEPT",
        "WINDOW",
        "QUALIFY",
    }
)

#: Functions the guard is willing to accept in a read statement without inspecting a body,
#: because they have no body: they are built into all four engines' grammars or standard
#: libraries and read no object.  Anything else — `dbo.CalculateBonus(x)` — may be a
#: user-defined function whose body reads tables this statement never names, so it is
#: refused (DESIGN-PERMISSIONS.md §6.5's last row, read closed rather than open).
#:
#: A qualified name is always refused regardless of what it spells, because a schema
#: qualification is exactly what a user-defined routine has and a built-in does not.
_BUILTIN_FUNCTIONS = frozenset(
    {
        # Aggregates
        "AVG", "COUNT", "GROUP_CONCAT", "MAX", "MIN", "STRING_AGG", "SUM", "TOTAL",
        # Window
        "DENSE_RANK", "LAG", "LEAD", "NTILE", "RANK", "ROW_NUMBER",
        # Conditional and null handling
        "COALESCE", "GREATEST", "IF", "IFNULL", "ISNULL", "LEAST", "NULLIF", "NVL",
        # Strings
        "ASCII", "CHAR", "CHAR_LENGTH", "CHARINDEX", "CONCAT", "CONCAT_WS", "FORMAT",
        "INSTR", "LEFT", "LEN", "LENGTH", "LOWER", "LPAD", "LTRIM", "POSITION", "REPLACE",
        "REVERSE", "RIGHT", "RPAD", "RTRIM", "SPLIT_PART", "SUBSTR", "SUBSTRING", "TRIM",
        "UPPER",
        # Numbers
        "ABS", "CEIL", "CEILING", "EXP", "FLOOR", "LN", "LOG", "MOD", "POWER", "ROUND",
        "SIGN", "SQRT", "TRUNC",
        # Dates
        "CURDATE", "CURRENT_DATE", "CURRENT_TIMESTAMP", "CURTIME", "DATE", "DATEADD",
        "DATEDIFF", "DATEPART", "DATE_ADD", "DATE_FORMAT", "DATE_PART", "DATE_SUB",
        "DATE_TRUNC", "DAY", "EXTRACT", "GETDATE", "HOUR", "MINUTE", "MONTH", "NOW",
        "SECOND", "STRFTIME", "SYSDATE", "TIME", "TO_CHAR", "TO_DATE", "TO_TIMESTAMP",
        "YEAR",
        # Casting and types
        "CAST", "CONVERT", "TRY_CAST", "TRY_CONVERT",
        # Type names, which reach the walker looking like calls: `CAST(x AS varchar(50))`
        "BIGINT", "BINARY", "BIT", "CHARACTER", "DEC", "DECIMAL", "DOUBLE", "FLOAT", "INT",
        "INTEGER", "NCHAR", "NUMERIC", "NVARCHAR", "REAL", "SIGNED", "SMALLINT", "TEXT",
        "TIMESTAMP", "TINYINT", "UNSIGNED", "VARBINARY", "VARCHAR",
    }
)

#: Keywords that may stand where a table source is expected without *being* that source.
#: `FROM ONLY t` names `t`, not `ONLY`, so re-reading a modelled keyword as a table name has
#: to make an exception for the handful that modify the source rather than name it — and
#: keeping the exception list explicit is what stops the re-reading from ever changing which
#: object an accepted statement reads.
_SOURCE_MODIFIERS = frozenset({"ONLY"})

#: Whitespace `sqlparse` may leave inside a multi-word keyword token.
_WHITESPACE_RUN = re.compile(r"\s+")


def _normalise_keyword(value: str) -> str:
    """Upper-case a keyword and collapse its internal whitespace.

    `GROUP\\n   BY` and `GROUP BY` are one keyword to every engine and two strings to a set
    lookup; the collapse is what stops a newline between the two words from turning a
    modelled clause into an unmodelled one and refusing a perfectly ordinary query.
    """

    return _WHITESPACE_RUN.sub(" ", value.strip()).upper()


@dataclass(frozen=True, slots=True)
class _Token:
    """One significant token: `sqlparse`'s type, its text, and its keyword spelling."""

    ttype: object
    value: str
    upper: str


@dataclass(frozen=True, slots=True)
class _Parsed:
    """The single statement the pre-flight was willing to hand on to classification."""

    text: str
    tokens: tuple[_Token, ...]
    classification: Classification
    verb: str


# --------------------------------------------------------------------------------------
# The guard
# --------------------------------------------------------------------------------------


class SqlGuard:
    """Decides whether one statement may run, and what it must be authorised against.

    Built on `sqlparse` for tokenisation and on `dialect.guard_traits()` for the four
    engine facts `sqlparse` cannot know (DESIGN-DIALECTS.md §6).  Everything else here is
    refusal logic, and it is written the way it is for one reason: **a statement the guard
    cannot fully attribute is refused, never attempted**.  Every branch below that cannot
    prove what a construct does raises `GuardRefusal`; there is no path that shrugs and
    returns a partial answer, because a partial answer is a partial authorisation and a
    partially authorised statement runs in full.

    The guard holds no connection and reads no catalogue.  Views are reported as the object
    the statement named; recursing one into its base tables is the MCP layer's job, because
    only it can query the catalogue (DESIGN-PERMISSIONS.md §6.2).
    """

    def __init__(self, dialect: Dialect) -> None:
        if not isinstance(dialect, Dialect):
            raise TypeError("SqlGuard takes a Dialect")
        self._dialect = dialect
        # Read once: `guard_traits()` is documented constant per engine and callable before
        # `configure()`, so caching it cannot go stale and keeps the hot path free of a
        # method call per statement.
        self._traits: GuardTraits = dialect.guard_traits()

    def __repr__(self) -> str:
        return f"<SqlGuard {self._dialect.engine}>"

    @property
    def dialect(self) -> Dialect:
        """The dialect this guard borrows its grammar facts from."""

        return self._dialect

    @property
    def traits(self) -> GuardTraits:
        """The engine facts, as read once at construction."""

        return self._traits

    @property
    def default_schema(self) -> str | None:
        """The schema an unqualified name in free-form SQL resolves against.

        The probed default where the server told us one, the engine's default otherwise,
        and finally the addressable stand-in an engine with no schema layer uses in the
        permission key (`main` on SQLite).  `None` means the guard genuinely does not know,
        and an unqualified name is then refused rather than resolved against a guess: on
        MySQL the answer is the connection's current database, which is a per-session fact,
        and a wrong guess authorises a table of the same name in another database.
        """

        return self._dialect.effective_default_schema() or self._dialect.addressable_schema

    # -- public API --------------------------------------------------------------------

    def classify(self, sql: str) -> Classification:
        """What this statement does.

        Raises `GuardRefusal` for anything that is not exactly one statement, or that the
        guard cannot lex safely — a batch, an executable comment, an unterminated literal.
        Returning a classification for a two-statement batch would be a lie whichever of the
        two it described.  A single statement whose leading verb is not recognised is
        `UNKNOWN`, which the read path refuses.
        """

        return self._parse(sql).classification

    def references(self, sql: str, *, default_schema: str | None = None) -> tuple[Reference, ...]:
        """Every object this statement touches, with the action each reference requires.

        For a read that is `FROM`, every flavour of `JOIN`, subqueries in any clause and CTE
        bodies, each carrying `select`, resolved against `default_schema` (or, when that is
        `None`, the connection's own default — see the property of the same name).  Common
        table expressions are excluded: `WITH c AS (SELECT ... FROM t) SELECT * FROM c` reads
        `t`, and `c` is not an object anyone can hold a permission on.

        For a write or a DDL statement it is the same enumeration plus the target, and the
        target carries the action the *write* needs — `insert`, `update`, `delete`, `create`
        or `drop` — while everything the statement merely reads on the way still carries
        `select`.  Until stage 7 this method refused a write outright, on the grounds that a
        set which named the write target under `select` would look authorising while the
        write went unchecked.  That reasoning is unchanged; what changed is that the guard
        can now name the action, so it no longer has to refuse in order to avoid lying.

        **Views are not expanded.**  The view is reported; the MCP layer recurses it through
        `Introspector` and re-authorises the bases, because only it can read the catalogue.

        Raises `GuardRefusal` for a statement the guard cannot classify, for a privilege
        statement (which `security.py` builds and authorises from structured arguments, never
        from parsed text), and for any statement whose object set cannot be determined in
        full.
        """

        parsed = self._parse(sql)
        return self._attribute(parsed, default_schema)

    def require_read_only(self, sql: str, *, default_schema: str | None = None) -> tuple[Reference, ...]:
        """Refuse unless this is one read statement, and return what it reads.

        The single entry point the read tools use.  It answers with the set the caller must
        pass to `PermissionStore.require_all()` *before* executing anything: authorise
        everything, then act (DESIGN-PERMISSIONS.md §6.3).
        """

        parsed = self._parse(sql)
        if parsed.classification is Classification.UNKNOWN:
            raise GuardRefusal(
                "The guard could not classify this statement, so it will not run it: "
                f"{parsed.verb!r} is not a statement d-MCP models. Unknown is denied.",
                unresolved=(parsed.verb,),
            )
        if not parsed.classification.is_read:
            raise GuardRefusal(
                f"This is a {parsed.classification.value} statement ({parsed.verb}) and the "
                "read path will not run it. Use the tool for that operation, which asks for "
                "confirmation and checks the matching permission.",
                unresolved=(parsed.verb,),
            )
        return self._enumerate(parsed, default_schema)

    def require_write(self, sql: str, *, default_schema: str | None = None) -> StatementPlan:
        """Refuse unless this is one write or DDL statement the guard can attribute in full.

        The single entry point the write tools use, and it keeps the read path's contract
        rather than relaxing it for convenience: a statement the guard cannot fully attribute
        is refused, never attempted.  The plan it returns is what the caller passes to
        `PermissionStore.require_all()` *before* executing anything — authorise everything,
        then act (DESIGN-PERMISSIONS.md §6.3) — and `plan.has_effective_where` is what the
        caller passes to the confirmation broker (DESIGN-MCP-TOOLS.md §8.1).

        "Write" here means *not a read*, so it covers `WRITE` and `DDL` alike.  The other
        three classifications are refused, each for its own reason:

        - `READ` — because a read authorised through the write path would be authorised
          against `insert`/`update`/`delete` flags it does not need and would skip the
          read-only session `run-read-query` runs on.  Call `require_read_only()`.
        - `SECURITY` — because `GRANT`, `CREATE USER` and their kin are built by
          `security.py` out of structured arguments and authorised against the
          database-scoped action tuple.  Nothing needs a privilege statement parsed out of
          free-form text, so nothing is given one.
        - `UNKNOWN` — unknown is denied, never allowed. That rule is the design's
          load-bearing property and it holds on this path exactly as it does on the read one.

        Within `WRITE` and `DDL` the guard models the statements d-MCP's own tools build and
        refuses the rest by name: `MERGE`, `TRUNCATE`, `REPLACE INTO`, `INSERT ... ON
        CONFLICT`/`ON DUPLICATE KEY`, `UPDATE ... FROM`, a multi-table `DELETE`, any `ALTER`,
        `CREATE INDEX`, routine bodies, and a write carrying a `WITH` clause.  Each is
        refused because it either performs an operation the permission model has no action
        for, or reaches objects the statement does not name — and an over-refusal is a
        message the operator can act on, whereas an under-attribution is a table changed
        without a rule ever being consulted.
        """

        parsed = self._parse(sql)
        if parsed.classification is Classification.UNKNOWN:
            raise GuardRefusal(
                "The guard could not classify this statement, so it will not run it: "
                f"{parsed.verb!r} is not a statement d-MCP models. Unknown is denied.",
                unresolved=(parsed.verb,),
            )
        if parsed.classification.is_read:
            raise GuardRefusal(
                f"This is a read statement ({parsed.verb}) and the write path will not run "
                "it. Reads go through the read tools, which run them on a read-only session.",
                unresolved=(parsed.verb,),
            )
        if parsed.classification is Classification.SECURITY:
            raise GuardRefusal(
                f"This is a privilege statement ({parsed.verb}). d-MCP builds those from the "
                "arguments of its own security tools and authorises them against the "
                "connection's security actions; it does not run one supplied as text.",
                unresolved=(parsed.verb,),
            )
        return StatementPlan(
            sql=parsed.text,
            classification=parsed.classification,
            verb=parsed.verb,
            references=self._attribute_write(parsed, default_schema),
            has_effective_where=self._effective_where(parsed),
        )

    def has_effective_where(self, sql: str) -> bool:
        """Whether this statement's `WHERE` clause can actually narrow the rows it touches.

        `update-rows` is brokered only when this is `False` (DESIGN-MCP-TOOLS.md §8.1), so
        the two answers are not symmetrical and must not be treated as though they were:
        **`False` means ask the human, `True` means do not.**  Every ambiguity below is
        therefore resolved towards `False`, and the cost of each one is a confirmation dialog
        for an operation that did not strictly need it — against the cost of `True`, which is
        a table-wide `UPDATE` running with nobody asked.

        `False` for:

        - no `WHERE` at all, and for a statement that cannot carry one;
        - a predicate mentioning no column: `WHERE 1=1`, `WHERE 'a'='a'`, `WHERE TRUE`,
          `WHERE 1`, `WHERE 1 IN (1,2)`, `WHERE NOT FALSE`, `WHERE 1 BETWEEN 0 AND 2`;
        - a comparison of a thing with itself, `WHERE id = id`, which mentions a column and
          filters nothing;
        - a disjunction with a columnless arm, `WHERE id = 5 OR 1=1` — the arm that filters
          nothing decides the whole predicate, so an `OR` filters only if *every* arm does.
          (`WHERE id = 5 OR 1=0` is genuinely a filter and is reported `False` anyway; that
          is the conservative direction taken deliberately.)
        - a column mentioned only inside a subquery: `WHERE EXISTS (SELECT 1 FROM other
          WHERE other.id = t.id)`.  Deciding this properly needs correlation analysis, and
          the uncorrelated form — `WHERE EXISTS (SELECT 1 FROM other)` — is true or false for
          every row at once, which is precisely a table-wide write;
        - anything containing `CASE`, whose truth the guard does not evaluate;
        - a name that spells a built-in function or type (`WHERE date = '2020-01-01'`),
          because the guard cannot tell that `date` is this table's column rather than a
          type name inside a `CAST`, and a type name is not a filter.  A column `sqlparse`
          types as a keyword rather than a name (`WHERE Year = 2024`) falls the same way,
          and for the same reason: in an expression position the guard does not re-read a
          keyword as an identifier (see `_reads_as_a_name`), so it does not see a column
          there and does not claim one;
        - a bound placeholder standing where the column would be: `WHERE ? = ?`.

        Knowingly **not** detected, and reported `True` even though the predicate matches
        every row: `WHERE id LIKE '%'`, `WHERE id IS NOT NULL` against a `NOT NULL` column,
        `WHERE id > -1`, `WHERE id = id + 0`, `WHERE id <> 'a value that never occurs'`.
        Each needs either the column's domain or arithmetic evaluation, and the guard has
        neither the catalogue nor an expression evaluator.  A predicate that names a real
        column and is not one of the syntactic tautologies above is taken at its word.

        This is not an authorisation and it is not a safety check.  Ask it only of a
        statement `require_write()` has already accepted — or read it off the plan that call
        returns, which is the same answer taken from the same parse.  Raises `GuardRefusal`
        for text the guard will not lex, because returning `True` for something it could not
        read would be the one answer that skips the human.
        """

        return self._effective_where(self._parse(sql))

    # -- pre-flight: one statement, lexed this engine's way ----------------------------

    def _parse(self, sql: str) -> _Parsed:
        """Everything that must hold before a single token is interpreted."""

        if not isinstance(sql, str):
            raise GuardRefusal(f"A statement must be text, not {type(sql).__name__}.")
        if sql.strip() == "":
            raise GuardRefusal("There is no statement to run.")

        found = sorted(_INVISIBLE_CHARACTERS.intersection(sql))
        if found:
            raise GuardRefusal(
                "The statement contains an invisible or direction-changing character "
                f"({', '.join(f'U+{ord(c):04X}' for c in found)}), so what it reads as and "
                "what it executes as need not be the same thing. It is refused unread.",
                unresolved=tuple(f"U+{ord(c):04X}" for c in found),
            )

        pattern = self._traits.executable_comment_pattern
        if pattern is not None and pattern.search(sql) is not None:
            # Deliberately not parsed: the content of `/*! ... */` obeys the same grammar as
            # the rest of the statement and can hide another layer of the same trick, so the
            # rule is refuse on sight (DESIGN-DIALECTS.md §6, conformance checklist).
            raise GuardRefusal(
                "The statement contains a MySQL executable comment (`/*!`). MySQL runs what "
                "is inside one while every other reader treats it as a comment, so d-MCP "
                "refuses the whole statement without looking inside it.",
                unresolved=("/*!",),
            )

        separator = self._traits.batch_separator_pattern
        if separator is not None and separator.search(sql) is not None:
            raise GuardRefusal(
                "The statement contains a batch separator (`GO`), which splits it into "
                "several statements that no SQL tokeniser reports as separate. Send one "
                "statement.",
                unresolved=("GO",),
            )

        if self._dialect.quote_close == "]" and "]]" in sql:
            # `[Weird]]Name]` is one identifier to SQL Server and four tokens to sqlparse,
            # which is precisely the kind of disagreement between our reader and the
            # server's that the guard exists to prevent. Refused rather than guessed.
            raise GuardRefusal(
                "The statement contains an escaped `]` inside a bracket-quoted identifier, "
                "which d-MCP's parser and SQL Server's read differently. Address the object "
                "through a tool argument rather than free-form SQL.",
                unresolved=("]]",),
            )

        segments = self._segments(sql)
        if not segments:
            raise GuardRefusal("There is no statement to run — only comments or whitespace.")
        if len(segments) > 1:
            raise GuardRefusal(
                f"This is {len(segments)} statements, not one. d-MCP runs exactly one "
                "statement per call, so a second one cannot ride along behind the first.",
                unresolved=tuple(s.strip()[:60] for s in segments[1:]),
            )

        # `sqlparse` gets a second, independent vote. It knows nothing of `#` comments or of
        # `GO`, so it is not a substitute for the scan above — but where the two disagree
        # about how many statements this text is, the honest answer is that we do not know.
        by_sqlparse = [part for part in sqlparse.split(sql) if part.strip()]
        if len(by_sqlparse) != 1:
            raise GuardRefusal(
                "d-MCP's reader and sqlparse disagree about how many statements this text "
                "contains, so it is refused rather than guessed at.",
                unresolved=tuple(part.strip()[:60] for part in by_sqlparse[1:]) or ("",),
            )

        statements = [s for s in sqlparse.parse(segments[0]) if str(s).strip()]
        if len(statements) != 1:
            raise GuardRefusal(
                "The statement did not parse as exactly one statement, so it is refused."
            )

        tokens = tuple(self._significant(statements[0]))
        if not tokens:
            raise GuardRefusal("There is no statement to run — only comments or whitespace.")
        for index, token in enumerate(tokens):
            if token.value == ";" and index != len(tokens) - 1:
                raise GuardRefusal(
                    "A statement terminator appears in the middle of the statement.",
                    unresolved=(";",),
                )
        if tokens[-1].value == ";":
            tokens = tokens[:-1]
        if not tokens:
            raise GuardRefusal("There is no statement to run.")

        classification, verb = self._classify_tokens(tokens)
        return _Parsed(
            text=segments[0], tokens=tokens, classification=classification, verb=verb
        )

    def _segments(self, sql: str) -> list[str]:
        """Split on `;` using *this engine's* lexical rules, and refuse the ambiguous.

        This is the guard's own lexer and it exists because `sqlparse` is dialect-blind in
        exactly the places that decide whether a second statement is hiding: MySQL treats
        `--x` as an operator rather than a comment when no space follows, and `#` as a
        comment when nothing else does.  Getting either wrong hides a `;` from us that the
        server will see.

        It errs towards refusal in every direction it cannot be sure of — an unterminated
        literal or comment, a backslash inside a string on an engine where the escape rule
        is a session setting — because an over-refusal is a message the operator can act on
        and an under-refusal is a `DROP` that ran.
        """

        engine = self._dialect.engine
        openers = self._delimiters()
        line_prefixes = sorted(self._traits.line_comment_prefixes, key=len, reverse=True)
        block_open, block_close = self._traits.block_comment_delimiters

        segments: list[str] = []
        start = 0
        index = 0
        length = len(sql)
        while index < length:
            character = sql[index]

            prefix = self._line_comment_at(sql, index, line_prefixes)
            if prefix is not None:
                newline = sql.find("\n", index)
                index = length if newline == -1 else newline + 1
                continue

            if sql.startswith(block_open, index):
                closing = sql.find(block_close, index + len(block_open))
                if closing == -1:
                    raise GuardRefusal(
                        "The statement contains a block comment that is never closed, so "
                        "where it ends — and what is inside it — is undecidable.",
                        unresolved=(block_open,),
                    )
                index = closing + len(block_close)
                continue

            if character in openers:
                closer, is_string = openers[character]
                index = self._skip_delimited(sql, index, character, closer, is_string, engine)
                continue

            if character == ";":
                segments.append(sql[start:index])
                start = index + 1
            index += 1

        segments.append(sql[start:])
        return [segment for segment in segments if self._has_content(segment, line_prefixes, block_open, block_close)]

    def _delimiters(self) -> dict[str, tuple[str, bool]]:
        """Opening delimiter -> (closing delimiter, is a string literal).

        `"` is listed on every engine, not only where it quotes an identifier: on MySQL
        without `ANSI_QUOTES` it is a string and with it an identifier, and on MS-SQL the
        same swap hangs off `QUOTED_IDENTIFIER`.  The span ends at the same character under
        either reading, which is all this lexer needs to decide where the statement does.
        """

        openers: dict[str, tuple[str, bool]] = {"'": ("'", True), '"': ('"', False)}
        opener = self._dialect.quote_open
        if opener not in openers:
            openers[opener] = (self._dialect.quote_close, False)
        return openers

    def _line_comment_at(self, sql: str, index: int, prefixes: Sequence[str]) -> str | None:
        """The line-comment prefix starting at `index`, honouring MySQL's space rule.

        MySQL requires whitespace or a control character after `--` before it is a comment;
        `--x` is two minus signs.  `GuardTraits`' own docstring calls over-recognising a
        comment the safe direction, and for *content* it is — but for *splitting* it is the
        unsafe one: reading `SELECT 1 --x; DROP TABLE t` as commented-out would hide a
        second statement the server executes. So the real rule is applied here.
        """

        for prefix in prefixes:
            if not sql.startswith(prefix, index):
                continue
            if prefix == "--" and self._dialect.engine is Engine.MYSQL:
                following = sql[index + len(prefix) : index + len(prefix) + 1]
                if following not in ("", " ", "\t", "\n", "\r", "\v", "\f"):
                    continue
            return prefix
        return None

    def _skip_delimited(
        self, sql: str, index: int, opener: str, closer: str, is_string: bool, engine: Engine
    ) -> int:
        """Step over a quoted span, treating a doubled closer as an escaped one."""

        position = index + len(opener)
        length = len(sql)
        while position < length:
            character = sql[position]
            if character == "\\" and is_string and engine in (Engine.MYSQL, Engine.POSTGRESQL):
                # Whether a backslash escapes the next character is a *session* setting on
                # both engines (`NO_BACKSLASH_ESCAPES`, `standard_conforming_strings`), and
                # the two readings disagree about where this literal ends — which is to say
                # about how many statements follow it. d-MCP cannot see the setting, so it
                # refuses instead of picking one.
                raise GuardRefusal(
                    "The statement contains a backslash inside a string literal. Whether it "
                    f"escapes the next character is a session setting on {engine}, so where "
                    "the literal ends is ambiguous and the statement is refused.",
                    unresolved=("\\",),
                )
            if sql.startswith(closer, position):
                if sql.startswith(closer * 2, position):
                    position += 2 * len(closer)
                    continue
                return position + len(closer)
            position += 1
        raise GuardRefusal(
            f"The statement contains a {opener}…{closer} literal that is never closed, so "
            "where it ends is undecidable.",
            unresolved=(opener,),
        )

    def _has_content(
        self, segment: str, prefixes: Sequence[str], block_open: str, block_close: str
    ) -> bool:
        """Whether a `;`-delimited segment holds anything but whitespace and comments.

        A trailing `;` produces an empty tail segment, and `SELECT 1; -- done` produces a
        comment-only one; neither is a second statement, and counting either as one would
        refuse the most ordinary query anybody writes.
        """

        index = 0
        length = len(segment)
        while index < length:
            prefix = self._line_comment_at(segment, index, prefixes)
            if prefix is not None:
                newline = segment.find("\n", index)
                index = length if newline == -1 else newline + 1
                continue
            if segment.startswith(block_open, index):
                closing = segment.find(block_close, index + len(block_open))
                index = length if closing == -1 else closing + len(block_close)
                continue
            if not segment[index].isspace():
                return True
            index += 1
        return False

    @staticmethod
    def _significant(statement: sqlparse.sql.Statement) -> Iterator[_Token]:
        """The token stream with whitespace and comments removed.

        Comments are dropped rather than inspected: by the time this runs the pre-flight has
        already refused an unterminated one, an executable one, and any `;` hiding behind
        one, so what remains cannot change what the server executes.
        """

        for token in statement.flatten():
            if token.ttype in (T.Whitespace, T.Newline) or token.ttype in T.Comment:
                continue
            if token.value.strip() == "":
                continue
            yield _Token(token.ttype, token.value, _normalise_keyword(token.value))

    # -- classification ----------------------------------------------------------------

    def _classify_tokens(self, tokens: Sequence[_Token]) -> tuple[Classification, str]:
        """Name the statement's verb and decide what family it belongs to.

        The keyword sets come from the dialect, never from this module: `REPLACE` is a write
        on MySQL and a function elsewhere, `MERGE` exists on two engines of the four, and
        `security_keywords` is empty on SQLite because SQLite has no principals.
        """

        leading = self._leading_words(tokens)
        traits = self._traits

        # Security before DDL, because `CREATE USER` is spelled with a DDL verb and is not a
        # DDL statement in this model — it is the security one, and it must not be
        # authorised by a `create` tick on a table rule.
        for size in (3, 2, 1):
            phrase = " ".join(leading[:size])
            if len(leading) >= size and phrase in traits.security_keywords:
                return Classification.SECURITY, phrase

        verb = leading[0] if leading else ""

        if tokens[0].ttype is T.Keyword.CTE and verb == "WITH":
            return self._classify_cte(tokens)

        if verb in traits.write_keywords:
            return Classification.WRITE, verb
        if verb in traits.ddl_keywords:
            return Classification.DDL, verb

        # `sqlparse` hands back `CREATE OR REPLACE` as a *single* keyword token — the same
        # lexing surprise as `NOT NULL` and `IF NOT EXISTS`, and with a sharper edge, because
        # the keyword sets hold `CREATE` alone. Left unhandled, the commonest way to replace
        # a view on PostgreSQL and MySQL classified `UNKNOWN`: refused, so nothing ran, but
        # refused as unrecognised text rather than as the destructive DDL it is, which is not
        # the message the operator needs and not a classification the write tools could
        # route. The phrase is decomposed rather than enumerated, as `_is_join` decomposes
        # `LEFT OUTER JOIN`.
        head = verb.split()[0] if verb else ""
        if head != verb:
            if head in traits.write_keywords:
                return Classification.WRITE, verb
            if head in traits.ddl_keywords:
                return Classification.DDL, verb

        if verb == "SELECT" and tokens[0].ttype is T.Keyword.DML:
            # A leading `SELECT` is not on its own enough to call the statement a read, and
            # the difference mattered less than it looks until now: the read path refused
            # `SELECT ... INTO` and `SELECT ... FOR UPDATE` inside the walker, so
            # `classify()` was free to answer READ for both and nothing noticed. It is not
            # free any more — `classify()` is the write tools' router, and a router told
            # READ sends a statement that creates a table (`SELECT * INTO copy FROM t` on
            # MS-SQL) or takes write locks (`FOR UPDATE`) to the path that will not check a
            # single write flag. The verdict is taken from the statement's whole token
            # stream, not from its first word.
            spoiled = self._disqualifier(tokens, 1)
            if spoiled is not None:
                return spoiled
            return Classification.READ, verb
        if verb == "TABLE" or verb == "VALUES":
            # `TABLE t` and `VALUES (...)` are read statements on some engines, but neither
            # is modelled by the walker, so classifying them as reads would promise an
            # attribution that cannot be delivered.
            return Classification.UNKNOWN, verb
        return Classification.UNKNOWN, verb or "(empty)"

    def _classify_cte(self, tokens: Sequence[_Token]) -> tuple[Classification, str]:
        """A `WITH` statement is a read only if nothing inside or after it writes.

        Both shapes `writing_cte_shape` names are caught by one rule, deliberately: on
        PostgreSQL and SQLite the write sits in the CTE body (`WITH c AS (INSERT ...)`),
        and on MS-SQL the body stays a `SELECT` while the statement that follows the CTE
        list targets the CTE's name (`WITH c AS (SELECT ...) UPDATE c SET ...`).  Scanning
        for a write verb anywhere in the statement covers both, and covers a third case the
        document does not name — a write verb inside a CTE body on an engine whose grammar
        forbids it, which is malformed rather than harmless and must not be run either.
        """

        spoiled = self._disqualifier(tokens, 0)
        if spoiled is not None:
            if spoiled[0] is Classification.WRITE:
                logger.debug(
                    "Writing CTE detected on %s (%s): %s",
                    self._dialect.engine,
                    self._traits.writing_cte_shape,
                    spoiled[1],
                )
            return spoiled
        if self._traits.writing_cte_shape is WritingCTEShape.NONE:
            logger.debug("Read-only WITH accepted on %s", self._dialect.engine)
        return Classification.READ, "WITH"

    def _disqualifier(
        self, tokens: Sequence[_Token], start: int
    ) -> tuple[Classification, str] | None:
        """The first token that stops a `SELECT`- or `WITH`-led statement being a read.

        One scan serves both, because the two hide the same things in the same way: a write
        verb somewhere other than the front (`WITH c AS (DELETE ...)`, `SELECT ... FOR
        UPDATE`), a DDL verb (`WITH c AS (SELECT ...) CREATE ...`), a privilege verb, or an
        `INTO`.

        `INTO` earns its own branch because it is the one disqualifier that is not a verb.
        `SELECT ... INTO t` creates a table on MS-SQL, assigns a variable on PostgreSQL and
        MySQL, and `INTO OUTFILE`/`INTO DUMPFILE` writes the server's filesystem — four
        different things, none of them a read, and no keyword set names it. It is reported
        `UNKNOWN` rather than `DDL` or `WRITE` because which of those it is depends on the
        engine and on what follows, and `UNKNOWN` is the answer that is refused by every
        path rather than routed to one of them.

        Returns `None` when the statement survives the scan, which is the ordinary case.
        """

        traits = self._traits
        for index, token in enumerate(tokens):
            if index < start:
                continue
            if token.ttype in T.Keyword and token.upper == "INTO":
                return Classification.UNKNOWN, "SELECT INTO"
            if token.upper in traits.write_keywords and token.ttype in (
                T.Keyword,
                T.Keyword.DML,
                T.Keyword.DDL,
            ):
                return Classification.WRITE, token.upper
            if token.upper in traits.ddl_keywords and token.ttype in (T.Keyword, T.Keyword.DDL):
                return Classification.DDL, token.upper
            if token.ttype is T.Keyword.DCL:
                return Classification.SECURITY, token.upper
            if token.ttype is T.Keyword.DML and token.upper != "SELECT":
                # A DML keyword this engine's `write_keywords` does not list — SQLite's
                # `REPLACE`, which `DESIGN-DIALECTS.md` §6 omits and `sqlite.py` records as
                # an omission. Not classifiable, therefore refused, which is where the
                # omission was already failing to; naming it here makes that deliberate.
                return Classification.UNKNOWN, token.upper
        return None

    @staticmethod
    def _leading_words(tokens: Sequence[_Token]) -> list[str]:
        """The first few keyword-ish words, for matching multi-word verbs like `CREATE USER`.

        Stops at the first token that is not a keyword or a bare name, so `CREATE TABLE
        users` contributes `CREATE TABLE USERS` and not the whole statement — the phrase
        lookup then matches `CREATE USER` only where those two words genuinely lead.
        """

        words: list[str] = []
        for token in tokens[:3]:
            if token.ttype in T.Keyword or token.ttype in T.Name:
                words.append(token.upper)
            else:
                break
        return words

    # -- reference enumeration ---------------------------------------------------------

    def _enumerate(self, parsed: _Parsed, default_schema: str | None) -> tuple[Reference, ...]:
        """Walk one read statement and collect every object it reads."""

        schema = default_schema if default_schema is not None else self.default_schema
        tokens = parsed.tokens
        pairs = self._match_parentheses(tokens)
        state = _WalkState(default_schema=schema)

        start = 0
        if tokens[0].ttype is T.Keyword.CTE:
            start = self._read_cte_list(tokens, pairs, state)
        self._scan(tokens, start, len(tokens), pairs, state)
        return tuple(state.references)

    @staticmethod
    def _match_parentheses(tokens: Sequence[_Token]) -> dict[int, int]:
        """Index of every `(` to the index of its `)`.  Unbalanced input is refused."""

        stack: list[int] = []
        pairs: dict[int, int] = {}
        for index, token in enumerate(tokens):
            if token.value == "(":
                stack.append(index)
            elif token.value == ")":
                if not stack:
                    raise GuardRefusal("The statement has an unbalanced closing parenthesis.")
                pairs[stack.pop()] = index
        if stack:
            raise GuardRefusal("The statement has an unclosed parenthesis.")
        return pairs

    def _read_cte_list(
        self, tokens: Sequence[_Token], pairs: dict[int, int], state: _WalkState
    ) -> int:
        """Consume `WITH a AS (...), b AS (...)`, recording the names and reading the bodies.

        A CTE name is not an object: nobody can hold a permission on it, and reporting one
        as a reference would send the MCP layer looking in the catalogue for a table that
        does not exist.  Recording the names is therefore not an optimisation — it is what
        keeps `SELECT * FROM c` from being attributed to a real table called `c`.

        The names are compared through the engine's match key, so a CTE declared `c` and
        used as `C` is one name wherever the engine says it is.
        """

        index = 1
        if index < len(tokens) and tokens[index].upper == "RECURSIVE":
            index += 1
        while True:
            if index >= len(tokens):
                raise GuardRefusal("The `WITH` clause ends before it names a query.")
            name_token = tokens[index]
            if not self._is_name_part(name_token):
                raise GuardRefusal(
                    "The `WITH` clause names something the guard cannot read as an "
                    f"identifier ({name_token.value!r}).",
                    unresolved=(name_token.value,),
                )
            state.cte_names.add(self._match_key(self._identifier(name_token)[0]))
            index += 1

            if index < len(tokens) and tokens[index].value == "(":
                # An explicit column list, `WITH c (a, b) AS (...)`: skipped whole, since a
                # column name is not an object and nothing inside can be a table source.
                index = pairs[index] + 1

            if index >= len(tokens) or tokens[index].upper != "AS":
                raise GuardRefusal("A `WITH` clause entry is missing its `AS`.")
            index += 1

            if index >= len(tokens) or tokens[index].value != "(":
                raise GuardRefusal("A `WITH` clause entry is not a parenthesised query.")
            body_end = pairs[index]
            self._scan(tokens, index + 1, body_end, pairs, state)
            index = body_end + 1

            if index < len(tokens) and tokens[index].value == ",":
                index += 1
                continue
            return index

    def _scan(
        self,
        tokens: Sequence[_Token],
        low: int,
        high: int,
        pairs: dict[int, int],
        state: _WalkState,
        *,
        inherits_source: bool = False,
    ) -> None:
        """Read one parenthesis-balanced scope, collecting its table sources.

        The scope, not the statement, is the unit: `WHERE x IN (SELECT y FROM z)` has its own
        `FROM` list, and treating the whole statement as one flat sequence would let the
        inner list's commas add sources to the outer one.  Each `(` recurses.

        Every token is checked against what a read statement may contain, and anything else
        is refused by name.  That allow-list *is* the guarantee: a construct nobody thought
        about — `FOR UPDATE`, `INTO OUTFILE`, `PIVOT`, a `MERGE` hiding behind a keyword this
        module never enumerated — cannot pass by being unrecognised, because unrecognised is
        the refusing case.
        """

        # A scope entered while a source was expected is itself a table reference —
        # `FROM (a JOIN b)`, `FROM ((a JOIN b) JOIN c)`. Starting it with the flags cleared
        # was a hole: `a` sits at the front of the sub-scope with nothing marking it as a
        # source, so it was read as a stray name and dropped from the authorisation set
        # while `b`, sitting after JOIN, was kept. A derived table clears the flags itself
        # on its leading SELECT, so inheriting costs that case nothing.
        index = low
        in_from = inherits_source
        expect_source = inherits_source
        while index < high:
            token = tokens[index]
            value, upper, ttype = token.value, token.upper, token.ttype

            if value == "(":
                closing = pairs[index]
                self._scan(
                    tokens, index + 1, closing, pairs, state, inherits_source=expect_source
                )
                expect_source = False
                index = closing + 1
                continue

            if ttype is T.Keyword.CTE:
                # A `WITH` anywhere but the very front means a nested CTE, whose names are
                # scoped to their own subquery. Honouring that scoping properly is more
                # machinery than the read tools need; ignoring it would let a nested name
                # shadow a real table in the outer scope and silently drop it from the
                # authorisation set. Refused instead.
                raise GuardRefusal(
                    "A `WITH` clause nested inside a subquery is not modelled by the guard.",
                    unresolved=("WITH",),
                )

            if ttype is T.Keyword.DML:
                if upper != "SELECT":
                    raise GuardRefusal(
                        f"A read statement cannot contain `{upper}`.", unresolved=(upper,)
                    )
                if expect_source and not (inherits_source and index == low):
                    # A derived table — `FROM (SELECT ...)` — is the one place a `SELECT`
                    # may legitimately satisfy an expected source, and it is the *first*
                    # token of the inherited scope when it does. Anywhere else, `FROM
                    # SELECT` is malformed, and clearing the flag quietly is how a source
                    # goes unauthorised.
                    raise GuardRefusal("A `FROM` or `JOIN` clause names no source.")
                in_from = False
                expect_source = False
                index += 1
                continue

            if ttype in (T.Keyword.DDL, T.Keyword.DCL):
                raise GuardRefusal(
                    f"A read statement cannot contain `{upper}`.", unresolved=(upper,)
                )

            reads_as_name = self._reads_as_a_name(
                tokens, index, high, expect_source=expect_source
            )

            if ttype in T.Keyword and not reads_as_name:
                if ttype is T.Keyword.Order:
                    index += 1
                    continue
                if upper == "FROM":
                    in_from = True
                    expect_source = True
                    index += 1
                    continue
                if self._is_join(upper):
                    expect_source = True
                    index += 1
                    continue
                if upper in _FROM_TERMINATORS:
                    if expect_source:
                        raise GuardRefusal("A `FROM` or `JOIN` clause names no source.")
                    in_from = False
                if upper not in _ALLOWED_KEYWORDS:
                    raise GuardRefusal(
                        f"The guard does not model `{upper}` in a read statement, so it "
                        "cannot say what the statement touches and will not run it."
                        + self._quoting_remedy(token),
                        unresolved=(upper,),
                    )
                if expect_source and upper not in _SOURCE_MODIFIERS:
                    # A word the guard *does* model as grammar, standing where only an
                    # object can stand: `SELECT * FROM Row`. It is not re-read as a name,
                    # because `ROW` means something here on some engines and reading it as
                    # a table would change which object an otherwise-legal statement reads.
                    # Saying so beats the bare "names no source" this used to fall through
                    # to, which told the caller nothing it could act on.
                    raise GuardRefusal(
                        f"`{upper}` stands where the statement should name an object, and it "
                        "is a word the guard reads as grammar rather than as a name. Write "
                        "it quoted or schema-qualified if it is the name of an object.",
                        unresolved=(upper,),
                    )
                index += 1
                continue

            if reads_as_name:
                if self._is_top_clause(tokens, index, expect_source):
                    # `SELECT TOP (10) ...`: sqlparse lexes MS-SQL's row limiter as a name
                    # followed by a parenthesis, which is indistinguishable from a function
                    # call without knowing the engine. It is one, here.
                    index += 1
                    continue
                parts, after = self._read_dotted(tokens, index, high)
                call = after < high and tokens[after].value == "("
                if expect_source:
                    if call:
                        raise GuardRefusal(
                            "The statement selects from a function "
                            f"({'.'.join(p.value for p in parts)}), whose body the guard "
                            "cannot inspect, so it cannot enumerate what that function "
                            "reads.",
                            unresolved=(".".join(p.value for p in parts),),
                        )
                    self._add_reference(parts, state)
                    expect_source = False
                elif call:
                    self._check_function(parts)
                index = after
                continue

            if ttype is T.Name.Placeholder or ttype in T.Literal.Number:
                index += 1
                continue
            if ttype in T.Literal.String and ttype is not T.Literal.String.Symbol:
                index += 1
                continue
            if ttype is T.Wildcard:
                index += 1
                continue
            if ttype in T.Operator:
                if ttype is T.Operator.Comparison or value in ("+", "-", "*", "/", "%", "||", "::"):
                    index += 1
                    continue
                raise GuardRefusal(
                    f"The guard does not model the operator `{value}`.", unresolved=(value,)
                )
            if ttype is T.Punctuation:
                if value == ",":
                    if in_from:
                        expect_source = True
                    index += 1
                    continue
                raise GuardRefusal(
                    f"The guard does not model `{value}` where it appears here.",
                    unresolved=(value,),
                )

            raise GuardRefusal(
                f"The guard does not model {value!r} in a read statement.", unresolved=(value,)
            )

        if expect_source:
            raise GuardRefusal("A `FROM` or `JOIN` clause names no source.")

    @staticmethod
    def _is_join(word: str) -> bool:
        """Whether a keyword phrase is some spelling of `JOIN`."""

        parts = word.split()
        return bool(parts) and "JOIN" in parts and all(part in _JOIN_WORDS for part in parts)

    @staticmethod
    def _is_name(token: _Token) -> bool:
        """Whether a token can be part of an object name."""

        if token.ttype is T.Name.Placeholder:
            return False
        return token.ttype in T.Name or token.ttype is T.Literal.String.Symbol

    @staticmethod
    def _keyword_could_be_a_name(token: _Token) -> bool:
        """Whether this keyword token is a word the guard attaches no grammar to.

        `sqlparse` types roughly a thousand words as keywords, and most of them are ordinary
        English nouns that any schema uses as table names: `Account`, `Source`, `Location`,
        `Type`, `Year`, `Level`, `Result`, `Owner`, `Session`, `Domain`, `Class`, `Object`.
        Handed one, the guard used to refuse the statement — `SELECT a FROM Account` was
        refused while `SELECT a FROM main.Account` and `SELECT a FROM "Account"` were not,
        which is a refusal the caller cannot act on because nothing in the message says the
        word is the problem.  This is the `IS NOT NULL` bug again: the tokeniser reports a
        keyword where a name was meant.

        The discriminator is *not* the word — widening the keyword allow-list would let a
        real keyword through in a position where it changes meaning, which is the opposite
        trade.  It is the position, and this predicate answers only the other half of the
        question: is this a word the guard has no meaning for?  A word it *does* model
        (`WHERE`, `ROW`, `ONLY`, `UNION`) keeps its meaning everywhere, and a word typed
        `DML`, `DDL`, `DCL` or `CTE` keeps its own: `GRANT` is how the guard notices a
        privilege statement wherever it appears, and a bare `GRANT` token is therefore never
        re-read as a table called `Grant`.  Both of those stay refused, and both say why.

        Multi-word tokens are excluded because a phrase (`GROUP BY`, `NOT NULL`,
        `IF NOT EXISTS`) is grammar by construction — no identifier is lexed with a space in
        it unless it was quoted, and a quoted one arrives as a `Symbol`.
        """

        ttype = token.ttype
        if ttype not in T.Keyword:
            return False
        if ttype in (T.Keyword.DML, T.Keyword.DDL, T.Keyword.DCL, T.Keyword.CTE):
            return False
        upper = token.upper
        if " " in upper:
            return False
        return not (
            upper in _ALLOWED_KEYWORDS or upper in _JOIN_WORDS or upper in _FROM_TERMINATORS
        )

    def _is_name_part(self, token: _Token) -> bool:
        """Whether a token may be one dot-separated part of a name.

        A part that follows a dot is in a position where nothing but a name is grammatical,
        so `s.Account` and `Account.id` read as names even where `Account` alone would not.
        """

        return self._is_name(token) or self._keyword_could_be_a_name(token)

    def _reads_as_a_name(
        self, tokens: Sequence[_Token], index: int, high: int, *, expect_source: bool
    ) -> bool:
        """Whether the token at `index` stands where an identifier is the only reading.

        Three positions qualify, and the list is short on purpose — this is the whole of the
        widening, and every position outside it keeps refusing.

        1. **Where a table source must stand.**  After `FROM`, after any `JOIN`, and after a
           comma inside a `FROM` list, nothing but an object name (or a parenthesis, handled
           before this is reached) is grammatical.
        2. **Either side of a dot.**  `Account.id` and `s.Account` can be nothing but a
           qualified name.
        3. **Immediately after `AS`.**  An alias, and nothing else, follows it.

        Deliberately *not* included: a bare expression position — the select list, an operand
        inside `WHERE`, an `ORDER BY` term.  A name is grammatical there, but so is a
        construct the guard does not model, and reading unmodelled words as columns there is
        how `SELECT * FROM t INTO OUTFILE '/tmp/x'` would become two column names and a
        string literal.  `SELECT Year FROM t` is therefore still refused, and the refusal now
        says to quote or qualify it, which `SELECT t.Year FROM t` and `SELECT "Year" FROM t`
        both satisfy.

        The safety property this is written to keep: **no statement the guard accepts today
        changes meaning.**  Every token this re-reads is one that produces an outright
        refusal as things stand, so the change can only turn refusals into acceptances — it
        can never turn one accepted reading into a different accepted reading.
        """

        token = tokens[index]
        if self._is_name(token):
            return True
        if not self._keyword_could_be_a_name(token):
            return False
        if expect_source:
            return True
        if index + 1 < high and tokens[index + 1].value == ".":
            return True
        if index > 0:
            previous = tokens[index - 1]
            if previous.value == ".":
                return True
            if previous.ttype in T.Keyword and previous.upper == "AS":
                return True
        return False

    def _quoting_remedy(self, token: _Token) -> str:
        """The sentence that turns a keyword refusal into something the caller can act on.

        Appended rather than folded into the message so that the refusal itself still reads
        the same for the words this does not apply to.
        """

        if self._keyword_could_be_a_name(token):
            return (
                f" If `{token.upper}` is meant as the name of an object or a column, write "
                "it quoted or schema-qualified: the guard reads a name in either of those "
                "forms, and cannot read a bare word its tokeniser reports as a keyword."
            )
        if token.ttype in T.Keyword:
            return (
                f" `{token.upper}` is a word the guard reads as grammar rather than as a "
                "name, so it has to be written quoted or schema-qualified to be read as an "
                "object."
            )
        return ""

    def _is_top_clause(self, tokens: Sequence[_Token], index: int, expect_source: bool) -> bool:
        """MS-SQL's `TOP`, which `sqlparse` reports as an ordinary name."""

        if expect_source or self._dialect.engine is not Engine.MSSQL:
            return False
        if tokens[index].upper != "TOP":
            return False
        previous = tokens[index - 1] if index > 0 else None
        return previous is not None and previous.upper in ("SELECT", "DISTINCT", "ALL")

    def _read_dotted(
        self, tokens: Sequence[_Token], index: int, high: int
    ) -> tuple[list[_Token], int]:
        """Read `a`, `a.b` or `a.b.c` as one name, returning it and the index after it."""

        parts = [tokens[index]]
        index += 1
        while (
            index + 1 < high
            and tokens[index].value == "."
            and self._is_name_part(tokens[index + 1])
        ):
            parts.append(tokens[index + 1])
            index += 2
        if index < high and tokens[index].value == ".":
            raise GuardRefusal(
                "A name ends in a dot, so the guard cannot tell what it addresses.",
                unresolved=(".".join(part.value for part in parts) + ".",),
            )
        return parts, index

    def _check_function(self, parts: Sequence[_Token]) -> None:
        """Refuse any function call whose body the guard cannot account for.

        A built-in reads nothing.  A user-defined function may read anything the connection
        can see, and `SELECT dbo.Bonus(id) FROM dbo.Staff` would then be authorised against
        `dbo.Staff` alone while reading `dbo.Salaries` through the function body
        (DESIGN-PERMISSIONS.md §6.5).  The guard cannot read that body, so it refuses.
        """

        spelled = ".".join(part.value for part in parts)
        if len(parts) > 1:
            raise GuardRefusal(
                f"The statement calls the schema-qualified function `{spelled}`. The guard "
                "cannot inspect a routine body, so it cannot enumerate what that call "
                "reads.",
                unresolved=(spelled,),
            )
        name, _ = self._identifier(parts[0])
        if name.upper() not in _BUILTIN_FUNCTIONS:
            raise GuardRefusal(
                f"The statement calls `{spelled}`, which is not a function d-MCP recognises "
                "as built in. It may be a user-defined routine whose body reads objects this "
                "statement never names, so the guard cannot attribute it.",
                unresolved=(spelled,),
            )

    def _add_reference(
        self,
        parts: Sequence[_Token],
        state: _WalkState,
        *,
        action: str = _SELECT_ACTION,
        object_type: ObjectType | None = None,
        is_target: bool = False,
    ) -> None:
        """Turn a name the statement addresses into a `Reference`, or refuse it.

        `action` defaults to `select` because most references are reads even inside a write.
        `is_target` marks the object the statement *changes*, and it turns off the
        common-table-expression check: a CTE name is not an object and is correctly dropped
        from a read's enumeration, but dropping a write's target because it happened to
        share a name with one would be a table changed with nothing authorised at all.
        """

        spelled = ".".join(part.value for part in parts)
        if len(parts) > 2:
            # Decision D9: a three- or four-part name addresses a second database, which the
            # permission model has no way to express — `connection_id` fixes exactly one.
            raise GuardRefusal(
                f"`{spelled}` names an object in another database. A d-MCP connection "
                "authorises one database, so a cross-database reference cannot be checked "
                "against any rule and is refused.",
                unresolved=(spelled,),
            )

        names = [self._identifier(part) for part in parts]
        if len(names) == 2:
            schema, name = names[0][0], names[1][0]
        else:
            name = names[0][0]
            if not is_target and self._match_key(name) in state.cte_names:
                return
            if state.default_schema is None:
                raise GuardRefusal(
                    f"`{spelled}` is not schema-qualified and the guard does not know which "
                    "schema this connection resolves an unqualified name against, so it "
                    "cannot say which object the statement reads.",
                    unresolved=(spelled,),
                )
            schema = state.default_schema

        reference = Reference(
            object_type=object_type, schema=schema, name=name, action=action
        )
        if reference not in state.seen:
            state.seen.add(reference)
            state.references.append(reference)

    def _identifier(self, token: _Token) -> tuple[str, bool]:
        """The canonical spelling of one name part, and whether it arrived quoted.

        Quoting is not cosmetic here: on PostgreSQL `Foo` and `"Foo"` are two tables that can
        coexist, so the quoted flag decides which of them the statement named.  The value
        goes through the dialect's own `normalise_identifier()` — the guard does not
        reimplement folding — and then through `quote_identifier()`, whose validation
        (embedded NUL, over-length) is the point rather than its return value.
        """

        raw = token.value
        quoted = False
        for opener, closer in (
            (self._dialect.quote_open, self._dialect.quote_close),
            ('"', '"'),
            ("`", "`"),
        ):
            if len(raw) >= len(opener) + len(closer) and raw.startswith(opener) and raw.endswith(closer):
                raw = raw[len(opener) : len(raw) - len(closer)].replace(closer * 2, closer)
                quoted = True
                break
        try:
            canonical = self._dialect.normalise_identifier(raw, quoted=quoted)
            self._dialect.quote_identifier(canonical)
        except DialectError as exc:
            raise GuardRefusal(
                f"The guard cannot resolve the identifier {token.value!r}: {exc}",
                unresolved=(token.value,),
            ) from exc
        return canonical, quoted

    def _match_key(self, name: str) -> str:
        """The comparison key for a CTE name, per the engine's folding rule."""

        try:
            return self._dialect.identifier_match_key(name)
        except DialectError as exc:
            raise GuardRefusal(
                f"The guard cannot key the identifier {name!r}: {exc}", unresolved=(name,)
            ) from exc

    # -- write and DDL attribution -----------------------------------------------------

    def _attribute(self, parsed: _Parsed, default_schema: str | None) -> tuple[Reference, ...]:
        """`references()`'s dispatcher: reads are walked, writes and DDL are attributed."""

        if parsed.classification is Classification.UNKNOWN:
            raise GuardRefusal(
                "The guard could not classify this statement, so it will not say what it "
                f"touches: {parsed.verb!r} is not a statement d-MCP models.",
                unresolved=(parsed.verb,),
            )
        if parsed.classification is Classification.SECURITY:
            raise GuardRefusal(
                f"The guard does not attribute a privilege statement ({parsed.verb}). What "
                "`GRANT` changes is a principal's rights, not an object's rows, and d-MCP "
                "authorises that through the connection's security actions instead.",
                unresolved=(parsed.verb,),
            )
        if parsed.classification.is_read:
            return self._enumerate(parsed, default_schema)
        return self._attribute_write(parsed, default_schema)

    def _attribute_write(
        self, parsed: _Parsed, default_schema: str | None
    ) -> tuple[Reference, ...]:
        """Name what a write or DDL statement writes, and everything it reads on the way.

        Dispatch is on the statement's *leading* token, not on `parsed.verb`, and the two can
        differ: `SELECT ... FOR UPDATE` classifies `WRITE` on the strength of a keyword in
        the middle of it, and arriving here it falls through to the closing refusal rather
        than being parsed as an `UPDATE` that it is not.
        """

        tokens = parsed.tokens
        if tokens[0].ttype is T.Keyword.CTE:
            # Both writing-CTE shapes in DESIGN-DIALECTS.md §6 land here: the write inside
            # the body on PostgreSQL and SQLite, and the write *through* the CTE's name on
            # MS-SQL, where the rows changed are the CTE's row set and the object behind that
            # name is only discoverable by resolving the CTE. No d-MCP tool builds either,
            # and attributing the second one wrongly would report a write against a name no
            # rule can cover while the real table went unnamed.
            raise GuardRefusal(
                "The guard does not model a write carried by a `WITH` clause. Address the "
                "table through the row tools, which name it directly.",
                unresolved=("WITH",),
            )

        pairs = self._match_parentheses(tokens)
        schema = default_schema if default_schema is not None else self.default_schema
        state = _WalkState(default_schema=schema)
        high = len(tokens)
        # The first *word*, because `CREATE OR REPLACE` arrives as one token (see
        # `_classify_tokens`); `_attribute_create` then reports the `OR` itself.
        leading = tokens[0].upper.split()[0]

        if leading == "INSERT":
            self._attribute_insert(tokens, high, pairs, state)
        elif leading == "UPDATE":
            self._attribute_update(tokens, high, pairs, state)
        elif leading == "DELETE":
            self._attribute_delete(tokens, high, pairs, state)
        elif leading == "CREATE":
            self._attribute_create(tokens, high, pairs, state)
        elif leading == "DROP":
            self._attribute_drop(tokens, high, pairs, state)
        else:
            # `MERGE`, `TRUNCATE`, `REPLACE INTO`, `ALTER`, and anything a future dialect
            # adds to `write_keywords` without teaching this module what it does. Each of
            # them changes rows or objects the permission model has no action for — a
            # `MERGE` inserts, updates *and* deletes in branches this parser does not read;
            # a `TRUNCATE` empties a table without a `delete` anyone approved; an `ALTER`
            # has no action in `ACTIONS_BY_TYPE` at all — so the honest answer is that the
            # guard cannot say what to authorise, and the honest answer is a refusal.
            raise GuardRefusal(
                f"The guard does not model `{leading}` as a write it can attribute, so it "
                "cannot say which permission would cover it. Use the tool for the operation "
                "you mean.",
                unresolved=(leading,),
            )
        return tuple(state.references)

    def _attribute_insert(
        self,
        tokens: Sequence[_Token],
        high: int,
        pairs: dict[int, int],
        state: _WalkState,
    ) -> None:
        """`INSERT INTO <object> [(columns)] {VALUES ... | SELECT ...} [RETURNING ...]`.

        Only that shape.  `INSERT OR REPLACE`, `INSERT OR IGNORE`, `INSERT IGNORE`,
        `INSERT ... ON CONFLICT DO UPDATE` and `INSERT ... ON DUPLICATE KEY UPDATE` all
        delete or overwrite rows that were already there, which is `update`/`delete`
        territory reached through a tool the broker never sees, so each is refused where it
        first shows: the word after `INSERT` must be `INTO`, and the clause after the rows
        must be nothing or `RETURNING`.
        """

        if high < 2 or tokens[1].upper != "INTO":
            offender = tokens[1].value if high > 1 else "(nothing)"
            raise GuardRefusal(
                "The guard models `INSERT INTO <object>` and nothing else, but the word "
                f"after `INSERT` is `{offender}`. The `OR REPLACE`, `IGNORE` and "
                "`ON CONFLICT` forms overwrite rows that already exist, which is not an "
                "insert and is not what an `insert` permission grants.",
                unresolved=(offender,),
            )

        target, index = self._read_target(tokens, 2, high, state, action=_WRITE_ACTIONS["INSERT"])

        if index < high and tokens[index].value == "(":
            closing = pairs[index]
            self._require_name_list(tokens, index + 1, closing, "the column list of an `INSERT`")
            index = closing + 1

        returning = self._find_top_level(tokens, index, high, pairs, frozenset({"RETURNING"}))
        body_high = high if returning < 0 else returning
        if index >= body_high:
            raise GuardRefusal("The `INSERT` supplies no rows.")

        self._refuse_upsert(tokens, index, body_high, pairs)

        word = tokens[index].upper
        if word == "VALUES":
            self._scan(tokens, index + 1, body_high, pairs, state)
        elif word == "DEFAULT" and index + 1 < body_high and tokens[index + 1].upper == "VALUES":
            if index + 2 != body_high:
                raise GuardRefusal(
                    "The guard does not model what follows `DEFAULT VALUES` here.",
                    unresolved=(tokens[index + 2].value,),
                )
        elif tokens[index].ttype is T.Keyword.DML or tokens[index].value == "(":
            # `INSERT INTO t SELECT ... FROM src`, the shape that reads one object and writes
            # another. Everything the select side names is enumerated by the ordinary read
            # walk and carries `select`, so a caller who may insert into `t` still cannot
            # copy `src` into it without `select` on `src`.
            self._scan(tokens, index, body_high, pairs, state)
        else:
            raise GuardRefusal(
                f"The guard does not model `{tokens[index].value}` after the target of an "
                "`INSERT`.",
                unresolved=(tokens[index].value,),
            )

        if returning >= 0:
            self._attribute_returning(tokens, returning + 1, high, pairs, target, state)

    def _refuse_upsert(
        self, tokens: Sequence[_Token], low: int, high: int, pairs: dict[int, int]
    ) -> None:
        """Refuse `ON CONFLICT ...` and `ON DUPLICATE KEY UPDATE` by name.

        Both were already refused, but only by falling off the read walk's allow-list several
        tokens later, which reported a keyword rather than the clause and left the refusal
        depending on `CONFLICT` never being added to that list.  The word is matched on the
        `ON` that introduces it and on what follows, because a bare `ON` is the ordinary join
        condition of an `INSERT ... SELECT` and must stay legal.
        """

        index = low
        while index < high:
            token = tokens[index]
            if token.value == "(":
                index = pairs[index] + 1
                continue
            if (
                token.ttype in T.Keyword
                and token.upper == "ON"
                and index + 1 < high
                and tokens[index + 1].upper in ("CONFLICT", "DUPLICATE")
            ):
                clause = f"ON {tokens[index + 1].upper}"
                raise GuardRefusal(
                    f"`{clause}` turns an insert into an update or a delete of rows that "
                    "were already there, and an `insert` permission does not grant either. "
                    "Use the tool for the operation you mean, which asks for confirmation.",
                    unresolved=(clause,),
                )
            index += 1

    def _attribute_update(
        self,
        tokens: Sequence[_Token],
        high: int,
        pairs: dict[int, int],
        state: _WalkState,
    ) -> None:
        """`UPDATE <object> [alias] SET ... [WHERE ...] [RETURNING ...]`.

        The `SET` list and the `WHERE` clause are walked by the same read scan the read tools
        use, so `UPDATE T SET a = (SELECT x FROM Other) WHERE id IN (SELECT id FROM Third)`
        reports `update` on `T` and `select` on `Other` and `Third` — three references, two
        actions, one statement.  Under-reporting either subquery would let a caller with
        `update` on one table read any other table in the database one row at a time.

        `UPDATE ... FROM` is refused.  PostgreSQL and MS-SQL both have it and they disagree
        about which relation the target is: on MS-SQL the target may be an alias declared in
        the `FROM` list, so the object actually written is not the object the statement
        appears to name.  d-MCP builds no such statement, and guessing wrong writes a table
        nobody authorised.
        """

        target, index = self._read_target(tokens, 1, high, state, action=_WRITE_ACTIONS["UPDATE"])
        index = self._skip_alias(tokens, index, high)
        if index >= high or tokens[index].upper != "SET":
            offender = tokens[index].value if index < high else "(nothing)"
            raise GuardRefusal(
                "The guard models `UPDATE <object> SET ...`, and what follows the target "
                f"here is `{offender}`.",
                unresolved=(offender,),
            )
        index += 1

        self._refuse_top_level(
            tokens,
            index,
            high,
            pairs,
            frozenset({"FROM", "USING", "OUTPUT", "JOIN"}),
            "an `UPDATE` the guard can attribute",
        )

        where = self._find_top_level(tokens, index, high, pairs, frozenset({"WHERE"}))
        returning = self._find_top_level(tokens, index, high, pairs, frozenset({"RETURNING"}))
        tail = min(position for position in (where, returning, high) if position >= 0)
        self._scan(tokens, index, tail, pairs, state)

        if where >= 0:
            where_high = returning if returning >= 0 else high
            if where + 1 >= where_high:
                raise GuardRefusal("The `WHERE` clause is empty.")
            self._scan(tokens, where + 1, where_high, pairs, state)
        if returning >= 0:
            self._attribute_returning(tokens, returning + 1, high, pairs, target, state)

    def _attribute_delete(
        self,
        tokens: Sequence[_Token],
        high: int,
        pairs: dict[int, int],
        state: _WalkState,
    ) -> None:
        """`DELETE FROM <object> [alias] [WHERE ...] [RETURNING ...]`.

        `FROM` is required even though MS-SQL and MySQL both accept it omitted, because the
        forms that omit it are the multi-table ones (`DELETE t FROM t JOIN u ...`), where
        which table loses rows is decided by a list this parser does not read.
        """

        if high < 2 or tokens[1].upper != "FROM":
            offender = tokens[1].value if high > 1 else "(nothing)"
            raise GuardRefusal(
                "The guard models `DELETE FROM <object>`, and the word after `DELETE` here "
                f"is `{offender}`. The forms that omit `FROM` delete from one of several "
                "joined tables, and the guard will not guess which.",
                unresolved=(offender,),
            )

        target, index = self._read_target(tokens, 2, high, state, action=_WRITE_ACTIONS["DELETE"])
        index = self._skip_alias(tokens, index, high)

        self._refuse_top_level(
            tokens,
            index,
            high,
            pairs,
            frozenset({"FROM", "USING", "OUTPUT", "JOIN"}),
            "a `DELETE` the guard can attribute",
        )

        where = self._find_top_level(tokens, index, high, pairs, frozenset({"WHERE"}))
        returning = self._find_top_level(tokens, index, high, pairs, frozenset({"RETURNING"}))
        first = min(position for position in (where, returning, high) if position >= 0)
        if index != first:
            raise GuardRefusal(
                f"The guard does not model `{tokens[index].value}` between the target of a "
                "`DELETE` and its `WHERE` clause.",
                unresolved=(tokens[index].value,),
            )
        if where >= 0:
            where_high = returning if returning >= 0 else high
            if where + 1 >= where_high:
                raise GuardRefusal("The `WHERE` clause is empty.")
            self._scan(tokens, where + 1, where_high, pairs, state)
        if returning >= 0:
            self._attribute_returning(tokens, returning + 1, high, pairs, target, state)

    def _attribute_create(
        self,
        tokens: Sequence[_Token],
        high: int,
        pairs: dict[int, int],
        state: _WalkState,
    ) -> None:
        """`CREATE TABLE`/`CREATE VIEW`, and a refusal for every other kind.

        A view body is walked as a read, because `create-view` requires `create` on the view
        *and* `select` on everything the body references — without that pair, `create-view`
        followed by `select-view-rows` is a two-step route around the rule store
        (DESIGN-MCP-TOOLS.md §5).  `CREATE TABLE ... AS SELECT` is walked the same way for
        the same reason.

        A routine is refused outright.  Its body is procedural code in a language `sqlparse`
        does not parse and this module does not model, so the guard cannot enumerate what the
        body reads — and §5 is explicit that a body which cannot be parsed confidently is
        refused rather than guessed at.  `create-function` authorises the routine from its
        own arguments; it does not get the guard's blessing on the text.

        `OR REPLACE`/`OR ALTER` is refused because it destroys the object it replaces, and
        §8.1 makes replacement `edit-*`, which is brokered, while `create-*` is not.
        """

        index = 1
        if index >= high:
            raise GuardRefusal("The `CREATE` names nothing.")
        if "OR" in tokens[0].upper.split() or tokens[index].upper == "OR":
            raise GuardRefusal(
                "`CREATE OR REPLACE` / `CREATE OR ALTER` destroys the object it replaces, so "
                "d-MCP treats it as an edit rather than a creation and will not accept it "
                "here. Replacing an object goes through the tool that asks for confirmation.",
                unresolved=("OR",),
            )

        kind = tokens[index].upper
        if kind in ("FUNCTION", "PROCEDURE"):
            raise GuardRefusal(
                f"The guard cannot read the body of a {kind.lower()}, so it cannot say what "
                "that body will read once it runs. Routine DDL is authorised from the tool's "
                "own arguments, not from parsed text.",
                unresolved=(kind,),
            )
        if kind not in ("TABLE", "VIEW"):
            raise GuardRefusal(
                f"The guard does not model `CREATE {kind}`. The permission model has an "
                "action for tables, views, functions and procedures, and for nothing else, "
                "so there is no rule that could authorise it.",
                unresolved=(kind,),
            )
        index += 1

        if index < high and tokens[index].upper == "IF NOT EXISTS":
            # One keyword token, not three — the same lexing surprise as `NOT NULL`. Matching
            # `IF`, `NOT` and `EXISTS` separately would never fire and the name would be read
            # out of the middle of the clause.
            index += 1

        object_type = _DDL_OBJECT_TYPES[kind]
        _, index = self._read_target(
            tokens, index, high, state, action=_CREATE_ACTION, object_type=object_type
        )

        if kind == "TABLE":
            if index < high and tokens[index].value == "(":
                closing = pairs[index]
                self._check_column_definitions(tokens, index + 1, closing, pairs)
                index = closing + 1
                if index != high:
                    raise GuardRefusal(
                        "The guard does not model what follows the column list of a "
                        f"`CREATE TABLE` (`{tokens[index].value}`).",
                        unresolved=(tokens[index].value,),
                    )
                return
            if index < high and tokens[index].upper == "AS":
                if index + 1 >= high:
                    raise GuardRefusal("`CREATE TABLE ... AS` is followed by no query.")
                self._scan(tokens, index + 1, high, pairs, state)
                return
            raise GuardRefusal(
                "A `CREATE TABLE` must be followed by a column list or by `AS <query>`.",
                unresolved=(tokens[index].value if index < high else "(nothing)",),
            )

        if index < high and tokens[index].value == "(":
            closing = pairs[index]
            self._require_name_list(
                tokens, index + 1, closing, "the column list of a `CREATE VIEW`"
            )
            index = closing + 1
        if index >= high or tokens[index].upper != "AS":
            raise GuardRefusal(
                "A `CREATE VIEW` must be followed by `AS <query>`.",
                unresolved=(tokens[index].value if index < high else "(nothing)",),
            )
        if index + 1 >= high:
            raise GuardRefusal("`CREATE VIEW ... AS` is followed by no query.")
        self._scan(tokens, index + 1, high, pairs, state)

    def _attribute_drop(
        self,
        tokens: Sequence[_Token],
        high: int,
        pairs: dict[int, int],
        state: _WalkState,
    ) -> None:
        """`DROP {TABLE|VIEW|FUNCTION|PROCEDURE} [IF EXISTS] <object>[, ...] [RESTRICT]`.

        `CASCADE` is refused.  It drops every dependent object the engine can find, and those
        objects are not named in the statement — so the guard would report one `drop` while
        the server performed several, and the confirmation dialog would show the operator a
        statement that understates what it does.  `RESTRICT` is the opposite instruction and
        is allowed.
        """

        if high < 2:
            raise GuardRefusal("The `DROP` names nothing.")
        kind = tokens[1].upper
        if kind not in _DDL_OBJECT_TYPES:
            raise GuardRefusal(
                f"The guard does not model `DROP {kind}`. The permission model has a `drop` "
                "action for tables, views, functions and procedures, and for nothing else.",
                unresolved=(kind,),
            )
        object_type = _DDL_OBJECT_TYPES[kind]
        index = 2
        if index < high and tokens[index].upper == "IF EXISTS":
            index += 1

        while True:
            _, index = self._read_target(
                tokens, index, high, state, action=_DROP_ACTION, object_type=object_type
            )
            if (
                object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE)
                and index < high
                and tokens[index].value == "("
            ):
                # PostgreSQL overloads routines, so the argument types are part of the name.
                # They address no object of their own; they are validated and stepped over.
                closing = pairs[index]
                self._require_name_list(
                    tokens,
                    index + 1,
                    closing,
                    "the argument list of a `DROP`",
                    allow_literals=True,
                )
                index = closing + 1
            if index < high and tokens[index].value == ",":
                index += 1
                continue
            break

        if index < high:
            word = tokens[index].upper
            if word == "RESTRICT" and index + 1 == high:
                return
            if word == "CASCADE":
                raise GuardRefusal(
                    "`DROP ... CASCADE` also drops every object that depends on this one, "
                    "and the statement does not name them, so neither the permission check "
                    "nor the confirmation dialog would cover what actually happens.",
                    unresolved=("CASCADE",),
                )
            raise GuardRefusal(
                f"The guard does not model `{tokens[index].value}` in a `DROP`.",
                unresolved=(tokens[index].value,),
            )

    def _attribute_returning(
        self,
        tokens: Sequence[_Token],
        low: int,
        high: int,
        pairs: dict[int, int],
        target: Sequence[_Token],
        state: _WalkState,
    ) -> None:
        """A `RETURNING` list reads back the rows the statement wrote, so it needs `select`.

        `insert-rows` can be granted without `select-rows`, and the operator who grants it
        that way has said the caller may put rows in and not take rows out.  `INSERT ...
        RETURNING *` hands those rows straight back, so the target is added a second time
        with `select` — the same object, two references, two actions, which is exactly what
        `Reference.action` is for.

        The list itself may hold only names, `*`, aliases and commas: a function call or a
        subquery here would read objects the statement never names.
        """

        if low >= high:
            raise GuardRefusal("The `RETURNING` clause names nothing.")
        self._require_name_list(
            tokens, low, high, "a `RETURNING` clause", allow_wildcard=True, allow_alias=True
        )
        self._add_reference(target, state, action=_SELECT_ACTION, is_target=True)

    # -- write-side helpers --------------------------------------------------------------

    def _read_target(
        self,
        tokens: Sequence[_Token],
        index: int,
        high: int,
        state: _WalkState,
        *,
        action: str,
        object_type: ObjectType | None = None,
    ) -> tuple[list[_Token], int]:
        """Read the object a write addresses, record it under `action`, and step past it."""

        if index >= high or not self._is_name_part(tokens[index]):
            offender = tokens[index].value if index < high else "(nothing)"
            raise GuardRefusal(
                f"The statement should name an object here and names `{offender}` instead."
                + (self._quoting_remedy(tokens[index]) if index < high else ""),
                unresolved=(offender,),
            )
        parts, after = self._read_dotted(tokens, index, high)
        self._add_reference(
            parts, state, action=action, object_type=object_type, is_target=True
        )
        return parts, after

    def _skip_alias(self, tokens: Sequence[_Token], index: int, high: int) -> int:
        """Step over `AS x` or a bare `x` after a write's target.

        A keyword is never mistaken for an alias, because `sqlparse` types `SET` and `WHERE`
        as keywords and this only accepts a name — which is also why `UPDATE t TOP (10) SET`
        is refused rather than read as an alias called `TOP`: what follows the alias must
        still be `SET`.
        """

        if index < high and tokens[index].upper == "AS":
            if index + 1 >= high or not self._is_name_part(tokens[index + 1]):
                raise GuardRefusal(
                    "An alias follows `AS` and the guard cannot read it as a name.",
                    unresolved=("AS",),
                )
            return index + 2
        if index < high and self._is_name(tokens[index]):
            return index + 1
        return index

    def _find_top_level(
        self,
        tokens: Sequence[_Token],
        low: int,
        high: int,
        pairs: dict[int, int],
        words: frozenset[str],
    ) -> int:
        """The index of the first of `words` outside every parenthesis, or -1.

        Depth is the whole point: the `WHERE` inside `SET a = (SELECT x FROM o WHERE y = 1)`
        is the subquery's, and taking it for the statement's would let
        `UPDATE t SET a = (SELECT ... WHERE id = 1)` — which touches every row of `t` — look
        as though it had a predicate.
        """

        index = low
        while index < high:
            token = tokens[index]
            if token.value == "(":
                index = pairs[index] + 1
                continue
            if token.ttype in T.Keyword and token.upper in words:
                return index
            index += 1
        return -1

    def _refuse_top_level(
        self,
        tokens: Sequence[_Token],
        low: int,
        high: int,
        pairs: dict[int, int],
        words: frozenset[str],
        what: str,
    ) -> None:
        """Refuse a clause that would make the statement's target ambiguous."""

        found = self._find_top_level(tokens, low, high, pairs, words)
        if found >= 0:
            word = tokens[found].upper
            raise GuardRefusal(
                f"`{word}` is not part of {what}: it brings in relations the statement's "
                "target is then resolved against, and the guard would be naming one object "
                "while the server wrote another.",
                unresolved=(word,),
            )

    def _require_name_list(
        self,
        tokens: Sequence[_Token],
        low: int,
        high: int,
        what: str,
        *,
        allow_wildcard: bool = False,
        allow_alias: bool = False,
        allow_literals: bool = False,
    ) -> None:
        """Refuse anything but bare names and commas in a list of column or argument names.

        A column list addresses no object, which is why it is stepped over rather than
        walked — but only as long as it really is a list of names.  A function call or a
        parenthesised `SELECT` smuggled into one would read an object the enumeration never
        reported, so the contents are checked rather than assumed.
        """

        index = low
        while index < high:
            token = tokens[index]
            value, upper = token.value, token.upper
            if value == ",":
                index += 1
                continue
            if allow_wildcard and token.ttype is T.Wildcard:
                index += 1
                continue
            if allow_literals and (
                token.ttype in T.Literal.Number
                or (token.ttype in T.Literal.String and token.ttype is not T.Literal.String.Symbol)
            ):
                index += 1
                continue
            if allow_alias and upper in _RETURNING_KEYWORDS:
                index += 1
                continue
            if self._is_name_part(token) and not (
                index + 1 < high and tokens[index + 1].value == "("
            ):
                self._identifier(token)
                index += 1
                continue
            raise GuardRefusal(
                f"The guard expects only names in {what} and found `{value}`.",
                unresolved=(value,),
            )

    def _check_column_definitions(
        self, tokens: Sequence[_Token], low: int, high: int, pairs: dict[int, int]
    ) -> None:
        """Let a `CREATE TABLE` column list through, minus every way it could reach an object.

        The list is not walked as a read and is not allow-listed keyword by keyword either.
        Allow-listing it would mean enumerating every type modifier of four engines —
        `IDENTITY`, `AUTO_INCREMENT`, `UNSIGNED`, `COLLATE`, `CHARACTER SET`, `COMMENT` — and
        the first one missed refuses an ordinary `create-table`.  So the reasoning is
        inverted: a column definition can name *another object* in exactly four ways, and all
        four are refused here.

        - `REFERENCES` — a foreign key ties this table to another one the statement's
          `create` permission says nothing about.
        - `CHECK` and `GENERATED`/`AS` — an expression that can carry a subquery or a call.
        - any `SELECT` — a subquery in a default or a constraint.
        - a call to anything that is not a recognised built-in — a user-defined function in
          a `DEFAULT` reads whatever its body reads.

        What is left is names, type names, literals, punctuation and constraint keywords,
        none of which addresses anything outside the table being created.
        """

        forbidden = {"REFERENCES", "CHECK", "GENERATED", "FOREIGN KEY", "AS"}
        index = low
        while index < high:
            token = tokens[index]
            if token.ttype in (T.Keyword.DML, T.Keyword.DDL, T.Keyword.DCL):
                raise GuardRefusal(
                    f"The guard does not model `{token.upper}` inside a column definition.",
                    unresolved=(token.upper,),
                )
            if token.ttype in T.Keyword and token.upper in forbidden:
                raise GuardRefusal(
                    f"`{token.upper}` in a column definition can reach an object this "
                    "statement does not name, and the guard cannot authorise what it cannot "
                    "name.",
                    unresolved=(token.upper,),
                )
            if self._is_name(token) and index + 1 < high and tokens[index + 1].value == "(":
                parts, _ = self._read_dotted(tokens, index, high)
                if len(parts) > 1 or parts[0].upper not in _BUILTIN_FUNCTIONS:
                    self._check_function(parts)
            index += 1

    # -- is this predicate a filter, or is it a tautology? -------------------------------

    def _effective_where(self, parsed: _Parsed) -> bool:
        """`has_effective_where`, once the statement is already parsed.

        Both callers reach it from one parse, so the answer the broker acts on and the
        references the resolver authorises describe the same reading of the same text.
        """

        tokens = parsed.tokens
        pairs = self._match_parentheses(tokens)
        high = len(tokens)
        where = self._find_top_level(tokens, 0, high, pairs, frozenset({"WHERE"}))
        if where < 0:
            return False
        end = self._find_top_level(tokens, where + 1, high, pairs, _PREDICATE_TERMINATORS)
        return self._predicate_filters(tokens, where + 1, end if end >= 0 else high, pairs)

    def _predicate_filters(
        self, tokens: Sequence[_Token], low: int, high: int, pairs: dict[int, int]
    ) -> bool:
        """Whether this boolean expression can exclude a row.

        Structural, not semantic.  `OR` filters only if *every* arm filters, because one arm
        that is always true carries the whole predicate; `AND` filters if *any* operand does,
        because one operand that filters narrows the result whatever the others say.  Both
        rules are the conservative reading of their connective, and where the two disagree
        the answer is `False`, which asks the human.
        """

        if low >= high:
            return False
        for index in range(low, high):
            token = tokens[index]
            if token.ttype in T.Keyword and token.upper in _UNDECIDABLE_IN_PREDICATE:
                return False

        arms = self._split_predicate(tokens, low, high, pairs, "OR")
        if len(arms) > 1:
            return all(self._predicate_filters(tokens, a, b, pairs) for a, b in arms)
        operands = self._split_predicate(tokens, low, high, pairs, "AND")
        if len(operands) > 1:
            return any(self._predicate_filters(tokens, a, b, pairs) for a, b in operands)

        if tokens[low].ttype in T.Keyword and tokens[low].upper == "NOT":
            # `NOT` cannot turn something that mentions no column into something that does,
            # and it cannot turn a real predicate into a constant, so it is transparent here.
            return self._predicate_filters(tokens, low + 1, high, pairs)

        if tokens[low].value == "(" and pairs.get(low) == high - 1:
            if self._is_subquery(tokens, low, pairs):
                return False
            return self._predicate_filters(tokens, low + 1, high - 1, pairs)

        return self._leaf_filters(tokens, low, high, pairs)

    def _split_predicate(
        self,
        tokens: Sequence[_Token],
        low: int,
        high: int,
        pairs: dict[int, int],
        word: str,
    ) -> list[tuple[int, int]]:
        """Split on `AND`/`OR` at this parenthesis depth, leaving `BETWEEN`'s `AND` alone.

        `BETWEEN 1 AND 5` borrows the conjunction's spelling without being one, and splitting
        there would hand `_leaf_filters` two halves of a range test.  The count is kept rather
        than a flag because `a BETWEEN 1 AND 5 AND b BETWEEN 2 AND 6` has two of each and
        they interleave.
        """

        parts: list[tuple[int, int]] = []
        start = low
        index = low
        pending_between = 0
        while index < high:
            token = tokens[index]
            if token.value == "(":
                index = pairs[index] + 1
                continue
            if token.ttype in T.Keyword:
                words = token.upper.split()
                if "BETWEEN" in words:
                    pending_between += 1
                elif token.upper == word:
                    if word == "AND" and pending_between:
                        pending_between -= 1
                    else:
                        parts.append((start, index))
                        start = index + 1
            index += 1
        parts.append((start, high))
        return parts

    def _leaf_filters(
        self, tokens: Sequence[_Token], low: int, high: int, pairs: dict[int, int]
    ) -> bool:
        """Whether one comparison — the smallest piece with no `AND`/`OR` in it — filters.

        Two ways it does not.  It compares something with itself (`WHERE id = id`, `WHERE
        1 = 1`, `WHERE UPPER(a) = UPPER(a)`), which mentions a column and excludes nothing;
        or it mentions no column at all, which makes it a constant the server evaluates once
        for the whole table.
        """

        cut = -1
        index = low
        while index < high:
            if tokens[index].value == "(":
                index = pairs[index] + 1
                continue
            if tokens[index].ttype is T.Operator.Comparison:
                cut = index
                break
            index += 1
        if cut >= 0:
            # Compared case-insensitively, which on a case-sensitive engine calls `A = a` a
            # self-comparison when it is two columns. That direction asks the human about a
            # predicate that did filter; the other direction runs a tautology unasked.
            left = [token.upper for token in tokens[low:cut]]
            right = [token.upper for token in tokens[cut + 1 : high]]
            if left and left == right:
                return False

        return self._mentions_a_column(tokens, low, high, pairs)

    def _mentions_a_column(
        self, tokens: Sequence[_Token], low: int, high: int, pairs: dict[int, int]
    ) -> bool:
        """Whether anything here reads a value that varies from row to row.

        A subquery's contents do not count.  Telling a correlated subquery — a real per-row
        filter — from an uncorrelated one — a single value the whole table is compared
        against, or an `EXISTS` that is simply true — needs to know which columns belong to
        the statement's own target, and the guard has no catalogue to ask.  Not counting them
        makes `WHERE EXISTS (SELECT ...)` ask the human, which is the safe direction for both
        readings.
        """

        index = low
        while index < high:
            token = tokens[index]
            if token.value == "(":
                closing = pairs[index]
                if not self._is_subquery(tokens, index, pairs) and self._mentions_a_column(
                    tokens, index + 1, closing, pairs
                ):
                    return True
                index = closing + 1
                continue
            if self._is_column_reference(tokens, index, high):
                return True
            index += 1
        return False

    @staticmethod
    def _is_subquery(tokens: Sequence[_Token], opening: int, pairs: dict[int, int]) -> bool:
        """Whether the parenthesis at `opening` holds a query rather than an expression."""

        closing = pairs[opening]
        if opening + 1 >= closing:
            return False
        inner = tokens[opening + 1]
        return inner.ttype is T.Keyword.DML or inner.ttype is T.Keyword.CTE

    def _is_column_reference(self, tokens: Sequence[_Token], index: int, high: int) -> bool:
        """Whether this token is plausibly a column, erring towards saying it is not.

        Three exclusions, all of them in the direction of asking the human.  A placeholder is
        not a column — `WHERE ? = ?` binds two constants.  A name `sqlparse` typed as a
        built-in is a type name, and `WHERE CAST(1 AS INT) = 1` must not count `INT` as the
        column that makes it a filter.  A name spelling a built-in function or type is
        excluded for the same reason even when `sqlparse` types it plainly, which does cost
        something real: a column genuinely called `date`, `year`, `text` or `left` is not
        counted, so `WHERE date = '2020-01-01'` asks for confirmation it did not need.  A
        name followed by `(` is a call, not a column.
        """

        token = tokens[index]
        if not self._is_name(token):
            return False
        if token.ttype is T.Name.Builtin:
            return False
        if token.upper in _BUILTIN_FUNCTIONS:
            return False
        return not (index + 1 < high and tokens[index + 1].value == "(")


@dataclass(slots=True)
class _WalkState:
    """What the scope walk accumulates: the names in scope and the objects found.

    `seen` is carried beside `references` rather than deduplicating at the end so that the
    order objects appear in the statement is the order the operator sees them in a denial
    message — a forty-line query denied on its third table should say so about the third
    table, not about whichever one a set happened to yield first.
    """

    default_schema: str | None
    cte_names: set[str] = field(default_factory=set)
    references: list[Reference] = field(default_factory=list)
    seen: set[Reference] = field(default_factory=set)
