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

"""The `Dialect` abstract base class and the dialect layer's exception hierarchy."""

from __future__ import annotations

import json
import logging
import re
from abc import ABC, abstractmethod
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, ClassVar

import sqlparse
from sqlparse import tokens as _sqltokens

from .types import (
    Capabilities,
    CaseFolding,
    ColumnSpec,
    ConnectionProfile,
    Engine,
    GuardTraits,
    NormalisedRef,
    ObjectRef,
    ObjectType,
    Operator,
    ParamStyle,
    Predicate,
    Query,
    RawPredicate,
    ReadOnlySession,
    Script,
    SecretStr,
    ServerTraits,
    StatementKind,
)

logger = logging.getLogger(__name__)

__all__ = [
    "MAX_WRITE_ROWS",
    "RESERVED_PARAM_NAMES",
    "CapabilityError",
    "DeferredSurface",
    "Dialect",
    "DialectError",
    "DialectNotConfiguredError",
    "DriverNotInstalledError",
    "InvalidIdentifierError",
    "UnknownDriverError",
    "fold_ascii_lower",
    "rewrite_placeholders",
]


# --------------------------------------------------------------------------------------
# Exceptions
# --------------------------------------------------------------------------------------


class DialectError(Exception):
    """Base of every error the dialect layer raises.

    `mcp_server.py` and the GUI's connection-test handler both catch this class and show the
    message verbatim.  Nothing below it should ever surface as a bare traceback: an
    `ImportError` or a `KeyError` reaching the user is a bug in this module, not in theirs.
    """


class UnknownDriverError(DialectError, KeyError):
    """`(engine, driver)` is not a pair the registry knows.

    A corrupt or hand-edited `connections.db` row, never a missing package — that is
    `DriverNotInstalledError`.  Derived from `KeyError` so existing `except KeyError`
    handlers around a registry lookup still catch it, with `__str__` overridden because
    `KeyError.__str__` reprs its argument and would render the message inside quotes.
    """

    def __str__(self) -> str:
        return self.args[0] if self.args else ""


class DriverNotInstalledError(DialectError, ImportError):
    """The DB-API package for a known driver is not importable.

    Carries the exact pip requirement in its message.  Raised only by `import_driver()`;
    `dialect_for()` must succeed with the package absent so the Connections page can show a
    fully built profile with a "driver not installed" state on the test button.
    """


class InvalidIdentifierError(DialectError, ValueError):
    """An identifier cannot be safely quoted or normalised.

    Derived from `ValueError` because §3.2 of `DESIGN-DIALECTS.md` specifies `ValueError`
    for the decision-D6 non-ASCII folding refusal, and callers written against either name
    must both work.
    """


class CapabilityError(DialectError):
    """The engine, at this version and variant, cannot do what was asked.

    Deliberately **not** a `NotImplementedError` subclass: the conformance checklist draws a
    hard line between "this engine has no such feature", which is a permanent, explainable
    answer the GUI greys out a control for, and "d-MCP has not written this yet", which is a
    defect.  Collapsing the two would hide unfinished code behind a plausible message.
    """


class DialectNotConfiguredError(DialectError, RuntimeError):
    """A probe-dependent answer was requested before `configure()` supplied the probe.

    Fail closed.  The alternative — answering from the engine's usual default — is how a
    permission rule silently matches the wrong object on a server whose collation or
    `lower_case_table_names` is not the usual one.
    """


# --------------------------------------------------------------------------------------
# Shared identifier helpers
# --------------------------------------------------------------------------------------


def fold_ascii_lower(name: str, *, engine: Engine | str) -> str:
    """ASCII-lower-fold `name`, refusing any name a full Unicode fold would change (D6).

    The test is exact rather than a character-class guess: fold the ASCII range only, then
    compare against what `str.lower()` would have produced.  If they differ, at least one
    non-ASCII character has a case mapping, and folding it is a decision this layer refuses
    to take.

    `café` passes — lowering it changes nothing, so there is no decision to get wrong.
    `CAFÉ` is refused, because the ASCII-only fold gives `cafÉ` while the server would
    compare it equal to `café`, and two server objects would then own one permission key.
    `İ` (U+0130) is refused because `str.lower()` expands it to two code points, and `ß`
    passes because `str.lower()` leaves it alone — it is `str.casefold()` that would turn it
    into `ss`, and this layer never casefolds.
    """

    folded = "".join(c.lower() if "A" <= c <= "Z" else c for c in name)
    if folded != name.lower():
        raise InvalidIdentifierError(
            f"the identifier {name!r} cannot be case-folded safely on {engine}: it contains "
            "a non-ASCII character with a case mapping, and folding it could collapse two "
            "distinct server objects onto one permission rule. Rename the object, or write "
            "the rule against its exact stored spelling."
        )
    return folded


_OPTION_KEY_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_ ]{0,63}$")


# --------------------------------------------------------------------------------------
# Write-side limits
# --------------------------------------------------------------------------------------

#: The most rows one `insert()` may compose into a single statement — the constant block of
#: `DESIGN-MCP-TOOLS.md` §3.1, alongside `DEFAULT_ROW_LIMIT` and `MAX_ROW_LIMIT`.
#:
#: Enforced *here*, in the builder that composes the multi-row `VALUES` clause, and not only
#: at the tool boundary.  The tool boundary is where a *model* is stopped; this is where a GUI
#: action, a future batch importer and the tool boundary are all stopped by the same number.
#: A batch that overruns is refused rather than split: silently splitting it would turn one
#: statement into several, and the promise that a partial batch never lands would go with it.
MAX_WRITE_ROWS = 1000

#: The forms a `ColumnSpec.default` may take, as a rendered SQL keyword rather than a bound
#: value.  DDL admits no parameter marker on any of the four engines, so a default has to be
#: written into the statement text; the answer is to keep what may be written as small as this
#: list and to reject everything else.  See `Dialect._default_literal()`.
_DEFAULT_KEYWORDS = frozenset(
    {"NULL", "TRUE", "FALSE", "CURRENT_TIMESTAMP", "CURRENT_DATE", "CURRENT_TIME"}
)

#: A plain decimal default, with an optional sign and an optional fractional part.  Bounded in
#: length so a caller cannot put a megabyte of digits into a `CREATE TABLE`.
_DECIMAL_DEFAULT_RE = re.compile(r"^[+-]?(?:\d{1,38})(?:\.\d{1,38})?$")

#: A type name argument list: `(50)`, `(10, 2)` or `(max)`.  Nothing else — no expression, no
#: identifier, no nested parentheses.
_TYPE_ARGS_RE = re.compile(r"^\(\s*(?:(max)|(\d{1,10})(?:\s*,\s*(\d{1,10}))?)\s*\)$", re.IGNORECASE)

#: A collation name.  Validated rather than quoted on three of the four engines because a
#: collation is not an identifier everywhere — MySQL and SQL Server take it as a bare word —
#: so the only protection available is a strict character class.
_COLLATION_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.@$-]{0,127}$")

#: `$tag$` / `$$` — PostgreSQL's dollar quoting, whose tag is an identifier or empty.
_DOLLAR_TAG_RE = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)?\$")

#: Words that open a block whose inner `;` separates statements *within* one routine body
#: rather than ending it.  `CASE` is here because it closes with `END` too, and without it the
#: depth counter would go negative on the first `CASE ... END` and start reading a legitimate
#: body semicolon as a smuggled second statement.
_BLOCK_OPENERS = frozenset({"BEGIN", "CASE"})


@dataclass(frozen=True, slots=True)
class _BodyToken:
    """One lexical piece of a DDL body, as `Dialect._body_tokens()` reads it.

    `kind` is one of `word`, `number`, `quoted`, `literal`, `comment` or `punct`.  The
    distinction that matters is which of them can carry text the server will execute: a
    `word` can, a `literal` and a `comment` cannot — which is exactly why the clause scan
    below reads only the `word` stream, and why an *executable* comment (MySQL's `/*!`) is
    refused outright rather than tokenised as a comment.
    """

    kind: str
    value: str
    text: str
    start: int
    end: int


# --------------------------------------------------------------------------------------
# Shared placeholder rewriting
# --------------------------------------------------------------------------------------

#: Parameter names `select()` mints for itself.  A free-form fragment may not use them: on a
#: mapping paramstyle two entries with one key collapse into one, and whichever of the row cap
#: and the model's value was bound second would silently win.
RESERVED_PARAM_NAMES = frozenset({"row_cap", "row_offset"})

#: The one placeholder spelling d-MCP accepts from a model, whatever the driver underneath.
_NAMED_PLACEHOLDER = re.compile(r"^:[A-Za-z_][A-Za-z0-9_]{0,62}$")


def rewrite_placeholders(
    dialect: Dialect,
    sql: str,
    parameters: Mapping[str, Any] | None,
    *,
    start_index: int = 0,
) -> tuple[str, list[Any], list[str]]:
    """Rewrite `:name` placeholders into the driver's own paramstyle, in text order.

    The model writes one spelling whatever the engine, so a tool's contract does not depend on
    which driver the operator picked for the connection.  Placeholders are located through
    `sqlparse`'s token stream rather than by a regex over the text, so a colon inside a string
    literal or a comment is left alone — that distinction is the difference between binding a
    value and rewriting the statement.

    Lives here, at module level, rather than in `mcp_server.py`, because both `run-read-query`
    and `Dialect.select()`'s free-form `where` fragment need exactly this rewrite, and two
    implementations of it would eventually disagree about what counts as a placeholder — which
    is a parsing difference in the one place a parsing difference is an injection.

    Args:
        dialect: The dialect whose paramstyle the markers are rendered in.
        sql: The statement, or the fragment, as the model wrote it.
        parameters: The values, keyed by placeholder name without the colon.
        start_index: How many parameters the caller has already bound ahead of this text.
            A positional style numbers markers by position, so a fragment composed after a
            row cap must start counting after it.

    Returns:
        The rewritten text, the values in the order their markers appear in it, and their
        names in the same order.  The order is not a convenience: a positional paramstyle
        pairs values to markers by position and nothing else.

    Raises:
        ValueError: A placeholder that is not `:name`, a name with no value, or a value with
            no placeholder.
    """

    supplied = dict(parameters or {})
    statements = sqlparse.parse(sql)
    if not statements:
        raise ValueError("the statement is empty")

    values: list[Any] = []
    names: list[str] = []
    emitted: dict[str, str] = {}
    used: set[str] = set()
    pieces: list[str] = []
    mapping_style = dialect.param_style.is_mapping_style

    for statement in statements:
        for token in statement.flatten():
            if token.ttype is not _sqltokens.Name.Placeholder:
                pieces.append(token.value)
                continue
            spelled = token.value
            if not _NAMED_PLACEHOLDER.match(spelled):
                raise ValueError(
                    f"{spelled!r} is not a placeholder d-MCP accepts: write :name whatever "
                    "the engine and pass the value in `parameters`"
                )
            name = spelled[1:]
            if name not in supplied:
                raise ValueError(f"the statement binds :{name}, which `parameters` does not supply")
            used.add(name)
            if mapping_style and name in emitted:
                # One key, one entry: repeating the value would collide in the mapping the
                # driver is handed, and the second write would win silently.
                pieces.append(emitted[name])
                continue
            marker = dialect.placeholder(start_index + len(values), name)
            values.append(supplied[name])
            names.append(name)
            emitted[name] = marker
            pieces.append(marker)

    unused = sorted(set(supplied) - used)
    if unused:
        raise ValueError(
            f"`parameters` supplies {', '.join(unused)}, which the statement never binds"
        )

    return "".join(pieces), values, names


# --------------------------------------------------------------------------------------
# The abstract base class
# --------------------------------------------------------------------------------------


class Dialect(ABC):
    """Authors SQL for one engine.  Holds no connection and executes nothing (decision D1).

    A dialect is constructed unprobed and is deliberately near-useless in that state: the
    catalogue builders work, but anything version-dependent reports the conservative answer
    and `normalise_identifier()` raises on MS-SQL and MySQL, where the folding rule is a
    property of the server rather than of the engine.  `engine.py` calls `configure()` with
    the probe result immediately after the first successful connect, once per pooled
    connection group.
    """

    engine: ClassVar[Engine]
    display_name: ClassVar[str]
    default_port: ClassVar[int | None]
    default_schema: ClassVar[str | None]
    max_identifier_length: ClassVar[int]

    #: Opening and closing identifier delimiters for this engine.
    quote_open: ClassVar[str] = '"'
    quote_close: ClassVar[str] = '"'

    #: The databases the engine installs for itself.  Used to *mark* rather than to hide
    #: (DESIGN-CONNECTION-SETUP.md §8.2): the flag drives sort order and a muted style, and
    #: a user administering `msdb` must still be able to choose it.  Empty on SQLite, where
    #: a profile has exactly one database and it is the file.
    SYSTEM_DATABASES: ClassVar[frozenset[str]] = frozenset()

    def __init__(self, param_style: ParamStyle, driver: str | None = None) -> None:
        """Bind the dialect to the parameter style — and the identity — of its driver.

        The style comes from the driver, not the engine (decision D4): the same
        `MSSQLDialect` emits `WHERE id = ?` for pyodbc and `WHERE id = %s` for pymssql.

        `driver` is an addition to §3.1's signature, and it is not decoration: PyMySQL and
        mysql-connector-python share an engine *and* a `ParamStyle`, yet want different
        connection keywords (`connect_timeout` against `connection_timeout`), so
        `build_dsn()` cannot tell them apart from the paramstyle alone.  It defaults to
        `None` so the documented one-argument construction still works, and `dialect_for()`
        always supplies it.
        """

        if not isinstance(param_style, ParamStyle):
            param_style = ParamStyle(param_style)
        self._param_style = param_style
        self._driver = driver
        self._traits: ServerTraits | None = None

    def __repr__(self) -> str:
        state = "probed" if self._traits is not None else "unprobed"
        return f"<{type(self).__name__} driver={self._driver!r} {self._param_style.value} {state}>"

    # -- identity ----------------------------------------------------------------------

    @property
    def driver(self) -> str | None:
        """The registry key of the driver this dialect was built for, where one was given."""

        return self._driver

    @property
    def probed(self) -> bool:
        """Whether `configure()` has run.  Cheap enough to test before every risky call."""

        return self._traits is not None

    def configure(self, traits: ServerTraits) -> None:
        """Record what the version probe learned and unlock the version-dependent answers.

        Idempotent, and refuses a second call with different traits — a pool handing one
        dialect instance to connections against two different servers is a bug that would
        make capability answers non-deterministic, and it would do so silently, on whichever
        connection happened to configure the instance first.
        """

        if not isinstance(traits, ServerTraits):
            raise TypeError("configure() takes a ServerTraits")
        if self._traits is not None and self._traits != traits:
            raise DialectError(
                f"{type(self).__name__} is already configured for "
                f"{self._traits.variant} {self._traits.raw_version!r} and cannot be "
                f"reconfigured for {traits.variant} {traits.raw_version!r}: one dialect "
                "instance serves one server."
            )
        self._traits = traits

    @property
    def traits(self) -> ServerTraits:
        """The probe result.  Raises `DialectNotConfiguredError` before `configure()`."""

        if self._traits is None:
            raise DialectNotConfiguredError(
                f"{type(self).__name__} has not been probed yet: engine.py must call "
                "configure() with the result of version_probe_sql() before any "
                "version-dependent answer is available."
            )
        return self._traits

    @property
    @abstractmethod
    def capabilities(self) -> Capabilities:
        """What this connection can do, derived from `traits` where the answer is
        version-dependent and from the engine where it is not.

        Unprobed, every version-dependent flag reads `False`.  Reporting an optimistic
        default here would turn "we do not know yet" into "yes, go ahead", which is the one
        direction a default-deny system must never fail in.
        """

    @property
    @abstractmethod
    def case_folding(self) -> CaseFolding:
        """How this server treats the case of an unquoted identifier.

        Constant for PostgreSQL and SQLite; probe-dependent for MS-SQL (catalogue collation)
        and MySQL (`lower_case_table_names`), where it raises before `configure()`.
        """

    @property
    def param_style(self) -> ParamStyle:
        """The bound driver's PEP 249 paramstyle."""

        return self._param_style

    # -- parameter marshalling ---------------------------------------------------------

    def placeholder(self, index: int, name: str | None = None) -> str:
        """Render one parameter marker for the bound style.

        `?` for qmark, `%s` for format, `%(name)s` for pyformat, `:1` for numeric, `:name`
        for named.  `index` is 0-based; the numeric style renders `index + 1` because PEP 249
        numbers from one.  Every builder in the layer goes through this, so adding a driver
        with a fifth style is one edit rather than four hundred.
        """

        if index < 0:
            raise ValueError("placeholder index is 0-based and cannot be negative")
        style = self._param_style
        if style is ParamStyle.QMARK:
            return "?"
        if style is ParamStyle.FORMAT:
            return "%s"
        if style is ParamStyle.NUMERIC:
            return f":{index + 1}"
        key = name if name is not None else f"p{index}"
        self._check_param_name(key)
        if style is ParamStyle.PYFORMAT:
            return f"%({key})s"
        return f":{key}"

    def parameters(
        self, values: Sequence[Any], names: Sequence[str] | None = None
    ) -> tuple[Any, ...] | dict[str, Any]:
        """Package values in the shape the bound style expects: a tuple, or a mapping."""

        values = tuple(values)
        if not self._param_style.is_mapping_style:
            if names is not None:
                # Not a warning to be tidy: a caller that passes names is expecting a
                # mapping back, and silently handing it a tuple produces a driver error far
                # from here with nothing pointing at the mismatch.
                raise ValueError(
                    f"the {self._param_style.value} paramstyle takes positional parameters; "
                    "names were supplied but cannot be used"
                )
            return values
        if names is None:
            names = [f"p{i}" for i in range(len(values))]
        names = list(names)
        if len(names) != len(values):
            raise ValueError("parameters(): names and values differ in length")
        for key in names:
            self._check_param_name(key)
        if len(set(names)) != len(names):
            raise ValueError("parameters(): duplicate parameter name")
        return dict(zip(names, values, strict=True))

    @staticmethod
    def _check_param_name(name: str) -> None:
        """Reject a parameter name that is not a bare word.

        A mapping key is interpolated into the statement text as `%(key)s`, so it is the one
        piece of a parameterised statement that is not itself a bound value.  Keys are
        generated internally today; validating anyway costs one regex and closes the hole
        before someone routes a column name through here in stage 6.
        """

        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,62}", name or ""):
            raise ValueError(f"unsafe parameter name {name!r}")

    def _raw_where_clause(
        self, where: RawPredicate, values: list[Any], names: list[str]
    ) -> str:
        """Render a free-form `WHERE` fragment, binding its values into the caller's slots.

        Concrete and defined once here rather than copied into the four dialects beside their
        `_where_clause()` twins: nothing in it is engine-specific beyond `placeholder()`, and
        four copies of a fragment-handling routine is four places for the rule about what may
        pass to drift.

        The fragment is emitted **parenthesised**.  That is not cosmetic.  Without the
        brackets, a fragment ending `OR 1 = 1` would rebind against whatever the dialect
        appends next, and a fragment containing its own `ORDER BY` would swallow the one the
        dialect adds after it — in both cases producing a statement that no longer means what
        the caller composed and, on the second, one whose row cap lands in the wrong clause.

        The values are appended to `values`/`names` at the point of call, so they occupy
        exactly the slots the structured `predicates` would have occupied.  On MS-SQL the row
        cap is bound *before* the predicate in the `TOP` form and *after* it in the
        `OFFSET … FETCH` form; a positional paramstyle pairs values to markers by position
        alone, so composing the fragment anywhere but here would bind the cap into the
        predicate without any error to show for it.

        Raises:
            ValueError: The fragment is blank, terminates a statement, or reuses one of
                `RESERVED_PARAM_NAMES`.
        """

        text = where.text.strip()
        if not text:
            raise ValueError(
                "the where fragment is empty; omit it rather than passing a blank string"
            )
        collisions = sorted(set(where.values) & RESERVED_PARAM_NAMES)
        if collisions:
            # Rejected on every paramstyle, not only the mapping ones that would actually
            # collapse the two entries: a fragment that works against pyodbc and corrupts the
            # row cap against pymssql is a far worse failure than a plain refusal.
            raise ValueError(
                f"the where fragment binds {', '.join(':' + c for c in collisions)}, which "
                "select() reserves for the row cap and offset; rename the placeholder"
            )
        for statement in sqlparse.parse(text):
            for token in statement.flatten():
                if token.ttype is _sqltokens.Punctuation and token.value == ";":
                    raise ValueError(
                        "the where fragment ends a statement with ';', which would let a "
                        "second statement ride along behind the first"
                    )
        rendered, bound, bound_names = rewrite_placeholders(
            self, text, where.values, start_index=len(values)
        )
        values.extend(bound)
        names.extend(bound_names)
        return f" WHERE ({rendered})"

    @staticmethod
    def _check_one_where(predicates: Sequence[Predicate], where: RawPredicate | None) -> None:
        """Refuse a call that passes both the structured predicates and a free-form fragment.

        There is no defensible composition of the two: `AND`-ing them silently narrows what
        the caller asked for and choosing one silently discards the other, so this is a bug at
        the call site and is reported as one rather than resolved here.

        Shared by `select()`, `count_matching()`, `update()` and `delete()`, which is why the
        message names "a row operation" rather than `select()`: the same mistake made on a
        `delete()` deserves a message that is about the call the caller actually made.
        """

        if predicates and where is not None:
            raise ValueError(
                "a row operation takes structured predicates or a free-form where fragment, "
                "not both: pass the whole condition one way or the other"
            )

    def _bind(
        self, value: Any, values: list[Any], names: list[str], name: str | None = None
    ) -> str:
        """Append one bound value and return its placeholder.

        The index is the position in the accumulator, so placeholders are numbered in the
        order the values are appended — which is why every builder in the layer appends them
        in the order they appear in the statement text.  A positional paramstyle has no other
        way of pairing the two, and getting it wrong swaps a row cap for a predicate value.

        Lifted out of the four dialects, where it stood four times byte for byte, when the
        write builders needed it too: eight identical copies of the one routine that decides
        what a marker is numbered would be eight places for that numbering to drift.
        """

        index = len(values)
        key = name if name is not None else f"v{index}"
        values.append(value)
        names.append(key)
        return self.placeholder(index, key)

    def _where_clause(
        self, predicates: Sequence[Predicate], values: list[Any], names: list[str]
    ) -> str:
        """Render structured predicates, with every value bound and every column quoted.

        The operator comes from the closed `Operator` enum and is coerced through it here, so
        a caller passing a string gets a `ValueError` rather than having that string reach the
        statement: the operator is the one part of a predicate that is neither a bound value
        nor a quoted identifier, and it must therefore be a member of a set we wrote.

        Lifted out of the four dialects for the same reason as `_bind()`: nothing in it was
        ever engine-specific, and `update()`/`delete()`/`count_matching()` need exactly it.
        """

        fragments: list[str] = []
        for predicate in predicates:
            column = self.quote_identifier(predicate.column)
            operator = Operator(predicate.operator)
            rendered = operator.value.upper()
            if operator in (Operator.IS_NULL, Operator.IS_NOT_NULL):
                fragments.append(f"{column} {rendered}")
            elif operator in (Operator.IN, Operator.NOT_IN):
                if not predicate.values:
                    # `IN ()` is a syntax error on three of the four engines and an always-false
                    # oddity on the fourth; refusing is the only reading that means the same
                    # thing everywhere.
                    raise ValueError(
                        f"the {operator.value} predicate on {predicate.column!r} has no values"
                    )
                marks = ", ".join(
                    self._bind(item, values, names) for item in predicate.values
                )
                fragments.append(f"{column} {rendered} ({marks})")
            elif operator is Operator.BETWEEN:
                if len(predicate.values) != 2:
                    raise ValueError(
                        f"the between predicate on {predicate.column!r} takes exactly two "
                        "values"
                    )
                low = self._bind(predicate.values[0], values, names)
                high = self._bind(predicate.values[1], values, names)
                fragments.append(f"{column} BETWEEN {low} AND {high}")
            else:
                fragments.append(
                    f"{column} {rendered} {self._bind(predicate.value, values, names)}"
                )
        return " WHERE " + " AND ".join(fragments) if fragments else ""

    def _condition(
        self,
        predicates: Sequence[Predicate],
        where: RawPredicate | None,
        values: list[Any],
        names: list[str],
    ) -> str:
        """One `WHERE` clause from whichever of the two forms the caller used, or none at all.

        The empty answer is a legitimate one and is *not* refused here.  `update()` and
        `delete()` with no condition are legal, destructive requests: the layer that stops
        them is `confirmation.py`, which cannot broker a statement this layer declined to
        compose.  Refusing here would look like safety and would in fact only mean the human
        never got the chance to say no.
        """

        self._check_one_where(predicates, where)
        if where is not None:
            return self._raw_where_clause(where, values, names)
        return self._where_clause(predicates, values, names)

    # -- quoting and normalisation -----------------------------------------------------

    @abstractmethod
    def quote_identifier(self, name: str) -> str:
        """Wrap `name` in this engine's identifier delimiters, doubling any inner delimiter.

        Raises `InvalidIdentifierError` for an embedded NUL, for a name exceeding
        `capabilities.max_identifier_length`, and for the engine's own additional
        prohibitions (MySQL forbids a trailing space; MS-SQL forbids a name that is entirely
        whitespace).  It never returns unquoted output: quoting unconditionally is what makes
        a reserved word, a space or an accent a non-event, and it costs nothing.
        """

    def _quote(self, name: str, *, max_length: int | None = None) -> str:
        """The shared body of `quote_identifier()`: validate, double, wrap.

        Length is measured in characters here.  PostgreSQL overrides that with a byte count,
        because `NAMEDATALEN - 1` is 63 *bytes* and an accented name reaches the limit sooner
        than its length suggests — silently truncated by the server, which is exactly the
        collision this method exists to prevent.
        """

        if not isinstance(name, str):
            raise InvalidIdentifierError(f"an identifier must be a str, not {type(name).__name__}")
        if name == "":
            raise InvalidIdentifierError("an empty identifier cannot be quoted")
        if "\x00" in name:
            raise InvalidIdentifierError(
                "the identifier contains an embedded NUL; no engine accepts one and several "
                "C client libraries would truncate the name at it, silently addressing a "
                "different object"
            )
        limit = self.max_identifier_length if max_length is None else max_length
        if len(name) > limit:
            raise InvalidIdentifierError(
                f"the identifier is {len(name)} characters, over {self.display_name}'s limit "
                f"of {limit}"
            )
        return f"{self.quote_open}{name.replace(self.quote_close, self.quote_close * 2)}{self.quote_close}"

    #: The schema name a permission rule uses on an engine that has no schema layer.
    #: `None` where the engine has real schemas and the catalogue supplies them; `"main"` on
    #: SQLite, per DESIGN-PERMISSIONS.md §5.5 — `rule_targets.schema_pattern` is NOT NULL, so a
    #: schema-less reference needs a canonical stand-in rather than a `None` the resolver
    #: would have to special-case. It deliberately does *not* affect emitted SQL: `quote_ref()`
    #: still omits the schema on any engine whose `capabilities.supports_schemas` is `False`.
    addressable_schema: ClassVar[str | None] = None

    def quote_ref(self, ref: ObjectRef | NormalisedRef) -> str:
        """Quote a schema-qualified name, omitting the schema part where the engine has none.

        "Has none" is `capabilities.supports_schemas`, not `default_schema is None`: the
        latter is also true on MySQL, where it would emit a bare name and let the server
        resolve it against whatever database the session happens to be using rather than the
        one the permission check authorised.
        """

        if isinstance(ref, NormalisedRef):
            schema, name = ref.canonical_schema, ref.canonical_name
        else:
            schema, name = ref.schema, ref.name
        if schema is None or not self.capabilities.supports_schemas:
            return self.quote_identifier(name)
        return f"{self.quote_identifier(schema)}.{self.quote_identifier(name)}"

    @abstractmethod
    def normalise_identifier(self, raw: str, *, quoted: bool = False) -> str:
        """Return the form the server's catalogue holds for `raw`.

        `quoted` says whether the identifier reached us already delimited, which changes the
        answer on PostgreSQL: unquoted `Foo` becomes `foo`, quoted `"Foo"` stays `Foo`, and
        they are two different tables that can coexist in one schema.

        Raises `InvalidIdentifierError` (a `ValueError`) for a non-ASCII identifier that
        would need case folding, rather than folding it (decision D6), and raises
        `DialectNotConfiguredError` before `configure()` wherever the rule is probe-dependent.
        Fail closed: a guessed identifier is a permission rule matching the wrong object.
        """

    @abstractmethod
    def identifier_match_key(self, name: str) -> str:
        """Return the key `permissions.resolve()` compares against a rule pattern.

        Distinct from `normalise_identifier()` (decision D5).  On PostgreSQL the two
        coincide.  On MS-SQL under the usual `..._CI_AS` collation the canonical form is
        `Salaries` while the match key is `salaries`; under a `..._CS_AS` collation the match
        key is `Salaries` and a rule written for `salaries` correctly fails to match.  On
        MySQL the answer differs for table names and column names, so callers must pass a
        table name here only through `normalise_ref()` and a column name through
        `column_match_key()`.
        """

    def column_match_key(self, name: str) -> str:
        """The match key for a *column* name, which is not always the object-name rule.

        An addition to §3.2, which states the divergence — "column, index, stored-routine and
        event names are always case-insensitive on every platform" on MySQL — and then leaves
        `identifier_match_key()` unable to express it.  Everywhere except MySQL the two
        answers coincide, so the default delegates.
        """

        return self.identifier_match_key(name)

    def normalise_ref(self, ref: ObjectRef) -> NormalisedRef:
        """Canonicalise and key a whole object reference in one step.

        Applies the engine's default schema where `ref.schema` is `None` and the engine has
        schemas — except that the MCP tools require an explicit schema, so this path is only
        reached from the GUI and from introspection results, never from LLM input.

        The test is `capabilities.supports_schemas`, and it has to be: `default_schema` says
        whether the engine has a *compile-time* default, which is a different question.  It
        is `None` on MySQL not because MySQL lacks schemas — a MySQL database is a schema —
        but because the answer is the session's current database and is only known once the
        probe has run.  Keying off it therefore discarded a schema the caller had supplied,
        so `describe_table(ObjectRef("otherdb", "t"))` silently described `t` in the
        connection's own database, and the resulting `key_schema=None` matched no rule that
        introspection had populated with the real name.  Where the engine genuinely has no
        schema layer the key still needs a value — `rule_targets.schema_pattern` is NOT NULL — and
        that is `addressable_schema`, `main` on SQLite (DESIGN-PERMISSIONS.md §5.5), which
        is also what `Introspector._ref_for()` mints so the two paths key alike.
        """

        schema: str | None = ref.schema
        if not self.capabilities.supports_schemas:
            schema = self.addressable_schema
        elif schema is None:
            schema = self.effective_default_schema()

        canonical_schema = self.normalise_identifier(schema) if schema is not None else None
        canonical_name = self.normalise_identifier(ref.name)
        return NormalisedRef(
            canonical_schema=canonical_schema,
            canonical_name=canonical_name,
            key_schema=(
                self.identifier_match_key(canonical_schema) if canonical_schema is not None else None
            ),
            key_name=self.identifier_match_key(canonical_name),
            object_type=ref.object_type,
        )

    def effective_default_schema(self) -> str | None:
        """The schema an unqualified name resolves against: the probed one, else the class
        default.  `SCHEMA_NAME()` on MS-SQL and `current_schema()` on PostgreSQL can both
        differ per login, and defaulting to `dbo`/`public` for a user whose default schema is
        something else addresses the wrong object."""

        if self._traits is not None and self._traits.default_schema:
            return self._traits.default_schema
        return self.default_schema

    def is_valid_identifier(self, raw: str) -> bool:
        """Cheap pre-flight for the GUI's inline validation.  Never a substitute for
        `quote_identifier()`, which is the enforcing call."""

        try:
            self.quote_identifier(raw)
        except (InvalidIdentifierError, TypeError):
            return False
        return True

    # -- what the guard borrows --------------------------------------------------------

    @abstractmethod
    def guard_traits(self) -> GuardTraits:
        """Grammar facts the guard needs and cannot get from `sqlparse` alone, in one call
        (decision D8).  Constant per engine — none of these facts are version-dependent, so
        this never consults `traits` and is callable before `configure()`.
        """

    # -- connection --------------------------------------------------------------------

    @abstractmethod
    def build_dsn(self, profile: ConnectionProfile) -> str | dict[str, Any]:
        """Assemble the connection string or keyword mapping for the bound driver —
        **without the password**.

        `profile` is the mapping `ConnectionStore` yields: `display_name, engine, driver,
        host, port, database, username, options_json, statement_timeout_s`.  The secret is
        never one of its keys and is never part of the result, so the value returned here is
        safe to log, to show on the Connections page and to put in an exception message.

        Where the driver only accepts a single string (pyodbc), `engine.py` calls
        `with_password()` immediately before `connect()`, inside a `try/finally` that clears
        the local name.
        """

    def with_password(self, dsn: str | dict[str, Any], password: SecretStr | str) -> str | dict[str, Any]:
        """Return `dsn` with the secret added, for use at the `connect()` call and nowhere else.

        An addition to §3.7, which specifies the `try/finally` substitution without saying who
        owns the escaping.  It has to be the dialect: ODBC's rule (wrap in braces, double an
        inner `}`) is not something `engine.py` should be reimplementing, and getting it wrong
        turns a password containing a semicolon into an injected connection-string keyword.

        The result is *not* safe to log.  Every caller must treat it as the secret it now is.
        """

        secret = password.get_secret_value() if isinstance(password, SecretStr) else password
        if isinstance(dsn, dict):
            return {**dsn, "password": secret}
        raise NotImplementedError(
            f"{type(self).__name__} returns a mapping DSN; override with_password() if it "
            "returns a string"
        )

    @abstractmethod
    def health_check_sql(self) -> str:
        """The cheapest statement that proves the connection is alive and the session usable.

        `SELECT 1` on three engines; SQLite offers `PRAGMA quick_check` behind a keyword, for
        the first check of a session, because a corrupt file is the SQLite-specific failure
        mode and it is silent until it is not.
        """

    def health_check(self) -> Query:
        """`health_check_sql()` wrapped as a `Query`, which is the §3.7 spelling."""

        return Query(sql=self.health_check_sql(), params=self.parameters(()), kind=StatementKind.READ)

    @abstractmethod
    def version_probe_sql(self) -> str:
        """One statement returning one row whose columns build a `ServerTraits`.

        §3.7 specifies `version_probe() -> tuple[Query, ...]` on the grounds that MS-SQL needs
        three statements and MySQL two.  They collapse into one `SELECT` of several columns on
        every engine, which is what this returns, and `version_probe()` below still offers the
        documented tuple shape.  One round trip, one row, one fixed column order that
        `parse_traits()` is written against.
        """

    def version_probe(self) -> tuple[Query, ...]:
        """`version_probe_sql()` wrapped as the §3.7 tuple of `Query` objects."""

        return (Query(sql=self.version_probe_sql(), params=self.parameters(()), kind=StatementKind.READ),)

    @classmethod
    @abstractmethod
    def parse_traits(cls, rows: Sequence[Sequence[Any]]) -> ServerTraits:
        """Turn the probe results into `ServerTraits`.

        `rows` is what the cursor returned for `version_probe_sql()`: a sequence of rows, of
        which only the first is read, its columns in the order that statement selects them.

        Refuses a server d-MCP does not support: a PostgreSQL wire-protocol impostor
        (CockroachDB, Redshift, Greenplum) is rejected by name here rather than half-working
        for three tool calls and then failing inside `pg_get_functiondef`.
        """

    # -- session hardening --------------------------------------------------------------

    @abstractmethod
    def read_only_session(self) -> ReadOnlySession:
        """The statements that make one session refuse to write, and undo that again.

        This is the second line of defence behind `sql_guard` on every read path
        (DESIGN-MCP-TOOLS.md §9.1 step 11).  The guard decides what d-MCP is willing to send;
        this decides what the server is willing to accept.  A guard that is the only line of
        defence is one bug away from being none, so the two are deliberately independent: the
        hardening knows nothing about the statement and the guard knows nothing about the
        session.

        Abstract rather than defaulting to "no hardening", because a fifth engine added later
        must state its answer out loud.  An engine that genuinely cannot harden a session has
        to say so in a `ReadOnlySession` with an empty `harden` and a `note` explaining it,
        which is a code review; inheriting silence is not.

        Returns:
            The plan `engine.read_only_session()` executes.  Nothing here runs any of it —
            a dialect holds no connection and executes nothing (decision D1).
        """

    @abstractmethod
    def statement_timeout_statements(self, seconds: int) -> tuple[Query, ...]:
        """Session-level statements that bound how long one statement may run.

        Applied once per connection out of the profile's `statement_timeout_s`
        (DESIGN-MCP-TOOLS.md §6.1 and §13 decision 2).  There is no per-call override
        anywhere above this: the budget belongs to whoever configured the connection.

        An empty tuple is a legitimate answer and means "this engine has no session-level
        control"; `engine.py` then falls back to the driver's own attribute, which is the
        only place SQL Server and SQLite have one.  The `note` for that case belongs in the
        implementing dialect's docstring.

        Args:
            seconds: A whole number of seconds, greater than zero.  The value is rendered
                into the statement text as an integer literal — the one place in this layer
                where a value is not bound — because no engine accepts a parameter in a `SET`.
                Every implementation therefore runs it through :meth:`_timeout_literal`
                first, which refuses anything that is not a plain positive integer.
        """

    def _session_statement(self, sql: str) -> Query:
        """Package one parameterless session-control statement for `engine.py`.

        The `kind` is `READ` throughout the hardening plans: none of these statements reads
        or writes a row, and none of them ever reaches `sql_guard`, which only ever sees SQL
        the model wrote.  The field is carried because `Query` is the shape `engine.py`
        executes, not because the guard will classify it.
        """

        return Query(sql=sql, params=self.parameters(()), kind=StatementKind.READ)

    @staticmethod
    def _timeout_literal(seconds: int, *, maximum: int = 86_400) -> int:
        """Validate a timeout before it is rendered into statement text.

        The guarantee the callers rely on is narrow and total: the return value is a Python
        `int`, strictly positive and bounded, so `f"SET statement_timeout = {value}"` cannot
        carry anything but digits however the profile was written or edited.
        """

        if isinstance(seconds, bool) or not isinstance(seconds, int):
            raise DialectError(f"a statement timeout must be a whole number of seconds, got {seconds!r}")
        if seconds <= 0:
            raise DialectError(f"a statement timeout must be greater than zero, got {seconds!r}")
        if seconds > maximum:
            raise DialectError(f"a statement timeout of {seconds} s exceeds the {maximum} s ceiling")
        return int(seconds)

    # -- the interpolation point that was deleted rather than implemented ---------------
    #
    # `_password_literal()` used to stand here, reserved by §3.8 of `DESIGN-DIALECTS.md` as
    # "the single interpolation point in `src/sape_d_mcp/db/`" and left unimplemented until
    # the security surface arrived.  Stage 8 deleted it instead of writing it, and the reason
    # is the whole of `DESIGN-MCP-TOOLS.md` §11.2, which is the newer document and emphatic:
    #
    #     **`create-user` takes no password, by design.** No credential is ever accepted from
    #     a model, generated by a tool, returned in a result or written to a log.
    #
    # `create_user()` therefore has no password to render.  It emits a principal that cannot
    # log in — `WITHOUT LOGIN` on SQL Server, `NOLOGIN` on PostgreSQL, `ACCOUNT LOCK` on
    # MySQL — and a human sets the credential outside d-MCP, at the server.
    #
    # Removing the method is a stronger outcome than auditing it.  §3.8 asked for an
    # allow-list, a NUL check, a newline check and a quote-doubling rule, all of them
    # defending one string on its way into statement text; the whole defence is unnecessary
    # once there is no string.  What is left in this file that is not a bound parameter is
    # `_default_literal()` and `_collate_clause()`, both of which say so in their own
    # docstrings, and neither of which ever handles a secret.
    #
    # The knock-on effects §3.8 anticipated go with it: there is no password to redact from
    # the audit record, none to keep out of a traceback, and no server-side statement log —
    # PostgreSQL's `log_statement = 'ddl'`, an MS-SQL audit specification — that could ever
    # record one, because d-MCP never sends one.
    #
    # Do not reinstate this method to make a feature work.  A feature that needs it is a
    # feature that accepts a credential from a model, which is the thing §11.2 forbids.

    # -- profile helpers ---------------------------------------------------------------

    @staticmethod
    def _profile_options(profile: ConnectionProfile) -> dict[str, Any]:
        """Decode `options_json` into a validated mapping of extra driver options.

        Hand-editable through the GUI, so it is parsed defensively: it must be an object, its
        keys must be bare words, and its values must be scalars.  A nested structure or an
        exotic key is refused rather than flattened, because the two engines whose connection
        form is a *string* would then have that structure interpolated into it.
        """

        raw = profile.get("options_json")
        if raw in (None, "", b""):
            return {}
        if isinstance(raw, dict):
            decoded: Any = raw
        else:
            try:
                decoded = json.loads(raw)
            except (TypeError, ValueError) as exc:
                raise DialectError(f"options_json is not valid JSON: {exc}") from exc
        if not isinstance(decoded, dict):
            raise DialectError("options_json must be a JSON object")
        options: dict[str, Any] = {}
        for key, value in decoded.items():
            if not isinstance(key, str) or not _OPTION_KEY_RE.match(key):
                raise DialectError(f"options_json key {key!r} is not a bare word")
            if not isinstance(value, (str, int, float, bool)) or isinstance(value, bytes):
                raise DialectError(f"options_json value for {key!r} must be a scalar")
            options[key] = value
        return options

    def _profile_port(self, profile: ConnectionProfile) -> int | None:
        """The port from the profile, else the engine default, validated as a real port."""

        port = profile.get("port")
        if port in (None, ""):
            return self.default_port
        try:
            port = int(port)
        except (TypeError, ValueError) as exc:
            raise DialectError(f"port {profile.get('port')!r} is not an integer") from exc
        if not 1 <= port <= 65535:
            raise DialectError(f"port {port} is outside 1-65535")
        return port

    def _profile_auth_mode(self, profile: ConnectionProfile, *, default: str = "password") -> str:
        """How this profile proves who it is, validated against the closed domain.

        `default` exists for SQLite alone, whose rows are pinned to `'none'`: everywhere
        else an absent `auth_mode` means `'password'`, which is what every profile written
        before schema version 2 meant, so an existing caller is unaffected.

        The import is local to the method rather than at module scope only to keep the
        dialect layer's import graph a tree: `auth_modes` is a leaf that imports nothing of
        ours, and nothing here should tempt a future edit into the reverse direction.
        """

        from ..auth_modes import AUTH_MODES

        value = profile.get("auth_mode")
        if value in (None, ""):
            return default
        mode = str(value).strip().lower()
        if mode not in AUTH_MODES:
            raise DialectError(
                f"auth_mode {value!r} is not one of {', '.join(AUTH_MODES)}"
            )
        return mode

    def _refuse_integrated(self, profile: ConnectionProfile, driver: str) -> None:
        """Raise the matrix's own sentence if this profile asks for the impossible.

        The belt-and-braces third layer of DESIGN-CONNECTION-SETUP.md §4.2.  The GUI
        disables the combo item and `ConnectionStore._validate()` refuses the profile, so
        reaching here means a hand-edited `connections.db` — which must fail with a sentence
        naming the cause, not with DB-Lib 20009 pointing at a firewall that is innocent.

        `driver` is passed rather than read from `self.driver`, which is `None` for a
        dialect built the documented one-argument way; each caller knows which of its
        drivers it is serving, and a lookup that guessed would answer for the wrong one.
        """

        from ..auth_modes import message_for, support_for

        if self._profile_auth_mode(profile) != "integrated":
            return
        support = support_for(str(self.engine), driver)
        if not support.supported:
            raise DialectError(message_for(support))

    @staticmethod
    def _profile_timeout(profile: ConnectionProfile) -> int | None:
        """`statement_timeout_s` as a non-negative integer, or `None` when unset."""

        value = profile.get("statement_timeout_s")
        if value in (None, ""):
            return None
        try:
            value = int(value)
        except (TypeError, ValueError) as exc:
            raise DialectError(f"statement_timeout_s {value!r} is not an integer") from exc
        if value < 0:
            raise DialectError("statement_timeout_s cannot be negative")
        return value

    @staticmethod
    def _require(profile: ConnectionProfile, key: str) -> str:
        """Read a profile field that has no sensible default and must not be blank."""

        value = profile.get(key)
        if value is None or str(value).strip() == "":
            raise DialectError(f"the connection profile has no {key}")
        return str(value)

    def _unsupported(self, feature: str, reason: str) -> CapabilityError:
        """Build the `CapabilityError` the MCP tool boundary shows verbatim.

        The wording is fixed here rather than at each call site so every engine's refusal
        reads the same way in the tool result and under the greyed-out GUI control:
        `'create_role' is not supported by sqlite — SQLite has no server-side principals`.
        """

        return CapabilityError(f"{feature!r} is not supported by {self.engine} — {reason}")

    def _stage(self, method: str, stage: int) -> NotImplementedError:
        """The placeholder every not-yet-written builder raises, naming the stage.

        Distinct from `CapabilityError` on purpose: this one means d-MCP has not written the
        code, and it must never be mistaken for "the engine cannot do that".
        """

        return NotImplementedError(
            f"{type(self).__name__}.{method}() is scheduled for stage {stage} and is not "
            "implemented yet"
        )

    # -- the write and DDL composition kit ---------------------------------------------

    #: The clause spellings a `create_*` builder refuses, in **both** the body it was handed
    #: and the DDL it generates (DESIGN-MCP-TOOLS.md §8.1).  Empty here on purpose: a dialect
    #: that has not enumerated its own engine's spellings cannot compose a `create_*`, because
    #: `_reject_or_replace()` fails closed on an empty list.  Adding a fifth engine therefore
    #: has to state out loud what "replace" is called there, rather than inheriting silence.
    #:
    #: Each entry is a phrase matched against the statement's **word stream** — comments,
    #: string literals and quoted identifiers removed, runs of whitespace collapsed to one
    #: space, everything upper-cased — so `CREATE /*x*/ OR\n REPLACE VIEW` matches the same
    #: pattern as `CREATE OR REPLACE VIEW`.
    or_replace_spellings: ClassVar[tuple[str, ...]] = ()

    #: Whether a backslash escapes the next character inside a string literal.  True only on
    #: MySQL/MariaDB, and only while `NO_BACKSLASH_ESCAPES` is off — which is the default and
    #: the case this layer assumes, because assuming the other way would let `'\'` close a
    #: literal the server would have left open and hand the scanner text as code.
    backslash_escapes_strings: ClassVar[bool] = False

    #: Whether `$tag$ ... $tag$` is a string literal here.  PostgreSQL only, and it matters:
    #: a PL/pgSQL body lives inside one, semicolons and all.
    dollar_quoted_strings: ClassVar[bool] = False

    #: The base type names `create_table()` will emit, lower-cased, in the engine's own
    #: vocabulary (DESIGN-DIALECTS.md §3.4).  No portable type language is invented: a silent
    #: `TEXT`-for-`NVARCHAR(MAX)` substitution is a data-loss bug wearing a convenience
    #: costume.  Empty here so a dialect that has declared no vocabulary cannot create a table.
    column_types: ClassVar[frozenset[str]] = frozenset()

    #: Whether `varchar(max)` — a length of `max` rather than a number — is spellable.
    supports_max_length_argument: ClassVar[bool] = False

    #: Whether a type may carry a trailing `[]` (PostgreSQL arrays).
    supports_array_types: ClassVar[bool] = False

    #: Whether one routine name may denote more than one object on this engine.  True on
    #: PostgreSQL alone: `add(integer, integer)` and `add(text, text)` are two functions
    #: sharing a name, and `DROP FUNCTION add` is refused by the server as ambiguous while
    #: both exist.  MS-SQL permits no overloading of user functions, MySQL none, and SQLite
    #: has no stored routine at all — so on those three an argument list is *refused* rather
    #: than ignored, exactly as `quote_principal()` refuses a MySQL `host`.
    overloads_routines: ClassVar[bool] = False

    #: Spellings that name the same type as each other, lower-cased, used **only** to compare
    #: a caller's argument list against the overloads the catalogue reported.  Never used to
    #: emit anything: what reaches a statement is rendered by `_render_argument_type()` from
    #: the caller's own spelling or refused, so a wrong entry here can make a match fail but
    #: can never make d-MCP address a type the caller did not name.
    type_aliases: ClassVar[Mapping[str, str]] = {}

    #: Type modifiers admitted after the base name, upper-cased.  MySQL's `UNSIGNED` and
    #: `ZEROFILL`; nothing anywhere else.
    type_modifiers: ClassVar[frozenset[str]] = frozenset()

    #: The most bound parameters one statement may carry, where the engine has a hard ceiling.
    #: `None` means the limit is a packet size rather than a count and cannot be checked here.
    max_bound_parameters: ClassVar[int | None] = None

    #: The most row tuples one `INSERT ... VALUES` may list, where the engine caps it.
    max_insert_value_rows: ClassVar[int | None] = None

    def _supports_drop_if_exists(self) -> bool:
        """Whether `DROP <object> IF EXISTS` is spellable on this server.

        A method rather than a flag because it is version-dependent on SQL Server, where the
        clause arrived in 2016.  Everywhere else it has been available for longer than the
        oldest server d-MCP will connect to.
        """

        return True

    def _body_tokens(self, sql: str) -> list[_BodyToken]:
        """Lex a DDL body far enough to tell code from text, and no further.

        Not a parser and not trying to be one: a routine body is a whole procedural language
        and §3.4 says so.  What this does is separate the characters the server will execute
        from the characters it will merely store — string literals, dollar-quoted bodies,
        quoted identifiers and comments — so that the two checks that follow can read only the
        first.  Those two checks are the whole of the security value: a smuggled second
        statement, and a smuggled `OR REPLACE`.

        An **executable comment** is refused rather than tokenised.  MySQL's `/*!40001 ... */`
        is a comment to every other reader and code to MySQL, so treating it as a comment here
        would mask exactly the text the server is going to run.  A batch separator (`GO`) is
        refused for the same reason: it is not a comment and not a statement, and every reader
        that ignores it is reading a different program from the one the client will send.

        Raises:
            ValueError: An unterminated literal or comment, an executable comment, or a batch
                separator.
        """

        if not isinstance(sql, str):
            raise ValueError(f"a SQL body must be text, not {type(sql).__name__}")
        traits = self.guard_traits()
        if traits.executable_comment_pattern is not None and traits.executable_comment_pattern.search(sql):
            raise ValueError(
                "the body contains an executable comment, which this engine runs and every "
                "other reader ignores; d-MCP will not compose a statement it cannot read the "
                "same way the server will"
            )
        if traits.batch_separator_pattern is not None and traits.batch_separator_pattern.search(sql):
            raise ValueError(
                "the body contains a batch separator, which would split it into more than one "
                "statement; d-MCP composes one statement at a time"
            )

        block_open, block_close = traits.block_comment_delimiters
        line_prefixes = tuple(sorted(traits.line_comment_prefixes, key=len, reverse=True))
        bracket_identifiers = self.quote_open == "[" and self.quote_close == "]"

        tokens: list[_BodyToken] = []
        index, length = 0, len(sql)
        while index < length:
            char = sql[index]
            if char.isspace():
                index += 1
                continue
            if block_open and sql.startswith(block_open, index):
                stop = sql.find(block_close, index + len(block_open))
                if stop < 0:
                    raise ValueError("the body has an unterminated block comment")
                stop += len(block_close)
                tokens.append(_BodyToken("comment", sql[index:stop], "", index, stop))
                index = stop
                continue
            prefix = next((p for p in line_prefixes if sql.startswith(p, index)), None)
            if prefix is not None:
                stop = sql.find("\n", index)
                stop = length if stop < 0 else stop
                tokens.append(_BodyToken("comment", sql[index:stop], "", index, stop))
                index = stop
                continue
            if self.dollar_quoted_strings and char == "$":
                opener = _DOLLAR_TAG_RE.match(sql, index)
                if opener is not None:
                    tag = opener.group(0)
                    stop = sql.find(tag, opener.end())
                    if stop < 0:
                        raise ValueError(f"the body has an unterminated {tag} quoted string")
                    stop += len(tag)
                    tokens.append(
                        _BodyToken("literal", sql[index:stop], sql[opener.end():stop - len(tag)], index, stop)
                    )
                    index = stop
                    continue
            if char in ("'", '"', "`") or (bracket_identifiers and char == "["):
                closer = "]" if char == "[" else char
                kind = "literal" if char == "'" else "quoted"
                body, stop = self._read_delimited(sql, index, char, closer)
                tokens.append(_BodyToken(kind, sql[index:stop], body, index, stop))
                index = stop
                continue
            if char.isalpha() or char == "_":
                stop = index + 1
                while stop < length and (sql[stop].isalnum() or sql[stop] in "_$"):
                    stop += 1
                tokens.append(_BodyToken("word", sql[index:stop], sql[index:stop], index, stop))
                index = stop
                continue
            if char.isdigit():
                stop = index + 1
                while stop < length and (sql[stop].isalnum() or sql[stop] == "."):
                    stop += 1
                tokens.append(_BodyToken("number", sql[index:stop], sql[index:stop], index, stop))
                index = stop
                continue
            tokens.append(_BodyToken("punct", char, char, index, index + 1))
            index += 1
        return tokens

    def _read_delimited(self, sql: str, start: int, opener: str, closer: str) -> tuple[str, int]:
        """Read one delimited run, honouring the doubling escape and, where the engine has
        one, the backslash escape.  Returns the content and the index just past the closer."""

        index = start + 1
        pieces: list[str] = []
        length = len(sql)
        while index < length:
            char = sql[index]
            if self.backslash_escapes_strings and opener == "'" and char == "\\" and index + 1 < length:
                pieces.append(sql[index + 1])
                index += 2
                continue
            if char == closer:
                if index + 1 < length and sql[index + 1] == closer:
                    pieces.append(closer)
                    index += 2
                    continue
                return "".join(pieces), index + 1
            pieces.append(char)
            index += 1
        raise ValueError(f"the body has an unterminated {opener}-delimited run")

    @staticmethod
    def _word_stream(tokens: Sequence[_BodyToken]) -> str:
        """The statement's executable words, upper-cased and single-spaced.

        Literals, comments and quoted identifiers are dropped, so what remains is the clause
        structure and nothing a caller can hide a clause inside.
        """

        return " ".join(token.value.upper() for token in tokens if token.kind == "word")

    def _reject_or_replace(self, tokens: Sequence[_BodyToken], *, what: str) -> None:
        """Refuse every spelling of "replace the object that is already there" (§8.1).

        This is the whole of the difference between `create-function` and `edit-function`.
        `edit_*` was brokered — a human saw the statement and approved it — and `create_*` is
        not, because creating something that did not exist destroys nothing.  A `create_*` that
        accepted `OR REPLACE` would therefore be `edit_*` authorised by the wrong permission
        flag.  Since ADR 0005 the `edit` action is never granted and the edit tools are refused
        before the broker is reached, so this check no longer decides which approval is asked
        for but whether an object that already exists is replaced at all.

        Fails closed on a dialect that has enumerated nothing: an empty `or_replace_spellings`
        means the engine's spellings were never written down, which is not the same as there
        being none.
        """

        if not self.or_replace_spellings:
            raise DialectError(
                f"{type(self).__name__} has not enumerated its OR REPLACE spellings, so it "
                "will not compose a create statement: a create that cannot recognise a "
                "replace is an edit under the create flag, and d-MCP replaces no object that "
                "already exists (docs/adr/0005)"
            )
        stream = self._word_stream(tokens)
        for phrase in self.or_replace_spellings:
            if re.search(rf"(?:^|\b){re.escape(phrase)}(?:\b|$)", stream):
                raise ValueError(
                    f"{what} may not contain {phrase!r}: replacing an object that already "
                    "exists destroys the previous one, and d-MCP never destroys an object "
                    "(docs/adr/0005). Redefining or removing an object that is already there "
                    "is a job for a database client."
                )

    def _reject_trailing_statement(self, tokens: Sequence[_BodyToken], *, what: str) -> None:
        """Refuse a second statement riding behind the first.

        The test is a `;` at block depth zero that is not the body's final token.  Depth is
        counted from `BEGIN`/`CASE` up and `END` down, because a routine body's own semicolons
        live inside a block and are part of one statement as far as the client is concerned,
        while a `;` outside every block ends the statement and starts another.

        The limitation is worth stating rather than discovering: a T-SQL procedure written
        without `BEGIN … END` and containing two statements is refused here, and the fix is to
        wrap the body in `BEGIN … END`, which is how such a procedure is normally written
        anyway.  Refusing a legitimate body is a message; admitting an illegitimate one is a
        `DROP`.
        """

        depth = 0
        executable = [token for token in tokens if token.kind != "comment"]
        for position, token in enumerate(executable):
            if token.kind == "word":
                upper = token.value.upper()
                if upper in _BLOCK_OPENERS:
                    depth += 1
                elif upper == "END":
                    depth = max(0, depth - 1)
                continue
            if (
                token.kind == "punct"
                and token.value == ";"
                and depth == 0
                and position != len(executable) - 1
            ):
                raise ValueError(
                    f"{what} ends a statement with ';' and then continues, which would let "
                    "a second statement ride along behind the first"
                )

    def _declared_object(
        self, tokens: Sequence[_BodyToken], keywords: Sequence[str]
    ) -> tuple[tuple[str | None, str], int]:
        """Read the dotted name a `CREATE … <keyword> <name>` body declares.

        Returns the `(schema, name)` pair — already normalised the way this engine's catalogue
        would hold it, honouring whether each part arrived quoted — and the index of the
        `CREATE` token, which `edit_routine()` needs so it can splice its own clause in at
        exactly the right offset rather than by rewriting text it matched with a regex.

        The scan stops at the first `(`: `CREATE DEFINER=`u`@`h` PROCEDURE p(...)` is what
        MySQL itself hands back from `SHOW CREATE`, so the keyword cannot be assumed to be the
        second word.
        """

        words = [token for token in tokens if token.kind != "comment"]
        if not words or words[0].kind != "word" or words[0].value.upper() != "CREATE":
            raise ValueError(
                "the body must begin with CREATE: d-MCP composes the statement around what it "
                "was given and cannot authorise a body whose first word it does not recognise"
            )
        wanted = {keyword.upper() for keyword in keywords}
        cursor = None
        for position, token in enumerate(words[1:], start=1):
            if token.kind == "punct" and token.value == "(":
                break
            if token.kind == "word" and token.value.upper() in wanted:
                cursor = position + 1
                break
        if cursor is None:
            raise ValueError(
                f"the body does not declare a {' or '.join(sorted(wanted)).lower()}: "
                f"expected CREATE {' or CREATE '.join(sorted(wanted))} followed by the name"
            )

        parts: list[tuple[str, bool]] = []
        while cursor < len(words):
            token = words[cursor]
            if token.kind == "quoted":
                parts.append((token.text, True))
            elif token.kind == "word":
                parts.append((token.value, False))
            else:
                break
            cursor += 1
            if cursor < len(words) and words[cursor].kind == "punct" and words[cursor].value == ".":
                cursor += 1
                continue
            break
        if not parts:
            raise ValueError("the body names no object after its CREATE clause")
        if len(parts) > 2:
            raise ValueError(
                "the body names a three-part object; d-MCP creates objects in the connection's "
                "own database only, because a rule is written against one connection"
            )
        schema_part = (
            self.normalise_identifier(parts[0][0], quoted=parts[0][1]) if len(parts) == 2 else None
        )
        name_part = self.normalise_identifier(parts[-1][0], quoted=parts[-1][1])
        return (schema_part, name_part), words[0].start

    def _check_declares(self, tokens: Sequence[_BodyToken], ref: NormalisedRef, keywords: Sequence[str]) -> int:
        """Check the body declares exactly the object `ref` names, and return the `CREATE`
        offset.

        The schema half is mandatory wherever the engine has schemas, and that is not
        pedantry: an unqualified name in a `CREATE` is resolved by the *server* against the
        session's search path, which need not be the schema the permission check authorised.
        A body that says `CREATE FUNCTION f` under a rule granting `create` on `sales.f` could
        then land `public.f`, authorised by a rule that never covered it.
        """

        (schema_part, name_part), offset = self._declared_object(tokens, keywords)
        if self.capabilities.supports_schemas:
            if schema_part is None:
                raise ValueError(
                    "the body must name the object schema-qualified: an unqualified CREATE is "
                    "resolved by the server against the session's schema, which need not be "
                    f"the {ref.canonical_schema!r} the permission check authorised"
                )
            if self.identifier_match_key(schema_part) != ref.key_schema:
                raise ValueError(
                    f"the body creates the object in {schema_part!r} but the call authorised "
                    f"{ref.canonical_schema!r}"
                )
        if self.identifier_match_key(name_part) != ref.key_name:
            raise ValueError(
                f"the body declares {name_part!r} but the call authorised {ref.canonical_name!r}"
            )
        return offset

    def _check_object_type(self, ref: NormalisedRef, expected: ObjectType, method: str) -> None:
        """Refuse a reference of the wrong kind before a character of SQL is written.

        `object_type` is part of the permission rule's key, so a `drop_view()` handed a
        `TABLE` reference would be authorised against the view rule and would drop the table.
        """

        if ref.object_type is not expected:
            raise ValueError(
                f"{method}() acts on a {expected}; {ref.object_type} is a different object "
                "type and answers to a different permission rule"
            )

    def _validate_type(self, data_type: str) -> str:
        """Validate a column type against this engine's own vocabulary and re-render it.

        Re-rendered rather than passed through, and that is the point: the returned text is
        assembled from a base name this module holds in a frozen set plus digits matched by a
        regex, so whatever the caller wrote, what reaches the statement is built out of pieces
        d-MCP owns.  Validating and then emitting the original string would leave the original
        string's trailing `, x int) --` in the DDL if the validation ever had a hole in it.
        """

        if not self.column_types:
            raise DialectError(
                f"{type(self).__name__} declares no column type vocabulary and cannot create a "
                "table"
            )
        if not isinstance(data_type, str) or not data_type.strip():
            raise ValueError("a column needs a data type")
        text = " ".join(data_type.split())

        modifiers: list[str] = []
        changed = True
        while changed and self.type_modifiers:
            changed = False
            for modifier in sorted(self.type_modifiers):
                if text.upper().endswith(" " + modifier):
                    text = text[: -(len(modifier) + 1)].rstrip()
                    if modifier not in modifiers:
                        modifiers.append(modifier)
                    changed = True
        modifiers.sort()

        array = False
        if self.supports_array_types and text.endswith("[]"):
            array = True
            text = text[:-2].rstrip()

        arguments = ""
        open_bracket = text.find("(")
        if open_bracket >= 0:
            match = _TYPE_ARGS_RE.match(text[open_bracket:])
            if match is None:
                raise ValueError(
                    f"the type {data_type!r} has an argument list d-MCP will not emit: only "
                    "(n), (n, m) and (max) are accepted"
                )
            if match.group(1) is not None:
                if not self.supports_max_length_argument:
                    raise ValueError(f"{self.display_name} has no (max) length; give a number")
                arguments = "(MAX)"
            elif match.group(3) is not None:
                arguments = f"({int(match.group(2))}, {int(match.group(3))})"
            else:
                arguments = f"({int(match.group(2))})"
            text = text[:open_bracket].rstrip()

        base = " ".join(text.split()).lower()
        if base not in self.column_types:
            raise ValueError(
                f"{self.display_name} has no type {base!r}; d-MCP emits only the types it has "
                "declared for this engine, because guessing a substitute is how an "
                "NVARCHAR(MAX) becomes a TEXT and a value is lost"
            )
        rendered = base.upper() + arguments
        if array:
            rendered += "[]"
        for modifier in modifiers:
            rendered += " " + modifier
        return rendered

    #: The keyword pair a boolean default renders as on this engine.  SQL Server and SQLite
    #: have no boolean literal at all — `bit` and integer affinity take `1`/`0`.
    boolean_literals: ClassVar[tuple[str, str]] = ("TRUE", "FALSE")

    #: The `_DEFAULT_KEYWORDS` this engine does *not* have.  SQL Server has no `CURRENT_DATE`
    #: and no `TRUE`/`FALSE`; naming them here turns a statement the server would reject into
    #: a message that says which keyword to use instead.
    unsupported_default_keywords: ClassVar[frozenset[str]] = frozenset()

    def _default_literal(self, default: Any) -> str:
        """Render a column default as statement text — the audited interpolation point.

        §3.8 called `_password_literal()` "the single interpolation point in
        `src/sape_d_mcp/db/`", and that claim never survived `create_table()`: no engine
        accepts a parameter marker anywhere in DDL, so a column default has nowhere to be a
        bound value.  Stage 8 settled the discrepancy the other way round — the password
        renderer was deleted rather than written (see the note where it stood), so this is now
        the interpolation point, and it is written to the standard §3.8 asked of that one: as
        small, as boring and as closed as it is possible to make it.

        * `None` emits nothing at all.
        * A `bool` renders as this engine's own boolean literal.
        * An `int` or a `float` renders as a plain decimal; `nan` and `inf` are refused.
        * A `str` must be a plain decimal, one of a six-word keyword list, or a single-quoted
          literal — which is re-rendered from its contents with the quote doubled, never
          passed through.  A backslash is refused outright rather than escaped, because
          whether it escapes anything is a per-engine, per-session question and getting the
          answer wrong turns `'\\'` into an unterminated literal that swallows the rest of the
          statement.

        Anything else is refused with a message naming the accepted forms.  An expression
        default — `DEFAULT NEXT VALUE FOR seq`, `DEFAULT (a + b)` — is out of reach from this
        surface by design, exactly as §11.3 says exotic table shapes are.
        """

        if default is None:
            return ""
        if isinstance(default, bool):
            true_word, false_word = self.boolean_literals
            return true_word if default else false_word
        if isinstance(default, int):
            return str(default)
        if isinstance(default, float):
            if default != default or default in (float("inf"), float("-inf")):
                raise ValueError("a column default cannot be NaN or infinity")
            return repr(default)
        if not isinstance(default, str):
            raise ValueError(
                f"a column default must be a number, a boolean or text, not "
                f"{type(default).__name__}"
            )

        text = default.strip()
        if _DECIMAL_DEFAULT_RE.match(text):
            return text
        upper = text.upper()
        if upper in _DEFAULT_KEYWORDS:
            if upper in self.unsupported_default_keywords:
                raise ValueError(
                    f"{self.display_name} has no {upper} default"
                )
            if upper in ("TRUE", "FALSE"):
                true_word, false_word = self.boolean_literals
                return true_word if upper == "TRUE" else false_word
            return upper
        if len(text) >= 2 and text[0] == "'" and text[-1] == "'":
            inner = text[1:-1]
            if "\\" in inner:
                raise ValueError(
                    "a column default may not contain a backslash: whether it escapes the next "
                    "character is a per-engine, per-session question, and the wrong answer "
                    "leaves an unterminated literal that swallows the rest of the statement"
                )
            if any(character < " " or character == "\x7f" for character in inner):
                raise ValueError("a column default may not contain a control character")
            if len(inner) > 255:
                raise ValueError("a column default literal is limited to 255 characters")
            if "'" in inner.replace("''", ""):
                raise ValueError(
                    "a column default literal has an unbalanced quote; double it to include one"
                )
            # `inner` is already correctly doubled — that is what the check above established
            # — so it is re-wrapped rather than re-escaped.  Escaping it a second time would
            # turn the two characters the caller wrote for one quote into four.
            return f"'{inner}'"
        raise ValueError(
            f"d-MCP will not emit {default!r} as a column default. Write a number, a quoted "
            "literal such as 'draft', or one of "
            + ", ".join(sorted(_DEFAULT_KEYWORDS - self.unsupported_default_keywords))
        )

    def _collate_clause(self, collation: str | None) -> str:
        """`COLLATE x`, with the name validated against a strict character class.

        A collation is an identifier on PostgreSQL and a bare word on the other three, so
        there is no single quoting rule to lean on and the character class *is* the control.
        PostgreSQL overrides this to quote it, which is what that engine requires.
        """

        if collation is None:
            return ""
        if not isinstance(collation, str) or not _COLLATION_RE.match(collation):
            raise ValueError(f"{collation!r} is not a collation name d-MCP will emit")
        return f" COLLATE {collation}"

    def _reject_column_comment(self, spec: ColumnSpec) -> None:
        """Refuse a column comment rather than interpolate one.

        A comment is free text with nowhere to be a bound value, so emitting it would open a
        third interpolation point in this layer for a field the MCP surface does not even
        offer — §11.3's `create-table` takes `{'name', 'type', 'nullable', 'default'}` and
        nothing else.  Refusing keeps the interpolation surface at the two places that have to
        exist.  A dialect whose engine has an inline, bindable form may override this.
        """

        if spec.comment is not None:
            raise ValueError(
                f"d-MCP does not emit a comment for column {spec.name!r}: a comment is free "
                "text that DDL gives no way to bind, and create-table's specification is "
                "name, type, nullability and default. Set the comment with the database's own "
                "tooling."
            )

    def _quoted_columns(self, columns: Sequence[str], *, what: str) -> list[str]:
        """Validate and quote a list of column names, refusing an empty list and a duplicate.

        A duplicate is refused rather than de-duplicated: `INSERT INTO t (a, a) VALUES (1, 2)`
        is a caller who has lost track of their own mapping, and picking one of the two values
        for them would make the statement succeed with the wrong data in it.
        """

        seen: set[str] = set()
        quoted: list[str] = []
        for column in columns:
            key = self.column_match_key(column)
            if key in seen:
                raise ValueError(f"{what} names the column {column!r} twice")
            seen.add(key)
            quoted.append(self.quote_identifier(column))
        if not quoted:
            raise ValueError(f"{what} needs at least one column")
        return quoted

    def _check_parameter_budget(self, count: int) -> None:
        """Refuse a statement with more bound values than the wire protocol can carry.

        SQL Server stops at 2 100 parameters and SQLite at its compile-time
        `SQLITE_MAX_VARIABLE_NUMBER`, so `MAX_WRITE_ROWS` alone is not the binding constraint:
        1 000 rows of five columns is 5 000 markers and fails on both.  Refused with the
        arithmetic in the message, because "split the batch" is only actionable if the caller
        is told what it has to be split into.
        """

        ceiling = self.max_bound_parameters
        if ceiling is not None and count > ceiling:
            raise ValueError(
                f"the statement binds {count} values, over {self.display_name}'s limit of "
                f"{ceiling}; send the rows in smaller batches"
            )

    def _row_query(
        self,
        sql: str,
        values: Sequence[Any],
        names: Sequence[str],
        ref: NormalisedRef,
        kind: StatementKind,
    ) -> Query:
        """Package a composed row statement and the one object it targets.

        `touches` carries exactly the object `ref` names and nothing a `where` fragment
        reaches — the same rule `select()` follows, and for the same reason: enumerating a
        fragment's references is the guard's job, done against the *composed* text, and a
        second and weaker enumeration here would only give the guard's answer something to
        disagree with.  A test pins the two together for `select()`; the write side answers to
        the same discipline.
        """

        self._check_parameter_budget(len(values))
        return Query(
            sql=sql,
            params=self.parameters(
                values, list(names) if self.param_style.is_mapping_style else None
            ),
            kind=kind,
            touches=(
                ObjectRef(
                    schema=ref.canonical_schema or self.addressable_schema,
                    name=ref.canonical_name,
                    object_type=ref.object_type,
                ),
            ),
        )

    def _ddl_step(self, sql: str, ref: NormalisedRef, kind: StatementKind) -> Query:
        """One DDL statement, with no bound values because DDL admits none."""

        return Query(
            sql=sql,
            params=self.parameters(()),
            kind=kind,
            touches=(
                ObjectRef(
                    schema=ref.canonical_schema or self.addressable_schema,
                    name=ref.canonical_name,
                    object_type=ref.object_type,
                ),
            ),
        )

    # -- catalogue query helpers -------------------------------------------------------

    def _catalogue_query(
        self,
        sql: str,
        values: Sequence[Any] = (),
        names: Sequence[str] | None = None,
        *,
        touches: Sequence[ObjectRef] = (),
    ) -> Query:
        """Package one catalogue statement and its bound values as a read `Query`.

        Shared by all four dialects because the fiddly part is the same everywhere and
        getting it wrong is not cosmetic: `parameters()` refuses `names` for a positional
        paramstyle, so every catalogue builder would otherwise carry the same
        `if self.param_style.is_mapping_style` conditional, and the one that forgot it would
        raise from inside the driver rather than here.

        `names` must be in the same order as `values`; a positional style discards them and a
        mapping style uses them, which is exactly the pairing `placeholder(index, name)`
        produces.
        """

        packaged = self.parameters(
            values, list(names) if names is not None and self._param_style.is_mapping_style else None
        )
        return Query(
            sql=sql,
            params=packaged,
            kind=StatementKind.READ,
            touches=tuple(touches),
        )

    def _schema_filter(
        self,
        schema: str | None,
        column: str,
        index: int = 0,
        name: str = "schema",
    ) -> tuple[str, tuple[Any, ...], tuple[str, ...]]:
        """Build the optional `AND <column> = <placeholder>` fragment of a `list_*` query.

        Returns the SQL fragment, the values to bind and their names, so a caller can splice
        all three into its own accumulators.  `column` is a catalogue column expression the
        dialect author wrote — never anything that arrived from outside — while `schema` is
        untrusted input from the GUI or from an MCP argument, and it therefore leaves here as
        a **bound value**, never as text spliced into the statement.

        It is still validated on the way past, for two reasons that are not the same reason:
        `normalise_identifier()` makes the comparison use the spelling the catalogue actually
        holds (`Sales` finds nothing on PostgreSQL, `sales` does), and `quote_identifier()`
        applies the engine's own prohibitions — an embedded NUL, an over-length name — which
        a bound parameter would otherwise carry to the server intact.  The quoted form is
        deliberately discarded: nothing here needs it, and the validation is the point.

        Consequence worth stating: on MS-SQL and MySQL `normalise_identifier()` raises before
        `configure()`, so `list_tables("sales")` needs a probed dialect while `list_tables()`
        does not.  Introspection always runs on a probed connection; the unprobed dialect is
        the Connections page's DSN-preview path, which never lists anything.
        """

        if schema is None:
            return "", (), ()
        canonical = self.normalise_identifier(schema)
        self.quote_identifier(canonical)
        return f" AND {column} = {self.placeholder(index, name)}", (canonical,), (name,)

    # ==================================================================================
    # Everything below is declared for review and lands in a later stage.  The signatures
    # and docstrings are final; the concrete classes raise from `_stage()`.
    # ==================================================================================

    # -- 3.3 catalogue introspection (stage 5) -----------------------------------------

    @abstractmethod
    def list_databases(self, *, include_system: bool = False) -> Query:
        """Every database on this server the current login is allowed to see.

        Fills the Connections dialog's editable Database combo (DESIGN-CONNECTION-SETUP.md
        §8).  It is a GUI affordance for a human, not an MCP tool, and it is not proposed
        for one: "list every database on this server" is a reconnaissance primitive the
        permission engine was never designed to gate.

        The statement is fixed and parameterless, it runs through the same
        `read_only_session()` and `apply_statement_timeout()` path as anything else, and —
        because it is a plain `SELECT` — through the same guard classification.  MySQL uses
        `information_schema.schemata` rather than `SHOW DATABASES` for exactly that reason:
        teaching a security chokepoint a new statement family to fill a combo box is a bad
        trade.

        **A short list is the normal shape of a permission failure here, not an exception.**
        All three server engines filter their catalogue silently: an MS-SQL login without
        `VIEW ANY DATABASE` simply sees fewer rows, and MySQL shows only the schemas the
        account holds a privilege on.  So a caller must never read "few rows" as "cannot
        connect", must keep the combo editable, and must let the human type a name the list
        does not contain.

        Args:
            include_system: Keep the engine's own databases in the result.  They are
                *marked* rather than hidden by default — the last column of every
                implementation is an `is_system` flag — because a user administering `msdb`
                must be able to select it.
        """

    @property
    @abstractmethod
    def bootstrap_database(self) -> str | None:
        """The catalogue to connect to when the target database is not known yet.

        Every driver needs *some* initial database before it can be asked what databases
        exist.  `None` means the question does not arise: a SQLite profile's file is the
        database, and the Find-databases button is hidden.
        """

    @abstractmethod
    def list_schemas(self) -> Query:
        """Every schema the current principal can see, system schemas excluded.

        SQLite returns a one-row synthetic result (`main`), so the Explorer page and the
        rule editor do not need an engine-specific branch.
        """

    @abstractmethod
    def list_tables(self, schema: str | None = None) -> Query:
        """Base tables only.  Views come from `list_views()` because they carry different
        actions in the permission model and must never be conflated."""

    @abstractmethod
    def list_views(self, schema: str | None = None) -> Query:
        """Views, including materialised views where the engine has them (PostgreSQL)."""

    @abstractmethod
    def list_functions(self, schema: str | None = None) -> Query:
        """Scalar and table-valued functions, aggregates excluded."""

    @abstractmethod
    def list_procedures(self, schema: str | None = None) -> Query:
        """Stored procedures.  On SQLite this is a synthetic empty result rather than an
        error: `list` operations hide what is unavailable instead of failing the call, which
        is the behaviour `dmcp-permissions` requires of every list-style tool."""

    @abstractmethod
    def describe_table(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Columns, primary key, unique keys and foreign keys, as a fixed-length tuple of
        queries in that order.  Kept as separate statements rather than one heroic join
        because the join is unreadable on three of the four engines and impossible on SQLite,
        where the answers come from four different pragma functions."""

    @abstractmethod
    def describe_routine(self, ref: NormalisedRef) -> tuple[Query, ...]:
        """Signature, parameters and return type for a function or procedure."""

    @abstractmethod
    def object_definition(self, ref: NormalisedRef) -> Query:
        """The stored source text of a view, function or procedure.

        Returns one row, one column, which may be `NULL`: MS-SQL returns `NULL` for a module
        created `WITH ENCRYPTION` and for CLR objects, and MySQL withholds a routine body
        from a principal lacking `SHOW_ROUTINE`.  The caller must distinguish "no definition"
        from "definition withheld" and say which — an empty editor with no explanation is the
        kind of thing that gets debugged for an hour.
        """

    @abstractmethod
    def estimate_row_count(self, ref: NormalisedRef) -> Query:
        """A cheap, approximate row count for the confirmation dialog's impact estimate.

        Approximate on purpose: an exact `COUNT(*)` on a large table is itself an expensive
        operation to trigger from a confirmation prompt.  `confirmation.py` labels the number
        as an estimate and, for a `DELETE`/`UPDATE` with a predicate, additionally runs the
        exact `count_matching()` below because that number is small by construction.
        """

    def count_matching(
        self,
        ref: NormalisedRef,
        predicates: Sequence[Predicate] = (),
        *,
        where: RawPredicate | None = None,
    ) -> Query:
        """Exact `COUNT(*)` restricted by the same condition as the pending write, so the
        confirmation dialog can say "this will delete 4 rows", not "this will delete some
        rows".

        `where` is the free-form form the user ruled the write tools take, and it has to be
        here as well as on `delete()`: the number the human is shown must come from *the same*
        condition the statement they are approving carries, and a count restricted by a
        different condition is worse than no count at all.  The fragment therefore goes
        through `_raw_where_clause()` — the identical composition, with the identical refusals
        — rather than through anything written a second time for the estimate.

        Concrete here rather than four times over: `SELECT COUNT(*) FROM t WHERE …` is spelled
        the same on all four engines, and the only per-engine part of it is `quote_ref()`.

        The condition may be empty, and then the answer is the whole table.  That is the case
        the confirmation dialog most needs a number for.
        """

        if ref.object_type not in (ObjectType.TABLE, ObjectType.VIEW):
            raise ValueError(
                f"count_matching() counts rows of a table or a view; {ref.object_type} is "
                "neither"
            )
        values: list[Any] = []
        names: list[str] = []
        condition = self._condition(predicates, where, values, names)
        sql = f"SELECT COUNT(*) AS match_count FROM {self.quote_ref(ref)}{condition}"
        return self._row_query(sql, values, names, ref, StatementKind.READ)

    # -- 3.4 DDL generation -------------------------------------------------------------
    #
    # Concrete here, not abstract, wherever the statement is spelled the same on all four
    # engines.  What genuinely differs is pushed into the small hooks each dialect overrides:
    # `_identity_clause()`, `_column_ddl()`, `_supports_drop_if_exists()`,
    # `create_or_replace_clause` and the `column_types` vocabulary.  `_raw_where_clause()`
    # already set the precedent and gave the reason — four copies of one rule about what may
    # pass is four places for that rule to drift.

    #: The clause `edit_routine()` splices in to replace a routine atomically.  `OR REPLACE`
    #: on PostgreSQL and MySQL; SQL Server overrides it with `OR ALTER`, which is the same
    #: idea under a different spelling and one that arrived only in 2016 SP1.
    create_or_replace_clause: ClassVar[str] = "OR REPLACE"

    def _identity_clause(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """How this engine spells "the server assigns this column's value".

        There is no portable spelling — `IDENTITY(1,1)`, `GENERATED BY DEFAULT AS IDENTITY`,
        `AUTO_INCREMENT` and `INTEGER PRIMARY KEY AUTOINCREMENT` are four different grammars
        with four different constraints attached — so a dialect that has not written its own
        refuses rather than inheriting one that would compose valid SQL for a different
        server.
        """

        raise self._unsupported(
            "create_table(is_identity=True)",
            f"{self.display_name} has no identity spelling declared in this dialect",
        )

    def _column_ddl(self, spec: ColumnSpec, *, primary_key: Sequence[str]) -> str:
        """One column definition: name, type, collation, identity, nullability, default.

        Every part of it is either an identifier this method quotes, a type name taken from
        `column_types`, or a default rendered by `_default_literal()`.  Nothing the caller
        wrote is copied through.
        """

        self._reject_column_comment(spec)
        piece = f"{self.quote_identifier(spec.name)} {self._validate_type(spec.data_type)}"
        piece += self._collate_clause(spec.collation)
        if spec.is_identity:
            if spec.default is not None:
                raise ValueError(
                    f"column {spec.name!r} is both an identity column and has a default; the "
                    "server assigns one or the other, and no engine accepts both"
                )
            piece += self._identity_clause(spec, primary_key=primary_key)
        if not spec.nullable:
            piece += " NOT NULL"
        if spec.default is not None:
            piece += " DEFAULT " + self._default_literal(spec.default)
        return piece

    def _primary_key_clause(
        self, primary_key: Sequence[str], columns: Sequence[ColumnSpec]
    ) -> str:
        """The table-level `PRIMARY KEY (...)` constraint, or nothing.

        Table-level rather than inline even for a single column, so the emitted DDL has one
        shape whatever the key's arity.  SQLite overrides it, because there the single-column
        integer key is not a constraint at all — it is the rowid, and spelling it any other
        way loses the aliasing.
        """

        if not primary_key:
            return ""
        quoted = self._quoted_columns(primary_key, what="the primary key")
        return "PRIMARY KEY (" + ", ".join(quoted) + ")"

    def create_table(
        self,
        ref: NormalisedRef,
        columns: Sequence[ColumnSpec],
        primary_key: Sequence[str] = (),
        if_not_exists: bool = False,
    ) -> Script:
        """Build a `CREATE TABLE`.  Types in `ColumnSpec` are given in the engine's own
        vocabulary and validated against the engine's type list before emission; d-MCP does
        not invent a portable type language, because a silent `TEXT`-for-`NVARCHAR(MAX)`
        substitution is a data-loss bug wearing a convenience costume.

        **`if_not_exists=True` is refused on every engine.**  §8.1 of `DESIGN-MCP-TOOLS.md`
        requires that creating a table whose name is already taken is an error and never an
        implicit replace, and this layer holds no connection and so cannot ask whether the
        name is taken (decision D1).  What it *can* guarantee is that the emitted statement
        never contains the clause that would swallow the collision: without `IF NOT EXISTS`
        the server raises, the tool surfaces the message, and the caller learns the table was
        not created.  With it, the call succeeds, nothing happens, and the model believes it
        has a table.  The parameter is kept because §3.4 declares it, and refused because
        honouring it would defeat the rule it sits next to.

        The generated DDL is scanned for every `OR REPLACE` spelling before it is returned —
        not only the caller's input.  A type name or a collation that smuggled a clause past
        the validators would be caught by the same reader that reads a routine body.
        """

        self._check_object_type(ref, ObjectType.TABLE, "create_table")
        if if_not_exists:
            raise ValueError(
                "create_table() will not emit IF NOT EXISTS: a name that is already taken has "
                "to be an error, never a silent no-op that leaves the caller believing the "
                "table was created (DESIGN-MCP-TOOLS.md §8.1). The table that holds the name "
                "cannot be removed through d-MCP (docs/adr/0005); create this one under a name "
                "that is free."
            )
        specs = list(columns)
        if not specs:
            raise ValueError("create_table() needs at least one column")
        for spec in specs:
            if not isinstance(spec, ColumnSpec):
                raise ValueError(
                    f"create_table() takes ColumnSpec entries, not {type(spec).__name__}"
                )
        self._quoted_columns([spec.name for spec in specs], what="create_table()")

        key = list(primary_key)
        if key:
            declared = {self.column_match_key(spec.name) for spec in specs}
            for column in key:
                if self.column_match_key(column) not in declared:
                    raise ValueError(
                        f"the primary key names {column!r}, which is not one of the columns "
                        "being created"
                    )

        pieces = [self._column_ddl(spec, primary_key=key) for spec in specs]
        constraint = self._primary_key_clause(key, specs)
        if constraint:
            pieces.append(constraint)
        sql = f"CREATE TABLE {self.quote_ref(ref)} (" + ", ".join(pieces) + ")"

        generated = self._body_tokens(sql)
        self._reject_or_replace(generated, what="the generated CREATE TABLE")
        self._reject_trailing_statement(generated, what="the generated CREATE TABLE")
        return Script(
            steps=(self._ddl_step(sql, ref, StatementKind.DDL),),
            atomic=self.capabilities.supports_transactional_ddl,
        )

    def _drop_script(
        self,
        ref: NormalisedRef,
        keyword: str,
        if_exists: bool,
        *,
        suffix: str = "",
    ) -> Script:
        """`DROP <keyword> [IF EXISTS] <name><suffix>` — and never `CASCADE`.

        The omission of `CASCADE` is the whole of §3.4's note on this method and is not a
        default that can be overridden from anywhere: taking an object's dependants with it
        is a separate act, separately confirmed, with the dependants listed first.

        Where the server has no `IF EXISTS` — SQL Server before 2016 — the clause is dropped
        rather than emulated, and the script carries a `warning_key` so the human is told that
        dropping something that is not there will raise instead of doing nothing.  Emulating
        it would take a second statement, and a two-statement drop is a batch.
        """

        clause = ""
        warning: str | None = None
        if if_exists:
            if self._supports_drop_if_exists():
                clause = " IF EXISTS"
            else:
                warning = "confirmation.warning_no_drop_if_exists"
        sql = f"DROP {keyword}{clause} {self.quote_ref(ref)}{suffix}"
        return Script(
            steps=(self._ddl_step(sql, ref, StatementKind.DESTRUCTIVE),),
            atomic=self.capabilities.supports_transactional_ddl,
            warning_key=warning,
        )

    def drop_table(self, ref: NormalisedRef, if_exists: bool = True) -> Script:
        """Destructive.  Never emits `CASCADE`: dropping a table and taking its dependants
        with it must be an explicit, separately confirmed act, and the confirmation dialog
        listed the dependants first.  Since ADR 0005 the `drop` action is never granted, so no
        dialog is reached through d-MCP at all."""

        self._check_object_type(ref, ObjectType.TABLE, "drop_table")
        return self._drop_script(ref, "TABLE", if_exists)

    def create_view(self, ref: NormalisedRef, body: str, or_replace: bool = False) -> Script:
        """`CREATE VIEW <ref> AS <body>`, with `or_replace` refused rather than honoured.

        §3.4 originally had `or_replace` honoured wherever
        `capabilities.supports_create_or_replace_view` allowed it.  §8.1 of
        `DESIGN-MCP-TOOLS.md` overrides that and is the newer document: `create-*` is not
        brokered *because* it destroys nothing, so a `create_view(or_replace=True)` would be
        an unbrokered replacement of an object that already exists — the approval step deleted
        by a keyword argument.  Replacing a view was `drop_view()` followed by `create_view()`,
        and `drop_view()` was brokered — but since ADR 0005 the `drop` action is never granted,
        so d-MCP has no route that replaces a view at all.  The parameter stays in the
        signature because §3.4 declares it; passing `True` raises.

        `body` is the view's `SELECT`, as §11.4 specifies — the tool layer has already put it
        through the same read-only gate as `run-read-query`, so every object it reads has been
        authorised for `select` before this method is reached.  Here it is checked for the one
        thing that gate cannot see: that it is still a single query once d-MCP has wrapped it,
        and that neither the body nor the wrapper carries a replace clause.
        """

        self._check_object_type(ref, ObjectType.VIEW, "create_view")
        if or_replace:
            raise ValueError(
                "create_view() will not replace an existing view: replacing an object is a "
                "destructive act, and d-MCP never performs one (docs/adr/0005). A view that "
                "already exists can be neither replaced nor removed through d-MCP by any "
                "route; redefining it is a job for a database client."
            )
        tokens = self._body_tokens(body)
        self._reject_or_replace(tokens, what="the view body")
        self._reject_trailing_statement(tokens, what="the view body")
        first = next((token for token in tokens if token.kind != "comment"), None)
        if first is None:
            raise ValueError("the view body is empty; a view is a query and needs one")
        opens_query = (first.kind == "punct" and first.value == "(") or (
            first.kind == "word" and first.value.upper() in ("SELECT", "WITH", "VALUES", "TABLE")
        )
        if not opens_query:
            raise ValueError(
                "a view body is a query: it must begin with SELECT, WITH, VALUES, TABLE or an "
                f"opening bracket, not {first.value!r}"
            )

        text = body.strip()
        if text.endswith(";"):
            text = text[:-1].rstrip()
        sql = f"CREATE VIEW {self.quote_ref(ref)} AS {text}"
        generated = self._body_tokens(sql)
        self._reject_or_replace(generated, what="the generated CREATE VIEW")
        self._reject_trailing_statement(generated, what="the generated CREATE VIEW")
        return Script(
            steps=(self._ddl_step(sql, ref, StatementKind.DDL),),
            atomic=self.capabilities.supports_transactional_ddl,
        )

    def drop_view(self, ref: NormalisedRef, if_exists: bool = True) -> Script:
        """Destructive.  As `drop_table()`, never `CASCADE`."""

        self._check_object_type(ref, ObjectType.VIEW, "drop_view")
        return self._drop_script(ref, "VIEW", if_exists)

    #: The `CREATE` keyword each routine object type is declared with.
    _ROUTINE_KEYWORDS: ClassVar[dict[ObjectType, str]] = {
        ObjectType.FUNCTION: "FUNCTION",
        ObjectType.PROCEDURE: "PROCEDURE",
    }

    def _routine_keyword(self, ref: NormalisedRef, object_type: ObjectType) -> str:
        """The keyword for this routine kind, with every precondition checked first."""

        try:
            keyword = self._ROUTINE_KEYWORDS[ObjectType(object_type)]
        except (KeyError, ValueError):
            raise ValueError(
                f"a routine is a function or a procedure; {object_type} is neither"
            ) from None
        self._check_object_type(ref, ObjectType(object_type), "create_routine")
        if ObjectType(object_type) is ObjectType.PROCEDURE and not self.capabilities.supports_stored_procedures:
            raise self._unsupported(
                "create_routine", f"{self.display_name} has no stored procedures"
            )
        return keyword

    def _validated_routine_body(
        self, body: str, ref: NormalisedRef, keyword: str, *, what: str
    ) -> tuple[str, int]:
        """The checks every routine body gets, whether it is being created or edited.

        Three of them, and no more.  The body is **not** parsed for meaning — §3.4 is explicit
        that a routine body is a whole procedural language and that pretending to validate it
        would be theatre — so what is checked is exactly what can be checked honestly: that it
        carries no smuggled second statement, that it carries no replace clause, and that the
        object it declares is the object the permission check authorised.

        Returns the body with a trailing statement terminator removed, and the offset of its
        `CREATE` keyword so `edit_routine()` can splice at a position rather than by matching
        text.
        """

        tokens = self._body_tokens(body)
        self._reject_or_replace(tokens, what=what)
        self._reject_trailing_statement(tokens, what=what)
        offset = self._check_declares(tokens, ref, [keyword])
        text = body.rstrip()
        if text.endswith(";"):
            text = text[:-1].rstrip()
        return text, offset

    def create_routine(
        self, ref: NormalisedRef, body: str, object_type: ObjectType, or_replace: bool = False
    ) -> Script:
        """`body` is the complete `CREATE …` text supplied by the caller and is **not**
        parsed for meaning — a routine body is a whole procedural language and pretending to
        validate it would be theatre.  It is checked for a single leading statement, checked
        that the object it declares matches `ref`, and composed as plain `DDL`: `create-*` is
        not brokered, because creating something that did not exist destroys nothing.  The
        rule that authorises it is `create` on that object type.

        `or_replace=True` raises, for the reason §8.1 gives and `create_view()` repeats:
        replacing a routine was `edit_routine()`, and `edit_routine()` was brokered.  A
        `create-function(or_replace=True)` that composed would be `edit-function` authorised
        by the `create` flag rather than the `edit` one, and without the approval that
        `edit-function` then carried.  Since ADR 0005 the `edit` action is never granted
        either — the edit tools are refused before the broker is reached — so this refusal
        leaves no route through d-MCP that replaces a routine.
        """

        keyword = self._routine_keyword(ref, object_type)
        if or_replace:
            raise ValueError(
                "create_routine() will not replace an existing routine: replacing a body "
                "destroys the old one, and d-MCP never destroys an object (docs/adr/0005). "
                "A routine that already exists can be neither replaced nor removed through "
                "d-MCP by any route; rewriting its body is a job for a database client."
            )
        text, _ = self._validated_routine_body(body, ref, keyword, what="the routine body")
        return Script(
            steps=(self._ddl_step(text, ref, StatementKind.DDL),),
            atomic=self.capabilities.supports_transactional_ddl,
        )

    def edit_routine(
        self,
        ref: NormalisedRef,
        body: str,
        object_type: ObjectType,
        previous_definition: str | None = None,
    ) -> Script:
        """Replace the body of an existing routine.  Destructive per `dmcp-permissions`.

        Where the engine has no atomic replacement (MySQL routines), the script is
        drop-then-create, `atomic=False`, with the previously introspected definition in
        `rollback` so a failed create can be undone, and a warning key explaining that grants
        on the routine are lost.

        `previous_definition` is an addition to §3.4's signature, and it is what makes the
        sentence above true rather than aspirational: §3.4 asks for the prior definition in
        `rollback` and gives the method no parameter to receive one through.  It is keyword-
        optional, so the documented three-argument call still works, and it is validated
        exactly as the new body is — it is text, and where it came from does not change that.

        The caller passes a plain `CREATE …`; the replace clause is spliced in here, at the
        offset the tokeniser found the `CREATE` keyword at, so the caller never writes the one
        clause `create_routine()` refuses and there is no path where the two methods disagree
        about what a body may contain.
        """

        keyword = self._routine_keyword(ref, object_type)
        text, offset = self._validated_routine_body(
            body, ref, keyword, what="the replacement routine body"
        )
        if not self.capabilities.supports_create_or_replace_routine:
            return self._replace_by_drop_and_create(ref, text, keyword, previous_definition)
        spliced = (
            text[:offset] + f"CREATE {self.create_or_replace_clause}" + text[offset + len("CREATE"):]
        )
        return Script(
            steps=(self._ddl_step(spliced, ref, StatementKind.DESTRUCTIVE),),
            atomic=self.capabilities.supports_transactional_ddl,
        )

    def _replace_by_drop_and_create(
        self,
        ref: NormalisedRef,
        text: str,
        keyword: str,
        previous_definition: str | None,
    ) -> Script:
        """The fallback where the engine cannot replace a routine in one statement.

        Two statements with a window between them where the routine does not exist, and — on
        MySQL, which commits implicitly on DDL — no transaction to close that window.  The
        `warning_key` is set only where the script is genuinely non-atomic: on SQL Server below
        2016 SP1 the same two statements run inside one transaction, so there is nothing to
        warn about and a warning shown anyway would teach the operator to dismiss them.
        """

        atomic = self.capabilities.supports_transactional_ddl
        rollback: tuple[Query, ...] = ()
        if previous_definition is not None:
            restored, _ = self._validated_routine_body(
                previous_definition, ref, keyword, what="the previous routine definition"
            )
            rollback = (self._ddl_step(restored, ref, StatementKind.DDL),)
        drop = self._drop_script(ref, keyword, if_exists=True)
        return Script(
            steps=(*drop.steps, self._ddl_step(text, ref, StatementKind.DDL)),
            atomic=atomic,
            rollback=rollback,
            warning_key=None if atomic else "confirmation.warning_non_atomic_routine_replace",
        )

    # -- 3.4 routines: the overload discriminator ----------------------------------------
    #
    # PostgreSQL identifies a routine by its name *and* its argument types: `f(integer)` and
    # `f(text)` are two objects, and a bare `DROP FUNCTION f` is an error while both exist.
    # Every path that names a routine for something other than reading it therefore has to be
    # able to carry an argument list — `drop_routine()`, `grant()` and `revoke()` — and all
    # three come through this one kit, so the four engines cannot drift into answering the
    # same question three different ways.  (`create_routine()` and `edit_routine()` need
    # nothing: the argument list is inside the `CREATE` text the caller supplies.  The read
    # side needs nothing either: `describe_routine()` already answers one header row *per*
    # overload, keyed by signature.)
    #
    # An argument type is the one part of these statements that is neither a bound value nor
    # an identifier this layer took out of the catalogue and quoted.  Two gates cover it:
    #
    #   * `resolve_overload()` matches the caller's argument list against the overload set the
    #     catalogue reported and hands back the **server's** spelling of it — so what is
    #     written down comes from the database and the caller's text only chose between the
    #     rows.  This is the gate the tool layer is meant to use, and the one that makes a
    #     user-defined type work at all;
    #   * `_render_argument_list()` rebuilds whatever it is given from parsed pieces — a mode
    #     word from a fixed tuple, a type from this engine's declared vocabulary or a
    #     well-formed identifier this layer re-quotes — and refuses anything it cannot
    #     attribute.  It runs on every path, including the one that skipped the first gate.
    #
    # Omitting the signature stays legal everywhere.  A routine with no overload is addressed
    # by bare name on all four engines, and where the name *is* overloaded and no signature
    # was given the server's own "function name is not unique" is the outcome — a loud
    # failure, and a better one than picking an overload.

    #: The argument modes a signature may carry, upper-cased.  Emitted from this tuple rather
    #: than from the caller's text.
    _ARGUMENT_MODES: ClassVar[tuple[str, ...]] = ("IN", "OUT", "INOUT", "VARIADIC")

    def _routine_argument_list(self, signature: str | None, *, method: str) -> str:
        """The `(...)` that follows an overloaded routine's name, or nothing at all.

        `None` is accepted everywhere and emits nothing.  A signature is refused wherever the
        engine cannot overload a routine, rather than ignored, for the same reason
        `quote_principal()` refuses a `host` on the three engines that have no host half: a
        caller who believes it has disambiguated and has not has a different object in mind
        from the one that is about to be dropped, and accepting-and-discarding would let it
        keep believing that.
        """

        if signature is None:
            return ""
        if not self.overloads_routines:
            raise ValueError(
                f"{self.display_name} does not overload routines, so {method}() takes no "
                "signature: one name is one object here"
            )
        return self._render_argument_list(signature)

    def _routine_arguments_for(
        self, ref: NormalisedRef, signature: str | None, *, method: str
    ) -> str:
        """`_routine_argument_list()`, having first checked that `ref` is a routine at all."""

        if signature is not None and ref.object_type not in (
            ObjectType.FUNCTION,
            ObjectType.PROCEDURE,
        ):
            raise ValueError(
                f"a signature names a routine's argument types, and {ref.object_type} is not "
                f"a routine, so {method}() takes none for it"
            )
        return self._routine_argument_list(signature, method=method)

    def _unwrap_argument_list(self, signature: str) -> str:
        """`(integer, text)` or `integer, text` — either spelling, brackets off.

        The outer pair comes off only when the opening bracket's own partner is the last
        character, which is the difference between a wrapper and an argument that happens to
        start with one.  `(integer) CASCADE` therefore keeps its brackets and is refused by
        the parser, rather than being unwrapped into something that parses.
        """

        text = str(signature).strip()
        if not text.startswith("("):
            return text
        depth = 0
        quoted = False
        index = 0
        while index < len(text):
            char = text[index]
            if quoted:
                if char == '"':
                    if index + 1 < len(text) and text[index + 1] == '"':
                        index += 1
                    else:
                        quoted = False
            elif char == '"':
                quoted = True
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return text[1:index].strip() if index == len(text) - 1 else text
            index += 1
        return text

    def _split_arguments(self, text: str) -> list[str]:
        """Split an argument list on its top-level commas.

        Not `text.split(",")`: `numeric(10, 2)` carries a comma of its own and splitting on it
        yields two fragments, neither of which is a type — which would turn a valid signature
        into a refusal, and, worse, is the shape of parser disagreement that lets text through
        a check by being read one way and emitted another.  Brackets and quoted spans are
        tracked, and one left open is refused here rather than passed on.
        """

        parts: list[str] = []
        current: list[str] = []
        depth = 0
        quoted = False
        index = 0
        while index < len(text):
            char = text[index]
            if quoted:
                current.append(char)
                if char == '"':
                    if index + 1 < len(text) and text[index + 1] == '"':
                        current.append('"')
                        index += 1
                    else:
                        quoted = False
                index += 1
                continue
            if char == '"':
                quoted = True
                current.append(char)
            elif char in "([":
                depth += 1
                current.append(char)
            elif char in ")]":
                depth -= 1
                if depth < 0:
                    raise ValueError(
                        f"the routine argument list {text!r} closes a bracket it never opened"
                    )
                current.append(char)
            elif char == "," and depth == 0:
                parts.append("".join(current))
                current = []
            else:
                current.append(char)
            index += 1
        if quoted:
            raise ValueError(f"the routine argument list {text!r} leaves a quoted name open")
        if depth:
            raise ValueError(f"the routine argument list {text!r} leaves a bracket open")
        parts.append("".join(current))
        return parts

    def _argument_pieces(self, argument: str) -> tuple[str, str]:
        """One `[mode] [name] type` argument as `(mode, type)`, the parameter name dropped.

        Dropped rather than emitted: an overload is identified by its argument *types* alone,
        so a parameter name adds nothing to the identification and adds text this layer would
        have to vouch for.

        Dropped only where the leading word is something that could **be** a parameter name,
        though.  A leading word that is not one is a refusal and not a discard: "the first
        word did not parse, so ignore it and read the rest" is how `(integer) CASCADE` becomes
        a statement about a type called `cascade`, which is a different act from the one the
        caller wrote down.
        """

        words = argument.split()
        if not words:
            raise ValueError(f"the routine argument list has an empty argument: {argument!r}")
        mode = ""
        if words[0].upper() in self._ARGUMENT_MODES:
            mode = words[0].upper() + " "
            words = words[1:]
        if not words:
            raise ValueError(f"the routine argument {argument!r} names no type")
        joined = " ".join(words)
        if len(words) == 1 or self._is_argument_type(joined):
            return mode, joined
        if not self._is_parameter_name(words[0]):
            raise ValueError(
                f"the routine argument list holds {argument!r}, which is neither a type this "
                "engine has nor a parameter name followed by one"
            )
        return mode, " ".join(words[1:])

    def _is_parameter_name(self, word: str) -> bool:
        """Whether `word` could be a parameter name — the only leading word that may be
        dropped rather than refused."""

        if len(word) >= 2 and word.startswith('"') and word.endswith('"'):
            return '"' not in word[1:-1].replace('""', "")
        if not word:
            return False
        first = word[0]
        if not (first.isalpha() or first == "_" or ord(first) > 127):
            return False
        return all(char.isalnum() or char in "_$" or ord(char) > 127 for char in word)

    def _render_argument_type(self, data_type: str) -> str:
        """One argument's type, re-rendered from this engine's declared vocabulary."""

        return self._validate_type(data_type)

    def _is_argument_type(self, candidate: str) -> bool:
        """Whether `candidate` renders as a type — used only to tell a parameter name from
        one, never to decide what is emitted."""

        try:
            self._render_argument_type(candidate)
        except (ValueError, DialectError):
            return False
        return True

    def _render_argument_list(self, signature: str) -> str:
        """Rebuild an argument list from validated pieces, or refuse it.

        Re-rendered rather than passed through, for the reason `_validate_type()` gives: what
        reaches the statement is assembled out of a mode word from a fixed tuple and a type
        this method vouched for, so a hole in the validation cannot leave the caller's
        `, x int) --` sitting in the middle of a `DROP`.
        """

        if not isinstance(signature, str):
            raise ValueError("a routine argument list is text")
        text = self._unwrap_argument_list(signature)
        if not text:
            # `f()` — a routine that takes nothing, which is still a signature and still
            # distinguishes it from an overload that takes something.
            return "()"
        rendered: list[str] = []
        for argument in self._split_arguments(text):
            mode, data_type = self._argument_pieces(argument)
            rendered.append(mode + self._render_argument_type(data_type))
        return "(" + ", ".join(rendered) + ")"

    def _type_match_key(self, data_type: str) -> str:
        """A type's comparison key: what has to be equal for two spellings to mean one type.

        Never emitted.  A wrong answer here can only fail a match — and a failed match raises
        with the real overload set in the message — so this may fold aggressively where
        `_render_argument_type()` may not.  It folds a length modifier away (PostgreSQL
        ignores one when it resolves a `DROP`), folds the schema qualification away (two
        same-named types from different schemas would collide into "ambiguous", which is a
        refusal and not a guess), and folds the engine's own type aliases together.  A quoted
        name is compared verbatim: `"char"` and `char` are different types on PostgreSQL and
        folding them together would match the wrong row.
        """

        text = " ".join(str(data_type).split())
        array = ""
        while text.endswith("[]"):
            array = "[]" + array
            text = text[:-2].rstrip()
        open_bracket = text.find("(")
        if open_bracket > 0 and text.endswith(")"):
            text = text[:open_bracket].rstrip()
        if '"' in text:
            return text + array
        text = text.rsplit(".", 1)[-1].strip().lower()
        return self.type_aliases.get(text, text) + array

    def _overload_key(self, signature: str) -> tuple[str, ...]:
        """An argument list's comparison key: its argument types, and nothing else."""

        text = self._unwrap_argument_list(signature)
        if not text:
            return ()
        key: list[str] = []
        for argument in self._split_arguments(text):
            _, data_type = self._argument_pieces(argument)
            key.append(self._type_match_key(data_type))
        return tuple(key)

    def _overload_key_or_none(self, signature: str) -> tuple[str, ...] | None:
        """`_overload_key()` for a catalogue row, which this layer did not write and will not
        refuse the whole call over: an entry that cannot be parsed simply matches nothing and
        is still listed in the message."""

        try:
            return self._overload_key(signature)
        except (ValueError, DialectError):
            return None

    def resolve_overload(
        self, ref: NormalisedRef, signature: str | None, overloads: Sequence[str]
    ) -> str | None:
        """Pick the one overload `signature` names out of the set the catalogue reported.

        This is where the argument types in a composed statement are meant to come from, and
        the answer is: from the server.  `overloads` is what introspection already answers for
        this schema and name — one entry per object, each the engine's own spelling of its
        argument list (`RoutineEntry.signature`, filled on PostgreSQL from
        `pg_get_function_identity_arguments`).  The caller's text is used to *choose between*
        those rows and never as the text that is written down; what is returned, and what
        should then be handed to `drop_routine()`, `grant()` or `revoke()`, is the catalogue's
        own string.

        `None` comes back when the bare name is unambiguous, which is every routine on three
        of the four engines and most of them on the fourth.  A signature that matches nothing
        raises, with the real overloads in the message, rather than resolving to the only
        candidate — the caller named `f(integer)` and the server has `f(text)`, and dropping
        `f(text)` because it was the only one there would drop an object nobody asked about.

        Calling this is optional and skipping it is not fatal: `drop_routine(ref, type)` with
        no signature still composes, and an overloaded name then fails at the server saying so.
        """

        rendered = self._routine_argument_list(signature, method="resolve_overload")
        # An empty string is kept, not filtered: on the one engine that overloads, `f()` is a
        # real overload and dropping it here would report it as absent.
        known = [str(one) for one in overloads if one is not None]
        where = self._overload_display(ref)
        if signature is None:
            # On an engine that cannot overload, one name is one object however many rows the
            # caller passed, so the question "which one" cannot arise and answering it with a
            # refusal would break a generic resolve-then-act caller on three engines out of
            # four.
            if not self.overloads_routines or len(known) <= 1:
                return None
            raise ValueError(
                f"{where} is overloaded {len(known)} ways and a name alone does not say which "
                f"one: pass one of {self._overload_display_list(known)}"
            )
        wanted = self._overload_key(signature)
        matched = [one for one in known if self._overload_key_or_none(one) == wanted]
        if len(matched) == 1:
            return matched[0]
        if not matched:
            raise ValueError(
                f"no overload of {where} takes {rendered or '()'}"
                + (
                    f"; the catalogue reports {self._overload_display_list(known)}"
                    if known
                    else ", and the catalogue reports no routine of that name at all"
                )
            )
        raise ValueError(
            f"{rendered or '()'} matches {len(matched)} of {where}'s overloads "
            f"({self._overload_display_list(matched)}); name the argument types exactly as "
            "the catalogue spells them"
        )

    def _overload_display(self, ref: NormalisedRef) -> str:
        """A routine reference as a message names it."""

        if ref.canonical_schema:
            return f"{ref.canonical_schema}.{ref.canonical_name}"
        return str(ref.canonical_name)

    @staticmethod
    def _overload_display_list(overloads: Sequence[str]) -> str:
        """The overload set as a message lists it."""

        return ", ".join(f"({one})" for one in overloads)

    def drop_routine(
        self,
        ref: NormalisedRef,
        object_type: ObjectType,
        signature: str | None = None,
        if_exists: bool = True,
    ) -> Script:
        """`signature` is the overload discriminator, and is needed on PostgreSQL whenever the
        name carries more than one object, because `DROP FUNCTION add` is ambiguous there and
        the server refuses it.

        Nowhere else does one mean anything: MS-SQL permits no overloading of a user function,
        MySQL none, and SQLite has no stored routine to drop at all.  Passing one there is
        refused rather than ignored (`_routine_argument_list()` says why).  Where it is
        accepted it is rebuilt from validated pieces rather than passed through, and
        `resolve_overload()` is how a caller turns "the one taking an integer" into the
        catalogue's own spelling of that.
        """

        keyword = self._routine_keyword(ref, object_type)
        arguments = self._routine_argument_list(signature, method="drop_routine")
        return self._drop_script(ref, keyword, if_exists, suffix=arguments)

    # -- 3.5 security: the shared composition kit ----------------------------------------
    #
    # Two rules carry the whole of this section's safety, and both live here rather than in
    # the four dialects for the reason the write kit does: four copies of a rule is four
    # places for it to drift, and these are the two least able to afford drifting.
    #
    #   * every principal name goes through `quote_principal()`;
    #   * every privilege word goes through `_validated_privileges()`.
    #
    # A principal name is where this layer differs most sharply from everything above it.  A
    # table name arrives from the catalogue and is checked against it; a principal name does
    # not exist in the catalogue until the statement creates it, so there is nothing to check
    # it against and `GRANT ... TO <name>` is caller-supplied text inside the statement that
    # decides who may do what.  It is treated as hostile without exception.

    #: The privilege words this engine will emit against a single object, keyed by their
    #: normalised form — upper-cased, internal whitespace collapsed — and valued by the exact
    #: spelling this module emits.
    #:
    #: The lookup is what makes the emission provable.  The text that reaches the statement is
    #: the **value** out of this table, so no byte of the caller's privilege string is ever in
    #: the SQL, whatever it contained and however it matched.  A privilege is a keyword rather
    #: than an identifier: no delimiter makes `ALL PRIVILEGES WITH GRANT OPTION` inert, so
    #: quoting cannot save this one and an allow-list is the only defence there is.
    #:
    #: Empty here on purpose, so a dialect that has not enumerated its own engine's vocabulary
    #: cannot grant anything: `_validated_privileges()` fails closed on an empty table.
    #:
    #: `ALL PRIVILEGES` is absent from every dialect's table and must stay absent.  It is the
    #: one privilege word whose meaning grows with the server — what it covered on the version
    #: the human approved is not what it covers after an upgrade — so a grant made through
    #: d-MCP would widen underneath the approval that authorised it.  The same reasoning keeps
    #: `GRANT OPTION` out as a privilege *word* on the engines that spell it as one: the
    #: ability to re-grant is `with_grant_option`, one visible flag on one call, not a string
    #: that can arrive in a list of six others.
    relation_privileges: ClassVar[frozenset[str]] = frozenset()

    #: The same, for a stored function or procedure.  Two sets rather than one because the two
    #: vocabularies barely overlap — `EXECUTE` is meaningless on a table and `INSERT` is
    #: meaningless on a function — and a caller who mixes them up gets a message naming the
    #: object type instead of a server error naming a syntax position.  They may overlap where
    #: the engine says they do: SQL Server's `VIEW DEFINITION` is in both.
    routine_privileges: ClassVar[frozenset[str]] = frozenset()

    def _privilege_table(self) -> Mapping[str, str]:
        """The engine's whole privilege vocabulary as `normalised -> emitted spelling`.

        Derived from the two sets rather than declared a third time, so a word cannot exist in
        the vocabulary without belonging to a scope — which is how `GRANT SELECT ON FUNCTION`
        would otherwise pass the vocabulary check and fail at the server.  The entries are
        written upper-cased and single-spaced in the dialects, which is exactly the normal form
        `_validated_privileges()` reduces a caller's word to, so the identity mapping is
        deliberate and not a placeholder.
        """

        return {word: word for word in (self.relation_privileges | self.routine_privileges)}

    def quote_principal(self, name: str, *, host: str | None = None) -> str:
        """Quote a role, user or group name for emission into a security statement.

        Separate from `quote_identifier()` because the two answer different questions.
        `quote_identifier()` renders a name that has already been matched against the
        catalogue; this renders one that never was and never could be, and the difference is
        the whole reason this method has a name of its own — a reader of `create_role()` should
        see that the name being emitted is untrusted, not have to infer it.

        The mechanism is nonetheless the engine's ordinary identifier quoting, because that is
        what the four engines accept for a principal: `[bob]`, `"bob"`, `` `bob` ``.  What
        differs is that there is no catalogue behind the name, so `quote_identifier()`'s
        refusals — an embedded NUL, an over-length name, MySQL's trailing space — are load
        bearing here rather than belt and braces.

        `host` is the second half of a MySQL account name and is refused on every other
        engine.  Accepting and ignoring it would let a caller believe it had scoped a grant to
        one host on a server that has no such notion, which is a belief about access that is
        false in the widening direction.
        """

        if host is not None:
            raise ValueError(
                f"{self.display_name} principals have no host part: 'host' is one half of a "
                "MySQL account name and means nothing here"
            )
        return self.quote_identifier(name)

    def _validated_privileges(
        self, privileges: Sequence[str], ref: NormalisedRef, *, what: str
    ) -> tuple[str, ...]:
        """Map the caller's privilege words onto this engine's own vocabulary, or refuse.

        §3.5 asks for this in terms: "an unrecognised privilege is refused rather than passed
        through, because passing it through is an identifier-injection hole in the one place
        it would be least expected".  The refusal is total — an unknown word is never emitted,
        never quoted, never repaired — and the words that *are* emitted come out of
        `_privilege_table()`, so the statement is composed from text this module owns even
        where the caller's spelling matched only case-insensitively.

        Duplicates collapse and first mention wins the ordering, so a list is emitted in the
        order the caller wrote it and an audit row reads the way the request did.  An empty
        sequence is refused rather than emitted: `GRANT ON t TO bob` with no privilege is a
        syntax error at the server and a mistake at the caller, and neither is improved by
        being guessed at.  A bare `str` is refused too — `privileges="SELECT"` iterates into
        seven one-character words, and every one of them would be rejected with a message
        about the letter `S`.
        """

        if isinstance(privileges, str):
            raise ValueError(
                "privileges is a sequence of privilege words, not one string: pass "
                "['SELECT'] rather than 'SELECT'"
            )
        table = self._privilege_table()
        if not table:
            raise self._unsupported(
                what, f"{self.display_name} has no object privilege vocabulary in this layer"
            )
        routine = ref.object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE)
        in_scope = self.routine_privileges if routine else self.relation_privileges
        ordered: dict[str, None] = {}
        for raw in privileges:
            if not isinstance(raw, str):
                raise ValueError(
                    f"a privilege must be a str, not {type(raw).__name__}"
                )
            canonical = table.get(" ".join(raw.upper().split()))
            if canonical is None:
                raise ValueError(
                    f"{raw!r} is not a privilege d-MCP will grant on {self.display_name}. "
                    "The accepted words are: " + ", ".join(sorted(table.values()))
                )
            if canonical not in in_scope:
                raise ValueError(
                    f"{canonical} is not a privilege {self.display_name} recognises on a "
                    f"{ref.object_type}. On this object type the accepted words are: "
                    + ", ".join(sorted(in_scope))
                )
            ordered[canonical] = None
        if not ordered:
            raise ValueError("at least one privilege is required")
        return tuple(ordered)

    @staticmethod
    def _check_grant_ref(ref: NormalisedRef | None) -> NormalisedRef:
        """Refuse the database-wide grant that `ref=None` asks for.

        `ref: NormalisedRef | None` is §3.5's signature and `None` means "the whole database".
        d-MCP authors no such grant on any engine, and the reason is not squeamishness alone:
        PostgreSQL's database-scoped form needs the database *name* as a literal, and a
        dialect holds no connection profile and therefore does not know it — the grammar
        admits no `current_database()` in that position either.  Supporting the broadest grant
        there is on two engines and refusing it on the other two would be worse than refusing
        it uniformly, so it is refused uniformly, and a human who wants it has a server prompt.
        """

        if ref is None:
            raise ValueError(
                "a grant with no object is a database-wide grant; d-MCP composes a grant "
                "against one named object only. A database-wide grant is made at the server "
                "by a human."
            )
        return ref

    def _security_step(self, sql: str) -> Query:
        """One security statement, parameterless and naming no object.

        `touches` is empty, and that is a decision rather than an omission.  The authorisation
        walk matches `ObjectRef`s against the rule table, and a principal is not an addressable
        object: what authorises these statements is the database-scoped `create_role`,
        `create_user`, `create_group`, `assign_role` or `assign_group` flag, resolved from the
        connection alone (`DESIGN-PERMISSIONS.md`, and the decision table's "database-scoped
        actions are resolved by connection alone").  Minting a synthetic `ObjectRef` for the
        principal would hand the resolver a name no rule can match, and a default-deny
        resolver answers "denied" to that — breaking the tool rather than securing it.

        `grant()` and `revoke()` are the exception that proves it: they *do* name a real
        object, and they report it, because there the object is exactly what is being
        permissioned.
        """

        return Query(sql=sql, params=self.parameters(()), kind=StatementKind.SECURITY)

    def _security_script(
        self,
        *sql: str,
        touches: Sequence[ObjectRef] = (),
        warning_key: str | None = None,
    ) -> Script:
        """Package one or more security statements as a `Script`.

        `atomic` follows `capabilities.supports_transactional_ddl`, which is the honest answer
        rather than the convenient one: on MySQL every statement here commits implicitly, so a
        two-step script genuinely has a window between its steps, and the `Script` says so
        instead of promising a rollback the engine cannot perform.
        """

        steps = tuple(self._security_step(one) for one in sql)
        if touches:
            steps = tuple(
                Query(sql=step.sql, params=step.params, kind=step.kind, touches=tuple(touches))
                for step in steps
            )
        return Script(
            steps=steps,
            atomic=self.capabilities.supports_transactional_ddl,
            warning_key=warning_key,
        )

    def _grant_touches(self, ref: NormalisedRef) -> tuple[ObjectRef, ...]:
        """The object a `GRANT`/`REVOKE` names, in the shape the authorisation walk reads."""

        return (
            ObjectRef(
                schema=ref.canonical_schema or self.addressable_schema,
                name=ref.canonical_name,
                object_type=ref.object_type,
            ),
        )

    # -- 3.5 security: the twelve builders ----------------------------------------------

    @abstractmethod
    def list_principals(self) -> Query:
        """Every role, user and group visible to the current principal, with enough columns
        to fill `PrincipalInfo` including which of the three d-MCP is calling it.

        Column order is part of the contract and is the same on all four engines:
        `(name, kind, native_kind, can_login, is_superuser)`, `kind` being one of d-MCP's own
        three words and `native_kind` whatever the server stores.  `mcp_server.py` reads
        column 0 as the name.
        """

    @abstractmethod
    def list_group_members(self, group: str) -> Query:
        """The members of one group, for the Explorer page's principal tree.

        `group` is a **bound value** here rather than a quoted identifier: this is a catalogue
        read comparing a name against a column, so it needs no more than a parameter, and a
        parameter is the strongest thing it could be.  It is still normalised on the way past,
        for the same reason `_schema_filter()` normalises: the comparison has to use the
        spelling the catalogue holds.
        """

    @abstractmethod
    def list_grants(self, ref: NormalisedRef | None = None) -> Query:
        """Server-side privileges, optionally for one object.  Read-only and shown beside the
        d-MCP rules in the Explorer page: the two permission systems are independent, and
        seeing where they disagree is most of the value of the page.

        Unlike `grant()`, `ref=None` is meaningful and supported: reading every grant in the
        database reveals nothing and grants nothing.  Column order is
        `(grantee, privilege, schema_name, object_name, grantable, state)`, and `state` is
        carried because SQL Server has `DENY` as well as `GRANT` and a `DENY` shown as a grant
        would over-report access.
        """

    @abstractmethod
    def create_role(self, name: str) -> Script:
        """Raises `CapabilityError` where `capabilities.supports_roles` is false — SQLite
        always, MySQL before 8.0, MariaDB before 10.0.5."""

    @abstractmethod
    def create_user(
        self,
        name: str,
        *,
        host: str | None = None,
        login: str | None = None,
        default_schema: str | None = None,
    ) -> Script:
        """Create a user that **cannot log in**, for a human to give a credential to later.

        This signature is a deliberate departure from §3.5, which had
        `create_user(name, password: SecretStr, *, host=None, login_only=False)`.
        `DESIGN-MCP-TOOLS.md` §11.2 is the newer document and is emphatic: *"`create-user`
        takes no password, by design. No credential is ever accepted from a model, generated
        by a tool, returned in a result or written to a log."*  The password parameter is
        therefore gone, and `_password_literal()` with it — deleted rather than implemented,
        with the reasoning recorded where it stood.

        `login_only` went the same way and for a related reason: with no credential to send,
        there is no `CREATE LOGIN` this layer can compose at all — a SQL login requires a
        password and a Windows login requires an Active Directory principal d-MCP has no way
        to check — so "the login half only" describes an act that no longer exists here.
        `login` replaces it, naming an **existing** login to map the new user onto, which is
        the case §4.1 was really about and the argument §11.2's tool actually carries.

        What each engine emits, and why each is genuinely unable to connect:

        * **MS-SQL** — `CREATE USER [x] WITHOUT LOGIN`, a database user mapped to no login and
          holding no password, or `CREATE USER [x] FOR LOGIN [y]` where a login is named.
        * **PostgreSQL** — `CREATE ROLE "x" NOLOGIN`.  `LOGIN PASSWORD NULL` would *not* do:
          `trust`, `peer`, `ident` and `cert` authentication never consult the password, so a
          `LOGIN` role with no password connects freely under any of them.
        * **MySQL** — `CREATE USER `x`@`h` ACCOUNT LOCK`.  A bare `CREATE USER` leaves an
          **empty** authentication string, which is a password the account can log in with.

        `host` is mandatory on MySQL, where identity is the pair `'user'@'host'`, and there is
        deliberately no default: defaulting to `'%'` would silently create a user reachable
        from anywhere on the network.  It is refused on the other three, which have no such
        notion.
        """

    @abstractmethod
    def create_group(self, name: str) -> Script:
        """"Group" is not a native object on any of the four engines; each dialect documents
        what it maps to (a `NOLOGIN` role, a database role, a MySQL 8 role)."""

    @abstractmethod
    def add_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """Add a principal to a group, in whatever the engine's spelling of that is.

        `host` is the host half of `member`'s MySQL account name, refused elsewhere.
        """

    @abstractmethod
    def remove_group_member(self, group: str, member: str, *, host: str | None = None) -> Script:
        """Remove a principal from a group."""

    @abstractmethod
    def assign_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """Grant a role to a principal — and, on MySQL, additionally `SET DEFAULT ROLE`,
        because a granted role is inert until activated and stopping at the `GRANT` leaves the
        human believing access was given when the next login proves otherwise."""

    @abstractmethod
    def revoke_role(self, role: str, principal: str, *, host: str | None = None) -> Script:
        """The inverse of `assign_role()`."""

    @abstractmethod
    def grant(
        self,
        privileges: Sequence[str],
        ref: NormalisedRef | None,
        principal: str,
        with_grant_option: bool = False,
        *,
        host: str | None = None,
        signature: str | None = None,
    ) -> Script:
        """`privileges` are validated against the engine's own privilege vocabulary before
        emission; an unrecognised privilege is refused rather than passed through, because
        passing it through is an identifier-injection hole in the one place it would be least
        expected.

        `ref=None` — a database-wide grant — is refused on every engine; see
        `_check_grant_ref()` for why that is uniform rather than per engine.

        `signature` is the same overload discriminator `drop_routine()` takes, and is here for
        the same reason: `GRANT EXECUTE ON FUNCTION f` is refused by PostgreSQL while more
        than one `f` exists, so a routine d-MCP can list and read would otherwise be one it
        cannot permission.  It is refused on the three engines that cannot overload and on any
        `ref` that is not a routine, and `resolve_overload()` is how a caller obtains one.
        """

    @abstractmethod
    def revoke(
        self,
        privileges: Sequence[str],
        ref: NormalisedRef | None,
        principal: str,
        *,
        host: str | None = None,
        signature: str | None = None,
    ) -> Script:
        """The inverse of `grant()`, with the same privilege-vocabulary validation and the
        same overload discriminator.

        A `REVOKE` that cannot name the overload is worse than a `GRANT` that cannot: the
        `GRANT` fails and nothing is given, while an operator who believes access was taken
        away and finds the statement refused has to notice the refusal to learn otherwise.
        """

    # -- 3.6 row operations (stage 6/7) -------------------------------------------------

    @abstractmethod
    def select(
        self,
        ref: NormalisedRef,
        columns: Sequence[str] | None = None,
        *,
        predicates: Sequence[Predicate] = (),
        where: RawPredicate | None = None,
        order_by: Sequence[tuple[str, bool]] = (),
        row_cap: int,
        offset: int = 0,
    ) -> Query:
        """A parameterised `SELECT` with a **mandatory** row cap.

        `row_cap` has no default anywhere in the signature chain, so no caller can forget it;
        `engine.py` caps again at `fetchmany(row_cap + 1)` and reports truncation honestly
        (decision D7).  `columns=None` means every column, expanded from the introspected
        catalogue rather than emitted as `*`, so the result shape is stable across a later
        `ALTER TABLE` and the LLM cannot be handed a column that appeared after the rule was
        written.  Every column name is validated against the catalogue and then quoted.

        `predicates` is the structured form of decision D3.  `where` is the free-form form
        the user has since ruled `select-rows` must accept, as `DESIGN-MCP-TOOLS.md` §5
        always described it: the fragment's text is emitted parenthesised and its values are
        bound, never interpolated, and the tool layer re-parses the *composed* statement
        through `SqlGuard` so a subquery inside the fragment is authorised object by object.
        Passing both is a caller bug and raises `ValueError`.

        `Query.touches` reports the one object named by `ref` and nothing the fragment
        reaches.  Enumerating the fragment's own references is the guard's job and is done
        against the composed text; a second, weaker enumeration here would be one more reader
        to disagree with the server's.
        """

    def _returning_clauses(self, returning: Sequence[str]) -> tuple[str, str]:
        """The two halves of a `RETURNING` clause: what goes before `VALUES` and what after.

        Two halves rather than one string because SQL Server puts its own spelling — `OUTPUT
        INSERTED.<column>` — between the column list and `VALUES`, where PostgreSQL and SQLite
        put `RETURNING` at the very end.  A single "suffix" would have emitted valid SQL on
        two engines and a syntax error on the third.

        Refused rather than silently dropped where the engine cannot return rows, because a
        caller relying on the returned keys would otherwise get nothing back and carry on.
        """

        if not returning:
            return "", ""
        if not self.capabilities.supports_returning:
            raise self._unsupported(
                "insert(returning=...)",
                f"{self.display_name} cannot return rows from an INSERT on this version",
            )
        quoted = self._quoted_columns(returning, what="returning")
        return "", " RETURNING " + ", ".join(quoted)

    def insert(
        self, ref: NormalisedRef, rows: Sequence[Mapping[str, Any]], *, returning: Sequence[str] = ()
    ) -> Query:
        """A multi-row `INSERT` with every value bound.  `returning` is honoured only where
        `capabilities.supports_returning`; elsewhere it is refused rather than silently
        dropped, because a caller relying on the returned keys would otherwise get `None` and
        carry on.

        **One statement, so a partial batch never lands.**  §7 of `DESIGN-MCP-TOOLS.md` asks
        for `insert-rows` to run its rows in one transaction; the strongest form of that this
        layer can author is one statement, which every engine executes atomically whether or
        not a transaction was opened around it.  There is no partial batch to land because
        there is no second statement to fail after the first succeeded — and a caller wrapping
        this in a transaction as well loses nothing.

        `MAX_WRITE_ROWS` is enforced here rather than only at the tool boundary, and the
        parameter budget with it: 1 000 rows of five columns is 5 000 markers, which is over
        SQL Server's 2 100 and over an older SQLite's 999.  Both refusals name the number, so
        "send fewer rows" is actionable.

        Every row must name the same columns.  A row with a different key set is refused
        rather than filled with `NULL` for the columns it omits: a silently defaulted column
        is a value the caller did not choose and will not be told about.
        """

        self._check_object_type(ref, ObjectType.TABLE, "insert")
        batch = list(rows)
        if not batch:
            raise ValueError("insert() needs at least one row")
        if len(batch) > MAX_WRITE_ROWS:
            raise ValueError(
                f"insert() was given {len(batch)} rows, over the {MAX_WRITE_ROWS}-row limit "
                "one statement may carry; send the rows in smaller batches"
            )
        if self.max_insert_value_rows is not None and len(batch) > self.max_insert_value_rows:
            raise ValueError(
                f"{self.display_name} accepts at most {self.max_insert_value_rows} row tuples "
                f"in one VALUES clause and {len(batch)} were given"
            )
        for position, row in enumerate(batch, start=1):
            if not isinstance(row, Mapping):
                raise ValueError(
                    f"row {position} is a {type(row).__name__}; insert() takes mappings of "
                    "column name to value"
                )
        columns = list(batch[0])
        if not columns:
            raise ValueError("insert() needs at least one column")
        for position, row in enumerate(batch[1:], start=2):
            if list(row) != columns:
                raise ValueError(
                    f"row {position} names different columns from row 1; every row of one "
                    "INSERT must name the same columns, because a column left out of a row is "
                    "a value the server would choose and the caller would never be told about"
                )
        quoted = self._quoted_columns(columns, what="insert()")
        prefix, suffix = self._returning_clauses(returning)

        values: list[Any] = []
        names: list[str] = []
        tuples: list[str] = []
        for position, row in enumerate(batch):
            marks = [
                self._bind(row[column], values, names, f"r{position}c{index}")
                for index, column in enumerate(columns)
            ]
            tuples.append("(" + ", ".join(marks) + ")")

        sql = (
            f"INSERT INTO {self.quote_ref(ref)} ({', '.join(quoted)}){prefix} "
            f"VALUES {', '.join(tuples)}{suffix}"
        )
        return self._row_query(sql, values, names, ref, StatementKind.WRITE)

    def update(
        self,
        ref: NormalisedRef,
        values: Mapping[str, Any],
        *,
        predicates: Sequence[Predicate] = (),
        where: RawPredicate | None = None,
    ) -> Query:
        """An `UPDATE` whose assignments and condition are both bound.

        An empty condition is a legal — but destructive — request: the resulting `Query.kind`
        is `DESTRUCTIVE`, which routes it through `confirmation.py` regardless of the
        permission flag.  It is deliberately *not* refused here.  The broker is what gates it,
        and the broker cannot gate a statement this layer declined to compose; refusing would
        look like safety while actually meaning the human never got asked.

        `where` supersedes §3.6's `predicates`-only signature, exactly as it did for
        `select()`: §12 gives `update-rows` a `where: str | None` and a `parameters: dict |
        None`, and the fragment is composed here — parenthesised, values bound into the slots
        after the `SET` list — because only the dialect knows the order its own clauses bind
        in.  Passing both forms raises.

        The `SET` values are bound **before** the condition, because that is the order they
        appear in the text and a positional paramstyle pairs values to markers by position
        alone.  Getting that backwards writes the filter into the row.
        """

        self._check_object_type(ref, ObjectType.TABLE, "update")
        if not isinstance(values, Mapping) or not values:
            raise ValueError("update() needs at least one column to set")
        self._quoted_columns(list(values), what="update()")

        bound: list[Any] = []
        names: list[str] = []
        assignments = [
            f"{self.quote_identifier(column)} = "
            f"{self._bind(value, bound, names, f'set{index}')}"
            for index, (column, value) in enumerate(values.items())
        ]
        condition = self._condition(predicates, where, bound, names)
        sql = f"UPDATE {self.quote_ref(ref)} SET {', '.join(assignments)}{condition}"
        # No condition means every row, which is the one shape of UPDATE the broker must see
        # (DESIGN-MCP-TOOLS.md §8.1).  A condition that is a tautology — `WHERE 1 = 1` — reads
        # as a condition from here and is the guard's `has_effective_where` to catch: this
        # method knows whether a fragment was supplied, not whether it filters anything.
        kind = StatementKind.WRITE if condition else StatementKind.DESTRUCTIVE
        return self._row_query(sql, bound, names, ref, kind)

    def delete(
        self,
        ref: NormalisedRef,
        *,
        predicates: Sequence[Predicate] = (),
        where: RawPredicate | None = None,
    ) -> Query:
        """As `update()`: always destructive, and doubly so with no predicate.

        `StatementKind.DESTRUCTIVE` unconditionally, condition or none — §8.1 brokers
        `delete-rows` "even with a WHERE", because deleted rows do not come back.  That is the
        one place `delete()` and `update()` differ, and it is the whole difference between the
        two rows of that table.
        """

        self._check_object_type(ref, ObjectType.TABLE, "delete")
        bound: list[Any] = []
        names: list[str] = []
        condition = self._condition(predicates, where, bound, names)
        sql = f"DELETE FROM {self.quote_ref(ref)}{condition}"
        return self._row_query(sql, bound, names, ref, StatementKind.DESTRUCTIVE)

    # `call_routine()` is deliberately absent.  `execute-function` and `execute-procedure` do
    # not ship at all: `DESIGN-MCP-TOOLS.md` §13 decision 1 records the user's ruling that
    # `prompt.md` never asked for routine execution, so both tools were scope the design had
    # invented, and the action sets shrank to `list, read_definition, create, edit, drop`
    # (§11.5, §11.6).  With no tool to serve, a builder for it would be unreachable surface on
    # a security-critical layer — and an `execute` grant on a body d-MCP cannot parse is
    # exactly the blank cheque the ruling removed.  A function is still reachable inside a
    # `run-read-query` SELECT, where the guard authorises what the function's own body reads.
    #
    # `rename_object()` is deliberately absent too.  None of the 38 tools in §12 renames
    # anything, and a rename moves an object out from under its permission rule — the most
    # security-sensitive DDL there is — so writing it before something calls it would leave an
    # unexercised path through the one part of the layer least able to afford one.



class DeferredSurface:
    """Empty.  Every method it once carried is implemented on a real dialect.

    This class was the layer's honesty mechanism.  It held one concrete stub for every
    `Dialect` method a stage had declared but not yet written, mixed in *before* `Dialect` by
    all four concrete classes so that each instantiated cleanly and the conformance test could
    ask "is any abstract method still unimplemented?" at collection time — while every call to
    a stub still failed loudly, naming the stage that would land it.

    Its docstring promised that when it was empty the layer would be finished.  Stage 8 emptied
    it.  The security surface — `list_principals`, `list_group_members`, `list_grants`,
    `create_role`, `create_user`, `create_group`, `add_group_member`, `remove_group_member`,
    `assign_role`, `revoke_role`, `grant` and `revoke` — was the last thing in here, and each
    stub was deleted as its implementation landed rather than after, so at no point did a real
    method and its own stub coexist.

    Two methods left this class **without** being implemented, and both are recorded where the
    gap is rather than only here: `call_routine()`, because `execute-function` and
    `execute-procedure` do not ship at all (`DESIGN-MCP-TOOLS.md` §13 decision 1), and
    `rename_object()`, because nothing among the 38 tools calls it and speculative surface on a
    security-sensitive layer is a liability.  A third, `_password_literal()`, was deleted from
    `Dialect` itself for a stronger reason still: §11.2 forbids d-MCP ever handling a
    credential, so the interpolation point it guarded no longer exists.

    It is kept, empty, rather than removed.  It costs one name in four class statements and it
    is where the next deferred method goes — and a stage that needs one will find the
    discipline already written down instead of inventing a private convention for it.  With
    nothing in it, a dialect that forgets a method now fails at instantiation with Python's own
    `TypeError`, which is the better error of the two.
    """
