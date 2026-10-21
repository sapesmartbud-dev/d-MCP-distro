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

"""Running the dialects' catalogue queries and turning their rows into d-MCP's own types."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from sape_d_mcp.db.dialects import (
    ColumnInfo,
    Dialect,
    DialectError,
    ForeignKeyInfo,
    KeyInfo,
    NormalisedRef,
    ObjectRef,
    ObjectType,
    ParameterInfo,
    Query,
)

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sape_d_mcp.db.engine import DatabaseConnection

logger = logging.getLogger(__name__)

__all__ = [
    "DefinitionText",
    "Introspector",
    "RelationEntry",
    "RoutineDescription",
    "RoutineEntry",
    "SchemaEntry",
    "TableDescription",
]


# --------------------------------------------------------------------------------------
# The row-shape contract
# --------------------------------------------------------------------------------------
#
# Every dialect's catalogue builder emits the *same* column order for the same method, and
# this module unpacks the rows positionally.  That uniformity is the whole reason there is
# one executor above four dialects instead of four executors: the engine-specific part is
# the SQL, which belongs in the dialect, and the shape is a contract between the two.
#
#   list_schemas()      (schema_name)
#   list_tables()       (schema_name, table_name, comment)
#   list_views()        (schema_name, view_name, is_materialised, comment)
#   list_functions()    (schema_name, routine_name, signature, returns, language,
#                        is_deterministic)
#   list_procedures()   as list_functions()
#   describe_table()    [0] columns   (column_name, data_type, is_nullable, column_default,
#                                      is_identity, is_generated, ordinal_position, comment)
#                       [1] primary   (constraint_name, column_name, key_ordinal)
#                       [2] unique    as [1]
#                       [3] foreign   (constraint_name, column_name, key_ordinal,
#                                      referenced_schema, referenced_table,
#                                      referenced_column, on_delete, on_update)
#   describe_routine()  [0] header    (schema_name, routine_name, routine_type, signature,
#                                      returns, language, is_deterministic)
#                       [1] params    (routine_signature, parameter_name, data_type,
#                                      parameter_mode, ordinal_position, has_default)
#   object_definition() (definition)
#
# Booleans arrive as 0/1 integers because three of the four engines have no boolean type in
# their catalogue; `_as_bool()` still accepts the other spellings a driver might hand back.

_TRUE_WORDS = frozenset({"1", "y", "t", "yes", "true", "on"})

#: Why a definition can come back NULL, per engine.  The caller must be able to tell "this
#: object has no body" from "you are not allowed to read the body", because an empty editor
#: with no explanation is the kind of thing that gets debugged for an hour.
_WITHHELD_REASON: dict[str, str] = {
    "mssql": (
        "SQL Server returned no module text. The object was created WITH ENCRYPTION, it is a "
        "CLR object whose body is an assembly, or this login lacks VIEW DEFINITION on it."
    ),
    "postgresql": (
        "PostgreSQL returned no definition. The current role lacks the privilege to read it, "
        "or the object is not one that stores source text."
    ),
    "mysql": (
        "MySQL returned an empty definition, which is how it reports a body withheld for want "
        "of SHOW VIEW on a view or SHOW_ROUTINE on a routine."
    ),
    "sqlite": "SQLite stored no CREATE text for this object.",
}


def _as_bool(value: Any) -> bool:
    """Coerce a catalogue truth value, whatever spelling the engine and driver chose.

    Written out rather than `bool(value)` because `bool("NO")` is `True`, and MySQL's
    `IS_DETERMINISTIC` is exactly that string.  The dialects normalise to 0/1 wherever they
    can, so this is the belt to that pair of braces.
    """

    if value is None:
        return False
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    return str(value).strip().lower() in _TRUE_WORDS


def _text(value: Any) -> str | None:
    """A catalogue string, with the empty string treated as absent.

    An empty comment, an empty default and an empty definition all mean "there is none" on at
    least one engine, and a GUI that renders `""` as a value shows an empty tooltip on every
    object that has no comment.
    """

    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value)
    return text if text != "" else None


# --------------------------------------------------------------------------------------
# What the catalogue hands back
# --------------------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class SchemaEntry:
    """One schema, in both spellings the rest of the application needs.

    `key_name` is `None` for a schema whose name decision D6 refuses to fold — an accented
    name with a case mapping, `Órdenes` and its kind.  Such a schema is shown, because hiding
    an object the human can see in their own database is worse than useless, and it is not
    addressable, because a match key that cannot be computed cannot be compared against a
    rule.  `unaddressable_reason` carries the sentence to show beside it.
    """

    canonical_name: str
    key_name: str | None
    unaddressable_reason: str | None = None

    @property
    def addressable(self) -> bool:
        """Whether a permission rule can be matched against this schema at all."""

        return self.key_name is not None


@dataclass(frozen=True, slots=True)
class RelationEntry:
    """One table or view from a `list_*` call.

    `ref` is the whole point of this layer: the resolver keys on `NormalisedRef.key_*`, so
    handing back a bare name would force every caller to normalise it again and one of them
    would eventually forget — or, worse, normalise it with the *unquoted* folding rule and
    turn PostgreSQL's `"Foo"` into `foo`, which is a different table.  It is `None` only for
    an object whose name cannot be keyed at all (decision D6), and `unaddressable_reason`
    then says why.
    """

    ref: NormalisedRef | None
    canonical_schema: str | None
    canonical_name: str
    object_type: ObjectType
    comment: str | None = None
    is_materialised: bool = False
    unaddressable_reason: str | None = None

    @property
    def addressable(self) -> bool:
        return self.ref is not None

    @property
    def display_name(self) -> str:
        """`schema.name`, or just the name where the engine has no schemas."""

        if self.canonical_schema is None:
            return self.canonical_name
        return f"{self.canonical_schema}.{self.canonical_name}"


@dataclass(frozen=True, slots=True)
class RoutineEntry:
    """One function or stored procedure from a `list_*` call.

    `signature` is the overload discriminator and is `""` on the three engines that cannot
    overload.  On PostgreSQL two entries can share `ref` and differ only here, which is
    exactly the situation `RoutineInfo`'s docstring describes: the permission rule matches
    the name, `DROP` needs the signature.
    """

    ref: NormalisedRef | None
    canonical_schema: str | None
    canonical_name: str
    object_type: ObjectType
    signature: str = ""
    returns: str | None = None
    language: str | None = None
    is_deterministic: bool | None = None
    unaddressable_reason: str | None = None

    @property
    def addressable(self) -> bool:
        return self.ref is not None

    @property
    def display_name(self) -> str:
        base = (
            self.canonical_name
            if self.canonical_schema is None
            else f"{self.canonical_schema}.{self.canonical_name}"
        )
        return f"{base}({self.signature})" if self.signature else base


@dataclass(frozen=True, slots=True)
class TableDescription:
    """A table or view as `describe_table()` found it.

    No comment and no row estimate: the comment comes from the `list_*` entry, which the
    schema browser already holds, and the estimate is `estimate_row_count()`'s job in stage 7
    — it is an approximation with its own caveats and does not belong in a structural
    description that everything else here can state exactly.
    """

    ref: NormalisedRef
    columns: tuple[ColumnInfo, ...] = ()
    primary_key: KeyInfo | None = None
    unique_keys: tuple[KeyInfo, ...] = ()
    foreign_keys: tuple[ForeignKeyInfo, ...] = ()

    @property
    def column_names(self) -> tuple[str, ...]:
        """The columns in catalogue order — what `select()` validates a column list against."""

        return tuple(column.name for column in self.columns)


@dataclass(frozen=True, slots=True)
class RoutineDescription:
    """One overload of a function or procedure, with its parameters in declaration order."""

    ref: NormalisedRef
    object_type: ObjectType
    signature: str = ""
    parameters: tuple[ParameterInfo, ...] = ()
    returns: str | None = None
    language: str | None = None
    is_deterministic: bool | None = None


@dataclass(frozen=True, slots=True)
class DefinitionText:
    """The stored source of a view or routine, and — when there is none — why not.

    `available` is `False` both for "no such object" and for "withheld", with `reason`
    telling them apart in words the GUI and the MCP tool show verbatim.  Collapsing the two
    into an empty string is how a caller ends up believing a routine has an empty body and
    overwriting it.
    """

    ref: NormalisedRef
    text: str | None = None
    available: bool = False
    reason: str | None = None


# --------------------------------------------------------------------------------------
# The executor
# --------------------------------------------------------------------------------------


@dataclass
class _Cache:
    """The per-connection catalogue cache.

    Plain dictionaries with no expiry: the Permissions page's schema browser calls this on
    every tree selection, and a catalogue does not change under a running session unless
    d-MCP itself changed it — at which point the caller invalidates explicitly.  A
    time-based expiry would be a guess in both directions, refetching what has not moved and
    serving what has.
    """

    schemas: tuple[SchemaEntry, ...] | None = None
    relations: dict[tuple[str, str | None], tuple[RelationEntry, ...]] = field(default_factory=dict)
    routines: dict[tuple[str, str | None], tuple[RoutineEntry, ...]] = field(default_factory=dict)
    tables: dict[NormalisedRef, TableDescription] = field(default_factory=dict)
    described_routines: dict[NormalisedRef, tuple[RoutineDescription, ...]] = field(
        default_factory=dict
    )
    definitions: dict[NormalisedRef, DefinitionText] = field(default_factory=dict)


class Introspector:
    """Reads one connection's catalogue and returns d-MCP's own types.

    A thin executor over the dialect: the dialect authors the SQL and fixes the row shape,
    `engine.py` owns the connection, and this class runs the one against the other and maps
    the rows.  It holds no SQL of its own — a catalogue query written here would be a
    fifth dialect nobody would think to look for.

    **Why this may execute statements directly.**  `DatabaseConnection.execute()` carries a
    warning that it is the plumbing under `sql_guard`, not a route around it.  The exemption
    this class relies on is narrow and worth stating: every statement it runs was built by
    the dialect from a fixed template, no caller text is spliced into any of them, every
    value is bound, and every one is a `SELECT` against the server's own catalogue.  There is
    nothing for the guard to classify that is not already known, and routing catalogue reads
    through the guard would make the guard depend on the introspection it exists to trust.
    Anything carrying caller-supplied SQL — `run-read-query` and every write — goes through
    `sql_guard` and does not come here.

    One instance per `DatabaseConnection`, held by the caller: the cache is the instance.
    `DatabaseConnection` defines `__slots__` without `__weakref__`, so this module cannot
    keep a weak registry of them, and a strong one would pin closed connections in memory
    for the life of the process.
    """

    def __init__(self, db: DatabaseConnection) -> None:
        self._db = db
        self._cache = _Cache()

    def __repr__(self) -> str:
        return f"<Introspector {self._db!r}>"

    @property
    def dialect(self) -> Dialect:
        """The connection's dialect, for a caller that needs to quote or normalise itself."""

        return self._db.dialect

    # -- cache -------------------------------------------------------------------------

    def invalidate(self) -> None:
        """Forget everything.  Call after any DDL and after switching database."""

        self._cache = _Cache()
        logger.debug("Catalogue cache cleared for %r", self._db)

    def invalidate_object(self, ref: NormalisedRef | ObjectRef) -> None:
        """Forget one object's description, keeping the listings.

        The listings stay because a `describe`-level change — a column added, a key dropped —
        does not move the object in or out of any list.  A `create` or a `drop` does, and
        that is what `invalidate()` is for.
        """

        target = self._coerce_ref(ref)
        self._cache.tables.pop(target, None)
        self._cache.described_routines.pop(target, None)
        self._cache.definitions.pop(target, None)

    # -- listings ----------------------------------------------------------------------

    def list_schemas(self) -> tuple[SchemaEntry, ...]:
        """Every schema the connection can see.

        SQLite answers with the single synthetic `main`, so the schema browser needs no
        engine test — see `SQLiteDialect.list_schemas()` for why that is a synthetic row
        rather than an empty list.
        """

        if self._cache.schemas is None:
            entries = []
            for row in self._rows(self.dialect.list_schemas()):
                name = _text(row[0])
                if name is None:
                    continue
                key, reason = self._key_for(name, routine=False)
                entries.append(SchemaEntry(canonical_name=name, key_name=key, unaddressable_reason=reason))
            self._cache.schemas = tuple(entries)
        return self._cache.schemas

    def list_tables(self, schema: str | None = None) -> tuple[RelationEntry, ...]:
        """Base tables in `schema`, or in every visible schema when it is `None`."""

        return self._list_relations("tables", schema, ObjectType.TABLE)

    def list_views(self, schema: str | None = None) -> tuple[RelationEntry, ...]:
        """Views, with materialised ones flagged rather than hidden or conflated."""

        return self._list_relations("views", schema, ObjectType.VIEW)

    def list_functions(self, schema: str | None = None) -> tuple[RoutineEntry, ...]:
        """Functions.  Empty on SQLite, which has none to enumerate — never an exception."""

        return self._list_routines("functions", schema, ObjectType.FUNCTION)

    def list_procedures(self, schema: str | None = None) -> tuple[RoutineEntry, ...]:
        """Stored procedures.  Empty on SQLite; empty on PostgreSQL below 11, which has none."""

        return self._list_routines("procedures", schema, ObjectType.PROCEDURE)

    # -- descriptions ------------------------------------------------------------------

    def describe_table(self, ref: NormalisedRef | ObjectRef) -> TableDescription:
        """Columns, primary key, unique keys and foreign keys for a table or a view.

        Returns a description with no columns rather than raising when the object is not
        there: the caller that needs the distinction has `resolve()`, which says so plainly,
        and a GUI panel refreshing on a tree selection should not have to catch an exception
        for an object that was dropped between the click and the query.
        """

        target = self._coerce_ref(ref)
        cached = self._cache.tables.get(target)
        if cached is not None:
            return cached

        queries = self.dialect.describe_table(target)
        if len(queries) != 4:
            raise DialectError(
                f"{type(self.dialect).__name__}.describe_table() returned {len(queries)} "
                "queries; the contract is four, in the order columns, primary key, unique "
                "keys, foreign keys"
            )
        columns = tuple(self._column(row) for row in self._rows(queries[0]))
        primary = self._keys(self._rows(queries[1]), primary=True)
        unique = self._keys(self._rows(queries[2]), primary=False)
        foreign = self._foreign_keys(self._rows(queries[3]))
        description = TableDescription(
            ref=target,
            columns=columns,
            primary_key=primary[0] if primary else None,
            unique_keys=unique,
            foreign_keys=foreign,
        )
        self._cache.tables[target] = description
        return description

    def describe_routine(self, ref: NormalisedRef | ObjectRef) -> tuple[RoutineDescription, ...]:
        """Every routine sharing this name, with its parameters.

        A tuple and not a single value because PostgreSQL overloads: `add(int, int)` and
        `add(text, text)` are two objects under one name and one permission rule, and picking
        the first would silently describe the wrong one half the time.  The other three
        engines return at most one element — or two, on MySQL, where a function and a
        procedure may share a name.
        """

        target = self._coerce_ref(ref)
        cached = self._cache.described_routines.get(target)
        if cached is not None:
            return cached

        queries = self.dialect.describe_routine(target)
        if len(queries) != 2:
            raise DialectError(
                f"{type(self.dialect).__name__}.describe_routine() returned {len(queries)} "
                "queries; the contract is two, the header then the parameters"
            )
        headers = self._rows(queries[0])
        parameter_rows = self._rows(queries[1])

        by_signature: dict[str | None, list[ParameterInfo]] = {}
        for row in parameter_rows:
            by_signature.setdefault(_text(row[0]), []).append(
                ParameterInfo(
                    name=_text(row[1]),
                    data_type=_text(row[2]) or "",
                    mode=(_text(row[3]) or "IN").upper(),
                    position=int(row[4] or 0),
                    has_default=_as_bool(row[5]),
                )
            )
        # A NULL signature in the parameter rows means "this engine cannot overload, so these
        # belong to whichever routine you asked about" — MySQL, MS-SQL and SQLite all say it.
        unkeyed = by_signature.get(None, [])

        descriptions = []
        for row in headers:
            signature = _text(row[3]) or ""
            parameters = by_signature.get(signature) if signature else None
            if parameters is None:
                parameters = unkeyed
            object_type = (
                ObjectType.PROCEDURE
                if (_text(row[2]) or "").lower() == "procedure"
                else ObjectType.FUNCTION
            )
            descriptions.append(
                RoutineDescription(
                    ref=NormalisedRef(
                        canonical_schema=target.canonical_schema,
                        canonical_name=target.canonical_name,
                        key_schema=target.key_schema,
                        key_name=target.key_name,
                        object_type=object_type,
                    ),
                    object_type=object_type,
                    signature=signature,
                    parameters=tuple(sorted(parameters, key=lambda p: p.position)),
                    returns=_text(row[4]),
                    language=_text(row[5]),
                    is_deterministic=None if row[6] is None else _as_bool(row[6]),
                )
            )
        result = tuple(descriptions)
        self._cache.described_routines[target] = result
        return result

    def definition_of(self, ref: NormalisedRef | ObjectRef) -> DefinitionText:
        """The stored source text of a view, function or procedure.

        Three outcomes, deliberately distinguished: text; no row at all, which is "no such
        object, or its metadata is invisible to this login"; and a row holding NULL, which is
        "the server has it and will not give it to you" and carries the engine's own reason.
        """

        target = self._coerce_ref(ref)
        cached = self._cache.definitions.get(target)
        if cached is not None:
            return cached

        rows = self._rows(self.dialect.object_definition(target))
        if not rows:
            result = DefinitionText(
                ref=target,
                available=False,
                reason=(
                    "No such object, or its definition is not visible to this login. "
                    "Re-list the schema: it may have been dropped or renamed."
                ),
            )
        else:
            texts = [t for t in (_text(row[0]) for row in rows) if t is not None]
            if not texts:
                result = DefinitionText(
                    ref=target,
                    available=False,
                    reason=_WITHHELD_REASON.get(
                        str(self.dialect.engine), "The server returned no definition text."
                    ),
                )
            elif len(texts) == 1:
                result = DefinitionText(ref=target, text=texts[0], available=True)
            else:
                # PostgreSQL overloading again: one name, several bodies.  Showing the first
                # and dropping the rest would be a silent lie in the one place a human is
                # most likely to copy the text back out and re-create the routine with it.
                result = DefinitionText(
                    ref=target,
                    text="\n\n".join(texts),
                    available=True,
                    reason=(
                        f"This name has {len(texts)} overloads and all {len(texts)} "
                        "definitions are shown, separated by a blank line. A permission rule "
                        "matches the name, so it covers every one of them."
                    ),
                )
        self._cache.definitions[target] = result
        return result

    # -- resolution --------------------------------------------------------------------

    def resolve(
        self,
        name: str,
        schema: str | None = None,
        object_type: ObjectType = ObjectType.TABLE,
    ) -> NormalisedRef:
        """Look an identifier up in the catalogue and adopt the spelling the server reports.

        This is `DESIGN-PERMISSIONS.md` §5.3's rule in code, and it is the reason folding
        alone is not trusted: the MS-SQL collation and MySQL's `lower_case_table_names` are
        per-server settings, so the only authority on how an object is spelled is the server
        that holds it.

        Raises `LookupError` when nothing matches and `ValueError` when more than one does —
        which MySQL can produce under a case-insensitive setting on a case-sensitive
        filesystem, and MS-SQL under a case-sensitive collation.  Neither is guessed at: an
        ambiguous identifier resolved by picking one is a permission rule applied to the
        wrong object.
        """

        if not isinstance(name, str) or name.strip() == "":
            raise ValueError("an object name must be a non-empty string")
        wanted_name, wanted_schema = self._match_keys(name, schema, object_type)

        candidates: list[NormalisedRef] = []
        if object_type in (ObjectType.TABLE, ObjectType.VIEW):
            entries: Iterable[Any] = (
                self.list_tables(schema) if object_type is ObjectType.TABLE else self.list_views(schema)
            )
        elif object_type is ObjectType.FUNCTION:
            entries = self.list_functions(schema)
        elif object_type is ObjectType.PROCEDURE:
            entries = self.list_procedures(schema)
        else:
            raise ValueError(f"{object_type} is not an object type that can be resolved by name")

        for entry in entries:
            if entry.ref is None:
                continue
            if entry.ref.key_name != wanted_name:
                continue
            # An entry with no schema key is SQLite's, where there is exactly one schema and
            # the catalogue reports none; asking for `main` there must not filter it away.
            if (
                wanted_schema is not None
                and entry.ref.key_schema is not None
                and entry.ref.key_schema != wanted_schema
            ):
                continue
            if entry.ref not in candidates:
                candidates.append(entry.ref)

        if not candidates:
            where = f"{schema}." if schema else ""
            raise LookupError(
                f"no {object_type} called {where}{name} exists in this connection's catalogue, "
                "or it is not visible to this login"
            )
        if len(candidates) > 1:
            spellings = ", ".join(
                f"{c.canonical_schema}.{c.canonical_name}" if c.canonical_schema else c.canonical_name
                for c in candidates
            )
            raise ValueError(
                f"{name!r} matches more than one {object_type} in this catalogue ({spellings}). "
                "d-MCP will not guess which was meant: qualify it, or write the rule against "
                "the exact stored spelling."
            )
        return candidates[0]

    # -- internals ---------------------------------------------------------------------

    def _rows(self, query: Query) -> list[tuple[Any, ...]]:
        """Run one catalogue `Query` and return its rows as plain tuples.

        Tuples rather than the driver's own row objects: pyodbc's `Row`, psycopg's tuple and
        mysql-connector's list are three different things, and letting any of them past this
        point would put a driver test in the mapping code.
        """

        logger.debug("Catalogue query on %r: %s", self._db, query.sql)
        cursor = self._db.execute(query.sql, query.params)
        try:
            rows = cursor.fetchall()
        finally:
            try:
                cursor.close()
            except Exception:
                logger.debug("Error closing a catalogue cursor", exc_info=True)
        return [tuple(row) for row in rows]

    def _list_relations(
        self, kind: str, schema: str | None, object_type: ObjectType
    ) -> tuple[RelationEntry, ...]:
        cached = self._cache.relations.get((kind, schema))
        if cached is not None:
            return cached
        query = (
            self.dialect.list_tables(schema)
            if object_type is ObjectType.TABLE
            else self.dialect.list_views(schema)
        )
        entries = []
        for row in self._rows(query):
            name = _text(row[1])
            if name is None:
                continue
            schema_name = _text(row[0])
            ref, reason = self._ref_for(schema_name, name, object_type)
            entries.append(
                RelationEntry(
                    ref=ref,
                    canonical_schema=schema_name,
                    canonical_name=name,
                    object_type=object_type,
                    comment=_text(row[2]) if object_type is ObjectType.TABLE else _text(row[3]),
                    is_materialised=_as_bool(row[2]) if object_type is ObjectType.VIEW else False,
                    unaddressable_reason=reason,
                )
            )
        result = tuple(entries)
        self._cache.relations[(kind, schema)] = result
        return result

    def _list_routines(
        self, kind: str, schema: str | None, object_type: ObjectType
    ) -> tuple[RoutineEntry, ...]:
        cached = self._cache.routines.get((kind, schema))
        if cached is not None:
            return cached
        query = (
            self.dialect.list_functions(schema)
            if object_type is ObjectType.FUNCTION
            else self.dialect.list_procedures(schema)
        )
        entries = []
        for row in self._rows(query):
            name = _text(row[1])
            if name is None:
                continue
            schema_name = _text(row[0])
            ref, reason = self._ref_for(schema_name, name, object_type)
            entries.append(
                RoutineEntry(
                    ref=ref,
                    canonical_schema=schema_name,
                    canonical_name=name,
                    object_type=object_type,
                    signature=_text(row[2]) or "",
                    returns=_text(row[3]),
                    language=_text(row[4]),
                    is_deterministic=None if row[5] is None else _as_bool(row[5]),
                    unaddressable_reason=reason,
                )
            )
        result = tuple(entries)
        self._cache.routines[(kind, schema)] = result
        return result

    @staticmethod
    def _column(row: Sequence[Any]) -> ColumnInfo:
        return ColumnInfo(
            name=_text(row[0]) or "",
            data_type=_text(row[1]) or "",
            nullable=_as_bool(row[2]),
            default=_text(row[3]),
            is_identity=_as_bool(row[4]),
            is_generated=_as_bool(row[5]),
            position=int(row[6] or 0),
            comment=_text(row[7]),
        )

    @staticmethod
    def _keys(rows: Sequence[Sequence[Any]], *, primary: bool) -> tuple[KeyInfo, ...]:
        """Group one-row-per-column key rows into one `KeyInfo` per constraint.

        Ordered by the ordinal the catalogue gave, never by the order the rows arrived: a
        composite key reported back to front is a description that reads plausibly and is
        wrong, which is worse than one that is obviously broken.
        """

        grouped: dict[str, list[tuple[int, str]]] = {}
        for row in rows:
            name = _text(row[0]) or ""
            column = _text(row[1])
            if column is None:
                continue
            grouped.setdefault(name, []).append((int(row[2] or 0), column))
        return tuple(
            KeyInfo(
                name=name,
                columns=tuple(column for _, column in sorted(columns)),
                is_primary=primary,
            )
            for name, columns in grouped.items()
        )

    @staticmethod
    def _foreign_keys(rows: Sequence[Sequence[Any]]) -> tuple[ForeignKeyInfo, ...]:
        """Group foreign-key rows by constraint, keeping local and referenced columns paired."""

        grouped: dict[str, dict[str, Any]] = {}
        for row in rows:
            name = _text(row[0]) or ""
            entry = grouped.setdefault(
                name,
                {
                    "columns": [],
                    "referenced_schema": _text(row[3]),
                    "referenced_table": _text(row[4]) or "",
                    "on_delete": _text(row[6]),
                    "on_update": _text(row[7]),
                },
            )
            entry["columns"].append((int(row[2] or 0), _text(row[1]), _text(row[5])))
        keys = []
        for name, entry in grouped.items():
            pairs = sorted(entry["columns"])
            keys.append(
                ForeignKeyInfo(
                    name=name,
                    columns=tuple(local for _, local, _ in pairs if local is not None),
                    referenced_schema=entry["referenced_schema"],
                    referenced_table=entry["referenced_table"],
                    # A NULL referenced column survives SQLite's implicit-parent-key case
                    # only where the parent has no primary key at all, which is a broken
                    # foreign key the server will refuse to enforce; it is dropped rather
                    # than rendered as the string "None".
                    referenced_columns=tuple(
                        remote for _, _, remote in pairs if remote is not None
                    ),
                    on_delete=entry["on_delete"],
                    on_update=entry["on_update"],
                )
            )
        return tuple(keys)

    def _coerce_ref(self, ref: NormalisedRef | ObjectRef) -> NormalisedRef:
        """Accept either reference type, normalising an `ObjectRef` on the way through.

        An `ObjectRef` is raw input — it is what the GUI and the MCP argument parser build —
        so it goes through `normalise_ref()`, which applies the engine's folding rule and the
        default schema.  A `NormalisedRef` came from a listing here and is already the
        catalogue's own spelling; folding it again would rewrite PostgreSQL's `"Foo"` to
        `foo` and address a different table.
        """

        if isinstance(ref, NormalisedRef):
            return ref
        if isinstance(ref, ObjectRef):
            return self.dialect.normalise_ref(ref)
        raise TypeError(f"expected a NormalisedRef or an ObjectRef, not {type(ref).__name__}")

    def _key_for(self, name: str, *, routine: bool) -> tuple[str | None, str | None]:
        """The match key for one catalogue name, or `None` and the reason it has none.

        Routine names take `column_match_key()` rather than `identifier_match_key()`.  That
        is not a slip: on MySQL, table names follow `lower_case_table_names` while column,
        index and stored-routine names are case-insensitive on every platform, and
        `MySQLDialect.identifier_match_key()`'s own docstring says it cannot tell which kind
        it was handed.  Getting this wrong would make a rule for `myproc` stop matching
        `MyProc` on a Linux server, which is a denial nobody could debug from the GUI.
        """

        try:
            return (
                self.dialect.column_match_key(name)
                if routine
                else self.dialect.identifier_match_key(name)
            ), None
        except DialectError as exc:
            logger.info("Catalogue name %r cannot be keyed on %s: %s", name, self.dialect.engine, exc)
            return None, str(exc)

    def _ref_for(
        self, schema: str | None, name: str, object_type: ObjectType
    ) -> tuple[NormalisedRef | None, str | None]:
        """Mint a `NormalisedRef` from a row the catalogue returned.

        `normalise_identifier(..., quoted=True)` and not the unquoted form, which is the
        whole subtlety of this function.  A name read out of the catalogue **is** the
        canonical spelling by definition; running it through the unquoted folding rule would
        turn PostgreSQL's `"Foo"` into `foo` and mint a reference to a table that may not
        exist, or worse, to a different one that does.  `normalise_ref()` cannot be used here
        for the same reason: it has no `quoted` parameter.
        """

        routine = object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE)

        # An engine with no schema layer still needs a schema in the permission key:
        # `rule_targets.schema_pattern` is NOT NULL, and DESIGN-PERMISSIONS.md §5.5 resolves that by
        # canonicalising SQLite's implicit schema to `main` rather than teaching the resolver
        # that one engine is different. This does not change the SQL: `quote_ref()` omits the
        # schema whenever `default_schema is None`, which stays true for SQLite.
        if schema is None and not self.dialect.capabilities.supports_schemas:
            schema = self.dialect.addressable_schema

        try:
            canonical_schema = (
                self.dialect.normalise_identifier(schema, quoted=True) if schema is not None else None
            )
            canonical_name = self.dialect.normalise_identifier(name, quoted=True)
        except DialectError as exc:
            return None, str(exc)
        key_schema: str | None = None
        if canonical_schema is not None:
            key_schema, reason = self._key_for(canonical_schema, routine=False)
            if key_schema is None:
                return None, reason
        key_name, reason = self._key_for(canonical_name, routine=routine)
        if key_name is None:
            return None, reason
        return (
            NormalisedRef(
                canonical_schema=canonical_schema,
                canonical_name=canonical_name,
                key_schema=key_schema,
                key_name=key_name,
                object_type=object_type,
            ),
            None,
        )

    def _match_keys(
        self, name: str, schema: str | None, object_type: ObjectType
    ) -> tuple[str, str | None]:
        """The keys `resolve()` compares a caller's spelling against.

        The caller's text is untrusted, so it takes the *unquoted* folding rule — the
        opposite of `_ref_for()`, and for the opposite reason: this is what the user typed,
        not what the server stores.
        """

        routine = object_type in (ObjectType.FUNCTION, ObjectType.PROCEDURE)
        canonical_name = self.dialect.normalise_identifier(name)
        key_name = (
            self.dialect.column_match_key(canonical_name)
            if routine
            else self.dialect.identifier_match_key(canonical_name)
        )
        if schema is None:
            return key_name, None
        canonical_schema = self.dialect.normalise_identifier(schema)
        return key_name, self.dialect.identifier_match_key(canonical_schema)
