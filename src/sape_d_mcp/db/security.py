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

"""Running the dialects' security builders: roles, users, groups, membership and grants."""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from sape_d_mcp.db import engine as db_engine
from sape_d_mcp.db.dialects import (
    Dialect,
    DialectError,
    Engine,
    NormalisedRef,
    ObjectRef,
    PrincipalInfo,
    Query,
    Script,
)
from sape_d_mcp.db.sql_guard import Classification, GuardRefusal, SqlGuard

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sape_d_mcp.db.engine import DatabaseConnection

logger = logging.getLogger(__name__)

__all__ = [
    "GROUP_KIND",
    "ROLE_KIND",
    "USER_KIND",
    "SecurityManager",
    "same_principal",
]


# --------------------------------------------------------------------------------------
# The row-shape contract
# --------------------------------------------------------------------------------------
#
# As in `introspection.py`: every dialect's security query emits the *same* column order for
# the same method and this module unpacks the rows positionally.  The SQL belongs to the
# dialect, which alone knows `pg_roles` from `sys.database_principals` from `mysql.user`; the
# shape is a contract between the dialect and this module, and it is written down here
# because this is the only place that reads it.
#
#   list_principals()     (name, kind, native_kind, can_login, is_superuser)
#   list_group_members()  (member_name, ...)   -- only the first column is read
#   list_grants()         (grantee, privilege, schema_name, object_name, grantable, state)
#
# `state` is carried because SQL Server has `DENY` as well as `GRANT`, and a `DENY` rendered
# as a grant would over-report access in the one panel an operator reads to find out what the
# server allows.
#
# `kind` is d-MCP's own vocabulary — `user`, `group` or `role` — and `native_kind` is what
# the server actually stores (`sql_login`, `database_user`, `database_role`, `role`), exactly
# as `PrincipalInfo` describes.  Booleans arrive as 0/1 integers because no catalogue among
# the four engines agrees on a boolean type.
#
# `list_group_members()` is read one column wide on purpose: it is the one query a dialect is
# most likely to want to widen later (a member's own kind, say), and a consumer that reads
# only what it needs does not have to be revised when it does.

#: d-MCP's three principal kinds.  A principal must land in at least one of them: a role the
#: catalogue reports and no list shows is a holder of access nobody can see.
USER_KIND = "user"
GROUP_KIND = "group"
ROLE_KIND = "role"

def _matches_kind(kind: str, wanted: str | None) -> bool:
    """Whether a principal of `kind` belongs in a listing asked for `wanted`.

    `user` is exact.  `role` and `group` match each other, and that is not laxity — it is the
    only reading of the three engines that does not lose principals:

    * PostgreSQL never says `role` at all.  Its `list_principals()` reports `user` for a role
      that may log in and `group` for one that may not, because that is the only distinction
      the server stores.  A strict `list-roles` would answer with nothing on the engine where
      every group *is* a role.
    * MS-SQL says `role` for a database role and reserves `group` for a **Windows** group,
      which is the opposite spelling of the same idea, and §11.2 describes `list-groups`
      there as answering over database roles.
    * MySQL 8 has one object for both.

    So the two tools answer over the same principals and differ in the word they use.  Each
    entry carries its own `kind` and `native_kind`, so a caller that needs the distinction
    still has it; what it cannot do is silently lose a principal to it.
    """

    if wanted is None:
        return True
    if kind == wanted:
        return True
    return {kind, wanted} == {ROLE_KIND, GROUP_KIND}


#: What "group" means on each engine, for the sentence `create_group()` reports.  None of the
#: four engines has a native group object (`DESIGN-DIALECTS.md` §3.5), and a model told only
#: "Created group 'readers'" would report something the operator cannot find in their own
#: server's catalogue under that word.
_GROUP_MAPPING: dict[str, str] = {
    Engine.MSSQL: "a SQL Server database role",
    Engine.POSTGRESQL: "a PostgreSQL role with NOLOGIN",
    Engine.MYSQL: "a MySQL role",
}

#: Engines where a user's identity is the pair `'name'@'host'` rather than a bare name.
#: `Dialect.create_user()` documents that `host` is mandatory on MySQL and deliberately has
#: no default, because defaulting to `'%'` silently creates a user reachable from anywhere on
#: the network.  The MCP tool signature (§11.2) has no `host` argument at all, so this module
#: accepts `name@host` in the username and refuses a bare name rather than inventing one.
_HOST_IS_IDENTITY = frozenset({Engine.MYSQL})

_TRUE_WORDS = frozenset({"1", "y", "t", "yes", "true", "on"})


def _as_bool(value: Any) -> bool:
    """Coerce a catalogue truth value, whatever spelling the engine and driver chose.

    Deliberately a second copy of `introspection._as_bool()` rather than an import of a
    private name across modules or a new shared module this stage did not ask for.  The
    reason it cannot be `bool(value)` is the same one: `bool("NO")` is `True`, and MySQL
    writes exactly that string into several catalogue columns.
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


def _close_quietly(cursor: Any) -> None:
    """Close a cursor without letting the close itself become the error.

    A cursor that will not close is not what went wrong on any path here, and letting it
    raise would replace the driver's account of the real failure with a footnote about
    housekeeping.
    """

    try:
        cursor.close()
    except Exception:
        logger.debug("Error closing a security cursor", exc_info=True)


def _text(value: Any) -> str | None:
    """A catalogue string, with the empty string treated as absent."""

    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = str(value)
    return text if text != "" else None


def same_principal(left: str | None, right: str | None) -> bool:
    """Whether two principal names are plausibly the same server principal.

    Deliberately loose, and only ever used to *refuse* — never to authorise.  Principal-name
    case rules are not the object-name rules the dialect can answer for: MySQL user names are
    case-sensitive while its table names follow `lower_case_table_names`, PostgreSQL folds an
    unquoted role name and preserves a quoted one, and MS-SQL follows the database collation.
    `identifier_match_key()` answers the *object* question and would be the wrong authority
    here.

    So this compares the names case-insensitively, and on the bare name either side of a
    MySQL `name@host` as well.  The asymmetry is the point: an over-match costs one `REVOKE`
    that a human types by hand, and an under-match costs the connection d-MCP is running on.
    """

    if not isinstance(left, str) or not isinstance(right, str):
        return False
    def _forms(value: str) -> set[str]:
        bare = value.strip().strip("'\"[]`")
        forms = {bare.casefold()}
        if "@" in bare:
            forms.add(bare.rsplit("@", 1)[0].strip().strip("'\"[]`").casefold())
        return {form for form in forms if form}

    return bool(_forms(left) & _forms(right))


class SecurityManager:
    """Runs one connection's security builders and reports what they did in a sentence.

    The analogue of :class:`~sape_d_mcp.db.introspection.Introspector` for principals rather
    than objects: the dialect authors the SQL and fixes the row shape, `engine.py` owns the
    connection, and this class runs the one against the other.  It holds no SQL of its own —
    a `GRANT` written here would be a fifth dialect nobody would think to look for — and it
    **authorises nothing**.  The `database`-scoped action (`create_role`, `create_user`,
    `create_group`, `assign_group`, `assign_role`, `read_catalogue`) is checked by the MCP
    layer before it calls in, exactly as it is for every other tool.

    **Why these writes do not go through `SqlGuard`, and where they still do.**  Both of the
    guard's authorising entry points refuse a `SECURITY` statement by name, and both are
    right to: `require_read_only()` would run it on a session hardened against writing, and
    `require_write()` would have to attribute it to an object and an action — but what a
    `GRANT` changes is a principal's rights, not an object's rows, so the set it produced
    would name no object and authorise nothing.  The guard exists to make free-form text
    safe; there is no free-form text on this path.  Every statement here is built by a
    dialect from a fixed template out of *structured* arguments, every value is bound and
    every identifier is quoted by the dialect that owns the quoting rule, so there is nothing
    left for the guard to discover that is not already known by construction.

    What the guard does add is its **lexical pre-flight**, and that is used, on every step,
    before it runs: :meth:`SqlGuard.classify` refuses a statement carrying a second statement
    behind a `;`, a batch separator, a MySQL executable comment or an invisible or
    direction-changing character, and it names the verb.  A step that classifies as anything
    other than `SECURITY` is refused unrun.  That is not defence against the model — the
    model never writes this text — it is defence against *us*: a dialect that one day builds
    a name into a statement instead of quoting it, or emits a `DROP TABLE` inside a security
    `Script`, is caught here rather than on someone's server.  It costs one `sqlparse` pass
    per statement and it is the only reason a bug in the layer below cannot become a dropped
    table.

    **What is brokered, and by whom.**  Whether a tool belongs in the destructive set was
    always the MCP layer's call and not this module's — the annotations and the broker are
    asserted equal there — and the call has now been made.  `DESIGN-MCP-TOOLS.md` §8.1 first
    reasoned that `remove-user-from-group` and `revoke-role` were reversible with their
    opposite tool and left both out; the user ruled the other way, on the ground that
    *reversible* is not the same as *reversible by whoever just lost the access*.  Revoking
    the last administrator's role leaves nobody able to grant it back from inside d-MCP, and
    no amount of `assign-role` afterwards helps if no principal remains that may run it.  So
    both are annotated `destructive_hint=True`, both route through `confirmation.py`, and
    §8.1 now lists ten destructive operations rather than eight.  The other five — the three
    `create-*`, `add-user-to-group` and `assign-role` — are additive, stay unbrokered and
    stay annotated `destructive_hint=False`.

    That ruling reaches this module as one optional argument and nothing else: it still runs
    no modal and knows no broker.  :meth:`revoke_role` and :meth:`remove_user_from_group`
    take an `approve` callable, and :meth:`_run` calls it with the built `Script` once every
    step has passed the tripwire and before any of them runs; raising from it cancels the
    operation with nothing executed.  A hook rather than a second build in the MCP layer, so
    that the statement a human approved is the identical object that then runs, and so that
    the `name@host` rule below keeps exactly one reader.

    Three things stand behind those two wherever no broker is attached, and they are why the
    refusal is safe rather than merely loud: `assign_role` is a `database` action a human
    must tick per connection before a model can reach either direction of it; every result
    sentence says in words that the reverse needs a principal who still holds the right to
    grant; and :meth:`revoke_role` refuses outright to strip the principal this very
    connection is logged in as, which is the one lockout this module can detect by itself —
    checked *before* `approve` is called, so nobody is ever asked to approve something that
    was never going to run.

    **No cache.**  `Introspector` caches its catalogue because a catalogue does not move
    under a running session unless d-MCP moved it.  A principal list does: a DBA adding an
    account in another window is the ordinary case, not the exception, and a stale answer
    here is a false statement about who can reach the data.  These are small queries; they
    are run again.

    One instance per :class:`~sape_d_mcp.db.engine.DatabaseConnection`, held by the caller.
    """

    def __init__(self, db: DatabaseConnection, *, guard: SqlGuard | None = None) -> None:
        self._db = db
        # Shared with the MCP layer where it has one, so the grammar facts behind the
        # tripwire and behind `run-read-query` can never be two different readings of the
        # same engine.  Built here otherwise: `SqlGuard(dialect)` reads `guard_traits()` once
        # and holds no connection, so a second one is cheap and cannot diverge.
        self._guard = guard if guard is not None else SqlGuard(db.dialect)

    def __repr__(self) -> str:
        return f"<SecurityManager {self._db!r}>"

    @property
    def dialect(self) -> Dialect:
        """The connection's dialect, for a caller that needs to quote or normalise itself."""

        return self._db.dialect

    # -- reading -----------------------------------------------------------------------

    def principals(
        self, kind: str | None = None, *, operation: str = "list-principals"
    ) -> tuple[PrincipalInfo, ...]:
        """Every principal the current login can see, optionally of one kind only.

        The typed form, for the GUI's Explorer page; the three `list_*` methods below shape
        the same rows into the `list[dict]` the tools return.

        Members are attached to a role or a group and not to a user: `list_group_members()`
        answers "who is in this", and there is no query in the dialect surface for the
        reverse, so a user's own memberships would be a claim this module cannot make.  A
        `None` kind returns everything, and then the membership queries are run for every
        role and group in the answer.
        """

        wanted = self._require_kind_supported(kind, operation)
        with db_engine.read_only_session(self._db):
            rows = self._rows(self.dialect.list_principals())
            found = [self._principal(row) for row in rows]
            selected = [p for p in found if _matches_kind(p.kind, wanted)]
            return tuple(
                p if p.kind == USER_KIND else self._with_members(p) for p in selected
            )

    def list_roles(self) -> list[dict[str, Any]]:
        """The database roles and who holds them, as `list-roles` returns them.

        This answer and :meth:`list_groups` cover the same principals and differ only in the
        word each uses for them; `_matches_kind()` gives the engine-by-engine evidence for
        why filtering strictly would empty one of the two listings on a real server.  Stated
        rather than hidden, because showing a principal under one tool and not the other
        would let an operator conclude a role has no members when it is simply being called
        a group.
        """

        return [_as_dict(p) for p in self.principals(ROLE_KIND, operation="list-roles")]

    def list_users(self) -> list[dict[str, Any]]:
        """The database users, as `list-users` returns them."""

        return [_as_dict(p) for p in self.principals(USER_KIND, operation="list-users")]

    def list_groups(self) -> list[dict[str, Any]]:
        """The groups and their members, as `list-groups` returns them."""

        return [_as_dict(p) for p in self.principals(GROUP_KIND, operation="list-groups")]

    def group_members(self, group: str) -> list[str]:
        """The members of one group or role, by name.

        Empty means the group exists and holds nobody, which — unlike an empty *principal*
        list on an engine that has principals — is an ordinary and truthful answer.
        """

        self._require_kind_supported(GROUP_KIND, "list-group-members")
        name = self._principal_name(group, what="group")
        with db_engine.read_only_session(self._db):
            return self._members(name)

    def list_grants(self, ref: NormalisedRef | ObjectRef | None = None) -> list[dict[str, Any]]:
        """The privileges the *server* holds, for the whole database or for one object.

        No MCP tool calls this: §11.2 registers no grant tool, and this serves the Explorer
        page, where the server's own privileges are shown beside d-MCP's rules precisely
        because the two systems are independent and seeing where they disagree is most of the
        value of the page (`DESIGN-DIALECTS.md` §3.5).

        One flat dictionary per row — `grantee`, `privilege`, `schema`, `object`, `grantable`,
        `state` — and deliberately not a reference-shaped record, for two reasons that point
        the same way.  A record built around this codebase's `ObjectRef` would carry the
        object as a schema-and-name pair typed by the permission model's five-member enum,
        and a server privilege can be held on a sequence, a schema or the database itself;
        dropping the object name to make such a row fit would render a real grant as an
        unattributed one, in the panel whose whole job is to show access the rule table
        cannot see.  So `schema` and `object` stay plain strings that repeat what the server
        said, whatever kind of thing it named.  And `state` has to be a field in its own
        right: it is how SQL Server distinguishes a `DENY` from a `GRANT`, and a shape with
        nowhere to put it renders a denial as a grant — a distinction that cannot be dropped
        in either direction without misstating who can reach what.
        """

        self._require_any_principals("list-grants")
        target = self._coerce_ref(ref) if ref is not None else None
        with db_engine.read_only_session(self._db):
            rows = self._rows(self.dialect.list_grants(target))
        grants = [self._grant(row) for row in rows]
        logger.debug("Read %d grant(s) from %r", len(grants), self._db)
        return grants

    # -- writing -----------------------------------------------------------------------

    def create_role(self, role: str) -> str:
        """Create a role that holds nothing, and say so."""

        self._require_capability("supports_roles", ROLE_KIND, "create-role")
        name = self._principal_name(role, what="role")
        self._run(self.dialect.create_role(name), operation="create-role")
        return (
            f"Created role {name!r}; it holds no privileges and no members until a human "
            "grants them"
        )

    def create_user(
        self,
        username: str,
        *,
        default_schema: str | None = None,
        login: str | None = None,
        host: str | None = None,
    ) -> str:
        """Create a user that cannot log in, and say that a human must credential it.

        **No password, anywhere.**  `DESIGN-MCP-TOOLS.md` §11.2 rules that no credential is
        accepted from a model, generated by a tool, returned in a result or written to a log,
        and this method has no parameter one could arrive through.  What is created is a
        principal with no usable authentication — a `WITHOUT LOGIN` database user on SQL
        Server, a `NOLOGIN` role on PostgreSQL, an `ACCOUNT LOCK` user on MySQL — and the
        sentence returned says so in words, so the model reports the follow-up rather than
        inventing a password to fill the gap it can feel.

        `default_schema` and `login` are passed straight through to the dialect, which is the
        only layer that knows whether either means anything on its engine: PostgreSQL has no
        login object separate from the role and refuses `login` outright, while
        `default_schema` becomes an `ALTER ROLE ... SET search_path` there and a
        `WITH DEFAULT_SCHEMA` clause on SQL Server.  Neither is quietly dropped anywhere —
        an argument accepted and ignored would have the model report a default schema that
        was never set, which is a false statement about the server produced by d-MCP rather
        than by the model.

        On MySQL identity is the pair `'name'@'host'` and the dialect documents that it has
        no default for the host.  §11.2's tool has no `host` argument, so the username may be
        written `reporting@10.0.0.5`; a bare name is refused rather than widened to `'%'`,
        which would create a user reachable from every host on the network.
        """

        self._require_capability("supports_users", USER_KIND, "create-user")
        name, resolved_host = self._split_host(username, host)
        self._run(
            self.dialect.create_user(
                name,
                host=resolved_host,
                login=None if login is None else self._principal_name(login, what="login"),
                default_schema=(
                    None
                    if default_schema is None
                    else self._plain_name(default_schema, what="schema")
                ),
            ),
            operation="create-user",
        )
        who = name if resolved_host is None else f"{name}@{resolved_host}"
        extras = ""
        if login is not None:
            extras += f", mapped to login {login!r}"
        if default_schema is not None:
            extras += f", with {default_schema!r} as its default schema"
        return (
            f"Created user {who!r} with no login{extras}; a d-MCP operator must set its "
            "credential before it can connect"
        )

    def create_group(self, group: str) -> str:
        """Create a group, naming what the engine actually stores for it."""

        self._require_capability("supports_groups", GROUP_KIND, "create-group")
        name = self._principal_name(group, what="group")
        self._run(self.dialect.create_group(name), operation="create-group")
        mapping = _GROUP_MAPPING.get(str(self.dialect.engine), "the engine's own group object")
        return (
            f"Created group {name!r} ({mapping}); it has no members and no privileges yet"
        )

    def add_user_to_group(self, username: str, group: str, *, host: str | None = None) -> str:
        """Put a principal in a group.

        `host` is the host half of the member's MySQL account name, as the dialect's own
        signature defines it; where the tool has no such argument the username may carry it
        as `name@host`, and a bare name on MySQL is refused rather than widened.
        """

        self._require_capability("supports_groups", GROUP_KIND, "add-user-to-group")
        member, member_host = self._split_host(username, host)
        name = self._principal_name(group, what="group")
        self._run(
            self.dialect.add_group_member(name, member, host=member_host),
            operation="add-user-to-group",
        )
        return (
            f"Added {_who(member, member_host)!r} to group {name!r}; sessions already open "
            "may not see the change until they reconnect"
        )

    def remove_user_from_group(
        self,
        username: str,
        group: str,
        *,
        host: str | None = None,
        approve: Callable[[Script], None] | None = None,
    ) -> str:
        """Take a principal out of a group, refusing to strip this connection's own login.

        `approve`, where the caller passes one, is called with the built script before any of
        it runs; this is one of the two tools the user ruled destructive, and the class
        docstring says why.  Raising from it leaves the membership exactly as it was.
        """

        self._require_capability("supports_groups", GROUP_KIND, "remove-user-from-group")
        member, member_host = self._split_host(username, host)
        name = self._principal_name(group, what="group")
        self._refuse_self_lockout(_who(member, member_host), "remove-user-from-group")
        self._run(
            self.dialect.remove_group_member(name, member, host=member_host),
            operation="remove-user-from-group",
            approve=approve,
        )
        return (
            f"Removed {_who(member, member_host)!r} from group {name!r}; sessions already "
            "open may keep the access until they reconnect, and add-user-to-group puts it "
            "back"
        )

    def assign_role(self, role: str, grantee: str, *, host: str | None = None) -> str:
        """Grant a role to a user, a group or another role.

        `host` belongs to the **grantee**, which is the principal MySQL identifies as a
        `'name'@'host'` pair; a role there is an account with no host of its own that d-MCP
        needs to name.
        """

        self._require_capability("supports_roles", ROLE_KIND, "assign-role")
        name = self._principal_name(role, what="role")
        principal, principal_host = self._split_host(grantee, host, what="grantee")
        self._run(
            self.dialect.assign_role(name, principal, host=principal_host),
            operation="assign-role",
        )
        return (
            f"Granted role {name!r} to {_who(principal, principal_host)!r}; sessions already "
            "open may not see the change until they reconnect"
        )

    def revoke_role(
        self,
        role: str,
        grantee: str,
        *,
        host: str | None = None,
        approve: Callable[[Script], None] | None = None,
    ) -> str:
        """Take a role away from a principal, refusing to strip this connection's own login.

        `approve`, where the caller passes one, is called with the built script before any of
        it runs: this is a destructive tool, and a human is shown the principal and the role
        before either changes.  Raising from it leaves the grant exactly as it was.

        The sentence still carries the reversibility caveat into the model's own report, and
        the modal is not a substitute for it: the human approving the revoke and the model
        reporting it afterwards are not the same reader, and `assign-role` undoes this only
        while some principal that may run `assign-role` still exists.
        """

        self._require_capability("supports_roles", ROLE_KIND, "revoke-role")
        name = self._principal_name(role, what="role")
        principal, principal_host = self._split_host(grantee, host, what="grantee")
        who = _who(principal, principal_host)
        self._refuse_self_lockout(who, "revoke-role")
        self._run(
            self.dialect.revoke_role(name, principal, host=principal_host),
            operation="revoke-role",
            approve=approve,
        )
        return (
            f"Revoked role {name!r} from {who!r}; sessions already open may keep the access "
            f"until they reconnect. assign-role puts it back only while some principal other "
            f"than {who!r} may still grant it — check that one does"
        )

    # -- refusals ----------------------------------------------------------------------

    def _require_capability(self, flag: str, kind: str, operation: str) -> None:
        """Refuse an operation the engine has no concept for, in the engine's own terms.

        `NotImplementedError`, matching `DESIGN-MCP-TOOLS.md` §11.2 and the wording the MCP
        layer already uses, rather than the dialect layer's `CapabilityError`.  The two say
        the same thing at different altitudes: the dialect would raise `CapabilityError` if
        this reached it, and it deliberately does not reach it, because the message an
        operator needs names the tool they called and the connection they called it on.

        Read off `capabilities`, never off the engine name.  SQLite is the engine with no
        principals at all, but MySQL below 8.0 and MariaDB below 10.0.5 have no roles either,
        and an unprobed connection reads `False` for every version-dependent flag — which is
        the correct direction to fail in, and the reason this is a capability test rather
        than an engine test.
        """

        capabilities = self.dialect.capabilities
        if getattr(capabilities, flag):
            return
        if not (
            capabilities.supports_roles
            or capabilities.supports_users
            or capabilities.supports_groups
        ):
            # The clause about the empty list is the design's own reasoning and belongs
            # only where an empty list was the alternative: a refused `create-role` was
            # never going to answer with one.
            instead = (
                " rather than answering with an empty list, which would read as 'there are "
                "none'"
                if operation.startswith("list")
                else ""
            )
            raise NotImplementedError(
                f"{self.dialect.engine} has no role, user or group concept, so d-MCP "
                f"refuses {operation} on this connection{instead}. Whoever can open the "
                f"file has full rights to it, and d-MCP's own rule table is the only access "
                f"boundary that exists here."
            )
        raise NotImplementedError(
            f"this {self.dialect.display_name} connection has no {kind} concept, so d-MCP "
            f"refuses {operation} on it. A {kind} is a server feature, and d-MCP will not "
            f"simulate one it cannot enforce."
        )

    def _require_any_principals(self, operation: str) -> None:
        """Refuse where the engine has no principal of any kind."""

        capabilities = self.dialect.capabilities
        if (
            capabilities.supports_roles
            or capabilities.supports_users
            or capabilities.supports_groups
        ):
            return
        self._require_capability("supports_users", USER_KIND, operation)

    def _require_kind_supported(self, kind: str | None, operation: str) -> str | None:
        """Validate a `kind` filter and refuse it where the engine has no such principal."""

        if kind is None:
            self._require_any_principals(operation)
            return None
        flags = {
            USER_KIND: "supports_users",
            GROUP_KIND: "supports_groups",
            ROLE_KIND: "supports_roles",
        }
        if kind not in flags:
            raise ValueError(
                f"{kind!r} is not a principal kind; expected one of "
                f"{', '.join(sorted(flags))}"
            )
        self._require_capability(flags[kind], kind, operation)
        return kind

    def _refuse_self_lockout(self, principal: str, operation: str) -> None:
        """Refuse to take access away from the login this connection is running as.

        The narrowest useful stand-in for the confirmation modal these two tools do not
        raise.  It cannot detect "the last administrator" — that would need a privilege graph
        this module has no query for — but it does detect the case that locks the operator
        out of the very connection they are working on, where the failure is immediate,
        total, and unfixable from inside d-MCP.

        Silent where the probe never learned the current user: refusing every revoke because
        we do not know who we are would be an over-refusal that closes a documented tool, and
        the honest statement is that the check is best-effort.  `same_principal()` says why it
        compares the way it does.
        """

        traits = getattr(self._db, "traits", None)
        current = getattr(traits, "current_user", None) if traits is not None else None
        if current is None:
            logger.debug(
                "%s: the current principal is unknown, so the self-lockout check was skipped",
                operation,
            )
            return
        if same_principal(principal, current):
            raise ValueError(
                f"{operation} would take access away from {current!r}, which is the login "
                f"this connection is running as. d-MCP refuses it: the change takes effect "
                f"immediately, nothing here could put it back afterwards, and the connection "
                f"would be unusable. Do it from another session, as another principal."
            )

    # -- execution ---------------------------------------------------------------------

    def _rows(self, query: Query) -> list[tuple[Any, ...]]:
        """Run one security query on a read-only session and return plain tuples.

        The read-only block is `DESIGN-MCP-TOOLS.md` §9.1 step 11 applied here as it is
        applied to every other read in the project: a catalogue query has no business being
        able to write, and the session refusing it is a defence independent of anything this
        module believes about the SQL.  It is re-entrant by depth, so a caller that has
        already opened one — the listing methods below wrap the whole `N+1` batch in a single
        block — hardens once and releases once.

        No timeout argument, here or anywhere above: `engine.connect()` applies the
        connection's own statement budget once per session (§13 decision 2), so every
        statement carries it and the model has no lever over it.
        """

        with db_engine.read_only_session(self._db):
            logger.debug("Security query on %r: %s", self._db, query.sql)
            cursor = self._db.execute(query.sql, query.params)
            try:
                rows = cursor.fetchall()
            finally:
                _close_quietly(cursor)
        return [tuple(row) for row in rows]

    def _run(
        self,
        script: Script,
        operation: str,
        approve: Callable[[Script], None] | None = None,
    ) -> None:
        """Execute a security `Script` step by step, committing once at the end.

        Every step passes the tripwire described in the class docstring before any of them
        runs, so a script whose second statement is not a privilege statement never gets as
        far as its first.

        `approve` is the destructive pair's confirmation hook, called after that tripwire and
        before the first statement — after, so that what a human is shown is text this module
        has already agreed to send, and before, so that declining it costs nothing.  It is
        called once with the whole script rather than once per step: the script is the unit
        that happens, and approving half of a two-step revoke is not a thing anyone can mean.
        Whatever it raises propagates untouched, because the MCP layer distinguishes a human
        saying no from a server saying no and this module must not blur the two.

        Not atomic everywhere, and the failure message says which: MySQL commits implicitly
        on DDL, so a two-step script that fails in the middle has genuinely half happened —
        a role granted but never made default, say, which is a grant that looks present and
        does nothing.  Reporting that as a plain failure would be the one wrong answer.
        """

        self._refuse_read_only_session(operation)
        if not script.steps:
            raise RuntimeError(
                f"{type(self.dialect).__name__} built an empty script for {operation}; "
                "nothing was run"
            )
        if script.warning_key is not None:
            logger.warning(
                "%s on %r carries the warning %s", operation, self._db, script.warning_key
            )
        for step in script.steps:
            self._vet(step, operation)
        if approve is not None:
            approve(script)

        executed = 0
        try:
            for step in script.steps:
                _close_quietly(self._db.execute(step.sql, step.params))
                executed += 1
            self._commit()
        except Exception as failure:
            self._rollback()
            if executed == 0 or script.atomic:
                raise
            remaining = "\n".join(step.sql for step in script.steps[executed:])
            raise RuntimeError(
                f"{failure}. {self.dialect.display_name} cannot undo a privilege statement "
                f"by rolling back, so the first {executed} step(s) of {operation} have "
                f"taken effect and the rest have not. Finish it by hand, or undo it, "
                f"starting from:\n{remaining}"
            ) from None
        logger.info("%s ran %d statement(s) on %r", operation, executed, self._db)

    def _vet(self, step: Query, operation: str) -> None:
        """Refuse a generated statement that is not exactly one privilege statement.

        The guard's lexical pre-flight, used as a tripwire on our own output rather than as
        an authorisation of anyone else's — the class docstring gives the reasoning.  A
        refusal here is a **d-MCP defect**, not a caller error, and the message says so,
        because the only way to reach it is for a dialect to have built something other than
        what it promised.
        """

        try:
            classification = self._guard.classify(step.sql)
        except GuardRefusal as refusal:
            raise RuntimeError(
                f"{type(self.dialect).__name__} built a statement for {operation} that the "
                f"SQL guard will not let through, so nothing was run. This is a d-MCP "
                f"defect: {refusal}"
            ) from None
        if classification is not Classification.SECURITY:
            raise RuntimeError(
                f"{type(self.dialect).__name__} built a {classification} statement for "
                f"{operation}, which only ever builds privilege statements, so nothing was "
                f"run. This is a d-MCP defect; the statement was: {step.sql}"
            )

    def _refuse_read_only_session(self, operation: str) -> None:
        """Refuse to write on a session a read block is currently holding hardened."""

        if self._db.read_only:
            raise RuntimeError(
                f"this session is currently hardened read-only for a read, so d-MCP will "
                f"not run {operation} on it; this is a d-MCP bug rather than anything the "
                f"caller did"
            )

    def _commit(self) -> None:
        """Commit through the DB-API handle, as the MCP layer's write path does.

        `DatabaseConnection` is a thin holder and offers no `commit()`; an uncommitted
        privilege change reported as a success would be the worst outcome available, so a
        failure here is never swallowed.
        """

        self._db.raw.commit()

    def _rollback(self) -> None:
        """Undo whatever the failed statement left open.  Best effort, never raises."""

        try:
            self._db.raw.rollback()
        except Exception:
            logger.debug("Error rolling back after a failed security statement", exc_info=True)

    # -- shaping -----------------------------------------------------------------------

    def _principal(self, row: Sequence[Any]) -> PrincipalInfo:
        """One `list_principals()` row, as `PrincipalInfo`."""

        if len(row) < 5:
            raise _contract_error(self.dialect, "list_principals", 5, len(row))
        name = _text(row[0])
        if name is None:
            # Refused rather than skipped or rendered as "None": a nameless principal is a
            # holder of access that no operator could look up, revoke or even talk about.
            raise DialectError(
                f"{type(self.dialect).__name__}.list_principals() returned a row whose name "
                "column is empty; a principal with no name cannot be listed, and dropping "
                "the row would hide access rather than report it"
            )
        native_kind = _text(row[2]) or ""
        can_login = _as_bool(row[3])
        kind = _text(row[1])
        if kind not in (USER_KIND, GROUP_KIND, ROLE_KIND):
            # Never dropped, and never guessed at silently: a principal the catalogue
            # reports and no list shows is access nobody can see.  `can_login` is the
            # distinction every one of the three engines actually stores, so it is what the
            # fallback reads — and the log line names the dialect, because a kind outside
            # the contract is a dialect defect to be fixed rather than tolerated.
            logger.warning(
                "%s reported principal %r with kind %r, which is outside the contract "
                "(user, group, role); classifying it by can_login=%s",
                type(self.dialect).__name__,
                name,
                kind,
                can_login,
            )
            kind = USER_KIND if can_login else GROUP_KIND
        return PrincipalInfo(
            name=name,
            kind=kind,
            native_kind=native_kind,
            can_login=can_login,
            is_superuser=_as_bool(row[4]),
        )

    def _grant(self, row: Sequence[Any]) -> dict[str, Any]:
        """One `list_grants()` row, as the Explorer page shows it."""

        if len(row) < 6:
            raise _contract_error(self.dialect, "list_grants", 6, len(row))
        return {
            "grantee": _text(row[0]) or "",
            "privilege": _text(row[1]) or "",
            "schema": _text(row[2]),
            "object": _text(row[3]),
            "grantable": _as_bool(row[4]),
            # Not defaulted: SQL Server's `DENY` is the reason this column exists, and a
            # missing state rendered as a grant would over-report access. `None` means the
            # dialect did not say, which the Explorer page shows as unknown.
            "state": _text(row[5]),
        }

    def _with_members(self, principal: PrincipalInfo) -> PrincipalInfo:
        """The same principal with its membership filled in.

        One query per role or group.  A join emitting one row per `(group, member)` pair
        would be a single round trip, but it would also be a fifth row shape for the dialects
        to agree on and a second query for them to write, and the count of roles on a
        database is tens rather than thousands.  The whole batch runs inside one read-only
        block, so it is one hardening, not one per group.
        """

        return PrincipalInfo(
            name=principal.name,
            kind=principal.kind,
            native_kind=principal.native_kind,
            can_login=principal.can_login,
            is_superuser=principal.is_superuser,
            members=tuple(self._members(principal.name)),
        )

    def _members(self, group: str) -> list[str]:
        """The first column of `list_group_members()`, as names."""

        names = []
        for row in self._rows(self.dialect.list_group_members(group)):
            if not row:
                continue
            member = _text(row[0])
            if member is not None:
                names.append(member)
        return names

    # -- argument handling -------------------------------------------------------------

    def _plain_name(self, raw: str, what: str) -> str:
        """The checks every name argument gets, whatever it names.

        Whitespace is refused rather than trimmed: `'alice '` and `'alice'` are two different
        principals on a server that accepts both, so trimming would silently address the
        other one — and on a revoke, addressing the other one means the access stays.  MySQL
        refuses a trailing space outright, which is the same judgement one layer down.
        """

        if not isinstance(raw, str) or raw.strip() == "":
            raise ValueError(f"a {what} name must be a non-empty string")
        if raw != raw.strip():
            raise ValueError(
                f"the {what} name {raw!r} begins or ends with whitespace. d-MCP will not "
                f"trim it, because the trimmed name is a different principal; pass the name "
                f"exactly as it is spelled on the server."
            )
        return raw

    def _principal_name(self, raw: str, what: str) -> str:
        """Validate a principal name and hand back the spelling that was given.

        Given back **unfolded**: the dialect quotes it, and a quoted identifier is stored as
        written, so folding `Alice` to `alice` here would create a principal under a name
        nobody asked for — and on PostgreSQL `"Alice"` and `alice` are two different roles.

        Validation is the dialect's own `quote_principal()`, which exists precisely because
        this name never was and never could be matched against a catalogue: its refusals — an
        embedded NUL, an over-length name, MySQL's trailing space — are load bearing rather
        than belt and braces.  It is called for those refusals and its result discarded, so
        the refusal happens before a statement is built rather than inside one.

        There is no interpolation on this path at any point.  What this returns is passed to
        the dialect as a structured argument and quoted there, by the layer that owns the
        quoting rule.
        """

        name = self._plain_name(raw, what)
        self.dialect.quote_principal(name)
        return name

    def _host_part(self, raw: str) -> str:
        """Validate the host half of a MySQL account name.

        `quote_principal()` cannot be used: it refuses a host on every engine but MySQL and,
        on MySQL, expects the pair rather than the half.  `quote_identifier()` applies the
        same NUL, length and trailing-space refusals to the half on its own.
        """

        host = self._plain_name(raw, "host")
        self.dialect.quote_identifier(host)
        return host

    def _split_host(
        self, username: str, host: str | None, what: str = "user"
    ) -> tuple[str, str | None]:
        """Separate `name@host` where the engine's identity is the pair.

        Only where it is: on the other three engines an `@` is an ordinary character in a
        principal name and splitting on it would address a principal that does not exist —
        and the dialect refuses a host outright there, so passing one on would fail the call
        rather than widen it.  More than one `@` is refused rather than split at a guess, and
        a missing host on MySQL is refused rather than widened to `'%'`.
        """

        if str(self.dialect.engine) not in _HOST_IS_IDENTITY:
            if host is not None:
                raise ValueError(
                    f"{self.dialect.display_name} principals have no host part: 'host' is "
                    "one half of a MySQL account name and means nothing here"
                )
            return self._principal_name(username, what=what), None
        if host is not None:
            return self._principal_name(username, what=what), self._host_part(host)
        if username.count("@") != 1:
            raise ValueError(
                "MySQL identifies an account as 'name'@'host', so write the name as "
                "name@host — reporting@10.0.0.5, or reporting@localhost. d-MCP will not "
                "default the host to '%', because that creates an account reachable from "
                "every host on the network, and it will not guess where a name holding more "
                "than one '@' should be split."
            )
        name, _, where = username.partition("@")
        return self._principal_name(name, what=what), self._host_part(where)

    def _coerce_ref(self, ref: NormalisedRef | ObjectRef) -> NormalisedRef:
        """Accept either reference type, normalising an `ObjectRef` on the way through."""

        if isinstance(ref, NormalisedRef):
            return ref
        if isinstance(ref, ObjectRef):
            return self.dialect.normalise_ref(ref)
        raise TypeError(f"expected a NormalisedRef or an ObjectRef, not {type(ref).__name__}")


def _who(name: str, host: str | None) -> str:
    """A principal as the result sentence names it: `alice`, or `alice@10.0.0.5` on MySQL.

    The host is not decoration there: `'alice'@'localhost'` and `'alice'@'%'` are two
    accounts, and a sentence naming only `alice` would report a change to whichever of them
    the reader assumed.
    """

    return name if host is None else f"{name}@{host}"


def _as_dict(principal: PrincipalInfo) -> dict[str, Any]:
    """One principal as the `list_*` tools return it.

    `members` is present for a role or a group and absent for a user, because there is no
    reverse-membership query in the dialect surface and an empty list beside a user would
    read as "belongs to nothing" rather than "not asked".
    """

    shaped: dict[str, Any] = {
        "name": principal.name,
        "kind": principal.kind,
        "native_kind": principal.native_kind,
        "can_login": principal.can_login,
        "is_superuser": principal.is_superuser,
    }
    if principal.kind != USER_KIND:
        shaped["members"] = list(principal.members)
    return shaped


def _contract_error(dialect: Dialect, method: str, expected: int, found: int) -> Exception:
    """The row-shape contract, quoted back at the dialect that broke it."""

    return DialectError(
        f"{type(dialect).__name__}.{method}() returned a row of {found} usable column(s); "
        f"the contract at the top of security.py is {expected}, in the order that module "
        f"documents"
    )
