"""The ``organization`` plugin (work package P5): organizations, members, roles,
invitations and app-defined permissions, plus ``has_permission`` (CONTRACTS 12.3)."""

from __future__ import annotations

import inspect
from collections.abc import Awaitable, Callable
from types import MappingProxyType
from typing import Any
from urllib.parse import urlencode

from gotauth.contracts.adapter import Where
from gotauth.contracts.config import DatabaseHooks, ModelHooks
from gotauth.contracts.core_schema import User
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError, UniqueViolation
from gotauth.contracts.http import SetCookie
from gotauth.contracts.http_models import (
    HasPermissionIn,
    HasPermissionOut,
    StatusOut,
)
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.schema import Field, ModelSchema, Reference, returned_only
from gotauth.contracts.sessions import cookie_name, secure_cookies

from ._access import AccessControl, access_control
from ._models import (
    AcceptInvitationIn,
    CreateOrganizationIn,
    FullOrganizationOut,
    InvitationIdIn,
    InvitationListOut,
    InvitationOut,
    InviteMemberIn,
    MemberOut,
    OrganizationIdIn,
    OrganizationListOut,
    OrganizationOut,
    OrganizationWithRoleOut,
    RemoveMemberIn,
    SetActiveIn,
    SetActiveOut,
    UpdateMemberRoleIn,
    UpdateOrganizationIn,
)

__all__ = ["organization"]

ORGANIZATION_MODEL = ModelSchema(
    name="organization",
    fields=MappingProxyType(
        {
            "name": Field("string"),
            "slug": Field("string", unique=True),
            "logo": Field("string", required=False),
            "metadata": Field("json", default=dict),
            "created_at": Field("datetime"),
        }
    ),
)
MEMBER_MODEL = ModelSchema(
    name="member",
    fields=MappingProxyType(
        {
            "organization_id": Field(
                "string",
                index=True,
                references=Reference("organization", on_delete="cascade"),
            ),
            "user_id": Field(
                "string", index=True, references=Reference("user", on_delete="cascade")
            ),
            "role": Field("string"),
            "created_at": Field("datetime"),
        }
    ),
    unique_together=(("organization_id", "user_id"),),
)
INVITATION_MODEL = ModelSchema(
    name="invitation",
    fields=MappingProxyType(
        {
            "organization_id": Field(
                "string",
                index=True,
                references=Reference("organization", on_delete="cascade"),
            ),
            "email": Field("string", index=True),
            "role": Field("string"),
            "status": Field("string"),  # pending | accepted | rejected | canceled
            "inviter_id": Field(
                "string",
                required=False,
                references=Reference("user", on_delete="set_null"),
            ),
            "token_hash": Field("string", unique=True, returned=False),
            "expires_at": Field("datetime"),
            "created_at": Field("datetime"),
        }
    ),
)
SESSION_FIELDS = ModelSchema(
    name="session",
    fields=MappingProxyType(
        {
            "active_organization_id": Field(
                "string",
                required=False,
                input=False,
                references=Reference("organization", on_delete="set_null"),
            )
        }
    ),
)

ERROR_CODES: dict[str, tuple[int, str]] = {
    "ORG_NOT_A_MEMBER": (403, "Not a member of this organization"),
    "ORG_FORBIDDEN": (403, "Your role does not allow this"),
    "ORG_LAST_OWNER": (409, "An organization needs at least one owner"),
    "ORG_SLUG_TAKEN": (409, "This slug is taken"),
    "ORG_INVITATION_INVALID": (400, "The invitation is not valid"),
    "ORG_MEMBERSHIP_LIMIT": (409, "The organization has reached its member limit"),
}

AllowCreate = bool | Callable[[User], bool | Awaitable[bool]]
INVITATION_PREFIX = "gav_"


def _error(code: str) -> AuthError:
    status, message = ERROR_CODES[code]
    return AuthError(code, status, message)


def _session_user(ctx: EndpointContext) -> str:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal.user_id


def _org_out(ctx: EndpointContext, row: dict[str, Any]) -> OrganizationOut:  # Any: row
    data = returned_only(ctx.auth.schema["organization"], row)
    data.setdefault("metadata", {})
    return OrganizationOut.model_validate(data)


def _invitation_out(
    ctx: EndpointContext, row: dict[str, Any]
) -> InvitationOut:  # Any: row
    return InvitationOut.model_validate(
        returned_only(ctx.auth.schema["invitation"], row)
    )


def _event_data(org_id: str, **extra: Any) -> dict[str, Any]:  # Any: event data
    return {"organization_id": org_id, **extra}


def organization(
    *,
    access: AccessControl | None = None,
    allow_create: AllowCreate = True,
    invitation_expires_in: Duration = "48h",
    invitation_url: str | None = None,
    membership_limit: int | None = None,
) -> Plugin:
    """Return the ``organization`` plugin.

    Args:
        access: Statements and roles from :func:`access_control`; default: the built-in
            statements and the ``owner``, ``admin`` and ``member`` roles.
        allow_create: Whether a user may create organizations: a bool or
            ``fn(user) -> bool`` (may be async).
        invitation_expires_in: How long an invitation works.
        invitation_url: The app page that accepts invitations; it gets
            ``?invitation_id=...&token=...``. Default: ``<base_url>/accept-invitation``.
        membership_limit: Most members per organization (pending invitations count).

    Returns:
        The plugin.
    """
    control = access or access_control()
    expires = to_timedelta(invitation_expires_in)

    # -------------------------------------------------------- helpers

    async def member(
        ctx: EndpointContext, org_id: str | None, user_id: str
    ) -> dict[str, Any]:  # Any: row
        """The caller's membership; an unknown org answers the same as no membership."""
        if not org_id:
            raise _error("ORG_NOT_A_MEMBER")
        row = await ctx.adapter.find_one(
            "member", [Where("organization_id", org_id), Where("user_id", user_id)]
        )
        if row is None:
            raise _error("ORG_NOT_A_MEMBER")
        return row

    def target_org(ctx: EndpointContext, given: str | None) -> str | None:
        if given:
            return given
        principal = ctx.principal
        return principal.organization_id if principal is not None else None

    def require(row: dict[str, Any], permission: str) -> None:  # Any: row
        if permission not in control.permissions(row["role"]):
            raise _error("ORG_FORBIDDEN")

    def check_role(role: str) -> None:
        if role not in control.roles:
            raise AuthError("INVALID_REQUEST", 400, f"Unknown role {role!r}")

    async def lock(ctx: EndpointContext, org_id: str) -> dict[str, Any]:  # Any: row
        """Write the organization row before counting owners: its row lock makes
        concurrent owner changes run one after the other."""
        row = await ctx.adapter.find_one("organization", [Where("id", org_id)])
        if row is None:
            raise _error("ORG_NOT_A_MEMBER")
        # created_at never changes, so this write cannot undo a concurrent rename.
        await ctx.adapter.update(
            "organization", [Where("id", org_id)], {"created_at": row["created_at"]}
        )
        return row

    async def locked_member(
        ctx: EndpointContext, org_id: str | None, user_id: str, permission: str | None
    ) -> dict[str, Any]:  # Any: row
        """Membership checked, then the organization locked, then the membership and
        permission checked again: a concurrent demotion of the caller counts."""
        first = await member(ctx, org_id, user_id)
        if permission is not None:
            require(first, permission)
        await lock(ctx, first["organization_id"])
        mine = await member(ctx, first["organization_id"], user_id)
        if permission is not None:
            require(mine, permission)
        return mine

    def may_assign(mine: dict[str, Any], role: str) -> bool:  # Any: row
        """A caller can only give or take away roles within their own rights; only
        owners touch ``owner``."""
        if mine["role"] == "owner":
            return True
        if role == "owner":
            return False
        return control.permissions(role) <= control.permissions(mine["role"])

    async def owners(ctx: EndpointContext, org_id: str) -> int:
        return await ctx.adapter.count(
            "member", [Where("organization_id", org_id), Where("role", "owner")]
        )

    async def forget_sessions(
        ctx: EndpointContext,
        sessions: list[dict[str, Any]],  # Any: rows
    ) -> None:
        """Drop C3's secondary-storage copies of these sessions (key format
        ``session:<token hash>``), now and again after the commit, so no request in
        between puts the old row back for 5 minutes."""
        storage = ctx.auth.secondary_storage
        if storage is None or not sessions:
            return
        keys = [f"session:{row['token_hash']}" for row in sessions]

        async def drop(_: Any) -> None:  # Any: the deferred context
            for key in keys:
                await storage.delete(key)

        await drop(None)
        ctx.defer(drop)

    async def clear_active(ctx: EndpointContext, user_id: str, org_id: str) -> None:
        """A user who leaves an organization stops having it active."""
        where = [Where("user_id", user_id), Where("active_organization_id", org_id)]
        affected = await ctx.adapter.find_many("session", where)
        await ctx.adapter.update_many(
            "session", where, {"active_organization_id": None}
        )
        await forget_sessions(ctx, affected)

    async def seats(ctx: EndpointContext, org_id: str) -> int:
        members = await ctx.adapter.count("member", [Where("organization_id", org_id)])
        pending = await ctx.adapter.count(
            "invitation",
            [
                Where("organization_id", org_id),
                Where("status", "pending"),
                Where("expires_at", ctx.clock.now(), "gt"),
            ],
        )
        return members + pending

    async def may_create(ctx: EndpointContext, user_id: str) -> bool:
        if isinstance(allow_create, bool):
            return allow_create
        row = await ctx.adapter.find_one("user", [Where("id", user_id)])
        if row is None:
            return False
        result = allow_create(
            User.model_validate(returned_only(ctx.auth.schema["user"], row))
        )
        if inspect.isawaitable(result):
            result = await result
        return bool(result)

    # -------------------------------------------------------- organizations

    async def create(
        ctx: EndpointContext, body: CreateOrganizationIn
    ) -> OrganizationOut:
        user_id = _session_user(ctx)
        if not await may_create(ctx, user_id):
            raise _error("ORG_FORBIDDEN")
        if await ctx.adapter.find_one("organization", [Where("slug", body.slug)]):
            raise _error("ORG_SLUG_TAKEN")
        now = ctx.clock.now()
        try:
            row = await ctx.adapter.create(
                "organization",
                {
                    "id": ctx.ids.new("org"),
                    "name": body.name,
                    "slug": body.slug,
                    "logo": body.logo,
                    "metadata": body.metadata or {},
                    "created_at": now,
                },
            )
        except UniqueViolation as exc:  # created concurrently
            raise _error("ORG_SLUG_TAKEN") from exc
        await ctx.adapter.create(
            "member",
            {
                "id": ctx.ids.new("mem"),
                "organization_id": row["id"],
                "user_id": user_id,
                "role": "owner",
                "created_at": now,
            },
        )
        await ctx.emit("org.created", user_id=user_id, **_event_data(row["id"]))
        await ctx.emit(
            "org.member_added",
            user_id=user_id,
            **_event_data(row["id"], member_user_id=user_id, role="owner"),
        )
        return _org_out(ctx, row)

    async def list_orgs(ctx: EndpointContext, _: None) -> OrganizationListOut:
        user_id = _session_user(ctx)
        memberships = await ctx.adapter.find_many("member", [Where("user_id", user_id)])
        roles = {row["organization_id"]: row["role"] for row in memberships}
        rows = (
            await ctx.adapter.find_many(
                "organization", [Where("id", list(roles), "in")]
            )
            if roles
            else []
        )
        rows.sort(key=lambda row: (row["created_at"], row["id"]))
        return OrganizationListOut(
            organizations=[
                OrganizationWithRoleOut(
                    **_org_out(ctx, row).model_dump(), role=roles[row["id"]]
                )
                for row in rows
            ]
        )

    async def get(ctx: EndpointContext, query: OrganizationIdIn) -> FullOrganizationOut:
        user_id = _session_user(ctx)
        mine = await member(ctx, target_org(ctx, query.organization_id), user_id)
        org_id = mine["organization_id"]
        org = await ctx.adapter.find_one("organization", [Where("id", org_id)])
        if org is None:
            raise _error("ORG_NOT_A_MEMBER")
        rows = await ctx.adapter.find_many("member", [Where("organization_id", org_id)])
        users = {
            row["id"]: row
            for row in await ctx.adapter.find_many(
                "user", [Where("id", [m["user_id"] for m in rows], "in")]
            )
        }
        rows.sort(key=lambda row: (row["created_at"], row["id"]))
        members = [
            MemberOut(
                id=row["id"],
                organization_id=org_id,
                user_id=row["user_id"],
                role=row["role"],
                created_at=row["created_at"],
                email=users.get(row["user_id"], {}).get("email"),
                name=users.get(row["user_id"], {}).get("name"),
            )
            for row in rows
        ]
        return FullOrganizationOut(
            organization=_org_out(ctx, org), members=members, role=mine["role"]
        )

    async def update(
        ctx: EndpointContext, body: UpdateOrganizationIn
    ) -> OrganizationOut:
        mine = await member(
            ctx, target_org(ctx, body.organization_id), _session_user(ctx)
        )
        require(mine, "organization:update")
        org_id = mine["organization_id"]
        changes = {
            name: getattr(body, name)
            for name in ("name", "slug", "logo", "metadata")
            if name in body.model_fields_set and getattr(body, name) is not None
        }
        if "slug" in changes:
            taken = await ctx.adapter.find_one(
                "organization",
                [Where("slug", changes["slug"]), Where("id", org_id, "ne")],
            )
            if taken is not None:
                raise _error("ORG_SLUG_TAKEN")
        row = await ctx.adapter.find_one("organization", [Where("id", org_id)])
        if changes:
            try:
                row = await ctx.adapter.update(
                    "organization", [Where("id", org_id)], changes
                )
            except UniqueViolation as exc:
                raise _error("ORG_SLUG_TAKEN") from exc
        if row is None:
            raise _error("ORG_NOT_A_MEMBER")
        return _org_out(ctx, row)

    async def delete(ctx: EndpointContext, body: OrganizationIdIn) -> StatusOut:
        user_id = _session_user(ctx)
        mine = await member(ctx, target_org(ctx, body.organization_id), user_id)
        require(mine, "organization:delete")
        await remove_organization(ctx, mine["organization_id"], user_id)
        return StatusOut(status="ok")

    async def remove_organization(
        ctx: EndpointContext, org_id: str, user_id: str | None
    ) -> None:
        # Org-owned keys and agents have a polymorphic owner: no foreign key ends
        # them, so revoke them through their plugins (CONTRACTS 12.3, 12.5).
        if "api_key" in ctx.auth.plugin_ids:
            await ctx.auth.api.call(
                "revoke_api_keys",
                body={"owner_type": "organization", "owner_id": org_id},
                ctx=ctx,
            )
        if "agent" in ctx.auth.plugin_ids:
            await ctx.auth.api.call(
                "revoke_agents",
                body={"owner_type": "organization", "owner_id": org_id},
                ctx=ctx,
            )
        await ctx.adapter.delete("organization", [Where("id", org_id)])
        await ctx.emit("org.deleted", user_id=user_id, **_event_data(org_id))

    async def before_user_delete(
        ctx: EndpointContext | None,
        row: dict[str, Any],  # Any: row
    ) -> None:
        """An account that is the last owner of an organization: with other members,
        it cannot be deleted (ORG_LAST_OWNER) until ownership moves; alone, its
        organization goes with it."""
        if ctx is None:  # the core always passes one (CCR 011)
            return
        for mine in await ctx.adapter.find_many(
            "member", [Where("user_id", row["id"]), Where("role", "owner")]
        ):
            org_id = mine["organization_id"]
            await lock(ctx, org_id)
            if await owners(ctx, org_id) > 1:
                continue
            others = await ctx.adapter.count(
                "member",
                [Where("organization_id", org_id), Where("user_id", row["id"], "ne")],
            )
            if others:
                raise _error("ORG_LAST_OWNER")
            await remove_organization(ctx, org_id, row["id"])

    async def set_active(ctx: EndpointContext, body: SetActiveIn) -> SetActiveOut:
        user_id = _session_user(ctx)
        principal = ctx.principal
        if principal is None or principal.via != "session":
            raise AuthError("UNAUTHENTICATED", 401)
        if body.organization_id is not None:
            await member(ctx, body.organization_id, user_id)
        session = await ctx.adapter.update(
            "session",
            [Where("id", principal.credential_id)],
            {"active_organization_id": body.organization_id},
        )
        if session is not None:
            # The session caches (secondary storage, session data cookie) hold the
            # old value: drop them so the next request reads the row.
            await forget_sessions(ctx, [session])
            config = ctx.auth.config
            ctx.set_cookie(
                SetCookie(
                    name=cookie_name(
                        "session_data",
                        base_url=config.base_url,
                        prefix=config.advanced.cookie_prefix,
                    ),
                    value="",
                    max_age=0,
                    secure=secure_cookies(config.base_url),
                )
            )
        return SetActiveOut(organization_id=body.organization_id)

    # -------------------------------------------------------- invitations

    async def invite(ctx: EndpointContext, body: InviteMemberIn) -> InvitationOut:
        user_id = _session_user(ctx)
        mine = await member(ctx, target_org(ctx, body.organization_id), user_id)
        require(mine, "invitation:create")
        check_role(body.role)
        org_id = mine["organization_id"]
        if not may_assign(mine, body.role):
            raise _error("ORG_FORBIDDEN")
        org = await ctx.adapter.find_one("organization", [Where("id", org_id)])
        if org is None:
            raise _error("ORG_NOT_A_MEMBER")
        # A newer invitation replaces a pending one for the same email.
        await ctx.adapter.update_many(
            "invitation",
            [
                Where("organization_id", org_id),
                Where("email", body.email),
                Where("status", "pending"),
            ],
            {"status": "canceled"},
        )
        if (
            membership_limit is not None
            and await seats(ctx, org_id) >= membership_limit
        ):
            raise _error("ORG_MEMBERSHIP_LIMIT")
        token = ctx.crypto.random_token(INVITATION_PREFIX)
        now = ctx.clock.now()
        row = await ctx.adapter.create(
            "invitation",
            {
                "id": ctx.ids.new("inv"),
                "organization_id": org_id,
                "email": body.email,
                "role": body.role,
                "status": "pending",
                "inviter_id": user_id,
                "token_hash": ctx.crypto.hash_token(token),
                "expires_at": now + expires,
                "created_at": now,
            },
        )
        inviter = await ctx.adapter.find_one("user", [Where("id", user_id)])
        base = (
            invitation_url
            or f"{ctx.auth.config.base_url.rstrip('/')}/accept-invitation"
        )
        separator = "&" if "?" in base else "?"
        url = base + separator + urlencode({"invitation_id": row["id"], "token": token})
        await ctx.email.send(
            "invitation",
            body.email,
            url=url,
            organization_name=org["name"],
            inviter_name=(inviter or {}).get("name")
            or (inviter or {}).get("email")
            or "",
        )
        await ctx.emit(
            "org.invitation_sent",
            user_id=user_id,
            **_event_data(org_id, invitation_id=row["id"], role=body.role),
        )
        # The same answer whether or not the email has an account (CONTRACTS 9.1).
        return _invitation_out(ctx, row)

    async def pending_invitation(
        ctx: EndpointContext, body: AcceptInvitationIn
    ) -> tuple[dict[str, Any], str]:  # Any: row
        """The invitation, if the token is right, it is pending and unexpired, and it
        is for the session user's email; else one error for every case."""
        user_id = _session_user(ctx)
        row = await ctx.adapter.find_one(
            "invitation", [Where("id", body.invitation_id)]
        )
        user = await ctx.adapter.find_one("user", [Where("id", user_id)])
        valid = (
            row is not None
            and user is not None
            and ctx.crypto.equal(row["token_hash"], ctx.crypto.hash_token(body.token))
            and row["status"] == "pending"
            and ctx.clock.now() < row["expires_at"]
            and str(user["email"]).lower() == str(row["email"]).lower()
        )
        if not valid or row is None:
            raise _error("ORG_INVITATION_INVALID")
        return row, user_id

    async def settle(
        ctx: EndpointContext, row: dict[str, Any], status: str
    ) -> None:  # Any: row
        claimed = await ctx.adapter.update(
            "invitation",
            [Where("id", row["id"]), Where("status", "pending")],
            {"status": status},
        )
        if claimed is None:  # used concurrently
            raise _error("ORG_INVITATION_INVALID")

    async def accept(ctx: EndpointContext, body: AcceptInvitationIn) -> MemberOut:
        row, user_id = await pending_invitation(ctx, body)
        await settle(ctx, row, "accepted")
        org_id = row["organization_id"]
        existing = await ctx.adapter.find_one(
            "member", [Where("organization_id", org_id), Where("user_id", user_id)]
        )
        if existing is None:
            now = ctx.clock.now()
            try:
                existing = await ctx.adapter.create(
                    "member",
                    {
                        "id": ctx.ids.new("mem"),
                        "organization_id": org_id,
                        "user_id": user_id,
                        "role": row["role"],
                        "created_at": now,
                    },
                )
            except UniqueViolation as exc:
                raise _error("ORG_INVITATION_INVALID") from exc
            await ctx.emit(
                "org.member_added",
                user_id=user_id,
                **_event_data(org_id, member_user_id=user_id, role=row["role"]),
            )
        await ctx.emit(
            "org.invitation_accepted",
            user_id=user_id,
            **_event_data(org_id, invitation_id=row["id"], role=row["role"]),
        )
        return MemberOut.model_validate(
            returned_only(ctx.auth.schema["member"], existing)
        )

    async def reject(ctx: EndpointContext, body: AcceptInvitationIn) -> StatusOut:
        row, _user = await pending_invitation(ctx, body)
        await settle(ctx, row, "rejected")
        return StatusOut(status="ok")

    async def cancel(ctx: EndpointContext, body: InvitationIdIn) -> StatusOut:
        user_id = _session_user(ctx)
        row = await ctx.adapter.find_one(
            "invitation", [Where("id", body.invitation_id)]
        )
        if row is None:
            raise _error("ORG_NOT_A_MEMBER")
        mine = await member(ctx, row["organization_id"], user_id)
        require(mine, "invitation:cancel")
        if row["status"] != "pending":
            raise _error("ORG_INVITATION_INVALID")
        await settle(ctx, row, "canceled")
        return StatusOut(status="ok")

    async def list_invitations(
        ctx: EndpointContext, query: OrganizationIdIn
    ) -> InvitationListOut:
        mine = await member(
            ctx, target_org(ctx, query.organization_id), _session_user(ctx)
        )
        require(mine, "invitation:create")
        rows = await ctx.adapter.find_many(
            "invitation",
            [
                Where("organization_id", mine["organization_id"]),
                Where("status", "pending"),
            ],
        )
        rows.sort(key=lambda row: (row["created_at"], row["id"]))
        return InvitationListOut(
            invitations=[_invitation_out(ctx, row) for row in rows]
        )

    # -------------------------------------------------------- members

    async def remove(ctx: EndpointContext, body: RemoveMemberIn) -> StatusOut:
        user_id = _session_user(ctx)
        mine = await locked_member(
            ctx, target_org(ctx, body.organization_id), user_id, "member:delete"
        )
        org_id = mine["organization_id"]
        target = await ctx.adapter.find_one(
            "member", [Where("organization_id", org_id), Where("user_id", body.user_id)]
        )
        if target is None:
            raise AuthError("NOT_FOUND", 404)
        if not may_assign(mine, target["role"]):
            raise _error("ORG_FORBIDDEN")
        if target["role"] == "owner" and await owners(ctx, org_id) <= 1:
            raise _error("ORG_LAST_OWNER")
        await ctx.adapter.delete("member", [Where("id", target["id"])])
        await clear_active(ctx, body.user_id, org_id)
        await ctx.emit(
            "org.member_removed",
            user_id=user_id,
            **_event_data(org_id, member_user_id=body.user_id),
        )
        return StatusOut(status="ok")

    async def update_role(ctx: EndpointContext, body: UpdateMemberRoleIn) -> MemberOut:
        user_id = _session_user(ctx)
        check_role(body.role)
        mine = await locked_member(
            ctx, target_org(ctx, body.organization_id), user_id, "member:update"
        )
        org_id = mine["organization_id"]
        target = await ctx.adapter.find_one(
            "member", [Where("organization_id", org_id), Where("user_id", body.user_id)]
        )
        if target is None:
            raise AuthError("NOT_FOUND", 404)
        # Both the role taken away and the role given must be within the caller's.
        if not (may_assign(mine, target["role"]) and may_assign(mine, body.role)):
            raise _error("ORG_FORBIDDEN")
        if (
            target["role"] == "owner"
            and body.role != "owner"
            and await owners(ctx, org_id) <= 1
        ):
            raise _error("ORG_LAST_OWNER")
        updated = await ctx.adapter.update(
            "member", [Where("id", target["id"])], {"role": body.role}
        )
        await ctx.emit(
            "org.role_changed",
            user_id=user_id,
            **_event_data(
                org_id,
                member_user_id=body.user_id,
                role=body.role,
                previous=target["role"],
            ),
        )
        return MemberOut.model_validate(
            returned_only(ctx.auth.schema["member"], updated or target)
        )

    async def leave(ctx: EndpointContext, body: OrganizationIdIn) -> StatusOut:
        user_id = _session_user(ctx)
        mine = await locked_member(
            ctx, target_org(ctx, body.organization_id), user_id, None
        )
        org_id = mine["organization_id"]
        if mine["role"] == "owner" and await owners(ctx, org_id) <= 1:
            raise _error("ORG_LAST_OWNER")
        await ctx.adapter.delete("member", [Where("id", mine["id"])])
        await clear_active(ctx, user_id, org_id)
        await ctx.emit(
            "org.member_removed",
            user_id=user_id,
            **_event_data(org_id, member_user_id=user_id),
        )
        return StatusOut(status="ok")

    # -------------------------------------------------------- permission check

    async def has_permission(
        ctx: EndpointContext, body: HasPermissionIn
    ) -> HasPermissionOut:
        principal = ctx.principal
        if principal is None:
            return HasPermissionOut(success=False)
        org_id = body.organization_id or principal.organization_id
        required = [
            f"{resource}:{action}"
            for resource, actions in body.permissions.items()
            for action in actions
        ]
        if not org_id or not required:
            return HasPermissionOut(success=False)
        if (
            principal.via != "session"
            and principal.organization_id is not None
            and principal.organization_id != org_id
        ):
            # An organization's key or token counts in that organization only.
            return HasPermissionOut(success=False)
        if principal.user_id is None:
            # An org-owned key or agent: its scopes only, for its own organization.
            ok = (
                principal.organization_id == org_id
                and principal.scopes is not None
                and principal.has_scopes(*required)
            )
            return HasPermissionOut(success=ok)
        row = await ctx.adapter.find_one(
            "member",
            [Where("organization_id", org_id), Where("user_id", principal.user_id)],
        )
        if row is None:
            return HasPermissionOut(success=False)
        # The role grants it, and a key or token acting for the user narrows it.
        ok = control.allows(row["role"], body.permissions) and principal.has_scopes(
            *required
        )
        return HasPermissionOut(success=ok)

    tags = ("organization",)

    def endpoint(
        id: str,
        method: str,
        path: str,
        handler: Any,  # Any: an endpoint handler
        **options: Any,  # Any: Endpoint options
    ) -> Endpoint[Any, Any]:
        options.setdefault("auth", "session")
        return Endpoint(id, method, path, handler, tags=tags, **options)  # type: ignore[arg-type]

    endpoints = (
        endpoint(
            "create_organization",
            "POST",
            "/organization/create",
            create,
            input=CreateOrganizationIn,
            output=OrganizationOut,
            summary="Create an organization (you become its owner)",
        ),
        endpoint(
            "list_organizations",
            "GET",
            "/organization/list",
            list_orgs,
            output=OrganizationListOut,
            summary="Your organizations and your role in each",
        ),
        endpoint(
            "get_organization",
            "GET",
            "/organization/get",
            get,
            input=OrganizationIdIn,
            output=FullOrganizationOut,
            summary="An organization, its members and your role",
        ),
        endpoint(
            "update_organization",
            "POST",
            "/organization/update",
            update,
            input=UpdateOrganizationIn,
            output=OrganizationOut,
            summary="Update an organization",
        ),
        endpoint(
            "delete_organization",
            "POST",
            "/organization/delete",
            delete,
            input=OrganizationIdIn,
            output=StatusOut,
            fresh_session=True,
            summary="Delete an organization and revoke its keys and agents",
        ),
        endpoint(
            "set_active_organization",
            "POST",
            "/organization/set-active",
            set_active,
            input=SetActiveIn,
            output=SetActiveOut,
            summary="Set the organization this session acts in",
        ),
        endpoint(
            "invite_member",
            "POST",
            "/organization/invite-member",
            invite,
            input=InviteMemberIn,
            output=InvitationOut,
            summary="Invite someone by email",
        ),
        endpoint(
            "accept_invitation",
            "POST",
            "/organization/accept-invitation",
            accept,
            input=AcceptInvitationIn,
            output=MemberOut,
            summary="Accept an invitation sent to your email",
        ),
        endpoint(
            "reject_invitation",
            "POST",
            "/organization/reject-invitation",
            reject,
            input=AcceptInvitationIn,
            output=StatusOut,
            summary="Reject an invitation sent to your email",
        ),
        endpoint(
            "cancel_invitation",
            "POST",
            "/organization/cancel-invitation",
            cancel,
            input=InvitationIdIn,
            output=StatusOut,
            summary="Cancel a pending invitation",
        ),
        endpoint(
            "list_invitations",
            "GET",
            "/organization/list-invitations",
            list_invitations,
            input=OrganizationIdIn,
            output=InvitationListOut,
            summary="Pending invitations of an organization",
        ),
        endpoint(
            "remove_member",
            "POST",
            "/organization/remove-member",
            remove,
            input=RemoveMemberIn,
            output=StatusOut,
            summary="Remove a member",
        ),
        endpoint(
            "update_member_role",
            "POST",
            "/organization/update-member-role",
            update_role,
            input=UpdateMemberRoleIn,
            output=MemberOut,
            summary="Change a member's role",
        ),
        endpoint(
            "leave_organization",
            "POST",
            "/organization/leave",
            leave,
            input=OrganizationIdIn,
            output=StatusOut,
            summary="Leave an organization",
        ),
        endpoint(
            "has_permission",
            "POST",
            "/organization/has-permission",
            has_permission,
            input=HasPermissionIn,
            output=HasPermissionOut,
            auth="principal",
            summary="Whether the caller has these organization permissions",
        ),
    )
    return Plugin(
        id="organization",
        schema={
            "organization": ORGANIZATION_MODEL,
            "member": MEMBER_MODEL,
            "invitation": INVITATION_MODEL,
            "session": SESSION_FIELDS,
        },
        endpoints=endpoints,
        error_codes=ERROR_CODES,
        database_hooks=DatabaseHooks(
            hooks={"user": ModelHooks(before_delete=before_user_delete)}
        ),
        requires_email=True,
    )
