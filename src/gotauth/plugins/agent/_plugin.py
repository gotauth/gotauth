"""The ``agent`` plugin (work package O3): agent identities owned by a user or an
organization, with their own API keys and OAuth clients (CONTRACTS 12.2, 12.3)."""

from __future__ import annotations

from typing import Any

from gotauth.contracts.adapter import Where
from gotauth.contracts.config import DatabaseHooks, GotAuthInstance, ModelHooks
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError, ConfigError
from gotauth.contracts.http_models import (
    ApiKeyOut,
    HasPermissionOut,
    IssueApiKeyOut,
    RevokeAgentsIn,
    RevokedOut,
)
from gotauth.contracts.oauth import AGENT_MODEL
from gotauth.contracts.schema import returned_only

from ._models import (
    AgentApiKeyListOut,
    AgentListOut,
    AgentOut,
    CreateAgentApiKeyIn,
    CreateAgentIn,
    LinkOAuthClientIn,
    ListAgentsIn,
    RevokeAgentOut,
    UpdateAgentIn,
)

__all__ = ["agent"]

ERROR_CODES: dict[str, tuple[int, str]] = {
    "AGENT_DISABLED": (403, "The agent is disabled"),
    "AGENT_CLIENT_ALREADY_LINKED": (409, "The client is linked to another agent"),
}


def _error(code: str) -> AuthError:
    status, message = ERROR_CODES[code]
    return AuthError(code, status, message)


def _session_user(ctx: EndpointContext) -> str:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal.user_id


def _out(ctx: EndpointContext, row: dict[str, Any]) -> AgentOut:  # Any: row
    data = returned_only(ctx.auth.schema["agent"], row)
    data.setdefault("metadata", {})
    return AgentOut.model_validate(data)


def _event_data(row: dict[str, Any]) -> dict[str, Any]:  # Any: event data
    # Ids and owner only, never secrets.
    return {
        "agent_id": row["id"],
        "owner_type": row["owner_type"],
        "owner_id": row["owner_id"],
    }


async def _org_permission(
    ctx: EndpointContext, organization_id: str, action: str
) -> None:
    """P5's ``has_permission`` for ``{"agent": [action]}``; without P5, refused."""
    if "organization" not in ctx.auth.plugin_ids:
        raise AuthError(
            "FORBIDDEN", 403, "Organization agents need the organization plugin"
        )
    result = await ctx.auth.api.call(
        "has_permission",
        body={"organization_id": organization_id, "permissions": {"agent": [action]}},
        ctx=ctx,
    )
    allowed = (
        result.success
        if isinstance(result, HasPermissionOut)
        else bool(getattr(result, "success", False))
    )
    if not allowed:
        raise AuthError("FORBIDDEN", 403)


async def _owned(
    ctx: EndpointContext, agent_id: str, action: str
) -> dict[str, Any]:  # Any: row
    """The agent the session user may act on, else NOT_FOUND (FORBIDDEN for an
    organization member without the permission)."""
    user_id = _session_user(ctx)
    row = await ctx.adapter.find_one("agent", [Where("id", agent_id)])
    if row is None:
        raise AuthError("NOT_FOUND", 404)
    if row["owner_type"] == "user" and row["owner_id"] == user_id:
        return row
    if row["owner_type"] == "organization":
        await _org_permission(ctx, row["owner_id"], action)
        return row
    raise AuthError("NOT_FOUND", 404)


async def _revoke(
    ctx: EndpointContext, row: dict[str, Any]
) -> tuple[dict[str, Any], int, int, int]:  # Any: row
    """Disable the agent and revoke everything it holds, in the caller's transaction.
    Idempotent: a second run revokes nothing more."""
    if row.get("disabled_at") is None:
        updated = await ctx.adapter.update(
            "agent", [Where("id", row["id"])], {"disabled_at": ctx.clock.now()}
        )
        row = updated or row
    keys = await ctx.auth.api.call(
        "revoke_api_keys",
        body={"owner_type": "agent", "owner_id": row["id"]},
        ctx=ctx,
    )
    clients = tokens = 0
    if "oauth_provider" in ctx.auth.plugin_ids:
        linked = await ctx.adapter.find_many(
            "oauth_client",
            [Where("agent_id", row["id"]), Where("disabled_at", True, "is_null")],
        )
        for client in linked:
            await ctx.auth.api.call(
                "update_oauth_client",
                body={"client_id": client["client_id"], "disabled": True},
                ctx=ctx,
            )
        clients = len(linked)
        revoked = await ctx.auth.api.call(
            "revoke_oauth_tokens", body={"agent_id": row["id"]}, ctx=ctx
        )
        tokens = revoked.revoked
    await ctx.emit(
        "agent.revoked",
        api_keys=keys.revoked,
        oauth_clients=clients,
        oauth_tokens=tokens,
        **_event_data(row),
    )
    return row, keys.revoked, clients, tokens


async def _revoke_owner(ctx: EndpointContext, owner_type: str, owner_id: str) -> int:
    rows = await ctx.adapter.find_many(
        "agent", [Where("owner_type", owner_type), Where("owner_id", owner_id)]
    )
    for row in rows:
        await _revoke(ctx, row)
    return len(rows)


def agent() -> Plugin:
    """Return the ``agent`` plugin: agent identities with their own API keys and
    OAuth clients. Needs the ``api_key`` plugin; linking OAuth clients needs
    ``oauth_provider``.

    Example::

        auth = GotAuth(..., plugins=[api_key(), oauth_provider(), agent()])
    """

    async def init(auth: GotAuthInstance) -> None:
        if "api_key" not in auth.plugin_ids:
            msg = "agent() needs the api_key plugin"
            raise ConfigError(msg)

    async def create(ctx: EndpointContext, body: CreateAgentIn) -> AgentOut:
        user_id = _session_user(ctx)
        if body.organization_id is not None:
            await _org_permission(ctx, body.organization_id, "create")
            owner_type, owner_id = "organization", body.organization_id
        else:
            owner_type, owner_id = "user", user_id
        row = await ctx.adapter.create(
            "agent",
            {
                "id": ctx.ids.new("agt"),
                "name": body.name,
                "description": body.description,
                "owner_type": owner_type,
                "owner_id": owner_id,
                "created_by": user_id,
                "created_at": ctx.clock.now(),
                "metadata": body.metadata or {},
            },
        )
        await ctx.emit("agent.created", **_event_data(row))
        return _out(ctx, row)

    async def list_agents(ctx: EndpointContext, query: ListAgentsIn) -> AgentListOut:
        user_id = _session_user(ctx)
        if query.organization_id is not None:
            await _org_permission(ctx, query.organization_id, "read")
            owner = ("organization", query.organization_id)
        else:
            owner = ("user", user_id)
        rows = await ctx.adapter.find_many(
            "agent", [Where("owner_type", owner[0]), Where("owner_id", owner[1])]
        )
        rows.sort(key=lambda row: (row["created_at"], row["id"]))
        return AgentListOut(agents=[_out(ctx, row) for row in rows])

    async def get(ctx: EndpointContext, _: None) -> AgentOut:
        return _out(ctx, await _owned(ctx, ctx.path_params["id"], "read"))

    async def update(ctx: EndpointContext, body: UpdateAgentIn) -> AgentOut:
        row = await _owned(ctx, ctx.path_params["id"], "update")
        if body.enabled is False:
            row, *_ = await _revoke(ctx, row)
        changes: dict[str, Any] = {  # Any: field values
            name: getattr(body, name)
            for name in ("name", "description", "metadata")
            if name in body.model_fields_set and getattr(body, name) is not None
        }
        if body.enabled is True and row.get("disabled_at") is not None:
            # Re-enabling needs the right to revoke; revoked keys and tokens stay so.
            if row["owner_type"] == "organization":
                await _org_permission(ctx, row["owner_id"], "revoke")
            changes["disabled_at"] = None
        if changes:
            row = (
                await ctx.adapter.update("agent", [Where("id", row["id"])], changes)
                or row
            )
        return _out(ctx, row)

    async def revoke(ctx: EndpointContext, _: None) -> RevokeAgentOut:
        row = await _owned(ctx, ctx.path_params["id"], "revoke")
        row, keys, clients, tokens = await _revoke(ctx, row)
        return RevokeAgentOut(
            agent=_out(ctx, row),
            api_keys=keys,
            oauth_clients=clients,
            oauth_tokens=tokens,
        )

    async def create_key(
        ctx: EndpointContext, body: CreateAgentApiKeyIn
    ) -> IssueApiKeyOut:
        row = await _owned(ctx, ctx.path_params["id"], "update")
        if row.get("disabled_at") is not None:
            raise _error("AGENT_DISABLED")
        out = await ctx.auth.api.call(
            "issue_api_key",
            body={
                "owner_type": "agent",
                "owner_id": row["id"],
                "user_id": row["owner_id"] if row["owner_type"] == "user" else None,
                "created_by": _session_user(ctx),
                "name": body.name,
                "scopes": body.scopes,
                "expires_in": body.expires_in,
            },
            ctx=ctx,
        )
        return IssueApiKeyOut.model_validate(out.model_dump())

    async def list_keys(ctx: EndpointContext, _: None) -> AgentApiKeyListOut:
        row = await _owned(ctx, ctx.path_params["id"], "read")
        keys = await ctx.adapter.find_many(
            "api_key", [Where("owner_type", "agent"), Where("owner_id", row["id"])]
        )
        keys.sort(key=lambda key: (key["created_at"], key["id"]))
        model = ctx.auth.schema["api_key"]
        return AgentApiKeyListOut(
            api_keys=[
                ApiKeyOut.model_validate(returned_only(model, key)) for key in keys
            ]
        )

    async def link_client(ctx: EndpointContext, body: LinkOAuthClientIn) -> AgentOut:
        if "oauth_provider" not in ctx.auth.plugin_ids:
            raise AuthError("NOT_FOUND", 404)  # as if the route did not exist
        row = await _owned(ctx, ctx.path_params["id"], "update")
        if row.get("disabled_at") is not None:
            raise _error("AGENT_DISABLED")
        client = await ctx.adapter.find_one(
            "oauth_client", [Where("client_id", body.client_id)]
        )
        # The client must belong to the agent's owning user (for an organization's
        # agent, to the member linking it); anything else looks like no client.
        owner = row["owner_id"] if row["owner_type"] == "user" else _session_user(ctx)
        if client is None or client.get("owner_user_id") != owner:
            raise AuthError("NOT_FOUND", 404)
        if client.get("agent_id") not in (None, row["id"]):
            raise _error("AGENT_CLIENT_ALREADY_LINKED")
        if client.get("agent_id") != row["id"]:
            await ctx.auth.api.call(
                "update_oauth_client",
                body={"client_id": client["client_id"], "agent_id": row["id"]},
                ctx=ctx,
            )
        return _out(ctx, row)

    async def revoke_agents(ctx: EndpointContext, body: RevokeAgentsIn) -> RevokedOut:
        return RevokedOut(
            revoked=await _revoke_owner(ctx, body.owner_type, body.owner_id)
        )

    async def before_user_delete(
        ctx: EndpointContext | None,
        row: dict[str, Any],  # Any: row
    ) -> None:
        # The owner's agents: revoke everything they hold, then delete them, in the
        # delete's transaction. The core always passes a context (CCR 011).
        if ctx is None:
            msg = "agent(): a user delete without a context (needs CCR 011)"
            raise ConfigError(msg)
        await _revoke_owner(ctx, "user", row["id"])
        await ctx.adapter.delete(
            "agent", [Where("owner_type", "user"), Where("owner_id", row["id"])]
        )

    tags = ("agents",)
    return Plugin(
        id="agent",
        schema={AGENT_MODEL.name: AGENT_MODEL},
        endpoints=(
            Endpoint(
                "create_agent",
                "POST",
                "/agents",
                create,
                input=CreateAgentIn,
                output=AgentOut,
                auth="session",
                summary="Create an agent",
                tags=tags,
            ),
            Endpoint(
                "list_agents",
                "GET",
                "/agents",
                list_agents,
                input=ListAgentsIn,
                output=AgentListOut,
                auth="session",
                summary="List your agents, or an organization's",
                tags=tags,
            ),
            Endpoint(
                "get_agent",
                "GET",
                "/agents/{id}",
                get,
                output=AgentOut,
                auth="session",
                summary="Get an agent",
                tags=tags,
            ),
            Endpoint(
                "update_agent",
                "PATCH",
                "/agents/{id}",
                update,
                input=UpdateAgentIn,
                output=AgentOut,
                auth="session",
                summary="Rename, describe, disable or re-enable an agent",
                tags=tags,
            ),
            Endpoint(
                "revoke_agent",
                "POST",
                "/agents/{id}/revoke",
                revoke,
                output=RevokeAgentOut,
                auth="session",
                fresh_session=True,
                summary="Disable an agent and revoke its keys, clients and tokens",
                tags=tags,
            ),
            Endpoint(
                "create_agent_api_key",
                "POST",
                "/agents/{id}/api-keys",
                create_key,
                input=CreateAgentApiKeyIn,
                output=IssueApiKeyOut,
                auth="session",
                summary="Create an API key for an agent (shown once)",
                tags=tags,
            ),
            Endpoint(
                "list_agent_api_keys",
                "GET",
                "/agents/{id}/api-keys",
                list_keys,
                output=AgentApiKeyListOut,
                auth="session",
                summary="List an agent's API keys",
                tags=tags,
            ),
            Endpoint(
                "link_oauth_client",
                "POST",
                "/agents/{id}/clients",
                link_client,
                input=LinkOAuthClientIn,
                output=AgentOut,
                auth="session",
                summary="Link one of your OAuth clients to an agent",
                tags=tags,
            ),
            Endpoint(
                "revoke_agents",
                "POST",
                "/agents/revoke-by-owner",
                revoke_agents,
                input=RevokeAgentsIn,
                output=RevokedOut,
                server_only=True,
                tags=tags,
            ),
        ),
        database_hooks=DatabaseHooks(
            hooks={"user": ModelHooks(before_delete=before_user_delete)}
        ),
        error_codes=ERROR_CODES,
        init=init,
    )
