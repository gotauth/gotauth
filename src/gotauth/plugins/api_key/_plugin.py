"""The ``api_key`` plugin: scoped, revocable keys resolved into a ``Principal`` (P1)."""

from __future__ import annotations

import math
import re
from collections.abc import Sequence
from datetime import datetime, timedelta
from typing import Any, Literal

from gotauth.contracts.adapter import Where
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http_models import (
    ApiKeyOut,
    HasPermissionOut,
    IssueApiKeyIn,
    IssueApiKeyOut,
    RevokeApiKeysIn,
    RevokedOut,
    StatusOut,
    VerifyApiKeyIn,
    VerifyOut,
)
from gotauth.contracts.oauth import API_KEY_MODEL
from gotauth.contracts.primitives import Duration, to_timedelta
from gotauth.contracts.principal import Principal
from gotauth.contracts.schema import returned_only
from gotauth.contracts.sessions import TOKEN_PREFIXES

from ._models import ApiKeyListOut, CreateApiKeyIn, ListApiKeysIn, UpdateApiKeyIn

__all__ = ["API_KEY_PREFIX", "ApiKeyResolver", "api_key"]

API_KEY_PREFIX = TOKEN_PREFIXES["api_key"]
_KEY_SHAPE = re.compile(r"gak_[A-Za-z0-9_-]{43}")
_LAST_USED_EVERY = timedelta(minutes=1)
OwnerType = Literal["user", "organization", "agent"]

ERROR_CODES: dict[str, tuple[int, str]] = {
    "API_KEY_INVALID": (401, "Invalid API key"),
    "API_KEY_DISABLED": (401, "The API key is disabled"),
    "API_KEY_EXPIRED": (401, "The API key has expired"),
    "API_KEY_RATE_LIMITED": (429, "Too many requests for this API key"),
}


def _error(code: str, *, headers: dict[str, str] | None = None) -> AuthError:
    status, message = ERROR_CODES[code]
    return AuthError(code, status, message, headers=headers)


class _Settings:
    """Plugin options plus the in-process rate-limit windows."""

    def __init__(
        self,
        allowed_scopes: Sequence[str],
        default_expires_in: Duration | None,
        max_expires_in: Duration | None,
        rate_limit: tuple[int, int] | None,
    ) -> None:
        self.allowed_scopes = frozenset(allowed_scopes)
        self.default_expires_in = default_expires_in
        self.max_expires_in = to_timedelta(max_expires_in) if max_expires_in else None
        self.rate_limit = rate_limit
        # (key id, window start) -> count; only used without secondary storage.
        self.windows: dict[tuple[str, int], int] = {}

    def check_scopes(self, scopes: Sequence[str]) -> list[str]:
        unknown = sorted(set(scopes) - self.allowed_scopes)
        if unknown:
            raise AuthError(
                "INVALID_REQUEST", 400, "Scopes not allowed", {"scopes": unknown}
            )
        return sorted(set(scopes))

    def expiry(self, now: datetime, expires_in: Duration | None) -> datetime | None:
        lifetime = to_timedelta(expires_in) if expires_in is not None else None
        if lifetime is None and self.default_expires_in is not None:
            lifetime = to_timedelta(self.default_expires_in)
        if self.max_expires_in is not None:
            if lifetime is None:
                lifetime = self.max_expires_in
            elif lifetime > self.max_expires_in:
                raise AuthError(
                    "INVALID_REQUEST", 400, "expires_in is above the maximum"
                )
        if lifetime is not None and lifetime <= timedelta(0):
            raise AuthError("INVALID_REQUEST", 400, "expires_in must be positive")
        return now + lifetime if lifetime is not None else None


# ---------------------------------------------------------------- helpers


def _out(ctx: EndpointContext, row: dict[str, Any]) -> ApiKeyOut:  # Any: row values
    return ApiKeyOut.model_validate(returned_only(ctx.auth.schema["api_key"], row))


def _event_data(row: dict[str, Any]) -> dict[str, Any]:  # Any: event data
    # Never the key: id, display start and owner only.
    return {
        "id": row["id"],
        "start": row["start"],
        "owner_type": row["owner_type"],
        "owner_id": row["owner_id"],
    }


def _session_user(ctx: EndpointContext) -> str:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline already checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal.user_id


async def _require_org_permission(
    ctx: EndpointContext, organization_id: str, action: str
) -> None:
    """Organization keys need P5's ``has_permission``; without P5 they are refused."""
    if "organization" not in ctx.auth.plugin_ids:
        raise AuthError(
            "FORBIDDEN", 403, "Organization keys need the organization plugin"
        )
    result = await ctx.auth.api.call(
        "has_permission",
        body={"organization_id": organization_id, "permissions": {"api_key": [action]}},
        ctx=ctx,
    )
    allowed = (
        result.success
        if isinstance(result, HasPermissionOut)
        else bool(getattr(result, "success", False))
    )
    if not allowed:
        raise AuthError("FORBIDDEN", 403)


async def _issue(
    ctx: EndpointContext,
    settings: _Settings,
    *,
    owner_type: OwnerType,
    owner_id: str,
    user_id: str | None,
    created_by: str | None,
    name: str,
    scopes: Sequence[str],
    expires_in: Duration | None,
    metadata: dict[str, Any] | None,  # Any: app-defined JSON
    rate_limit_max: int | None = None,
    rate_limit_window: int | None = None,
) -> IssueApiKeyOut:
    now = ctx.clock.now()
    key = ctx.crypto.random_token(API_KEY_PREFIX)
    if rate_limit_max is None and settings.rate_limit is not None:
        rate_limit_max, rate_limit_window = settings.rate_limit
    row = await ctx.adapter.create(
        "api_key",
        {
            "id": ctx.ids.new("key"),
            "name": name,
            "start": key[len(API_KEY_PREFIX) : len(API_KEY_PREFIX) + 6],
            "key_hash": ctx.crypto.hash_token(key),
            "owner_type": owner_type,
            "owner_id": owner_id,
            "user_id": user_id,
            "scopes": settings.check_scopes(scopes),
            "expires_at": settings.expiry(now, expires_in),
            "rate_limit_max": rate_limit_max,
            "rate_limit_window": (rate_limit_window or 60) if rate_limit_max else None,
            "enabled": True,
            "created_by": created_by,
            "created_at": now,
            "metadata": metadata or {},
        },
    )
    await ctx.emit("api_key.created", user_id=user_id, **_event_data(row))
    return IssueApiKeyOut(api_key=_out(ctx, row), key=key)


async def _owned(
    ctx: EndpointContext, key_id: str, action: str
) -> dict[str, Any]:  # Any: row
    """Return a key the session user may manage, else NOT_FOUND (or FORBIDDEN)."""
    user_id = _session_user(ctx)
    row = await ctx.adapter.find_one("api_key", [Where("id", key_id)])
    if row is None:
        raise AuthError("NOT_FOUND", 404)
    if row["owner_type"] == "user" and row["owner_id"] == user_id:
        return row
    if row["owner_type"] == "organization":
        await _require_org_permission(ctx, row["owner_id"], action)
        return row
    raise AuthError("NOT_FOUND", 404)


# ---------------------------------------------------------------- resolution


async def _rate_limit(
    ctx: EndpointContext,
    settings: _Settings,
    row: dict[str, Any],  # Any: row
) -> None:
    limit = row.get("rate_limit_max")
    if not limit:
        return
    window = int(row.get("rate_limit_window") or 60)
    now = ctx.clock.now().timestamp()
    start = int(now // window) * window
    storage = ctx.auth.secondary_storage
    if storage is not None:
        count = await storage.incr(f"api_key_rl:{row['id']}:{start}", window)
    else:
        # In-process only: each worker process counts on its own.
        windows = settings.windows
        for stale in [k for k in windows if k[1] + window <= now]:
            del windows[stale]
        count = windows.get((row["id"], start), 0) + 1
        windows[(row["id"], start)] = count
    if count > limit:
        retry = max(1, math.ceil(start + window - now))
        raise _error("API_KEY_RATE_LIMITED", headers={"retry-after": str(retry)})


async def _touch(ctx: EndpointContext, row: dict[str, Any]) -> None:  # Any: row
    """Record use at most once a minute (compare-and-set, so concurrent requests
    write once)."""
    now = ctx.clock.now()
    last = row.get("last_used_at")
    if last is not None and now - last < _LAST_USED_EVERY:
        return
    guard = (
        Where("last_used_at", True, "is_null")
        if last is None
        else Where("last_used_at", last)
    )
    await ctx.adapter.update(
        "api_key", [Where("id", row["id"]), guard], {"last_used_at": now}
    )


async def resolve_key(
    ctx: EndpointContext, settings: _Settings, credential: str
) -> Principal:
    """Turn a raw ``gak_`` key into its principal, or raise the matching error."""
    if not _KEY_SHAPE.fullmatch(credential):
        raise _error("API_KEY_INVALID")
    key_hash = ctx.crypto.hash_token(credential)
    row = await ctx.adapter.find_one("api_key", [Where("key_hash", key_hash)])
    if row is None or not ctx.crypto.equal(row["key_hash"], key_hash):
        raise _error("API_KEY_INVALID")
    if not row["enabled"]:
        raise _error("API_KEY_DISABLED")
    expires_at = row.get("expires_at")
    if expires_at is not None and ctx.clock.now() >= expires_at:
        raise _error("API_KEY_EXPIRED")
    agent_id: str | None = None
    organization_id: str | None = None
    if row["owner_type"] == "agent":
        if "agent" not in ctx.auth.schema:
            raise _error("API_KEY_INVALID")
        agent = await ctx.adapter.find_one("agent", [Where("id", row["owner_id"])])
        if agent is None or agent.get("disabled_at") is not None:
            raise _error("API_KEY_DISABLED")
        agent_id = agent["id"]
        if agent["owner_type"] == "organization":
            organization_id = agent["owner_id"]
    elif row["owner_type"] == "organization":
        organization_id = row["owner_id"]
    await _rate_limit(ctx, settings, row)
    await _touch(ctx, row)
    return Principal(
        via="api_key",
        credential_id=row["id"],
        user_id=row["user_id"],
        agent_id=agent_id,
        organization_id=organization_id,
        scopes=frozenset(row["scopes"]),
    )


class ApiKeyResolver:
    """Resolves ``gak_`` credentials from ``Authorization: Bearer`` or ``x-api-key``."""

    prefixes: tuple[str, ...] = (API_KEY_PREFIX,)

    def __init__(self, settings: _Settings) -> None:
        self._settings = settings

    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal | None:
        """Return the key's principal; errors carry the specific API_KEY_* code."""
        return await resolve_key(ctx, self._settings, credential)


# ---------------------------------------------------------------- plugin


def api_key(
    *,
    allowed_scopes: Sequence[str] = (),
    default_expires_in: Duration | None = None,
    max_expires_in: Duration | None = None,
    rate_limit: tuple[int, int] | None = None,
) -> Plugin:
    """Return the ``api_key`` plugin.

    Args:
        allowed_scopes: The only scopes keys may carry; empty means keys carry none.
        default_expires_in: Lifetime when a request gives none; ``None`` never expires.
        max_expires_in: Longest lifetime a key may get.
        rate_limit: Default per-key limit ``(max requests, window seconds)``.
    """
    settings = _Settings(allowed_scopes, default_expires_in, max_expires_in, rate_limit)

    async def create(ctx: EndpointContext, body: CreateApiKeyIn) -> IssueApiKeyOut:
        user_id = _session_user(ctx)
        if body.organization_id is not None:
            await _require_org_permission(ctx, body.organization_id, "create")
            owner_type: OwnerType = "organization"
            owner_id, acts_for = body.organization_id, None
        else:
            owner_type, owner_id, acts_for = "user", user_id, user_id
        return await _issue(
            ctx,
            settings,
            owner_type=owner_type,
            owner_id=owner_id,
            user_id=acts_for,
            created_by=user_id,
            name=body.name,
            scopes=body.scopes,
            expires_in=body.expires_in,
            metadata=body.metadata,
            rate_limit_max=body.rate_limit_max,
            rate_limit_window=body.rate_limit_window,
        )

    async def list_keys(ctx: EndpointContext, query: ListApiKeysIn) -> ApiKeyListOut:
        user_id = _session_user(ctx)
        if query.organization_id is not None:
            await _require_org_permission(ctx, query.organization_id, "read")
            where = [
                Where("owner_type", "organization"),
                Where("owner_id", query.organization_id),
            ]
        else:
            where = [Where("owner_type", "user"), Where("owner_id", user_id)]
        rows = await ctx.adapter.find_many("api_key", where)
        rows.sort(key=lambda row: row["created_at"], reverse=True)
        return ApiKeyListOut(api_keys=[_out(ctx, row) for row in rows])

    async def update(ctx: EndpointContext, body: UpdateApiKeyIn) -> ApiKeyOut:
        row = await _owned(ctx, ctx.path_params["id"], "update")
        changes: dict[str, Any] = {}  # Any: field values
        if body.name is not None:
            changes["name"] = body.name
        if body.scopes is not None:
            changes["scopes"] = settings.check_scopes(body.scopes)
        if body.enabled is not None:
            changes["enabled"] = body.enabled
        if "expires_at" in body.model_fields_set:
            changes["expires_at"] = body.expires_at
        if not changes:
            return _out(ctx, row)
        updated = await ctx.adapter.update("api_key", [Where("id", row["id"])], changes)
        if updated is None:
            raise AuthError("NOT_FOUND", 404)
        if row["enabled"] and body.enabled is False:
            await ctx.emit(
                "api_key.revoked", user_id=row["user_id"], **_event_data(row)
            )
        return _out(ctx, updated)

    async def delete(ctx: EndpointContext, _: None) -> StatusOut:
        row = await _owned(ctx, ctx.path_params["id"], "revoke")
        await ctx.adapter.delete("api_key", [Where("id", row["id"])])
        await ctx.emit("api_key.revoked", user_id=row["user_id"], **_event_data(row))
        return StatusOut(status="ok")

    async def verify(ctx: EndpointContext, body: VerifyApiKeyIn) -> VerifyOut:
        try:
            principal = await resolve_key(ctx, settings, body.key)
        except AuthError as error:
            return VerifyOut(valid=False, code=error.code)
        if body.scopes and not principal.has_scopes(*body.scopes):
            return VerifyOut(valid=False, code="INSUFFICIENT_SCOPE")
        return VerifyOut(valid=True, principal=principal)

    async def issue(ctx: EndpointContext, body: IssueApiKeyIn) -> IssueApiKeyOut:
        return await _issue(
            ctx,
            settings,
            owner_type=body.owner_type,
            owner_id=body.owner_id,
            user_id=body.user_id,
            created_by=body.created_by,
            name=body.name,
            scopes=body.scopes,
            expires_in=body.expires_in,
            metadata=body.metadata,
        )

    async def revoke(ctx: EndpointContext, body: RevokeApiKeysIn) -> RevokedOut:
        where = [
            Where("owner_type", body.owner_type),
            Where("owner_id", body.owner_id),
            Where("enabled", True),
        ]
        if body.key_id is not None:
            where.append(Where("id", body.key_id))
        rows = await ctx.adapter.find_many("api_key", where)
        count = await ctx.adapter.update_many("api_key", where, {"enabled": False})
        for row in rows:
            await ctx.emit(
                "api_key.revoked", user_id=row["user_id"], **_event_data(row)
            )
        return RevokedOut(revoked=count)

    tags = ("api-keys",)
    return Plugin(
        id="api_key",
        schema={"api_key": API_KEY_MODEL},
        endpoints=(
            Endpoint(
                "create_api_key",
                "POST",
                "/api-keys",
                create,
                input=CreateApiKeyIn,
                output=IssueApiKeyOut,
                auth="session",
                summary="Create an API key (the key is shown once)",
                tags=tags,
            ),
            Endpoint(
                "list_api_keys",
                "GET",
                "/api-keys",
                list_keys,
                input=ListApiKeysIn,
                output=ApiKeyListOut,
                auth="session",
                summary="List your API keys",
                tags=tags,
            ),
            Endpoint(
                "update_api_key",
                "PATCH",
                "/api-keys/{id}",
                update,
                input=UpdateApiKeyIn,
                output=ApiKeyOut,
                auth="session",
                summary="Update an API key",
                tags=tags,
            ),
            Endpoint(
                "delete_api_key",
                "DELETE",
                "/api-keys/{id}",
                delete,
                output=StatusOut,
                auth="session",
                summary="Delete an API key",
                tags=tags,
            ),
            Endpoint(
                "verify_api_key",
                "POST",
                "/api-keys/verify",
                verify,
                input=VerifyApiKeyIn,
                output=VerifyOut,
                server_only=True,
                tags=tags,
            ),
            Endpoint(
                "issue_api_key",
                "POST",
                "/api-keys/issue",
                issue,
                input=IssueApiKeyIn,
                output=IssueApiKeyOut,
                server_only=True,
                tags=tags,
            ),
            Endpoint(
                "revoke_api_keys",
                "POST",
                "/api-keys/revoke",
                revoke,
                input=RevokeApiKeysIn,
                output=RevokedOut,
                server_only=True,
                tags=tags,
            ),
        ),
        principal_resolvers=(ApiKeyResolver(settings),),
        error_codes=ERROR_CODES,
    )
