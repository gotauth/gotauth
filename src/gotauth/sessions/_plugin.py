"""The ``sessions`` plugin: session endpoints and the ``gas_`` bearer resolver."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict

from gotauth.contracts.core_schema import Session
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http_models import SessionListOut, SessionWithUserOut, StatusOut
from gotauth.contracts.principal import Principal
from gotauth.contracts.sessions import cookie_name

from ._service import SESSION_PREFIX

__all__ = ["RevokeSessionIn", "SessionResolver", "session_principal", "sessions_plugin"]


class RevokeSessionIn(BaseModel):
    """``revoke_session`` input."""

    model_config = ConfigDict(extra="forbid")

    session_id: str


def session_principal(session: Session) -> Principal:
    """Return the principal for a session, with ``active_organization_id`` if set."""
    extra = session.model_extra or {}
    organization_id = extra.get("active_organization_id")
    return Principal(
        via="session",
        credential_id=session.id,
        user_id=session.user_id,
        organization_id=organization_id if isinstance(organization_id, str) else None,
    )


class SessionResolver:
    """Resolves ``Bearer gas_...`` credentials when ``sessions.allow_bearer`` is on."""

    prefixes: tuple[str, ...] = (SESSION_PREFIX,)

    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal | None:
        """Return the session principal, or ``None`` (UNAUTHENTICATED)."""
        if not ctx.auth.config.sessions.allow_bearer:
            return None
        found = await ctx.sessions.get(ctx, credential)
        return session_principal(found.session) if found is not None else None


def _principal(ctx: EndpointContext) -> Principal:
    principal = ctx.principal
    if principal is None or principal.user_id is None:  # the pipeline already checked
        raise AuthError("UNAUTHENTICATED", 401)
    return principal


def _current_session_id(ctx: EndpointContext) -> str | None:
    principal = ctx.principal
    if principal is None or principal.via != "session":
        return None
    return principal.credential_id


def _request_token(ctx: EndpointContext) -> str | None:
    # The same order as the pipeline (C1): Bearer, then X-Api-Key, then the cookie.
    headers = ctx.request.headers
    authorization = headers.get("authorization", "")
    if authorization[:7].lower() == "bearer ":
        return authorization[7:].strip()
    if headers.get("x-api-key"):
        return headers["x-api-key"].strip()
    config = ctx.auth.config
    name = cookie_name(
        "session_token", base_url=config.base_url, prefix=config.advanced.cookie_prefix
    )
    return ctx.request.cookies.get(name)


async def _get_session(ctx: EndpointContext, _: None) -> SessionWithUserOut | None:
    current = _current_session_id(ctx)
    token = _request_token(ctx)
    if current is None or token is None:
        return None
    # The resolver already slid the session, so this read does not write again.
    found = await ctx.sessions.get(ctx, token)
    if found is None or found.session.id != current:
        return None
    return SessionWithUserOut(session=found.session, user=found.user)


async def _list_sessions(ctx: EndpointContext, _: None) -> SessionListOut:
    principal = _principal(ctx)
    sessions = await ctx.sessions.list_for_user(ctx, principal.user_id or "")
    return SessionListOut(
        sessions=sessions, current_session_id=_current_session_id(ctx)
    )


async def _revoke_session(ctx: EndpointContext, body: RevokeSessionIn) -> StatusOut:
    principal = _principal(ctx)
    owned = {
        s.id for s in await ctx.sessions.list_for_user(ctx, principal.user_id or "")
    }
    if body.session_id not in owned:
        raise AuthError("NOT_FOUND", 404)
    await ctx.sessions.revoke(ctx, body.session_id)
    if body.session_id == _current_session_id(ctx):
        ctx.sessions.clear_cookies(ctx)
    return StatusOut(status="ok")


async def _revoke_other_sessions(ctx: EndpointContext, _: None) -> StatusOut:
    principal = _principal(ctx)
    await ctx.sessions.revoke_all(
        ctx, principal.user_id or "", except_session_id=_current_session_id(ctx)
    )
    return StatusOut(status="ok")


def sessions_plugin() -> Plugin:
    """Return the ``sessions`` plugin (CONTRACTS 13.2). C1 installs it first."""
    return Plugin(
        id="sessions",
        endpoints=(
            Endpoint(
                "get_session",
                "GET",
                "/session",
                _get_session,
                output=SessionWithUserOut,
                auth="optional",
                summary="Get the current session",
                tags=("sessions",),
            ),
            Endpoint(
                "list_sessions",
                "GET",
                "/sessions",
                _list_sessions,
                output=SessionListOut,
                auth="session",
                summary="List your sessions",
                tags=("sessions",),
            ),
            Endpoint(
                "revoke_session",
                "POST",
                "/sessions/revoke",
                _revoke_session,
                input=RevokeSessionIn,
                output=StatusOut,
                auth="session",
                summary="Revoke one of your sessions",
                tags=("sessions",),
            ),
            Endpoint(
                "revoke_other_sessions",
                "POST",
                "/sessions/revoke-others",
                _revoke_other_sessions,
                output=StatusOut,
                auth="session",
                summary="Revoke all your other sessions",
                tags=("sessions",),
            ),
        ),
        principal_resolvers=(SessionResolver(),),
    )
