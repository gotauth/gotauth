"""A test plugin with stub endpoints, and a GotAuth built around it."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

import pytest
from pydantic import BaseModel

from gotauth.contracts import (
    AuthError,
    AuthEvent,
    AuthResponse,
    Endpoint,
    EndpointContext,
    Plugin,
    RateLimitRule,
    SignInChallenge,
    User,
    Where,
)
from gotauth.testing import fake_clock, fake_sessions, make_auth


class EchoIn(BaseModel):
    name: str
    count: int = 1


class EchoOut(BaseModel):
    name: str
    user_id: str | None = None


class LoginIn(BaseModel):
    email: str
    remember_me: bool = True


class FactorIn(BaseModel):
    factor: str


class TokenIn(BaseModel):
    grant_type: str


async def echo(ctx: EndpointContext, data: EchoIn) -> EchoOut:
    user_id = ctx.principal.user_id if ctx.principal else None
    return EchoOut(name=data.name * data.count, user_id=user_id)


async def whoami(ctx: EndpointContext, data: None) -> dict[str, Any]:
    principal = ctx.principal
    assert principal is not None
    return {"user_id": principal.user_id, "via": principal.via}


async def login(ctx: EndpointContext, data: LoginIn) -> Any:
    row = await ctx.adapter.find_one("user", [Where("email", data.email.lower())])
    if row is None:
        user = await ctx.auth.create_user_record(ctx, {"email": data.email})
    else:
        user = User.model_validate({k: v for k, v in row.items()})
    return await ctx.auth.complete_sign_in(
        ctx, user, method="password", remember_me=data.remember_me
    )


async def finish(ctx: EndpointContext, data: FactorIn) -> Any:
    return await ctx.auth.finish_challenge(ctx, satisfied=data.factor)


async def write_then_fail(ctx: EndpointContext, data: EchoIn) -> None:
    await ctx.auth.create_user_record(ctx, {"email": f"{data.name}@example.com"})
    await ctx.emit("sign_in.failed", reason="test")
    await ctx.emit("user.updated")
    raise AuthError("INVALID_CREDENTIALS", 401)


async def boom(ctx: EndpointContext, data: None) -> None:
    raise RuntimeError("secret detail that must not leak")


async def token(ctx: EndpointContext, data: TokenIn) -> dict[str, str]:
    if data.grant_type != "authorization_code":
        raise AuthError("OAUTH_INVALID_GRANT", 400, "bad grant")
    return {"access_token": "x"}


async def item(ctx: EndpointContext, data: None) -> dict[str, str]:
    return {"id": ctx.path_params["id"]}


async def remove(ctx: EndpointContext, data: EchoIn) -> dict[str, str]:
    return {"removed": data.name}


async def count_users(ctx: EndpointContext, data: None) -> dict[str, int]:
    return {"users": await ctx.adapter.count("user")}


async def create_marker(ctx: EndpointContext, data: EchoIn) -> dict[str, str]:
    user = await ctx.auth.create_user_record(ctx, {"email": f"{data.name}@example.com"})
    return {"id": user.id}


async def caller(ctx: EndpointContext, data: EchoIn) -> dict[str, str]:
    await ctx.auth.create_user_record(ctx, {"email": f"{data.name}@example.com"})
    await ctx.auth.api.call("callee", body={"name": data.name}, ctx=ctx)
    return {"status": "ok"}


async def callee(ctx: EndpointContext, data: EchoIn) -> None:
    if data.name == "fail":
        raise AuthError("FORBIDDEN", 403)


async def wk(ctx: EndpointContext, data: None) -> dict[str, str]:
    return {"issuer": ctx.auth.config.base_url}


def endpoint(
    id: str, method: str, path: str, handler: Callable[..., Any], **kw: Any
) -> Endpoint[Any, Any]:
    return Endpoint[Any, Any](id=id, method=method, path=path, handler=handler, **kw)  # type: ignore[arg-type]


TEST_ENDPOINTS: tuple[Endpoint[Any, Any], ...] = (
    endpoint("echo", "POST", "/echo", echo, input=EchoIn, output=EchoOut),
    endpoint("whoami", "GET", "/whoami", whoami, auth="principal"),
    endpoint("login", "POST", "/login", login, input=LoginIn),
    endpoint("finish", "POST", "/finish", finish, input=FactorIn),
    endpoint("write_then_fail", "POST", "/fail", write_then_fail, input=EchoIn),
    endpoint("boom", "GET", "/boom", boom),
    endpoint(
        "token",
        "POST",
        "/token",
        token,
        input=TokenIn,
        input_format="form",
        error_format="oauth",
    ),
    endpoint("item", "GET", "/items/{id}", item),
    endpoint("remove", "DELETE", "/thing", remove, input=EchoIn, auth="session"),
    endpoint(
        "session_echo", "POST", "/session-echo", echo, input=EchoIn, auth="session"
    ),
    endpoint(
        "fresh_echo",
        "POST",
        "/fresh-echo",
        echo,
        input=EchoIn,
        auth="session",
        fresh_session=True,
    ),
    endpoint(
        "scoped",
        "POST",
        "/scoped",
        echo,
        input=EchoIn,
        auth="principal",
        scopes=("echo:write",),
    ),
    endpoint("count_users", "GET", "/count", count_users, server_only=True),
    endpoint("create_marker", "POST", "/marker", create_marker, input=EchoIn),
    endpoint("caller", "POST", "/caller", caller, input=EchoIn),
    endpoint("callee", "POST", "/callee", callee, input=EchoIn, server_only=True),
    endpoint(
        "limited",
        "POST",
        "/limited",
        echo,
        input=EchoIn,
        rate_limit=RateLimitRule(path="/limited", window="60s", max=3, key="ip_path"),
    ),
)


def sample_plugin(**overrides: Any) -> Plugin:
    values: dict[str, Any] = {
        "id": "test",
        "endpoints": TEST_ENDPOINTS,
        "well_known_endpoints": (
            endpoint("wk", "GET", "/.well-known/test{base_path}", wk),
        ),
        "error_codes": {"OAUTH_INVALID_GRANT": (400, "Invalid grant")},
    }
    values.update(overrides)
    return Plugin(**values)


def two_factor_plugin() -> Plugin:
    async def interceptor(
        ctx: EndpointContext, user: User, method: str
    ) -> SignInChallenge | None:
        return SignInChallenge(type="two_factor", methods=("totp",))

    return Plugin(id="tfa", sign_in_interceptors=(interceptor,))


def build(*plugins: Plugin, **overrides: Any) -> Any:
    advanced = overrides.pop("advanced", {})
    advanced.setdefault("install_core_plugins", False)
    advanced.setdefault("session_service", fake_sessions())
    return make_auth(
        plugins=[sample_plugin(), *plugins], advanced=advanced, **overrides
    )


@pytest.fixture
def clock() -> Any:
    return fake_clock()


@pytest.fixture
def events() -> list[AuthEvent]:
    return []


@pytest.fixture
def auth(clock: Any, events: list[AuthEvent]) -> Any:
    async def record(event: AuthEvent) -> None:
        events.append(event)

    return build(clock=clock, on_event=record)


__all__ = ["AuthResponse", "build", "two_factor_plugin"]
