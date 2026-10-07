"""Helpers for the social login tests."""

from __future__ import annotations

from typing import Any, Literal

from gotauth.contracts import AuthResponse, Endpoint, Plugin, ProviderUser, Where
from gotauth.social import social_plugin
from gotauth.testing import FakeContext, call_endpoint, make_context
from gotauth.testing._oauth import StubOAuthProvider

PLUGIN = social_plugin()
ENDPOINTS: dict[str, Endpoint[Any, Any]] = {e.id: e for e in PLUGIN.endpoints}


def person(
    id: str = "p1",
    email: str | None = "ada@example.com",
    *,
    verified: bool = True,
    name: str | None = "Ada",
) -> ProviderUser:
    """Return a provider-side user."""
    return ProviderUser(
        id=id, email=email, email_verified=verified, name=name, image=None, raw={}
    )


def provider(
    id: str = "fake",
    *,
    users: dict[str, ProviderUser] | None = None,
    store_provider_tokens: bool = False,
    callback_method: Literal["GET", "POST"] = "GET",
) -> StubOAuthProvider:
    """Return a fake provider."""
    return StubOAuthProvider(
        id,
        users=users or {},
        store_provider_tokens=store_provider_tokens,
        callback_method=callback_method,
    )


def social_ctx(
    *providers: StubOAuthProvider,
    plugins: tuple[Plugin, ...] = (),
    linking: dict[str, Any] | None = None,
) -> FakeContext:
    """Return a context with the social plugin and these providers."""
    base = make_context(plugins=(PLUGIN, *plugins), providers=providers)
    if linking is None:
        return base
    config = base.auth.config.model_copy(
        update={
            "account_linking": base.auth.config.account_linking.model_copy(
                update=linking
            )
        }
    )
    return make_context(plugins=(PLUGIN, *plugins), providers=providers, config=config)


async def call(
    ctx: FakeContext, endpoint_id: str, body: dict[str, Any] | None = None
) -> Any:
    """Call one of the plugin's endpoints."""
    return await call_endpoint(ENDPOINTS[endpoint_id], body, ctx=ctx)


async def start(
    ctx: FakeContext, endpoint_id: str = "sign_in_social", **body: Any
) -> str:
    """Start a flow and return the provider authorization URL."""
    body.setdefault("provider", "fake")
    out = await call(ctx, endpoint_id, body)
    return str(out.url)


async def callback(
    ctx: FakeContext,
    query: dict[str, str],
    *,
    provider_id: str = "fake",
    cookies: dict[str, str] | None = None,
    keep_jar: bool = True,
) -> tuple[AuthResponse, FakeContext]:
    """Run the GET callback as the browser's next request."""
    if keep_jar:
        next_ctx = ctx.next_request(
            method="GET", path_params={"provider": provider_id}, cookies=cookies
        )
    else:
        next_ctx = ctx.auth.context(request=None, path_params={"provider": provider_id})
    result = await call(next_ctx, "social_callback", query)
    assert isinstance(result, AuthResponse)
    return result, next_ctx


async def sign_in_with(
    ctx: FakeContext, prov: StubOAuthProvider, code: str, **body: Any
) -> tuple[AuthResponse, FakeContext]:
    """Run a whole sign-in: start, approve with ``code``, callback."""
    url = await start(ctx, provider=prov.id, **body)
    return await callback(ctx, prov.approve(url, code), provider_id=prov.id)


async def accounts(ctx: FakeContext, user_id: str) -> list[dict[str, Any]]:
    """Return a user's account rows."""
    return await ctx.adapter.find_many("account", [Where("user_id", user_id)])
