"""Helpers for the email + password tests."""

from __future__ import annotations

from typing import Any, cast

from gotauth.contracts import (
    CryptoKit,
    EmailPasswordConfig,
    Endpoint,
    PasswordCheck,
    Where,
)
from gotauth.email_password import CREDENTIAL_PROVIDER, email_password_plugin
from gotauth.testing import FakeContext, call_endpoint, make_context

PLUGIN = email_password_plugin()
ENDPOINTS: dict[str, Endpoint[Any, Any]] = {e.id: e for e in PLUGIN.endpoints}
PASSWORD = "correct horse battery"


class SpyCrypto:
    """Wraps a crypto kit and records the stored hashes ``verify_password`` sees."""

    def __init__(self, inner: CryptoKit) -> None:
        self._inner = inner
        self.verified: list[str] = []
        self.hashed = 0
        self.fail_on_verify = False

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def hash_password(self, password: str) -> str:
        self.hashed += 1
        return await self._inner.hash_password(password)

    async def verify_password(self, password: str, stored: str) -> PasswordCheck:
        if self.fail_on_verify:
            raise AssertionError("verify_password must not run")
        self.verified.append(stored)
        return await self._inner.verify_password(password, stored)


def ep_ctx(*, spy: SpyCrypto | None = None, **settings: Any) -> FakeContext:
    """Return a context with the plugin installed and ``email_password`` settings."""
    base = make_context(plugins=(PLUGIN,))
    config = base.auth.config.model_copy(
        update={"email_password": EmailPasswordConfig(**settings)}
    )
    crypto = cast("CryptoKit", spy) if spy is not None else None
    return make_context(plugins=(PLUGIN,), config=config, crypto=crypto)


def spy_crypto() -> SpyCrypto:
    """Return a spy over the default test crypto kit."""
    return SpyCrypto(make_context().crypto)


async def call(
    ctx: FakeContext, endpoint_id: str, body: dict[str, Any] | None = None
) -> Any:
    """Call one of the plugin's endpoints on ``ctx``."""
    return await call_endpoint(ENDPOINTS[endpoint_id], body, ctx=ctx)


async def add_user(
    ctx: FakeContext,
    email: str = "ada@example.com",
    password: str = PASSWORD,
    *,
    verified: bool = True,
    password_hash: str | None = None,
) -> str:
    """Create a user with a credential account and return its id."""
    user = await ctx.auth.create_user_record(ctx, {"email": email})
    if verified:
        await ctx.adapter.update(
            "user", [Where("id", user.id)], {"email_verified": True}
        )
    now = ctx.clock.now()
    await ctx.adapter.create(
        "account",
        {
            "id": ctx.ids.new("acc"),
            "user_id": user.id,
            "provider_id": CREDENTIAL_PROVIDER,
            "account_id": user.id,
            "password_hash": password_hash or await ctx.crypto.hash_password(password),
            "created_at": now,
            "updated_at": now,
        },
    )
    return user.id


async def password_hash(ctx: FakeContext, user_id: str) -> str:
    """Return the stored password hash of a user's credential account."""
    row = await ctx.adapter.find_one(
        "account",
        [Where("user_id", user_id), Where("provider_id", CREDENTIAL_PROVIDER)],
    )
    assert row is not None
    return str(row["password_hash"])


def token_from(url: str) -> str:
    """Return the ``token`` query value of an emailed URL."""
    from urllib.parse import parse_qs, urlsplit

    return parse_qs(urlsplit(url).query)["token"][0]
