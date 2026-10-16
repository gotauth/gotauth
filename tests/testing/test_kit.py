"""The testing kit works today, before the core (C1) and sessions (C3) exist."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from pydantic import BaseModel

from gotauth.contracts import (
    AuthError,
    Endpoint,
    EndpointContext,
    Plugin,
    Principal,
    ProviderUser,
    SignInChallenge,
    User,
    Where,
)
from gotauth.crypto import crypto_kit, pkce_s256
from gotauth.testing import (
    TEST_SECRET,
    FakeContext,
    call_endpoint,
    fake_oauth_provider,
    load_vectors,
    make_auth,
    make_context,
    stub_plugin,
    stub_resolver,
)


async def new_user(ctx: FakeContext, email: str = "Ada@Example.com") -> User:
    return await ctx.auth.create_user_record(ctx, {"email": email, "name": "Ada"})


# ------------------------------------------------------------------ users


async def test_create_user_record_lowercases_and_emits(ctx: FakeContext) -> None:
    user = await new_user(ctx)
    assert user.email == "ada@example.com"
    assert user.id.startswith("usr_")
    assert ctx.event_types() == ["user.created"]


async def test_delete_user_cascades_to_sessions_and_accounts(ctx: FakeContext) -> None:
    user = await new_user(ctx)
    now = ctx.clock.now()
    await ctx.adapter.create(
        "account",
        {
            "id": ctx.ids.new("acc"),
            "user_id": user.id,
            "provider_id": "credential",
            "account_id": user.id,
            "created_at": now,
            "updated_at": now,
        },
    )
    await ctx.sign_in(user.id)
    await ctx.auth.delete_user(ctx, user.id)
    for model in ("user", "session", "account"):
        assert await ctx.adapter.count(model) == 0
    assert ctx.event_types()[-1] == "user.deleted"


# ------------------------------------------------------------------ sessions


async def test_fake_sessions_store_only_token_hashes(ctx: FakeContext) -> None:
    user = await new_user(ctx)
    created = await ctx.sign_in(user.id)
    assert created.token.startswith("gas_")
    assert created.token not in json.dumps(await ctx.dump(), default=str)
    found = await ctx.sessions.get(ctx, created.token)
    assert found is not None
    assert found.user.id == user.id


# ------------------------------------------------------------------ challenge


async def test_challenge_round_trip(ctx: FakeContext) -> None:
    async def two_factor(
        ctx: EndpointContext, user: User, method: str
    ) -> SignInChallenge | None:
        return SignInChallenge(type="two_factor", methods=("totp",))

    ctx = make_context(
        plugins=[Plugin(id="tfa_stub", sign_in_interceptors=(two_factor,))],
        clock=ctx.clock,
    )
    user = await new_user(ctx)
    first = await ctx.auth.complete_sign_in(ctx, user, method="password")
    assert first.model_dump()["challenge"]["type"] == "two_factor"
    assert await ctx.adapter.count("session") == 0

    nxt = ctx.next_request()
    state = nxt.auth.read_challenge(nxt)
    assert state is not None
    assert state.user_id == user.id
    with pytest.raises(AuthError) as wrong:
        await nxt.auth.finish_challenge(nxt, satisfied="backup_code")
    assert wrong.value.code == "FORBIDDEN"
    done = await nxt.auth.finish_challenge(nxt, satisfied="totp")
    assert done.user.id == user.id
    assert await nxt.adapter.count("session") == 1
    assert nxt.cookie("challenge") is None


async def test_expired_challenge(ctx: FakeContext) -> None:
    async def always(
        ctx: EndpointContext, user: User, method: str
    ) -> SignInChallenge | None:
        return SignInChallenge(type="two_factor", methods=("totp",))

    ctx = make_context(plugins=[Plugin(id="t", sign_in_interceptors=(always,))])
    user = await new_user(ctx)
    await ctx.auth.complete_sign_in(ctx, user, method="password")
    ctx.clock.advance("11m")
    nxt = ctx.next_request()
    with pytest.raises(AuthError) as caught:
        await nxt.auth.finish_challenge(nxt, satisfied="totp")
    assert caught.value.code == "TOKEN_EXPIRED"


# ------------------------------------------------------------------ endpoints


class EchoIn(BaseModel):
    name: str
    count: int


class EchoOut(BaseModel):
    name: str
    user_id: str | None


async def echo(ctx: EndpointContext, data: EchoIn) -> EchoOut:
    user_id = ctx.principal.user_id if ctx.principal else None
    return EchoOut(name=data.name * data.count, user_id=user_id)


ECHO = Endpoint[EchoIn, EchoOut](
    id="echo", method="POST", path="/echo", handler=echo, input=EchoIn, output=EchoOut
)
ECHO_SESSION = Endpoint[EchoIn, EchoOut](
    id="echo_session",
    method="POST",
    path="/echo-session",
    handler=echo,
    input=EchoIn,
    output=EchoOut,
    auth="principal",
    scopes=("echo:write",),
)


async def test_call_endpoint_validates_without_echoing_values(ctx: FakeContext) -> None:
    out = await call_endpoint(ECHO, {"name": "ab", "count": 2}, ctx=ctx)
    assert out.name == "abab"
    with pytest.raises(AuthError) as caught:
        await call_endpoint(ECHO, {"name": "secret-value", "count": "x"}, ctx=ctx)
    assert caught.value.code == "INVALID_REQUEST"
    assert "secret-value" not in str(caught.value.details)


async def test_call_endpoint_enforces_auth_and_scopes() -> None:
    with pytest.raises(AuthError) as missing:
        await call_endpoint(ECHO_SESSION, {"name": "a", "count": 1}, ctx=make_context())
    assert missing.value.code == "UNAUTHENTICATED"

    narrow = Principal(
        via="api_key", credential_id="key_1", user_id="usr_1", scopes=frozenset()
    )
    keys = Plugin(id="keys", principal_resolvers=(stub_resolver("gak_", narrow),))
    ctx = make_context(plugins=[keys])
    with pytest.raises(AuthError) as scoped:
        await call_endpoint(
            ECHO_SESSION,
            {"name": "a", "count": 1},
            ctx=ctx.next_request(headers={"x-api-key": "gak_anything"}),
        )
    assert scoped.value.code == "INSUFFICIENT_SCOPE"

    wide = Principal(
        via="api_key",
        credential_id="key_2",
        user_id="usr_2",
        scopes=frozenset({"echo:write"}),
    )
    keys = Plugin(id="keys", principal_resolvers=(stub_resolver("gak_", wide),))
    ctx = make_context(plugins=[keys])
    out = await call_endpoint(
        ECHO_SESSION,
        {"name": "a", "count": 1},
        ctx=ctx.next_request(headers={"authorization": "Bearer gak_x"}),
    )
    assert out.user_id == "usr_2"


# ------------------------------------------------------------------ cross-plugin


async def test_stub_plugin_records_the_12_5_shape() -> None:
    async def revoke(**body: Any) -> dict[str, int]:
        return {"revoked": 2}

    keys = stub_plugin("api_key", {"revoke_api_keys": revoke})
    ctx = make_context(plugins=[keys])
    assert "api_key" in ctx.auth.plugin_ids
    out = await ctx.auth.api.call(
        "revoke_api_keys",
        body={"owner_type": "organization", "owner_id": "org_1"},
        ctx=ctx,
    )
    assert out.model_dump() == {"revoked": 2}
    assert keys.calls_to("revoke_api_keys") == [
        {"owner_type": "organization", "owner_id": "org_1"}
    ]
    with pytest.raises(AuthError):
        await ctx.auth.api.call(
            "revoke_api_keys", body={"owner_type": "user", "nope": 1}, ctx=ctx
        )


# ------------------------------------------------------------------ providers


async def test_fake_oauth_provider_checks_pkce() -> None:
    user = ProviderUser(
        id="42", email="a@b.c", email_verified=True, name=None, image=None, raw={}
    )
    provider = fake_oauth_provider(users={"code-1": user})
    verifier = "v" * 43
    provider.authorization_url(
        state="s1",
        code_challenge=pkce_s256(verifier),
        redirect_uri="http://localhost:8000/cb",
        scopes=["openid"],
        nonce=None,
    )
    async with httpx.AsyncClient() as http:
        with pytest.raises(AuthError):
            await provider.exchange_code(
                http,
                code="code-1",
                code_verifier="w" * 43,
                redirect_uri="http://localhost:8000/cb",
            )
        tokens = await provider.exchange_code(
            http,
            code="code-1",
            code_verifier=verifier,
            redirect_uri="http://localhost:8000/cb",
        )
        found = await provider.get_user(http, tokens, nonce=None)
    assert found.id == "42"


# ------------------------------------------------------------------ misc


def test_load_vectors() -> None:
    cases = load_vectors("totp")
    assert cases
    assert all(isinstance(case, dict) for case in cases)


def test_load_vectors_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        load_vectors("no-such-vectors")


def test_make_auth_needs_c1() -> None:
    try:
        import gotauth.core as core

        has_core = hasattr(core, "GotAuth")
    except ImportError:
        has_core = False
    if has_core:
        pytest.skip("C1 has merged; make_auth is covered by C1's tests")
    with pytest.raises(NotImplementedError, match="C1"):
        make_auth()


async def test_the_kit_hashes_passwords_at_the_test_cost() -> None:
    # make_context and make_auth both use TEST_SCRYPT (issue #16).
    prefix = "scrypt$ln=10,r=8,p=1$"
    assert (await make_context().crypto.hash_password("pw")).startswith(prefix)
    auth: Any = make_auth()
    assert (await auth.crypto.hash_password("pw")).startswith(prefix)


async def test_make_auth_keeps_a_crypto_override() -> None:
    kit = crypto_kit([TEST_SECRET])
    auth: Any = make_auth(advanced={"crypto": kit})
    assert auth.crypto is kit
    assert (await auth.crypto.hash_password("pw")).startswith("scrypt$ln=15,r=8,p=3$")


async def test_where_helper_in_kit_context(ctx: FakeContext) -> None:
    user = await new_user(ctx)
    row = await ctx.adapter.find_one("user", [Where("email", "ada@example.com")])
    assert row is not None
    assert row["id"] == user.id


# ------------------------------------------------------------------ review fixes


async def test_session_get_hides_plugin_fields_marked_not_returned() -> None:
    from gotauth.contracts import Field, ModelSchema

    hidden = Plugin(
        id="hidden",
        schema={
            "user": ModelSchema(
                "user", {"secret_note": Field("string", required=False, returned=False)}
            )
        },
    )
    ctx = make_context(plugins=[hidden])
    user = await ctx.auth.create_user_record(
        ctx, {"email": "a@b.c", "secret_note": "do-not-return"}
    )
    created = await ctx.sign_in(user.id)
    found = await ctx.sessions.get(ctx, created.token)
    assert found is not None
    assert "secret_note" not in found.user.model_dump()


def test_revoke_oauth_tokens_needs_a_real_filter() -> None:
    from pydantic import ValidationError

    from gotauth.contracts import RevokeOAuthTokensIn

    with pytest.raises(ValidationError):
        RevokeOAuthTokensIn.model_validate({"client_id": None})
    assert RevokeOAuthTokensIn.model_validate({"user_id": "usr_1"}).user_id == "usr_1"


async def test_failure_events_survive_a_failed_call_with_path_params() -> None:
    async def fail(ctx: EndpointContext, data: BaseModel | None) -> None:
        await ctx.emit("sign_in.failed", user_id=None)
        raise AuthError("INVALID_CREDENTIALS", 401)

    plugin = Plugin(
        id="failing",
        endpoints=(
            Endpoint[Any, Any](
                id="fail_with_param", method="POST", path="/fail/{id}", handler=fail
            ),
        ),
    )
    ctx = make_context(plugins=[plugin])
    with pytest.raises(AuthError):
        await ctx.auth.api.call("fail_with_param", ctx=ctx, path_params={"id": "x"})
    assert ctx.event_types() == ["sign_in.failed"]


async def test_fake_delete_user_without_a_context_gives_hooks_one() -> None:
    # As the core does (CCR 011).
    from gotauth.contracts import DatabaseHooks, ModelHooks, Plugin

    seen: list[object] = []

    async def before_delete(ctx: Any, row: dict[str, Any]) -> None:
        seen.append(ctx)

    hooks = DatabaseHooks(hooks={"user": ModelHooks(before_delete=before_delete)})
    ctx = make_context(plugins=[Plugin(id="cleanup", database_hooks=hooks)])
    user = await new_user(ctx)
    await ctx.auth.delete_user(None, user.id)
    assert len(seen) == 1 and seen[0] is not None


async def test_fake_check_principal_runs_plugin_checks() -> None:
    async def banned(ctx: EndpointContext, principal: Principal) -> None:
        raise AuthError("ADMIN_USER_BANNED", 403)

    ctx = make_context(plugins=[Plugin(id="admin", principal_checks=(banned,))])
    principal = Principal(via="api_key", credential_id="key_1", user_id="usr_1")
    with pytest.raises(AuthError) as refused:
        await ctx.auth.check_principal(ctx, principal)
    assert refused.value.code == "ADMIN_USER_BANNED"
