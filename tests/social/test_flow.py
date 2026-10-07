"""Social sign-in and linking flows on the testing kit."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import (
    CORE_ENDPOINTS,
    AuthError,
    AuthResponse,
    EndpointContext,
    Plugin,
    SignInChallenge,
    User,
    Where,
)
from gotauth.contracts.http_models import StatusOut
from gotauth.contracts.social import ProviderTokens
from gotauth.testing._oauth import StubOAuthProvider

from .conftest import (
    ENDPOINTS,
    accounts,
    call,
    callback,
    person,
    provider,
    sign_in_with,
    social_ctx,
    start,
)


def test_endpoints_match_the_contract_table() -> None:
    specs = {spec.id: spec for spec in CORE_ENDPOINTS if spec.owner == "C4"}
    assert set(ENDPOINTS) == set(specs)
    for id, spec in specs.items():
        endpoint = ENDPOINTS[id]
        assert (endpoint.method, endpoint.path, endpoint.auth) == (
            spec.method,
            spec.path,
            spec.auth,
        )
        assert endpoint.fresh_session == spec.fresh_session
        if spec.input_format is not None:
            assert endpoint.input_format == spec.input_format
        models = [kind for kind in spec.output if not isinstance(kind, str)]
        if models:
            assert endpoint.output in models


# ---------------------------------------------------------------- sign-in


async def test_new_user_signs_in_and_pkce_is_checked() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    url = await start(ctx, callback_url="/home")
    query = parse_qs(urlsplit(url).query)
    assert query["code_challenge_method"] == ["S256"]
    assert "nonce" in query  # openid is in the default scopes
    result, _ = await callback(ctx, fake.approve(url, "c1"))
    assert result.redirect == "/home"
    assert fake.exchanged == ["c1"]  # the stub only accepts a matching verifier
    [sign_in] = ctx.auth.sign_ins
    assert sign_in.method == "social"
    row = await ctx.adapter.find_one("user", [Where("email", "ada@example.com")])
    assert row is not None and row["email_verified"] and row["name"] == "Ada"
    [account] = await accounts(ctx, row["id"])
    assert (account["provider_id"], account["account_id"]) == ("fake", "p1")


async def test_existing_pair_signs_in_the_same_user() -> None:
    fake = provider(users={"c1": person(), "c2": person(email="changed@example.com")})
    ctx = social_ctx(fake)
    await sign_in_with(ctx, fake, "c1")
    await sign_in_with(ctx, fake, "c2")
    first, second = ctx.auth.sign_ins
    assert first.user_id == second.user_id
    assert await ctx.adapter.count("user") == 1


async def test_challenge_redirects_with_its_type() -> None:
    async def interceptor(
        ctx: EndpointContext, user: User, method: str
    ) -> SignInChallenge | None:
        return SignInChallenge(type="two_factor", methods=("totp",))

    fake = provider(users={"c1": person()})
    ctx = social_ctx(
        fake, plugins=(Plugin(id="tf", sign_in_interceptors=(interceptor,)),)
    )
    result, _ = await sign_in_with(ctx, fake, "c1", callback_url="/home")
    assert result.redirect == "/home?challenge=two_factor"


async def test_no_email_is_a_provider_error() -> None:
    fake = provider(users={"c1": person(email=None)})
    ctx = social_ctx(fake)
    url = await start(ctx, error_callback_url="/oops")
    result, _ = await callback(ctx, fake.approve(url, "c1"))
    assert result.redirect == "/oops?error=PROVIDER_ERROR"
    assert ctx.auth.sign_ins == []


async def test_provider_error_parameter() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    url = await start(ctx)
    state = parse_qs(urlsplit(url).query)["state"][0]
    with pytest.raises(AuthError) as error:
        await callback(ctx, {"state": state, "error": "access_denied"})
    assert error.value.code == "PROVIDER_ERROR"


# ---------------------------------------------------------------- login CSRF


async def test_missing_cookie_is_rejected() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    url = await start(ctx)
    with pytest.raises(AuthError) as error:
        await callback(ctx, fake.approve(url, "c1"), keep_jar=False)
    assert error.value.code == "TOKEN_INVALID"
    assert ctx.auth.sign_ins == []


async def test_cookie_for_another_state_is_rejected() -> None:
    fake = provider(users={"c1": person()})
    victim = social_ctx(fake)
    attacker_url = await start(victim.next_request())
    await start(victim)  # the victim's own cookie
    with pytest.raises(AuthError) as error:
        await callback(victim, fake.approve(attacker_url, "c1"))
    assert error.value.code == "TOKEN_INVALID"
    assert victim.auth.sign_ins == []


async def test_reused_state_is_rejected() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    url = await start(ctx)
    query = fake.approve(url, "c1")
    jar_ctx = ctx.next_request()
    await callback(ctx, query)
    with pytest.raises(AuthError) as error:
        await callback(jar_ctx, query)
    assert error.value.code == "TOKEN_INVALID"
    assert len(ctx.auth.sign_ins) == 1


async def test_expired_state() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    url = await start(ctx)
    ctx.clock.advance("10m")
    with pytest.raises(AuthError) as error:
        await callback(ctx, fake.approve(url, "c1"))
    assert error.value.code == "TOKEN_EXPIRED"


async def test_state_of_another_provider_is_rejected() -> None:
    one = provider("one", users={"c1": person()})
    two = provider("two", users={"c1": person()})
    ctx = social_ctx(one, two)
    url = await start(ctx, provider="one")
    with pytest.raises(AuthError) as error:
        await callback(ctx, one.approve(url, "c1"), provider_id="two")
    assert error.value.code == "TOKEN_INVALID"


async def test_untrusted_callback_url_is_rejected() -> None:
    ctx = social_ctx(provider())
    for field in ("callback_url", "error_callback_url"):
        with pytest.raises(AuthError) as error:
            await start(ctx, **{field: "https://evil.test/x"})
        assert error.value.code == "INVALID_REQUEST"


async def test_unknown_provider() -> None:
    ctx = social_ctx(provider())
    with pytest.raises(AuthError) as error:
        await start(ctx, provider="nope")
    assert error.value.code == "NOT_FOUND"


# ---------------------------------------------------------------- tokens


async def test_provider_tokens_are_not_stored_by_default() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    await sign_in_with(ctx, fake, "c1")
    [row] = await ctx.adapter.find_many("account")
    assert row["access_token_enc"] is None
    assert "fake-access" not in json.dumps(await ctx.dump(), default=str)


async def test_provider_tokens_are_stored_encrypted_with_the_flag() -> None:
    fake = provider(users={"c1": person()}, store_provider_tokens=True)
    ctx = social_ctx(fake)
    await sign_in_with(ctx, fake, "c1")
    [row] = await ctx.adapter.find_many("account")
    assert row["access_token_enc"].startswith("v1.")
    assert (
        ctx.crypto.decrypt(row["access_token_enc"], purpose="account_token")
        == "fake-access-1"
    )
    assert "fake-access" not in json.dumps(await ctx.dump(), default=str)


async def test_state_row_holds_no_plain_verifier() -> None:
    ctx = social_ctx(provider())
    await start(ctx)
    [row] = await ctx.adapter.find_many("verification")
    assert set(row["data"]) == {"sealed"}
    assert row["data"]["sealed"].startswith("v1.")


# ---------------------------------------------------------------- linking rules


async def local_user(ctx: Any, *, verified: bool, password: bool = True) -> str:
    user = await ctx.auth.create_user_record(
        ctx, {"email": "ada@example.com", "email_verified": verified}
    )
    if password:
        now = ctx.clock.now()
        await ctx.adapter.create(
            "account",
            {
                "id": ctx.ids.new("acc"),
                "user_id": user.id,
                "provider_id": "credential",
                "account_id": user.id,
                "password_hash": "scrypt$x",
                "created_at": now,
                "updated_at": now,
            },
        )
    return user.id


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    provider_verified=st.booleans(),
    local_verified=st.booleans(),
    trusted=st.booleans(),
    same_email=st.booleans(),
)
async def test_linking_matrix(
    provider_verified: bool, local_verified: bool, trusted: bool, same_email: bool
) -> None:
    email = "ada@example.com" if same_email else "other@example.com"
    fake = provider(users={"c1": person(email=email, verified=provider_verified)})
    ctx = social_ctx(fake, linking={"trusted_providers": ("fake",) if trusted else ()})
    user_id = await local_user(ctx, verified=local_verified)
    url = await start(ctx, error_callback_url="/oops")
    result, _ = await callback(ctx, fake.approve(url, "c1"))
    if not same_email:
        expected = "new_user"
    elif provider_verified and (local_verified or trusted):
        expected = "linked"
    else:
        expected = "refused"
    if expected == "refused":
        assert result.redirect == "/oops?error=ACCOUNT_NOT_LINKED"
        assert ctx.auth.sign_ins == []
        return
    [sign_in] = ctx.auth.sign_ins
    if expected == "linked":
        assert sign_in.user_id == user_id
    else:
        assert sign_in.user_id != user_id
        row = await ctx.adapter.find_one("user", [Where("id", sign_in.user_id)])
        assert row is not None and row["email_verified"] is provider_verified


async def test_linking_can_be_turned_off() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake, linking={"enabled": False})
    await local_user(ctx, verified=True)
    url = await start(ctx, error_callback_url="/oops")
    result, _ = await callback(ctx, fake.approve(url, "c1"))
    assert result.redirect == "/oops?error=ACCOUNT_NOT_LINKED"


async def test_trusted_link_to_unverified_account_drops_its_password() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake, linking={"trusted_providers": ("fake",)})
    user_id = await local_user(ctx, verified=False)
    squatter = await ctx.sessions.create(ctx, user_id)
    await sign_in_with(ctx, fake, "c1")
    rows = await accounts(ctx, user_id)
    assert [r["provider_id"] for r in rows] == ["fake"]
    assert await ctx.sessions.get(ctx, squatter.token) is None
    row = await ctx.adapter.find_one("user", [Where("id", user_id)])
    assert row is not None and row["email_verified"]


async def test_link_social() -> None:
    fake = provider(
        users={"c1": person(id="gh1"), "c2": person(id="gh2", email="x@example.com")}
    )
    ctx = social_ctx(fake)
    user_id = await local_user(ctx, verified=True)
    await ctx.sign_in(user_id)
    url = await start(ctx, "link_social", callback_url="/settings")
    result, done = await callback(ctx, fake.approve(url, "c1"))
    assert result.redirect == "/settings"
    assert {r["provider_id"] for r in await accounts(ctx, user_id)} == {
        "credential",
        "fake",
    }
    assert ctx.auth.sign_ins == []
    assert "account.linked" in done.event_types()
    # A different email is refused unless allowed.
    url = await start(ctx, "link_social", callback_url="/settings")
    result, _ = await callback(ctx, fake.approve(url, "c2"))
    assert result.redirect == "/settings?error=ACCOUNT_NOT_LINKED"


async def test_link_social_refuses_a_pair_owned_by_someone_else() -> None:
    fake = provider(
        users={
            "c1": person(email="bob@example.com"),
            "c2": person(email="ada@example.com"),
        }
    )
    ctx = social_ctx(fake)
    await sign_in_with(ctx, fake, "c1")  # bob owns pair (fake, p1)
    user_id = await local_user(ctx, verified=True)
    await ctx.sign_in(user_id)
    url = await start(ctx, "link_social", callback_url="/settings")
    result, _ = await callback(ctx, fake.approve(url, "c2"))
    assert result.redirect == "/settings?error=ACCOUNT_NOT_LINKED"


async def test_link_social_with_different_emails_allowed() -> None:
    fake = provider(users={"c1": person(email="x@example.com")})
    ctx = social_ctx(fake, linking={"allow_different_emails": True})
    user_id = await local_user(ctx, verified=True)
    await ctx.sign_in(user_id)
    url = await start(ctx, "link_social")
    await callback(ctx, fake.approve(url, "c1"))
    assert len(await accounts(ctx, user_id)) == 2


# ---------------------------------------------------------------- accounts


async def test_list_and_unlink_accounts() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    user_id = await local_user(ctx, verified=True)
    await ctx.sign_in(user_id)
    url = await start(ctx, "link_social")
    await callback(ctx, fake.approve(url, "c1"))
    listed = await call(ctx, "list_accounts")
    assert [a.provider_id for a in listed.accounts] == ["credential", "fake"]
    assert await call(ctx, "unlink_account", {"provider_id": "fake"}) == StatusOut(
        status="ok"
    )
    with pytest.raises(AuthError) as last:
        await call(ctx, "unlink_account", {"provider_id": "credential"})
    assert last.value.code == "LAST_SIGN_IN_METHOD"
    with pytest.raises(AuthError) as missing:
        await call(ctx, "unlink_account", {"provider_id": "fake"})
    assert missing.value.code == "NOT_FOUND"


async def test_a_social_only_user_cannot_unlink_the_last_provider() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake)
    await sign_in_with(ctx, fake, "c1")
    [sign_in] = ctx.auth.sign_ins
    await ctx.sign_in(sign_in.user_id)
    with pytest.raises(AuthError) as error:
        await call(ctx, "unlink_account", {"provider_id": "fake"})
    assert error.value.code == "LAST_SIGN_IN_METHOD"


# ---------------------------------------------------------------- form_post


async def test_form_post_callback_continues_as_get() -> None:
    apple = provider("apple", users={"c1": person(name=None)}, callback_method="POST")
    ctx = social_ctx(apple)
    url = await start(ctx, provider="apple", callback_url="/home")
    query = apple.approve(url, "c1")
    form_ctx = ctx.auth.context(
        request=None, path_params={"provider": "apple"}
    )  # no cookie
    posted = await call(
        form_ctx,
        "social_callback_post",
        {**query, "user": json.dumps({"name": {"firstName": "Ada", "lastName": "L"}})},
    )
    assert isinstance(posted, AuthResponse)
    target = urlsplit(posted.redirect or "")
    assert target.path == "/api/auth/callback/apple"
    forwarded = {k: v[0] for k, v in parse_qs(target.query).items()}
    result, _ = await callback(ctx, forwarded, provider_id="apple")
    assert result.redirect == "/home"
    assert len(ctx.auth.sign_ins) == 1


async def test_form_post_for_a_get_provider_is_not_found() -> None:
    ctx = social_ctx(provider())
    form_ctx = ctx.auth.context(request=None, path_params={"provider": "fake"})
    with pytest.raises(AuthError) as error:
        await call(form_ctx, "social_callback_post", {"code": "x", "state": "y"})
    assert error.value.code == "NOT_FOUND"


# ---------------------------------------------------------------- review fixes


async def test_trusted_claim_removes_every_unproven_link() -> None:
    fake = provider(users={"c1": person()})
    ctx = social_ctx(fake, linking={"trusted_providers": ("fake",)})
    user_id = await local_user(ctx, verified=False)
    now = ctx.clock.now()
    await ctx.adapter.create(
        "account",
        {
            "id": "acc_attacker",
            "user_id": user_id,
            "provider_id": "microsoft",
            "account_id": "attacker",
            "created_at": now,
            "updated_at": now,
        },
    )
    await sign_in_with(ctx, fake, "c1")
    assert [r["provider_id"] for r in await accounts(ctx, user_id)] == ["fake"]


class RefreshOnce(StubOAuthProvider):
    """Sends a refresh token only on the first exchange, like Google."""

    async def exchange_code(self, http: Any, **kwargs: Any) -> ProviderTokens:
        tokens = await super().exchange_code(http, **kwargs)
        first = len(self.exchanged) == 1
        return ProviderTokens(
            access_token=tokens.access_token,
            refresh_token="rt-1" if first else None,
            id_token=None,
            expires_at=None,
            scope=tokens.scope if first else None,
        )


async def test_later_sign_ins_keep_the_stored_refresh_token() -> None:
    fake = RefreshOnce(
        "fake", users={"c1": person(), "c2": person()}, store_provider_tokens=True
    )
    ctx = social_ctx(fake)
    await sign_in_with(ctx, fake, "c1")
    await sign_in_with(ctx, fake, "c2")
    [row] = await ctx.adapter.find_many("account")
    assert (
        ctx.crypto.decrypt(row["refresh_token_enc"], purpose="account_token") == "rt-1"
    )
    assert (
        ctx.crypto.decrypt(row["access_token_enc"], purpose="account_token")
        == "fake-access-2"
    )
    assert row["scope"] is not None


async def test_oidc_providers_get_a_nonce_without_openid_scope() -> None:
    fake = provider(users={"c1": person()})
    fake.default_scopes = ("name", "email")
    fake.uses_nonce = True  # type: ignore[attr-defined]
    ctx = social_ctx(fake)
    url = await start(ctx)
    state = parse_qs(urlsplit(url).query)["state"][0]
    assert fake.started[state].nonce is not None
    plain = provider("plain", users={"c1": person()})
    plain.default_scopes = ("email",)
    ctx = social_ctx(plain)
    url = await start(ctx, provider="plain")
    state = parse_qs(urlsplit(url).query)["state"][0]
    assert plain.started[state].nonce is None
