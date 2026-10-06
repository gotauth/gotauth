"""Email + password flows on the testing kit."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import CORE_ENDPOINTS, AuthError, AuthResponse, Where
from gotauth.contracts.http_models import ChallengeOut, SignInOut, StatusOut
from gotauth.email_password import VERIFICATION_PREFIX
from gotauth.testing import FakeContext

from .conftest import (
    ENDPOINTS,
    PASSWORD,
    PLUGIN,
    add_user,
    call,
    ep_ctx,
    password_hash,
    spy_crypto,
    token_from,
)


def test_endpoints_match_the_contract_table() -> None:
    specs = {spec.id: spec for spec in CORE_ENDPOINTS if spec.owner == "C2"}
    assert set(ENDPOINTS) == set(specs)
    for id, spec in specs.items():
        endpoint = ENDPOINTS[id]
        assert (endpoint.method, endpoint.path, endpoint.auth) == (
            spec.method,
            spec.path,
            spec.auth,
        )
        assert endpoint.fresh_session == spec.fresh_session
        assert endpoint.server_only == spec.server_only
        if spec.input_format is not None:
            assert endpoint.input_format == spec.input_format
        models = [kind for kind in spec.output if not isinstance(kind, str)]
        assert endpoint.output in models


def test_requires_email_follows_verification() -> None:
    from gotauth.contracts import EmailPasswordConfig
    from gotauth.email_password import email_password_plugin

    assert PLUGIN.requires_email
    off = EmailPasswordConfig(require_email_verification=False)
    assert not email_password_plugin(off).requires_email


# ---------------------------------------------------------------- sign-up


async def test_sign_up_sends_verification_and_creates_no_session() -> None:
    ctx = ep_ctx()
    out = await call(
        ctx, "sign_up_email", {"email": " Ada@Example.com ", "password": PASSWORD}
    )
    assert out == StatusOut(status="verification_sent")
    assert ctx.auth.sign_ins == []
    message = ctx.mailer.last("verify_email", "ada@example.com")
    assert message.data["url"].startswith("/verify-email?token=gav_")
    user = await ctx.adapter.find_one("user", [Where("email", "ada@example.com")])
    assert user is not None
    account = await ctx.adapter.find_one("account", [Where("user_id", user["id"])])
    assert account is not None
    assert account["provider_id"] == "credential"
    assert account["account_id"] == user["id"]


async def test_sign_up_existing_email_looks_the_same() -> None:
    spy = spy_crypto()
    ctx = ep_ctx(spy=spy)
    await add_user(ctx)
    spy.hashed = 0
    out = await call(
        ctx, "sign_up_email", {"email": "ada@example.com", "password": PASSWORD}
    )
    assert out == StatusOut(status="verification_sent")
    assert spy.hashed == 1  # the password was still hashed
    assert ctx.mailer.last("sign_up_existing_account", "ada@example.com")
    assert await ctx.adapter.count("user") == 1


async def test_sign_up_without_verification() -> None:
    ctx = ep_ctx(require_email_verification=False)
    out = await call(
        ctx, "sign_up_email", {"email": "ada@example.com", "password": PASSWORD}
    )
    assert isinstance(out, SignInOut | ChallengeOut)
    assert [call.method for call in ctx.auth.sign_ins] == ["password"]
    with pytest.raises(AuthError) as error:
        await call(
            ctx, "sign_up_email", {"email": "ada@example.com", "password": PASSWORD}
        )
    assert error.value.code == "USER_ALREADY_EXISTS"


async def test_sign_up_without_auto_sign_in() -> None:
    ctx = ep_ctx(require_email_verification=False, auto_sign_in=False)
    out = await call(
        ctx, "sign_up_email", {"email": "ada@example.com", "password": PASSWORD}
    )
    assert out == StatusOut(status="ok")
    assert ctx.auth.sign_ins == []


async def test_sign_up_race_answers_like_an_existing_email() -> None:
    ctx = ep_ctx()
    original = ctx.auth.create_user_record

    async def racing(context: Any, data: Any) -> Any:
        await original(context, data)  # the concurrent sign-up
        return await original(context, data)

    ctx.auth.create_user_record = racing  # type: ignore[method-assign]
    out = await call(
        ctx, "sign_up_email", {"email": "ada@example.com", "password": PASSWORD}
    )
    assert out == StatusOut(status="verification_sent")


@pytest.mark.parametrize("email", ["no-at-sign", "a@b", "x" * 250 + "@example.com"])
async def test_invalid_emails_are_rejected(email: str) -> None:
    ctx = ep_ctx()
    with pytest.raises(AuthError) as error:
        await call(ctx, "sign_up_email", {"email": email, "password": PASSWORD})
    assert error.value.code == "INVALID_REQUEST"


async def test_untrusted_redirects_are_rejected() -> None:
    ctx = ep_ctx()
    for endpoint_id, body in [
        (
            "sign_up_email",
            {
                "email": "a@example.com",
                "password": PASSWORD,
                "callback_url": "https://evil.test",
            },
        ),
        (
            "send_verification_email",
            {"email": "a@example.com", "callback_url": "//evil.test"},
        ),
        (
            "request_password_reset",
            {"email": "a@example.com", "redirect_to": "https://evil.test/r"},
        ),
        ("verify_email", {"token": "gav_x", "callback_url": "https://evil.test"}),
    ]:
        with pytest.raises(AuthError) as error:
            await call(ctx, endpoint_id, body)
        assert error.value.code == "INVALID_REQUEST", endpoint_id


# ---------------------------------------------------------------- sign-in


async def test_sign_in_unknown_and_wrong_password_look_the_same() -> None:
    spy = spy_crypto()
    ctx = ep_ctx(spy=spy)
    await add_user(ctx)
    errors = []
    for email, password in [
        ("nobody@example.com", PASSWORD),
        ("ada@example.com", "wrong password"),
    ]:
        with pytest.raises(AuthError) as error:
            await call(ctx, "sign_in_email", {"email": email, "password": password})
        errors.append((error.value.code, error.value.status, error.value.message))
    assert errors[0] == errors[1] == ("INVALID_CREDENTIALS", 401, errors[0][2])
    assert spy.verified[0] == ""  # the dummy hash ran for the unknown email
    assert ctx.event_types().count("sign_in.failed") == 2


async def test_sign_in_success_goes_through_complete_sign_in() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    await call(
        ctx,
        "sign_in_email",
        {"email": "ada@example.com", "password": PASSWORD, "remember_me": False},
    )
    [sign_in] = ctx.auth.sign_ins
    assert (sign_in.user_id, sign_in.method, sign_in.remember_me) == (
        user_id,
        "password",
        False,
    )


async def test_unverified_needs_the_right_password_first() -> None:
    ctx = ep_ctx()
    await add_user(ctx, verified=False)
    with pytest.raises(AuthError) as wrong:
        await call(
            ctx,
            "sign_in_email",
            {"email": "ada@example.com", "password": "bad password"},
        )
    assert wrong.value.code == "INVALID_CREDENTIALS"
    with pytest.raises(AuthError) as right:
        await call(
            ctx, "sign_in_email", {"email": "ada@example.com", "password": PASSWORD}
        )
    assert right.value.code == "EMAIL_NOT_VERIFIED"


async def test_over_long_password_is_not_hashed() -> None:
    spy = spy_crypto()
    ctx = ep_ctx(spy=spy)
    await add_user(ctx)
    spy.fail_on_verify = True
    with pytest.raises(AuthError) as error:
        await call(
            ctx, "sign_in_email", {"email": "ada@example.com", "password": "x" * 129}
        )
    assert error.value.code == "INVALID_CREDENTIALS"


async def test_weak_hashes_are_upgraded_after_sign_in() -> None:
    import bcrypt

    ctx = ep_ctx()
    legacy = "bcrypt$" + bcrypt.hashpw(PASSWORD.encode(), bcrypt.gensalt(4)).decode()
    check = await ctx.crypto.verify_password(PASSWORD, legacy)
    if not check.ok:
        pytest.skip("crypto kit uses another tag for bcrypt")
    user_id = await add_user(ctx, password_hash=legacy)
    await call(ctx, "sign_in_email", {"email": "ada@example.com", "password": PASSWORD})
    upgraded = await password_hash(ctx, user_id)
    assert upgraded != legacy
    assert not (await ctx.crypto.verify_password(PASSWORD, upgraded)).needs_rehash


async def test_sign_out() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    created = await ctx.sign_in(user_id)
    assert await call(ctx, "sign_out") == StatusOut(status="ok")
    assert await ctx.sessions.get(ctx, created.token) is None
    assert "sign_out" in ctx.event_types()
    assert ctx.cookie("session_token") is None


# ---------------------------------------------------------------- verification


async def test_verify_email_flow_and_single_use() -> None:
    ctx = ep_ctx()
    await call(ctx, "sign_up_email", {"email": "ada@example.com", "password": PASSWORD})
    token = token_from(ctx.mailer.last("verify_email").data["url"])
    assert await call(ctx, "verify_email", {"token": token}) == StatusOut(status="ok")
    user = await ctx.adapter.find_one("user", [Where("email", "ada@example.com")])
    assert user is not None and user["email_verified"]
    assert "user.email_verified" in ctx.event_types()
    with pytest.raises(AuthError) as again:
        await call(ctx, "verify_email", {"token": token})
    assert again.value.code == "TOKEN_INVALID"


async def test_verify_email_redirects_with_callback() -> None:
    ctx = ep_ctx()
    await call(
        ctx,
        "sign_up_email",
        {"email": "ada@example.com", "password": PASSWORD, "callback_url": "/welcome"},
    )
    url = ctx.mailer.last("verify_email").data["url"]
    assert "callback_url=%2Fwelcome" in url
    token = token_from(url)
    ok = await call(ctx, "verify_email", {"token": token, "callback_url": "/welcome"})
    assert isinstance(ok, AuthResponse) and ok.redirect == "/welcome"
    bad = await call(
        ctx, "verify_email", {"token": token, "callback_url": "/welcome?x=1"}
    )
    assert (
        isinstance(bad, AuthResponse)
        and bad.redirect == "/welcome?x=1&error=TOKEN_INVALID"
    )


async def test_send_verification_email_is_quiet() -> None:
    ctx = ep_ctx()
    await add_user(ctx, verified=False)
    await add_user(ctx, "bob@example.com")
    outs = [
        await call(ctx, "send_verification_email", {"email": email})
        for email in ("ada@example.com", "bob@example.com", "nobody@example.com")
    ]
    assert outs == [StatusOut(status="ok")] * 3
    assert [m.to for m in ctx.mailer.sent] == ["ada@example.com"]


async def test_verification_token_is_for_the_address_it_was_sent_to() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx, verified=False)
    await call(ctx, "send_verification_email", {"email": "ada@example.com"})
    token = token_from(ctx.mailer.last("verify_email").data["url"])
    await ctx.adapter.update(
        "user", [Where("id", user_id)], {"email": "other@example.com"}
    )
    with pytest.raises(AuthError) as error:
        await call(ctx, "verify_email", {"token": token})
    assert error.value.code == "TOKEN_INVALID"


# ---------------------------------------------------------------- password reset


async def request_reset(ctx: FakeContext, email: str = "ada@example.com") -> str:
    await call(ctx, "request_password_reset", {"email": email, "redirect_to": "/reset"})
    url = ctx.mailer.last("reset_password").data["url"]
    assert url.startswith("http://localhost:8000/reset?token=gav_")
    return token_from(url)


async def test_request_password_reset_is_quiet() -> None:
    ctx = ep_ctx()
    await add_user(ctx)
    for email in ("ada@example.com", "nobody@example.com"):
        out = await call(
            ctx, "request_password_reset", {"email": email, "redirect_to": "/reset"}
        )
        assert out == StatusOut(status="ok")
    assert [m.to for m in ctx.mailer.sent] == ["ada@example.com"]


async def test_reset_password_revokes_sessions_by_default() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    session = await ctx.sign_in(user_id)
    token = await request_reset(ctx)
    out = await call(
        ctx, "reset_password", {"token": token, "new_password": "a new password"}
    )
    assert out == StatusOut(status="ok")
    assert await ctx.sessions.get(ctx, session.token) is None
    assert (
        await ctx.crypto.verify_password(
            "a new password", await password_hash(ctx, user_id)
        )
    ).ok
    assert ctx.mailer.last("security_notice").data["event"] == "password.reset"
    assert "password.reset" in ctx.event_types()


async def test_reset_password_keeps_sessions_with_the_flag_off() -> None:
    ctx = ep_ctx(revoke_sessions_on_password_reset=False)
    user_id = await add_user(ctx)
    session = await ctx.sign_in(user_id)
    token = await request_reset(ctx)
    await call(
        ctx, "reset_password", {"token": token, "new_password": "a new password"}
    )
    assert await ctx.sessions.get(ctx, session.token) is not None


async def test_reset_token_expiry_kind_and_length() -> None:
    ctx = ep_ctx()
    await add_user(ctx)
    token = await request_reset(ctx)
    with pytest.raises(AuthError) as short:
        await call(ctx, "reset_password", {"token": token, "new_password": "short"})
    assert short.value.code == "PASSWORD_TOO_SHORT"
    ctx.clock.advance("1h")
    with pytest.raises(AuthError) as expired:
        await call(
            ctx, "reset_password", {"token": token, "new_password": "a new password"}
        )
    assert expired.value.code == "TOKEN_EXPIRED"
    await ctx.adapter.update(
        "user", [Where("email", "ada@example.com")], {"email_verified": False}
    )
    await call(ctx, "send_verification_email", {"email": "ada@example.com"})
    verify = token_from(ctx.mailer.last("verify_email").data["url"])
    with pytest.raises(AuthError) as kind:
        await call(
            ctx, "reset_password", {"token": verify, "new_password": "a new password"}
        )
    assert kind.value.code == "TOKEN_INVALID"


async def test_a_new_reset_token_replaces_the_old_one() -> None:
    ctx = ep_ctx()
    await add_user(ctx)
    first = await request_reset(ctx)
    await request_reset(ctx)
    with pytest.raises(AuthError) as error:
        await call(
            ctx, "reset_password", {"token": first, "new_password": "a new password"}
        )
    assert error.value.code == "TOKEN_INVALID"


async def test_concurrent_resets_with_one_token_succeed_once() -> None:
    ctx = ep_ctx()
    await add_user(ctx)
    token = await request_reset(ctx)
    contexts = [ctx.next_request() for _ in range(20)]

    async def attempt(context: FakeContext) -> bool:
        try:
            await call(
                context,
                "reset_password",
                {"token": token, "new_password": "a new password"},
            )
        except AuthError:
            return False
        return True

    results = await asyncio.gather(*(attempt(c) for c in contexts))
    assert results.count(True) == 1


async def test_no_raw_verification_token_is_stored() -> None:
    ctx = ep_ctx()
    await add_user(ctx)
    token = await request_reset(ctx)
    dumped = json.dumps(await ctx.dump(), default=str)
    assert token not in dumped
    assert VERIFICATION_PREFIX not in dumped


# ---------------------------------------------------------------- account


async def test_change_password() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    current = await ctx.sign_in(user_id)
    other_ctx = ctx.next_request()
    other = await other_ctx.sessions.create(other_ctx, user_id)
    with pytest.raises(AuthError) as wrong:
        await call(
            ctx,
            "change_password",
            {"current_password": "bad", "new_password": "another password"},
        )
    assert wrong.value.code == "INVALID_CREDENTIALS"
    out = await call(
        ctx,
        "change_password",
        {
            "current_password": PASSWORD,
            "new_password": "another password",
            "revoke_other_sessions": True,
        },
    )
    assert out == StatusOut(status="ok")
    assert "password.changed" in ctx.event_types()
    assert await ctx.sessions.get(ctx, current.token) is not None
    assert await ctx.sessions.get(ctx, other.token) is None


async def test_change_email_flow() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    await ctx.sign_in(user_id)
    out = await call(ctx, "change_email", {"new_email": "New@Example.com"})
    assert out == StatusOut(status="verification_sent")
    message = ctx.mailer.last("change_email", "new@example.com")
    assert message.data["new_email"] == "new@example.com"
    assert ctx.mailer.last("security_notice", "ada@example.com")
    await call(ctx, "verify_email", {"token": token_from(message.data["url"])})
    row = await ctx.adapter.find_one("user", [Where("id", user_id)])
    assert (
        row is not None and row["email"] == "new@example.com" and row["email_verified"]
    )
    assert "user.email_changed" in ctx.event_types()


async def test_change_email_to_a_taken_address_looks_the_same() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    await add_user(ctx, "bob@example.com")
    await ctx.sign_in(user_id)
    out = await call(ctx, "change_email", {"new_email": "bob@example.com"})
    assert out == StatusOut(status="verification_sent")
    with pytest.raises(LookupError):
        ctx.mailer.last("change_email")


async def test_change_email_taken_by_the_time_of_verification() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    await ctx.sign_in(user_id)
    await call(ctx, "change_email", {"new_email": "new@example.com"})
    token = token_from(ctx.mailer.last("change_email").data["url"])
    await add_user(ctx, "new@example.com")
    with pytest.raises(AuthError) as error:
        await call(ctx, "verify_email", {"token": token})
    assert error.value.code == "USER_ALREADY_EXISTS"


async def test_update_user() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    await ctx.sign_in(user_id)
    out = await call(ctx, "update_user", {"name": "Ada"})
    assert out.name == "Ada"
    assert out.email == "ada@example.com"
    assert "user.updated" in ctx.event_types()
    with pytest.raises(AuthError) as error:
        await call(ctx, "update_user", {"email": "x@example.com"})
    assert error.value.code == "INVALID_REQUEST"


async def test_delete_user_needs_the_password() -> None:
    ctx = ep_ctx()
    user_id = await add_user(ctx)
    await ctx.sign_in(user_id)
    for body in ({}, {"password": "wrong password"}):
        with pytest.raises(AuthError) as error:
            await call(ctx, "delete_user", body)
        assert error.value.code == "INVALID_CREDENTIALS"
    assert ctx.auth.deleted_users == []
    assert await call(ctx, "delete_user", {"password": PASSWORD}) == StatusOut(
        status="ok"
    )
    assert ctx.auth.deleted_users == [user_id]
    assert ctx.cookie("session_token") is None


# ---------------------------------------------------------------- properties


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(length=st.integers(min_value=0, max_value=140))
async def test_length_boundaries(length: int) -> None:
    ctx = ep_ctx()
    password = "p" * length
    body = {"email": "ada@example.com", "password": password}
    if length < 8:
        expected: str | None = "PASSWORD_TOO_SHORT"
    elif length > 128:
        expected = "PASSWORD_TOO_LONG"
    else:
        expected = None
    try:
        await call(ctx, "sign_up_email", body)
    except AuthError as error:
        assert error.code == expected
    else:
        assert expected is None


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    password=st.text(
        alphabet=st.characters(codec="utf-8", exclude_categories=("Cs",)),
        min_size=12,
        max_size=40,
    )
)
async def test_passwords_never_leak(
    password: str, caplog: pytest.LogCaptureFixture
) -> None:
    password = "pw-secret-" + password  # distinct from ids, hashes and timestamps
    caplog.set_level(logging.DEBUG)
    ctx = ep_ctx()
    outputs: list[str] = []
    for endpoint_id, body in [
        ("sign_up_email", {"email": "ada@example.com", "password": password}),
        ("sign_in_email", {"email": "ada@example.com", "password": password}),
        ("sign_in_email", {"email": "nobody@example.com", "password": password}),
    ]:
        try:
            result = await call(ctx, endpoint_id, body)
            outputs.append(repr(result))
        except AuthError as error:
            outputs.append(repr(error) + str(error.details))
    outputs.append(repr([event.data for event in ctx.events]))
    outputs.append(caplog.text)
    assert all(password not in text for text in outputs)
