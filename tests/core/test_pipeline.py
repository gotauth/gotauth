"""The request pipeline over HTTP (CONTRACTS 4, 5, 6, 10, 12.1, 14)."""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import AuthEvent, EndpointContext, Plugin, Principal
from gotauth.testing import make_client, stub_resolver

from .conftest import build, two_factor_plugin


async def sign_in(
    client: httpx.AsyncClient, email: str = "ada@example.com"
) -> httpx.Response:
    response = await client.post("/login", json={"email": email})
    assert response.status_code == 200, response.text
    return response


# ------------------------------------------------------------------ routing and input


async def test_json_round_trip_and_no_store(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.post("/echo", json={"name": "ab", "count": 2})
    assert response.status_code == 200
    assert response.json() == {"name": "abab", "user_id": None}
    assert response.headers["cache-control"] == "no-store"


async def test_unknown_route_and_server_only_are_not_found(auth: Any) -> None:
    async with make_client(auth) as client:
        assert (await client.get("/nope")).json()["error"]["code"] == "NOT_FOUND"
        assert (await client.get("/count")).status_code == 404
        assert (await client.get("/echo")).status_code == 404


async def test_path_params(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.get("/items/abc")
    assert response.json() == {"id": "abc"}


async def test_json_endpoint_rejects_other_content_types(auth: Any) -> None:
    async with make_client(auth) as client:
        plain = await client.post(
            "/echo", content=b'{"name": "a"}', headers={"content-type": "text/plain"}
        )
        form = await client.post("/echo", data={"name": "a"})
    assert plain.status_code == 415
    assert plain.json()["error"]["code"] == "UNSUPPORTED_MEDIA_TYPE"
    assert form.status_code == 415


async def test_form_endpoint_parses_form_bodies(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.post(
            "/token", data={"grant_type": "authorization_code"}
        )
    assert response.json() == {"access_token": "x"}


async def test_delete_with_json_body(auth: Any) -> None:
    async with make_client(auth) as client:
        await sign_in(client)
        response = await client.request("DELETE", "/thing", json={"name": "x"})
    assert response.json() == {"removed": "x"}


async def test_invalid_json(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.post("/echo", content=b"{not json")
    assert response.json()["error"]["code"] == "INVALID_REQUEST"


@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    secret=st.text(min_size=1, max_size=30).filter(lambda s: s.strip() and '"' not in s)
)
async def test_validation_errors_never_echo_input(auth: Any, secret: str) -> None:
    async with make_client(auth) as client:
        value = f"x{secret}"  # never a valid integer
        response = await client.post("/echo", json={"name": value, "count": value})
    assert response.status_code == 400
    body = response.json()
    assert body["error"]["code"] == "INVALID_REQUEST"
    assert value not in json.dumps(body["error"].get("details"))


async def test_body_size_cap(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.post("/echo", content=b"x" * (1024 * 1024 + 1))
    assert response.status_code == 413


# ------------------------------------------------------------------ principals


async def test_session_cookie_principal(auth: Any) -> None:
    async with make_client(auth) as client:
        await sign_in(client)
        response = await client.get("/whoami")
    assert response.json()["via"] == "session"


async def test_bearer_session_token() -> None:
    auth = build(sessions={"expose_token": True})
    async with make_client(auth) as client:
        token = (await sign_in(client)).json()["token"]
        client.cookies.clear()
        response = await client.get(
            "/whoami", headers={"authorization": f"Bearer {token}"}
        )
    assert response.json()["via"] == "session"


async def test_unknown_credential_prefix_is_unauthenticated(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.get("/whoami", headers={"x-api-key": "zzz_123"})
    assert response.status_code == 401


async def test_resolver_with_longest_prefix_and_scopes() -> None:
    narrow = Principal(
        via="api_key", credential_id="key_1", user_id="usr_1", scopes=frozenset()
    )
    wide = Principal(
        via="api_key",
        credential_id="key_2",
        user_id="usr_2",
        scopes=frozenset({"echo:write"}),
    )
    keys = Plugin(
        id="keys",
        principal_resolvers=(
            stub_resolver("gak_", narrow),
            stub_resolver("gak_w", wide),
        ),
    )
    auth = build(keys)
    async with make_client(auth) as client:
        denied = await client.post(
            "/scoped", json={"name": "a"}, headers={"x-api-key": "gak_1"}
        )
        allowed = await client.post(
            "/scoped", json={"name": "a"}, headers={"authorization": "Bearer gak_w1"}
        )
    assert denied.status_code == 403
    assert denied.json()["error"]["details"] == {"required": ["echo:write"]}
    assert allowed.json()["user_id"] == "usr_2"


async def test_session_endpoint_rejects_api_keys() -> None:
    principal = Principal(via="api_key", credential_id="key_1", user_id="usr_1")
    auth = build(
        Plugin(id="keys", principal_resolvers=(stub_resolver("gak_", principal),))
    )
    async with make_client(auth) as client:
        response = await client.post(
            "/session-echo", json={"name": "a"}, headers={"x-api-key": "gak_1"}
        )
    assert response.status_code == 401


async def test_fresh_session(clock: Any) -> None:
    auth = build(clock=clock)
    async with make_client(auth) as client:
        await sign_in(client)
        assert (await client.post("/fresh-echo", json={"name": "a"})).status_code == 200
        clock.advance("2d")
        stale = await client.post("/fresh-echo", json={"name": "a"})
    assert stale.json()["error"]["code"] in (
        "FRESH_SESSION_REQUIRED",
        "UNAUTHENTICATED",
    )


async def test_failing_resolver_fails_closed() -> None:
    async def broken(ctx: Any, credential: str) -> Principal | None:
        raise RuntimeError("db down")

    class Resolver:
        prefixes: tuple[str, ...] = ("gak_",)

        async def __call__(
            self, ctx: EndpointContext, credential: str
        ) -> Principal | None:
            return await broken(ctx, credential)

    auth = build(Plugin(id="keys", principal_resolvers=(Resolver(),)))
    async with make_client(auth) as client:
        response = await client.get("/whoami", headers={"x-api-key": "gak_1"})
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"


async def test_principal_check_rejects_with_its_code() -> None:
    from gotauth.contracts import AuthError

    async def banned(ctx: Any, principal: Principal) -> None:
        raise AuthError("ADMIN_USER_BANNED", 403)

    auth = build(
        Plugin(
            id="admin",
            principal_checks=(banned,),
            error_codes={"ADMIN_USER_BANNED": (403, "Banned")},
        )
    )
    async with make_client(auth) as client:
        await sign_in(client)
        response = await client.get("/whoami")
    assert response.json()["error"]["code"] == "ADMIN_USER_BANNED"


async def test_check_principal_runs_the_checks_outside_the_pipeline() -> None:
    # CCR 015: a server call that accepts a credential itself runs the same checks.
    from gotauth.contracts import AuthError, Endpoint, StatusOut

    checked: list[str | None] = []

    async def banned(ctx: Any, principal: Principal) -> None:
        checked.append(principal.user_id)
        if principal.user_id == "usr_banned":
            raise AuthError("ADMIN_USER_BANNED", 403)

    async def accept(ctx: EndpointContext, _: None) -> StatusOut:
        for user_id in ("usr_ok", "usr_banned"):
            principal = Principal(via="api_key", credential_id="key_1", user_id=user_id)
            await ctx.auth.check_principal(ctx, principal)
        return StatusOut(status="accepted")

    auth = build(
        Plugin(
            id="admin",
            endpoints=(
                Endpoint(
                    "accept",
                    "POST",
                    "/accept",
                    accept,
                    output=StatusOut,
                    server_only=True,
                ),
            ),
            principal_checks=(banned,),
            error_codes={"ADMIN_USER_BANNED": (403, "Banned")},
        )
    )
    with pytest.raises(AuthError) as refused:
        await auth.api.call("accept")
    assert refused.value.code == "ADMIN_USER_BANNED"
    assert checked == ["usr_ok", "usr_banned"]


async def test_get_principal(auth: Any) -> None:
    async with make_client(auth) as client:
        await sign_in(client)
        cookies = dict(client.cookies)
    principal = await auth.get_principal({}, cookies)
    assert principal is not None
    assert principal.via == "session"
    assert await auth.get_principal({"x-api-key": "zzz_1"}, {}) is None


# ------------------------------------------------------------------ origin


async def test_cookie_post_needs_a_trusted_origin() -> None:
    auth = build(trusted_origins=["https://*.example.org"])
    async with make_client(auth) as client:
        await sign_in(client)
        missing = await client.post(
            "/session-echo", json={"name": "a"}, headers={"origin": ""}
        )
        wrong = await client.post(
            "/session-echo", json={"name": "a"}, headers={"origin": "https://evil.com"}
        )
        wildcard = await client.post(
            "/session-echo",
            json={"name": "a"},
            headers={"origin": "https://app.example.org"},
        )
        same = await client.post("/session-echo", json={"name": "a"})
    assert missing.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    assert wrong.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"
    assert wildcard.status_code == 200
    assert same.status_code == 200


async def test_bearer_requests_are_exempt_from_origin() -> None:
    auth = build(sessions={"expose_token": True})
    async with make_client(auth) as client:
        token = (await sign_in(client)).json()["token"]
        response = await client.post(
            "/session-echo",
            json={"name": "a"},
            headers={"origin": "https://evil.com", "authorization": f"Bearer {token}"},
        )
    assert response.status_code == 200


# ------------------------------------------------------------------ rate limits


async def test_endpoint_rule_allows_exactly_max(clock: Any) -> None:
    auth = build(clock=clock)
    async with make_client(auth) as client:
        codes = [
            (await client.post("/limited", json={"name": "a"})).status_code
            for _ in range(4)
        ]
        limited = await client.post("/limited", json={"name": "a"})
        clock.advance("61s")
        again = await client.post("/limited", json={"name": "a"})
    assert codes == [200, 200, 200, 429]
    assert 1 <= int(limited.headers["retry-after"]) <= 60
    assert again.status_code == 200


async def test_identifier_rule_counts_one_email_across_ips() -> None:
    from gotauth.contracts import RateLimitRule

    rule = RateLimitRule(
        path="/login", window="15m", max=2, key="identifier", identifier="email"
    )
    auth = build(rate_limit={"rules": [rule]})
    statuses = []
    for ip in ("1.1.1.1", "2.2.2.2", "3.3.3.3"):
        transport = httpx.ASGITransport(
            app=auth.asgi(), root_path="/api/auth", client=(ip, 1)
        )
        async with httpx.AsyncClient(
            transport=transport, base_url="http://localhost:8000/api/auth"
        ) as client:
            response = await client.post("/login", json={"email": "Ada@Example.com"})
            statuses.append(response.status_code)
    assert statuses == [200, 200, 429]


async def test_spoofed_forwarded_for_is_ignored() -> None:
    auth = build()
    statuses = []
    async with make_client(auth) as client:
        for index in range(4):
            response = await client.post(
                "/limited",
                json={"name": "a"},
                headers={"x-forwarded-for": f"9.9.9.{index}"},
            )
            statuses.append(response.status_code)
    assert statuses[-1] == 429


async def test_rate_limits_can_be_disabled() -> None:
    auth = build(rate_limit=False)
    async with make_client(auth) as client:
        codes = {
            (await client.post("/limited", json={"name": "a"})).status_code
            for _ in range(6)
        }
    assert codes == {200}


# ------------------------------------------------------------------ errors and events


async def test_unexpected_errors_are_500_without_details(auth: Any) -> None:
    async with make_client(auth) as client:
        response = await client.get("/boom")
    assert response.status_code == 500
    assert "secret detail" not in response.text


async def test_rollback_keeps_only_sign_in_failed(
    auth: Any, events: list[AuthEvent]
) -> None:
    async with make_client(auth) as client:
        response = await client.post("/fail", json={"name": "zed"})
    await auth.drain()
    assert response.status_code == 401
    assert [event.type for event in events] == ["sign_in.failed"]
    assert await auth.api.call("count_users") == {"users": 0}


async def test_events_after_commit_and_failing_on_event(clock: Any) -> None:
    async def explode(event: AuthEvent) -> None:
        raise RuntimeError("listener down")

    auth = build(clock=clock, on_event=explode)
    async with make_client(auth) as client:
        response = await client.post("/marker", json={"name": "m"})
    await auth.drain()
    assert response.status_code == 200


async def test_oauth_error_format(auth: Any) -> None:
    async with make_client(auth) as client:
        grant = await client.post("/token", data={"grant_type": "password"})
        invalid = await client.post("/token", data={})
        wrong_type = await client.post("/token", json={"grant_type": "x"})
    assert grant.status_code == 400
    assert grant.json() == {"error": "invalid_grant", "error_description": "bad grant"}
    assert invalid.json()["error"] == "invalid_request"
    assert wrong_type.json()["error"] == "invalid_request"


async def test_oauth_rate_limited_format() -> None:
    from gotauth.contracts import RateLimitRule

    rule = RateLimitRule(path="/token", window="60s", max=1, key="ip_path")
    auth = build(rate_limit={"rules": [rule]})
    async with make_client(auth) as client:
        await client.post("/token", data={"grant_type": "authorization_code"})
        limited = await client.post("/token", data={"grant_type": "authorization_code"})
    assert limited.status_code == 429
    assert limited.json()["error"] == "temporarily_unavailable"
    assert "retry-after" in limited.headers


# ------------------------------------------------------------------ challenge


async def test_challenge_flow() -> None:
    auth = build(two_factor_plugin())
    async with make_client(auth) as client:
        first = await client.post(
            "/login", json={"email": "a@b.c", "remember_me": False}
        )
        assert first.json()["challenge"]["type"] == "two_factor"
        assert (await client.get("/whoami")).status_code == 401
        wrong = await client.post("/finish", json={"factor": "backup_code"})
        assert wrong.json()["error"]["code"] == "FORBIDDEN"
        done = await client.post("/finish", json={"factor": "totp"})
        assert done.status_code == 200
        assert done.json()["session"]["remember_me"] is False
        assert (await client.get("/whoami")).status_code == 200
        again = await client.post("/finish", json={"factor": "totp"})
    assert again.json()["error"]["code"] == "TOKEN_INVALID"


async def test_tampered_and_expired_challenge(clock: Any) -> None:
    auth = build(two_factor_plugin(), clock=clock)
    async with make_client(auth) as client:
        await client.post("/login", json={"email": "a@b.c"})
        name = auth.cookie_name("challenge")
        good = client.cookies[name]
        client.cookies.clear()
        client.cookies.set(name, good[:-2] + "xx")
        tampered = await client.post("/finish", json={"factor": "totp"})
        client.cookies.clear()
        client.cookies.set(name, good)
        clock.advance("11m")
        expired = await client.post("/finish", json={"factor": "totp"})
    assert tampered.json()["error"]["code"] == "TOKEN_INVALID"
    assert expired.json()["error"]["code"] == "TOKEN_EXPIRED"


async def test_raising_interceptor_blocks_sign_in() -> None:
    from gotauth.contracts import AuthError

    async def block(ctx: Any, user: Any, method: str) -> None:
        raise AuthError("FORBIDDEN", 403)

    auth = build(Plugin(id="block", sign_in_interceptors=(block,)))
    async with make_client(auth) as client:
        response = await client.post("/login", json={"email": "a@b.c"})
    assert response.status_code == 403


# ------------------------------------------------------------------ well-known


async def test_well_known_substitutes_base_path(auth: Any) -> None:
    transport = httpx.ASGITransport(app=auth.well_known())
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:8000"
    ) as client:
        found = await client.get("/.well-known/test/api/auth")
        missing = await client.get("/.well-known/other")
    assert found.json() == {"issuer": "http://localhost:8000"}
    assert missing.status_code == 404


@pytest.mark.parametrize("path", ["/echo", "/whoami"])
async def test_unsafe_methods_on_get_routes_404(auth: Any, path: str) -> None:
    async with make_client(auth) as client:
        response = await client.patch(path, json={})
    assert response.status_code == 404
