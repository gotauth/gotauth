"""The sessions plugin over HTTP, on a real GotAuth with the core plugins installed."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import BaseModel

from gotauth.contracts import (
    CORE_ENDPOINTS,
    Endpoint,
    EndpointContext,
    Plugin,
    User,
    Where,
)
from gotauth.sessions import sessions_plugin
from gotauth.testing import make_auth, make_client


class LoginIn(BaseModel):
    email: str


async def login(ctx: EndpointContext, data: LoginIn) -> Any:
    row = await ctx.adapter.find_one("user", [Where("email", data.email)])
    if row is None:
        user = await ctx.auth.create_user_record(ctx, {"email": data.email})
    else:
        user = User.model_validate(row)
    return await ctx.auth.complete_sign_in(ctx, user, method="password")


LOGIN = Plugin(
    id="login",
    endpoints=(Endpoint("login", "POST", "/login", login, input=LoginIn),),
)


def build(**overrides: Any) -> Any:
    options: dict[str, Any] = {
        "email_password": {"enabled": False},
        "plugins": [LOGIN],
        "sessions": {"expose_token": True},
    }
    options.update(overrides)
    return make_auth(**options)


async def sign_in(client: Any, email: str = "ada@example.com") -> str:
    response = await client.post("/login", json={"email": email})
    assert response.status_code == 200, response.text
    token = response.json()["token"]
    assert isinstance(token, str)
    return token


def bearer(token: str) -> dict[str, str]:
    return {"authorization": f"Bearer {token}"}


def test_endpoints_match_the_contract_table() -> None:
    specs = {spec.id: spec for spec in CORE_ENDPOINTS if spec.owner == "C3"}
    endpoints = {e.id: e for e in sessions_plugin().endpoints}
    assert set(endpoints) == set(specs)
    for id, spec in specs.items():
        endpoint = endpoints[id]
        assert (endpoint.method, endpoint.path, endpoint.auth) == (
            spec.method,
            spec.path,
            spec.auth,
        )
        assert endpoint.fresh_session == spec.fresh_session
        assert endpoint.server_only == spec.server_only
        models = [kind for kind in spec.output if not isinstance(kind, str)]
        assert endpoint.output in models


async def test_get_session_with_cookie_and_without() -> None:
    auth = build()
    async with make_client(auth) as client:
        assert (await client.get("/session")).json() is None
        await sign_in(client)
        body = (await client.get("/session")).json()
    assert body["user"]["email"] == "ada@example.com"
    assert "token_hash" not in body["session"]


async def test_get_session_with_bearer() -> None:
    auth = build()
    async with make_client(auth) as client:
        token = await sign_in(client)
        client.cookies.clear()
        body = (await client.get("/session", headers=bearer(token))).json()
    assert body["user"]["email"] == "ada@example.com"


async def test_bearer_can_be_turned_off() -> None:
    auth = build(sessions={"expose_token": True, "allow_bearer": False})
    async with make_client(auth) as client:
        token = await sign_in(client)
        client.cookies.clear()
        response = await client.get("/sessions", headers=bearer(token))
    assert response.status_code == 401


async def test_revoked_bearer_is_unauthenticated() -> None:
    auth = build()
    async with make_client(auth) as client:
        first = await sign_in(client)
        client.cookies.clear()
        second = await sign_in(client)
        client.cookies.clear()
        listed = (await client.get("/sessions", headers=bearer(second))).json()
        assert len(listed["sessions"]) == 2
        current = listed["current_session_id"]
        other = next(s["id"] for s in listed["sessions"] if s["id"] != current)
        response = await client.post(
            "/sessions/revoke", json={"session_id": other}, headers=bearer(second)
        )
        assert response.json() == {"status": "ok"}
        again = await client.get("/sessions", headers=bearer(first))
    assert again.status_code == 401
    assert again.json()["error"]["code"] == "UNAUTHENTICATED"


async def test_revoke_other_sessions_keeps_the_current_one() -> None:
    auth = build()
    async with make_client(auth) as client:
        old = await sign_in(client)
        client.cookies.clear()
        await sign_in(client)
        response = await client.post("/sessions/revoke-others")
        assert response.json() == {"status": "ok"}
        listed = (await client.get("/sessions")).json()
        assert [s["id"] for s in listed["sessions"]] == [listed["current_session_id"]]
        client.cookies.clear()
        assert (await client.get("/sessions", headers=bearer(old))).status_code == 401


async def test_another_users_session_is_not_found() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_in(client, "bob@example.com")
        bob_id = (await client.get("/session")).json()["session"]["id"]
        client.cookies.clear()
        await sign_in(client)
        response = await client.post("/sessions/revoke", json={"session_id": bob_id})
        assert response.status_code == 404
        assert response.json()["error"]["code"] == "NOT_FOUND"
        missing = await client.post("/sessions/revoke", json={"session_id": "ses_none"})
        assert missing.status_code == 404


async def test_revoking_the_current_session_clears_cookies() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_in(client)
        current = (await client.get("/session")).json()["session"]["id"]
        response = await client.post("/sessions/revoke", json={"session_id": current})
        assert response.status_code == 200
        cleared = response.headers.get_list("set-cookie")
        assert any(c.startswith("gotauth.session_token=;") for c in cleared)
        assert any(c.startswith("gotauth.session_data=;") for c in cleared)
        assert (await client.get("/session")).json() is None


@pytest.mark.parametrize("path", ["/sessions"])
async def test_session_endpoints_need_a_session(path: str) -> None:
    auth = build()
    async with make_client(auth) as client:
        response = await client.get(path)
    assert response.status_code == 401


async def test_secondary_storage_is_used_end_to_end() -> None:
    from gotauth.sessions import memory_secondary_storage

    storage = memory_secondary_storage()
    auth = build(secondary_storage=storage)
    async with make_client(auth) as client:
        token = await sign_in(client)
        assert (await client.get("/session")).json() is not None
    key = f"session:{auth.crypto.hash_token(token)}"
    assert await storage.get(key) is not None
