"""API keys over HTTP on a real GotAuth, plus resolver properties."""

from __future__ import annotations

import json
import re
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import Endpoint, EndpointContext, Plugin, Where
from gotauth.contracts.oauth import PLUGIN_ENDPOINTS
from gotauth.plugins.api_key import api_key
from gotauth.sessions import memory_secondary_storage
from gotauth.testing import (
    fake_clock,
    make_auth,
    make_client,
    make_context,
    stub_plugin,
)

PASSWORD = "correct horse battery"


async def whoami(ctx: EndpointContext, _: None) -> dict[str, Any]:  # Any: JSON
    principal = ctx.principal
    assert principal is not None
    return {
        "via": principal.via,
        "user_id": principal.user_id,
        "organization_id": principal.organization_id,
        "agent_id": principal.agent_id,
        "scopes": sorted(principal.scopes) if principal.scopes is not None else None,
    }


APP = Plugin(
    id="app",
    endpoints=(
        Endpoint(
            "read_projects",
            "GET",
            "/projects",
            whoami,
            auth="principal",
            scopes=("projects:read",),
        ),
        Endpoint("whoami", "GET", "/whoami", whoami, auth="principal"),
    ),
)

SCOPES = ["projects:read", "projects:write"]


def build(*extra: Plugin, **overrides: Any) -> Any:  # Any: GotAuth
    options: dict[str, Any] = {
        "email_password": {"require_email_verification": False},
        "plugins": [
            api_key(allowed_scopes=SCOPES, **overrides.pop("keys", {})),
            APP,
            *extra,
        ],
    }
    options.update(overrides)
    return make_auth(**options)


async def sign_up(client: Any, email: str = "ada@example.com") -> None:
    response = await client.post(
        "/sign-up/email", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text


async def create_key(client: Any, **body: Any) -> dict[str, Any]:  # Any: JSON
    body.setdefault("name", "ci")
    body.setdefault("scopes", ["projects:read"])
    response = await client.post("/api-keys", json=body)
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


def bearer(key: str) -> dict[str, str]:
    return {"authorization": f"Bearer {key}"}


# ---------------------------------------------------------------- contract


def test_endpoints_match_the_contract_table() -> None:
    specs = {spec.id: spec for spec in PLUGIN_ENDPOINTS if spec.owner == "P1"}
    endpoints = {e.id: e for e in api_key().endpoints}
    assert set(endpoints) == set(specs)
    for id, spec in specs.items():
        endpoint = endpoints[id]
        assert endpoint.server_only == spec.server_only
        if not spec.server_only:
            assert (endpoint.method, endpoint.path, endpoint.auth) == (
                spec.method,
                spec.path,
                spec.auth,
            )


# ---------------------------------------------------------------- create and use


async def test_key_is_shown_once_and_never_stored() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        created = await create_key(client)
        key = created["key"]
        assert re.fullmatch(r"gak_[A-Za-z0-9_-]{43}", key)
        assert created["api_key"]["start"] == key[4:10]
        assert "key_hash" not in created["api_key"]
        listed = (await client.get("/api-keys")).text
        updated = (
            await client.patch(
                f"/api-keys/{created['api_key']['id']}", json={"name": "x"}
            )
        ).text
    assert key not in listed and key not in updated
    dump = {m: await auth.database.find_many(m) for m in auth.schema}
    assert key not in json.dumps(dump, default=str)
    row = await auth.database.find_one(
        "api_key", [Where("id", created["api_key"]["id"])]
    )
    assert row["key_hash"] == auth.crypto.hash_token(key)


async def test_bearer_and_x_api_key_and_scopes() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        reader = (await create_key(client, scopes=["projects:read"]))["key"]
        writer = (await create_key(client, scopes=["projects:write"]))["key"]
        client.cookies.clear()
        ok = await client.get("/projects", headers=bearer(reader))
        assert ok.status_code == 200
        body = ok.json()
        assert body["via"] == "api_key" and body["scopes"] == ["projects:read"]
        assert (
            await client.get("/projects", headers={"x-api-key": reader})
        ).status_code == 200
        denied = await client.get("/projects", headers=bearer(writer))
        assert denied.status_code == 403
        assert denied.json()["error"]["code"] == "INSUFFICIENT_SCOPE"
        # A key never gets session rights.
        assert (await client.get("/sessions", headers=bearer(reader))).status_code in (
            401,
            403,
        )
        assert (
            await client.post("/api-keys", json={"name": "x"}, headers=bearer(reader))
        ).status_code in (401, 403)


async def test_unknown_and_malformed_keys() -> None:
    auth = build()
    async with make_client(auth) as client:
        for value in ("gak_" + "A" * 43, "gak_short", "gak_" + "!" * 43):
            response = await client.get("/whoami", headers=bearer(value))
            assert response.status_code == 401
            assert response.json()["error"]["code"] == "API_KEY_INVALID"


async def test_delete_disable_and_expiry_apply_at_once() -> None:
    clock = fake_clock()
    auth = build(clock=clock)
    async with make_client(auth) as client:
        await sign_up(client)
        one = await create_key(client)
        two = await create_key(client)
        three = await create_key(client, expires_in="1h")
        await client.delete(f"/api-keys/{one['api_key']['id']}")
        await client.patch(f"/api-keys/{two['api_key']['id']}", json={"enabled": False})
        clock.advance("1h")
        client.cookies.clear()
        codes = [
            (await client.get("/whoami", headers=bearer(k["key"]))).json()["error"][
                "code"
            ]
            for k in (one, two, three)
        ]
    assert codes == ["API_KEY_INVALID", "API_KEY_DISABLED", "API_KEY_EXPIRED"]


async def test_other_users_keys_are_not_found() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client, "bob@example.com")
        bobs = (await create_key(client))["api_key"]["id"]
        client.cookies.clear()
        await sign_up(client)
        assert (
            await client.patch(f"/api-keys/{bobs}", json={"name": "x"})
        ).status_code == 404
        assert (await client.delete(f"/api-keys/{bobs}")).status_code == 404
        assert (await client.get("/api-keys")).json() == {"api_keys": []}


async def test_scope_outside_allowed_is_invalid() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api-keys", json={"name": "x", "scopes": ["admin"]}
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "INVALID_REQUEST"


async def test_expiry_limits() -> None:
    auth = build(keys={"default_expires_in": "30d", "max_expires_in": "90d"})
    async with make_client(auth) as client:
        await sign_up(client)
        default = (await create_key(client))["api_key"]
        assert default["expires_at"] is not None
        too_long = await client.post(
            "/api-keys", json={"name": "x", "expires_in": "365d"}
        )
        assert too_long.status_code == 400


@pytest.mark.parametrize("expires_in", ["soon", "12x", "", "1.5d"])
async def test_an_unparseable_expiry_is_invalid_request(expires_in: str) -> None:
    # Found by the security fuzz test: this used to be a 500 (issue #21).
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api-keys", json={"name": "x", "expires_in": expires_in}
        )
    assert response.status_code == 400
    error = response.json()["error"]
    assert error["code"] == "INVALID_REQUEST"
    assert ["expires_in"] in [e["loc"] for e in error["details"]["errors"]]
    assert expires_in not in response.text or not expires_in  # no input echoed


# ---------------------------------------------------------------- organizations


async def test_org_key_without_p5_is_forbidden() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        response = await client.post(
            "/api-keys", json={"name": "x", "organization_id": "org_1"}
        )
        assert response.status_code == 403


async def test_org_key_with_permission() -> None:
    async def has_permission(**body: Any) -> dict[str, bool]:
        return {"success": body.get("organization_id") == "org_1"}

    orgs = stub_plugin("organization", {"has_permission": has_permission})
    auth = build(orgs)
    async with make_client(auth) as client:
        await sign_up(client)
        me = (await client.get("/session")).json()["user"]["id"]
        created = await create_key(client, organization_id="org_1")
        assert created["api_key"]["user_id"] is None
        assert created["api_key"]["created_by"] == me
        assert created["api_key"]["owner_type"] == "organization"
        denied = await client.post(
            "/api-keys", json={"name": "x", "organization_id": "org_2"}
        )
        assert denied.status_code == 403
        listed = await client.get("/api-keys", params={"organization_id": "org_1"})
        assert len(listed.json()["api_keys"]) == 1
        client.cookies.clear()
        principal = (await client.get("/whoami", headers=bearer(created["key"]))).json()
    assert principal["user_id"] is None and principal["organization_id"] == "org_1"
    assert orgs.calls_to("has_permission")[0] == {
        "organization_id": "org_1",
        "permissions": {"api_key": ["create"]},
    }


# ---------------------------------------------------------------- usage tracking


async def test_last_used_is_written_once_a_minute() -> None:
    clock = fake_clock()
    auth = build(clock=clock)
    async with make_client(auth) as client:
        await sign_up(client)
        created = await create_key(client)
        client.cookies.clear()
        writes: list[str] = []
        original = auth.database.update

        async def counting(model: str, where: Any, data: Any) -> Any:
            if model == "api_key" and "last_used_at" in data:
                writes.append(model)
            return await original(model, where, data)

        auth.database.update = counting
        for _ in range(10):
            await client.get("/whoami", headers=bearer(created["key"]))
        assert len(writes) == 1
        clock.advance("61s")
        await client.get("/whoami", headers=bearer(created["key"]))
        assert len(writes) == 2


@pytest.mark.parametrize("secondary", [False, True])
async def test_per_key_rate_limit(secondary: bool) -> None:
    clock = fake_clock()
    extra: dict[str, Any] = (
        {"secondary_storage": memory_secondary_storage(clock=clock)}
        if secondary
        else {}
    )
    auth = build(clock=clock, **extra)
    async with make_client(auth) as client:
        await sign_up(client)
        created = await create_key(client, rate_limit_max=3, rate_limit_window=60)
        client.cookies.clear()
        statuses = [
            (await client.get("/whoami", headers=bearer(created["key"]))).status_code
            for _ in range(4)
        ]
        limited = await client.get("/whoami", headers=bearer(created["key"]))
        assert statuses == [200, 200, 200, 429]
        assert limited.json()["error"]["code"] == "API_KEY_RATE_LIMITED"
        assert 1 <= int(limited.headers["retry-after"]) <= 60
        clock.advance("60s")
        assert (
            await client.get("/whoami", headers=bearer(created["key"]))
        ).status_code == 200


# ---------------------------------------------------------------- server-only calls


async def test_issue_verify_and_revoke() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        user_id = (await client.get("/session")).json()["user"]["id"]
    issued = await auth.api.call(
        "issue_api_key",
        body={
            "owner_type": "user",
            "owner_id": user_id,
            "user_id": user_id,
            "name": "x",
            "scopes": ["projects:read"],
        },
    )
    key = issued.key
    ok = await auth.api.call(
        "verify_api_key", body={"key": key, "scopes": ["projects:read"]}
    )
    assert ok.valid and ok.principal.credential_id == issued.api_key.id
    missing = await auth.api.call(
        "verify_api_key", body={"key": key, "scopes": ["projects:write"]}
    )
    assert (missing.valid, missing.code) == (False, "INSUFFICIENT_SCOPE")
    revoked = await auth.api.call(
        "revoke_api_keys", body={"owner_type": "user", "owner_id": user_id}
    )
    assert revoked.revoked == 1
    after = await auth.api.call("verify_api_key", body={"key": key})
    assert (after.valid, after.code) == (False, "API_KEY_DISABLED")


async def test_agent_keys_carry_the_agent() -> None:
    from gotauth.contracts.oauth import AGENT_MODEL

    agents = Plugin(id="agent", schema={"agent": AGENT_MODEL})
    auth = build(agents)
    now = auth.clock.now()
    await auth.database.create(
        "agent",
        {
            "id": "agt_1",
            "name": "bot",
            "owner_type": "organization",
            "owner_id": "org_9",
            "created_at": now,
        },
    )
    issued = await auth.api.call(
        "issue_api_key",
        body={"owner_type": "agent", "owner_id": "agt_1", "name": "bot", "scopes": []},
    )
    result = await auth.api.call("verify_api_key", body={"key": issued.key})
    assert result.principal.agent_id == "agt_1"
    assert result.principal.organization_id == "org_9"
    assert result.principal.user_id is None
    await auth.database.update("agent", [Where("id", "agt_1")], {"disabled_at": now})
    disabled = await auth.api.call("verify_api_key", body={"key": issued.key})
    assert disabled.code == "API_KEY_DISABLED"


async def test_deleting_the_user_removes_their_keys() -> None:
    auth = build()
    async with make_client(auth) as client:
        await sign_up(client)
        await create_key(client)
        user_id = (await client.get("/session")).json()["user"]["id"]
    await auth.delete_user(None, user_id)
    assert await auth.database.count("api_key") == 0


async def test_events_never_contain_keys() -> None:
    seen: list[Any] = []

    async def on_event(event: Any) -> None:
        seen.append(event)

    auth = build(on_event=on_event)
    async with make_client(auth) as client:
        await sign_up(client)
        created = await create_key(client)
        await client.delete(f"/api-keys/{created['api_key']['id']}")
    await auth.drain()
    types = [event.type for event in seen]
    assert "api_key.created" in types and "api_key.revoked" in types
    assert created["key"] not in repr([event.data for event in seen])


class SpyCrypto:
    """Records ``equal`` calls and delegates everything else."""

    def __init__(self, inner: Any) -> None:
        self._inner = inner
        self.compared: list[tuple[Any, Any]] = []

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    def equal(self, a: Any, b: Any) -> bool:
        self.compared.append((a, b))
        return bool(self._inner.equal(a, b))


async def test_hash_comparison_uses_crypto_equal() -> None:
    plugin = api_key()
    spy = SpyCrypto(make_context().crypto)
    ctx = make_context(plugins=(plugin,), crypto=spy)  # type: ignore[arg-type]
    issued = await ctx.auth.api.call(
        "issue_api_key",
        body={"owner_type": "user", "owner_id": "u", "name": "x", "scopes": []},
        ctx=ctx,
    )
    principal = await plugin.principal_resolvers[0](ctx, issued.key)
    assert principal is not None
    expected = spy.hash_token(issued.key)
    assert (expected, expected) in spy.compared


# ---------------------------------------------------------------- properties


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(other=st.text(min_size=1, max_size=60))
async def test_keys_resolve_only_to_themselves(other: str) -> None:
    auth = build()
    issued = await auth.api.call(
        "issue_api_key",
        body={"owner_type": "user", "owner_id": "u", "name": "x", "scopes": []},
    )
    key = issued.key
    assert re.fullmatch(r"gak_[A-Za-z0-9_-]{43}", key)
    assert issued.api_key.start == key[4:10]
    mine = await auth.api.call("verify_api_key", body={"key": key})
    assert mine.valid and mine.principal.credential_id == issued.api_key.id
    if other != key:
        result = await auth.api.call("verify_api_key", body={"key": "gak_" + other})
        assert not result.valid


async def test_sqlite_never_stores_the_key_and_cascades() -> None:
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import StaticPool

    from gotauth.storage.sqlalchemy import create_missing, sqlalchemy_adapter

    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    auth = build(database=sqlalchemy_adapter(engine))
    await create_missing(
        engine, auth.schema, table_prefix=auth.config.advanced.table_prefix
    )
    async with make_client(auth) as client:
        await sign_up(client)
        created = await create_key(client)
        user_id = (await client.get("/session")).json()["user"]["id"]
    dump = {m: await auth.database.find_many(m) for m in auth.schema}
    assert created["key"] not in json.dumps(dump, default=str)
    await auth.delete_user(None, user_id)
    assert await auth.database.count("api_key") == 0
    await engine.dispose()


# ---------------------------------------------------------------- review fixes


async def test_rate_limit_windows_do_not_interfere() -> None:
    clock = fake_clock()
    auth = build(clock=clock)
    async with make_client(auth) as client:
        await sign_up(client)
        hourly = await create_key(client, rate_limit_max=2, rate_limit_window=3600)
        minute = await create_key(client, rate_limit_max=100, rate_limit_window=60)
        client.cookies.clear()
        for _ in range(2):
            assert (
                await client.get("/whoami", headers=bearer(hourly["key"]))
            ).status_code == 200
        clock.advance("120s")
        await client.get("/whoami", headers=bearer(minute["key"]))  # sweeps old windows
        assert (
            await client.get("/whoami", headers=bearer(hourly["key"]))
        ).status_code == 429


async def test_default_window_and_lonely_window() -> None:
    auth = build(keys={"rate_limit": (10, 3600)})
    async with make_client(auth) as client:
        await sign_up(client)
        created = await create_key(client, rate_limit_max=5)
        assert created["api_key"]["rate_limit_window"] == 3600
        lonely = await client.post(
            "/api-keys", json={"name": "x", "rate_limit_window": 60}
        )
        assert lonely.status_code == 400


async def test_update_respects_the_maximum_and_needs_a_time_zone() -> None:
    auth = build(keys={"max_expires_in": "30d"})
    async with make_client(auth) as client:
        await sign_up(client)
        key_id = (await create_key(client))["api_key"]["id"]
        for value in (None, "2099-01-01T00:00:00+00:00"):
            response = await client.patch(
                f"/api-keys/{key_id}", json={"expires_at": value}
            )
            assert response.status_code == 400, value
        naive = await client.patch(
            f"/api-keys/{key_id}", json={"expires_at": "2026-01-02T00:00:00"}
        )
        assert naive.status_code == 400
        ok = await client.patch(
            f"/api-keys/{key_id}", json={"expires_at": "2026-01-02T00:00:00+00:00"}
        )
        assert ok.status_code == 200
