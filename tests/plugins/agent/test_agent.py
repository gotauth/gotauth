"""Agent identities (work package O3): ownership, agent keys and clients, the act
claim, revocation of everything an agent holds, and re-enabling."""

from __future__ import annotations

from typing import Any

import jwt
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import ConfigError
from gotauth.contracts.oauth import PLUGIN_ENDPOINTS
from gotauth.plugins.agent import agent
from gotauth.plugins.api_key import api_key
from gotauth.plugins.oauth_provider import oauth_provider
from gotauth.testing import make_auth, stub_plugin

from .conftest import REDIRECT, SCOPES, world


def test_endpoints_match_the_contract_table() -> None:
    specs = {s.id: s for s in PLUGIN_ENDPOINTS if s.owner == "O3"}
    endpoints = {e.id: e for e in agent().endpoints}
    assert set(endpoints) == set(specs)
    for id, spec in specs.items():
        endpoint = endpoints[id]
        assert endpoint.server_only == spec.server_only, id
        if not spec.server_only:
            assert (endpoint.method, endpoint.path, endpoint.auth) == (
                spec.method,
                spec.path,
                spec.auth,
            ), id
    assert endpoints["revoke_agent"].fresh_session


async def test_create_list_get_and_update() -> None:
    w = await world()
    created = await w.new_agent("Helper")
    assert created["id"].startswith("agt_")
    assert (created["owner_type"], created["owner_id"]) == ("user", w.ada_id)
    assert created["created_by"] == w.ada_id and created["disabled_at"] is None
    listed = (await w.ada.get("/agents")).json()["agents"]
    assert [a["id"] for a in listed] == [created["id"]]
    assert (await w.bob.get("/agents")).json() == {"agents": []}
    got = await w.ada.get(f"/agents/{created['id']}")
    assert got.json()["name"] == "Helper"
    renamed = await w.ada.patch(
        f"/agents/{created['id']}", json={"name": "Researcher", "metadata": {"a": 1}}
    )
    assert renamed.json()["name"] == "Researcher"
    assert renamed.json()["metadata"] == {"a": 1}


async def test_non_owners_get_not_found() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    for method, path, body in (
        ("GET", f"/agents/{agent_id}", None),
        ("PATCH", f"/agents/{agent_id}", {"enabled": True}),
        ("POST", f"/agents/{agent_id}/revoke", None),
        ("POST", f"/agents/{agent_id}/api-keys", {"name": "k", "scopes": []}),
        ("GET", f"/agents/{agent_id}/api-keys", None),
        ("POST", f"/agents/{agent_id}/clients", {"client_id": "x"}),
    ):
        response = await w.bob.request(method, path, json=body)
        assert response.status_code == 404, (method, path, response.text)


async def test_an_agent_key_acts_for_the_owner_as_the_agent() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    key = await w.agent_key(agent_id)
    principal = await w.key_principal(key)
    assert principal is not None
    assert (principal.agent_id, principal.user_id) == (agent_id, w.ada_id)
    listed = (await w.ada.get(f"/agents/{agent_id}/api-keys")).json()["api_keys"]
    assert [k["owner_id"] for k in listed] == [agent_id]
    assert "key" not in listed[0] and "key_hash" not in listed[0]


async def test_a_linked_client_s_tokens_name_the_agent() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    client_id = await w.client()
    linked = await w.ada.post(
        f"/agents/{agent_id}/clients", json={"client_id": client_id}
    )
    assert linked.status_code == 200, linked.text
    tokens = await w.tokens(client_id)
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert claims["act"] == {"sub": agent_id}
    principal = await w.token_principal(tokens["access_token"])
    assert (principal.agent_id, principal.user_id) == (agent_id, w.ada_id)


async def test_linking_someone_else_s_or_a_linked_client_is_refused() -> None:
    w = await world()
    first = (await w.new_agent("one"))["id"]
    second = (await w.new_agent("two"))["id"]
    bobs = await w.client(owner=w.bob_id)
    other = await w.ada.post(f"/agents/{first}/clients", json={"client_id": bobs})
    assert other.status_code == 404
    mine = await w.client()
    assert (
        await w.ada.post(f"/agents/{first}/clients", json={"client_id": mine})
    ).status_code == 200
    again = await w.ada.post(f"/agents/{second}/clients", json={"client_id": mine})
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "AGENT_CLIENT_ALREADY_LINKED"


async def test_revoke_ends_everything_the_agent_holds_at_once() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    key = await w.agent_key(agent_id)
    client_id = await w.client()
    await w.ada.post(f"/agents/{agent_id}/clients", json={"client_id": client_id})
    tokens = await w.tokens(client_id)
    revoked = await w.ada.post(f"/agents/{agent_id}/revoke")
    assert revoked.status_code == 200, revoked.text
    body = revoked.json()
    assert body["agent"]["disabled_at"] is not None
    assert (body["api_keys"], body["oauth_clients"]) == (1, 1)
    assert body["oauth_tokens"] >= 1
    # No clock advance: every credential is dead now.
    assert await w.key_principal(key) is None
    assert await w.token_principal(tokens["access_token"]) is None
    refresh = await w.ada.post(
        "/oauth2/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": tokens["refresh_token"],
            "client_id": client_id,
        },
    )
    # The disabled client is refused first; either way the refresh token is dead.
    assert refresh.json()["error"] in ("invalid_client", "invalid_grant")
    authorize = await w.ada.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT,
            "scope": "openid",
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    assert authorize.status_code == 400  # a disabled client: the error page
    disabled = await w.ada.post(
        f"/agents/{agent_id}/api-keys", json={"name": "k", "scopes": []}
    )
    assert disabled.json()["error"]["code"] == "AGENT_DISABLED"
    # Idempotent.
    second = (await w.ada.post(f"/agents/{agent_id}/revoke")).json()
    assert (second["api_keys"], second["oauth_clients"], second["oauth_tokens"]) == (
        0,
        0,
        0,
    )


async def test_re_enabling_keeps_old_keys_dead() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    old = await w.agent_key(agent_id)
    refused = await w.ada.patch(f"/agents/{agent_id}", json={"enabled": False})
    assert refused.status_code == 400  # disabling goes through revoke (fresh)
    disabled = await w.ada.post(f"/agents/{agent_id}/revoke")
    assert disabled.json()["agent"]["disabled_at"] is not None
    enabled = await w.ada.patch(f"/agents/{agent_id}", json={"enabled": True})
    assert enabled.json()["disabled_at"] is None
    assert await w.key_principal(old) is None
    assert await w.key_principal(await w.agent_key(agent_id)) is not None


async def test_deleting_the_owner_deletes_the_agents() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    key = await w.agent_key(agent_id)
    client_id = await w.client()
    await w.ada.post(f"/agents/{agent_id}/clients", json={"client_id": client_id})
    tokens = await w.tokens(client_id)
    await w.auth.delete_user(None, w.ada_id)
    assert await w.key_principal(key) is None
    assert await w.token_principal(tokens["access_token"]) is None
    assert await w.auth.database.find_many("agent", []) == []


async def test_events_name_the_agent_and_never_a_secret() -> None:
    events: list[Any] = []

    async def record(event: Any) -> None:
        events.append(event)

    w = await world(on_event=record)
    agent_id = (await w.new_agent())["id"]
    key = await w.agent_key(agent_id)
    await w.ada.post(f"/agents/{agent_id}/revoke")
    await w.auth.drain()
    created = next(e for e in events if e.type == "agent.created")
    revoked = next(e for e in events if e.type == "agent.revoked")
    assert created.data["agent_id"] == agent_id
    assert revoked.data["api_keys"] == 1
    assert all(key not in repr(e.data) for e in events)


async def test_organization_agents_need_the_organization_plugin() -> None:
    w = await world()
    response = await w.ada.post(
        "/agents", json={"name": "Team bot", "organization_id": "org_1"}
    )
    assert response.status_code == 403


async def test_the_api_key_plugin_is_required() -> None:
    auth = make_auth(plugins=[agent()])
    with pytest.raises(ConfigError, match="api_key"):
        await auth.get_principal({}, {})  # plugins initialize before first use


async def test_linking_needs_the_oauth_server() -> None:
    w = await world(plugins=[api_key(allowed_scopes=["projects:read"]), agent()])
    agent_id = (await w.new_agent())["id"]
    response = await w.ada.post(f"/agents/{agent_id}/clients", json={"client_id": "c"})
    assert response.status_code == 404


# ---------------------------------------------------------------- property


OPS = st.lists(st.sampled_from(["key", "link", "revoke", "enable"]), max_size=8)


@settings(
    max_examples=15,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(ops=OPS)
async def test_nothing_issued_before_the_last_revoke_survives(ops: list[str]) -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    keys: list[str] = []
    tokens: list[str] = []
    keys_before: list[str] = []
    tokens_before: list[str] = []
    enabled = True
    for op in [*ops, "revoke"]:
        if op == "revoke":
            await w.ada.post(f"/agents/{agent_id}/revoke")
            enabled = False
            keys_before, tokens_before = list(keys), list(tokens)
        elif op == "enable":
            await w.ada.patch(f"/agents/{agent_id}", json={"enabled": True})
            enabled = True
        elif op == "key" and enabled:
            keys.append(await w.agent_key(agent_id))
        elif op == "link" and enabled:
            client_id = await w.client()
            linked = await w.ada.post(
                f"/agents/{agent_id}/clients", json={"client_id": client_id}
            )
            assert linked.status_code == 200
            tokens.append((await w.tokens(client_id))["access_token"])
    for key in keys_before:
        assert await w.key_principal(key) is None
    for token in tokens_before:
        assert await w.token_principal(token) is None


async def test_client_credentials_of_a_user_s_agent_act_for_that_user() -> None:
    # CONTRACTS 12.1: user_id is the owning user of the client's agent.
    w = await world()
    agent_id = (await w.new_agent())["id"]
    created = await w.auth.api.call(
        "create_oauth_client",
        body={
            "name": "Agent worker",
            "type": "confidential",
            "redirect_uris": [REDIRECT],
            "grant_types": ["client_credentials"],
            "scopes": ["projects:read"],
            "owner_user_id": w.ada_id,
        },
    )
    client_id = created.client.client_id
    await w.ada.post(f"/agents/{agent_id}/clients", json={"client_id": client_id})
    response = await w.ada.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client_id,
            "client_secret": created.client_secret,
            "scope": "projects:read",
        },
    )
    assert response.status_code == 200, response.text
    principal = await w.token_principal(response.json()["access_token"])
    assert (principal.agent_id, principal.user_id) == (agent_id, w.ada_id)


# ---------------------------------------------------------------- review fixes


async def test_tokens_from_before_the_link_are_revoked_too() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    client_id = await w.client()
    before = await w.tokens(client_id)  # no act claim, no agent id on the grant
    await w.ada.post(f"/agents/{agent_id}/clients", json={"client_id": client_id})
    revoked = (await w.ada.post(f"/agents/{agent_id}/revoke")).json()
    assert revoked["oauth_tokens"] >= 1
    assert await w.token_principal(before["access_token"]) is None
    # Even if the app enables the client again, the old grant stays dead.
    await w.auth.api.call(
        "update_oauth_client", body={"client_id": client_id, "disabled": False}
    )
    assert await w.token_principal(before["access_token"]) is None


async def test_a_disabled_client_is_not_relinked_silently() -> None:
    w = await world()
    agent_id = (await w.new_agent())["id"]
    client_id = await w.client()
    await w.ada.post(f"/agents/{agent_id}/clients", json={"client_id": client_id})
    await w.ada.post(f"/agents/{agent_id}/revoke")
    await w.ada.patch(f"/agents/{agent_id}", json={"enabled": True})
    again = await w.ada.post(
        f"/agents/{agent_id}/clients", json={"client_id": client_id}
    )
    assert again.status_code == 409
    assert again.json()["error"]["code"] == "AGENT_CLIENT_DISABLED"


async def test_revoke_agents_counts_only_what_it_revoked() -> None:
    w = await world()
    await w.new_agent("one")
    await w.new_agent("two")
    body = {"owner_type": "user", "owner_id": w.ada_id}
    first = await w.auth.api.call("revoke_agents", body=body)
    second = await w.auth.api.call("revoke_agents", body=body)
    assert (first.revoked, second.revoked) == (2, 0)


async def test_organization_agents_follow_the_organization_s_permissions() -> None:
    granted: dict[str, set[str]] = {"agent": set(), "api_key": set()}
    asked: list[dict[str, Any]] = []

    async def has_permission(
        permissions: dict[str, list[str]], organization_id: str | None = None
    ) -> dict[str, bool]:
        asked.append(permissions)
        ok = all(
            set(acts) <= granted.get(res, set()) for res, acts in permissions.items()
        )
        return {"success": ok}

    org = stub_plugin("organization", {"has_permission": has_permission})
    w = await world(
        plugins=[
            api_key(allowed_scopes=["projects:read"]),
            oauth_provider(scopes=SCOPES),
            agent(),
            org,
        ]
    )
    body = {"name": "Team bot", "organization_id": "org_1"}
    assert (await w.ada.post("/agents", json=body)).status_code == 403
    granted["agent"] = {"create", "read", "update"}
    created = await w.ada.post("/agents", json=body)
    assert created.status_code == 200, created.text
    agent_id = created.json()["id"]
    assert created.json()["owner_type"] == "organization"
    assert (await w.ada.get(f"/agents/{agent_id}")).status_code == 200
    # A key acts for the organization: P1's api_key create right is needed too.
    key = {"name": "k", "scopes": ["projects:read"]}
    assert (
        await w.ada.post(f"/agents/{agent_id}/api-keys", json=key)
    ).status_code == 404
    granted["api_key"] = {"create"}
    minted = await w.ada.post(f"/agents/{agent_id}/api-keys", json=key)
    assert minted.status_code == 200, minted.text
    principal = await w.key_principal(minted.json()["key"])
    assert (principal.agent_id, principal.user_id) == (agent_id, None)
    assert principal.organization_id == "org_1"
    # Without the read right the agent does not exist for the caller.
    granted["agent"] = set()
    assert (await w.ada.get(f"/agents/{agent_id}")).status_code == 404
    assert {"agent": ["update"], "api_key": ["create"]} in asked
