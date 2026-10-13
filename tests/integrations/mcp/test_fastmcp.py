"""FastMCP with GotAuth in the same process: challenges, tool scopes, revocation and
the access a tool sees (work package O2)."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest
from fastmcp import FastMCP
from fastmcp.server.auth import require_scopes

from gotauth.contracts import ConfigError
from gotauth.integrations.mcp import (
    current_access,
    fastmcp_auth,
    protected_resource_metadata,
)

from .conftest import (
    ISSUER,
    METADATA,
    OTHER,
    RESOURCE,
    Issuer,
    call,
    issuer,
    mcp_client,
    post,
)

MISSING = f'Bearer resource_metadata="{METADATA}", scope="projects:read"'
INVALID = (
    f'Bearer error="invalid_token", resource_metadata="{METADATA}", '
    'scope="projects:read"'
)
STEP_UP = (
    'Bearer error="insufficient_scope", scope="projects:read projects:write", '
    f'resource_metadata="{METADATA}"'
)


def server(provider: Any) -> Any:  # Any: FastMCP's provider and app
    mcp = FastMCP("projects", auth=provider)

    @mcp.tool
    def list_projects() -> dict[str, Any]:
        access = current_access()
        assert access is not None
        return {
            "user_id": access.user_id,
            "agent_id": access.agent_id,
            "client_id": access.client_id,
            "scopes": sorted(access.scopes),
        }

    @mcp.tool(auth=require_scopes("projects:write"))
    def create_project(name: str) -> str:
        return f"created {name}"

    return mcp.http_app(path="/mcp", stateless_http=True, json_response=True)


def app_for(world: Issuer) -> Any:  # Any: a Starlette app
    return server(
        fastmcp_auth(
            world.auth, resource=RESOURCE, scopes=["projects:read", "offline_access"]
        )
    )


def result(response: Any) -> Any:  # Any: JSON
    assert response.status_code == 200, response.text
    body = response.json()
    assert "error" not in body, body
    return body["result"]["structuredContent"]


async def test_a_token_with_the_scope_calls_the_tool() -> None:
    world = await issuer()
    token = await world.token("projects:read")
    async with mcp_client(app_for(world)) as http:
        seen = result(await post(http, call("list_projects"), token))
    assert seen["user_id"].startswith("usr_")
    assert seen["client_id"] == world.client_id
    assert seen["agent_id"] is None
    assert seen["scopes"] == ["projects:read"]


async def test_no_token_is_a_401_naming_the_metadata() -> None:
    world = await issuer()
    async with mcp_client(app_for(world)) as http:
        response = await post(http, call("list_projects"))
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == MISSING


async def test_a_missing_tool_scope_is_a_403_step_up() -> None:
    world = await issuer()
    reader = await world.token("projects:read")
    writer = await world.token("projects:read projects:write")
    async with mcp_client(app_for(world)) as http:
        denied = await post(http, call("create_project", {"name": "x"}), reader)
        assert denied.status_code == 403
        assert denied.headers["www-authenticate"] == STEP_UP
        allowed = await post(http, call("create_project", {"name": "x"}), writer)
        assert result(allowed) == {"result": "created x"}


async def test_a_token_without_the_server_scope_is_a_403() -> None:
    world = await issuer()
    token = await world.token("openid")
    async with mcp_client(app_for(world)) as http:
        response = await post(http, call("list_projects"), token)
    assert response.status_code == 403
    assert response.headers["www-authenticate"] == (
        'Bearer error="insufficient_scope", scope="projects:read", '
        f'resource_metadata="{METADATA}"'
    )


def _tamper(token: str, **header: Any) -> str:  # Any: JSON
    head, body, signature = token.split(".")
    decoded = json.loads(base64.urlsafe_b64decode(head + "=="))
    decoded.update(header)
    new = base64.urlsafe_b64encode(json.dumps(decoded).encode()).rstrip(b"=").decode()
    return f"{new}.{body}.{signature}"


async def test_bad_tokens_are_401_invalid_token() -> None:
    world = await issuer()
    good = await world.token("projects:read")
    other = await world.token("projects:read", resource=OTHER)
    head, body, signature = good.split(".")
    bad = [
        "not-a-jwt",
        f"{head}.{body}.{signature[:-4]}AAAA",  # bad signature
        _tamper(good, alg="none"),
        _tamper(good, kid="unknown"),
        other,  # issued for another resource
    ]
    async with mcp_client(app_for(world)) as http:
        for token in bad:
            response = await post(http, call("list_projects"), token)
            assert response.status_code == 401, token
            assert response.headers["www-authenticate"] == INVALID
        world.clock.advance("11m")  # past the 10 minute access token lifetime
        expired = await post(http, call("list_projects"), good)
        assert expired.status_code == 401
        assert expired.headers["www-authenticate"] == INVALID


async def test_revocation_takes_effect_on_the_next_call() -> None:
    world = await issuer()
    token = await world.token("projects:read")
    async with mcp_client(app_for(world)) as http:
        assert (await post(http, call("list_projects"), token)).status_code == 200
        await world.auth.api.call(
            "revoke_oauth_tokens", body={"client_id": world.client_id}
        )
        response = await post(http, call("list_projects"), token)
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == INVALID


async def test_a_client_credentials_token_has_no_user() -> None:
    world = await issuer(confidential=True)
    tokens = await world.http.post(
        "/oauth2/token",
        data={
            "grant_type": "client_credentials",
            "client_id": world.client_id,
            "client_secret": world.client_secret,
            "scope": "projects:read",
            "resource": RESOURCE,
        },
    )
    assert tokens.status_code == 200, tokens.text
    async with mcp_client(app_for(world)) as http:
        seen = result(
            await post(http, call("list_projects"), tokens.json()["access_token"])
        )
    assert seen["user_id"] is None
    assert seen["client_id"] == world.client_id


async def test_the_resource_metadata_is_served_at_its_path_form() -> None:
    world = await issuer()
    async with mcp_client(app_for(world)) as http:
        response = await http.get("/.well-known/oauth-protected-resource/mcp")
    assert response.status_code == 200
    assert response.json() == {
        "resource": RESOURCE,
        "authorization_servers": [ISSUER],
        "scopes_supported": ["projects:read"],
        "bearer_methods_supported": ["header"],
    }


def test_metadata_never_lists_offline_access() -> None:
    document = protected_resource_metadata(
        resource=RESOURCE, issuer=ISSUER, scopes=["projects:read", "offline_access"]
    )
    assert document["scopes_supported"] == ["projects:read"]


async def test_configuration_errors() -> None:
    world = await issuer()
    with pytest.raises(ConfigError, match="exactly one"):
        fastmcp_auth(resource=RESOURCE)
    with pytest.raises(ConfigError, match="exactly one"):
        fastmcp_auth(world.auth, issuer=ISSUER, resource=RESOURCE)
    with pytest.raises(ConfigError, match="resource"):
        fastmcp_auth(world.auth, resource="/mcp")
    with pytest.raises(ConfigError, match="introspection_client"):
        fastmcp_auth(issuer=ISSUER, resource=RESOURCE, introspect=True)


# ---------------------------------------------------------------- review fixes


async def test_a_403_names_every_scope_the_call_needs() -> None:
    # The tool's own scope is granted, the server's is not: both are named.
    world = await issuer()
    token = await world.token("projects:write")
    async with mcp_client(app_for(world)) as http:
        response = await post(http, call("create_project", {"name": "x"}), token)
    assert response.status_code == 403
    assert response.headers["www-authenticate"] == STEP_UP


async def test_an_unreadable_body_is_refused_not_passed_on() -> None:
    world = await issuer()
    token = await world.token("projects:read")
    async with mcp_client(app_for(world)) as http:
        for body in (b"[" * 100_000, b'{"id": ' + b"9" * 5000 + b"}", b"{not json"):
            response = await http.post(
                "/mcp",
                content=body,
                headers={
                    "accept": "application/json, text/event-stream",
                    "content-type": "application/json",
                    "authorization": f"Bearer {token}",
                },
            )
            assert response.status_code == 400, body[:20]


def test_resources_that_can_never_match_are_refused() -> None:
    for resource in ("https://user@host.example/mcp", "https://host.example/a/../mcp"):
        with pytest.raises(ConfigError, match="resource"):
            fastmcp_auth(issuer=ISSUER, resource=resource)
