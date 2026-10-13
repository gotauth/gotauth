"""The official MCP SDK with ``mcp_sdk_auth``: the same challenges as FastMCP, tool
scopes through the guard, and the access a tool sees (work package O2)."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer

from gotauth.integrations.mcp import current_access, mcp_sdk_auth

from .conftest import ISSUER, METADATA, RESOURCE, Issuer, call, issuer, mcp_client, post

MISSING = f'Bearer resource_metadata="{METADATA}", scope="projects:read"'
INVALID = (
    f'Bearer error="invalid_token", resource_metadata="{METADATA}", '
    'scope="projects:read"'
)
STEP_UP = (
    'Bearer error="insufficient_scope", scope="projects:read projects:write", '
    f'resource_metadata="{METADATA}"'
)


def apps_for(world: Issuer) -> tuple[Any, Any]:  # Any: ASGI apps
    settings, verifier = mcp_sdk_auth(
        world.auth, resource=RESOURCE, scopes=["projects:read"]
    )
    assert str(settings.issuer_url) == ISSUER
    server = MCPServer("projects", auth=settings, token_verifier=verifier)

    @server.tool()
    def whoami() -> str:
        access = current_access()
        assert access is not None
        return f"{access.user_id} {access.client_id}"

    @server.tool()
    def create_project(name: str) -> str:
        return f"created {name}"

    inner = server.streamable_http_app(stateless_http=True, json_response=True)
    guarded = verifier.guard(inner, tool_scopes={"create_project": ["projects:write"]})
    return guarded, inner


def text(response: Any) -> str:  # Any: an httpx response
    assert response.status_code == 200, response.text
    body = response.json()
    assert "error" not in body, body
    return str(body["result"]["content"][0]["text"])


async def test_the_sdk_server_with_gotauth() -> None:
    world = await issuer()
    reader = await world.token("projects:read")
    writer = await world.token("projects:read projects:write")
    guarded, inner = apps_for(world)
    async with mcp_client(guarded, inner) as http:
        missing = await post(http, call("whoami"))
        assert missing.status_code == 401
        assert missing.headers["www-authenticate"] == MISSING
        bad = await post(http, call("whoami"), "not-a-token")
        assert bad.status_code == 401
        assert bad.headers["www-authenticate"] == INVALID
        assert text(await post(http, call("whoami"), reader)).endswith(world.client_id)
        denied = await post(http, call("create_project", {"name": "x"}), reader)
        assert denied.status_code == 403
        assert denied.headers["www-authenticate"] == STEP_UP
        assert text(
            await post(http, call("create_project", {"name": "x"}), writer)
        ) == ("created x")
        metadata = await http.get("/.well-known/oauth-protected-resource/mcp")
        assert metadata.json()["authorization_servers"] == [ISSUER]


async def test_the_sdk_guard_protects_every_path_by_default() -> None:
    world = await issuer()
    guarded, inner = apps_for(world)
    async with mcp_client(guarded, inner) as http:
        response = await http.post("/messages/", json={})
    assert response.status_code == 401
    assert response.headers["www-authenticate"] == MISSING
