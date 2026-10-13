"""The demo script, automated: sign in, consent, call the tools, step up, revoke in
the app, and the next call is a 401."""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from app.auth import INSPECTOR_REDIRECT, MCP_URL

from .conftest import ORIGIN, Example

METADATA = f"{ORIGIN}/.well-known/oauth-protected-resource/mcp"


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def access_token(example: Example, browser: httpx.AsyncClient, scope: str) -> str:
    """MCP Inspector's flow: authorize, consent in the browser, exchange the code."""
    client_id = example.app.state.inspector_client_id
    verifier, challenge = pkce()
    authorize = await browser.get(
        "/api/auth/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": INSPECTOR_REDIRECT,
            "scope": scope,
            "state": "s",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "resource": MCP_URL,
        },
        headers={"accept": "application/json"},
    )
    if authorize.status_code == 302:
        location = authorize.headers["location"]
    else:
        assert authorize.status_code == 200, authorize.text
        consent = await browser.post(
            "/api/auth/oauth2/consent",
            data={"consent_id": authorize.json()["consent_id"], "accept": "true"},
        )
        location = consent.headers["location"]
    code = parse_qs(urlsplit(location).query)["code"][0]
    tokens = await browser.post(
        "/api/auth/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": INSPECTOR_REDIRECT,
            "code_verifier": verifier,
            "client_id": client_id,
        },
    )
    assert tokens.status_code == 200, tokens.text
    return str(tokens.json()["access_token"])


async def call(
    http: httpx.AsyncClient,
    tool: str,
    token: str | None,
    arguments: dict[str, Any] | None = None,
) -> httpx.Response:
    headers = {"accept": "application/json, text/event-stream"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return await http.post(
        "/mcp",
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments or {}},
        },
        headers=headers,
    )


async def test_the_demo_script(example: Example) -> None:
    async with (
        example.running(),
        example.browser() as browser,
        example.mcp_client() as mcp,
    ):
        # Before signing in, an MCP client learns where to get a token.
        first = await call(mcp, "list_projects", None)
        assert first.status_code == 401
        assert first.headers["www-authenticate"] == (
            f'Bearer resource_metadata="{METADATA}", scope="projects:read"'
        )
        document = (await mcp.get("/.well-known/oauth-protected-resource/mcp")).json()
        issuer = document["authorization_servers"][0]
        assert issuer == f"{ORIGIN}/api/auth"
        metadata = await mcp.get("/.well-known/oauth-authorization-server/api/auth")
        assert metadata.json()["issuer"] == issuer

        # The user signs up in the browser and allows read access.
        assert (await browser.get("/sign-in")).status_code == 200
        signed_up = await browser.post(
            "/api/auth/sign-up/email",
            json={"email": "ada@example.com", "password": "correct horse battery"},
        )
        assert signed_up.status_code == 200, signed_up.text
        reader = await access_token(example, browser, "openid projects:read")

        listed = await call(mcp, "list_projects", reader)
        assert listed.status_code == 200, listed.text
        projects = listed.json()["result"]["structuredContent"]["result"]
        names = [project["name"] for project in projects]
        assert "Website redesign" in names

        # Creating a project needs projects:write: a 403 the client steps up from.
        denied = await call(mcp, "create_project", reader, {"name": "Launch"})
        assert denied.status_code == 403
        assert denied.headers["www-authenticate"] == (
            'Bearer error="insufficient_scope", '
            f'scope="projects:read projects:write", resource_metadata="{METADATA}"'
        )
        writer = await access_token(
            example, browser, "openid projects:read projects:write"
        )
        created = await call(mcp, "create_project", writer, {"name": "Launch"})
        assert created.status_code == 200, created.text

        # The app shows the connection, and revoking it ends access at once.
        page = await browser.get("/connected-apps")
        assert "MCP Inspector" in page.text
        revoked = await browser.post(
            "/api/auth/oauth2/grants/revoke",
            json={"client_id": example.app.state.inspector_client_id},
        )
        assert revoked.status_code == 200, revoked.text
        after = await call(mcp, "list_projects", writer)
        assert after.status_code == 401
        challenge = after.headers["www-authenticate"]
        assert challenge.startswith('Bearer error="invalid_token"')
        assert "None yet." in (await browser.get("/connected-apps")).text


async def test_pages_need_no_javascript_to_render(example: Example) -> None:
    async with example.running(), example.browser() as browser:
        home = await browser.get("/")
        assert "Sign in or create an account" in home.text
        apps = await browser.get("/connected-apps", follow_redirects=False)
        assert apps.status_code == 303
        assert apps.headers["location"] == "/sign-in?callback_url=/connected-apps"


async def test_mcp_inspector_may_call_from_its_page(example: Example) -> None:
    async with example.running(), example.mcp_client() as http:
        for origin, allowed in (
            ("http://localhost:6274", True),
            ("https://evil.example", False),
        ):
            preflight = await http.options(
                "/api/auth/oauth2/token",
                headers={
                    "origin": origin,
                    "access-control-request-method": "POST",
                    "access-control-request-headers": "content-type",
                },
            )
            granted = preflight.headers.get("access-control-allow-origin")
            assert (granted == origin) is allowed, origin
            assert "access-control-allow-credentials" not in preflight.headers


async def test_a_look_alike_client_is_never_used_for_inspector(
    example: Example,
) -> None:
    async with example.running(), example.mcp_client() as http:
        seeded = example.app.state.inspector_client_id
        registered = await http.post(
            "/api/auth/oauth2/register",
            json={
                "client_name": "MCP Inspector",
                "redirect_uris": ["https://evil.example/callback"],
                "application_type": "web",
            },
        )
        assert registered.status_code == 201, registered.text
    async with example.running():  # a restart seeds again
        assert example.app.state.inspector_client_id == seeded


async def test_sign_in_elsewhere_points_to_the_app(example: Example) -> None:
    async with example.running():
        other = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=example.app),
            base_url="http://127.0.0.1:8000",
        )
        async with other:
            page = await other.get("/sign-in")
    assert "This app runs at" in page.text
    async with example.running(), example.browser() as browser:
        assert "This app runs at" not in (await browser.get("/sign-in")).text
