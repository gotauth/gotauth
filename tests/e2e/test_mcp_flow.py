"""The MCP OAuth flow on examples/fastmcp-server, against real servers (Q2).

An MCP client (scripted with httpx) discovers GotAuth from the server's 401, runs the
authorization code flow with PKCE and a resource; the user signs up and consents in a
real browser; the client calls a tool, rotates its refresh token, and is cut off when
the user revokes the app. The token names its MCP server as the audience, and a second
instance of the server, on another URL but with the same database and keys, refuses it.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from playwright.sync_api import Page, expect

from .conftest import PASSWORD, new_email, wait_for

EXAMPLE = Path(__file__).resolve().parents[2] / "examples" / "fastmcp-server"
INSPECTOR_REDIRECT = "http://localhost:6274/oauth/callback"


@dataclass
class McpServer:
    url: str
    process: subprocess.Popen[str]
    output: Path

    @property
    def mcp_url(self) -> str:
        return f"{self.url}/mcp"

    def client_id(self) -> str:
        def printed() -> str | None:
            found = re.search(
                r"MCP Inspector client_id: (\S+)", self.output.read_text()
            )
            return found.group(1) if found else None

        return str(wait_for(printed, "the seeded MCP Inspector client"))


def start(port: int, env: dict[str, str], log: Path) -> McpServer:
    url = f"http://localhost:{port}"
    with log.open("w") as handle:  # the child keeps its own copy of the file
        process = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(port)],
            cwd=EXAMPLE,
            # Unbuffered: client_id() reads what the server prints while it runs.
            env={**env, "BASE_URL": url, "PYTHONUNBUFFERED": "1"},
            stdout=handle,
            stderr=subprocess.STDOUT,
            text=True,
        )
    server = McpServer(url=url, process=process, output=log)

    def up() -> bool:
        try:
            return httpx.get(f"{url}/", timeout=2).status_code == 200
        except httpx.HTTPError:
            return False

    try:
        wait_for(up, f"the MCP example on port {port}", timeout=60)
    except BaseException:
        stop(server)
        raise
    return server


def stop(server: McpServer) -> None:
    server.process.terminate()
    try:
        server.process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        server.process.kill()
        server.process.wait()


@pytest.fixture(scope="module")
def servers(
    tmp_path_factory: pytest.TempPathFactory,
) -> Iterator[tuple[McpServer, McpServer]]:
    work = tmp_path_factory.mktemp("mcp")
    env = {
        **os.environ,
        "GOTAUTH_SECRET": "e2e-mcp-secret-not-for-anything-else-0123456789",
        "DATABASE_URL": f"sqlite+aiosqlite:///{work / 'mcp.db'}",
        "BASE_URL": "http://localhost:8000",
    }
    subprocess.run(
        [
            sys.executable,
            "-c",
            "from gotauth.cli import main; raise SystemExit(main())",
            "migrate",
            "--auth",
            "app.auth:auth",
        ],
        cwd=EXAMPLE,
        env=env,
        check=True,
    )
    started: list[McpServer] = []
    try:
        started.append(start(8000, env, work / "main.log"))
        started.append(start(8001, env, work / "other.log"))
        yield started[0], started[1]
    finally:
        for server in started:
            stop(server)


def call(
    server: McpServer, token: str | None, tool: str = "list_projects"
) -> httpx.Response:
    headers = {"accept": "application/json, text/event-stream"}
    if token is not None:
        headers["authorization"] = f"Bearer {token}"
    return httpx.post(
        server.mcp_url,
        json={
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": tool, "arguments": {}},
        },
        headers=headers,
    )


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    digest = hashlib.sha256(verifier.encode()).digest()
    return verifier, base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def test_mcp_oauth_flow(page: Page, servers: tuple[McpServer, McpServer]) -> None:
    server, other = servers
    client_id = server.client_id()

    # 1. Without a token, the server says where to get one (RFC 9728).
    first = call(server, None)
    assert first.status_code == 401
    challenge = first.headers["www-authenticate"]
    metadata_url = re.search(r'resource_metadata="([^"]+)"', challenge)
    assert metadata_url, challenge
    resource_doc = httpx.get(metadata_url.group(1)).json()
    assert resource_doc["resource"] == server.mcp_url
    issuer = resource_doc["authorization_servers"][0]
    assert issuer == f"{server.url}/api/auth"

    # 2. The authorization server's metadata at the host root (RFC 8414).
    meta = httpx.get(
        f"{server.url}/.well-known/oauth-authorization-server/api/auth"
    ).json()
    assert meta["issuer"] == issuer
    assert "S256" in meta["code_challenge_methods_supported"]

    # 3. Authorization code with PKCE and a resource; the user signs up and consents.
    verifier, challenge_s256 = pkce()
    state = secrets.token_urlsafe(16)
    query = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": INSPECTOR_REDIRECT,
        "scope": "openid projects:read offline_access",
        "state": state,
        "code_challenge": challenge_s256,
        "code_challenge_method": "S256",
        "resource": server.mcp_url,
    }
    # MCP Inspector's callback is not running: the redirect there fails, and the
    # test reads the code from the request it tried.
    page.goto(f"{meta['authorization_endpoint']}?{urlencode(query)}")
    expect(page.get_by_role("heading", name="Sign in")).to_be_visible()
    page.get_by_label("Email").fill(new_email("mcp"))
    page.get_by_label("Password").fill(PASSWORD)
    page.get_by_role("button", name="Create account").click()
    with page.expect_request(re.compile(r"^http://localhost:6274/")) as redirected:
        page.locator("#allow").click()
    answer = parse_qs(urlsplit(redirected.value.url).query)
    assert answer["state"] == [state]
    assert answer["iss"] == [issuer]

    # 4. The token request, as a form.
    tokens = httpx.post(
        meta["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": answer["code"][0],
            "redirect_uri": INSPECTOR_REDIRECT,
            "code_verifier": verifier,
            "client_id": client_id,
        },
    )
    assert tokens.status_code == 200, tokens.text
    access, refresh = tokens.json()["access_token"], tokens.json()["refresh_token"]

    # 5. A tool call with the token.
    listed = call(server, access)
    assert listed.status_code == 200, listed.text
    result: dict[str, Any] = listed.json()["result"]
    assert result["structuredContent"]["result"]

    # 6. The token is bound to this MCP server (RFC 8707), and another one refuses it.
    payload = access.split(".")[1]
    claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    assert claims["aud"] == server.mcp_url
    assert claims["iss"] == issuer
    assert call(other, access).status_code == 401

    # 7. Refresh rotation: a new refresh token each time.
    rotated = httpx.post(
        meta["token_endpoint"],
        data={
            "grant_type": "refresh_token",
            "refresh_token": refresh,
            "client_id": client_id,
        },
    )
    assert rotated.status_code == 200, rotated.text
    access = rotated.json()["access_token"]
    assert rotated.json()["refresh_token"] != refresh
    assert call(server, access).status_code == 200

    # 8. The user revokes the app in "Connected apps": the next call is a 401.
    page.goto(f"{server.url}/connected-apps")
    page.get_by_role("button", name="Revoke").first.click()
    expect(page.get_by_text("MCP Inspector")).to_have_count(0)
    assert call(server, access).status_code == 401
