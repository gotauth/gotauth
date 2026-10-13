"""Remote verification (``issuer=``): discovery, JWKS with pinned algorithms and a
refetch limit, introspection, and the access a tool sees (work package O2)."""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from typing import Any

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from jwt.algorithms import ECAlgorithm

from gotauth.integrations.mcp import _verify
from gotauth.integrations.mcp._verify import RemoteVerifier, VerifierUnavailable

ISSUER = "https://auth.example.com/api/auth"
RESOURCE = "https://mcp.example.com/mcp"
CLIENT = "cli_1"


class FakeIssuer:
    """Serves metadata, JWKS and introspection, and counts the JWKS fetches."""

    def __init__(self) -> None:
        self.keys: dict[str, Any] = {}  # Any: private keys by kid
        self.jwks_fetches = 0
        self.introspections = 0
        self.active = True
        self.add_key("k1")

    def add_key(self, kid: str) -> None:
        self.keys[kid] = ec.generate_private_key(ec.SECP256R1())

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/oauth-authorization-server/api/auth":
            return httpx.Response(
                200,
                json={
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/oauth2/jwks",
                    "introspection_endpoint": f"{ISSUER}/oauth2/introspect",
                },
            )
        if path == "/api/auth/oauth2/jwks":
            self.jwks_fetches += 1
            keys = [
                {
                    **json.loads(ECAlgorithm.to_jwk(key.public_key())),
                    "kid": kid,
                    "alg": "ES256",
                }
                for kid, key in self.keys.items()
            ]
            return httpx.Response(200, json={"keys": keys})
        if path == "/api/auth/oauth2/introspect":
            self.introspections += 1
            assert request.headers["authorization"].startswith("Basic ")
            return httpx.Response(200, json={"active": self.active})
        return httpx.Response(404)

    def mint(self, kid: str = "k1", **claims: Any) -> str:  # Any: JSON
        now = int(time.time())
        body = {
            "iss": ISSUER,
            "sub": "usr_1",
            "aud": RESOURCE,
            "client_id": CLIENT,
            "scope": "projects:read",
            "iat": now,
            "exp": now + 600,
            "jti": "tok_1",
            **claims,
        }
        return jwt.encode(
            body,
            self.keys[kid],
            algorithm="ES256",
            headers={"kid": kid, "typ": "at+jwt"},
        )


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> FakeIssuer:
    issuer = FakeIssuer()
    monkeypatch.setattr(
        _verify,
        "new_http_client",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(issuer.handler)),
    )
    return issuer


def verifier(
    clock: Callable[[], float] = time.monotonic, introspect: bool = False
) -> RemoteVerifier:
    return RemoteVerifier(
        ISSUER,
        RESOURCE,
        introspection_client=(CLIENT, "secret") if introspect else None,
        clock=clock,
    )


async def test_a_good_token_and_its_access(fake: FakeIssuer) -> None:
    verified = await verifier().verify(fake.mint())
    assert verified is not None
    access = verified.access
    assert (access.user_id, access.client_id, access.jti) == ("usr_1", CLIENT, "tok_1")
    assert access.scopes == {"projects:read"} and access.agent_id is None


async def test_agents_and_client_credentials(fake: FakeIssuer) -> None:
    agent = await verifier().verify(fake.mint(act={"sub": "agt_1"}))
    assert agent is not None
    assert (agent.access.user_id, agent.access.agent_id) == ("usr_1", "agt_1")
    machine = await verifier().verify(fake.mint(sub=CLIENT))
    assert machine is not None and machine.access.user_id is None
    agent_machine = await verifier().verify(
        fake.mint(sub="agt_1", act={"sub": "agt_1"})
    )
    assert agent_machine is not None and agent_machine.access.user_id is None


def _none_token(fake: FakeIssuer) -> str:
    _, body, _ = fake.mint().split(".")
    header = json.dumps({"alg": "none", "kid": "k1", "typ": "at+jwt"}).encode()
    unsigned = base64.urlsafe_b64encode(header).rstrip(b"=").decode()
    return f"{unsigned}.{body}."


async def test_bad_tokens_are_rejected(fake: FakeIssuer) -> None:
    check = verifier()
    hs256 = jwt.encode(
        {"iss": ISSUER, "aud": RESOURCE, "sub": "usr_1", "exp": 9999999999, "jti": "t"},
        "a-shared-secret-that-is-long-enough",
        algorithm="HS256",
        headers={"kid": "k1", "typ": "at+jwt"},
    )
    bad = [
        fake.mint(aud="https://other.example.com/mcp"),
        fake.mint(iss="https://evil.example.com"),
        fake.mint(exp=int(time.time()) - 60),
        fake.mint()[:-4] + "AAAA",
        _none_token(fake),
        hs256,
        jwt.encode(
            {"iss": ISSUER, "aud": RESOURCE, "sub": "u", "exp": 9999999999, "jti": "t"},
            fake.keys["k1"],
            algorithm="ES256",
            headers={"kid": "k1", "typ": "JWT"},  # an ID token, not an access token
        ),
        "not-a-jwt",
    ]
    for token in bad:
        assert await check.verify(token) is None, token


async def test_a_rotated_key_is_used_after_one_refetch(fake: FakeIssuer) -> None:
    now = [0.0]
    check = verifier(clock=lambda: now[0])
    assert await check.verify(fake.mint()) is not None
    assert fake.jwks_fetches == 1
    fake.add_key("k2")
    now[0] = 31.0
    assert await check.verify(fake.mint("k2")) is not None
    assert fake.jwks_fetches == 2


async def test_unknown_kids_stay_within_the_refetch_limit(fake: FakeIssuer) -> None:
    now = [0.0]
    check = verifier(clock=lambda: now[0])
    assert await check.verify(fake.mint()) is not None
    fake.add_key("k2")
    for _ in range(50):
        now[0] += 0.1  # 5 seconds in all, inside the 30 second limit
        assert await check.verify(fake.mint("k2")) is None
    assert fake.jwks_fetches == 1


async def test_introspection_sees_revocation_at_once(fake: FakeIssuer) -> None:
    now = [0.0]
    check = verifier(clock=lambda: now[0], introspect=True)
    token = fake.mint()
    assert await check.verify(token) is not None
    assert await check.verify(token) is not None
    assert fake.introspections == 1  # cached for 5 seconds
    fake.active = False
    now[0] = 6.0
    assert await check.verify(token) is None


async def test_an_unreachable_issuer_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        _verify,
        "new_http_client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(503))
        ),
    )
    with pytest.raises(VerifierUnavailable):
        await verifier().verify(FakeIssuer().mint())


async def test_fastmcp_with_a_remote_issuer(fake: FakeIssuer) -> None:
    from fastmcp import FastMCP

    from gotauth.integrations.mcp import current_access, fastmcp_auth

    mcp = FastMCP(
        "projects",
        auth=fastmcp_auth(
            issuer=ISSUER,
            resource=RESOURCE,
            scopes=["projects:read"],
            introspect=True,
            introspection_client=(CLIENT, "secret"),
        ),
    )

    @mcp.tool
    def whoami() -> str:
        access = current_access()
        return access.user_id if access and access.user_id else "nobody"

    app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
    body = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {"name": "whoami", "arguments": {}},
    }
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com"
        ) as http,
    ):

        async def send(token: str) -> httpx.Response:
            return await http.post(
                "/mcp",
                json=body,
                headers={
                    "accept": "application/json, text/event-stream",
                    "authorization": f"Bearer {token}",
                },
            )

        ok = await send(fake.mint())
        assert ok.status_code == 200, ok.text
        assert ok.json()["result"]["content"][0]["text"] == "usr_1"
        fake.active = False
        revoked = await send(fake.mint(jti="tok_2"))
        assert revoked.status_code == 401
        assert revoked.headers["www-authenticate"].startswith(
            'Bearer error="invalid_token", resource_metadata='
            '"https://mcp.example.com/.well-known/oauth-protected-resource/mcp"'
        )


async def test_an_unreachable_issuer_is_a_503_not_a_401(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fastmcp import FastMCP

    from gotauth.integrations.mcp import fastmcp_auth

    monkeypatch.setattr(
        _verify,
        "new_http_client",
        lambda: httpx.AsyncClient(
            transport=httpx.MockTransport(lambda _: httpx.Response(502))
        ),
    )
    mcp = FastMCP("p", auth=fastmcp_auth(issuer=ISSUER, resource=RESOURCE))
    app = mcp.http_app(path="/mcp", stateless_http=True, json_response=True)
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="https://mcp.example.com"
        ) as http,
    ):
        response = await http.post(
            "/mcp",
            json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
            headers={"authorization": f"Bearer {FakeIssuer().mint()}"},
        )
    assert response.status_code == 503
    assert "www-authenticate" not in response.headers


async def test_a_removed_key_stops_verifying(fake: FakeIssuer) -> None:
    now = [0.0]
    check = verifier(clock=lambda: now[0])
    token = fake.mint()
    assert await check.verify(token) is not None
    del fake.keys["k1"]
    fake.add_key("k2")
    now[0] = 299.0
    assert await check.verify(token) is not None  # cached keys, no fetch yet
    now[0] = 301.0
    assert await check.verify(token) is None
    assert fake.jwks_fetches == 2


async def test_known_keys_keep_working_while_the_issuer_is_down(
    fake: FakeIssuer,
) -> None:
    now = [0.0]
    check = verifier(clock=lambda: now[0])
    assert await check.verify(fake.mint()) is not None
    original = fake.handler
    fake.handler = lambda _: httpx.Response(502)  # type: ignore[method-assign]
    check._http = httpx.AsyncClient(  # pyright: ignore[reportPrivateUsage]
        transport=httpx.MockTransport(lambda request: fake.handler(request))
    )
    now[0] = 400.0
    assert await check.verify(fake.mint()) is not None
    fake.handler = original  # type: ignore[method-assign]


async def test_a_small_clock_difference_is_allowed(fake: FakeIssuer) -> None:
    later = int(time.time()) + 10
    assert await verifier().verify(fake.mint(iat=later, nbf=later)) is not None
