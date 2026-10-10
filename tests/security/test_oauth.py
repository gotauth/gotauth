"""OAuth server attacks not already covered by O1's own suite.

Covered in ``tests/plugins/oauth_provider``: PKCE missing, ``plain`` and wrong
verifier (``test_pkce_is_required_and_checked``); trailing slash, case, query and
fragment redirects (``test_redirect_tricks_get_an_error_page``); CIMD addresses,
redirects, size, timeout and bad ports (``test_cimd_*``); ``alg=none``, unknown
``kid`` and ID tokens used as access tokens (``test_forged_tokens_are_rejected``);
revocation seen on the next call (``test_introspection_and_revocation``).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from typing import Any

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization

from .conftest import (
    REDIRECT,
    RESOURCE,
    App,
    full_app,
    oauth_client,
    oauth_code,
    oauth_tokens,
    pkce,
)


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def server_of(app: App) -> Any:  # Any: the plugin's private server object
    plugin = next(p for p in app.auth.plugins if p.id == "oauth_provider")
    return plugin.principal_resolvers[0]._server


async def issued(app: App, http: httpx.AsyncClient) -> dict[str, Any]:  # Any: JSON
    client_id, _ = await oauth_client(app)
    code, verifier = await oauth_code(http, client_id, resource=RESOURCE)
    return (await oauth_tokens(http, client_id, code, verifier)).json()


async def accepted(app: App, token: str) -> bool:
    """Whether any in-process check takes the token."""
    result = await app.auth.api.call(
        "verify_access_token", body={"token": token, "resource": RESOURCE}
    )
    principal = await app.auth.get_principal({"authorization": f"Bearer {token}"}, {})
    return result.valid or principal is not None


@pytest.mark.parametrize(
    "redirect",
    [
        "http://app.example.com/cb",
        "https://app.example.com/cb/../evil",
        "https://app.example.com/cbx",
        "https://evil@app.example.com/cb",
        "https://app.example.com.evil.test/cb",
        "https://app.example.com:8443/cb",
    ],
)
async def test_unregistered_redirects_never_receive_a_redirect(redirect: str) -> None:
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        client_id, _ = await oauth_client(app)
        _, challenge = pkce()
        response = await http.get(
            "/oauth2/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect,
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
        )
    assert response.status_code == 400
    assert "location" not in response.headers


async def test_code_is_bound_to_its_redirect_uri() -> None:
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        client_id, _ = await oauth_client(app)
        code, verifier = await oauth_code(http, client_id)
        response = await oauth_tokens(
            http, client_id, code, verifier, redirect_uri=REDIRECT + "/other"
        )
    assert response.json()["error"] == "invalid_grant"


async def test_tampered_tokens_signed_with_the_real_key_are_rejected() -> None:
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        real = (await issued(app, http))["access_token"]
    header = jwt.get_unverified_header(real)
    claims = jwt.decode(real, options={"verify_signature": False})
    keys = server_of(app).keys
    key = keys._private[header["kid"]]

    def resign(typ: str = "at+jwt", **changes: Any) -> str:  # Any: claim values
        return keys.sign(
            {**claims, **changes},
            kid=header["kid"],
            alg=header["alg"],
            key=key,
            typ=typ,
        )

    assert await accepted(app, resign())  # re-signing alone keeps it valid
    forgeries = {
        "typ JWT": resign(typ="JWT"),
        "id token typ": resign(typ="id_token+jwt"),
        "other audience": resign(aud="https://other.example.com/api"),
        "other issuer": resign(iss="https://evil.example.com"),
        "expired": resign(exp=claims["iat"] - 1),
        "unknown jti": resign(jti="tok_" + "0" * 26),
    }
    for name, token in forgeries.items():
        assert not await accepted(app, token), name


async def test_hs256_signed_with_the_public_key_is_rejected() -> None:
    # Built by hand: PyJWT refuses to use a PEM public key as an HMAC secret, so the
    # library cannot be relied on to produce this forgery.
    app = full_app()
    async with app.client() as http:
        await app.verified_user(http)
        real = (await issued(app, http))["access_token"]
        jwks = (await http.get("/oauth2/jwks")).json()
    header = jwt.get_unverified_header(real)
    claims = jwt.decode(real, options={"verify_signature": False})
    public = jwt.PyJWK(jwks["keys"][0]).key
    secrets_to_try = [
        public.public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        json.dumps(jwks["keys"][0]).encode(),
    ]
    for secret in secrets_to_try:
        head = _b64(json.dumps({**header, "alg": "HS256"}).encode())
        body = _b64(json.dumps(claims).encode())
        signature = hmac.new(secret, f"{head}.{body}".encode(), hashlib.sha256)
        token = f"{head}.{body}.{_b64(signature.digest())}"
        assert not await accepted(app, token)


CIMD = "https://client.example.com/oauth/client.json"


@pytest.mark.parametrize(
    "answers",
    [
        ["93.184.216.34", "10.0.0.5"],
        ["10.0.0.5", "93.184.216.34"],
        ["93.184.216.34", "::1"],
        [],
    ],
)
@respx.mock
async def test_cimd_rejects_any_private_answer_in_a_mixed_lookup(
    answers: list[str],
) -> None:
    # DNS rebinding: one public and one private answer must not let a fetch reach
    # the private address, so any non-public answer refuses the client.
    route = respx.get(url__regex=r".*").mock(
        return_value=httpx.Response(
            200,
            json={
                "client_id": CIMD,
                "client_name": "Agent",
                "redirect_uris": ["http://localhost:3000/callback"],
            },
        )
    )
    app = full_app()

    async def resolve(host: str, port: int) -> list[str]:
        del host, port
        return answers

    server_of(app).clients.resolver = resolve
    async with app.client() as http:
        await app.verified_user(http)
        response = await http.get(
            "/oauth2/authorize",
            params={
                "response_type": "code",
                "client_id": CIMD,
                "redirect_uri": "http://localhost:3000/callback",
                "code_challenge": pkce()[1],
                "code_challenge_method": "S256",
            },
        )
    assert response.status_code == 400
    assert not route.called
