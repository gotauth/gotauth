"""CIMD fetching, token forgery, keys, registration and the URL rules."""

from __future__ import annotations

import base64
import json
from typing import Any

import httpx
import jwt
import pytest
import respx
from hypothesis import given
from hypothesis import strategies as st

from gotauth.plugins.oauth_provider import (
    normalize_resource,
    redirect_matches,
    valid_redirect_uri,
)

from .conftest import ISSUER, REDIRECT, RESOURCE, pkce, query_of, world

CIMD = "https://client.example.com/oauth/client.json"
PUBLIC_IP = "93.184.216.34"
CIMD_TARGET = f"https://{PUBLIC_IP}:443/oauth/client.json"


def document(**overrides: Any) -> dict[str, Any]:  # Any: JSON
    doc: dict[str, Any] = {
        "client_id": CIMD,
        "client_name": "Claude",
        "redirect_uris": ["http://localhost:3000/callback"],
        "grant_types": ["authorization_code", "refresh_token"],
    }
    doc.update(overrides)
    return {k: v for k, v in doc.items() if v is not None}


async def cimd_world(ips: list[str] | None = None) -> Any:  # Any: World
    w = await world()
    server = w.auth.plugins[-1].principal_resolvers[0]._server

    async def resolve(host: str, port: int) -> list[str]:
        assert host == "client.example.com"
        return ips if ips is not None else [PUBLIC_IP]

    server.clients.resolver = resolve
    w.extra["server"] = server
    return w


async def authorize_cimd(
    w: Any, redirect: str = "http://localhost:3000/callback"
) -> httpx.Response:  # Any: World
    return await w.http.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": CIMD,
            "redirect_uri": redirect,
            "code_challenge": pkce()[1],
            "code_challenge_method": "S256",
            "scope": "openid",
        },
        headers={"accept": "application/json"},
    )


# ---------------------------------------------------------------- CIMD


@respx.mock
async def test_cimd_valid_document_is_used_and_cached() -> None:
    route = respx.get(CIMD_TARGET).mock(
        return_value=httpx.Response(
            200, json=document(), headers={"cache-control": "max-age=600"}
        )
    )
    w = await cimd_world()
    first = await authorize_cimd(w)
    assert (
        first.status_code == 200
        and first.json()["client"]["host"] == "client.example.com"
    )
    assert route.calls[0].request.headers["host"] == "client.example.com"
    assert route.calls[0].request.extensions["sni_hostname"] == "client.example.com"
    await authorize_cimd(w)
    assert route.call_count == 1  # cached
    from gotauth.contracts import Where

    row = await w.auth.database.find_one("oauth_client", [Where("client_id", CIMD)])
    assert row is not None and row["registration"] == "cimd" and row["type"] == "public"


@pytest.mark.parametrize(
    "ip",
    [
        "10.0.0.5",
        "127.0.0.1",
        "169.254.169.254",
        "fd00::1",
        "::ffff:8.8.8.8",
        "224.0.0.1",
    ],
)
@respx.mock
async def test_cimd_rejects_non_public_addresses(ip: str) -> None:
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=document()))
    w = await cimd_world([ip])
    response = await authorize_cimd(w)
    assert (
        response.status_code == 400 and "text/html" in response.headers["content-type"]
    )


@pytest.mark.parametrize(
    ("reply", "case"),
    [
        (
            httpx.Response(
                302, headers={"location": "https://evil.example.com/doc.json"}
            ),
            "redirect",
        ),
        (httpx.Response(200, content=b"{" + b" " * 6000 + b"}"), "too large"),
        (
            httpx.Response(
                200, json=document(client_id="https://other.example.com/x.json")
            ),
            "client_id mismatch",
        ),
        (httpx.Response(200, json=document(client_secret="s")), "client_secret"),
        (
            httpx.Response(
                200, json=document(token_endpoint_auth_method="private_key_jwt")
            ),
            "private_key_jwt",
        ),
        (
            httpx.Response(
                200, json=document(redirect_uris=["http://evil.example.com/cb"])
            ),
            "bad redirect",
        ),
        (
            httpx.Response(200, json=document(grant_types=["client_credentials"])),
            "grant types",
        ),
        (httpx.Response(404), "not found"),
    ],
)
@respx.mock
async def test_cimd_rejections(reply: httpx.Response, case: str) -> None:
    respx.get(CIMD_TARGET).mock(return_value=reply)
    w = await cimd_world()
    response = await authorize_cimd(w)
    assert response.status_code == 400, case


@respx.mock
async def test_cimd_timeout_and_errors_are_not_cached() -> None:
    route = respx.get(CIMD_TARGET).mock(
        side_effect=[
            httpx.ConnectTimeout("slow"),
            httpx.Response(404),
            httpx.Response(200, json=document()),
        ]
    )
    w = await cimd_world()
    assert (await authorize_cimd(w)).status_code == 400
    assert (await authorize_cimd(w)).status_code == 400
    assert (await authorize_cimd(w)).status_code == 200  # the failures were not cached
    assert route.call_count == 3


async def test_cimd_urls_with_dot_segments_are_not_fetched() -> None:
    from gotauth.plugins.oauth_provider import is_cimd_url

    assert is_cimd_url(CIMD)
    for url in (
        "https://a.example.com/../x.json",
        "https://a.example.com/a/./b",
        "https://a.example.com/",
        "http://a.example.com/x",
        "https://u:p@a.example.com/x",
        "https://a.example.com/x#f",
    ):
        assert not is_cimd_url(url), url


@respx.mock
async def test_private_key_jwt_at_the_token_endpoint_is_invalid_client() -> None:
    respx.get(CIMD_TARGET).mock(
        return_value=httpx.Response(
            200, json=document(token_endpoint_auth_method="private_key_jwt")
        )
    )
    w = await cimd_world()
    response = await w.http.post(
        "/oauth2/token",
        data={
            "grant_type": "authorization_code",
            "client_id": CIMD,
            "code": "x",
            "redirect_uri": "http://localhost:3000/callback",
            "code_verifier": "v" * 43,
        },
    )
    assert response.status_code == 401 and response.json()["error"] == "invalid_client"


@respx.mock
async def test_cimd_loopback_always_shows_consent() -> None:
    respx.get(CIMD_TARGET).mock(
        return_value=httpx.Response(
            200, json=document(), headers={"cache-control": "max-age=600"}
        )
    )
    w = await cimd_world()
    screen = (await authorize_cimd(w)).json()
    assert screen["loopback_only"] is True
    location = (await w.consent(screen["consent_id"])).headers["location"]
    assert "code" in query_of(location)
    again = await authorize_cimd(w)
    assert (
        again.status_code == 200 and "consent_id" in again.json()
    )  # no code on the GET


# ---------------------------------------------------------------- tokens


def _forge(
    header: dict[str, Any], claims: dict[str, Any], key: bytes | str = b""
) -> str:  # Any: JSON
    def b64(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode().rstrip("=")

    signing = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}"
    if header.get("alg") == "none":
        return signing + "."
    return jwt.encode(claims, key, algorithm=header["alg"], headers=header)


async def test_forged_tokens_are_rejected() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code(scope="openid"))).json()
    real = tokens["access_token"]
    header = jwt.get_unverified_header(real)
    claims = jwt.decode(real, options={"verify_signature": False})
    jwks = (await w.http.get("/oauth2/jwks")).json()
    public_pem = jwt.PyJWK(jwks["keys"][0]).key.public_bytes(
        encoding=__import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["x"]
        ).Encoding.PEM,
        format=__import__(
            "cryptography.hazmat.primitives.serialization", fromlist=["x"]
        ).PublicFormat.SubjectPublicKeyInfo,
    )
    forgeries = {
        "alg none": _forge({**header, "alg": "none"}, claims),
        "unknown kid": real.replace(
            real.split(".")[0],
            base64.urlsafe_b64encode(json.dumps({**header, "kid": "nope"}).encode())
            .decode()
            .rstrip("="),
        ),
        "id token": tokens["id_token"],
    }
    try:
        forgeries["hs256 with public key"] = jwt.encode(
            claims, public_pem, algorithm="HS256", headers={**header, "alg": "HS256"}
        )
    except jwt.InvalidKeyError:
        pass  # PyJWT itself refuses an asymmetric key as an HMAC secret
    for name, token in forgeries.items():
        result = await w.auth.api.call("verify_access_token", body={"token": token})
        assert not result.valid, name
        assert (
            await w.auth.get_principal({"authorization": f"Bearer {token}"}, {}) is None
        ), name


async def test_disabled_client_tokens_stop_working() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code())).json()
    await w.auth.api.call(
        "update_oauth_client", body={"client_id": w.client_id, "disabled": True}
    )
    result = await w.auth.api.call(
        "verify_access_token", body={"token": tokens["access_token"]}
    )
    assert not result.valid


async def test_revoke_oauth_tokens_by_user() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code())).json()
    user_id = (await w.http.get("/session")).json()["user"]["id"]
    revoked = await w.auth.api.call("revoke_oauth_tokens", body={"user_id": user_id})
    assert revoked.revoked == 1
    assert not (
        await w.auth.api.call(
            "verify_access_token", body={"token": tokens["access_token"]}
        )
    ).valid


async def test_key_rotation_keeps_old_tokens_valid_until_expiry() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code())).json()
    old_kid = jwt.get_unverified_header(tokens["access_token"])["kid"]
    new = await w.auth.api.call("rotate_signing_key", body={})
    assert new.kid != old_kid
    kids = {k["kid"] for k in (await w.http.get("/oauth2/jwks")).json()["keys"]}
    assert kids == {old_kid, new.kid}
    assert (
        await w.auth.api.call(
            "verify_access_token", body={"token": tokens["access_token"]}
        )
    ).valid
    w.clock.advance("11m")
    kids = {k["kid"] for k in (await w.http.get("/oauth2/jwks")).json()["keys"]}
    assert kids == {new.kid}


async def test_access_token_claims() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code(resource=RESOURCE, nonce="n-9"))).json()
    header = jwt.get_unverified_header(tokens["access_token"])
    claims = jwt.decode(tokens["access_token"], options={"verify_signature": False})
    assert header["typ"] == "at+jwt" and header["alg"] == "ES256"
    assert (
        claims["iss"] == ISSUER
        and claims["aud"] == RESOURCE
        and claims["client_id"] == w.client_id
    )
    id_claims = jwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert (
        id_claims["aud"] == w.client_id
        and id_claims["nonce"] == "n-9"
        and "auth_time" in id_claims
    )


# ---------------------------------------------------------------- dynamic registration


async def test_dynamic_registration() -> None:
    w = await world(allow_dynamic_registration=True)
    ok = await w.http.post(
        "/oauth2/register",
        json={
            "client_name": "Tool",
            "redirect_uris": ["http://127.0.0.1:8123/cb"],
            "application_type": "native",
        },
    )
    assert ok.status_code == 201 and ok.json()["token_endpoint_auth_method"] == "none"
    missing = await w.http.post(
        "/oauth2/register", json={"redirect_uris": ["http://127.0.0.1/cb"]}
    )
    assert (
        missing.status_code == 400
        and missing.json()["error"] == "invalid_client_metadata"
    )
    web_loopback = await w.http.post(
        "/oauth2/register",
        json={"redirect_uris": ["http://127.0.0.1/cb"], "application_type": "web"},
    )
    assert web_loopback.json()["error"] == "invalid_redirect_uri"
    off = await world()
    assert (await off.http.post("/oauth2/register", json={})).status_code == 404


# ---------------------------------------------------------------- URL rules


def test_redirect_rule() -> None:
    assert valid_redirect_uri(REDIRECT) and valid_redirect_uri(
        "http://localhost:3000/cb"
    )
    assert valid_redirect_uri("http://[::1]:5000/cb")
    for bad in (
        "http://example.com/cb",
        "https://a.example.com/cb#x",
        "myapp://cb",
        "https://u:p@a.example.com/cb",
        "http://127.0.0.1.nip.io/cb",
    ):
        assert not valid_redirect_uri(bad), bad
    assert redirect_matches("http://localhost:3000/cb", "http://localhost:5555/cb")
    assert not redirect_matches(
        "http://localhost:3000/cb", "http://localhost:5555/other"
    )
    assert not redirect_matches(REDIRECT, REDIRECT + "/")


@given(
    st.text(alphabet=st.characters(categories=("Ll", "Nd")), min_size=1, max_size=12),
    st.integers(min_value=1, max_value=65535),
)
def test_loopback_ports_match_any_port(path: str, port: int) -> None:
    assert redirect_matches(
        f"http://127.0.0.1:3000/{path}", f"http://127.0.0.1:{port}/{path}"
    )
    assert (
        not redirect_matches(
            f"https://example.com:3000/{path}", f"https://example.com:{port}/{path}"
        )
        or port == 3000
    )


def test_resource_normalization() -> None:
    assert normalize_resource("HTTPS://MCP.EXAMPLE.COM:443/mcp") == RESOURCE
    assert (
        normalize_resource("https://mcp.example.com:8443/mcp")
        == "https://mcp.example.com:8443/mcp"
    )
    for bad in (
        "https://mcp.example.com/mcp/../admin",
        "https://mcp.example.com/mcp#x",
        "mcp",
        "ftp://x/y",
    ):
        assert normalize_resource(bad) is None, bad


# ---------------------------------------------------------------- review fixes


async def test_authorize_requires_redirect_uri() -> None:
    w = await world()
    response = await w.authorize(redirect_uri="")
    assert (
        response.status_code == 400 and "text/html" in response.headers["content-type"]
    )


async def test_malformed_verifier_is_invalid_grant() -> None:
    w = await world()
    code = await w.code()
    response = await w.exchange(code, code_verifier="short!")
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


async def test_narrowing_on_refresh_does_not_shrink_the_grant() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code(scope="openid profile email"))).json()
    narrow = (
        await w.token(
            grant_type="refresh_token",
            refresh_token=tokens["refresh_token"],
            scope="openid",
        )
    ).json()
    assert narrow["scope"] == "openid"
    full = (
        await w.token(
            grant_type="refresh_token",
            refresh_token=narrow["refresh_token"],
            scope="openid profile email",
        )
    ).json()
    assert set(full["scope"].split()) == {"openid", "profile", "email"}


async def test_id_token_auth_time_is_the_sign_in_time() -> None:
    w = await world()
    signed_in_at = int(w.clock.now().timestamp())
    w.clock.advance("2h")
    tokens = (await w.exchange(await w.code(scope="openid"))).json()
    first = jwt.decode(tokens["id_token"], options={"verify_signature": False})
    assert first["auth_time"] == signed_in_at
    w.clock.advance("1h")
    refreshed = (
        await w.token(grant_type="refresh_token", refresh_token=tokens["refresh_token"])
    ).json()
    second = jwt.decode(refreshed["id_token"], options={"verify_signature": False})
    assert second["auth_time"] == signed_in_at


@pytest.mark.parametrize("ip", ["100.64.1.1", "64:ff9b::7f00:1", "64:ff9b::a9fe:a9fe"])
@respx.mock
async def test_cimd_rejects_shared_and_nat64_addresses(ip: str) -> None:
    respx.get(url__regex=r".*").mock(return_value=httpx.Response(200, json=document()))
    w = await cimd_world([ip])
    assert (await authorize_cimd(w)).status_code == 400


async def test_cimd_bad_port_is_an_error_page() -> None:
    w = await world()
    response = await w.http.get(
        "/oauth2/authorize",
        params={
            "response_type": "code",
            "client_id": "https://client.example.com:99999/c.json",
            "redirect_uri": "http://localhost:3000/cb",
            "code_challenge": pkce()[1],
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 400


async def test_userinfo_refuses_tokens_for_other_resources() -> None:
    w = await world()
    tokens = (
        await w.exchange(await w.code(scope="openid email", resource=RESOURCE))
    ).json()
    response = await w.http.get(
        "/oauth2/userinfo",
        headers={"authorization": f"Bearer {tokens['access_token']}"},
    )
    assert response.status_code == 401
