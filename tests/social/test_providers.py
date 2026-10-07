"""Real providers against mocked HTTP, with ID tokens signed by a test key."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from gotauth.contracts import AuthError, OAuthProvider, ProviderTokens
from gotauth.social import (
    apple,
    discord,
    generic_oidc,
    github,
    gitlab,
    google,
    microsoft,
)
from gotauth.social.oidc import JwksCache

KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
OTHER_KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
CLIENT = "client-123"
TENANT = "11111111-2222-3333-4444-555555555555"


def jwk(key: rsa.RSAPrivateKey, kid: str) -> dict[str, Any]:
    data = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    return {**data, "kid": kid, "use": "sig", "alg": "RS256"}


def id_token(
    issuer: str,
    *,
    key: rsa.RSAPrivateKey = KEY,
    kid: str = "k1",
    alg: str = "RS256",
    **claims: Any,
) -> str:
    now = int(time.time())
    body = {
        "iss": issuer,
        "aud": CLIENT,
        "sub": "user-1",
        "iat": now,
        "exp": now + 300,
        "nonce": "n-1",
        "email": "ada@example.com",
        "email_verified": True,
        **claims,
    }
    return jwt.encode(body, key, algorithm=alg, headers={"kid": kid})


class Server:
    """A mock identity provider; tests set ``token_body`` and add JSON routes."""

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.token_body: dict[str, Any] = {"access_token": "at-1", "expires_in": 3600}
        self.requests: list[httpx.Request] = []

    def oidc(self, base: str, issuer: str | None = None) -> None:
        self.routes[f"{base}/.well-known/openid-configuration"] = {
            "issuer": issuer or base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "jwks_uri": f"{base}/jwks",
            "id_token_signing_alg_values_supported": ["RS256", "HS256", "none"],
        }
        self.routes[f"{base}/jwks"] = {"keys": [jwk(KEY, "k1")]}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url).split("?")[0]
        if url.endswith("/token") or url.endswith("access_token"):
            return httpx.Response(200, json=self.token_body)
        if url in self.routes:
            return httpx.Response(200, json=self.routes[url])
        return httpx.Response(404, json={"error": "not found"})

    def client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(transport=httpx.MockTransport(self.handler))


async def run(
    provider: OAuthProvider, server: Server, *, nonce: str | None = "n-1"
) -> Any:
    async with server.client() as http:
        prepare: Callable[..., Any] | None = getattr(provider, "prepare", None)
        if prepare is not None:
            await prepare(http)
        url = provider.authorization_url(
            state="s",
            code_challenge="cc",
            redirect_uri="https://app/cb",
            scopes=["openid"],
            nonce=nonce,
        )
        query = parse_qs(urlsplit(url).query)
        assert query["code_challenge_method"] == ["S256"]
        assert query["client_id"] == [CLIENT]
        tokens = await provider.exchange_code(
            http, code="code", code_verifier="v", redirect_uri="https://app/cb"
        )
        token_request = next(r for r in server.requests if r.method == "POST")
        form = parse_qs(token_request.content.decode())
        assert form["code_verifier"] == ["v"]
        assert form["grant_type"] == ["authorization_code"]
        return await provider.get_user(http, tokens, nonce=nonce)


# ---------------------------------------------------------------- plain OAuth 2


async def test_github_uses_the_primary_verified_email() -> None:
    server = Server()
    server.routes["https://api.github.com/user"] = {
        "id": 42,
        "login": "ada",
        "avatar_url": "a.png",
    }
    server.routes["https://api.github.com/user/emails"] = [
        {"email": "old@example.com", "primary": False, "verified": True},
        {"email": "ada@example.com", "primary": True, "verified": True},
    ]
    user = await run(github(client_id=CLIENT, client_secret="s"), server, nonce=None)
    assert (user.id, user.email, user.email_verified, user.name) == (
        "42",
        "ada@example.com",
        True,
        "ada",
    )


async def test_github_unverified_primary_gives_no_email() -> None:
    server = Server()
    server.routes["https://api.github.com/user"] = {"id": 42, "login": "ada"}
    server.routes["https://api.github.com/user/emails"] = [
        {"email": "ada@example.com", "primary": True, "verified": False}
    ]
    user = await run(github(client_id=CLIENT, client_secret="s"), server, nonce=None)
    assert user.email is None and not user.email_verified


async def test_discord() -> None:
    server = Server()
    server.routes["https://discord.com/api/users/@me"] = {
        "id": "7",
        "username": "ada",
        "email": "ada@example.com",
        "verified": False,
        "avatar": "h",
    }
    user = await run(discord(client_id=CLIENT, client_secret="s"), server, nonce=None)
    assert (user.id, user.email_verified) == ("7", False)
    assert user.image == "https://cdn.discordapp.com/avatars/7/h.png"


async def test_token_endpoint_errors_are_provider_errors() -> None:
    server = Server()
    server.token_body = {"error": "invalid_grant"}
    with pytest.raises(AuthError) as error:
        await run(discord(client_id=CLIENT, client_secret="s"), server, nonce=None)
    assert error.value.code == "PROVIDER_ERROR"


# ---------------------------------------------------------------- OIDC


GOOGLE = "https://accounts.google.com"


async def test_google() -> None:
    server = Server()
    server.oidc(GOOGLE)
    server.token_body = {
        "access_token": "at",
        "id_token": id_token(GOOGLE, picture="p.png"),
    }
    user = await run(google(client_id=CLIENT, client_secret="s"), server)
    assert (user.id, user.email, user.email_verified, user.image) == (
        "user-1",
        "ada@example.com",
        True,
        "p.png",
    )


@pytest.mark.parametrize(
    "token",
    [
        pytest.param(lambda: id_token("https://evil.test"), id="wrong-iss"),
        pytest.param(lambda: id_token(GOOGLE, aud="someone-else"), id="wrong-aud"),
        pytest.param(lambda: id_token(GOOGLE, nonce="other"), id="wrong-nonce"),
        pytest.param(
            lambda: id_token(GOOGLE, exp=int(time.time()) - 120), id="expired"
        ),
        pytest.param(lambda: id_token(GOOGLE, key=OTHER_KEY), id="wrong-key"),
        pytest.param(lambda: id_token(GOOGLE, kid="unknown"), id="unknown-kid"),
        pytest.param(
            lambda: jwt.encode(
                {"iss": GOOGLE, "aud": CLIENT, "sub": "x"},
                None,  # pyright: ignore[reportArgumentType] - alg none takes no key
                algorithm="none",
            ),
            id="alg-none",
        ),
        pytest.param(
            lambda: jwt.encode(
                {
                    "iss": GOOGLE,
                    "aud": CLIENT,
                    "sub": "x",
                    "exp": int(time.time()) + 60,
                    "iat": int(time.time()),
                },
                "s" * 32,
                algorithm="HS256",
                headers={"kid": "k1"},
            ),
            id="hs256-with-client-secret",
        ),
    ],
)
async def test_bad_id_tokens_are_rejected(token: Callable[[], str]) -> None:
    server = Server()
    server.oidc(GOOGLE)
    server.token_body = {"access_token": "at", "id_token": token()}
    with pytest.raises(AuthError) as error:
        await run(google(client_id=CLIENT, client_secret="s" * 32), server)
    assert error.value.code == "PROVIDER_ERROR"


async def test_missing_id_token() -> None:
    server = Server()
    server.oidc(GOOGLE)
    with pytest.raises(AuthError) as error:
        await run(google(client_id=CLIENT, client_secret="s"), server)
    assert error.value.code == "PROVIDER_ERROR"


MS = "https://login.microsoftonline.com/common/v2.0"


async def test_microsoft_common_checks_the_tenant_issuer() -> None:
    server = Server()
    server.oidc(MS, issuer="https://login.microsoftonline.com/{tenantid}/v2.0")
    good = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    server.token_body = {"access_token": "at", "id_token": id_token(good, tid=TENANT)}
    user = await run(microsoft(client_id=CLIENT, client_secret="s"), server)
    assert user.email == "ada@example.com"
    assert not user.email_verified  # no xms_edov claim
    server.token_body = {
        "access_token": "at",
        "id_token": id_token(good, tid="99999999-0000-0000-0000-000000000000"),
    }
    with pytest.raises(AuthError):
        await run(microsoft(client_id=CLIENT, client_secret="s"), server)


async def test_microsoft_xms_edov_proves_the_email() -> None:
    server = Server()
    server.oidc(MS, issuer="https://login.microsoftonline.com/{tenantid}/v2.0")
    good = f"https://login.microsoftonline.com/{TENANT}/v2.0"
    server.token_body = {
        "access_token": "at",
        "id_token": id_token(good, tid=TENANT, xms_edov=True),
    }
    user = await run(microsoft(client_id=CLIENT, client_secret="s"), server)
    assert user.email_verified


async def test_gitlab_self_hosted() -> None:
    base = "https://git.example.com"
    server = Server()
    server.oidc(base)
    server.token_body = {"access_token": "at", "id_token": id_token(base)}
    user = await run(
        gitlab(client_id=CLIENT, client_secret="s", base_url=base + "/"), server
    )
    assert user.id == "user-1"


async def test_apple_string_email_verified_and_form_post() -> None:
    base = "https://appleid.apple.com"
    server = Server()
    server.oidc(base)
    server.token_body = {
        "access_token": "at",
        "id_token": id_token(base, email_verified="true"),
    }
    provider = apple(client_id=CLIENT, client_secret="client-secret-jwt")
    assert provider.callback_method == "POST"
    async with server.client() as http:
        await provider.prepare(http)
    url = provider.authorization_url(
        state="s", code_challenge="c", redirect_uri="r", scopes=["name"], nonce="n-1"
    )
    assert parse_qs(urlsplit(url).query)["response_mode"] == ["form_post"]
    user = await run(provider, server)
    assert user.email_verified
    assert (
        provider.name_from_form('{"name": {"firstName": "Ada", "lastName": "L"}}')
        == "Ada L"
    )
    assert provider.name_from_form("not json") is None


async def test_generic_oidc() -> None:
    base = "https://id.example.com"
    server = Server()
    server.oidc(base)
    server.token_body = {
        "access_token": "at",
        "id_token": id_token(base, email_verified=False),
    }
    provider = generic_oidc(
        "acme",
        base + "/.well-known/openid-configuration",
        client_id=CLIENT,
        client_secret="s",
    )
    user = await run(provider, server)
    assert provider.id == "acme" and not user.email_verified


async def test_jwks_is_cached_and_refetched_on_rotation() -> None:
    base = "https://id.example.com"
    server = Server()
    server.oidc(base)
    now = [1000.0]
    cache = JwksCache(base + "/jwks", now=lambda: now[0])
    async with server.client() as http:
        await cache.key(http, "k1")
        await cache.key(http, "k1")
        fetches = sum(1 for r in server.requests if str(r.url).endswith("/jwks"))
        assert fetches == 1
        server.routes[base + "/jwks"] = {"keys": [jwk(OTHER_KEY, "k2")]}
        now[0] += 120
        await cache.key(http, "k2")  # unknown kid: one refetch
        with pytest.raises(AuthError):
            await cache.key(http, "k3")  # within a minute: no refetch storm
        fetches = sum(1 for r in server.requests if str(r.url).endswith("/jwks"))
        assert fetches == 2


def test_provider_tokens_are_left_out_of_repr() -> None:
    tokens = ProviderTokens(
        access_token="secret-at",
        refresh_token="secret-rt",
        id_token=None,
        expires_at=None,
        scope=None,
    )
    assert "secret" not in repr(tokens)
    assert "s" * 10 not in repr(github(client_id=CLIENT, client_secret="s" * 10))


def test_every_factory_returns_an_oauth_provider() -> None:
    # Checked by pyright: each factory's class satisfies the OAuthProvider protocol.
    made: list[OAuthProvider] = [
        github(client_id=CLIENT, client_secret="s"),
        google(client_id=CLIENT, client_secret="s"),
        microsoft(client_id=CLIENT, client_secret="s"),
        discord(client_id=CLIENT, client_secret="s"),
        gitlab(client_id=CLIENT, client_secret="s"),
        apple(client_id=CLIENT, client_secret="s"),
        generic_oidc(
            "x",
            "https://x/.well-known/openid-configuration",
            client_id=CLIENT,
            client_secret="s",
        ),
    ]
    assert len({p.id for p in made}) == 7
