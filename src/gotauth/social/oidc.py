"""OpenID Connect client helpers: discovery and ID token verification.

Kept separate from the providers so enterprise SSO (E1) can reuse them. Every network
call goes through the caller's ``httpx.AsyncClient`` (never blocking I/O), and every
failure becomes ``AuthError("PROVIDER_ERROR")``.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

import httpx

from gotauth.contracts.errors import AuthError

if TYPE_CHECKING:
    import jwt


def _jwt() -> Any:  # Any: the jwt module
    # Imported on first use: PyJWT loads cryptography, which probes optional modules
    # (bcrypt) that importing gotauth must not pull in.
    import jwt

    return jwt


__all__ = [
    "ALLOWED_ALGORITHMS",
    "Discovery",
    "DiscoveryCache",
    "JwksCache",
    "provider_error",
    "verify_id_token",
]

ALLOWED_ALGORITHMS: tuple[str, ...] = (
    "RS256",
    "RS384",
    "RS512",
    "PS256",
    "PS384",
    "PS512",
    "ES256",
    "ES384",
    "ES512",
    "EdDSA",
)
"""Asymmetric algorithms only: never ``none`` and never HS* (the client secret)."""

_TTL = 3600.0
_MISS_INTERVAL = 60.0  # at most one refetch a minute for unknown key ids
_LEEWAY = 60


def provider_error(detail: str) -> AuthError:
    """Return the error for any identity provider failure."""
    return AuthError("PROVIDER_ERROR", 502, detail)


async def fetch_json(
    http: httpx.AsyncClient, url: str, **kwargs: Any
) -> dict[str, Any]:  # Any: JSON
    """GET (or POST with ``data=``) a JSON object, or raise PROVIDER_ERROR."""
    try:
        if "data" in kwargs:
            response = await http.post(url, **kwargs)
        else:
            response = await http.get(url, **kwargs)
    except httpx.HTTPError as exc:
        raise provider_error(f"request failed ({type(exc).__name__})") from exc
    if response.status_code >= 400:
        raise provider_error(f"HTTP {response.status_code}")
    try:
        body = response.json()
    except ValueError as exc:
        raise provider_error("response is not JSON") from exc
    if not isinstance(body, dict):
        raise provider_error("response is not a JSON object")
    return cast("dict[str, Any]", body)


@dataclass(frozen=True)
class Discovery:
    """The parts of an OpenID provider configuration GotAuth uses."""

    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None = None
    algorithms: tuple[str, ...] = ("RS256",)


@dataclass
class DiscoveryCache:
    """Fetches ``.well-known/openid-configuration`` and keeps it for an hour."""

    url: str
    now: Callable[[], float] = time.monotonic
    _value: Discovery | None = field(default=None, init=False)
    _fetched: float = field(default=0.0, init=False)

    async def get(self, http: httpx.AsyncClient) -> Discovery:
        """Return the cached configuration, fetching it when stale."""
        if self._value is not None and self.now() - self._fetched < _TTL:
            return self._value
        body = await fetch_json(http, self.url)
        try:
            algorithms = tuple(
                a
                for a in body.get("id_token_signing_alg_values_supported", ["RS256"])
                if a in ALLOWED_ALGORITHMS
            )
            value = Discovery(
                issuer=str(body["issuer"]),
                authorization_endpoint=str(body["authorization_endpoint"]),
                token_endpoint=str(body["token_endpoint"]),
                jwks_uri=str(body["jwks_uri"]),
                userinfo_endpoint=body.get("userinfo_endpoint"),
                algorithms=algorithms or ("RS256",),
            )
        except (KeyError, TypeError) as exc:
            raise provider_error("incomplete discovery document") from exc
        self._value, self._fetched = value, self.now()
        return value


@dataclass
class JwksCache:
    """A JWKS kept for an hour and refetched once when a ``kid`` is unknown."""

    url: str
    now: Callable[[], float] = time.monotonic
    _keys: dict[str, jwt.PyJWK] = field(
        default_factory=lambda: dict[str, "jwt.PyJWK"](), init=False
    )
    _fetched: float = field(default=0.0, init=False)

    async def _refresh(self, http: httpx.AsyncClient) -> None:
        lib = _jwt()
        body = await fetch_json(http, self.url)
        keys: dict[str, jwt.PyJWK] = {}
        listed: object = body.get("keys", [])
        for entry in cast("list[object]", listed) if isinstance(listed, list) else []:
            if not isinstance(entry, dict):
                continue
            raw = cast("dict[str, Any]", entry)
            if raw.get("use", "sig") != "sig":
                continue
            try:
                key = lib.PyJWK(raw)
            except lib.PyJWTError:
                continue  # unsupported key types are skipped
            keys[str(raw.get("kid", ""))] = key
        self._keys, self._fetched = keys, self.now()

    async def key(self, http: httpx.AsyncClient, kid: str) -> jwt.PyJWK:
        """Return the key with this ``kid``.

        Raises:
            AuthError: PROVIDER_ERROR when the key is not in the JWKS.
        """
        age = self.now() - self._fetched
        if not self._keys or age >= _TTL:
            await self._refresh(http)
        elif kid not in self._keys and age >= _MISS_INTERVAL:
            await self._refresh(http)  # the provider may have rotated its keys
        found = self._keys.get(kid)
        if found is None:
            raise provider_error("unknown signing key")
        return found


async def verify_id_token(
    http: httpx.AsyncClient,
    token: str,
    *,
    jwks: JwksCache,
    audience: str,
    issuer: str | Callable[[Mapping[str, Any]], bool],
    nonce: str | None,
    algorithms: Sequence[str] = ("RS256",),
) -> dict[str, Any]:  # Any: JWT claims
    """Verify an ID token and return its claims.

    Checks the signature against the provider's JWKS with an asymmetric algorithm from
    ``algorithms``, then ``aud``, ``exp`` (60 seconds of leeway), ``iss`` (a value, or
    a function of the claims for multi-tenant issuers) and ``nonce``.

    Raises:
        AuthError: PROVIDER_ERROR for any failed check.
    """
    lib = _jwt()
    allowed = [a for a in algorithms if a in ALLOWED_ALGORITHMS]
    try:
        header = lib.get_unverified_header(token)
    except lib.PyJWTError as exc:
        raise provider_error("malformed ID token") from exc
    if header.get("alg") not in allowed:
        raise provider_error("ID token algorithm not allowed")
    key = await jwks.key(http, str(header.get("kid", "")))
    try:
        claims: dict[str, Any] = lib.decode(
            token,
            key=key.key,
            algorithms=allowed,
            audience=audience,
            leeway=_LEEWAY,
            options={"require": ["exp", "iat", "iss", "aud", "sub"]},
        )
    except lib.PyJWTError as exc:
        raise provider_error(f"ID token rejected ({type(exc).__name__})") from exc
    valid_issuer = (
        claims.get("iss") == issuer if isinstance(issuer, str) else issuer(claims)
    )
    if not valid_issuer:
        raise provider_error("ID token issuer mismatch")
    if nonce is not None and claims.get("nonce") != nonce:
        raise provider_error("ID token nonce mismatch")
    return claims
