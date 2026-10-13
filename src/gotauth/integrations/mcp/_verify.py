"""Access token verification: in the same process through O1's
``verify_access_token``, or remotely through discovery, JWKS and optional RFC 7662
introspection (CONTRACTS 12.4)."""

from __future__ import annotations

import asyncio
import hashlib
import time
from collections import OrderedDict
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, cast
from urllib.parse import urlsplit

import httpx
import jwt

from gotauth.contracts.errors import ConfigError
from gotauth.integrations.mcp._access import GotAuthAccess
from gotauth.integrations.mcp._metadata import normalize_resource

if TYPE_CHECKING:
    from gotauth.contracts.config import GotAuthInstance

__all__ = [
    "LocalVerifier",
    "RemoteVerifier",
    "Verified",
    "Verifier",
    "VerifierUnavailable",
    "build_verifier",
]

ASYMMETRIC = frozenset(
    {"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"}
)
"""Algorithms a remote key may use; ``none`` and ``HS*`` never verify."""

JWKS_REFETCH_SECONDS = 30.0
"""The least time between two JWKS fetch attempts, failed ones included."""
JWKS_MAX_AGE_SECONDS = 300.0
"""Keys are refreshed after this, so a key the issuer removed stops verifying."""
LEEWAY_SECONDS = 30
"""Allowed clock difference with the issuer for ``exp``, ``nbf`` and ``iat``."""
INTROSPECTION_CACHE_SECONDS = 5.0
_INTROSPECTION_CACHE_SIZE = 1024
_TIMEOUT = httpx.Timeout(5.0)


class VerifierUnavailable(Exception):
    """The authorization server could not be reached: a 503, not a 401."""


@dataclass(frozen=True)
class Verified:
    """A token that passed every check."""

    access: GotAuthAccess
    claims: Mapping[str, Any]  # Any: JWT claims


class Verifier(Protocol):
    """Checks one access token for one resource."""

    issuer: str
    resource: str

    async def verify(self, token: str) -> Verified | None:
        """The verified token, or ``None`` when it must be rejected.

        Raises:
            VerifierUnavailable: When the authorization server cannot be reached.
        """
        ...


def _string(value: Any) -> str | None:  # Any: a JSON value
    return value if isinstance(value, str) and value else None


def _object(value: Any) -> dict[str, Any] | None:  # Any: JSON
    """A JSON object, or ``None`` for anything else."""
    return cast(dict[str, Any], value) if isinstance(value, dict) else None


class LocalVerifier:
    """Same process: O1's ``verify_access_token`` checks the signature, ``typ``,
    ``iss``, ``exp``, ``aud``, revocation and disabled clients and agents, so a
    revocation takes effect on the next call."""

    def __init__(self, auth: GotAuthInstance, resource: str) -> None:
        if "oauth_provider" not in auth.plugin_ids:
            msg = (
                "fastmcp_auth(auth=...) needs the oauth_provider plugin on that GotAuth"
            )
            raise ConfigError(msg)
        self._auth = auth
        self.resource = resource
        self.issuer = auth.config.base_url.rstrip("/") + auth.config.base_path.rstrip(
            "/"
        )

    async def verify(self, token: str) -> Verified | None:
        out = await self._auth.api.call(
            "verify_access_token", body={"token": token, "resource": self.resource}
        )
        principal = out.principal
        if not out.valid or principal is None or principal.via != "oauth_token":
            return None
        # O1 has checked the signature; read the claims it signed.
        claims = jwt.decode(token, options={"verify_signature": False})
        access = GotAuthAccess(
            user_id=principal.user_id,
            agent_id=principal.agent_id,
            client_id=principal.client_id or "",
            scopes=principal.scopes or frozenset(),
            jti=principal.credential_id,
            expires_at=claims.get("exp"),
        )
        return Verified(access, claims)


def new_http_client() -> httpx.AsyncClient:
    """The HTTP client of a remote verifier (tests replace this)."""
    return httpx.AsyncClient(timeout=_TIMEOUT, follow_redirects=False)


class RemoteVerifier:
    """Another process: the issuer's metadata and JWKS, cached.

    A key is used only with its own ``alg``. The JWKS is refreshed every 5 minutes,
    and an unknown ``kid`` refetches it, but never more than once per 30 seconds,
    failed attempts included. While the issuer is down the last keys stay in use.
    Without introspection a revoked token works until it expires (10 minutes by
    default); with it, revocation is seen within 5 seconds.
    """

    def __init__(
        self,
        issuer: str,
        resource: str,
        *,
        introspection_client: tuple[str, str] | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.issuer = issuer.rstrip("/")
        self.resource = resource
        self._client_auth = introspection_client
        self._clock = clock
        self._http: httpx.AsyncClient | None = None
        self._metadata: dict[str, Any] | None = None  # Any: JSON
        self._keys: dict[str, dict[str, Any]] = {}  # Any: JWK members
        self._fetched_at: float | None = None
        self._attempted_at: float | None = None
        self._lock = asyncio.Lock()
        self._introspected: OrderedDict[str, tuple[bool, float]] = OrderedDict()

    def _client(self) -> httpx.AsyncClient:
        if self._http is None:
            self._http = new_http_client()
        return self._http

    async def _get_json(self, url: str, **kwargs: Any) -> Any:  # Any: JSON
        try:
            response = await self._client().request(
                kwargs.pop("method", "GET"), url, **kwargs
            )
        except httpx.HTTPError as exc:
            raise VerifierUnavailable(url) from exc
        if response.status_code != 200:
            raise VerifierUnavailable(f"{url}: HTTP {response.status_code}")
        try:
            return response.json()
        except ValueError as exc:
            raise VerifierUnavailable(f"{url}: not JSON") from exc

    async def metadata(self) -> dict[str, Any]:  # Any: JSON
        """The issuer's RFC 8414 metadata (path-insertion form first, then OIDC)."""
        if self._metadata is None:
            parts = urlsplit(self.issuer)
            origin = f"{parts.scheme}://{parts.netloc}"
            candidates = (
                f"{origin}/.well-known/oauth-authorization-server{parts.path}",
                f"{self.issuer}/.well-known/openid-configuration",
            )
            last: VerifierUnavailable | None = None
            for url in candidates:
                try:
                    found = await self._get_json(url)
                except VerifierUnavailable as exc:
                    last = exc
                    continue
                document = _object(found)
                if document is not None and document.get("issuer") == self.issuer:
                    self._metadata = document
                    break
            if self._metadata is None:
                raise last or VerifierUnavailable("no metadata for the issuer")
        return self._metadata

    async def _key(self, kid: str) -> dict[str, Any] | None:  # Any: JWK members
        fetched = self._fetched_at
        if (
            kid in self._keys
            and fetched is not None
            and self._clock() - fetched < JWKS_MAX_AGE_SECONDS
        ):
            return self._keys[kid]  # the common case: no lock, no network
        async with self._lock:
            now = self._clock()
            stale = (
                self._fetched_at is None
                or now - self._fetched_at >= JWKS_MAX_AGE_SECONDS
            )
            allowed = (
                self._attempted_at is None
                or now - self._attempted_at >= JWKS_REFETCH_SECONDS
            )
            if (stale or kid not in self._keys) and allowed:
                self._attempted_at = now
                try:
                    await self._refresh()
                    self._fetched_at = now
                except VerifierUnavailable:
                    if self._fetched_at is None:
                        raise
                    # The issuer is down: keep the keys fetched last time.
            elif self._fetched_at is None:
                msg = "the issuer could not be reached; retrying in 30 seconds"
                raise VerifierUnavailable(msg)
            return self._keys.get(kid)

    async def _refresh(self) -> None:
        jwks_uri = _string((await self.metadata()).get("jwks_uri"))
        if jwks_uri is None:
            raise VerifierUnavailable("the issuer has no jwks_uri")
        found = await self._get_json(jwks_uri)
        keys = (_object(found) or {}).get("keys")
        members = cast(list[Any], keys) if isinstance(keys, list) else []
        fresh: dict[str, dict[str, Any]] = {}  # Any: JWK members
        for member in members:
            jwk = _object(member)
            if jwk is not None and isinstance(jwk.get("kid"), str):
                fresh[str(jwk["kid"])] = jwk
        self._keys = fresh

    async def verify(self, token: str) -> Verified | None:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.InvalidTokenError:
            return None
        kid, alg = header.get("kid"), header.get("alg")
        typ = str(header.get("typ", "")).lower()
        if not isinstance(kid, str) or typ not in ("at+jwt", "application/at+jwt"):
            return None
        jwk = await self._key(kid)
        if jwk is None or jwk.get("alg") not in ASYMMETRIC or alg != jwk.get("alg"):
            return None
        try:
            key = jwt.PyJWK(jwk, algorithm=str(alg))
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[str(alg)],
                audience=self.resource,
                issuer=self.issuer,
                options={"require": ["exp", "iss", "aud", "sub", "jti"]},
                leeway=LEEWAY_SECONDS,
            )
        except (jwt.InvalidTokenError, jwt.PyJWKError):
            return None
        if self._client_auth is not None and not await self._active(token):
            return None
        return Verified(_remote_access(claims), claims)

    async def _active(self, token: str) -> bool:
        cache_key = hashlib.sha256(token.encode()).hexdigest()
        now = self._clock()
        cached = self._introspected.get(cache_key)
        if cached is not None and cached[1] > now:
            return cached[0]
        endpoint = _string((await self.metadata()).get("introspection_endpoint"))
        if endpoint is None or self._client_auth is None:
            raise VerifierUnavailable("the issuer has no introspection_endpoint")
        found = await self._get_json(
            endpoint,
            method="POST",
            data={"token": token, "token_type_hint": "access_token"},
            auth=self._client_auth,
        )
        active = (_object(found) or {}).get("active") is True
        self._introspected[cache_key] = (active, now + INTROSPECTION_CACHE_SECONDS)
        while len(self._introspected) > _INTROSPECTION_CACHE_SIZE:
            self._introspected.popitem(last=False)
        return active


def _remote_access(claims: Mapping[str, Any]) -> GotAuthAccess:  # Any: JWT claims
    act = claims.get("act")
    agent_id = _string((_object(act) or {}).get("sub"))
    client_id = _string(claims.get("client_id")) or _string(claims.get("azp")) or ""
    subject = _string(claims.get("sub"))
    # A client_credentials token's sub is the client or its agent, never a user.
    user_id = None if subject in (client_id, agent_id) else subject
    scope = claims.get("scope")
    return GotAuthAccess(
        user_id=user_id,
        agent_id=agent_id,
        client_id=client_id,
        scopes=frozenset(scope.split()) if isinstance(scope, str) else frozenset(),
        jti=str(claims["jti"]),
        expires_at=claims.get("exp"),
    )


def build_verifier(
    auth: GotAuthInstance | None,
    *,
    issuer: str | None,
    resource: str,
    introspect: bool,
    introspection_client: tuple[str, str] | None,
) -> Verifier:
    """The verifier for ``fastmcp_auth`` and ``mcp_sdk_auth``.

    Raises:
        ConfigError: Unless exactly one of ``auth`` and ``issuer`` is given, for a bad
            ``resource``, or for ``introspect=True`` with ``issuer`` and no
            ``introspection_client``.
    """
    if (auth is None) == (issuer is None):
        msg = "pass exactly one of auth (same process) and issuer (remote)"
        raise ConfigError(msg)
    normalized = normalize_resource(resource)
    if auth is not None:
        return LocalVerifier(auth, normalized)  # introspect is not needed here
    if introspect and introspection_client is None:
        msg = "introspect=True needs introspection_client=(client_id, client_secret)"
        raise ConfigError(msg)
    return RemoteVerifier(
        cast(str, issuer),
        normalized,
        introspection_client=introspection_client if introspect else None,
    )
