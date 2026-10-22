"""Signing keys, JWKS and JWT signing and verification."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Any, cast

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwt.algorithms import ECAlgorithm, RSAAlgorithm

from gotauth.contracts.adapter import Adapter, SortBy, Where
from gotauth.contracts.crypto import CryptoKit
from gotauth.contracts.errors import AuthError
from gotauth.contracts.primitives import Clock, IdGenerator, to_timedelta

from ._rules import Settings

__all__ = ["KeyStore", "TokenRejected"]

_LEEWAY = 60  # seconds of clock skew allowed for iat


class TokenRejected(Exception):
    """A JWT failed verification; the message is safe to log, never the token."""


class PrincipalRefused(TokenRejected):
    """A principal check (CCR 015) refused the token; ``error`` is the check's own."""

    def __init__(self, error: AuthError) -> None:
        super().__init__(f"refused by a principal check: {error.code}")
        self.error = error
        self.code = error.code


def _generate(alg: str) -> Any:  # Any: a private key object
    if alg == "ES256":
        return ec.generate_private_key(ec.SECP256R1())
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _public_jwk(private_key: Any, alg: str, kid: str) -> dict[str, Any]:  # Any: JSON
    algorithm = ECAlgorithm if alg == "ES256" else RSAAlgorithm
    data = cast(dict[str, Any], json.loads(algorithm.to_jwk(private_key.public_key())))
    return {**data, "kid": kid, "alg": alg, "use": "sig"}


class KeyStore:
    """Keys in the ``jwk`` model; private keys encrypted (purpose ``jwk_private``)."""

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._private: dict[str, Any] = {}  # kid -> private key, decrypted lazily
        self._public: dict[str, Any] = {}  # kid -> public key

    async def create(
        self, adapter: Adapter, crypto: CryptoKit, clock: Clock, ids: IdGenerator
    ) -> dict[str, Any]:  # Any: the row
        """Create a signing key and retire the current one."""
        alg = self._settings.signing_alg
        private_key = _generate(alg)
        kid = ids.new("jwk")
        pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ).decode()
        now = clock.now()
        await adapter.update_many(
            "jwk", [Where("retired_at", True, "is_null")], {"retired_at": now}
        )
        row = await adapter.create(
            "jwk",
            {
                "id": kid,
                "kid": kid,
                "alg": alg,
                "public_jwk": _public_jwk(private_key, alg, kid),
                "private_key_enc": crypto.encrypt(pem, purpose="jwk_private"),
                "created_at": now,
            },
        )
        self._private[kid] = private_key
        return row

    async def ensure(
        self, adapter: Adapter, crypto: CryptoKit, clock: Clock, ids: IdGenerator
    ) -> None:
        """Create a key when there is no active one."""
        if await adapter.count("jwk", [Where("retired_at", True, "is_null")]) == 0:
            await self.create(adapter, crypto, clock, ids)

    async def published(
        self, adapter: Adapter, now: datetime
    ) -> list[dict[str, Any]]:  # Any: rows
        """Keys that can still verify: active, or retired less than one access-token
        lifetime ago."""
        rows = await adapter.find_many("jwk", sort_by=SortBy("created_at", "desc"))
        grace = to_timedelta(self._settings.access_token_ttl)
        return [
            row
            for row in rows
            if row.get("retired_at") is None or row["retired_at"] + grace > now
        ]

    async def jwks(
        self, adapter: Adapter, now: datetime
    ) -> dict[str, Any]:  # Any: JSON
        return {
            "keys": [row["public_jwk"] for row in await self.published(adapter, now)]
        }

    async def signer(
        self, adapter: Adapter, crypto: CryptoKit
    ) -> tuple[str, str, Any]:  # Any: the private key
        """The newest active key: ``(kid, alg, private_key)``."""
        rows = await adapter.find_many(
            "jwk",
            [Where("retired_at", True, "is_null")],
            sort_by=SortBy("created_at", "desc"),
            limit=1,
        )
        if not rows:
            msg = "no active signing key"
            raise RuntimeError(msg)
        row = rows[0]
        kid = str(row["kid"])
        key = self._private.get(kid)
        if key is None:
            stored = await adapter.find_one("jwk", [Where("kid", kid)])
            pem = crypto.decrypt(
                str((stored or {}).get("private_key_enc", "")), purpose="jwk_private"
            )
            if pem is None:
                msg = "signing key cannot be decrypted (secret changed?)"
                raise RuntimeError(msg)
            key = serialization.load_pem_private_key(pem.encode(), password=None)
            self._private[kid] = key
        return kid, str(row["alg"]), key

    @staticmethod
    def sign(
        claims: Mapping[str, Any], *, kid: str, alg: str, key: Any, typ: str
    ) -> str:  # Any: JSON, key
        return jwt.encode(
            dict(claims), key, algorithm=alg, headers={"kid": kid, "typ": typ}
        )

    async def verify(
        self,
        adapter: Adapter,
        now: datetime,
        token: str,
        *,
        typ: str,
        issuer: str,
        audiences: Sequence[str] | None,
    ) -> dict[str, Any]:  # Any: claims
        """Check signature (algorithm pinned per ``kid``), ``typ``, ``iss``, ``exp``
        and, unless ``audiences`` is ``None``, ``aud``.

        Raises:
            TokenRejected: On any failure.
        """
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise TokenRejected("malformed") from exc
        kid = header.get("kid")
        if not isinstance(kid, str):
            raise TokenRejected("no kid")
        rows = {str(row["kid"]): row for row in await self.published(adapter, now)}
        row = rows.get(kid)
        if row is None:
            raise TokenRejected("unknown kid")
        alg = str(row["alg"])
        if header.get("alg") != alg:
            raise TokenRejected("algorithm mismatch")
        if str(header.get("typ", "")).lower() != typ.lower():
            raise TokenRejected("wrong token type")
        public = self._public.get(kid)
        if public is None:
            public = jwt.PyJWK(cast(dict[str, Any], row["public_jwk"])).key
            self._public[kid] = public
        try:
            claims: dict[str, Any] = jwt.decode(
                token,
                key=public,
                algorithms=[alg],
                issuer=issuer,
                audience=list(audiences) if audiences is not None else None,
                options={
                    "require": ["exp", "iat", "iss", "sub", "jti"],
                    "verify_aud": audiences is not None,
                    # Times are checked below against GotAuth's clock, not the host's.
                    "verify_exp": False,
                    "verify_iat": False,
                },
            )
        except jwt.PyJWTError as exc:
            raise TokenRejected(type(exc).__name__) from exc
        moment = now.timestamp()
        exp, iat = claims.get("exp"), claims.get("iat")
        if not isinstance(exp, int | float) or moment >= exp:
            raise TokenRejected("expired")
        if not isinstance(iat, int | float) or iat > moment + _LEEWAY:
            raise TokenRejected("issued in the future")
        return claims
