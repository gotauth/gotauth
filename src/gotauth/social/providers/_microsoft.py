"""Microsoft Entra ID (OpenID Connect v2; checked against learn.microsoft.com on
2026-10-07)."""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import Any

from gotauth.contracts.social import ProviderUser

from ._base import OidcProvider, as_bool

__all__ = ["MicrosoftProvider"]

_MULTI_TENANT = ("common", "organizations", "consumers")


class MicrosoftProvider(OidcProvider):
    """Microsoft.

    For ``common``, ``organizations`` and ``consumers`` the issuer is checked against
    the token's own ``tid``. The email counts as verified only when the ``xms_edov``
    claim proves it, since tenant admins can set addresses nobody verified.
    """

    id = "microsoft"
    name = "Microsoft"

    def __init__(
        self,
        *,
        client_id: str,
        client_secret: str,
        tenant: str = "common",
        scopes: Sequence[str] = (),
        store_provider_tokens: bool = False,
    ) -> None:
        self.tenant = tenant
        self.discovery_url = (
            f"https://login.microsoftonline.com/{tenant}/v2.0"
            "/.well-known/openid-configuration"
        )
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            store_provider_tokens=store_provider_tokens,
        )

    def _issuer_check(self, issuer: str) -> str | Callable[[Mapping[str, Any]], bool]:
        if self.tenant not in _MULTI_TENANT:
            return issuer

        def matches(claims: Mapping[str, Any]) -> bool:
            tid = claims.get("tid")
            expected = f"https://login.microsoftonline.com/{tid}/v2.0"
            return isinstance(tid, str) and bool(tid) and claims.get("iss") == expected

        return matches

    def user_from_claims(self, claims: Mapping[str, Any]) -> ProviderUser:
        """Map claims; ``email_verified`` comes only from ``xms_edov``."""
        email = claims.get("email")
        return ProviderUser(
            id=str(claims["sub"]),
            email=email if isinstance(email, str) else None,
            email_verified=as_bool(claims.get("xms_edov")),
            name=claims.get("name"),
            image=None,
            raw=dict(claims),
        )
