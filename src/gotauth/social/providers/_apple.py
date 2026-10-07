"""Sign in with Apple (OpenID Connect with form_post; checked against
developer.apple.com on 2026-10-07)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any, ClassVar, Literal, cast

from gotauth.contracts.social import ProviderUser

from ._base import OidcProvider, as_bool

__all__ = ["AppleProvider"]


class AppleProvider(OidcProvider):
    """Apple.

    ``client_secret`` is the signed client-secret JWT that Apple requires. The name is
    sent only on the first sign-in, in the form ``user`` field.
    """

    id = "apple"
    name = "Apple"
    default_scopes: tuple[str, ...] = ("name", "email")
    callback_method: Literal["GET", "POST"] = "POST"
    discovery_url = "https://appleid.apple.com/.well-known/openid-configuration"
    extra_authorize_params: ClassVar[Mapping[str, str]] = {"response_mode": "form_post"}

    def user_from_claims(self, claims: Mapping[str, Any]) -> ProviderUser:
        """Map claims; Apple sends ``email_verified`` as a string."""
        email = claims.get("email")
        return ProviderUser(
            id=str(claims["sub"]),
            email=email if isinstance(email, str) else None,
            email_verified=as_bool(claims.get("email_verified")),
            name=None,
            image=None,
            raw=dict(claims),
        )

    @staticmethod
    def name_from_form(user_field: str | None) -> str | None:
        """Read the display name from Apple's first-sign-in ``user`` form field."""
        if not user_field:
            return None
        try:
            data = json.loads(user_field)
        except ValueError:
            return None
        if not isinstance(data, dict):
            return None
        name = cast("dict[str, Any]", data).get("name")
        if not isinstance(name, dict):
            return None
        parts = cast("dict[str, Any]", name)
        full = " ".join(
            str(part)
            for part in (parts.get("firstName"), parts.get("lastName"))
            if isinstance(part, str) and part
        )
        return full or None
