"""Google (OpenID Connect; checked against developers.google.com on 2026-10-07)."""

from __future__ import annotations

from ._base import OidcProvider

__all__ = ["GoogleProvider"]


class GoogleProvider(OidcProvider):
    """Google, through its discovery document and verified ID tokens."""

    id = "google"
    name = "Google"
    discovery_url = "https://accounts.google.com/.well-known/openid-configuration"
