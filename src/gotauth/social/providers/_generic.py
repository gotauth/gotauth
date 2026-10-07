"""Any OpenID Connect provider, from its discovery URL."""

from __future__ import annotations

from collections.abc import Sequence

from ._base import OidcProvider

__all__ = ["GenericOidcProvider"]


class GenericOidcProvider(OidcProvider):
    """A provider configured only by ``id`` and ``discovery_url``."""

    def __init__(
        self,
        id: str,
        discovery_url: str,
        *,
        client_id: str,
        client_secret: str,
        name: str | None = None,
        scopes: Sequence[str] = (),
        store_provider_tokens: bool = False,
    ) -> None:
        self.id = id
        self.name = name or id
        self.discovery_url = discovery_url
        super().__init__(
            client_id=client_id,
            client_secret=client_secret,
            scopes=scopes,
            store_provider_tokens=store_provider_tokens,
        )
