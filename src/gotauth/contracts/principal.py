"""CONTRACTS section 12.1: the principal every authenticated request resolves to."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Literal

__all__ = ["PRINCIPAL_PREFIXES", "Principal"]

PRINCIPAL_PREFIXES: Mapping[str, str] = MappingProxyType(
    {
        "gas_": "C3",
        "gak_": "P1",
        "eyJ": "O1",
    }
)
"""Credential prefix -> work package whose ``PrincipalResolver`` owns it (12.1)."""


@dataclass(frozen=True)
class Principal:
    """Who a request acts for, and with which rights.

    Attributes:
        via: How the credential was presented.
        credential_id: Session id, API key id or OAuth token id.
        user_id: The human the request acts for; never an agent or client id.
        agent_id: Set when an agent acts (O3).
        organization_id: ``session.active_organization_id``, or the owning org of a key.
        client_id: The OAuth client, when ``via == "oauth_token"``.
        scopes: Granted scopes; ``None`` means the full rights of a user session.
    """

    via: Literal["session", "api_key", "oauth_token"]
    credential_id: str
    user_id: str | None
    agent_id: str | None = None
    organization_id: str | None = None
    client_id: str | None = None
    scopes: frozenset[str] | None = None

    def has_scopes(self, *required: str) -> bool:
        """Return True if ``scopes`` is None or contains every required scope.

        Scopes are flat: no scope implies another, so this is exact containment.
        """
        if self.scopes is None:
            return True
        return self.scopes.issuperset(required)
