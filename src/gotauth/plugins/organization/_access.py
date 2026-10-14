"""Access control for organizations: statements (resource -> actions) and roles,
resolved once into frozen ``"resource:action"`` sets (CONTRACTS 12.1, 12.3)."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from types import MappingProxyType

from gotauth.contracts.errors import ConfigError
from gotauth.contracts.oauth import ORGANIZATION_STATEMENTS

__all__ = ["DEFAULT_ROLES", "AccessControl", "access_control"]

DEFAULT_ROLES = ("owner", "admin", "member")
"""``owner``: every permission. ``admin``: all but ``organization:delete``.
``member``: none."""


@dataclass(frozen=True)
class AccessControl:
    """Statements and roles, resolved.

    Attributes:
        statements: Every resource and its actions, built-in ones included.
        roles: Role name -> the ``"resource:action"`` permissions it grants.
    """

    statements: Mapping[str, frozenset[str]]
    roles: Mapping[str, frozenset[str]]

    def permissions(self, role: str | None) -> frozenset[str]:
        """What ``role`` grants; nothing for an unknown role."""
        return self.roles.get(role or "", frozenset())

    def allows(self, role: str | None, required: Mapping[str, Sequence[str]]) -> bool:
        """True if ``role`` grants every ``resource: [action]`` pair."""
        granted = self.permissions(role)
        return all(
            f"{resource}:{action}" in granted
            for resource, actions in required.items()
            for action in actions
        )


def _pairs(
    statements: Mapping[str, frozenset[str]],
    grants: Mapping[str, Sequence[str]],
    role: str,
) -> frozenset[str]:
    found: set[str] = set()
    for resource, actions in grants.items():
        known = statements.get(resource)
        if known is None:
            msg = (
                f"access_control(): role {role!r} names the unknown resource "
                f"{resource!r}"
            )
            raise ConfigError(msg)
        for action in actions:
            if action not in known:
                msg = (
                    f"access_control(): role {role!r} names the unknown action "
                    f"{resource}:{action}"
                )
                raise ConfigError(msg)
            found.add(f"{resource}:{action}")
    return frozenset(found)


def access_control(
    statements: Mapping[str, Sequence[str]] | None = None,
    roles: Mapping[str, Mapping[str, Sequence[str]]] | None = None,
) -> AccessControl:
    """Build the organization access control.

    Args:
        statements: App resources and their actions, e.g.
            ``{"project": ["create", "read", "update", "delete"]}``, added to the
            built-in ones (organization, member, invitation, api_key, agent).
        roles: Roles by name, each ``{resource: [action]}``. They replace the
            default role of the same name; the defaults stay otherwise. A
            permission is ``"resource:action"``, the same string as an API key or
            OAuth scope.

    Returns:
        The resolved access control.

    Raises:
        ConfigError: A role naming an unknown resource or action, or an app
            resource redefining a built-in one.
    """
    merged: dict[str, frozenset[str]] = {
        resource: frozenset(actions)
        for resource, actions in ORGANIZATION_STATEMENTS.items()
    }
    for resource, actions in (statements or {}).items():
        if resource in merged:
            msg = f"access_control(): {resource!r} is a built-in resource"
            raise ConfigError(msg)
        if ":" in resource or any(":" in action for action in actions):
            msg = "access_control(): resource and action names cannot contain ':'"
            raise ConfigError(msg)
        merged[resource] = frozenset(actions)
    everything = frozenset(
        f"{resource}:{action}"
        for resource, actions in merged.items()
        for action in actions
    )
    resolved: dict[str, frozenset[str]] = {
        "owner": everything,
        "admin": everything - {"organization:delete"},
        "member": frozenset(),
    }
    for name, grants in (roles or {}).items():
        resolved[name] = _pairs(merged, grants, name)
    return AccessControl(
        statements=MappingProxyType(merged), roles=MappingProxyType(resolved)
    )
