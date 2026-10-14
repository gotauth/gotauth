"""Organizations (work package P5): organizations, members, roles, invitations and
app-defined permissions, and ``has_permission`` for A1, P1 and O3::

    from gotauth.plugins.organization import access_control, organization

    access = access_control(
        statements={"project": ["create", "read", "update", "delete"]},
        roles={"member": {"project": ["read"]}},
    )
    auth = GotAuth(..., plugins=[organization(access=access)])
"""

from __future__ import annotations

from gotauth.plugins.organization._access import AccessControl, access_control
from gotauth.plugins.organization._plugin import organization

__all__ = ["AccessControl", "access_control", "organization"]
