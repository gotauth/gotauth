"""Admin (work package P6): user management for app administrators, bans and
audited impersonation::

    from gotauth.plugins.admin import admin

    auth = GotAuth(..., plugins=[admin(admin_user_ids=("usr_...",))])
"""

from __future__ import annotations

from gotauth.plugins.admin._plugin import admin

__all__ = ["admin"]
