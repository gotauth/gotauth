"""Agent identities (work package O3): AI agents owned by a user or an organization,
with their own API keys and OAuth clients. Every request records which agent acted
for whom, and one call revokes everything an agent holds::

    from gotauth.plugins.agent import agent

    auth = GotAuth(..., plugins=[api_key(), oauth_provider(), agent()])
"""

from __future__ import annotations

from gotauth.plugins.agent._plugin import agent

__all__ = ["agent"]
