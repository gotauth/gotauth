# Agents

When an AI agent acts for a user, give it its own identity instead of the user's
credentials. With the `agent` plugin:

- the agent has its own API keys and OAuth clients
- every request records which agent acted, and for whom (`principal.agent_id` and
  `principal.user_id`; events carry it too)
- one call revokes everything the agent holds, without touching the user's own sessions
  and keys

## Set up

<!-- sample: skip: a configuration fragment; the runnable version is below -->
```python
from gotauth.plugins.agent import agent
from gotauth.plugins.api_key import api_key
from gotauth.plugins.oauth_provider import oauth_provider

auth = GotAuth(..., plugins=[api_key(allowed_scopes=["projects:read"]), oauth_provider(), agent()])
```

`agent()` needs `api_key()`. `oauth_provider()` is needed only to link OAuth clients
(for example an MCP client) to an agent.

## An agent with its own key

<!-- sample: run -->
```python
import asyncio

from gotauth import AuthError
from gotauth.plugins.agent import agent
from gotauth.plugins.api_key import api_key
from gotauth.testing import make_auth, make_client

auth = make_auth(
    plugins=[api_key(allowed_scopes=["projects:read"]), agent()],
    email_password={"require_email_verification": False},
)


async def flow() -> None:
    async with make_client(auth) as browser:
        signed_up = await browser.post(
            "/sign-up/email",
            json={"email": "ada@example.com", "password": "correct horse battery"},
        )
        user_id = signed_up.json()["user"]["id"]
        bot = (await browser.post("/agents", json={"name": "Release bot"})).json()
        key = (
            await browser.post(
                f"/agents/{bot['id']}/api-keys",
                json={"name": "ci", "scopes": ["projects:read"]},
            )
        ).json()["key"]

        principal = await auth.get_principal({"x-api-key": key}, {})
        assert principal is not None
        assert (principal.agent_id, principal.user_id) == (bot["id"], user_id)

        # Revoking the agent revokes its keys at once (it needs a fresh session).
        revoked = await browser.post(f"/agents/{bot['id']}/revoke")
        assert revoked.status_code == 200, revoked.text
    try:
        await auth.get_principal({"x-api-key": key}, {})
    except AuthError as error:
        assert error.status == 401
    else:
        raise AssertionError("the agent's key still works")


asyncio.run(flow())
```

## Agents and OAuth

Link an OAuth client the user registered (for example the MCP client the agent runs
in) with `POST /agents/{id}/clients {client_id}`. Its access tokens then carry
`act: {"sub": "<agent id>"}`, so your MCP tools see `current_access().agent_id`.

## Organizations

With the [organization plugin](../plugins/organizations.md), an agent can belong to an
organization (`POST /agents {"organization_id": ...}`); its keys then act for the
organization, and the `agent` permissions decide who may create, read, update or revoke
it.

The [Agents plugin page](../plugins/agents.md) lists every endpoint and rule.
