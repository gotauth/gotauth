# Events

GotAuth tells your app what happened through one callback, `on_event`. Use it for audit
logs, analytics, welcome emails or syncing users to another system.

<!-- sample: run -->
```python
import asyncio

from gotauth.contracts import AuthEvent
from gotauth.testing import make_auth, make_client

seen: list[str] = []


async def on_event(event: AuthEvent) -> None:
    seen.append(event.type)


auth = make_auth(on_event=on_event, email_password={"require_email_verification": False})


async def check() -> None:
    async with make_client(auth) as client:
        await client.post(
            "/sign-up/email",
            json={"email": "ada@example.com", "password": "correct horse battery"},
        )
    await auth.drain()  # wait for deliveries
    assert "user.created" in seen and "sign_in.succeeded" in seen


asyncio.run(check())
```

## The event

| Field | Meaning |
|---|---|
| `id` | `evt_...` |
| `type` | One of the types below |
| `at` | When it happened (UTC) |
| `user_id` | The user concerned, if any |
| `principal` | Who acted; `principal.agent_id` is set when an agent acted |
| `ip_address`, `user_agent` | The client |
| `data` | Details. Never passwords, tokens or keys |

## Delivery

- Events are delivered after the transaction commits, so a rolled-back request sends
  none. The exception is `sign_in.failed`, which is delivered even on failure.
- Delivery always runs in the background, so responses don't wait for your callback.
  In tests and scripts, `await auth.drain()` before checking what was delivered.
- An error in `on_event` is logged and never fails the request.

## Types

| Area | Types |
|---|---|
| Users | `user.created`, `user.updated`, `user.deleted`, `user.email_verified`, `user.email_changed`, `user.role_changed`, `user.banned`, `user.unbanned` |
| Sign-in | `sign_in.succeeded`, `sign_in.failed`, `sign_out`, `session.revoked` |
| Passwords | `password.changed`, `password.reset` |
| Accounts | `account.linked`, `account.unlinked` |
| Two-factor and passkeys | `two_factor.enabled`, `two_factor.disabled`, `passkey.added`, `passkey.removed` |
| Keys and agents | `api_key.created`, `api_key.revoked`, `agent.created`, `agent.revoked` |
| OAuth server | `oauth.consent_granted`, `oauth.token_revoked`, `oauth.client_created` |
| Organizations | `org.created`, `org.deleted`, `org.member_added`, `org.member_removed`, `org.role_changed`, `org.invitation_sent`, `org.invitation_accepted` |
| Admin | `admin.impersonation_started`, `admin.impersonation_stopped` |
