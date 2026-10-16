# Testing your auth

`gotauth.testing` ships with the package, so you test your app's auth the way GotAuth
tests itself: no real email, no real clock, no network.

## A full GotAuth in one line

`make_auth(**overrides)` builds a real `GotAuth` with an in-memory database, a test
secret, a fake mailer, a fake clock and cheap password hashing. Any `GotAuth` keyword
overrides the defaults. `make_client(auth)` gives an httpx client over it that keeps
cookies and sends the `Origin` header:

<!-- sample: run -->
```python
import asyncio
import re

from gotauth.testing import fake_clock, fake_mailer, make_auth, make_client

mailer = fake_mailer()
clock = fake_clock()
auth = make_auth(mailer=mailer, clock=clock)


async def sign_up_and_verify() -> None:
    async with make_client(auth) as client:
        body = {"email": "ada@example.com", "password": "correct horse battery"}
        assert (await client.post("/sign-up/email", json=body)).json() == {
            "status": "verification_sent"
        }
        email = mailer.last("verify_email", "ada@example.com")
        token = re.search(r"token=([^&\s]+)", email.text)
        assert token
        await client.get("/verify-email", params={"token": token.group(1)})
        assert (await client.post("/sign-in/email", json=body)).status_code == 200

        clock.advance("8d")  # past the 7-day session lifetime
        assert (await client.get("/session")).json() is None


asyncio.run(sign_up_and_verify())
```

## Your own FastAPI app

Build your app from a function that takes the `GotAuth`, and give the tests one from
`make_auth` (or your real configuration with `email_sender=fake_mailer()` and a test
database). `examples/fastapi-nextjs/backend/tests` does this against SQLite and Postgres
migrated with Alembic.

## Other helpers

| Helper | For |
|---|---|
| `fake_oauth_provider(users=...)` | Social login without the network |
| `SoftAuthenticator` (`gotauth.plugins.passkey.testing`) | Passkey registration and sign-in |
| `gotauth.crypto.totp(secret, at=...)` | Two-factor codes |
| `stub_resolver(prefix, principal)` | A principal for an API key or token without creating it |
| `fresh_database_url(url)` | One Postgres database per test session |
| `await auth.drain()` | Wait for background emails and events |

The [testing kit page](../modules/testing.md) covers unit tests of endpoints and plugins.
