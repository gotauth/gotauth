# Plugins and hooks

Everything beyond email, password, sessions and social login is a plugin: API keys,
two-factor, passkeys, organizations, the OAuth server, agents and admin. You add them in
one list:

<!-- sample: skip: a configuration fragment -->
```python
from gotauth.plugins.api_key import api_key
from gotauth.plugins.two_factor import two_factor

auth = GotAuth(..., plugins=[api_key(allowed_scopes=["projects:read"]), two_factor()])
```

Import each plugin from its own module (`gotauth.plugins.api_key`), never from
`gotauth.plugins`. After adding one, create its tables: see
[Schema and migrations](schema-and-migrations.md).

## What a plugin can add

A plugin is a `Plugin` value with:

- **endpoints**, served under the same mount (`/api-keys`, `/two-factor/...`)
- **schema**: new models, or new fields on `user` and `session`
- **hooks** before or after endpoints, and **database hooks** around writes
- **sign-in interceptors**, which can require another step (two-factor) or block a
  sign-in (bans)
- **principal resolvers** for new credentials, and **principal checks** run on every
  request
- **error codes** and **rate limits**

Plugins never import each other: they call each other's endpoints through
`ctx.auth.api.call(..., ctx=ctx)`, in the same transaction.

## Hooks in your app

You can hook the core and plugin endpoints without writing a plugin. A `before` hook can
refuse a request; an `after` hook can replace the response:

<!-- sample: run -->
```python
import asyncio

from gotauth.contracts import AuthError, EndpointContext, Hook, HookPayload
from gotauth.testing import make_auth, make_client


async def company_emails_only(ctx: EndpointContext, payload: HookPayload) -> None:
    if not payload.input.email.endswith("@example.com"):
        raise AuthError("FORBIDDEN", 403, "Sign up with your company email")


auth = make_auth(hooks=[Hook("before", ("sign_up_email",), company_emails_only)])


async def check() -> None:
    async with make_client(auth) as client:
        body = {"email": "eve@other.test", "password": "correct horse battery"}
        refused = await client.post("/sign-up/email", json=body)
        assert refused.status_code == 403
        assert refused.json()["error"]["message"] == "Sign up with your company email"


asyncio.run(check())
```

Endpoint ids are the operation ids in the OpenAPI document: `sign_up_email`,
`sign_in_email`, `create_api_key`, and so on.

## Database hooks

`database_hooks=DatabaseHooks(hooks={"user": ModelHooks(before_create=...)})` runs around
writes the core and plugins make: a `before_*` hook can change the row or raise
`AuthError`. Use them to create your own profile row when a user is created, or to clean
up your data when a user is deleted (`after_delete`).

## Sign-in interceptors and principal checks

These are for plugins. Every sign-in method goes through `complete_sign_in`, which runs
the interceptors after the credentials are verified: two-factor answers with a
challenge, the admin plugin refuses banned users. Principal checks run after any
credential is resolved, on every request.
