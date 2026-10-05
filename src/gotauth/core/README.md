# gotauth.core

The `GotAuth` class: it validates the configuration, assembles the core and the plugins, and runs every request through one fail-closed pipeline (CONTRACTS sections 4, 5, 6, 10, 12.1, 13 and 14).

```python
from gotauth import GotAuth
from gotauth.storage.memory import memory_adapter

auth = GotAuth(
    database=memory_adapter(),
    secret="a-secret-of-at-least-32-characters-long",
    base_url="https://api.example.com",
)
app.mount("/api/auth", auth.asgi())     # any ASGI framework
app.mount("/", auth.well_known())       # host-root metadata (OAuth server)
```

## Pipeline
Every request goes through the same steps, in this order:

1. route match (unknown or `server_only` endpoints are NOT_FOUND)
2. content-type check: JSON endpoints need `application/json`, form endpoints `application/x-www-form-urlencoded`; empty bodies are exempt
3. IP and IP + path rate limits
4. parse and validate the input; errors never echo submitted values
5. principal resolution (bearer, `x-api-key`, then the session cookie) and principal checks; enforce `auth`, `scopes` and `fresh_session`
6. origin check for cookie-authenticated POST, PATCH and DELETE
7. identifier and principal rate limits
8. before hooks, handler, after hooks, all in one transaction; writes run the database hooks
9. events are delivered to `on_event` after commit; only `sign_in.failed` survives a rollback

Unexpected exceptions anywhere become `INTERNAL_ERROR` (500) and never grant access. Endpoints with `error_format="oauth"` render every error in the RFC 6749 shape through `OAUTH_ERROR_MAP`.

## Core services
`complete_sign_in`, `read_challenge`, `finish_challenge`, `create_user_record`, `delete_user`, `background` and `drain`, plus `auth.api` for server-side calls. `auth.api.call(id, ..., ctx=ctx)` joins the caller's transaction, which is how plugins call each other.

## Testing before the core modules exist
`advanced={"install_core_plugins": False, "session_service": fake_sessions()}` builds a `GotAuth` without the sessions, email + password and social modules.
