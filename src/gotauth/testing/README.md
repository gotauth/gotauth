# gotauth.testing

The GotAuth testing kit (CONTRACTS section 15). It is shipped with the package, so apps can test their own auth code the same way GotAuth does. It imports with the core dependencies only; pytest, hypothesis and the extras are imported inside the functions that need them.

## Unit tests from day one

```python
from gotauth.testing import call_endpoint, make_context

async def test_my_endpoint() -> None:
    ctx = make_context()                                   # every service faked
    user = await ctx.auth.create_user_record(ctx, {"email": "ada@example.com"})
    await ctx.sign_in(user.id)                             # session principal
    out = await call_endpoint(my_endpoint, {"name": "x"}, ctx=ctx)
```

`make_context()` gives a memory adapter with the core schema (plus `plugins=` schemas), a fake clock and ids, the real crypto kit, `fake_sessions()`, a mailer that records messages and a fake `auth` with `complete_sign_in`, `read_challenge`, `finish_challenge`, `create_user_record`, `delete_user` and `background`. `ctx.next_request()` carries the cookie jar to the next request, like a browser.

`call_endpoint` validates the input like the real pipeline (`INVALID_REQUEST` without echoing values) and enforces `auth` and `scopes`.

## Fakes and stubs

| Function | Use |
|---|---|
| `fake_clock()`, `seq_ids()` | Deterministic time and ids |
| `fake_mailer()` | `.sent`, `.last(kind, to)` |
| `fake_sessions()` | Sessions in the adapter, hashed `gas_` tokens |
| `fake_oauth_provider(users=...)` | Social login without the network; checks PKCE |
| `stub_resolver(prefix, principal)` | API-key or JWT principals before P1 and O1 exist |
| `stub_plugin(id, endpoints)` | Fake another plugin's CONTRACTS 12.5 endpoints; records `.calls` |
| `fresh_database_url(base_url)` | One Postgres database per test session, dropped afterwards |
| `load_vectors(name)` | Cases of `spec/<name>.json` |
| `adapter_conformance(factory)` | The section 3 test class every adapter subclasses |

## HTTP round trips

`make_auth(**overrides)` builds a real `GotAuth` with the fakes, and `make_client(auth)` returns an `httpx.AsyncClient` over `auth.asgi()` that keeps cookies and sends `Origin` and `Content-Type: application/json`. Both need the core (work package C1); until it merges, `make_auth` raises `NotImplementedError`.

`make_auth` and `make_context` hash passwords with `TEST_SCRYPT` (scrypt `ln=10,r=8,p=1`), about 1/100 of the cost of the production default, so tests that sign users up stay fast. To test with the real cost, pass your own kit: `make_auth(advanced={"crypto": crypto_kit([TEST_SECRET])})`.
