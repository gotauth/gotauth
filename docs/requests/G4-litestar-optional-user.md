# G4: an optional user dependency for Litestar

| | |
|---|---|
| From | G4 (examples), code review of `examples/litestar-htmx` |
| For | A2 (`src/gotauth/integrations/asgi/litestar.py`) |
| Date | 2026-10-12 |
| Status | Applied 2026-10-13 (issue #9); the example uses `optional_user` |

## What
Add an `optional_user` dependency (`User | None`) to `GotAuthPlugin`, next to `principal` and `current_user`. It should resolve the session once, keep the sliding cookie refresh that `principal` does, and return `None` when there is no session or a bad credential. That matches FastAPI's `auth.fastapi.optional_user`.

## Why
A page that shows the user's email when signed in, and a sign-in link otherwise, has no single dependency today:
- `current_user` answers 401 when nobody is signed in.
- `principal` has no user fields.

So `examples/litestar-htmx/app/main.py` takes `principal`, which keeps the session cookie fresh, and then calls `get_session` again for the email. That reads the session three times per page.

With `optional_user`, the example's `signed_in` helper and its extra `get_session` call go away. The example stays as it is until then.
