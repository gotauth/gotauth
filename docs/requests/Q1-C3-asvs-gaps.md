# Q1: session gaps from the ASVS mapping

| | |
|---|---|
| From | Q1 (`docs/security/asvs.md`) |
| For | C3 (`src/gotauth/sessions/`) and C1 (`complete_sign_in` in `src/gotauth/core/`); item 1 adds config, so it needs a CCR |
| Date | 2026-10-10 |

## What and why

### 1. No absolute session lifetime (ASVS 7.3.2 and 7.1.1, Level 2)
Sessions slide: each use after `update_age` (1 day) pushes `expires_at` to now plus `expires_in` (7 days). A session used at least weekly never ends, so a stolen token works for as long as the thief keeps using it.

**Proposed:** add `sessions={"absolute_lifetime": "30d"}` (default 30 days; `None` turns it off). When sliding, use `min(now + expires_in, created_at + absolute_lifetime)`. A test needs a session refreshed daily for 31 days that then expires.

### 2. The session presented at sign-in is not ended (ASVS 7.2.4, Level 1)
Sign-in always issues a new token (`sec/test_requests.py::test_a_planted_session_cookie_is_never_adopted`). But a valid session cookie sent with the sign-in request keeps working afterwards (`tests/sessions/test_service.py::test_each_create_makes_a_new_token_even_when_one_is_presented` checks only that the token is new). The ASVS item asks that re-authentication end the current token.

**Proposed:** in `complete_sign_in`, when the request carries a valid session cookie, revoke that session after creating the new one. Do not do this for bearer tokens, which belong to other clients. No contract change is needed.

## In the meantime
`docs/security/asvs.md` records 7.3.2 as not met, and 7.1.1 and 7.2.4 as partial.
