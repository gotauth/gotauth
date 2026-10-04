# gotauth.contracts

The shared interfaces every GotAuth module builds against: [docs/plan/CONTRACTS.md](../../../docs/plan/CONTRACTS.md) as typed code, one module per section.

| Module | CONTRACTS section |
|---|---|
| `primitives.py` | 1: `Clock`, `IdGenerator`, `Duration`, `to_timedelta` |
| `schema.py`, `core_schema.py` | 2: `Field`, `ModelSchema`, `merge_schemas`, the core models |
| `adapter.py` | 3: `Adapter`, `Where`, `SortBy` |
| `http.py` | 4: `AuthRequest`, `AuthResponse`, `SetCookie` |
| `endpoints.py` | 5: `Endpoint`, `Plugin`, `Hook`, interceptors, resolvers |
| `errors.py` | 6: `AuthError`, `ERROR_CODES`, `ConfigError`, `UniqueViolation`, `ReferenceViolation` |
| `sessions.py` | 7: `SessionService`, token prefixes, cookie names |
| `crypto.py` | 8: `CryptoKit`, `PasswordCheck`, purpose strings |
| `email.py` | 9: `EmailSender`, `EmailService`, `EmailMessage` |
| `protection.py` | 10: rate limits, `resolve_client_ip`, `validate_redirect` |
| `social.py` | 11: `OAuthProvider`, `ProviderUser` |
| `principal.py`, `oauth.py` | 12: `Principal`, plugin models, endpoint ids, cross-plugin call shapes |
| `config.py`, `http_models.py` | 13: configuration objects, response models, `CORE_ENDPOINTS` |
| `events.py` | 14: `AuthEvent`, `AUTH_EVENT_TYPES` |

```python
from gotauth.contracts import AuthError, Principal, Where

principal = Principal(via="api_key", credential_id="key_1", user_id="usr_1",
                      scopes=frozenset({"project:read"}))
assert principal.has_scopes("project:read")
```

The contracts are frozen at milestone M0. To change one, write a contract change request in `docs/ccr/` (see AGENTS.md). `tests/contracts/test_tables.py` parses CONTRACTS.md and fails when the code and the document disagree.

Only the core dependencies (pydantic, httpx, cryptography, PyJWT) are imported here.
