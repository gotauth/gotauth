# GotAuth contracts (version 0)

This file defines the **shared interfaces every work package builds against**. Work package F2 turns it into code in `src/gotauth/contracts/`, one module per section. That code is the source of truth when the two differ. After milestone **M0** the contracts are **frozen**: any change needs a contract change request (see [AGENT-RULES.md](AGENT-RULES.md)).

Agents can work in parallel because each module implements one interface and depends only on the *other* modules' interfaces, never on their code.

```python
CONTRACT_VERSION = 0
```

**Revision note (pre-M0):** this version settles the gaps the three brief-writing passes reported. The topics:
- challenge completion, sign-in methods and blocking checks
- form-encoded and OAuth-format endpoints
- per-identifier rate limits
- background email
- endpoint ids for API keys, the OAuth server and agents
- token revocation semantics
- model fixes (`unique_together`, `remember_me`, optional OAuth token fields)
- table prefix
- entry points and import paths

---

## 0. Ground rules for all code
- **Python >= 3.11**, fully typed, and pyright strict passes. `from __future__ import annotations` in every module.
- **Async-first.** Every I/O method is `async def`. CPU-heavy work (password hashing) runs in a worker thread through the crypto kit.
- **Core runtime dependencies:** `pydantic>=2`, `httpx`, `cryptography`, `PyJWT`. Nothing else in the core. Everything else goes behind an extra and is imported lazily:

  | Extra | Pulls in |
  |---|---|
  | `fastapi` | fastapi |
  | `starlette` | starlette |
  | `litestar` | litestar |
  | `sqlalchemy` | sqlalchemy[asyncio], alembic |
  | `postgres` | asyncpg |
  | `sqlite` | aiosqlite |
  | `redis` | redis |
  | `argon2` | argon2-cffi |
  | `bcrypt` | bcrypt |
  | `passkey` | webauthn |
  | `mcp` | mcp, fastmcp |
  | `smtp` | aiosmtplib |
  | `flask`, `django`, `sqlmodel` | Phase 4 only (A3, S2), added through a request when those start |
- **Only F1 edits `pyproject.toml`.** Every dev dependency the briefs allow is added up front by F1. Anything else needs a request file.
- **No framework imports** outside `src/gotauth/integrations/*`.
- **Datetimes** are timezone-aware UTC everywhere. Storage keeps them as UTC; JSON uses ISO-8601 with `Z`.
- **Fail closed.** An unexpected exception while authenticating or authorizing becomes `AuthError("INTERNAL_ERROR", 500)` and never yields a principal.
- **Naming:**

  | What | Convention |
  |---|---|
  | Python identifiers and JSON fields | `snake_case` |
  | URL paths | `kebab-case` |
  | Table names | `snake_case`, singular, prefixed with `advanced.table_prefix` (default `"auth_"`, e.g. `auth_user`). The prefix avoids clashes with an app's existing `user` table |
  | Endpoint ids | `snake_case`, **verb first** (`send_magic_link`, `create_api_key`). Exception: OAuth protocol endpoints are `oauth_<endpoint>` (`oauth_token`) |

## 1. Primitives
```python
from datetime import datetime, timedelta
from typing import Literal, Protocol

class Clock(Protocol):
    def now(self) -> datetime: ...                  # timezone-aware UTC

IdPrefix = Literal[
    "usr", "acc", "ses", "ver", "key", "org", "mem", "inv", "tem", "tmm",
    "agt", "cli", "ocn", "cod", "tok", "pky", "tfa", "jwk", "rlt", "evt",
]

class IdGenerator(Protocol):
    def new(self, prefix: IdPrefix) -> str: ...      # e.g. "usr_01J9Z3...": prefix + "_" + 26-char ULID

Duration = int | timedelta | str                    # int = seconds; str like "90s", "15m", "12h", "7d"
def to_timedelta(value: Duration) -> timedelta: ...  # raises ValueError on bad input

class SystemClock: ...                               # default Clock
class UlidIds: ...                                   # default IdGenerator (monotonic ULIDs from the crypto kit)
```
**Imported rows** (I1) may keep their original ids, e.g. UUID strings. Code must treat ids as opaque strings and never parse the prefix.

## 2. Schema
Plugins add models and fields; adapters and the `gotauth generate` CLI read the merged schema.

```python
from dataclasses import dataclass, field as dc_field
from typing import Any, Callable, Mapping

FieldType = Literal["string", "text", "integer", "boolean", "datetime", "json", "string_list"]

@dataclass(frozen=True)
class Reference:
    model: str                                       # logical model name, e.g. "user"
    field: str = "id"
    on_delete: Literal["cascade", "set_null", "restrict"] = "cascade"

@dataclass(frozen=True)
class Field:
    type: FieldType
    required: bool = True
    unique: bool = False
    index: bool = False
    references: Reference | None = None
    default: Any | Callable[[], Any] | None = None   # applied by the core, not the database
    returned: bool = True                            # False: never included in API output
    input: bool = True                               # False: clients can't set it
    max_length: int | None = None

@dataclass(frozen=True)
class ModelSchema:
    name: str                                        # logical name, e.g. "session"
    fields: Mapping[str, Field]                      # "id" (string primary key) is implicit; never listed
    unique_together: tuple[tuple[str, ...], ...] = ()
    table: str | None = None                         # default: advanced.table_prefix + name

Schema = Mapping[str, ModelSchema]

def merge_schemas(base: Schema, *extra: Schema) -> Schema: ...
# Adding a new model or new fields to an existing model is allowed.
# Redefining an existing field raises SchemaConflictError at GotAuth(...) construction.
```

### 2.1 Core models
| Model | Fields (besides `id`) |
|---|---|
| `user` | `email` (string, unique, stored lower-case), `email_verified` (bool, default False), `name` (string, optional), `image` (string, optional), `created_at`, `updated_at` |
| `account` | `user_id` -> user (cascade), `provider_id` (string; `"credential"` for email + password), `account_id` (string; the provider's user id, or the user id for credentials), `password_hash` (string, optional, `returned=False`), `access_token_enc` / `refresh_token_enc` / `id_token_enc` (text, optional, `returned=False`; AES-GCM, purpose `"account_token"`; stored only when the provider was created with `store_provider_tokens=True`), `access_token_expires_at` (datetime, optional), `scope` (string, optional), `created_at`, `updated_at`. `unique_together = (("provider_id", "account_id"),)` |
| `session` | `user_id` -> user (cascade), `token_hash` (string, unique, `returned=False`), `expires_at`, `remember_me` (bool, default True), `created_at`, `updated_at`, `ip_address` (optional), `user_agent` (optional) |
| `verification` | `identifier` (string, index), `value_hash` (string, unique, `returned=False`), `expires_at`, `created_at`, `attempts` (integer, default 0), `data` (json, optional) |

**Verification hashing rule:**
- Long tokens (`gav_...`): `value_hash = crypto.hash_token(token)`.
- Short codes (OTPs, 6 digits): `value_hash = crypto.hash_token(identifier + ":" + code)`. Two users can then hold the same code without breaking the unique index.

**Plugins add, for example:**

| Plugin | Adds |
|---|---|
| two_factor | `user.two_factor_enabled` |
| organization | `session.active_organization_id` |
| admin | `user.role`, `user.banned`, `user.ban_reason`, `user.ban_expires_at`, `session.impersonated_by` |
| various | the models `api_key`, `organization`, `member`, `invitation`, `team`, `team_member`, `passkey`, `two_factor`, `agent`, `oauth_client`, `oauth_consent`, `oauth_code`, `oauth_token`, `jwk` |

Their fields are defined in each plugin's brief and in section 12.

### 2.2 Record types
Records are plain `dict[str, Any]` at the adapter boundary. The core turns them into Pydantic models:
```python
class User(BaseModel):
    id: str
    email: str
    email_verified: bool
    name: str | None
    image: str | None
    created_at: datetime
    updated_at: datetime
    model_config = ConfigDict(extra="allow")       # plugin fields with returned=True

class Session(BaseModel):
    id: str
    user_id: str
    expires_at: datetime
    remember_me: bool
    created_at: datetime
    updated_at: datetime
    ip_address: str | None
    user_agent: str | None
    model_config = ConfigDict(extra="allow")
```
`Account`, `Verification` and the plugin models follow the same pattern. Fields with `returned=False` are never present on these models.

**Names F2 defines in `contracts/`** that other sections use:
- `ConfigError`, `SchemaConflictError`, `UniqueViolation`
- `HookPayload`, `ASGIApp`, `ResolvedConfig`, `AuthApi`, `ChallengeState`
- `FakeClock`, `FakeMailer`, `FakeOAuthProvider`
- `EndpointContext` and `GotAuthInstance` as **Protocols**, because contracts cannot import C1's classes.

## 3. Adapter (storage)
```python
WhereOp = Literal["eq", "ne", "lt", "lte", "gt", "gte", "in", "not_in", "contains", "starts_with", "ends_with", "is_null"]

@dataclass(frozen=True)
class Where:
    field: str
    value: Any = None
    op: WhereOp = "eq"
    connector: Literal["and", "or"] = "and"         # how this clause joins the previous one

@dataclass(frozen=True)
class SortBy:
    field: str
    direction: Literal["asc", "desc"] = "asc"

class Adapter(Protocol):
    id: str                                          # "memory", "sqlalchemy", ...

    async def create(self, model: str, data: Mapping[str, Any]) -> dict[str, Any]: ...
    async def find_one(self, model: str, where: Sequence[Where]) -> dict[str, Any] | None: ...
    async def find_many(
        self, model: str, where: Sequence[Where] = (), *,
        limit: int | None = None, offset: int | None = None, sort_by: SortBy | None = None,
    ) -> list[dict[str, Any]]: ...
    async def count(self, model: str, where: Sequence[Where] = ()) -> int: ...
    async def update(self, model: str, where: Sequence[Where], data: Mapping[str, Any]) -> dict[str, Any] | None: ...
    async def update_many(self, model: str, where: Sequence[Where], data: Mapping[str, Any]) -> int: ...
    async def delete(self, model: str, where: Sequence[Where]) -> int: ...   # number of rows deleted
    def transaction(self) -> AbstractAsyncContextManager[Adapter]: ...
    def bind_schema(self, schema: Schema, *, table_prefix: str = "auth_") -> None: ...   # called once by GotAuth(...)
```
Rules every adapter follows (checked by the conformance suite):
- **Keys** are logical field names. The adapter maps them to table and column names using the bound schema.
- **IDs** are always supplied by the caller (`ctx.ids`); the adapter never generates them.
- **`update` changes at most one row.** It returns the updated row, or `None` if nothing matched. Callers use it as **compare-and-set** by putting the expected current state in `where`. This includes version counters, e.g. P2's `two_factor.version`.
- **`delete` returns the number of rows removed.** Single-use consumption is `delete(where=[id, value_hash, expires_at > now]) == 1`. That is atomic in SQL and in the memory adapter.
- `string_list` and `json` round-trip as Python lists and objects; `datetime` round-trips as aware UTC.
- `transaction()` gives an adapter whose operations commit or roll back together. Nested calls reuse the outer transaction.
- Unique violations (including `unique_together`) raise `UniqueViolation(model, fields)`.

## 4. HTTP abstraction
Framework integrations convert to and from these types. The core never sees a framework object.
```python
@dataclass(frozen=True)
class AuthRequest:
    method: str                                      # upper-case
    path: str                                        # relative to the mount, e.g. "/sign-in/email"
    url: str                                         # full external URL (for redirects and origin checks)
    query: Mapping[str, str]
    headers: Mapping[str, str]                       # lower-case keys
    cookies: Mapping[str, str]
    body: bytes
    client_ip: str | None                            # resolved by the integration with resolve_client_ip()

@dataclass(frozen=True)
class SetCookie:
    name: str
    value: str                                       # "" with max_age=0 deletes the cookie
    max_age: int | None = None
    path: str = "/"
    domain: str | None = None
    secure: bool = True
    http_only: bool = True
    same_site: Literal["lax", "strict", "none"] = "lax"

@dataclass
class AuthResponse:
    status: int = 200
    body: BaseModel | Mapping[str, Any] | None = None   # serialized as JSON
    html: str | None = None                             # server-rendered pages (consent, error)
    redirect: str | None = None                         # sets 302 + Location
    headers: dict[str, str] = dc_field(default_factory=dict)
    cookies: list[SetCookie] = dc_field(default_factory=list)
```
- Every JSON response has `Cache-Control: no-store`.
- **Shared helpers.** Every module must use these, never its own versions. Both are implemented by **F2** in `contracts/protection.py`, so they exist at M0 for C2, C4, A1 and A2 while C1 is still in progress. `gotauth.core` re-exports them.
  - `resolve_client_ip(peer, headers, config)`. `advanced.ip_headers` is honored only when the peer is in `advanced.trusted_proxies`, and the result is the right-most untrusted entry.
  - `validate_redirect(url, config)` (section 10.1).
  - `contracts.sessions.cookie_name(base, *, base_url, prefix)` and `secure_cookies(base_url)` (F2). `cookie_name` returns `<prefix>.<base>`, e.g. `gotauth.session_token`. **Every** GotAuth cookie gets the `__Secure-` prefix when `base_url` is https.

## 5. Endpoints, plugins and hooks
```python
EndpointAuth = Literal["none", "optional", "session", "principal"]
# none: anonymous
# optional: principal resolved if present
# session: a cookie or bearer *session* is required
# principal: a session, API key or OAuth access token is required

SignInMethod = Literal["password", "social", "passkey", "magic_link", "email_otp", "sso"]
# complete_sign_in(method=...) uses these values; plugins may add values only through a CCR.
# Admin impersonation (P6) is not a sign-in: it is the one place allowed to call
# ctx.sessions.create(expires_in=..., extra={"impersonated_by": ...}) directly.

@dataclass(frozen=True)
class Endpoint(Generic[I, O]):
    id: str                                          # snake_case, verb first; also the auth.api method name
    method: Literal["GET", "POST", "PATCH", "DELETE"]
    path: str                                        # kebab-case; may contain "{param}", e.g. "/callback/{provider}"
    handler: Callable[[EndpointContext, I], Awaitable[O | AuthResponse]]
    input: type[BaseModel] | None = None
    input_format: Literal["json", "form", "query"] | None = None
    # None = "query" for GET, "json" for POST, PATCH and DELETE (DELETE may carry a JSON body)
    output: type[BaseModel] | None = None
    auth: EndpointAuth = "none"
    fresh_session: bool = False                      # session must be younger than sessions.fresh_age
    scopes: tuple[str, ...] = ()                     # required scopes when called with an API key or OAuth token
    rate_limit: RateLimitRule | None = None          # overrides the matching default rule
    error_format: Literal["gotauth", "oauth"] = "gotauth"
    # "oauth": every error from this endpoint, including pipeline errors such as RATE_LIMITED,
    # is rendered as RFC 6749 {"error", "error_description"} (mapping table owned by C1)
    server_only: bool = False                        # only callable through auth.api, never over HTTP
    summary: str = ""                                # OpenAPI
    tags: tuple[str, ...] = ()

class EndpointContext(Protocol):
    auth: GotAuthInstance                            # section 13
    request: AuthRequest
    adapter: Adapter                                 # every endpoint runs inside a transaction (GET included)
    clock: Clock
    ids: IdGenerator
    crypto: CryptoKit
    sessions: SessionService
    email: EmailService
    principal: Principal | None
    path_params: Mapping[str, str]
    def set_cookie(self, cookie: SetCookie) -> None: ...
    def set_header(self, name: str, value: str) -> None: ...
    async def emit(self, event_type: AuthEventType, **data: Any) -> None: ...   # section 14

@dataclass(frozen=True)
class HookPayload:
    endpoint_id: str
    input: Any                                       # validated input model (before) or None
    output: Any                                      # handler result (after) or None

@dataclass(frozen=True)
class Hook:
    when: Literal["before", "after"]
    endpoints: tuple[str, ...]                       # endpoint ids; ("*",) = all
    run: Callable[[EndpointContext, HookPayload], Awaitable[AuthResponse | None]]
    # before: return an AuthResponse to short-circuit, or raise AuthError
    # after: return an AuthResponse to replace the result

class SignInInterceptor(Protocol):
    """Runs after credentials are verified and before a session is created (any sign-in method)."""
    async def __call__(self, ctx: EndpointContext, user: User, method: SignInMethod) -> SignInChallenge | None: ...
    # Return a challenge to require another step, None to continue, or raise AuthError to block the sign-in.
    # admin (P6) blocks banned users this way with ADMIN_USER_BANNED.

@dataclass(frozen=True)
class SignInChallenge:
    type: str                                        # e.g. "two_factor", "two_factor_setup"
    methods: tuple[str, ...]                         # e.g. ("totp", "backup_code", "email_otp")

PrincipalCheck = Callable[[EndpointContext, Principal], Awaitable[None]]
# Runs after any principal is resolved (session, API key or OAuth token). Raise AuthError to reject.
# admin (P6) rejects banned users this way.

class PrincipalResolver(Protocol):
    """Turns request credentials into a Principal. Return None if the credential isn't yours."""
    prefixes: tuple[str, ...]                        # e.g. ("gak_",); the OAuth JWT resolver owns ("eyJ",)
    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal | None: ...

@dataclass(frozen=True)
class Plugin:
    id: str
    schema: Schema = dc_field(default_factory=dict)
    endpoints: tuple[Endpoint[Any, Any], ...] = ()
    well_known_endpoints: tuple[Endpoint[Any, Any], ...] = ()   # served at the host root by auth.well_known()
    hooks: tuple[Hook, ...] = ()
    database_hooks: DatabaseHooks | None = None
    sign_in_interceptors: tuple[SignInInterceptor, ...] = ()
    principal_resolvers: tuple[PrincipalResolver, ...] = ()
    principal_checks: tuple[PrincipalCheck, ...] = ()
    error_codes: Mapping[str, tuple[int, str]] = dc_field(default_factory=dict)   # code -> (status, message)
    rate_limits: tuple[RateLimitRule, ...] = ()
    requires_email: bool = False                     # ConfigError at construction if no email sender is available
    init: Callable[[GotAuthInstance], Awaitable[None]] | None = None
```
- **Pipeline order (C1).** Identifier and principal rate limits come after parsing, so `identifier` functions can read the validated input and `ctx.principal`. The steps:
  1. route match
  2. content-type check (10.1)
  3. IP and IP + path rate limits
  4. parse and validate input
  5. principal resolution and `principal_checks` (skipped for `auth="none"`)
  6. origin check (10.1)
  7. identifier and principal rate limits
  8. before hooks
  9. handler, in a transaction
  10. after hooks
  11. events
- **OAuth-format errors.** With `error_format="oauth"`, core codes map through C1's `OAUTH_ERROR_MAP`. Plugin codes named `OAUTH_<NAME>` (e.g. `OAUTH_INVALID_GRANT`) render as `error="<name>"` in lower case, with their registered status.
- **Plugin paths** are prefixed by the plugin: `/api-keys`, `/two-factor/...`, `/organization/...`, `/oauth2/...`.
- **Duplicates** with the same `(method, path)` or the same `id` raise `ConfigError` at construction.
- **The challenge cookie** `gotauth.challenge`:
  - lives 10 minutes
  - is signed with purpose `"challenge"`
  - holds JSON `{user_id, type, methods, method, remember_me, exp}`

  Plugins read it with `ctx.auth.read_challenge` and finish it only through `ctx.auth.finish_challenge` (section 13), never by creating sessions themselves.

## 6. Errors
```python
class AuthError(Exception):
    def __init__(self, code: str, status: int, message: str | None = None, details: Mapping[str, Any] | None = None): ...

class ErrorOut(BaseModel):                           # {"error": {"code", "message", "details"?}}
    error: ErrorBody
```
**JSON shape:** `{"error": {"code": "INVALID_CREDENTIALS", "message": "Invalid email or password"}}`. Endpoints with `error_format="oauth"` use RFC 6749 instead (section 5).

| Code | Status | Notes |
|---|---|---|
| `INVALID_REQUEST` | 400 | Validation failures put the Pydantic error locations in `details`, never the input values |
| `UNSUPPORTED_MEDIA_TYPE` | 415 | |
| `INVALID_CREDENTIALS` | 401 | The same response for an unknown email and for a wrong password |
| `UNAUTHENTICATED` | 401 | |
| `FORBIDDEN` | 403 | |
| `INSUFFICIENT_SCOPE` | 403 | `details.required` lists the scopes |
| `FRESH_SESSION_REQUIRED` | 403 | |
| `EMAIL_NOT_VERIFIED` | 403 | |
| `ORIGIN_NOT_ALLOWED` | 403 | |
| `NOT_FOUND` | 404 | |
| `USER_ALREADY_EXISTS` | 409 | Only when `require_email_verification=False`, see 9.1 |
| `TOKEN_INVALID` | 400 | |
| `TOKEN_EXPIRED` | 400 | |
| `PASSWORD_TOO_SHORT` | 400 | |
| `PASSWORD_TOO_LONG` | 400 | |
| `ACCOUNT_NOT_LINKED` | 409 | |
| `LAST_SIGN_IN_METHOD` | 409 | |
| `PROVIDER_ERROR` | 502 | |
| `RATE_LIMITED` | 429 | Plus a `Retry-After` header |
| `INTERNAL_ERROR` | 500 | |

Plugins add codes through `Plugin.error_codes`, prefixed with their area, e.g. `TWO_FACTOR_INVALID_CODE`, `API_KEY_EXPIRED`, `ORG_NOT_A_MEMBER`, `ADMIN_USER_BANNED`.

## 7. Sessions
- **Token formats** (prefixes make leaks detectable by secret scanners):

  | Token | Format |
  |---|---|
  | Session token | `gas_` + 32 random bytes, base64url |
  | API key | `gak_` |
  | OAuth refresh token | `gar_` |
  | OAuth authorization code | `gac_` |
  | Verification token | `gav_` |
  | OAuth client secret | `gcs_` |
  | OAuth access token | JWT, so it starts with `eyJ` (section 12.2) |

  Only `crypto.hash_token(token)` (SHA-256 hex) is ever stored.
- **Cookies:**
  - **Session:** `gotauth.session_token` (`__Secure-` prefix on https, see section 4). HttpOnly, Secure (except on `http://localhost` / `127.0.0.1`), SameSite=Lax, Path=`/`. Max-Age is the time until `expires_at`; when `remember_me=False` there is no Max-Age, so it is a browser-session cookie.
  - **Optional cookie cache:** `gotauth.session_data`, a signed JSON `{session, user, exp}` lasting `cookie_cache.max_age`. It lets reads skip the database. Revocation can then take up to `max_age` to apply, and the docs must say so.
- **Bearer:** `Authorization: Bearer gas_...` is accepted when `sessions.allow_bearer=True` (the default).
- **Cookie names in use.** Each base name below goes through `cookie_name`. A new cookie needs a CCR so names never collide between parallel work packages.

  | Base name | Owner |
  |---|---|
  | `session_token`, `session_data` | C3 |
  | `challenge` | C1 |
  | `oauth_state` | C4 |
  | `two_factor_trust` | P2 |
  | `passkey_challenge` | P3 |
- **`SessionConfig`:**

  | Field | Default | Meaning |
  |---|---|---|
  | `expires_in` | `"7d"` | |
  | `update_age` | `"1d"` | Sliding refresh: once a session is older than this since its last update, `expires_at` moves forward |
  | `fresh_age` | `"1d"` | |
  | `short_expires_in` | `"1d"` | Server expiry for `remember_me=False` |
  | `allow_bearer` | `True` | |
  | `expose_token` | `False` | When True, sign-in responses include `token` for native and CLI clients |
  | `cookie_cache` | `{enabled: False, max_age: "5m"}` | |
- **Sliding refresh on `GET /session`** is allowed bookkeeping and doesn't count as a state change (see AGENT-RULES).

```python
@dataclass(frozen=True)
class CreatedSession:
    session: Session
    token: str                                       # raw token; returned once

@dataclass(frozen=True)
class SessionWithUser:
    session: Session
    user: User

class SessionService(Protocol):
    async def create(self, ctx: EndpointContext, user_id: str, *, remember_me: bool = True,
                     expires_in: Duration | None = None,
                     extra: Mapping[str, Any] | None = None) -> CreatedSession: ...   # also sets the cookie
    async def get(self, ctx: EndpointContext, token: str) -> SessionWithUser | None: ...  # validates expiry; sliding refresh
    async def list_for_user(self, ctx: EndpointContext, user_id: str) -> list[Session]: ...
    async def revoke(self, ctx: EndpointContext, session_id: str) -> bool: ...
    async def revoke_all(self, ctx: EndpointContext, user_id: str, *, except_session_id: str | None = None) -> int: ...
    def clear_cookies(self, ctx: EndpointContext) -> None: ...

class SecondaryStorage(Protocol):                    # optional: Redis or similar
    async def get(self, key: str) -> str | None: ...
    async def set(self, key: str, value: str, ttl_seconds: int | None = None) -> None: ...
    async def delete(self, key: str) -> None: ...
    async def incr(self, key: str, ttl_seconds: int) -> int: ...   # atomic; sets the TTL on first increment
```

## 8. Crypto kit
```python
@dataclass(frozen=True)
class PasswordCheck:
    ok: bool
    needs_rehash: bool                               # algorithm or parameters differ from the configured default

class CryptoKit(Protocol):
    def random_token(self, prefix: str = "", nbytes: int = 32) -> str: ...   # secrets.token_bytes + base64url (no padding)
    def hash_token(self, token: str) -> str: ...                              # SHA-256 hex
    def equal(self, a: str | bytes, b: str | bytes) -> bool: ...              # hmac.compare_digest
    async def hash_password(self, password: str) -> str: ...
    async def verify_password(self, password: str, stored: str) -> PasswordCheck: ...
    def sign(self, value: str, *, purpose: str) -> str: ...                   # "<value>.<b64url HMAC-SHA256>"
    def unsign(self, signed: str, *, purpose: str) -> str | None: ...         # tries every configured secret
    def encrypt(self, plaintext: str, *, purpose: str) -> str: ...           # AES-256-GCM; "v1.<b64 nonce>.<b64 ct>"
    def decrypt(self, ciphertext: str, *, purpose: str) -> str | None: ...
    def derive_key(self, purpose: str, length: int = 32) -> bytes: ...       # HKDF-SHA256(secret, info=b"gotauth:" + purpose)
    def new_totp_secret(self) -> str: ...                                     # 20 random bytes, base32 without padding
    def totp(self, secret_b32: str, *, at: datetime, digits: int = 6, period: int = 30) -> str: ...
    def verify_totp(self, secret_b32: str, code: str, *, at: datetime, window: int = 1) -> int | None: ...
    # returns the matched time step, so callers can reject reuse of the same step
    def new_otp(self, digits: int = 6) -> str: ...                            # uniform random numeric code
    def pkce_s256(self, verifier: str) -> str: ...
    def new_ulid(self, at: datetime) -> str: ...
```
- **Password hash format:**
  - default: `scrypt$ln=15,r=8,p=1$<b64 salt>$<b64 hash>` (stdlib `hashlib.scrypt`, 16-byte salt, 64-byte key)
  - with the `argon2` extra and `advanced.password_algorithm="argon2id"`: `argon2id$<PHC string>`
  - imports only, verify-only, `bcrypt` extra: `bcrypt$<original $2b$ string>`

  `verify_password` runs a dummy hash when `stored` is empty, so unknown users take the same time.
- **Password limits:** min length 8 (configurable), max length 128. Passwords are never logged or echoed.
- **Secrets:** `secret` is a string of >= 32 characters, or a list `[current, *previous]` for rotation. Signing and encryption use the first; verification tries all of them.
- **Purpose strings in use** (each owner WP documents its own; reusing another's purpose is a bug):
  - `"session_data"` (C3)
  - `"challenge"` (C1)
  - `"oauth_state"` (C4)
  - `"account_token"` (C4, I1)
  - `"two_factor_secret"` and `"trusted_device"` (P2)
  - `"passkey_challenge"` (P3)
  - `"jwk_private"` and `"oauth_consent"` (O1)

**Spec vectors** (F3 owns them; every language port must pass them byte for byte):

| File | Contents |
|---|---|
| `spec/hotp.json` | RFC 4226 appendix D |
| `spec/totp.json` | RFC 6238 appendix B (SHA1) |
| `spec/pkce.json` | RFC 7636 appendix B |
| `spec/hkdf.json` | RFC 5869 |
| `spec/password-hash.json` | Known scrypt and bcrypt hashes to verify |
| `spec/sign.json` | `sign` / `unsign` with fixed secrets |
| `spec/token-format.json` | Prefix and length rules |

## 9. Email and passwords
```python
EmailKind = Literal[
    "verify_email", "reset_password", "change_email", "magic_link", "otp",
    "invitation", "sign_up_existing_account", "security_notice",
]

@dataclass(frozen=True)
class EmailMessage:
    kind: EmailKind
    to: str
    subject: str
    text: str
    html: str | None = None
    from_address: str | None = None                  # EmailConfig.from_address unless a sender overrides it
    data: Mapping[str, Any] = dc_field(default_factory=dict)   # url, code, org name, ...

class EmailSender(Protocol):
    async def send(self, message: EmailMessage) -> None: ...

class EmailService(Protocol):                        # D1: renders templates, then calls the sender
    async def send(self, kind: EmailKind, to: str, **data: Any) -> None: ...
    async def drain(self) -> None: ...               # waits for background deliveries (tests, shutdown)
```
- **`EmailConfig`:** `app_name` (default `"GotAuth"`), `from_address`, `templates` (overrides per kind), `render` (a callable replacing the renderer).
- **Senders:** if no sender is configured and the app runs on localhost, the console sender is used. Otherwise any plugin with `requires_email=True`, or email + password with verification on, raises `ConfigError` at construction.
- **Background delivery:** outside localhost, `EmailService.send` renders immediately (template errors still raise), then delivers on a background task and returns. Response time therefore doesn't reveal whether an account exists. `auth.drain()` waits for pending deliveries.
- **Password reset links** point to the app's `redirect_to` page with `?token=gav_...`. That page then calls `POST /reset-password`. There is no GET reset endpoint.

### 9.1 Account enumeration rules
These are binding for C2, P4 and the organization invitations.
- **`request_password_reset`, `send_verification_email`, magic link and email OTP** always return the same success body, whether the account exists or not.
- **Sign-up with `require_email_verification=True`:** an existing email gets the same "verification sent" response, and the owner receives a `sign_up_existing_account` email.
- **Sign-up with `require_email_verification=False`:** this inherently reveals existence (the user is signed in at once), so it returns `USER_ALREADY_EXISTS`. The docs must state the trade-off.
- **Sign-in:** an unknown email runs a dummy password verification and returns `INVALID_CREDENTIALS`.

## 10. Request protection
### 10.1 Origin, content type and redirects
- **POST, PATCH and DELETE authenticated by a cookie** require an `Origin` header (or `Referer` as a fallback) that matches the origin of `base_url` or one of `trusted_origins`. Otherwise: `ORIGIN_NOT_ALLOWED`. Requests authenticated by a bearer token or API key are exempt.
- **Endpoints with `input_format="json"`** require `Content-Type: application/json` when the request has a body; anything else gets `UNSUPPORTED_MEDIA_TYPE`. Browsers can't send that content type cross-site without a CORS preflight, which closes login CSRF on cookie-less endpoints such as `sign_in_email`. A request with an empty body is exempt, e.g. `curl -X DELETE` with an API key.
- **Redirect parameters** (`callback_url`, `error_callback_url`, `redirect_to`) go through `validate_redirect`:
  - allowed: a relative path (not `//x` or `/\x`), or an absolute URL on a trusted origin
  - otherwise: `INVALID_REQUEST`
- **Trusted origins** support exact origins and `https://*.example.com` wildcards. `base_url` is always trusted.

### 10.2 Rate limits
```python
@dataclass(frozen=True)
class RateLimitRule:
    path: str                                        # exact path or prefix with "*", e.g. "/sign-in/*"
    window: Duration
    max: int
    key: Literal["ip", "ip_path", "principal", "identifier"] = "ip_path"
    identifier: str | Callable[[EndpointContext, Any], str | None] | None = None
    # key="identifier": an input field name (e.g. "email"; lower-cased) or a function of (ctx, input).
    # The value is hashed before storage. None from the function skips the rule.

class RateLimitConfig(BaseModel):
    enabled: bool = True
    storage: Literal["memory", "database", "secondary"] = "memory"   # "database" uses the rate_limit model
    rules: list[RateLimitRule] = []                                    # added to and overriding the defaults
```
**Defaults:**

| Paths | Limit |
|---|---|
| All endpoints | 100 per 60s per IP + path |
| `/sign-in/*`, `/sign-up/*`, `/request-password-reset`, `/reset-password`, `/send-verification-email`, `/two-factor/*`, `/magic-link/*`, `/email-otp/*` | 5 per 60s per IP + path |
| `/sign-in/email`, `/request-password-reset`, `/magic-link/send`, `/email-otp/send` | 10 per 15 minutes per `email` identifier. This blocks distributed credential stuffing and email bombing |
| `/passkey/*` | 10 per 60s |
| `/oauth2/token` | 30 per 60s |

**Client IP** comes from `resolve_client_ip` (section 4).

## 11. Social login
```python
@dataclass(frozen=True)
class ProviderTokens:
    access_token: str
    refresh_token: str | None
    id_token: str | None
    expires_at: datetime | None
    scope: str | None

@dataclass(frozen=True)
class ProviderUser:
    id: str
    email: str | None
    email_verified: bool
    name: str | None
    image: str | None
    raw: Mapping[str, Any]

class OAuthProvider(Protocol):
    id: str                                          # "github"
    name: str                                        # "GitHub"
    default_scopes: tuple[str, ...]
    store_provider_tokens: bool                      # factory keyword, default False
    callback_method: Literal["GET", "POST"]          # "POST" only for form_post providers (Apple)
    def authorization_url(self, *, state: str, code_challenge: str, redirect_uri: str,
                          scopes: Sequence[str], nonce: str | None) -> str: ...
    async def exchange_code(self, http: httpx.AsyncClient, *, code: str, code_verifier: str,
                            redirect_uri: str) -> ProviderTokens: ...
    async def get_user(self, http: httpx.AsyncClient, tokens: ProviderTokens, *, nonce: str | None) -> ProviderUser: ...
```
- **Flow:**
  1. `POST /sign-in/social` stores the state in `verification` (hashed). The value holds the code verifier, callback URLs and nonce.
  2. It sets a signed `gotauth.oauth_state` cookie (purpose `"oauth_state"`) that binds the flow to the browser.
  3. It returns `{"url": ...}`.
  4. The callback (`GET /callback/{provider}`, or `POST` for form_post providers) checks the state against both the cookie and the database, consumes it once, exchanges the code, then signs in through `complete_sign_in(method="social")` or links the account.
- **Account linking:**
  - An existing `(provider_id, account_id)` signs in that user.
  - Otherwise, if a user with the same email exists, link only when the provider says the email is verified **and** either the local email is verified or the provider is in `account_linking.trusted_providers`. Otherwise: `ACCOUNT_NOT_LINKED`.
  - Otherwise, create a user (`email_verified` = the provider's flag).
- **ID tokens** from OIDC providers are verified with the provider's JWKS (PyJWT). Check `iss`, `aud`, `exp`, `nonce`. The OIDC client code lives in `social/oidc.py` so E1 can reuse it.

## 12. API keys, OAuth server, agents and MCP
These are fixed now because Waves 2-3 depend on them.

### 12.1 Principal
Every authenticated request resolves to one principal.
```python
@dataclass(frozen=True)
class Principal:
    via: Literal["session", "api_key", "oauth_token"]
    credential_id: str                               # session id, api_key id or oauth_token id
    user_id: str | None                              # the human the request acts for; never an agent or client id
    agent_id: str | None = None                      # set when an agent acts (O3)
    organization_id: str | None = None               # session.active_organization_id, or the owning org of a key
    client_id: str | None = None                     # OAuth client, when via == "oauth_token"
    scopes: frozenset[str] | None = None             # None = the full rights of a user session
    def has_scopes(self, *required: str) -> bool: ...   # True if scopes is None or contains them all
```
**Resolution order:**
1. `Authorization: Bearer <credential>` or `x-api-key: <credential>`, routed to the `PrincipalResolver` that owns the prefix:

   | Prefix | Resolver |
   |---|---|
   | `gas_` | C3 sessions |
   | `gak_` | P1 API keys |
   | `eyJ` | O1 JWT access tokens |
2. Then the session cookie.

An unknown prefix gives `UNAUTHENTICATED`. After resolution, every `Plugin.principal_checks` entry runs.

**Field rules:**
- **`organization_id`:** the C3 session resolver copies `session.active_organization_id` into it when that field exists (P5 installed).
- **Permissions and scopes** share one vocabulary: the scope `"project:delete"` is the permission `{"project": ["delete"]}`. P5's `has_permission` and A1's `require(...)` both use this mapping.
- **`client_credentials` tokens:** `user_id` is the owning user of the client's agent (if the agent is user-owned), otherwise `None`; `agent_id` is the agent.

### 12.2 Models and token rules
**`api_key` (P1):**
- `name`
- `start` (first 6 characters after the prefix, for display)
- `key_hash` (unique, `returned=False`)
- `owner_type` (`"user"` | `"organization"` | `"agent"`), `owner_id`
- `user_id` -> user (cascade, optional): the human it acts for. Deleting the user removes their keys.
- `scopes` (string_list)
- `expires_at` (optional), `last_used_at` (optional)
- `rate_limit_max` / `rate_limit_window` (optional)
- `enabled` (default True)
- `created_by` -> user (set_null, optional)
- `created_at`, `metadata` (json)

**`agent` (O3):**
- `name`, `description` (optional)
- `owner_type` (`"user"` | `"organization"`), `owner_id`
- `created_by` -> user (set_null, optional)
- `disabled_at` (optional)
- `created_at`, `metadata` (json)

**`oauth_client` (O1):**
- `client_id` (unique; for CIMD clients, the metadata URL)
- `client_secret_hash` (optional; public clients have none; secrets use the `gcs_` prefix)
- `type` (`"public"` | `"confidential"`)
- `name`, `redirect_uris` (string_list), `grant_types` (string_list), `scopes` (string_list)
- `registration` (`"static"` | `"cimd"` | `"dynamic"`)
- `agent_id` -> agent (optional, set_null), `owner_user_id` (optional)
- `disabled_at` (optional), `created_at`

**`oauth_consent` (O1, prefix `ocn`):** `user_id` -> user (cascade), `client_id`, `scopes` (string_list), `resource` (optional), `created_at`.

**`oauth_code` (O1):**
- `code_hash` (unique)
- `client_id`, `user_id`
- `redirect_uri`
- `scopes`, `resource`
- `code_challenge`
- `nonce` (optional)
- `expires_at` (now + 60s)

**`oauth_token` (O1):**
- `refresh_token_hash` (optional, unique when set; `client_credentials` tokens have none)
- `family_id` (rotation family)
- `parent_id` -> oauth_token (optional; O4 delegation chains)
- `client_id`, `user_id` (optional), `agent_id` (optional)
- `scopes`, `resource`
- `expires_at`, `revoked_at` (optional)
- `created_at`

**`jwk` (O1):**
- `kid`, `alg`
- `public_jwk` (json)
- `private_key_enc` (text, `returned=False`, purpose `"jwk_private"`)
- `created_at`, `retired_at` (optional)

**Access tokens** follow the JWT profile of RFC 9068:
- Signed ES256 by default.
- Header `typ: at+jwt`, `kid`.
- Claims:
  - `iss` = `base_url` + `base_path`
  - `sub` = user id (for `client_credentials`: the agent id, or the client id when there is no agent)
  - `aud` = the `resource` (RFC 8707), or the issuer when no resource was requested
  - `client_id`
  - `scope` (space-separated)
  - `iat`, `exp` (default 10 minutes), `jti` = oauth_token id
  - `act: {"sub": "<agent id>"}` when the client belongs to an agent (RFC 8693 actor claim)

**Refresh tokens:**
- Opaque and hashed at rest.
- Rotated on every use.
- Reusing an old refresh token revokes its whole `family_id`.

**Revocation semantics:**
- **In-process checks** (the `eyJ` resolver and `verify_access_token`) look up `jti` and reject revoked tokens, disabled clients and disabled agents at once. A cache of up to 5 seconds is allowed.
- **Remote resource servers** that verify JWTs only locally accept a revoked token until it expires, at most 10 minutes. They can opt into RFC 7662 introspection for immediate revocation (O2 `introspect=True`).

### 12.3 Endpoint ids for P1, O1 and O3
| id | Method + path | Auth | Owner |
|---|---|---|---|
| `create_api_key` | POST `/api-keys` | session | P1 |
| `list_api_keys` | GET `/api-keys` | session | P1 |
| `update_api_key` | PATCH `/api-keys/{id}` | session | P1 |
| `delete_api_key` | DELETE `/api-keys/{id}` | session | P1 |
| `verify_api_key` | server_only | | P1 |
| `issue_api_key` | server_only (any owner; used by O3) | | P1 |
| `revoke_api_keys` | server_only (by owner or key) | | P1 |
| `oauth_authorize` | GET `/oauth2/authorize` | optional | O1 |
| `oauth_consent` | POST `/oauth2/consent` (form) | session | O1 |
| `oauth_token` | POST `/oauth2/token` (form, `error_format="oauth"`) | none (client auth) | O1 |
| `oauth_introspect` | POST `/oauth2/introspect` (form, oauth errors) | none (client auth) | O1 |
| `oauth_revoke` | POST `/oauth2/revoke` (form, oauth errors) | none (client auth) | O1 |
| `oauth_jwks` | GET `/oauth2/jwks` | none | O1 |
| `oauth_userinfo` | GET `/oauth2/userinfo` | none (own token check) | O1 |
| `oauth_register` | POST `/oauth2/register` (off by default) | none | O1 |
| `oauth_openid_configuration` | GET `/.well-known/openid-configuration` (inside the mount: issuer + path) | none | O1 |
| `oauth_server_metadata` | well-known: GET `/.well-known/oauth-authorization-server{base_path}` at the host root (RFC 8414 path insertion) | none | O1 |
| `create_oauth_client`, `list_oauth_clients`, `get_oauth_client`, `update_oauth_client`, `delete_oauth_client`, `rotate_oauth_client_secret`, `rotate_signing_key`, `revoke_oauth_tokens`, `verify_access_token` | server_only | | O1 |
| `create_agent` | POST `/agents` | session | O3 |
| `list_agents` | GET `/agents` | session | O3 |
| `get_agent` | GET `/agents/{id}` | session | O3 |
| `update_agent` | PATCH `/agents/{id}` | session | O3 |
| `revoke_agent` | POST `/agents/{id}/revoke` | session | O3 |
| `create_agent_api_key` | POST `/agents/{id}/api-keys` | session | O3 |
| `list_agent_api_keys` | GET `/agents/{id}/api-keys` | session | O3 |
| `link_oauth_client` | POST `/agents/{id}/clients` | session | O3 |
| `revoke_agents` | server_only (by owner; used by P5 on org deletion and by O3's user-delete hook) | | O3 |

**OAuth server rules (O1):**
- **PKCE S256 is required** for every authorization-code request. `plain` is rejected.
- **Exact `redirect_uri` match.** Loopback redirect URIs may use any port (RFC 8252).
- **CIMD (client ID metadata documents):**
  - A `client_id` that is an https URL is fetched, with a 5s timeout, a 64 KB size cap and caching by HTTP cache headers.
  - Its `client_id` field must equal the URL.
  - Its redirect URIs are then trusted.
  - Private, loopback and link-local IPs (checked after DNS resolution) are rejected (SSRF guard).
- **Resource indicators:** `resource` binds tokens to an audience; a token for one MCP server can't be used at another.
- **Grants:** `authorization_code`, `refresh_token`, `client_credentials` (confidential clients only).
- **`GET /oauth2/authorize` may issue a code directly** when the user's consent for the same client, scopes and resource is already stored. This is the standard OAuth flow and an allowed exception to "no state change on GET".

**Organization permission check (P5)** is used by A1, P1 and O3:

| id | Method + path | Auth | Input | Output |
|---|---|---|---|---|
| `has_permission` | POST `/organization/has-permission` | principal | `{organization_id?, permissions: {resource: [action]}}` | `{success: bool}` |

A denial returns `success=false`, not an error.

**P5's built-in statements:**

| Resource | Actions |
|---|---|
| `organization` | `update`, `delete` |
| `member` | `create`, `update`, `delete` |
| `invitation` | `create`, `cancel` |
| `api_key` | `create`, `read`, `update`, `revoke` |
| `agent` | `create`, `read`, `update`, `revoke` |

**Deleting an organization** revokes its org-owned API keys (P1 `revoke_api_keys`) and its org-owned agents (O3 `revoke_agents`), both with `owner_type="organization"`, when those plugins are installed. Their owner is polymorphic, so no foreign key does this.

### 12.5 Cross-plugin calls
Plugins are built in parallel by different agents, so they never import each other's code. A plugin uses another plugin only like this:
1. Check that the other plugin is installed: `"<plugin id>" in ctx.auth.plugin_ids`. Skip, or raise `ConfigError` at construction, when it isn't.
2. Call it through `await ctx.auth.api.call("<endpoint id>", body={...}, ctx=ctx)`. Passing `ctx` runs the call inside the caller's transaction (section 13).
3. Use exactly the shapes below. They are frozen at M0 like the rest of this file. Output models are defined by F2 in `contracts/http_models.py`.

| id (owner) | Input | Output |
|---|---|---|
| `issue_api_key` (P1) | `{owner_type, owner_id, user_id?, created_by?, name, scopes, expires_in?, metadata?}` | `{api_key: ApiKeyOut, key}` |
| `revoke_api_keys` (P1) | `{owner_type, owner_id, key_id?}` | `{revoked: int}` |
| `verify_api_key` (P1) | `{key, scopes?}` | `{valid: bool, code?, principal?: Principal}` |
| `create_oauth_client` (O1) | `{name, type, redirect_uris, grant_types?, scopes?, owner_user_id?, agent_id?}` | `{client: OAuthClientOut, client_secret?}` |
| `update_oauth_client` (O1) | `{client_id, name?, redirect_uris?, scopes?, agent_id?, disabled?}`. An explicit `agent_id: null` unlinks | `{client: OAuthClientOut}` |
| `revoke_oauth_tokens` (O1) | `{client_id?, user_id?, agent_id?, family_id?}` (at least one) | `{revoked: int}` |
| `verify_access_token` (O1) | `{token, resource?, scopes?}` | `{valid: bool, code?, principal?: Principal}` |
| `revoke_agents` (O3) | `{owner_type, owner_id}` | `{revoked: int}` |
| `has_permission` (P5) | `{organization_id?, permissions: {resource: [action]}}` | `{success: bool}` |

Before the other plugin has merged, tests fake it with `stub_plugin(...)` (section 15).

### 12.4 MCP integration surface (O2)
```python
def fastmcp_auth(auth: GotAuth | None = None, *, issuer: str | None = None, resource: str,
                 scopes: Sequence[str] = (), introspect: bool = False,
                 introspection_client: tuple[str, str] | None = None) -> Any: ...
# Returns a FastMCP auth provider that verifies GotAuth access tokens and advertises the
# authorization server in RFC 9728 metadata.
# Same process (`auth=`): uses verify_access_token, so revocation is immediate.
# Remote (`issuer=`): verifies locally via JWKS. With introspect=True it also calls RFC 7662
# introspection, authenticating as the confidential client (client_id, client_secret) given in
# introspection_client; introspect=True without it raises ConfigError.

def mcp_sdk_auth(auth: GotAuth | None = None, *, issuer: str | None = None, resource: str,
                 scopes: Sequence[str] = (), introspect: bool = False,
                 introspection_client: tuple[str, str] | None = None) -> tuple[Any, Any]: ...
# Returns (AuthSettings, TokenVerifier) for the official MCP Python SDK.

def protected_resource_metadata(*, resource: str, issuer: str, scopes: Sequence[str]) -> dict[str, Any]: ...
```

## 13. Configuration and the `auth.api` contract
```python
class GotAuth:
    def __init__(
        self, *,
        database: Adapter,
        secret: str | Sequence[str],
        base_url: str,                               # external origin, e.g. "https://api.example.com"
        base_path: str = "/api/auth",
        trusted_origins: Sequence[str] = (),
        email_password: EmailPasswordConfig | Mapping[str, Any] | None = None,
        social_providers: Sequence[OAuthProvider] = (),
        account_linking: AccountLinkingConfig | Mapping[str, Any] | None = None,
        sessions: SessionConfig | Mapping[str, Any] | None = None,
        rate_limit: RateLimitConfig | Mapping[str, Any] | bool | None = None,
        email: EmailConfig | Mapping[str, Any] | None = None,
        email_sender: EmailSender | None = None,
        secondary_storage: SecondaryStorage | None = None,
        plugins: Sequence[Plugin] = (),
        hooks: Sequence[Hook] = (),
        database_hooks: DatabaseHooks | None = None,
        on_event: Callable[[AuthEvent], Awaitable[None]] | None = None,
        advanced: AdvancedConfig | Mapping[str, Any] | None = None,
    ) -> None: ...

    schema: Schema                                   # merged core + plugin schema (used by `gotauth generate`)
    api: AuthApi                                     # server-side calls
    async def handle(self, request: AuthRequest) -> AuthResponse: ...       # C1
    def asgi(self) -> ASGIApp: ...                                          # C1; mount at base_path
    def well_known(self) -> ASGIApp: ...                                    # C1; mount at "/"; serves Plugin.well_known_endpoints
    async def get_principal(self, headers: Mapping[str, str], cookies: Mapping[str, str]) -> Principal | None: ...
    async def drain(self) -> None: ...                                      # waits for background tasks (email, events)
    @property
    def fastapi(self) -> FastAPIIntegration: ...                            # A1; lazy import
```
- **Config objects** are Pydantic models with defaults. Plain dicts are validated into them.

| Config | Fields (defaults) |
|---|---|
| `EmailPasswordConfig` | `enabled` (True), `require_email_verification` (True), `min_password_length` (8), `max_password_length` (128), `auto_sign_in` (True), `reset_token_expires_in` ("1h"), `verify_token_expires_in` ("24h"), `revoke_sessions_on_password_reset` (True) |
| `AccountLinkingConfig` | `enabled` (True), `trusted_providers` (()), `allow_different_emails` (False) |
| `SessionConfig` | section 7 |
| `RateLimitConfig` | section 10.2 |
| `EmailConfig` | section 9 |
| `AdvancedConfig` | `cookie_prefix` ("gotauth"), `table_prefix` ("auth_"), `ip_headers` (()), `trusted_proxies` (()), `password_algorithm` ("scrypt" or "argon2id"), `clock`, `ids`, `session_service` and `email_service` overrides (testing and advanced use), `install_core_plugins` (True). False skips the automatic sessions, email + password and social plugins; it is meant for C1's own tests and for tests that run before C2-C4 merge |

```python
@dataclass(frozen=True)
class ModelHooks:
    before_create: Callable[[EndpointContext | None, dict[str, Any]], Awaitable[dict[str, Any] | None]] | None = None
    after_create: Callable[[EndpointContext | None, dict[str, Any]], Awaitable[None]] | None = None
    before_update: Callable[[EndpointContext | None, dict[str, Any]], Awaitable[dict[str, Any] | None]] | None = None
    after_update: Callable[[EndpointContext | None, dict[str, Any]], Awaitable[None]] | None = None
    before_delete: Callable[[EndpointContext | None, dict[str, Any]], Awaitable[None]] | None = None
    after_delete: Callable[[EndpointContext | None, dict[str, Any]], Awaitable[None]] | None = None

@dataclass(frozen=True)
class DatabaseHooks:
    hooks: Mapping[str, ModelHooks]                  # logical model name -> hooks (config and plugins both allowed)
```
A `before_*` hook may return modified data, or raise `AuthError` to abort. The core runs hooks for writes made through its services (`delete_user`, session create, user create).

**`GotAuthInstance`** (a Protocol in contracts) is the `GotAuth` object. Besides the members above, endpoint code may use:
```python
    config: ResolvedConfig                           # every config object with defaults applied
    providers: Mapping[str, OAuthProvider]
    plugin_ids: frozenset[str]                       # e.g. {"api_key", "organization"}
    http: httpx.AsyncClient                          # shared client for providers, CIMD and email APIs (10s timeout)
    async def complete_sign_in(self, ctx: EndpointContext, user: User, *, method: SignInMethod,
                               remember_me: bool = True) -> SignInOut | ChallengeOut: ...
    # Owned by C1. Every sign-in path calls this, never ctx.sessions.create directly.
    # It runs the SignInInterceptors in plugin order (any may raise to block), then either
    # creates the session (SignInOut) or sets the challenge cookie (ChallengeOut). Emits "sign_in.succeeded".
    def read_challenge(self, ctx: EndpointContext) -> ChallengeState | None: ...
    # Owned by C1. Verifies the challenge cookie and returns {user_id, type, methods, method, remember_me, exp},
    # or None when it is missing or tampered with. Plugins never unsign the cookie themselves.
    async def finish_challenge(self, ctx: EndpointContext, *, satisfied: str) -> SignInOut: ...
    # Owned by C1. Re-verifies the challenge cookie, checks that `satisfied` (the factor used, e.g. "totp")
    # is in its methods, creates the session with its remember_me, clears the cookie and emits
    # "sign_in.succeeded". Raises TOKEN_INVALID / TOKEN_EXPIRED when the cookie is missing, tampered
    # with or expired, and FORBIDDEN when `satisfied` is not an allowed method.
    async def create_user_record(self, ctx: EndpointContext | None, data: Mapping[str, Any]) -> User: ...
    # Owned by C1. The way every sign-up path creates a user (C2, C4, P4, P6 create_user, E1):
    # lower-cases the email, runs user before_create/after_create hooks from config and plugins,
    # and emits "user.created". Bulk importers (I1) may write rows directly and must document it.
    async def delete_user(self, ctx: EndpointContext | None, user_id: str) -> None: ...
    # Owned by C1. The only way to delete a user (C2 delete_user, P6 remove_user):
    # runs user before_delete/after_delete hooks from config and plugins, deletes (FK cascades)
    # and emits "user.deleted".
    def background(self, coro: Awaitable[None]) -> None: ...                 # C1; tracked task; errors logged
```
**Permission checks:** when P5 is installed, it registers `has_permission` (section 12.3). A1's `require(permission=...)` calls it through `auth.api.call("has_permission", ...)`. Without P5, asking for a permission raises `ConfigError` at startup.

**`auth.api`:** every endpoint, including `server_only` ones, can be called as
```python
await auth.api.<endpoint_id>(body=None, *, headers=None, query=None, path_params=None, as_response=False, ctx=None)
```
- It returns the output model, or raises `AuthError`.
- Server calls skip origin checks and rate limits.
- With `ctx=` (calls from inside another endpoint, section 12.5), the call joins `ctx`'s transaction and principal. Without it, the call runs in its own transaction.
- With `as_response=True` it returns the full `AuthResponse`, including cookies.
- Core endpoints have typed methods on `AuthApi`. Plugin endpoints are reachable through `auth.api.call("<endpoint_id>", ...)`, and each plugin may add typed helpers.

### 13.1 Core endpoint table (for A1 OpenAPI, D2 and the examples)
| id | Method + path | Auth | Output | Owner |
|---|---|---|---|---|
| `sign_up_email` | POST `/sign-up/email` | none | `SignInOut` or `StatusOut` | C2 |
| `sign_in_email` | POST `/sign-in/email` | none | `SignInOut` or `ChallengeOut` | C2 |
| `sign_out` | POST `/sign-out` | session | `StatusOut` | C2 |
| `send_verification_email` | POST `/send-verification-email` | none | `StatusOut` | C2 |
| `verify_email` | GET `/verify-email` | none | redirect or `StatusOut` | C2 |
| `request_password_reset` | POST `/request-password-reset` | none | `StatusOut` | C2 |
| `reset_password` | POST `/reset-password` | none | `StatusOut` | C2 |
| `change_password` | POST `/change-password` | session, fresh | `StatusOut` | C2 |
| `change_email` | POST `/change-email` | session | `StatusOut` | C2 |
| `update_user` | PATCH `/user` | session | `UserOut` | C2 |
| `delete_user` | DELETE `/user` (JSON body `{password?}`) | session, fresh | `StatusOut` | C2 |
| `get_session` | GET `/session` | optional | `SessionWithUserOut` or `null` | C3 |
| `list_sessions` | GET `/sessions` | session | `SessionListOut {sessions, current_session_id}` | C3 |
| `revoke_session` | POST `/sessions/revoke` | session | `StatusOut` | C3 |
| `revoke_other_sessions` | POST `/sessions/revoke-others` | session | `StatusOut` | C3 |
| `sign_in_social` | POST `/sign-in/social` | none | `RedirectOut {url}` | C4 |
| `social_callback` | GET `/callback/{provider}` | none | redirect | C4 |
| `social_callback_post` | POST `/callback/{provider}` (form; form_post providers only) | none | redirect | C4 |
| `link_social` | POST `/link-social` | session | `RedirectOut` | C4 |
| `list_accounts` | GET `/accounts` | session | `AccountListOut {accounts}` | C4 |
| `unlink_account` | POST `/unlink-account` | session, fresh | `StatusOut` | C4 |

**Response models** are in `contracts/http_models.py` (F2): `UserOut`, `SessionOut`, `SessionWithUserOut {session, user}`, `SignInOut {user, session, token?}`, `ChallengeOut {challenge: {type, methods}}`, `StatusOut {status}`, `RedirectOut {url}`, `SessionListOut`, `AccountOut`, `AccountListOut`, `ErrorOut`.

### 13.2 Entry points and public import paths
| Import | What | Owner |
|---|---|---|
| `from gotauth import GotAuth, AuthError, Principal, User, Session` | Main class and core types | C1, F2 |
| `gotauth.crypto.crypto_kit(secret, *, password_algorithm) -> CryptoKit` | Crypto kit | F3 |
| `gotauth.sessions.session_service(config, *, secondary_storage=None) -> SessionService`, `gotauth.sessions.sessions_plugin() -> Plugin`, `memory_secondary_storage()`, `redis_secondary_storage(...)` | Sessions | C3 |
| `gotauth.email_password.email_password_plugin(config) -> Plugin` | Email + password | C2 |
| `gotauth.social.social_plugin() -> Plugin`, `from gotauth.social import github, google, microsoft, discord, gitlab, apple, generic_oidc` | Social login. Provider modules are private (`social/providers/_github.py`), so factory names never collide with submodules | C4 |
| `gotauth.email.email_service(config, sender) -> EmailService`, `console_sender()`, `smtp_sender(...)`, `resend_sender(...)` | Email | D1 |
| `gotauth.storage.memory.memory_adapter()`, `gotauth.storage.sqlalchemy.sqlalchemy_adapter(engine)` | Storage | F2, S1 |
| `from gotauth.plugins.<name> import <name>`, e.g. `from gotauth.plugins.api_key import api_key` | Plugin factories. Import from the plugin's own module: importing a submodule would shadow a same-named function on the `gotauth.plugins` package | each plugin WP |
| `gotauth.integrations.mcp.fastmcp_auth`, `mcp_sdk_auth`, `protected_resource_metadata` | MCP | O2 |
| `gotauth.core.resolve_client_ip`, `gotauth.core.validate_redirect` | Integration helpers, implemented in `contracts/protection.py` and re-exported by `gotauth.core` | F2 (C1 re-exports) |

C1 assembles the core: `GotAuth(...)` always installs `sessions_plugin()`, `email_password_plugin()` (when enabled) and `social_plugin()` (when providers are given) before the user's plugins.

## 14. Events
```python
AuthEventType = Literal[
    "user.created", "user.updated", "user.deleted", "user.email_verified", "user.email_changed",
    "user.role_changed", "user.banned", "user.unbanned",
    "sign_in.succeeded", "sign_in.failed", "sign_out",
    "password.changed", "password.reset",
    "session.revoked",
    "account.linked", "account.unlinked",
    "two_factor.enabled", "two_factor.disabled",
    "passkey.added", "passkey.removed",
    "api_key.created", "api_key.revoked",
    "agent.created", "agent.revoked",
    "oauth.consent_granted", "oauth.token_revoked", "oauth.client_created",
    "org.created", "org.deleted", "org.member_added", "org.member_removed", "org.role_changed",
    "org.invitation_sent", "org.invitation_accepted",
    "admin.impersonation_started", "admin.impersonation_stopped",
]

@dataclass(frozen=True)
class AuthEvent:
    id: str                                          # "evt_..."
    type: AuthEventType
    at: datetime
    user_id: str | None
    principal: Principal | None                      # carries agent_id when an agent acted
    ip_address: str | None
    user_agent: str | None
    data: Mapping[str, Any]                          # never secrets
```
- **Delivery:** `ctx.emit(...)` delivers to `on_event` after the transaction commits, through `auth.background`. Failure events (`sign_in.failed`) are delivered even when the transaction rolls back. Errors in `on_event` are logged and never fail the request.
- **New event types** are added through a CCR. E1's SSO and SCIM events are added when E1 starts.

## 15. Testing kit (`gotauth.testing`, shipped to users)
```python
def memory_adapter() -> Adapter: ...
def fake_clock(start: datetime = datetime(2026, 1, 1, tzinfo=UTC)) -> FakeClock: ...   # .advance(Duration)
def seq_ids() -> IdGenerator: ...                                                        # "usr_00000000000000000000000001", ...
def fake_mailer() -> FakeMailer: ...           # .sent: list[EmailMessage]; .last(kind, to) -> EmailMessage
def fake_oauth_provider(id: str = "fake", *, users: Mapping[str, ProviderUser] | None = None) -> FakeOAuthProvider: ...
def make_auth(**overrides: Any) -> GotAuth: ...
# memory adapter, fake clock, ids and mailer; secret "test-secret-" * 4; base_url "http://localhost:8000".
# Imports C1 lazily, so it works unchanged once C1 merges.
def make_client(auth: GotAuth) -> httpx.AsyncClient: ...
# ASGI transport over auth.asgi(); keeps cookies; sends Origin and Content-Type: application/json
def adapter_conformance(factory: Callable[[], Awaitable[Adapter]]) -> type: ...
# returns a pytest test class to subclass in an adapter's tests
def load_vectors(name: str) -> list[dict[str, Any]]: ...                                 # reads spec/<name>.json

# For testing plugin and module endpoints before C1 and C3 are merged:
def fake_sessions() -> SessionService: ...     # in-memory sessions, same cookie names and token format
def make_context(**overrides: Any) -> EndpointContext: ...
# fakes for every service, including complete_sign_in / read_challenge / finish_challenge /
# create_user_record / delete_user / background;
# overrides e.g. principal=..., request=..., adapter=...
async def call_endpoint(endpoint: Endpoint[Any, Any], body: Mapping[str, Any] | None = None, *,
                        ctx: EndpointContext | None = None) -> Any: ...
# validates the input model, then runs the handler
def stub_resolver(prefix: str, principal: Principal) -> PrincipalResolver: ...
# lets integration tests use API-key and JWT principals before P1 and O1 exist
def stub_plugin(id: str, endpoints: Mapping[str, Callable[..., Awaitable[Any]]]) -> Plugin: ...
# a server_only fake of another plugin's 12.5 endpoints, e.g. stub_plugin("api_key", {"revoke_api_keys": fake});
# records calls in .calls so tests can assert on the cross-plugin shapes
async def fresh_database_url(base_url: str) -> AsyncIterator[str]: ...
# creates a uniquely named Postgres database for one test session and drops it afterwards
```

**Shared test files.** F2 owns `tests/conftest.py`, which holds the fixtures that wrap this kit; it is frozen at M0 like the contracts. Each work package puts its own fixtures in `tests/<area>/conftest.py`. pytest runs with `--import-mode=importlib`, so test files in different folders may share names.
