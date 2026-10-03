# F2: Contracts as code, memory adapter, testing kit

| | |
|---|---|
| Lane / wave | Foundation / **Phase 0**, after F1 (parallel with F3) |
| Size | M (2 agent-days) |
| Depends on | F1 |
| Can start | when F1 is merged |
| Write scope | `src/gotauth/contracts/**`, `src/gotauth/storage/memory/**`, `src/gotauth/testing/**`, `tests/conftest.py`, `tests/contracts/`, `tests/storage/memory/`, `tests/testing/`, `tests/integration/test_plugin_matrix.py`, `changes/F2.*.md` |
| Allowed new deps | none (pytest is imported lazily inside `adapter_conformance`) |

## Goal
Every interface in CONTRACTS.md exists as typed code, plus a memory adapter and the `gotauth.testing` kit, so Wave 1 builds in parallel. Frozen at M0.

## Build
- `contracts/`: one module per section, Protocols and data types only (small helpers allowed): `primitives.py` (1), `schema.py` (2), `core_schema.py` (2.1-2.2: `CORE_SCHEMA` + record models), `adapter.py` (3), `http.py` (4), `endpoints.py` (5), `errors.py` (6, `ERROR_CODES`, `ErrorOut`), `sessions.py` (7), `crypto.py` (8), `email.py` (9), `protection.py` (10, `DEFAULT_RATE_LIMITS`), `social.py` (11), `principal.py` (12.1), `oauth.py` (12.2-12.4: plugin model schemas, the 12.3 endpoint table, MCP signatures), `config.py` (13), `http_models.py` (13.1), `events.py` (14). `__init__.py`: `CONTRACT_VERSION = 0`, re-exports.
- Write every name exactly as CONTRACTS states it, including the pre-M0 revision:
  - 2: `ModelSchema.unique_together` and `table`; `session.remember_me`, `verification.attempts`, `account` unique pair in `CORE_SCHEMA`.
  - 2.2 names: ConfigError, SchemaConflictError(ConfigError), UniqueViolation(model, fields), HookPayload, ASGIApp, ResolvedConfig (secrets as SecretStr), AuthApi, FakeClock, FakeMailer, FakeOAuthProvider, and EndpointContext / GotAuthInstance as Protocols with every section 13 member (`complete_sign_in`, `finish_challenge`, `delete_user`, `background`, `drain`, `well_known`).
  - 5: `SignInMethod`, `Endpoint.input_format` / `error_format`, `PrincipalCheck`, the full `Plugin` (`well_known_endpoints`, `database_hooks`, `principal_checks`, `requires_email`).
  - 4 / 7: `cookie_name(base, *, base_url, prefix)` -> `"<prefix>.<base>"`, with `__Secure-` in front when `base_url` is https; `secure_cookies(base_url)` (False only for http localhost / 127.0.0.1); `SessionConfig` with every section 7 field.
  - 10: `RateLimitRule.key="identifier"` + `identifier`, `RateLimitConfig`. 13: every config model of the table, `ModelHooks`, `DatabaseHooks`. 13.1: `CORE_ENDPOINTS` (id, method, path, auth, fresh_session, input_format, output, owner) and the response models incl. `SessionWithUserOut`.
- UlidIds calls the crypto kit lazily (`# TODO(F3)`).
- `storage/memory`: `MemoryAdapter` (`id = "memory"`): copies rows in and out; `bind_schema(schema, *, table_prefix="auth_")`; `update` = compare-and-set on at most one row; `delete` returns the count and applies `Reference.on_delete` (cascade, set_null, restrict), so `delete_user` cascades as in SQL; `unique` (None values exempt) and `unique_together` raise UniqueViolation; `transaction()` snapshots and restores on error, nested calls reuse it, transactions serialized by an asyncio.Lock.
- `testing/`, every function of section 15:
  - `fake_clock` (`.advance()`, `.set()`), `seq_ids` (counter per prefix), `fake_mailer` (`.sent`, `.last(kind, to)`), `load_vectors` (finds `spec/` walking up from the CWD).
  - `fake_oauth_provider`: `users` keyed by authorization code; `exchange_code` checks the PKCE verifier against the challenge it saw; `store_provider_tokens=False`, `callback_method="GET"`.
  - `make_auth` / `make_client`: real code against the section 13 signature, lazy `gotauth.GotAuth` import (`NotImplementedError("TODO(C1)")` until C1 merges). `make_client` sends `Origin` and `Content-Type: application/json`.
  - `fake_sessions`: hashed `gas_` tokens in `ctx.adapter`, `remember_me` stored, section 7 cookie names via `cookie_name`.
  - `make_context(**overrides)`: memory adapter bound to `CORE_SCHEMA` + `plugins=` schemas, fake clock, seq ids, the F3 crypto kit (stand-in `testing/_crypto_stub.py` until F3 merges), `fake_sessions()`, an EmailService passing `data` through to `fake_mailer` (with `drain()`). A stub `auth` mirroring C1's brief: `complete_sign_in` runs `interceptors=` and sets the section 5 challenge cookie or calls `ctx.sessions.create`; `finish_challenge(ctx, satisfied=)` reads that cookie; `delete_user` runs `database_hooks=`, deletes and emits `user.deleted`; `background` tracks tasks. Records `.cookies` and `.events`.
  - `call_endpoint`: validates input like C1 (INVALID_REQUEST, no input values), enforces `auth` and `scopes`, runs the handler.
  - `stub_resolver(prefix, principal)`: a PrincipalResolver returning `principal` for any credential with that prefix.
  - `adapter_conformance(factory)`: pytest class for every section 3 rule, on a test schema using every FieldType, a `unique_together` pair and each `on_delete` mode.
- Also define `ChallengeState` and make the `make_context` fakes cover `read_challenge` and `create_user_record` (CONTRACTS 13, 15); `EmailMessage.from_address`; the `introspection_client` parameter is part of the 12.4 signatures.
- **Parallel-work support** (CONTRACTS 4, 12.5, 15):
  - `contracts/protection.py` implements `resolve_client_ip` and `validate_redirect` (with the 10.1 rules), so C2, C4, A1 and A2 can use them before C1 merges.
  - `http_models.py` also holds every 12.5 output model, including `ApiKeyOut` and `OAuthClientOut`, so P1, O1, O3 and P5 share one definition.
  - `stub_plugin(id, endpoints)` records calls, and `fresh_database_url(base_url)` creates and drops one uniquely named Postgres database per test session.
  - `tests/conftest.py` exposes the kit as fixtures and is frozen at M0.
  - `tests/integration/test_plugin_matrix.py` discovers every `gotauth.plugins.<name>` module that exports a `<name>` factory. It builds `make_auth(plugins=[...])` with all of them and with each pair, which catches duplicate endpoint ids, paths, error codes, schema fields and cookie names at merge time. It is skipped until C1 merges and never needs editing when a plugin lands.

## Acceptance tests
- Memory adapter passes `adapter_conformance`. The suite pins Where semantics: `and` binds tighter than `or`; `contains` = substring on strings, membership on `string_list`; `is_null` takes True/False; `eq None` = IS NULL.
- Hypothesis + `asyncio.gather`: 20 compare-and-set updates -> exactly 1 row back; 20 single-use deletes -> exactly one returns 1; rollback restores the prior state exactly.
- `to_timedelta`: int, timedelta, "90s", "15m", "12h", "7d"; else ValueError. `merge_schemas` conflict -> SchemaConflictError. `has_scopes` property test.
- Table tests: IdPrefix == 1, ERROR_CODES == 6 (incl. UNSUPPORTED_MEDIA_TYPE), DEFAULT_RATE_LIMITS == 10.2 (incl. identifier and `/passkey/*` rules), AuthEventType == 14, CORE_ENDPOINTS == 13.1, CORE_SCHEMA == 2.1, the 12.3 table.
- `cookie_name` / `secure_cookies` for https, `http://localhost`, `http://127.0.0.1`.
- `make_context`: challenge round trip (`complete_sign_in` with an interceptor, then `finish_challenge`); `delete_user` cascades to sessions and accounts.
- pyright strict on all three packages; `gotauth.contracts` imports only core deps.
- `fake_sessions`, `make_context`, `call_endpoint`, `stub_resolver` work now with a sample endpoint.
- `resolve_client_ip`: spoofed `x-forwarded-for` from an untrusted peer is ignored; the right-most untrusted entry wins (Hypothesis over proxy chains). `validate_redirect` rejects `//x`, `/\x`, look-alike hosts and `javascript:`.
- `stub_plugin` records the exact 12.5 input shape; `fresh_database_url` leaves no database behind after the session.

## Out of scope
- GotAuth and the pipeline (C1); crypto (F3); SQL adapter (S1).

## Notes
- Memory transactions hold a lock, so root-adapter calls inside an open transaction deadlock. Document it.
- Anything CONTRACTS leaves open that code must decide goes in the PR description for the integrator to fold into CONTRACTS.md before M0.
