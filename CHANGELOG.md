# Changelog

All notable changes to GotAuth are listed here. The entries are built by
[towncrier](https://towncrier.readthedocs.io) from the news fragments in
[`changes/`](changes/README.md) when a release is made.

<!-- towncrier release notes start -->

## 0.0.1 (2026-10-12)

### Security

- Publish a security policy with response targets, a threat model and an OWASP ASVS 5.0 Level 2 mapping. Releases are published to PyPI with trusted publishing and PEP 740 attestations. (Q1)

### Features

- FastAPI integration: real routes with OpenAPI, dependencies for users, sessions, principals and API keys, a scope and permission guard, and exception handlers. (A1)
- Starlette and Litestar integration: an authentication backend and scope guard for Starlette, and a Litestar plugin with mounts, dependencies and guards. (A2)
- Add the `GotAuth` class: configuration checks, plugin assembly, a pure ASGI app and a fail-closed request pipeline with content-type and origin checks, rate limits (memory, database or secondary storage), principal resolution, hooks, transactions and events, the RFC 6749 error format, sign-in challenges and the user create and delete services. (C1)
- Email and password: sign-up, sign-in, sign-out, email verification, password reset and change, email change, profile update and account deletion, without revealing which emails have accounts. (C2)
- Sessions: hashed `gas_` tokens in cookies or bearer headers, sliding expiry, session list and revoke endpoints, an optional signed cookie cache, and memory and Redis secondary storage. (C3)
- Social login: GitHub, Google, Microsoft, Discord, GitLab, Apple and any OpenID Connect provider, with PKCE, browser-bound state, verified ID tokens and strict account linking. (C4)
- Email delivery: default templates for every email kind, a console sender for local development, SMTP and Resend senders, and background delivery off localhost. (D1)
- UI components (part 1): a typed fetch client, useSession, and shadcn registry items for sign-in, sign-up, social buttons, the user menu, the session list and the API key manager. (D2)
- Add the package layout, the `gotauth` console script entry point, the optional extras and typed lazy top-level exports (`GotAuth`, `AuthError`, `Principal`, `User`, `Session`). (F1)
- Add `gotauth.contracts` (every shared interface of CONTRACTS.md as typed code, with tests that compare the code to the document), the in-memory storage adapter and the `gotauth.testing` kit: fakes for every service, `make_context` and `call_endpoint` for unit tests, stubs for other plugins, an adapter conformance suite, per-session Postgres databases and spec vector loading. (F2)
- Add the crypto kit `gotauth.crypto.crypto_kit(secret, *, password_algorithm="scrypt")`: scrypt password hashing (argon2id with the `argon2` extra, verify-only bcrypt for imported passlib hashes), an unknown-user check that takes as long as a wrong password, HMAC signing and AES-256-GCM encryption bound to a purpose with secret rotation, HKDF key derivation, TOTP, numeric one-time codes, PKCE and monotonic ULIDs, plus language-neutral spec vectors in `spec/`. (F3)
- Add `gotauth check` (also `python -m gotauth.checkup`), a standard-library-only static scanner that finds 13 kinds of risky hand-written auth code (passlib and python-jose imports, hard-coded JWT secrets, unverified JWT decoding, timing-unsafe comparisons, disabled TLS checks, weak password hashing, insecure cookies and CORS) and prints a 0-100 score as text, JSON or SARIF 2.1.0. (G3)
- Add the `fastapi-nextjs` example: FastAPI and Next.js with email and password, GitHub login and API keys, runnable with `docker compose up`, with a test of the full walkthrough on SQLite and Postgres. Add the `litestar-htmx` example: server-rendered sign-up, sign-in, sign-out and API keys with Litestar and htmx. (G4)
- OAuth 2.1 authorization server and OpenID Connect provider: authorization code with PKCE, refresh rotation, client credentials, consent, CIMD clients, resource indicators, introspection, revocation and discovery. (O1)
- API keys: scoped, revocable keys for users, organizations and agents, hashed at rest and shown once, with per-key rate limits. (P1)
- SQLAlchemy storage for Postgres and SQLite, and the `gotauth` CLI: `init`, `migrate`, `generate` (Alembic revisions or SQL) and `secret`. (S1)

### Bug fixes

- Resolve the principal once per request in the FastAPI dependencies. A route using both `api_key_principal` and `require(...)` looked the key up twice, so it counted twice against the key's rate limit. (A1)
- Install python-multipart with the `fastapi` extra. Without it, FastAPI refused to build the router once a social provider was configured. (A1)
- Make `ApiKeyManager` and `SessionList` pass the React lint rules in `eslint-config-next`: the first load no longer sets state synchronously inside an effect, and the dialog copy has no unescaped apostrophes. (D2)
