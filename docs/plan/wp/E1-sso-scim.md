# E1: Enterprise SSO (OIDC + SAML) + SCIM

| | |
|---|---|
| Lane / wave | Enterprise / **Wave 4** |
| Size | XL: split into E1a, E1b, E1c before starting |
| Depends on | P5 (organizations), C4 (OIDC client code), M3 |
| Can start | only after the post-launch test passes and public requests exist (Notes) |
| Write scope | `src/gotauth/plugins/sso/**`, `src/gotauth/plugins/scim/**`, `tests/plugins/sso/**`, `tests/plugins/scim/**`, `changes/E1*.md` |
| Allowed new deps | E1a, E1c: none. E1b: one SAML library behind a new `saml` extra, chosen in E1b |

## Goal
Let an organization sign its members in through its own identity provider and provision them automatically, without a per-connection fee.

## Build
- **E1a per-org OIDC SSO:** model `sso_provider` (`organization_id` -> organization (cascade), `issuer`, `client_id`, `client_secret_enc`, `domains`, `enabled`, `created_at`); domain verification by DNS TXT token; `sign_in_sso` by email domain or org slug; reuse C4's OIDC code in `social/oidc.py` (JWKS, `iss`, `aud`, `nonce`); just-in-time provisioning creates the user and a `member` with a configured role; `ctx.auth.complete_sign_in(ctx, user, method="sso")` (`"sso"` is already a `SignInMethod`, section 5).
- **E1b SAML 2.0:** first a decision record comparing python3-saml and pysaml2: xmlsec cost (system libxmlsec1 or the `xmlsec1` binary), wheels for Linux, macOS and Windows on Python 3.11-3.14, maintenance, signature-wrapping advisories. Then SP-initiated login, signed assertions required, per-org SP metadata.
- **E1c SCIM 2.0 server** (RFC 7643, RFC 7644): `/scim/v2/Users` and `/scim/v2/Groups` (groups map to P5 roles or teams), `eq` filters on `userName` / `externalId`, PATCH, deprovisioning = deactivate + revoke sessions; per-org bearer tokens, prefixed and hashed at rest like API keys.
- Management endpoints gated by P5 `has_permission` with `{"sso": ["manage"]}` / `{"scim": ["manage"]}` (scope form `sso:manage`, 12.1). Endpoint ids verb first (`sign_in_sso`, `create_sso_provider`, `list_scim_users`, ...); tables get `advanced.table_prefix` automatically.
- New users are created only through `ctx.auth.create_user_record(ctx, data)` (CONTRACTS 13), so user database hooks run and `user.created` is emitted.

## Acceptance tests
- E1a: sign-in against a local mock IdP; unverified domain rejected; JIT creates exactly one member; another org's IdP token rejected.
- E1b: unsigned, wrapped, replayed, expired and wrong-audience assertions rejected.
- E1c: a SCIM compliance test tool passes for Users and Groups; an org A token cannot touch org B.

## Out of scope
Hosted connection management UI (X), LDAP, IdP-initiated SAML (later, on request).

## Notes
- Gate: post-launch test passed and >= 3 independent public requests (GitHub issues, discussions or posts) for SSO or SCIM.
- Needs a CCR first (section 14 says SSO and SCIM events come this way): id prefixes for the new models, event types, the `saml` extra, a token prefix for SCIM tokens, a purpose string for `client_secret_enc` (section 8), built-in `sso` and `scim` statements in P5 (12.3), and how SCIM tokens resolve (a new `Principal.via` value, or a check inside the SCIM handlers like O1's userinfo).
- Check current library versions and SCIM test tools at start.
