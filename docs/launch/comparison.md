# GotAuth compared with other Python auth options

> **Draft for the public comparison page.** Last checked: **2026-10-04** (data retrieved 2026-10-03).
>
> **GotAuth has not shipped yet.** Every GotAuth cell says "planned" and links to the work package that builds it. Those cells change to "yes" only when the feature is released.

## How to read this page
- **yes:** the project's own docs or source show the feature.
- **partial:** it exists with a real limit, named in the cell (for example, client only, or paid plans only).
- **planned:** on the project's published roadmap, not shipped.
- **no:** not in the project's docs, feature list or source on the check date. The link goes to the page we checked, so you can see for yourself.
- **Every cell links to its source.** Version numbers, stars and download counts are snapshots from the date above.
- **Corrections are welcome.** If a cell is wrong or out of date, open an issue with a link and we will fix it.

## Core auth
| Project | Runs in your app, users in your database | Email + password | Social login | 2FA (TOTP) | Passkeys | Organizations / roles |
|---|---|---|---|---|---|---|
| **GotAuth** | [planned][ga-plan] | [planned][ga-c2] | [planned][ga-c4] | [planned][ga-p2] | [planned][ga-p3] | [planned][ga-p5] |
| fastapi-users | [yes][fu-db] | [yes][fu-reset] | [yes][fu-oauth] | [no][fu-readme] | [no][fu-readme] | [no: superuser flag only][fu-user] |
| reauth | [partial: you wire storage][ra-start] | [planned: passwords on roadmap; email OTP yes][ra-road] | [yes][ra-road] | [yes: TOTP, HOTP, MFA flows][ra-road] | [planned][ra-road] | [planned: teams][ra-road] |
| better-auth-server | [yes][ba-readme] | [yes][ba-server] | [yes: 36 providers][ba-server] | [yes: plugin][ba-server] | [yes: plugin][ba-server] | [yes: plugin][ba-server] |
| AuthX | [partial: no user model][ax-user] | [no][ax-readme] | [no: validates external tokens only][ax-oauth] | [no][ax-docs] | [no][ax-docs] | [partial: scopes and policies][ax-scopes] |
| Authlib | [partial: protocol library, bring your user model][al-as-flask] | [no][al-as-flask] | [yes: OAuth client][al-client] | [partial: separate otpauth package][al-otp] | [no][al-docs] | [no][al-docs] |
| FastMCP built-in providers | [no: sign-in at an external identity provider][fm-auth] | [no: left to the identity provider][fm-auth] | [yes: GitHub, Google and others][fm-proxy] | [no: left to the identity provider][fm-auth] | [no: left to the identity provider][fm-auth] | [partial: scope and role checks on token claims][fm-authz] |
| Auth0 | [no: vendor-hosted][a0-tenant] | [yes][a0-db] | [yes][a0-social] | [yes: paid plans][a0-mfa] | [yes][a0-passkeys] | [yes][a0-orgs] |
| Clerk | [no: vendor-hosted][ck-security] | [yes][ck-options] | [yes][ck-social] | [yes: paid plans][ck-options] | [yes: paid plans][ck-pricing] | [yes][ck-orgs] |
| WorkOS | [no: vendor-hosted][wo-dpa] | [yes][wo-password] | [yes][wo-social] | [yes][wo-mfa] | [partial: hosted UI only][wo-passkeys] | [yes][wo-roles] |
| django-allauth | [yes][dj-intro] | [yes][dj-views] | [yes][dj-providers] | [yes][dj-mfa] | [yes][dj-webauthn] | [no][dj-docs] |

## API keys, OAuth server and MCP
| Project | API keys | OAuth 2.1 / OIDC authorization server | Protects an MCP server (RFC 9728 metadata) | CIMD for MCP clients | FastAPI integration |
|---|---|---|---|---|---|
| **GotAuth** | [planned][ga-p1] | [planned][ga-o1] | [planned][ga-o2] | [planned][ga-o1] | [planned][ga-a1] |
| fastapi-users | [no][fu-readme] | [no][fu-readme] | [no][fu-readme] | [no][fu-readme] | [yes][fu-docs] |
| reauth | [no][ra-road] | [planned: OIDC server][ra-road] | [no][ra-road] | [no][ra-road] | [planned: framework wrappers][ra-road] |
| better-auth-server | [yes: plugin][ba-server] | [yes: oauth-provider plugin][ba-oauth] | [no: no MCP plugin in the plugin list][ba-plugins] | [no: not ported][ba-cimd] | [yes][ba-server] |
| AuthX | [no][ax-readme] | [no][ax-readme] | [no][ax-readme] | [no][ax-readme] | [yes][ax-readme] |
| Authlib | [no][al-docs] | [yes: Flask and Django][al-as] | [no: open issue][al-9728] | [no: open issue][al-cimd] | [partial: client only][al-fastapi] |
| FastMCP built-in providers | [no: static tokens are for development][fm-tokens] | [partial: proxy issues its own tokens; full server is abstract][fm-full] | [yes][fm-remote] | [yes: on by default][fm-cimd] | [partial: mounts MCP into FastAPI][fm-fastapi] |
| Auth0 | [partial: machine-to-machine client credentials][a0-m2m] | [yes][a0-dcr] | [yes: Auth for MCP][a0-mcp] | [partial: admin imports each client][a0-cimd] | [partial: Python SDKs, some in beta][a0-api-py] |
| Clerk | [yes][ck-apikeys] | [yes][ck-oauth] | [yes: Next.js and Express guides][ck-mcp] | [yes][ck-cimd] | [partial: backend SDK verifies tokens][ck-py] |
| WorkOS | [yes][wo-apikeys] | [yes][wo-connect] | [yes][wo-mcp] | [yes: off by default][wo-mcp] | [partial: Python SDK with login helpers][wo-py] |
| django-allauth | [no][dj-tokens] | [yes: OIDC provider][dj-idp] | [partial: server side only, no RFC 9728 helper][dj-idp-int] | [yes][dj-cimd] | [no: Django only][dj-headless] |

## Status and cost
| Project | License | Latest release | GitHub stars | Downloads, last 30 days | Price |
|---|---|---|---|---|---|
| **GotAuth** | MIT (planned) | not released | n/a | n/a | free |
| fastapi-users | MIT | [15.0.5, 2026-03-27][fu-pypi]; [maintenance mode][fu-maint] | [6,248][fu-gh] | [1.27M][fu-stats] | free |
| reauth | MIT | [0.4.2, 2026-09-26][ra-pypi]; early stage | [11][ra-gh] | [13.4K][ra-stats] | free |
| better-auth-server | MIT | [1.1.0, 2026-09-30][ba-pypi] | [3][ba-gh] | [530][ba-stats] | free |
| AuthX | MIT | [1.7.1, 2026-06-27][ax-pypi] | [1,203][ax-gh] | [34.0K][ax-stats] | free |
| Authlib | BSD-3-Clause | [1.8.0, 2026-08-30][al-pypi] | [5,430][al-gh] | [103.4M][al-stats] | free; [paid support plans][al-plans] |
| FastMCP | Apache-2.0 | [4.0.10, 2026-09-25][fm-pypi] | [27,962][fm-gh] | [50.1M][fm-stats] | free; the identity provider may charge |
| Auth0 | proprietary | hosted | n/a | n/a | [free up to 25,000 MAU; paid plans and add-ons][a0-pricing] |
| Clerk | proprietary | hosted | n/a | n/a | [free up to 50,000 retained users per app; SSO: 1 connection on Pro, then $75/mo each][ck-pricing] |
| WorkOS | proprietary | hosted | n/a | n/a | [free up to 1M users; SSO $125/mo per connection for the first 15][wo-pricing] |
| django-allauth | MIT | [65.19.7, 2026-10-01][dj-pypi] | [10,379 (GitHub mirror)][dj-gh] | [4.76M][dj-stats] | free |

Downloads come from the pypistats `recent` API and include CI and mirror traffic. Stars come from the GitHub API.

## When to choose something else
- **fastapi-users.** You already run it and need register, login, reset, verify and OAuth login for FastAPI. It is stable, widely used (1.27M downloads a month) and still gets security fixes ([announcement][fu-maint]).
- **reauth.** You want small, well-tested building blocks from the fastapi-users author (email OTP, TOTP, HOTP, MFA flows, sessions), you run Python 3.14, and you are happy to wire storage and routes yourself. It has a published security policy ([SECURITY.md][ra-security]) and CI with coverage ([workflow][ra-ci]).
- **better-auth-server.** You run a Better Auth TypeScript app and want a Python service on the same database and wire format, or you want the widest plugin set today: 27 plugins and four framework integrations ([README][ba-server]). Its CI ran 3,049 tests, all passing, on the commit tagged 1.1.0 ([CI run][ba-ci]).
- **AuthX.** You only need JWT issuing and checking in FastAPI (header or cookie tokens, CSRF, refresh, revocation) and you manage users yourself ([README][ax-readme]).
- **Authlib.** You want standards building blocks with wide spec coverage: an OAuth client, JOSE, and an authorization server for Flask or Django ([specs][al-specs]). You are ready to build the user side yourself.
- **FastMCP's built-in providers.** Your users already sign in with an identity provider (Google, GitHub, Entra ID, Auth0, WorkOS, Keycloak and others), and you only need that login in front of an MCP server. CIMD works by default ([docs][fm-cimd]).
- **Auth0, Clerk or WorkOS.** You want hosted sign-in pages, compliance reports such as SOC 2, enterprise SSO and SCIM, and a vendor that runs and operates the service. You accept per-user or per-connection pricing and user data on the vendor's servers ([Auth0 compliance][a0-compliance], [Clerk security][ck-security], [WorkOS admin portal][wo-admin]).
- **django-allauth.** You build on Django. It covers headless APIs, MFA, passkeys and an OIDC provider with DCR and CIMD today ([release notes][dj-notes]).

## Where GotAuth fits (planned)
GotAuth aims at one gap in the tables above:
- an embeddable OAuth 2.1 server for MCP clients, with CIMD, running on **your own user table** inside a FastAPI or ASGI app
- API keys and agent identities in the same library
- sessions, social login, 2FA, passkeys and organizations

None of it has shipped. This section will link to releases and test results as each part lands ([build plan][ga-plan]).

<!-- Sources. Retrieved 2026-10-03, links checked 2026-10-04. -->
[ga-plan]: ../build-plan.md
[ga-c2]: ../plan/wp/C2-email-password.md
[ga-c4]: ../plan/wp/C4-social.md
[ga-p1]: ../plan/wp/P1-api-keys.md
[ga-p2]: ../plan/wp/P2-two-factor.md
[ga-p3]: ../plan/wp/P3-passkeys.md
[ga-p5]: ../plan/wp/P5-organizations.md
[ga-o1]: ../plan/wp/O1-oauth-server.md
[ga-o2]: ../plan/wp/O2-mcp.md
[ga-a1]: ../plan/wp/A1-fastapi.md

[fu-db]: https://fastapi-users.github.io/fastapi-users/latest/configuration/databases/sqlalchemy/
[fu-reset]: https://fastapi-users.github.io/fastapi-users/latest/configuration/routers/reset/
[fu-oauth]: https://fastapi-users.github.io/fastapi-users/latest/configuration/oauth/
[fu-readme]: https://github.com/fastapi-users/fastapi-users/blob/master/README.md
[fu-user]: https://fastapi-users.github.io/fastapi-users/latest/usage/current-user/
[fu-docs]: https://fastapi-users.github.io/fastapi-users/latest/
[fu-pypi]: https://pypi.org/project/fastapi-users/
[fu-maint]: https://github.com/fastapi-users/fastapi-users/discussions/1543
[fu-gh]: https://github.com/fastapi-users/fastapi-users
[fu-stats]: https://pypistats.org/packages/fastapi-users

[ra-start]: https://frankie567.github.io/reauth/getting-started/
[ra-road]: https://github.com/frankie567/reauth#roadmap
[ra-pypi]: https://pypi.org/project/reauth/
[ra-gh]: https://github.com/frankie567/reauth
[ra-stats]: https://pypistats.org/packages/reauth
[ra-security]: https://github.com/frankie567/reauth/blob/main/SECURITY.md
[ra-ci]: https://github.com/frankie567/reauth/blob/main/.github/workflows/build.yml

[ba-readme]: https://github.com/oumarbarry/better-auth-py#readme
[ba-server]: https://github.com/oumarbarry/better-auth-py/blob/main/src/better_auth/README.md
[ba-oauth]: https://better-auth-py.oumarbarry.dev/plugins/oauth-provider
[ba-plugins]: https://github.com/oumarbarry/better-auth-py/blob/d2826ca2e05ecfa8c15ff22bae9430e4807a460f/src/better_auth/plugins_ext/__init__.py
[ba-cimd]: https://github.com/oumarbarry/better-auth-py/blob/d2826ca2e05ecfa8c15ff22bae9430e4807a460f/src/better_auth/plugins_ext/oauth_provider/register.py#L568
[ba-pypi]: https://pypi.org/project/better-auth-server/
[ba-gh]: https://github.com/oumarbarry/better-auth-py
[ba-stats]: https://pypistats.org/packages/better-auth-server
[ba-ci]: https://github.com/oumarbarry/better-auth-py/actions/runs/36656784799

[ax-user]: https://authx.yezz.me/callbacks/user/
[ax-readme]: https://github.com/yezz123/authx/blob/main/README.md
[ax-oauth]: https://authx.yezz.me/extra/OAuth2/
[ax-docs]: https://authx.yezz.me/
[ax-scopes]: https://authx.yezz.me/get-started/scopes/
[ax-pypi]: https://pypi.org/project/authx/
[ax-gh]: https://github.com/yezz123/authx
[ax-stats]: https://pypistats.org/packages/authx

[al-as-flask]: https://docs.authlib.org/en/stable/oauth2/authorization-server/flask/authorization-server.html
[al-client]: https://docs.authlib.org/en/stable/oauth2/client/web/index.html
[al-otp]: https://otp.authlib.org/
[al-docs]: https://docs.authlib.org/en/stable/
[al-as]: https://docs.authlib.org/en/stable/oauth2/authorization-server/index.html
[al-9728]: https://github.com/authlib/authlib/issues/752
[al-cimd]: https://github.com/authlib/authlib/issues/900
[al-fastapi]: https://docs.authlib.org/en/stable/oauth2/client/web/fastapi.html
[al-specs]: https://docs.authlib.org/en/stable/oauth2/specs/index.html
[al-pypi]: https://pypi.org/project/Authlib/
[al-gh]: https://github.com/authlib/authlib
[al-stats]: https://pypistats.org/packages/authlib
[al-plans]: https://authlib.org/plans

[fm-auth]: https://gofastmcp.com/servers/auth/authentication
[fm-proxy]: https://gofastmcp.com/servers/auth/oauth-proxy
[fm-authz]: https://gofastmcp.com/servers/authorization
[fm-tokens]: https://gofastmcp.com/servers/auth/token-verification
[fm-full]: https://gofastmcp.com/servers/auth/full-oauth-server
[fm-remote]: https://gofastmcp.com/servers/auth/remote-oauth
[fm-cimd]: https://gofastmcp.com/servers/auth/oauth-proxy#cimd-support
[fm-fastapi]: https://gofastmcp.com/integrations/fastapi
[fm-pypi]: https://pypi.org/project/fastmcp/
[fm-gh]: https://github.com/PrefectHQ/fastmcp
[fm-stats]: https://pypistats.org/packages/fastmcp

[a0-tenant]: https://auth0.com/docs/get-started/auth0-overview/create-tenants
[a0-db]: https://auth0.com/docs/authenticate/database-connections
[a0-social]: https://auth0.com/docs/authenticate/identity-providers/social-identity-providers
[a0-mfa]: https://auth0.com/docs/secure/multi-factor-authentication/multi-factor-authentication-factors
[a0-passkeys]: https://auth0.com/docs/authenticate/database-connections/passkeys
[a0-orgs]: https://auth0.com/docs/manage-users/organizations/organizations-overview
[a0-m2m]: https://auth0.com/docs/get-started/authentication-and-authorization-flow/client-credentials-flow
[a0-dcr]: https://auth0.com/docs/get-started/applications/dynamic-client-registration
[a0-mcp]: https://auth0.com/ai/docs/mcp/why-auth-for-mcp
[a0-cimd]: https://auth0.com/docs/get-started/auth0-overview/create-applications/register-applications-with-cimd
[a0-api-py]: https://pypi.org/project/auth0-api-python/
[a0-pricing]: https://auth0.com/pricing
[a0-compliance]: https://auth0.com/docs/secure/data-privacy-and-compliance

[ck-security]: https://clerk.com/security
[ck-options]: https://clerk.com/docs/guides/configure/auth-strategies/sign-up-sign-in-options
[ck-social]: https://clerk.com/docs/guides/configure/auth-strategies/social-connections/overview
[ck-pricing]: https://clerk.com/pricing
[ck-orgs]: https://clerk.com/docs/guides/organizations/overview
[ck-apikeys]: https://clerk.com/docs/guides/development/machine-auth/api-keys
[ck-oauth]: https://clerk.com/docs/guides/configure/auth-strategies/oauth/how-clerk-implements-oauth
[ck-mcp]: https://clerk.com/docs/guides/ai/mcp/build-mcp-server
[ck-cimd]: https://clerk.com/changelog/2026-09-17-client-id-metadata-documents-ga
[ck-py]: https://github.com/clerk/clerk-sdk-python

[wo-dpa]: https://workos.com/legal/data-processing-addendum
[wo-password]: https://workos.com/docs/authkit/email-password
[wo-social]: https://workos.com/docs/authkit/social-login
[wo-mfa]: https://workos.com/docs/authkit/mfa
[wo-passkeys]: https://workos.com/docs/authkit/passkeys
[wo-roles]: https://workos.com/docs/authkit/roles-and-permissions
[wo-apikeys]: https://workos.com/docs/authkit/api-keys
[wo-connect]: https://workos.com/docs/authkit/connect
[wo-mcp]: https://workos.com/docs/authkit/mcp
[wo-py]: https://workos.com/docs/sdks/python
[wo-pricing]: https://workos.com/pricing
[wo-admin]: https://workos.com/docs/admin-portal

[dj-intro]: https://docs.allauth.org/en/latest/introduction/index.html
[dj-views]: https://docs.allauth.org/en/latest/account/views.html
[dj-providers]: https://docs.allauth.org/en/latest/socialaccount/providers/index.html
[dj-mfa]: https://docs.allauth.org/en/latest/mfa/introduction.html
[dj-webauthn]: https://docs.allauth.org/en/latest/mfa/webauthn.html
[dj-docs]: https://docs.allauth.org/en/latest/
[dj-tokens]: https://docs.allauth.org/en/latest/headless/token-strategies/index.html
[dj-idp]: https://docs.allauth.org/en/latest/idp/openid-connect/introduction.html
[dj-idp-int]: https://docs.allauth.org/en/latest/idp/openid-connect/integrations.html
[dj-cimd]: https://docs.allauth.org/en/latest/idp/openid-connect/client-id-metadata-document.html
[dj-headless]: https://docs.allauth.org/en/latest/headless/introduction.html
[dj-notes]: https://docs.allauth.org/en/latest/release-notes/recent.html
[dj-pypi]: https://pypi.org/project/django-allauth/
[dj-gh]: https://github.com/pennersr/django-allauth
[dj-stats]: https://pypistats.org/packages/django-allauth
