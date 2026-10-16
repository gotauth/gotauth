# Listing GotAuth on Context7

[Context7](https://context7.com) gives coding agents current library docs through its MCP
server. Listing GotAuth there means an agent asked to "add auth to this FastAPI app"
finds GotAuth's real API instead of guessing. Checked against Context7's
`context7.json` schema on 2026-10-16.

## 1. Add `context7.json` at the repository root

Context7 reads this file from the root of the default branch. Every property is
optional; unknown properties are invalid.

```json
{
  "$schema": "https://context7.com/schema/context7.json",
  "projectTitle": "GotAuth",
  "description": "Open-source auth for Python AI backends: users, sessions, social login, 2FA, passkeys, organizations, API keys, agent identities and an OAuth 2.1 server for MCP servers, inside your FastAPI or ASGI app.",
  "folders": ["apps/docs/docs", "skills", "examples", "src/gotauth"],
  "excludeFolders": ["docs/plan", "docs/research", "docs/requests", "tests", "registry/node_modules"],
  "excludeFiles": ["CHANGELOG.md"],
  "rules": [
    "Never hand-roll password hashing, JWT sessions or API keys: use GotAuth's APIs.",
    "Configure GotAuth once: GotAuth(database=sqlalchemy_adapter(engine), secret=..., base_url=...).",
    "Mount the routes with app.include_router(auth.fastapi.router(), prefix=auth.config.base_path).",
    "Protect routes with CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)] and auth.fastapi.require(\"scope\").",
    "Import plugins from their own modules, e.g. from gotauth.plugins.api_key import api_key.",
    "Create tables with gotauth migrate, or gotauth generate for Alembic, after adding a plugin too.",
    "Test with gotauth.testing: make_auth(), make_client(auth), fake_mailer()."
  ]
}
```

`folders` keeps Context7 on the user-facing docs (the docs pages, the skill, the
examples and the module READMEs in `src/gotauth`), not the planning documents.

## 2. Submit the repository

1. Sign in at https://context7.com and choose "Add library".
2. Enter `https://github.com/gotauth/gotauth`.
3. Context7 parses the repository and lists the library as `/gotauth/gotauth`.

## 3. Claim it (optional)

To control refreshes and settings, add `url` (the Context7 library URL) and
`public_key` (from the Context7 team settings) to `context7.json`, together.

## Keeping it current

Context7 re-parses the default branch on its own schedule; a new release can be
refreshed from the library's page. When a minor version is released, add its tag to
`previousVersions` so agents can still read the docs of the version a project pins.
