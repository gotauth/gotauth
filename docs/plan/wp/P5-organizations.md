# P5: Organizations + access control

| | |
|---|---|
| Lane / wave | Plugins / **Wave 3** |
| Size | L |
| Depends on | C3, A1 (`require(permission=...)`), D1 (kind `invitation`) |
| Can start | after M2, or earlier against `gotauth.testing` |
| Write scope | `src/gotauth/plugins/organization/**`, `tests/plugins/organization/**`, `changes/P5.*.md` |
| Allowed new deps | none |

## Goal
An `organization()` plugin (id `"organization"`, `from gotauth.plugins.organization import organization`): orgs, members, roles, invitations and app-defined permissions, plus `has_permission` (12.3), used by A1's `require(permission=...)`, P1's org keys and O3's org-owned agents.

## Build
- Models: `organization` (`org`): `name`, `slug` (unique, `[a-z0-9-]`, 3-48), `logo`, `metadata` (json), `created_at`. `member` (`mem`): `organization_id` -> organization (cascade), `user_id` -> user (cascade), `role`, `created_at`; `unique_together` (`organization_id`, `user_id`). `invitation` (`inv`): `organization_id` -> organization (cascade), `email`, `role`, `status` (`pending` | `accepted` | `rejected` | `canceled`), `inviter_id` -> user (set_null), `token_hash` (unique, `returned=False`), `expires_at`, `created_at`. Session field `active_organization_id` (set_null, `input=False`). Sets `Plugin.requires_email=True` (invitations, 9).
- `access_control(statements={"project": ["create", "read", "update", "delete"]}, roles={...})`. Built-in statements (12.3): `organization: [update, delete]`, `member: [create, update, delete]`, `invitation: [create, cancel]`, `api_key: [create, read, update, revoke]`, `agent: [create, read, update, revoke]`. Default roles: `owner` = all, `admin` = all but `organization:delete`, `member` = none; app roles replace them by name. Resolved at construction into frozen `"resource:action"` sets (12.1); unknown names -> `ConfigError`.
- Config: `allow_create` (bool or callable), `invitation_expires_in` "48h", `invitation_url` (app page), `membership_limit`, `teams` False.
- Endpoints (ids verb first), `session` unless noted; `organization_id` defaults to the active org:
  - `create_organization` POST `/organization/create` (creator = `owner`), `list_organizations` GET `/organization/list`, `get_organization` GET `/organization/get` (members, caller role), `update_organization` POST `/organization/update`, `delete_organization` POST `/organization/delete` (fresh), `set_active_organization` POST `/organization/set-active`.
  - `invite_member` POST `/organization/invite-member`: token `crypto.random_token("gav_")`, only the hash stored (long-token rule, 2.1), mail kind `invitation`; same response whether the email has an account (9.1). `accept_invitation`, `reject_invitation` POST `/organization/accept-invitation`, `/organization/reject-invitation` `{invitation_id, token}`: session email must equal the invitation email; compare-and-set `status` from `pending`. `cancel_invitation` POST `/organization/cancel-invitation`, `list_invitations` GET `/organization/list-invitations`.
  - `remove_member` POST `/organization/remove-member`, `update_member_role` POST `/organization/update-member-role`, `leave_organization` POST `/organization/leave`.
  - `has_permission` POST `/organization/has-permission`, principal. `{organization_id?, permissions: {resource: [action]}}` -> `{success: bool}`; a denial is `success=false`, not an error. Session: member role. Key or token acting for a user: role and `principal.has_scopes("resource:action")`. Org-owned key: scopes only, and its `organization_id` must match.
- Rules: unknown org and non-member both -> `ORG_NOT_A_MEMBER` (403); no permission -> `ORG_FORBIDDEN` (403); only owners grant or remove `owner`; last owner cannot leave, be removed or demoted -> `ORG_LAST_OWNER` (409). Owner changes update the org row first (row lock), then count owners, in one transaction.
- Also `ORG_SLUG_TAKEN` (409), `ORG_INVITATION_INVALID` (400, one code for wrong, used, expired, canceled or other-email).
- Events (14): `org.created`, `org.deleted`, `org.member_added`, `org.member_removed`, `org.role_changed`, `org.invitation_sent`, `org.invitation_accepted` (ids and roles; never the token).
- `Principal.organization_id`: C3 copies `session.active_organization_id` (12.1); P1 sets it for org keys. P5 adds no resolver.
- Teams (cut-list item 5, last, `teams=True`): `team` (`tem`) and `team_member` (`tmm`) models and `create_team`, `list_teams`, `remove_team`, `add_team_member`, `remove_team_member` under `/organization/team/...`.
- `delete_organization` revokes the org's API keys (P1 `revoke_api_keys` with `owner_type="organization"`) and org-owned agents (O3 server-only `revoke_agents`, `owner_type="organization"`) when those plugins are installed, through `ctx.auth.api.call(..., ctx=ctx)` with the CONTRACTS 12.5 shapes (tested with `stub_plugin`) (CONTRACTS 12.3); the owner is polymorphic, so no foreign key does it.

## Acceptance tests
- Hypothesis: `has_permission` is true only for pairs in the role's resolved set (no unlisted permission ever); scopes only narrow.
- Cross-org: a member of org A gets `ORG_NOT_A_MEMBER` on every org B endpoint and `success=false`, also with an org-A key.
- Invitation token: works once; reuse, expired, canceled, other email -> `ORG_INVITATION_INVALID`; no raw token in a DB dump.
- Last owner rules hold; two concurrent cross-demotions leave >= 1 owner (SQLite, Postgres).
- Admin cannot grant `owner`; `member` cannot invite.
- A session with an active org resolves a `Principal` whose `organization_id` is that org.
- A1 `require(permission={"project": ["create"]})`: 403 for `member`, pass for `admin` (skip until A1 merges).

## Out of scope
Org SSO and SCIM (E1), cross-org admin (P6), billing (X3), UI (D2).

## Notes
- Document `resource:action` as the scope form for app permissions (12.1; P1, O1 users).
