# gotauth.plugins.organization

Organizations (work package P5): organizations, members, roles, invitations and
app-defined permissions, plus `has_permission` (CONTRACTS 12.3). A1's
`require(permission=...)`, P1's organization keys and O3's organization agents use it.

```python
from gotauth.plugins.organization import access_control, organization

access = access_control(
    statements={"project": ["create", "read", "update", "delete"]},
    roles={"member": {"project": ["read"]}},
)
auth = GotAuth(..., plugins=[organization(access=access)])

can_create = auth.fastapi.require(permission={"project": ["create"]})
```

## Roles and permissions

**Built-in statements:**

| Resource | Actions |
|---|---|
| `organization` | `update`, `delete` |
| `member` | `create`, `update`, `delete` |
| `invitation` | `create`, `cancel` |
| `api_key` | `create`, `read`, `update`, `revoke` |
| `agent` | `create`, `read`, `update`, `revoke` |

**App statements** are added beside them.

**Default roles:**
- `owner`: everything
- `admin`: everything but `organization:delete`
- `member`: nothing

App roles with the same name replace these. Roles are resolved once into
`"resource:action"` sets, and a role naming an unknown resource or action is a
`ConfigError`.

A permission is the same string as an API key or OAuth scope (`"project:create"`).
That's how `has_permission` narrows a key or token acting for a user.

## Options

- **`access`:** from `access_control(...)`.
- **`allow_create`:** a bool, or `fn(user) -> bool` (may be async).
- **`invitation_expires_in`:** `"48h"` by default.
- **`invitation_url`:** the app page that accepts invitations; it gets `?invitation_id=...&token=...`. The default is `<base_url>/accept-invitation`.
- **`membership_limit`:** pending invitations count toward it.

The plugin needs an email sender for invitations.

## Endpoints

All need a session, except `has_permission` (any principal). `organization_id`
defaults to the session's active organization.

| Endpoint | Needs |
|---|---|
| `POST /organization/create` | `allow_create`; the creator is the owner |
| `GET /organization/list`, `GET /organization/get` | membership |
| `POST /organization/update` | `organization:update` |
| `POST /organization/delete` | `organization:delete`, fresh session. Also revokes the organization's API keys (P1) and agents (O3) |
| `POST /organization/set-active` | membership; `null` clears it |
| `POST /organization/invite-member` | `invitation:create`; only roles within your own rights, only owners invite owners |
| `POST /organization/accept-invitation`, `/reject-invitation` | `{invitation_id, token}` from the email, signed in with the invited email |
| `POST /organization/cancel-invitation` | `invitation:cancel` |
| `GET /organization/list-invitations` | `invitation:create` |
| `POST /organization/remove-member` | `member:delete`; only members whose role is within your own rights, only owners remove owners |
| `POST /organization/update-member-role` | `member:update`; the old and new role must both be within your own rights, and only owners grant or change `owner` |
| `POST /organization/leave` | membership |
| `POST /organization/has-permission` | `{organization_id?, permissions: {resource: [action]}}` gives `{success}`; a denial is `success: false` |

## `has_permission`

- **A session:** the member's role must grant every pair.
- **A key or token acting for a user:** the role, and the key's scopes must include every pair.
- **An organization's own key or agent:** its scopes only, and only for its own organization.
- **Any key or token tied to an organization** counts in that organization only, even when it also acts for a user.
- **An organization agent's OAuth token** carries no organization, so it gets `success: false`; the agent acts for the organization through its API keys. A linked client acting for the organization would skip the limits on those keys (allowed scopes, expiry, rate limit, audit), so this stays closed until it can apply them (issue #42).
- **A non-member, an unknown organization or an empty request:** `success: false`.

## Rules

- **Membership:** an unknown organization and a non-member both answer `ORG_NOT_A_MEMBER` (403), so organization ids say nothing.
- **Missing permission:** `ORG_FORBIDDEN` (403).
- **The last owner** cannot leave, be removed or be demoted: `ORG_LAST_OWNER` (409).
  - Owner and role changes write the organization row first (a column that never changes), then read the caller's membership and permission again and count the owners, in one transaction. Two owners who demote each other at the same time leave one, and a caller demoted meanwhile is refused. Tested on memory, SQLite and Postgres.
  - **Deleting the last owner's account:** blocked (`ORG_LAST_OWNER`) while the organization has other members; an organization whose last owner is its only member is deleted with the account.
- **Invitations:**
  - **Token:** a `gav_` token, of which only the hash is stored. Each invitation works once.
  - **Every failure** (a wrong token, used, expired, canceled, or another email) answers `ORG_INVITATION_INVALID` (400).
  - **Same answer for any email:** inviting gives the same response whether or not the email has an account.
  - **Replacement:** a new invitation for the same email cancels the pending one.
- **Leaving:** removing a member or leaving clears that organization from the user's active sessions, and drops their secondary-storage copies, now and again after the commit.
- **Setting the active organization** also drops the cached copies of the session (secondary storage, and the session data cookie of that browser).
- **Stale caches:** another browser's session data cookie keeps the old value until it expires (`cookie_cache.max_age`). `has_permission` always checks membership, so a stale `Principal.organization_id` grants nothing.
- **Coupling:** the cache keys follow C3's `session:<token hash>` format.
- **Events:** `org.created`, `org.deleted`, `org.member_added`, `org.member_removed`, `org.role_changed`, `org.invitation_sent` and `org.invitation_accepted` carry ids and roles, never the token.
- **Slugs:** 3 to 48 characters of `a-z`, `0-9` and `-`, unique (`ORG_SLUG_TAKEN`, 409).

## Not in v0.1

Teams inside organizations (the last cut-list item). Organization SSO and SCIM are E1.
