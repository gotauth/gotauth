"""Organizations (work package P5): organizations, invitations, roles, the last-owner
rules, cross-organization isolation and ``has_permission``."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import ConfigError, Principal, Where
from gotauth.contracts.oauth import PLUGIN_ENDPOINTS
from gotauth.plugins.organization import access_control, organization
from gotauth.testing import stub_plugin

from .conftest import ACCESS, world


def test_has_permission_matches_the_contract_table() -> None:
    spec = next(s for s in PLUGIN_ENDPOINTS if s.id == "has_permission")
    found = next(e for e in organization().endpoints if e.id == "has_permission")
    assert (found.method, found.path, found.auth) == (spec.method, spec.path, spec.auth)


def test_access_control_resolves_roles() -> None:
    assert "project:read" in ACCESS.permissions("member")
    assert "organization:delete" in ACCESS.permissions("owner")
    assert "organization:delete" not in ACCESS.permissions("admin")
    assert "project:delete" in ACCESS.permissions("admin")
    with pytest.raises(ConfigError, match="unknown resource"):
        access_control(roles={"viewer": {"nothing": ["read"]}})
    with pytest.raises(ConfigError, match="unknown action"):
        access_control(roles={"viewer": {"member": ["fly"]}})
    with pytest.raises(ConfigError, match="built-in"):
        access_control(statements={"member": ["read"]})


# ---------------------------------------------------------------- organizations


async def test_create_list_get_update_and_delete() -> None:
    w = world()
    org_id = await w.org("ada")
    ada = await w.user("ada")
    listed = (await ada.get("/organization/list")).json()["organizations"]
    assert [(o["id"], o["role"]) for o in listed] == [(org_id, "owner")]
    got = (
        await ada.get("/organization/get", params={"organization_id": org_id})
    ).json()
    assert got["role"] == "owner"
    assert got["members"][0]["email"] == "ada@example.com"
    taken = await (await w.user("bob")).post(
        "/organization/create", json={"name": "Other", "slug": "acme"}
    )
    assert taken.json()["error"]["code"] == "ORG_SLUG_TAKEN"
    renamed = await ada.post(
        "/organization/update", json={"organization_id": org_id, "name": "Acme Inc"}
    )
    assert renamed.json()["name"] == "Acme Inc"
    deleted = await ada.post("/organization/delete", json={"organization_id": org_id})
    assert deleted.status_code == 200, deleted.text
    assert (await ada.get("/organization/list")).json() == {"organizations": []}


async def test_creating_can_be_restricted() -> None:
    w = world(
        plugins=[organization(allow_create=lambda user: user.email.startswith("a"))]
    )
    assert (
        await (await w.user("ada")).post(
            "/organization/create", json={"name": "A", "slug": "a-org"}
        )
    ).status_code == 200
    refused = await (await w.user("bob")).post(
        "/organization/create", json={"name": "B", "slug": "b-org"}
    )
    assert refused.json()["error"]["code"] == "ORG_FORBIDDEN"


# ---------------------------------------------------------------- invitations


async def test_an_invitation_works_once_for_its_email() -> None:
    w = world()
    org_id = await w.org("ada")
    invitation_id, token = await w.invite("ada", org_id, "bob")
    carol = await w.user("carol")
    other = await carol.post(
        "/organization/accept-invitation",
        json={"invitation_id": invitation_id, "token": token},
    )
    assert other.json()["error"]["code"] == "ORG_INVITATION_INVALID"
    bob = await w.user("bob")
    wrong = await bob.post(
        "/organization/accept-invitation",
        json={"invitation_id": invitation_id, "token": "gav_wrong"},
    )
    assert wrong.json()["error"]["code"] == "ORG_INVITATION_INVALID"
    ok = await bob.post(
        "/organization/accept-invitation",
        json={"invitation_id": invitation_id, "token": token},
    )
    assert ok.status_code == 200 and ok.json()["role"] == "member"
    again = await bob.post(
        "/organization/accept-invitation",
        json={"invitation_id": invitation_id, "token": token},
    )
    assert again.json()["error"]["code"] == "ORG_INVITATION_INVALID"
    dump = repr(await w.auth.database.find_many("invitation", []))
    assert token not in dump


async def test_expired_and_canceled_invitations_are_invalid() -> None:
    w = world()
    org_id = await w.org("ada")
    expiring = await w.invite("ada", org_id, "bob")
    w.clock.advance("49h")
    bob = await w.user("bob")
    late = await bob.post(
        "/organization/accept-invitation",
        json={"invitation_id": expiring[0], "token": expiring[1]},
    )
    assert late.json()["error"]["code"] == "ORG_INVITATION_INVALID"
    canceled = await w.invite("ada", org_id, "bob")
    ada = await w.user("ada")
    done = await ada.post(
        "/organization/cancel-invitation", json={"invitation_id": canceled[0]}
    )
    assert done.status_code == 200
    after = await bob.post(
        "/organization/accept-invitation",
        json={"invitation_id": canceled[0], "token": canceled[1]},
    )
    assert after.json()["error"]["code"] == "ORG_INVITATION_INVALID"


async def test_inviting_answers_the_same_with_or_without_an_account() -> None:
    w = world()
    org_id = await w.org("ada")
    await w.user("bob")
    ada = await w.user("ada")
    answers = []
    for email in ("bob@example.com", "nobody@example.com"):
        response = await ada.post(
            "/organization/invite-member",
            json={"organization_id": org_id, "email": email},
        )
        body = response.json()
        answers.append((response.status_code, sorted(body), body["status"]))
    assert answers[0] == answers[1]


# ---------------------------------------------------------------- roles


async def test_role_rules() -> None:
    w = world()
    org_id = await w.org("ada")
    await w.join("ada", org_id, "bob", role="admin")
    await w.join("ada", org_id, "carol", role="member")
    carol = await w.user("carol")
    refused = await carol.post(
        "/organization/invite-member",
        json={"organization_id": org_id, "email": "dan@example.com"},
    )
    assert refused.json()["error"]["code"] == "ORG_FORBIDDEN"
    bob = await w.user("bob")
    no_owner = await bob.post(
        "/organization/update-member-role",
        json={"organization_id": org_id, "user_id": w.ids["carol"], "role": "owner"},
    )
    assert no_owner.json()["error"]["code"] == "ORG_FORBIDDEN"
    invite_owner = await bob.post(
        "/organization/invite-member",
        json={"organization_id": org_id, "email": "dan@example.com", "role": "owner"},
    )
    assert invite_owner.json()["error"]["code"] == "ORG_FORBIDDEN"
    promoted = await bob.post(
        "/organization/update-member-role",
        json={"organization_id": org_id, "user_id": w.ids["carol"], "role": "admin"},
    )
    assert promoted.json()["role"] == "admin"


async def test_the_last_owner_stays() -> None:
    w = world()
    org_id = await w.org("ada")
    ada = await w.user("ada")
    for path, body in (
        ("/organization/leave", {"organization_id": org_id}),
        (
            "/organization/update-member-role",
            {"organization_id": org_id, "user_id": w.ids["ada"], "role": "admin"},
        ),
    ):
        response = await ada.post(path, json=body)
        assert response.json()["error"]["code"] == "ORG_LAST_OWNER", path
    await w.join("ada", org_id, "bob", role="owner")
    removed = await (await w.user("bob")).post(
        "/organization/remove-member",
        json={"organization_id": org_id, "user_id": w.ids["ada"]},
    )
    assert removed.status_code == 200
    last = await (await w.user("bob")).post(
        "/organization/leave", json={"organization_id": org_id}
    )
    assert last.json()["error"]["code"] == "ORG_LAST_OWNER"


@pytest.mark.parametrize("database", ["memory", "sqlite"])
async def test_concurrent_cross_demotions_leave_an_owner(
    database: str, tmp_path: Any
) -> None:
    options: dict[str, Any] = {}
    engine = None
    if database == "sqlite":
        from sqlalchemy.ext.asyncio import create_async_engine

        from gotauth.storage.sqlalchemy import sqlalchemy_adapter

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'db.sqlite'}")
        options["database"] = sqlalchemy_adapter(engine)
    w = world(**options)
    if engine is not None:
        from gotauth.storage.sqlalchemy import create_missing

        await create_missing(engine, w.auth.schema)
    org_id = await w.org("ada")
    await w.join("ada", org_id, "bob", role="owner")
    ada, bob = await w.user("ada"), await w.user("bob")
    await asyncio.gather(
        ada.post(
            "/organization/update-member-role",
            json={"organization_id": org_id, "user_id": w.ids["bob"], "role": "member"},
        ),
        bob.post(
            "/organization/update-member-role",
            json={"organization_id": org_id, "user_id": w.ids["ada"], "role": "member"},
        ),
    )
    owners = await w.auth.database.count(
        "member", [Where("organization_id", org_id), Where("role", "owner")]
    )
    assert owners >= 1
    if engine is not None:
        await engine.dispose()


# ---------------------------------------------------------------- isolation


async def test_other_organizations_are_out_of_reach() -> None:
    w = world()
    org_a = await w.org("ada", "alpha")
    org_b = await w.org("carol", "beta")
    ada = await w.user("ada")
    for method, path, body in (
        ("GET", "/organization/get", {"organization_id": org_b}),
        ("POST", "/organization/update", {"organization_id": org_b, "name": "x"}),
        ("POST", "/organization/delete", {"organization_id": org_b}),
        ("POST", "/organization/set-active", {"organization_id": org_b}),
        (
            "POST",
            "/organization/invite-member",
            {"organization_id": org_b, "email": "x@example.com"},
        ),
        ("GET", "/organization/list-invitations", {"organization_id": org_b}),
        (
            "POST",
            "/organization/remove-member",
            {"organization_id": org_b, "user_id": w.ids["carol"]},
        ),
        (
            "POST",
            "/organization/update-member-role",
            {"organization_id": org_b, "user_id": w.ids["carol"], "role": "member"},
        ),
        ("POST", "/organization/leave", {"organization_id": org_b}),
    ):
        if method == "GET":
            response = await ada.get(path, params=body)
        else:
            response = await ada.post(path, json=body)
        assert response.json()["error"]["code"] == "ORG_NOT_A_MEMBER", path
    check = {"organization_id": org_b, "permissions": {"project": ["read"]}}
    assert (await ada.post("/organization/has-permission", json=check)).json() == {
        "success": False
    }
    key = await ada.post(
        "/api-keys",
        json={"name": "k", "scopes": ["project:read"], "organization_id": org_a},
    )
    assert key.status_code == 200, key.text
    response = await ada.post(
        "/organization/has-permission",
        json=check,
        headers={"authorization": f"Bearer {key.json()['key']}"},
    )
    assert response.json() == {"success": False}


async def test_an_organization_key_has_its_scopes_in_its_organization() -> None:
    w = world()
    org_id = await w.org("ada")
    ada = await w.user("ada")
    key = (
        await ada.post(
            "/api-keys",
            json={"name": "k", "scopes": ["project:read"], "organization_id": org_id},
        )
    ).json()["key"]
    headers = {"authorization": f"Bearer {key}"}
    for permissions, expected in (
        ({"project": ["read"]}, True),
        ({"project": ["create"]}, False),
    ):
        response = await ada.post(
            "/organization/has-permission",
            json={"organization_id": org_id, "permissions": permissions},
            headers=headers,
        )
        assert response.json() == {"success": expected}


async def test_the_active_organization_is_on_the_principal() -> None:
    from gotauth.sessions import memory_secondary_storage

    w = world(secondary_storage=memory_secondary_storage())
    org_id = await w.org("ada")
    ada = await w.user("ada")
    cookies = {name: value for name, value in ada.cookies.items()}
    before = await w.auth.get_principal({}, cookies)
    assert before.organization_id is None
    response = await ada.post(
        "/organization/set-active", json={"organization_id": org_id}
    )
    assert response.json() == {"organization_id": org_id}
    after = await w.auth.get_principal({}, cookies)
    assert after.organization_id == org_id
    allowed = await ada.post(
        "/organization/has-permission", json={"permissions": {"project": ["delete"]}}
    )
    assert allowed.json() == {"success": True}  # the active org, as its owner


async def test_deleting_revokes_the_organization_s_keys_and_agents() -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    async def revoke_keys(**body: Any) -> dict[str, int]:
        calls.append(("revoke_api_keys", body))
        return {"revoked": 1}

    async def revoke_agents(**body: Any) -> dict[str, int]:
        calls.append(("revoke_agents", body))
        return {"revoked": 1}

    w = world(
        plugins=[
            organization(access=ACCESS),
            stub_plugin("api_key", {"revoke_api_keys": revoke_keys}),
            stub_plugin("agent", {"revoke_agents": revoke_agents}),
        ]
    )
    org_id = await w.org("ada")
    deleted = await (await w.user("ada")).post(
        "/organization/delete", json={"organization_id": org_id}
    )
    assert deleted.status_code == 200, deleted.text
    owner = {"owner_type": "organization", "owner_id": org_id}
    assert calls == [("revoke_api_keys", owner), ("revoke_agents", owner)]


# ---------------------------------------------------------------- property


ROLE = st.dictionaries(
    st.sampled_from(["project", "member", "invitation"]),
    st.lists(
        st.sampled_from(["create", "read", "update", "delete", "cancel"]),
        unique=True,
        max_size=3,
    ),
    max_size=3,
)


def _valid(grants: dict[str, list[str]]) -> dict[str, list[str]]:
    known = ACCESS.statements
    return {
        resource: [a for a in actions if a in known[resource]]
        for resource, actions in grants.items()
    }


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(grants=ROLE, asked=ROLE)
async def test_has_permission_never_grants_an_unlisted_pair(
    grants: dict[str, list[str]], asked: dict[str, list[str]]
) -> None:
    access = access_control(
        statements={"project": ["create", "read", "update", "delete"]},
        roles={"member": _valid(grants)},
    )
    w = world(plugins=[organization(access=access)])
    org_id = await w.org("ada")
    await w.join("ada", org_id, "bob")
    bob = await w.user("bob")
    response = await bob.post(
        "/organization/has-permission",
        json={"organization_id": org_id, "permissions": asked},
    )
    wanted = {f"{r}:{a}" for r, actions in asked.items() for a in actions}
    expected = bool(wanted) and wanted <= access.permissions("member")
    assert response.json() == {"success": expected}


async def test_fastapi_require_permission_uses_the_member_s_role() -> None:
    # A1's require(permission=...) against the real plugin.
    w = world()
    org_id = await w.org("ada")
    await w.join("ada", org_id, "bob", role="member")
    await w.join("ada", org_id, "carol", role="admin")
    app = FastAPI()
    app.include_router(w.auth.fastapi.router(), prefix="/api/auth")
    w.auth.fastapi.add_exception_handlers(app)
    can_create = w.auth.fastapi.require(permission={"project": ["create"]})

    @app.post("/projects")
    async def create_project(
        principal: Principal = Depends(can_create),  # noqa: B008 - FastAPI style
    ) -> dict[str, str | None]:
        return {"user": principal.user_id}

    statuses: dict[str, int] = {}
    for name in ("bob", "carol"):
        browser = await w.user(name)
        await browser.post("/organization/set-active", json={"organization_id": org_id})
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://localhost:8000",
            headers={"origin": "http://localhost:8000"},
            cookies=dict(browser.cookies.items()),
        ) as http:
            statuses[name] = (await http.post("/projects")).status_code
    assert statuses == {"bob": 403, "carol": 200}
