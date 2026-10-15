"""Admin plugin (work package P6)."""

from __future__ import annotations

import os
import re
from collections.abc import AsyncGenerator
from dataclasses import dataclass, field
from typing import Any, cast

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts.adapter import Where
from gotauth.contracts.config import DatabaseHooks, ModelHooks
from gotauth.contracts.endpoints import Endpoint, EndpointContext, Plugin
from gotauth.contracts.errors import ConfigError
from gotauth.contracts.http_models import StatusOut
from gotauth.contracts.principal import Principal
from gotauth.plugins.admin import admin
from gotauth.plugins.api_key import api_key
from gotauth.storage.memory import memory_adapter
from gotauth.testing import fake_clock, make_auth, make_client

PASSWORD = "correct horse battery"
ADMIN_ENDPOINTS = admin().endpoints
SAMPLE_BODIES: dict[str, dict[str, Any]] = {
    "create_user": {"email": "new@example.com"},
    "set_user_role": {"role": "editor"},
    "set_user_password": {"new_password": PASSWORD + "!"},
}


@dataclass
class TokenResolver:
    """OAuth-token principals for one user, standing in for O1's resolver."""

    prefixes: tuple[str, ...] = ("eyJ",)
    user_id: str = ""

    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal:
        del ctx, credential
        return Principal(
            via="oauth_token",
            credential_id="tok_1",
            user_id=self.user_id,
            scopes=frozenset(),
        )


async def _whoami(ctx: EndpointContext, _: None) -> StatusOut:
    assert ctx.principal is not None
    return StatusOut(status=str(ctx.principal.user_id))


@dataclass
class World:
    auth: Any  # Any: GotAuth
    clock: Any  # Any: ManualClock
    db: Any  # Any: the memory adapter
    tokens: TokenResolver
    events: list[Any] = field(default_factory=list[Any])  # Any: AuthEvent
    deleted: list[str] = field(default_factory=list[str])
    users: dict[str, httpx.AsyncClient] = field(
        default_factory=dict[str, httpx.AsyncClient]
    )
    ids: dict[str, str] = field(default_factory=dict[str, str])

    async def user(self, name: str) -> httpx.AsyncClient:
        """A signed-in browser for ``<name>@example.com``."""
        if name not in self.users:
            http = make_client(self.auth)
            response = await http.post(
                "/sign-up/email",
                json={"email": f"{name}@example.com", "password": PASSWORD},
            )
            assert response.status_code == 200, response.text
            self.users[name] = http
            self.ids[name] = str(response.json()["user"]["id"])
        return self.users[name]

    async def admin(self, name: str = "ada") -> httpx.AsyncClient:
        http = await self.user(name)
        await self.db.update("user", [Where("id", self.ids[name])], {"role": "admin"})
        return http

    async def sign_in(self, name: str, password: str = PASSWORD) -> httpx.Response:
        return await make_client(self.auth).post(
            "/sign-in/email",
            json={"email": f"{name}@example.com", "password": password},
        )

    async def row(self, name: str) -> dict[str, Any]:
        found = await self.db.find_one("user", [Where("id", self.ids[name])])
        assert found is not None
        return dict(found)

    def types(self) -> list[str]:
        return [event.type for event in self.events]


def world(**options: Any) -> World:
    clock = fake_clock()
    db = options.pop("database", None) or memory_adapter()
    tokens = TokenResolver()
    holder: dict[str, World] = {}

    async def on_event(event: Any) -> None:
        holder["w"].events.append(event)

    async def record_delete(ctx: EndpointContext | None, row: dict[str, Any]) -> None:
        del ctx
        holder["w"].deleted.append(row["id"])

    probe = Plugin(
        id="probe",
        endpoints=(Endpoint("whoami", "GET", "/whoami", _whoami, auth="principal"),),
        principal_resolvers=(tokens,),
        database_hooks=DatabaseHooks(
            hooks={"user": ModelHooks(before_delete=record_delete)}
        ),
    )
    plugins = [admin(**options.pop("admin", {})), api_key(), probe]
    auth = make_auth(
        clock=clock,
        database=db,
        email_password={"require_email_verification": False},
        plugins=plugins,
        on_event=on_event,
        **options,
    )
    holder["w"] = World(auth=auth, clock=clock, db=db, tokens=tokens)
    return holder["w"]


def _path(endpoint: Endpoint[Any, Any], user_id: str) -> str:
    return endpoint.path.replace("{user_id}", user_id)


async def _call(
    http: httpx.AsyncClient,
    endpoint: Endpoint[Any, Any],
    user_id: str,
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    body = SAMPLE_BODIES.get(endpoint.id)
    path = _path(endpoint, user_id)
    if endpoint.method == "GET":
        return await http.get(path, headers=headers)
    if body is None:
        return await http.request(endpoint.method, path, headers=headers)
    return await http.request(endpoint.method, path, json=body, headers=headers)


def _code(response: httpx.Response) -> str:
    return str(response.json()["error"]["code"])


# ---------------------------------------------------------------- access


@pytest.mark.parametrize("endpoint", ADMIN_ENDPOINTS, ids=lambda e: e.id)
async def test_admin_endpoints_refuse_everyone_but_admin_sessions(
    endpoint: Endpoint[Any, Any],
) -> None:
    w = world()
    await w.admin("ada")
    bob = await w.user("bob")
    target = w.ids["bob"]
    anonymous = await _call(make_client(w.auth), endpoint, target)
    assert (anonymous.status_code, _code(anonymous)) == (401, "UNAUTHENTICATED")
    if endpoint.id != "stop_impersonating":
        member = await _call(bob, endpoint, target)
        assert (member.status_code, _code(member)) == (403, "FORBIDDEN")
    # An admin's API key: admin endpoints take sessions only.
    ada = w.users["ada"]
    created = await ada.post("/api-keys", json={"name": "ops"})
    key = created.json()["key"]
    keyed = await _call(make_client(w.auth), endpoint, target, {"x-api-key": key})
    assert (keyed.status_code, _code(keyed)) == (401, "UNAUTHENTICATED")


@pytest.mark.parametrize(
    "endpoint",
    [e for e in ADMIN_ENDPOINTS if e.id != "stop_impersonating"],
    ids=lambda e: e.id,
)
async def test_an_impersonation_session_cannot_call_admin_endpoints(
    endpoint: Endpoint[Any, Any],
) -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    await w.user("cy")
    started = await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert started.status_code == 200, started.text
    response = await _call(ada, endpoint, w.ids["cy"])
    assert (response.status_code, _code(response)) == (403, "FORBIDDEN")


async def test_admin_user_ids_make_an_admin_without_a_role() -> None:
    probe = world()
    await probe.user("ada")
    w = world(admin={"admin_user_ids": (probe.ids["ada"],)})
    ada = await w.user("ada")
    assert w.ids["ada"] == probe.ids["ada"]
    assert (await ada.get("/admin/users")).status_code == 200


def test_config_errors() -> None:
    with pytest.raises(ConfigError):
        admin(admin_roles=())
    with pytest.raises(ConfigError):
        admin(impersonation_expires_in=0)


# ---------------------------------------------------------------- users


async def test_list_users_searches_and_counts() -> None:
    w = world()
    ada = await w.admin("ada")
    for name in ("bob", "bea", "cy"):
        w.clock.advance("1s")
        await w.user(name)
    await w.db.update("user", [Where("id", w.ids["cy"])], {"name": "Cy Bobson"})
    found = (await ada.get("/admin/users", params={"search": "Bob"})).json()
    assert found["total"] == 2
    assert {u["email"] for u in found["users"]} == {
        "bob@example.com",
        "cy@example.com",
    }
    assert found["users"][0]["role"] == "user"
    page = (await ada.get("/admin/users", params={"limit": 2})).json()
    assert page["total"] == 4
    assert [u["email"] for u in page["users"]] == ["cy@example.com", "bea@example.com"]
    by_email = await ada.get(
        "/admin/users", params={"sort_by": "email", "sort_direction": "asc"}
    )
    assert [u["email"] for u in by_email.json()["users"]] == [
        "ada@example.com",
        "bea@example.com",
        "bob@example.com",
        "cy@example.com",
    ]
    too_many = await ada.get("/admin/users", params={"limit": 101})
    assert too_many.status_code == 400


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    count=st.integers(min_value=0, max_value=9),
    limit=st.integers(min_value=1, max_value=4),
    sort_by=st.sampled_from(["created_at", "email"]),
    direction=st.sampled_from(["asc", "desc"]),
)
async def test_paging_returns_every_user_once(
    count: int, limit: int, sort_by: str, direction: str
) -> None:
    w = world()
    ada = await w.admin("ada")
    for index in range(count):
        made = await ada.post("/admin/users", json={"email": f"u{index}@example.com"})
        assert made.status_code == 200, made.text
    seen: list[str] = []
    offset = 0
    while True:
        page = await ada.get(
            "/admin/users",
            params={
                "limit": limit,
                "offset": offset,
                "sort_by": sort_by,
                "sort_direction": direction,
            },
        )
        users = page.json()["users"]
        seen.extend(u["id"] for u in users)
        assert page.json()["total"] == count + 1
        if len(users) < limit:
            break
        offset += limit
    assert len(seen) == len(set(seen)) == count + 1


async def test_create_user_with_a_password_can_sign_in() -> None:
    w = world()
    ada = await w.admin("ada")
    made = await ada.post(
        "/admin/users",
        json={
            "email": " Dee@Example.com ",
            "password": PASSWORD,
            "name": "Dee",
            "role": "editor",
            "email_verified": True,
        },
    )
    assert made.status_code == 200, made.text
    body = made.json()
    assert (body["email"], body["role"], body["banned"]) == (
        "dee@example.com",
        "editor",
        False,
    )
    assert body["email_verified"] is True
    assert (await w.sign_in("dee")).status_code == 200
    again = await ada.post("/admin/users", json={"email": "dee@example.com"})
    assert (again.status_code, _code(again)) == (409, "USER_ALREADY_EXISTS")
    short = await ada.post(
        "/admin/users", json={"email": "eve@example.com", "password": "short"}
    )
    assert _code(short) == "PASSWORD_TOO_SHORT"
    sneaky = await ada.post(
        "/admin/users", json={"email": "fay@example.com", "banned": True}
    )
    assert sneaky.status_code == 400
    await w.auth.drain()
    assert "user.created" in w.types()


async def test_users_cannot_set_admin_fields_themselves() -> None:
    w = world()
    bob = await w.user("bob")
    for field_name, value in (
        ("role", "admin"),
        ("banned", False),
        ("ban_reason", "x"),
        ("ban_expires_at", "2030-01-01T00:00:00Z"),
    ):
        response = await bob.patch("/user", json={field_name: value})
        assert response.status_code == 400, field_name
    sign_up = await make_client(w.auth).post(
        "/sign-up/email",
        json={"email": "mal@example.com", "password": PASSWORD, "role": "admin"},
    )
    assert sign_up.status_code == 400
    assert (await w.row("bob"))["role"] == "user"
    assert (await bob.get("/admin/users")).status_code == 403


async def test_get_user_and_unknown_users() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    got = (await ada.get(f"/admin/users/{w.ids['bob']}")).json()
    assert (got["email"], got["ban_reason"]) == ("bob@example.com", None)
    missing = await ada.get("/admin/users/usr_missing")
    assert (missing.status_code, _code(missing)) == (404, "NOT_FOUND")
    removed = await ada.delete("/admin/users/usr_missing")
    assert removed.status_code == 404


async def test_remove_user_runs_the_user_delete_hooks_and_cascades() -> None:
    w = world()
    ada = await w.admin("ada")
    bob = await w.user("bob")
    await w.sign_in("bob")
    response = await ada.delete(f"/admin/users/{w.ids['bob']}")
    assert response.status_code == 200, response.text
    assert w.deleted == [w.ids["bob"]]
    assert await w.db.find_many("session", [Where("user_id", w.ids["bob"])]) == []
    assert (await bob.get("/whoami")).status_code == 401
    own = await ada.delete(f"/admin/users/{w.ids['ada']}")
    assert _code(own) == "ADMIN_CANNOT_TARGET_SELF"
    await w.auth.drain()
    assert "user.deleted" in w.types()


async def test_remove_user_needs_a_fresh_session() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    w.clock.advance("25h")
    stale = await ada.delete(f"/admin/users/{w.ids['bob']}")
    assert (stale.status_code, _code(stale)) == (403, "FRESH_SESSION_REQUIRED")


async def test_set_user_role_makes_an_admin_and_emits() -> None:
    w = world()
    ada = await w.admin("ada")
    bob = await w.user("bob")
    changed = await ada.post(
        f"/admin/users/{w.ids['bob']}/role", json={"role": "admin"}
    )
    assert changed.json()["role"] == "admin"
    assert (await bob.get("/admin/users")).status_code == 200
    bad = await ada.post(f"/admin/users/{w.ids['bob']}/role", json={"role": "Ad min"})
    assert bad.status_code == 400
    await w.auth.drain()
    event = next(e for e in w.events if e.type == "user.role_changed")
    assert event.user_id == w.ids["bob"]
    assert dict(event.data) == {"role": "admin", "previous_role": "user"}


async def test_set_user_password_signs_the_user_out() -> None:
    w = world()
    ada = await w.admin("ada")
    bob = await w.user("bob")
    new = PASSWORD + " 2"
    response = await ada.post(
        f"/admin/users/{w.ids['bob']}/password", json={"new_password": new}
    )
    assert response.status_code == 200, response.text
    assert (await bob.get("/whoami")).status_code == 401
    assert (await w.sign_in("bob")).status_code == 401
    assert (await w.sign_in("bob", new)).status_code == 200
    # A user without a password gets a credential account.
    made = await ada.post("/admin/users", json={"email": "dee@example.com"})
    dee = made.json()["id"]
    await ada.post(f"/admin/users/{dee}/password", json={"new_password": new})
    w.ids["dee"] = dee
    assert (await w.sign_in("dee", new)).status_code == 200
    # The admin's own session survives setting their own password.
    await ada.post(f"/admin/users/{w.ids['ada']}/password", json={"new_password": new})
    assert (await ada.get("/whoami")).status_code == 200
    await w.auth.drain()
    assert w.types().count("password.changed") == 3


# ---------------------------------------------------------------- bans


async def test_ban_signs_out_and_blocks_sign_in() -> None:
    w = world()
    ada = await w.admin("ada")
    bob = await w.user("bob")
    banned = await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={"reason": "spam"})
    assert banned.status_code == 200, banned.text
    assert (banned.json()["banned"], banned.json()["ban_reason"]) == (True, "spam")
    assert (await bob.get("/whoami")).status_code == 401
    right = await w.sign_in("bob")
    assert (right.status_code, _code(right)) == (403, "ADMIN_USER_BANNED")
    wrong = await w.sign_in("bob", "wrong password!")
    assert _code(wrong) == "INVALID_CREDENTIALS"
    unbanned = await ada.post(f"/admin/users/{w.ids['bob']}/unban")
    assert unbanned.json()["banned"] is False
    assert (await w.sign_in("bob")).status_code == 200
    own = await ada.post(f"/admin/users/{w.ids['ada']}/ban", json={})
    assert _code(own) == "ADMIN_CANNOT_TARGET_SELF"
    await w.auth.drain()
    assert {"user.banned", "user.unbanned"} <= set(w.types())


async def test_a_ban_with_expires_in_ends_by_itself() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={"expires_in": "1h"})
    assert _code(await w.sign_in("bob")) == "ADMIN_USER_BANNED"
    w.clock.advance("61m")
    assert (await w.sign_in("bob")).status_code == 200
    row = await w.row("bob")
    assert (row["banned"], row["ban_expires_at"]) == (False, None)
    for bad in ("0s", "-1h", "soon", 10**30):
        response = await ada.post(
            f"/admin/users/{w.ids['bob']}/ban", json={"expires_in": bad}
        )
        assert response.status_code == 400, bad


async def test_a_ban_blocks_api_keys_and_oauth_tokens() -> None:
    w = world()
    ada = await w.admin("ada")
    bob = await w.user("bob")
    key = (await bob.post("/api-keys", json={"name": "cli"})).json()["key"]
    w.tokens.user_id = w.ids["bob"]
    client = make_client(w.auth)
    by_key = {"x-api-key": key}
    by_token = {"authorization": "Bearer eyJ.token"}
    assert (await client.get("/whoami", headers=by_key)).status_code == 200
    assert (await client.get("/whoami", headers=by_token)).status_code == 200
    await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={})
    for headers in (by_key, by_token):
        refused = await client.get("/whoami", headers=headers)
        assert (refused.status_code, _code(refused)) == (403, "ADMIN_USER_BANNED")
    await ada.post(f"/admin/users/{w.ids['bob']}/unban")
    for headers in (by_key, by_token):
        assert (await client.get("/whoami", headers=headers)).status_code == 200


async def test_the_ban_flag_is_cached_for_at_most_five_seconds() -> None:
    w = world()
    await w.admin("ada")
    await w.user("bob")
    w.tokens.user_id = w.ids["bob"]
    client = make_client(w.auth)
    headers = {"authorization": "Bearer eyJ.token"}
    assert (await client.get("/whoami", headers=headers)).status_code == 200
    # Banned by another process: this one sees it within 5 seconds.
    await w.db.update("user", [Where("id", w.ids["bob"])], {"banned": True})
    w.clock.advance("5s")
    assert (await client.get("/whoami", headers=headers)).status_code == 403


async def test_a_banned_user_s_cached_session_is_refused() -> None:
    w = world(sessions={"cookie_cache": {"enabled": True}})
    ada = await w.admin("ada")
    bob = await w.user("bob")
    assert (await bob.get("/whoami")).status_code == 200
    await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={})
    refused = await bob.get("/whoami")
    assert (refused.status_code, _code(refused)) == (403, "ADMIN_USER_BANNED")


# ---------------------------------------------------------------- sessions


async def test_list_and_revoke_user_sessions() -> None:
    w = world()
    ada = await w.admin("ada")
    bob = await w.user("bob")
    await w.sign_in("bob")
    listed = (await ada.get(f"/admin/users/{w.ids['bob']}/sessions")).json()
    assert len(listed["sessions"]) == 2
    first = listed["sessions"][0]["id"]
    one = await ada.post(
        f"/admin/users/{w.ids['bob']}/sessions/revoke", json={"session_id": first}
    )
    assert one.json() == {"count": 1}
    other = await ada.post(
        f"/admin/users/{w.ids['ada']}/sessions/revoke",
        json={"session_id": listed["sessions"][1]["id"]},
    )
    assert other.status_code == 404
    rest = await ada.post(f"/admin/users/{w.ids['bob']}/sessions/revoke", json={})
    assert rest.json() == {"count": 1}
    assert (await bob.get("/whoami")).status_code == 401


# ---------------------------------------------------------------- impersonation


async def test_impersonation_round_trip() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    w.clock.advance("1s")
    started = await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert started.status_code == 200, started.text
    body = started.json()
    assert body["session"]["impersonated_by"] == w.ids["ada"]
    assert body["token"] is None
    assert "gotauth.admin_session" in ada.cookies
    assert (await ada.get("/whoami")).json() == {"status": w.ids["bob"]}
    session = (await ada.get("/session")).json()["session"]
    assert session["impersonated_by"] == w.ids["ada"]
    admin_view = make_client(w.auth)
    await admin_view.post(
        "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
    )
    listed = await admin_view.get(f"/admin/users/{w.ids['bob']}/sessions")
    assert [s["impersonated_by"] for s in listed.json()["sessions"]] == [
        w.ids["ada"],
        None,
    ]
    stopped = await ada.post("/admin/stop-impersonating")
    assert stopped.json() == {"restored": True}
    assert (await ada.get("/whoami")).json() == {"status": w.ids["ada"]}
    assert (await ada.get("/admin/users")).status_code == 200
    assert "gotauth.admin_session" not in ada.cookies
    not_one = await ada.post("/admin/stop-impersonating")
    assert _code(not_one) == "ADMIN_NOT_IMPERSONATING"
    await w.auth.drain()
    started_event = next(e for e in w.events if e.type == "admin.impersonation_started")
    assert started_event.data["admin_id"] == w.ids["ada"]
    assert started_event.data["target_id"] == w.ids["bob"]
    assert "admin.impersonation_stopped" in w.types()


async def test_an_impersonation_expires_after_an_hour_even_when_used() -> None:
    w = world(sessions={"update_age": "1m"})
    ada = await w.admin("ada")
    await w.user("bob")
    await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    for _minute in range(5):
        w.clock.advance("11m")
        assert (await ada.get("/whoami")).status_code == 200
    w.clock.advance("6m")
    assert (await ada.get("/whoami")).status_code == 401
    assert (
        await w.db.find_many("session", [Where("impersonated_by", w.ids["ada"])]) == []
    )


async def test_impersonation_needs_a_fresh_session() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    w.clock.advance("25h")
    stale = await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert (stale.status_code, _code(stale)) == (403, "FRESH_SESSION_REQUIRED")


async def test_impersonating_admins_banned_users_and_yourself() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.admin("cy")
    await w.user("bob")
    refused = await ada.post(f"/admin/users/{w.ids['cy']}/impersonate")
    assert (refused.status_code, _code(refused)) == (
        403,
        "ADMIN_CANNOT_IMPERSONATE_ADMIN",
    )
    own = await ada.post(f"/admin/users/{w.ids['ada']}/impersonate")
    assert _code(own) == "ADMIN_CANNOT_TARGET_SELF"
    await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={})
    banned = await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert _code(banned) == "ADMIN_USER_BANNED"

    allowed = world(admin={"allow_impersonating_admins": True})
    eve = await allowed.admin("eve")
    await allowed.admin("fay")
    ok = await eve.post(f"/admin/users/{allowed.ids['fay']}/impersonate")
    assert ok.status_code == 200
    # Still no admin rights while impersonating an admin.
    assert (await eve.get("/admin/users")).status_code == 403


async def test_an_impersonation_ends_when_its_admin_loses_the_role() -> None:
    w = world()
    ada = await w.admin("ada")
    cy = await w.admin("cy")
    await w.user("bob")
    await cy.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert (await cy.get("/whoami")).status_code == 200
    await ada.post(f"/admin/users/{w.ids['cy']}/role", json={"role": "user"})
    assert (await cy.get("/whoami")).status_code == 401


async def test_an_impersonation_ends_when_its_admin_is_removed() -> None:
    w = world()
    ada = await w.admin("ada")
    cy = await w.admin("cy")
    await w.user("bob")
    await cy.post(f"/admin/users/{w.ids['bob']}/impersonate")
    removed = await ada.delete(f"/admin/users/{w.ids['cy']}")
    assert removed.status_code == 200, removed.text
    assert await w.db.find_many("session", [Where("user_id", w.ids["bob"])]) != []
    assert (await cy.get("/whoami")).status_code == 401
    assert all(
        row.get("impersonated_by") is None
        for row in await w.db.find_many("session", [Where("user_id", w.ids["bob"])])
    )


async def test_a_bearer_admin_gets_the_impersonation_token() -> None:
    w = world(sessions={"expose_token": True})
    signed_in = await w.user("ada")
    await w.admin("ada")
    signed_in.cookies.clear()
    token = (await w.sign_in("ada")).json()["token"]
    bearer = make_client(w.auth)
    await w.user("bob")
    started = await bearer.post(
        f"/admin/users/{w.ids['bob']}/impersonate",
        headers={"authorization": f"Bearer {token}"},
    )
    assert started.status_code == 200, started.text
    as_bob = started.json()["token"]
    assert re.match(r"^gas_", as_bob)
    who = await make_client(w.auth).get(
        "/whoami", headers={"authorization": f"Bearer {as_bob}"}
    )
    assert who.json() == {"status": w.ids["bob"]}
    stopped = await make_client(w.auth).post(
        "/admin/stop-impersonating", headers={"authorization": f"Bearer {as_bob}"}
    )
    assert stopped.json() == {"restored": False}


async def test_a_stale_admin_cookie_is_not_restored() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    # The admin's own session is revoked meanwhile, e.g. from another device.
    await w.db.delete(
        "session",
        [Where("user_id", w.ids["ada"])],
    )
    stopped = await ada.post("/admin/stop-impersonating")
    assert stopped.json() == {"restored": False}
    assert (await ada.get("/whoami")).status_code == 401


# ---------------------------------------------------------------- databases


@pytest.mark.parametrize("database", ["memory", "sqlite", "postgres"])
async def test_admin_flows_on_every_database(database: str, tmp_path: Any) -> None:
    from sqlalchemy.ext.asyncio import create_async_engine

    from gotauth.storage.sqlalchemy import create_missing, sqlalchemy_adapter
    from gotauth.testing import fresh_database_url

    databases = None
    url = None
    if database == "sqlite":
        url = f"sqlite+aiosqlite:///{tmp_path / 'db.sqlite'}"
    elif database == "postgres":
        base = os.environ.get("GOTAUTH_TEST_POSTGRES_URL")
        if not base:
            pytest.skip("GOTAUTH_TEST_POSTGRES_URL is not set")
        databases = cast(
            "AsyncGenerator[str, None]",
            fresh_database_url(
                base.replace("postgresql://", "postgresql+asyncpg://", 1)
            ),
        )
        url = await anext(databases)
    engine = create_async_engine(url) if url else None
    try:
        w = world(database=sqlalchemy_adapter(engine)) if engine else world()
        if engine is not None:
            await create_missing(engine, w.auth.schema)
        ada = await w.admin("ada")
        for name in ("bob", "bea", "cy"):
            await w.user(name)
            w.clock.advance("1s")
        found = await ada.get("/admin/users", params={"search": "B"})
        assert {u["email"] for u in found.json()["users"]} >= {
            "bob@example.com",
            "bea@example.com",
        }
        for sort_by in ("created_at", "email"):
            seen: list[str] = []
            for offset in range(0, 4, 3):
                page = await ada.get(
                    "/admin/users",
                    params={"limit": 3, "offset": offset, "sort_by": sort_by},
                )
                assert page.json()["total"] == 4
                seen.extend(u["id"] for u in page.json()["users"])
            assert sorted(seen) == sorted(w.ids.values())
        await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={"expires_in": "1h"})
        assert _code(await w.sign_in("bob")) == "ADMIN_USER_BANNED"
        w.clock.advance("61m")
        assert (await w.sign_in("bob")).status_code == 200
        assert (await w.row("bob"))["banned"] is False
        await ada.post(f"/admin/users/{w.ids['cy']}/impersonate")
        assert (await ada.get("/whoami")).json() == {"status": w.ids["cy"]}
        stopped = await ada.post("/admin/stop-impersonating")
        assert stopped.json() == {"restored": True}
        removed = await ada.delete(f"/admin/users/{w.ids['bea']}")
        assert removed.status_code == 200, removed.text
    finally:
        if engine is not None:
            await engine.dispose()
        if databases is not None:
            await databases.aclose()


# ---------------------------------------------------------------- review fixes


async def test_an_impersonation_cannot_mint_credentials_or_change_security() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    key = await ada.post("/api-keys", json={"name": "backdoor"})
    assert (key.status_code, _code(key)) == (403, "ADMIN_IMPERSONATION_BLOCKED")
    password = await ada.post(
        "/change-password",
        json={"current_password": PASSWORD, "new_password": PASSWORD + "!"},
    )
    assert _code(password) == "ADMIN_IMPERSONATION_BLOCKED"
    # Reading is fine.
    assert (await ada.get("/api-keys")).status_code == 200


async def test_the_blocked_list_can_be_changed() -> None:
    w = world(admin={"impersonation_blocked": ()})
    ada = await w.admin("ada")
    await w.user("bob")
    await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert (await ada.post("/api-keys", json={"name": "ok"})).status_code == 200


async def test_signing_out_of_an_impersonation_ends_the_admin_session_too() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    out = await ada.post("/sign-out")
    assert out.status_code == 200, out.text
    assert "gotauth.admin_session" not in ada.cookies
    assert await w.db.find_many("session", [Where("user_id", w.ids["ada"])]) == []
    await w.auth.drain()
    assert "admin.impersonation_stopped" in w.types()


async def test_the_admin_cookie_lasts_no_longer_than_the_impersonation() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    started = await ada.post(f"/admin/users/{w.ids['bob']}/impersonate")
    header = next(
        value
        for value in started.headers.get_list("set-cookie")
        if value.startswith("gotauth.admin_session=")
    )
    assert "Max-Age=3600" in header
    assert "HttpOnly" in header


async def test_a_revoked_impersonation_stays_refused_with_the_cookie_cache() -> None:
    w = world(sessions={"cookie_cache": {"enabled": True}})
    ada = await w.admin("ada")
    cy = await w.admin("cy")
    await w.user("bob")
    await cy.post(f"/admin/users/{w.ids['bob']}/impersonate")
    assert (await cy.get("/whoami")).status_code == 200
    await ada.post(f"/admin/users/{w.ids['cy']}/role", json={"role": "user"})
    # The row is gone; the cache cookie still names the session.
    for _attempt in range(2):
        assert (await cy.get("/whoami")).status_code == 401


async def test_an_unknown_cached_session_cannot_call_admin_endpoints() -> None:
    w = world(sessions={"cookie_cache": {"enabled": True}})
    ada = await w.admin("ada")
    await w.db.delete("session", [Where("user_id", w.ids["ada"])])
    refused = await ada.get("/admin/users")
    assert (refused.status_code, _code(refused)) == (403, "FORBIDDEN")


async def test_an_expired_ban_is_not_written_on_requests() -> None:
    w = world()
    ada = await w.admin("ada")
    await w.user("bob")
    w.tokens.user_id = w.ids["bob"]
    await ada.post(f"/admin/users/{w.ids['bob']}/ban", json={"expires_in": "1h"})
    w.clock.advance("61m")
    client = make_client(w.auth)
    headers = {"authorization": "Bearer eyJ.token"}
    assert (await client.get("/whoami", headers=headers)).status_code == 200
    assert (await w.row("bob"))["banned"] is True
    assert (await w.sign_in("bob")).status_code == 200
    assert (await w.row("bob"))["banned"] is False
