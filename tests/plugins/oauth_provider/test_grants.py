"""A signed-in user lists the apps they authorized and revokes one (issue #7)."""

from __future__ import annotations

from gotauth.testing import make_client

from .conftest import PASSWORD, RESOURCE, query_of, world


async def test_grants_need_a_session() -> None:
    w = await world(sign_in=False)
    assert (await w.http.get("/oauth2/grants")).status_code == 401
    revoke = await w.http.post("/oauth2/grants/revoke", json={"client_id": w.client_id})
    assert revoke.status_code == 401


async def test_list_shows_the_authorized_app() -> None:
    w = await world()
    assert (await w.http.get("/oauth2/grants")).json() == {"grants": []}
    code = await w.code(resource=RESOURCE, scope="openid profile offline_access")
    assert (await w.exchange(code)).status_code == 200
    w.clock.advance("1h")
    refreshed = await w.token(
        grant_type="refresh_token",
        refresh_token=(await w.exchange(await w.code(resource=RESOURCE))).json()[
            "refresh_token"
        ],
    )
    assert refreshed.status_code == 200, refreshed.text
    [grant] = (await w.http.get("/oauth2/grants")).json()["grants"]
    assert grant["client_id"] == w.client_id
    assert grant["client_name"] == "Example App"
    assert grant["scopes"] == ["email", "offline_access", "openid", "profile"]
    assert grant["resources"] == [RESOURCE]
    assert grant["created_at"] < grant["last_used_at"]


async def test_revoke_ends_tokens_codes_and_consent() -> None:
    w = await world()
    tokens = (
        await w.exchange(await w.code(resource=RESOURCE, scope="openid offline_access"))
    ).json()
    pending = await w.code(resource=RESOURCE, scope="openid")  # not yet exchanged
    revoked = await w.http.post(
        "/oauth2/grants/revoke", json={"client_id": w.client_id}
    )
    assert revoked.status_code == 200, revoked.text
    assert revoked.json()["revoked"] >= 1
    # The access token stops working at once; the refresh token and code too.
    check = await w.auth.api.call(
        "verify_access_token", body={"token": tokens["access_token"]}
    )
    assert not check.valid
    refresh = await w.token(
        grant_type="refresh_token", refresh_token=tokens["refresh_token"]
    )
    assert refresh.json()["error"] == "invalid_grant"
    assert (await w.exchange(pending)).json()["error"] == "invalid_grant"
    assert (await w.http.get("/oauth2/grants")).json() == {"grants": []}
    # The consent is gone: the next authorize asks again.
    again = await w.authorize(resource=RESOURCE, scope="openid")
    assert again.status_code == 200 and "consent_id" in again.json()


async def test_a_user_only_revokes_their_own_grant() -> None:
    w = await world()
    tokens = (await w.exchange(await w.code(resource=RESOURCE))).json()
    async with make_client(w.auth) as other:
        signed_up = await other.post(
            "/sign-up/email", json={"email": "bob@example.com", "password": PASSWORD}
        )
        assert signed_up.status_code == 200
        response = await other.post(
            "/oauth2/grants/revoke", json={"client_id": w.client_id}
        )
        assert response.json() == {"revoked": 0}
        assert (await other.get("/oauth2/grants")).json() == {"grants": []}
    check = await w.auth.api.call(
        "verify_access_token",
        body={"token": tokens["access_token"], "resource": RESOURCE},
    )
    assert check.valid
    assert len((await w.http.get("/oauth2/grants")).json()["grants"]) == 1
    # Consent stays too: a code comes straight from the GET.
    again = await w.authorize(resource=RESOURCE)
    assert again.status_code == 302 and "code" in query_of(again.headers["location"])
