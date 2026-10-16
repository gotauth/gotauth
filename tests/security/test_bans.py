"""A banned user (P6) is refused on every sign-in method and every credential,
including where other code accepts a credential outside the pipeline (CCR 015)."""

from __future__ import annotations

from typing import Any

import httpx

from gotauth.contracts.adapter import Where
from gotauth.contracts.errors import AuthError
from gotauth.plugins.passkey.testing import SoftAuthenticator
from gotauth.testing import TEST_BASE_URL

from .conftest import (
    PASSWORD,
    RESOURCE,
    App,
    full_app,
    oauth_client,
    oauth_code,
    oauth_tokens,
)

EMAIL = "ada@example.com"
Client = tuple[str, str | None]


async def denied(app: App, headers: dict[str, str]) -> str | None:
    """The error code ``get_principal`` raises for these headers, if any."""
    try:
        await app.auth.get_principal(headers, {})
    except AuthError as error:
        return error.code
    return None


async def token(http: httpx.AsyncClient, client: Client, **form: str) -> httpx.Response:
    client_id, secret = client
    body = {"client_id": client_id, "client_secret": secret or "", **form}
    return await http.post("/oauth2/token", data=body)


async def introspect(http: httpx.AsyncClient, client: Client, value: str) -> Any:
    client_id, secret = client
    body = {"token": value, "client_id": client_id, "client_secret": secret or ""}
    return (await http.post("/oauth2/introspect", data=body)).json()


async def verify(app: App, access_token: str, resource: str | None = None) -> Any:
    body = {"token": access_token} | ({"resource": resource} if resource else {})
    return await app.auth.api.call("verify_access_token", body=body)


async def test_banned_users_are_rejected_on_every_credential() -> None:
    app = full_app()
    device = SoftAuthenticator(origin=TEST_BASE_URL)
    async with app.client() as boss, app.client() as http:
        await app.verified_user(boss, "boss@example.com")
        await app.auth.database.update(
            "user", [Where("email", "boss@example.com")], {"role": "admin"}
        )
        await app.verified_user(http)
        ada = await app.auth.database.find_one("user", [Where("email", EMAIL)])

        # Ada's credentials, made before the ban.
        options = (await http.post("/passkey/register/options")).json()
        added = await http.post(
            "/passkey/register/verify", json={"response": device.create(options)}
        )
        assert added.status_code == 200, added.text
        created = await http.post(
            "/api-keys", json={"name": "ci", "scopes": ["projects:read"]}
        )
        key = created.json()["key"]
        client = await oauth_client(app, "confidential")
        code, verifier = await oauth_code(
            http, client[0], resource=RESOURCE, scope="openid offline_access"
        )
        mcp = (
            await oauth_tokens(
                http, client[0], code, verifier, client_secret=client[1] or ""
            )
        ).json()
        code, verifier = await oauth_code(http, client[0])  # for GotAuth's own API
        local = (
            await oauth_tokens(
                http, client[0], code, verifier, client_secret=client[1] or ""
            )
        ).json()
        unused_code, unused_verifier = await oauth_code(  # a new scope: a new consent
            http, client[0], scope="openid profile"
        )
        owned = await app.auth.api.call(
            "create_oauth_client",
            body={
                "name": "Ada's service",
                "type": "confidential",
                "grant_types": ["client_credentials"],
                "redirect_uris": [],
                "scopes": ["profile"],
                "owner_user_id": ada["id"],
            },
        )
        service: Client = (owned.client.client_id, owned.client_secret)
        service_token = (
            await token(http, service, grant_type="client_credentials")
        ).json()["access_token"]
        assert (await verify(app, mcp["access_token"], RESOURCE)).valid  # the control
        assert (await verify(app, service_token)).valid

        banned = await boss.post(f"/admin/users/{ada['id']}/ban", json={})
        assert banned.status_code == 200, banned.text

        # Her browser session ended.
        assert (await http.get("/session")).json() is None
        # Every sign-in method: a right password says banned, a wrong one does not.
        right = await http.post(
            "/sign-in/email", json={"email": EMAIL, "password": PASSWORD}
        )
        assert right.json()["error"]["code"] == "ADMIN_USER_BANNED"
        wrong = await http.post(
            "/sign-in/email", json={"email": EMAIL, "password": "not her password"}
        )
        assert wrong.json()["error"]["code"] == "INVALID_CREDENTIALS"
        started = await http.post("/sign-in/social", json={"provider": "fake"})
        query = app.social.approve(started.json()["url"], "c1")
        social = await http.get("/callback/fake", params=query)
        assert social.json()["error"]["code"] == "ADMIN_USER_BANNED"
        options = (await http.post("/passkey/sign-in/options")).json()
        by_passkey = await http.post(
            "/passkey/sign-in/verify", json={"response": device.get(options)}
        )
        assert by_passkey.json()["error"]["code"] == "ADMIN_USER_BANNED"
        await http.post("/magic-link/send", json={"email": EMAIL})
        by_link = await http.get(await app.emailed("magic_link", r"https?://\S+"))
        assert by_link.json()["error"]["code"] == "ADMIN_USER_BANNED"
        await http.post("/email-otp/send", json={"email": EMAIL, "type": "sign_in"})
        by_code = await http.post(
            "/email-otp/verify",
            json={
                "email": EMAIL,
                "otp": await app.emailed("otp", r"\b\d{6}\b"),
                "type": "sign_in",
            },
        )
        assert by_code.json()["error"]["code"] == "ADMIN_USER_BANNED"
        assert (await http.get("/session")).json() is None

        # Her API key, in the pipeline and through the server call.
        bearer = {"authorization": f"Bearer {key}"}
        assert await denied(app, bearer) == "ADMIN_USER_BANNED"
        checked = await app.auth.api.call("verify_api_key", body={"key": key})
        assert (checked.valid, checked.code) == (False, "ADMIN_USER_BANNED")

        # Her OAuth tokens: GotAuth's own API and userinfo, an MCP server in the same
        # process (verify_access_token), one that introspects, and every grant.
        bearer = {"authorization": f"Bearer {local['access_token']}"}
        assert await denied(app, bearer) == "ADMIN_USER_BANNED"
        userinfo = await http.get("/oauth2/userinfo", headers=bearer)
        assert userinfo.status_code == 401
        verified = await verify(app, mcp["access_token"], RESOURCE)
        assert (verified.valid, verified.code) == (False, "ADMIN_USER_BANNED")
        assert (await introspect(http, client, mcp["access_token"])) == {
            "active": False
        }
        assert (await introspect(http, client, mcp["refresh_token"])) == {
            "active": False
        }
        refused = [
            await token(
                http,
                client,
                grant_type="refresh_token",
                refresh_token=mcp["refresh_token"],
            ),
            await oauth_tokens(
                http,
                client[0],
                unused_code,
                unused_verifier,
                client_secret=client[1] or "",
            ),
            # A client she owns acts for no user, but it is hers.
            await token(http, service, grant_type="client_credentials"),
        ]
        assert [r.json()["error"] for r in refused] == ["invalid_grant"] * 3
        assert not (await verify(app, service_token)).valid

        # Unbanned, the refresh token works again: the refused grant changed nothing.
        unbanned = await boss.post(f"/admin/users/{ada['id']}/unban")
        assert unbanned.status_code == 200, unbanned.text
        again = await token(
            http, client, grant_type="refresh_token", refresh_token=mcp["refresh_token"]
        )
        assert again.status_code == 200, again.text
