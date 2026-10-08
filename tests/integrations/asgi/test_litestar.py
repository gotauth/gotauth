"""Litestar: the plugin mounts GotAuth, provides dependencies and guards routes.

No ``from __future__ import annotations``: Litestar reads annotations at runtime.
"""

from typing import Any

import httpx
from litestar import Litestar, get
from litestar.di import NamedDependency
from litestar.testing import AsyncTestClient

from gotauth.contracts import Endpoint, EndpointContext, Plugin, Principal, User
from gotauth.integrations.asgi.litestar import (
    GotAuthPlugin,
    requires_scopes,
    requires_session,
)
from gotauth.plugins.api_key import api_key
from gotauth.testing import make_auth

PASSWORD = "correct horse battery"
ORIGIN = {"origin": "http://localhost:8000"}


async def well_known_doc(ctx: EndpointContext, _: None) -> dict[str, str]:
    return {"issuer": ctx.auth.config.base_url}


@get("/me")
async def me(current_user: NamedDependency[User]) -> dict[str, str]:
    return {"id": current_user.id}


@get("/principal")
async def principal_view(
    principal: NamedDependency[Principal | None],
) -> dict[str, Any]:
    return {"via": principal.via if principal else None}


@get("/session-only", guards=[requires_session])
async def session_only() -> dict[str, bool]:
    return {"ok": True}


@get("/projects", guards=[requires_scopes("projects:read")])
async def projects() -> dict[str, bool]:
    return {"ok": True}


@get("/hello")
async def hello() -> dict[str, str]:
    return {"hello": "world"}


def build() -> Litestar:
    probe = Plugin(
        id="probe",
        well_known_endpoints=(
            Endpoint("probe_well_known", "GET", "/.well-known/probe", well_known_doc),
        ),
    )
    auth = make_auth(
        email_password={"require_email_verification": False},
        plugins=[api_key(allowed_scopes=["projects:read"]), probe],
    )
    return Litestar(
        route_handlers=[me, principal_view, session_only, projects, hello],
        plugins=[GotAuthPlugin(auth)],
    )


async def sign_up(http: AsyncTestClient[Litestar]) -> None:
    response = await http.post(
        "/api/auth/sign-up/email",
        json={"email": "ada@example.com", "password": PASSWORD},
        headers=ORIGIN,
    )
    assert response.status_code == 200, response.text


async def test_plugin_mounts_auth_and_provides_the_user() -> None:
    async with AsyncTestClient(
        app=build(), base_url="http://localhost.local:8000"
    ) as http:
        unauthenticated = await http.get("/me")
        assert unauthenticated.status_code == 401
        assert unauthenticated.json()["error"]["code"] == "UNAUTHENTICATED"
        assert (await http.get("/principal")).json() == {"via": None}
        await sign_up(http)
        assert (await http.get("/me")).json()["id"].startswith("usr_")
        assert (await http.get("/principal")).json() == {"via": "session"}


async def test_guards() -> None:
    async with AsyncTestClient(
        app=build(), base_url="http://localhost.local:8000"
    ) as http:
        assert (await http.get("/session-only")).status_code == 401
        assert (await http.get("/projects")).status_code == 401
        await sign_up(http)
        assert (await http.get("/session-only")).status_code == 200
        assert (await http.get("/projects")).status_code == 200
        reader = (
            await http.post(
                "/api/auth/api-keys",
                json={"name": "r", "scopes": ["projects:read"]},
                headers=ORIGIN,
            )
        ).json()["key"]
        none = (
            await http.post("/api/auth/api-keys", json={"name": "n"}, headers=ORIGIN)
        ).json()["key"]
        http.cookies = httpx.Cookies()
        assert (
            await http.get("/projects", headers={"x-api-key": reader})
        ).status_code == 200
        assert (
            await http.get("/session-only", headers={"x-api-key": reader})
        ).status_code == 401
        denied = await http.get("/projects", headers={"x-api-key": none})
        assert denied.status_code == 403
        assert denied.json()["error"]["details"] == {"required": ["projects:read"]}


async def test_well_known_mount_keeps_app_routes() -> None:
    async with AsyncTestClient(
        app=build(), base_url="http://localhost.local:8000"
    ) as http:
        assert (await http.get("/.well-known/probe")).json() == {
            "issuer": "http://localhost:8000"
        }
        assert (await http.get("/hello")).json() == {"hello": "world"}
