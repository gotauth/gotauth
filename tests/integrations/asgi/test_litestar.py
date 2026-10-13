"""Litestar: the plugin mounts GotAuth, provides dependencies and guards routes.

No ``from __future__ import annotations``: Litestar reads annotations at runtime.
"""

from typing import Any, cast

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


# ---------------------------------------------------------------- review fixes


def build_with(**overrides: Any) -> tuple[Any, Litestar]:
    auth = make_auth(
        email_password={"require_email_verification": False},
        plugins=[api_key(allowed_scopes=["projects:read"])],
        **overrides,
    )
    app = Litestar(
        route_handlers=[me, principal_view, session_only, hello],
        plugins=[GotAuthPlugin(auth)],
    )
    return auth, app


async def test_sliding_refresh_cookie_is_sent() -> None:
    from gotauth.testing import fake_clock

    clock = fake_clock()
    _, app = build_with(clock=clock)
    async with AsyncTestClient(app=app, base_url="http://localhost.local:8000") as http:
        await sign_up(http)
        clock.advance("2d")
        response = await http.get("/me")
        assert response.status_code == 200
        assert "gotauth.session_token=gas_" in response.headers.get("set-cookie", "")
        clock.advance("2d")
        guarded = await http.get("/session-only")
        assert guarded.status_code == 200
        assert "gotauth.session_token=gas_" in guarded.headers.get("set-cookie", "")


async def test_works_under_an_outer_mount_and_drains_on_shutdown() -> None:
    from starlette.applications import Starlette
    from starlette.routing import Mount

    drained: list[bool] = []

    async def drain() -> None:
        drained.append(True)

    auth = make_auth(email_password={"require_email_verification": False})
    auth.drain = drain  # before the plugin registers its shutdown hook
    inner = Litestar(route_handlers=[hello], plugins=[GotAuthPlugin(auth)])
    # Litestar's own ASGI type differs from Starlette's; both are plain ASGI apps.
    outer = Starlette(routes=[Mount("/v1", app=cast(Any, inner))])
    async with AsyncTestClient(app=inner):  # runs the inner app's lifespan
        pass
    assert drained == [True]
    transport = httpx.ASGITransport(app=outer)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:8000"
    ) as http:
        response = await http.post(
            "/v1/api/auth/sign-up/email",
            json={"email": "ada@example.com", "password": PASSWORD},
            headers=ORIGIN,
        )
        assert response.status_code == 200, response.text
        encoded = await http.get("/v1/api/auth/sess%69on")  # percent-encoded path
        assert encoded.status_code == 200


# ------------------------------------------------------------ optional_user (#9)


@get("/greeting")
async def greeting(
    optional_user: NamedDependency[User | None],
) -> dict[str, str | None]:
    return {"email": optional_user.email if optional_user else None}


@get("/both")
async def both(
    current_user: NamedDependency[User],
    optional_user: NamedDependency[User | None],
) -> dict[str, bool]:
    return {"same": optional_user is not None and optional_user.id == current_user.id}


def build_optional() -> tuple[Any, Litestar, list[str]]:
    auth = make_auth(email_password={"require_email_verification": False})
    calls: list[str] = []
    real_call = auth.api.call

    async def counting_call(name: str, **kwargs: Any) -> Any:
        calls.append(name)
        return await real_call(name, **kwargs)

    cast(Any, auth.api).call = counting_call
    app = Litestar(route_handlers=[greeting, both], plugins=[GotAuthPlugin(auth)])
    return auth, app, calls


async def test_optional_user_is_none_when_signed_out() -> None:
    _, app, _ = build_optional()
    async with AsyncTestClient(app=app, base_url="http://localhost.local:8000") as http:
        assert (await http.get("/greeting")).json() == {"email": None}
        http.cookies.set("gotauth.session_token", "gas_not-a-real-token")
        response = await http.get("/greeting")
        assert response.status_code == 200
        assert response.json() == {"email": None}


async def test_optional_user_is_the_user_when_signed_in() -> None:
    _, app, calls = build_optional()
    async with AsyncTestClient(app=app, base_url="http://localhost.local:8000") as http:
        await sign_up(http)
        assert (await http.get("/greeting")).json() == {"email": "ada@example.com"}
        calls.clear()
        assert (await http.get("/both")).json() == {"same": True}
        # One session read per request, however many dependencies ask.
        assert calls == ["get_session"]


async def test_optional_user_keeps_the_sliding_refresh() -> None:
    from gotauth.testing import fake_clock

    clock = fake_clock()
    auth = make_auth(email_password={"require_email_verification": False}, clock=clock)
    app = Litestar(route_handlers=[greeting], plugins=[GotAuthPlugin(auth)])
    async with AsyncTestClient(app=app, base_url="http://localhost.local:8000") as http:
        await sign_up(http)
        clock.advance("2d")
        response = await http.get("/greeting")
        assert response.json() == {"email": "ada@example.com"}
        assert "gotauth.session_token=gas_" in response.headers.get("set-cookie", "")
