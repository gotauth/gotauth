"""Starlette: mounts, the authentication backend, guards and WebSockets."""

from __future__ import annotations

import subprocess
import sys
from typing import Any

import httpx
from starlette.applications import Starlette
from starlette.authentication import requires
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocket

from gotauth.contracts import Endpoint, EndpointContext, Plugin, Principal
from gotauth.integrations.asgi.starlette import (
    GotAuthUser,
    gotauth_middleware,
    requires_scopes,
)
from gotauth.plugins.api_key import api_key
from gotauth.testing import make_auth, stub_resolver

PASSWORD = "correct horse battery"
ORIGIN = {"origin": "http://localhost:8000"}


async def well_known_doc(ctx: EndpointContext, _: None) -> dict[str, str]:
    return {"issuer": ctx.auth.config.base_url}


def build(*extra: Plugin, **overrides: Any) -> tuple[Any, Starlette]:
    probe = Plugin(
        id="probe",
        well_known_endpoints=(
            Endpoint("probe_well_known", "GET", "/.well-known/probe", well_known_doc),
        ),
    )
    options: dict[str, Any] = {
        "email_password": {"require_email_verification": False},
        "sessions": {"expose_token": True},
        "plugins": [api_key(allowed_scopes=["projects:read"]), probe, *extra],
    }
    options.update(overrides)
    auth = make_auth(**options)

    async def whoami(request: Request) -> JSONResponse:
        user = request.user
        return JSONResponse(
            {
                "authenticated": user.is_authenticated,
                "identity": user.identity if isinstance(user, GotAuthUser) else None,
                "scopes": sorted(request.auth.scopes) if request.auth else [],
            }
        )

    @requires("authenticated")
    async def private(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    @requires_scopes("projects:read")
    async def projects(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True})

    async def socket(websocket: WebSocket) -> None:
        await websocket.accept()
        user = websocket.user
        await websocket.send_json(
            {"identity": user.identity if isinstance(user, GotAuthUser) else None}
        )
        await websocket.close()

    async def hello(request: Request) -> JSONResponse:
        return JSONResponse({"hello": "world"})

    app = Starlette(
        routes=[
            Route("/whoami", whoami),
            Route("/private", private),
            Route("/projects", projects),
            Route("/hello", hello),
            WebSocketRoute("/ws", socket),
            Mount(auth.config.base_path, app=auth.asgi()),
            Mount("/", app=auth.well_known()),
        ],
        middleware=[gotauth_middleware(auth)],
    )
    return auth, app


def client(app: Starlette) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://localhost:8000",
        headers=ORIGIN,
    )


async def sign_up(http: httpx.AsyncClient) -> str:
    response = await http.post(
        "/api/auth/sign-up/email",
        json={"email": "ada@example.com", "password": PASSWORD},
    )
    assert response.status_code == 200, response.text
    return str(response.json()["token"])


async def test_user_for_every_credential() -> None:
    jwt = Principal(
        via="oauth_token",
        credential_id="tok_1",
        user_id="usr_j",
        scopes=frozenset({"x"}),
    )
    _, app = build(Plugin(id="jwt", principal_resolvers=(stub_resolver("eyJ", jwt),)))
    async with client(app) as http:
        assert (await http.get("/whoami")).json()["authenticated"] is False
        token = await sign_up(http)
        by_cookie = (await http.get("/whoami")).json()
        assert by_cookie["authenticated"] is True
        assert by_cookie["scopes"] == ["authenticated", "session"]
        key = (
            await http.post(
                "/api/auth/api-keys", json={"name": "k", "scopes": ["projects:read"]}
            )
        ).json()["key"]
        http.cookies = httpx.Cookies()
        by_bearer = (
            await http.get("/whoami", headers={"authorization": f"Bearer {token}"})
        ).json()
        assert by_bearer["identity"] == by_cookie["identity"]
        by_key = (await http.get("/whoami", headers={"x-api-key": key})).json()
        assert by_key["scopes"] == ["authenticated", "projects:read"]
        by_jwt = (
            await http.get("/whoami", headers={"authorization": "Bearer eyJx"})
        ).json()
        assert by_jwt["identity"] == "usr_j"


async def test_requires_and_requires_scopes() -> None:
    _, app = build()
    async with client(app) as http:
        assert (
            await http.get("/private")
        ).status_code == 403  # Starlette's own decorator
        anonymous = await http.get("/projects")
        assert anonymous.status_code == 401
        assert anonymous.json()["error"]["code"] == "UNAUTHENTICATED"
        await sign_up(http)
        assert (await http.get("/private")).status_code == 200
        assert (
            await http.get("/projects")
        ).status_code == 200  # sessions have full rights
        reader = (
            await http.post(
                "/api/auth/api-keys", json={"name": "r", "scopes": ["projects:read"]}
            )
        ).json()["key"]
        none = (
            await http.post("/api/auth/api-keys", json={"name": "n", "scopes": []})
        ).json()["key"]
        http.cookies = httpx.Cookies()
        assert (
            await http.get("/projects", headers={"x-api-key": reader})
        ).status_code == 200
        denied = await http.get("/projects", headers={"x-api-key": none})
        assert denied.status_code == 403
        assert denied.json()["error"]["details"] == {"required": ["projects:read"]}


async def test_bad_credentials_mean_anonymous_with_the_error_kept() -> None:
    _, app = build()
    bad = {"x-api-key": "gak_" + "A" * 43}
    async with client(app) as http:
        assert (await http.get("/whoami", headers=bad)).json()["authenticated"] is False
        guarded = await http.get("/projects", headers=bad)
    assert guarded.status_code == 401
    assert guarded.json()["error"]["code"] == "API_KEY_INVALID"


async def test_backend_failure_is_a_500_and_no_user() -> None:
    async def explode(ctx: EndpointContext, principal: Principal) -> None:
        raise RuntimeError("secret detail")

    _, app = build(Plugin(id="boom", principal_checks=(explode,)))
    async with client(app) as http:
        await sign_up(http)
        response = await http.get("/whoami")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "secret detail" not in response.text


def test_websocket_uses_the_session_cookie() -> None:
    _, app = build()
    with TestClient(app, base_url="http://localhost:8000") as sync:
        sync.post(
            "/api/auth/sign-up/email",
            json={"email": "ada@example.com", "password": PASSWORD},
            headers=ORIGIN,
        )
        identity = sync.get("/whoami").json()["identity"]
        # The test client does not match response-set cookies against ws:// URLs, so
        # send the session cookie header the browser would send.
        session = sync.cookies["gotauth.session_token"]
        cookie = {"cookie": f"gotauth.session_token={session}"}
        with sync.websocket_connect("/ws", headers=cookie) as ws:
            assert ws.receive_json() == {"identity": identity}


async def test_well_known_mount_keeps_app_routes() -> None:
    _, app = build()
    async with client(app) as http:
        assert (await http.get("/.well-known/probe")).json() == {
            "issuer": "http://localhost:8000"
        }
        assert (await http.get("/hello")).json() == {"hello": "world"}


def test_import_gotauth_imports_no_framework() -> None:
    code = (
        "import sys, gotauth, gotauth.integrations.asgi; "
        "print(any(m in sys.modules for m in ('starlette', 'litestar')))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False"


# ---------------------------------------------------------------- review fixes


async def test_sliding_refresh_cookie_reaches_app_responses() -> None:
    from gotauth.testing import fake_clock

    clock = fake_clock()
    _, app = build(clock=clock)
    async with client(app) as http:
        await sign_up(http)
        clock.advance("2d")  # past update_age: the next read slides the session
        response = await http.get("/whoami")
    assert response.json()["authenticated"] is True
    assert "gotauth.session_token=gas_" in response.headers.get("set-cookie", "")


async def test_bad_credentials_do_not_block_auth_or_public_routes() -> None:
    _, app = build()
    revoked = {"x-api-key": "gak_" + "A" * 43}
    async with client(app) as http:
        signed_up = await http.post(
            "/api/auth/sign-up/email",
            json={"email": "ada@example.com", "password": PASSWORD},
            headers=revoked,
        )
        assert signed_up.status_code == 200
        assert (await http.get("/hello", headers=revoked)).status_code == 200
        http.cookies = httpx.Cookies()
        guarded = await http.get("/projects", headers=revoked)
        assert guarded.status_code == 401
        assert guarded.json()["error"]["code"] == "API_KEY_INVALID"


def test_lifespan_drains_on_shutdown() -> None:
    from gotauth.integrations.asgi.starlette import gotauth_lifespan

    auth, _ = build()
    drained: list[bool] = []

    async def drain() -> None:
        drained.append(True)

    auth.drain = drain
    app = Starlette(routes=[], lifespan=gotauth_lifespan(auth))
    with TestClient(app):
        assert drained == []
    assert drained == [True]
