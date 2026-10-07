"""The FastAPI integration on a real GotAuth.

No ``from __future__ import annotations``: FastAPI resolves the route annotations,
including aliases defined inside functions, at runtime.
"""

import json
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Annotated, Any

import httpx
import pytest
from fastapi import Depends, FastAPI
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import (
    CORE_ENDPOINTS,
    AuthError,
    ConfigError,
    Endpoint,
    EndpointContext,
    Plugin,
    Principal,
    User,
)
from gotauth.contracts.protection import resolve_client_ip
from gotauth.plugins.api_key import api_key
from gotauth.testing import make_auth, stub_plugin, stub_resolver

PASSWORD = "correct horse battery"
ORIGIN = {"origin": "http://localhost:8000"}
JWT_PRINCIPAL = Principal(
    via="oauth_token",
    credential_id="tok_1",
    user_id="usr_jwt",
    client_id="cli_1",
    scopes=frozenset({"projects:read"}),
)


async def client_ip(ctx: EndpointContext, _: None) -> dict[str, str | None]:
    return {"ip": ctx.request.client_ip}


async def well_known_doc(ctx: EndpointContext, _: None) -> dict[str, str]:
    return {"issuer": ctx.auth.config.base_url}


PROBE = Plugin(
    id="probe",
    endpoints=(Endpoint("client_ip", "GET", "/client-ip", client_ip),),
    well_known_endpoints=(
        Endpoint("probe_well_known", "GET", "/.well-known/probe", well_known_doc),
    ),
    principal_resolvers=(stub_resolver("eyJ", JWT_PRINCIPAL),),
)


def build(
    *extra: Plugin, prefix: str = "/api/auth", mount: bool = True, **overrides: Any
) -> tuple[Any, FastAPI]:
    options: dict[str, Any] = {
        "email_password": {"require_email_verification": False},
        "plugins": [
            api_key(allowed_scopes=["projects:read", "projects:write"]),
            PROBE,
            *extra,
        ],
    }
    options.update(overrides)
    auth = make_auth(**options)
    app = FastAPI()
    app.include_router(auth.fastapi.router(), prefix=prefix)
    auth.fastapi.add_exception_handlers(app)

    # Inline Annotated[...]: aliases must live at module level for type checkers, and
    # this app is built per test. The module-level alias form is checked by
    # test_alias_form_passes_pyright_strict.
    fa = auth.fastapi

    @app.get("/me")
    async def me(user: Annotated[User, Depends(fa.current_user)]) -> dict[str, str]:
        return {"id": user.id}

    @app.get("/maybe")
    async def maybe(
        user: Annotated[User | None, Depends(fa.optional_user)],
    ) -> dict[str, str | None]:
        return {"id": user.id if user else None}

    @app.get("/principal")
    async def principal(
        p: Annotated[Principal, Depends(fa.current_principal)],
    ) -> dict[str, str | None]:
        return {"via": p.via, "user_id": p.user_id}

    @app.get("/key-only")
    async def key_only(
        p: Annotated[Principal, Depends(fa.api_key_principal)],
    ) -> dict[str, str]:
        return {"id": p.credential_id}

    @app.get("/projects")
    async def projects(
        p: Annotated[Principal, Depends(fa.require("projects:read"))],
    ) -> dict[str, str]:
        return {"via": p.via}

    @app.get("/hello")
    async def hello() -> dict[str, str]:
        return {"hello": "world"}

    if mount:
        app.mount("/", auth.well_known())
    return auth, app


def client(app: FastAPI, *, origin: bool = True) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        base_url="http://localhost:8000",
        headers=ORIGIN if origin else {},
    )


async def sign_up(
    http: httpx.AsyncClient, email: str = "ada@example.com"
) -> dict[str, Any]:
    response = await http.post(
        "/api/auth/sign-up/email", json={"email": email, "password": PASSWORD}
    )
    assert response.status_code == 200, response.text
    data: dict[str, Any] = response.json()
    return data


# ---------------------------------------------------------------- OpenAPI


def test_openapi_documents_every_core_endpoint_without_422() -> None:
    auth, app = build()
    installed = {e.id for plugin in auth.plugins for e in plugin.endpoints}
    spec = app.openapi()
    assert "422" not in json.dumps(spec["paths"])
    for row in CORE_ENDPOINTS:
        if row.server_only or row.method is None or row.path is None:
            continue
        if row.id not in installed:  # social endpoints need configured providers
            continue
        operation = spec["paths"][f"/api/auth{row.path}"][row.method.lower()]
        assert operation["operationId"] == row.id
        assert "4XX" in operation["responses"]
        params = {p["name"]: p["in"] for p in operation.get("parameters", [])}
        for name in __import__("re").findall(r"\{(\w+)\}", row.path):
            assert params[name] == "path"
        content = operation.get("requestBody", {}).get("content", {})
        if row.input_format == "form":
            assert "application/x-www-form-urlencoded" in content
        elif row.method == "GET":
            assert "requestBody" not in operation
    session = spec["paths"]["/api/auth/session"]["get"]["responses"]["200"]
    schema = json.dumps(session["content"]["application/json"]["schema"])
    assert "SessionWithUserOut" in schema and "null" in schema
    sign_in = spec["paths"]["/api/auth/sign-in/email"]["post"]
    assert "application/json" in sign_in["requestBody"]["content"]
    verify = spec["paths"]["/api/auth/verify-email"]["get"]
    assert {p["name"] for p in verify["parameters"]} >= {"token"}
    assert "/api/auth/api-keys/{id}" in spec["paths"]
    assert sign_in["tags"] == ["email_password"]


# ---------------------------------------------------------------- pipeline


async def test_validation_and_content_type_stay_in_the_core() -> None:
    _, app = build()
    async with client(app) as http:
        bad = await http.post(
            "/api/auth/sign-in/email", json={"email": "not-an-email", "password": 7}
        )
        assert bad.status_code == 400
        assert bad.json()["error"]["code"] == "INVALID_REQUEST"
        assert "not-an-email" not in bad.text
        plain = await http.post(
            "/api/auth/sign-in/email",
            content=b"x",
            headers={"content-type": "text/plain"},
        )
        assert plain.status_code == 415


async def test_round_trip_cookies_and_sign_out() -> None:
    _, app = build()
    async with client(app) as http:
        await sign_up(http)
        signed_in = await http.post(
            "/api/auth/sign-in/email",
            json={"email": "ada@example.com", "password": PASSWORD},
        )
        cookie = signed_in.headers["set-cookie"]
        assert "gotauth.session_token=gas_" in cookie
        assert "HttpOnly" in cookie and "SameSite=Lax" in cookie and "Path=/" in cookie
        assert signed_in.headers["cache-control"] == "no-store"
        assert (await http.get("/me")).json()["id"].startswith("usr_")
        assert (await http.post("/api/auth/sign-out")).json() == {"status": "ok"}
        assert (await http.get("/me")).status_code == 401


async def test_redirects_pass_through() -> None:
    _, app = build()
    async with client(app) as http:
        response = await http.get(
            "/api/auth/verify-email",
            params={"token": "gav_bad", "callback_url": "/done"},
        )
    assert response.status_code == 302
    assert response.headers["location"] == "/done?error=TOKEN_INVALID"


async def test_wrong_prefix_is_a_config_error() -> None:
    auth, app = build(prefix="/auth")
    with pytest.raises(ConfigError, match="prefix"):
        auth.fastapi.check_app(app)
    async with client(app) as http:
        with pytest.raises(ConfigError, match="prefix"):
            await http.get("/auth/session")
    good_auth, good_app = build()
    good_auth.fastapi.check_app(good_app)


async def test_cookie_post_without_origin_is_refused() -> None:
    _, app = build()
    async with client(app) as http:
        await sign_up(http)
        cookies = http.cookies
    async with client(app, origin=False) as bare:
        bare.cookies = cookies
        response = await bare.post("/api/auth/sign-out")
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "ORIGIN_NOT_ALLOWED"


# ---------------------------------------------------------------- dependencies


async def test_dependencies_with_every_credential() -> None:
    _, app = build()
    async with client(app) as http:
        created = await sign_up(http)
        token = created.get("token")
        assert (await http.get("/maybe")).json()["id"] is not None
        key = (
            await http.post(
                "/api/auth/api-keys", json={"name": "k", "scopes": ["projects:read"]}
            )
        ).json()["key"]
        weak = (
            await http.post("/api/auth/api-keys", json={"name": "w", "scopes": []})
        ).json()["key"]
        session_principal = (await http.get("/principal")).json()
        assert session_principal["via"] == "session"
        assert (
            await http.get("/projects")
        ).status_code == 200  # sessions have every scope
        assert (await http.get("/key-only")).status_code == 401
        session_cookies = http.cookies
        http.cookies = httpx.Cookies()
        assert (await http.get("/me")).status_code == 401
        assert (await http.get("/maybe")).json() == {"id": None}
        unauthenticated = await http.get("/principal")
        assert unauthenticated.status_code == 401
        assert unauthenticated.headers["www-authenticate"] == "Bearer"
        by_key = await http.get(
            "/principal", headers={"authorization": f"Bearer {key}"}
        )
        assert by_key.json()["via"] == "api_key"
        assert (
            await http.get("/key-only", headers={"x-api-key": key})
        ).status_code == 200
        assert (await http.get("/me", headers={"x-api-key": key})).status_code == 401
        denied = await http.get("/projects", headers={"x-api-key": weak})
        assert denied.status_code == 403
        assert denied.json()["error"]["details"] == {"required": ["projects:read"]}
        jwt = await http.get("/principal", headers={"authorization": "Bearer eyJstub"})
        assert jwt.json() == {"via": "oauth_token", "user_id": "usr_jwt"}
        del session_cookies, token


async def test_bearer_session_token() -> None:
    _, app = build(sessions={"expose_token": True})
    async with client(app) as http:
        token = (await sign_up(http))["token"]
        http.cookies = httpx.Cookies()
        response = await http.get("/me", headers={"authorization": f"Bearer {token}"})
        assert response.status_code == 200
        await http.post(
            "/api/auth/sign-out", headers={"authorization": f"Bearer {token}"}
        )
        assert (
            await http.get("/me", headers={"authorization": f"Bearer {token}"})
        ).status_code == 401


async def test_principal_checks_and_dependency_errors() -> None:
    async def reject(ctx: EndpointContext, principal: Principal) -> None:
        if principal.via == "api_key":
            raise AuthError("FORBIDDEN", 403, "Banned")

    async def explode(ctx: EndpointContext, principal: Principal) -> None:
        if principal.via == "oauth_token":
            raise RuntimeError("secret detail")

    checks = Plugin(id="checks", principal_checks=(reject, explode))
    _, app = build(checks)
    async with client(app) as http:
        await sign_up(http)
        key = (await http.post("/api/auth/api-keys", json={"name": "k"})).json()["key"]
        http.cookies = httpx.Cookies()
        banned = await http.get("/principal", headers={"x-api-key": key})
        assert banned.status_code == 403
        broken = await http.get("/principal", headers={"authorization": "Bearer eyJx"})
        assert broken.status_code == 500
        assert broken.json()["error"]["code"] == "INTERNAL_ERROR"
        assert "secret detail" not in broken.text


def test_require_permission_needs_the_organization_plugin() -> None:
    auth, _ = build()
    with pytest.raises(ConfigError, match="organization"):
        auth.fastapi.require(permission={"project": ["delete"]})


async def test_require_permission_asks_has_permission() -> None:
    async def has_permission(**body: Any) -> dict[str, bool]:
        return {"success": body["permissions"] == {"project": ["read"]}}

    orgs = stub_plugin("organization", {"has_permission": has_permission})
    auth, app = build(orgs, mount=False)
    can_read = auth.fastapi.require(permission={"project": ["read"]})
    can_delete = auth.fastapi.require(permission={"project": ["delete"]})

    @app.get("/allowed")
    async def allowed(p: Annotated[Principal, Depends(can_read)]) -> dict[str, str]:
        return {"via": p.via}

    @app.get("/denied")
    async def denied(p: Annotated[Principal, Depends(can_delete)]) -> dict[str, str]:
        return {"via": p.via}

    async with client(app) as http:
        await sign_up(http)
        assert (await http.get("/allowed")).status_code == 200
        response = await http.get("/denied")
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "FORBIDDEN"


# ---------------------------------------------------------------- client IP


@settings(
    max_examples=40,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    forwarded=st.lists(st.ip_addresses().map(str), min_size=1, max_size=4).map(
        ", ".join
    ),
    trust_peer=st.booleans(),
)
async def test_client_ip_comes_from_resolve_client_ip(
    forwarded: str, trust_peer: bool
) -> None:
    proxies = ("127.0.0.1",) if trust_peer else ("10.9.9.9",)
    auth, app = build(
        advanced={"ip_headers": ("x-forwarded-for",), "trusted_proxies": proxies}
    )
    async with client(app) as http:
        response = await http.get(
            "/api/auth/client-ip", headers={"x-forwarded-for": forwarded}
        )
    expected = resolve_client_ip(
        "127.0.0.1", {"x-forwarded-for": forwarded}, auth.config
    )
    assert response.json() == {"ip": expected}
    if not trust_peer:
        assert response.json() == {"ip": "127.0.0.1"}  # a spoofed header is ignored


# ---------------------------------------------------------------- mounts and imports


async def test_well_known_mount_keeps_app_routes() -> None:
    _, app = build()
    async with client(app) as http:
        assert (await http.get("/.well-known/probe")).json() == {
            "issuer": "http://localhost:8000"
        }
        assert (await http.get("/hello")).json() == {"hello": "world"}


def test_import_gotauth_does_not_import_fastapi() -> None:
    code = (
        "import sys, gotauth, gotauth.integrations.fastapi; "
        "print('fastapi' in sys.modules)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "False"


def test_alias_form_passes_pyright_strict(tmp_path: Path) -> None:
    app_file = tmp_path / "app.py"
    app_file.write_text(
        textwrap.dedent(
            """
            # pyright: strict
            from typing import Annotated

            from fastapi import Depends, FastAPI

            from gotauth import GotAuth, User
            from gotauth.storage.memory import memory_adapter

            auth = GotAuth(database=memory_adapter(), secret="s" * 64, base_url="http://localhost:8000")
            CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]

            app = FastAPI()
            app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)


            @app.get("/projects")
            async def projects(user: CurrentUser) -> dict[str, str]:
                return {"user": user.id}
            """
        ),
        encoding="utf-8",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pyright", str(app_file)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout


# ---------------------------------------------------------------- review fixes


async def test_optional_user_treats_bad_credentials_as_signed_out() -> None:
    _, app = build()
    async with client(app) as http:
        bad = await http.get(
            "/maybe", headers={"authorization": "Bearer gas_" + "x" * 43}
        )
        assert bad.status_code == 200
        assert bad.json() == {"id": None}


async def test_check_app_does_not_freeze_the_docs() -> None:
    auth, app = build(mount=False)
    auth.fastapi.check_app(app)

    @app.get("/added-later")
    async def added_later() -> dict[str, str]:
        return {}

    assert "/added-later" in app.openapi()["paths"]


async def test_split_cookie_headers_are_joined() -> None:
    _, app = build()
    async with client(app) as http:
        await sign_up(http)
        session = http.cookies["gotauth.session_token"]
        http.cookies = httpx.Cookies()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url="http://localhost:8000"
    ) as raw:
        request = raw.build_request("GET", "/me")
        request.headers = httpx.Headers(
            [("cookie", f"gotauth.session_token={session}"), ("cookie", "theme=dark")]
        )
        assert (await raw.send(request)).status_code == 200
        request = raw.build_request("GET", "/api/auth/session")
        request.headers = httpx.Headers(
            [("cookie", "theme=dark"), ("cookie", f"gotauth.session_token={session}")]
        )
        assert (await raw.send(request)).json()["user"]["email"] == "ada@example.com"


async def test_permission_lookup_failures_are_json_500s() -> None:
    async def has_permission(**body: Any) -> dict[str, bool]:
        raise RuntimeError("database down")

    orgs = stub_plugin("organization", {"has_permission": has_permission})
    auth, app = build(orgs, mount=False)
    guard = auth.fastapi.require(permission={"project": ["read"]})

    @app.get("/guarded")
    async def guarded(p: Annotated[Principal, Depends(guard)]) -> dict[str, str]:
        return {"via": p.via}

    async with client(app) as http:
        await sign_up(http)
        response = await http.get("/guarded")
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "database down" not in response.text
