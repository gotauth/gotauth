"""An app for the OpenID Foundation conformance suite (used by work package Q1).

Run it with uvicorn behind https (the suite needs a public URL)::

    GOTAUTH_BASE_URL=https://op.example.test uvicorn \
        gotauth.plugins.oauth_provider.conformance:create_app --factory

``plan.json`` next to this file is the matching test plan configuration. No test
needs a PKCE bypass: the suite's clients send S256 challenges.

The app creates one test user at startup (``CONFORMANCE_EMAIL`` and
``CONFORMANCE_PASSWORD``, with test-only defaults) and serves a minimal ``/sign-in``
form for the suite's browser steps.
"""

from __future__ import annotations

import html
import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, urlsplit

__all__ = ["create_app"]

TEST_EMAIL = "conformance@example.com"
TEST_PASSWORD = "conformance-password"  # noqa: S105 - a test-only default

_FORM = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><title>Sign in</title></head>
<body><h1>Sign in</h1>{error}
<form method="post" action="/sign-in">
<input type="hidden" name="callback_url" value="{callback}">
<label>Email <input id="email" name="email" type="email"></label>
<label>Password <input id="password" name="password" type="password"></label>
<button id="sign-in" type="submit">Sign in</button>
</form></body></html>"""


def create_app() -> Any:  # Any: a FastAPI app; FastAPI is an optional extra
    """A FastAPI app with email sign-up, the OAuth server, two test clients, one
    test user and a sign-in page."""
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse, RedirectResponse, Response
    from starlette.routing import Route

    from gotauth import AuthError, GotAuth
    from gotauth.core._http import set_cookie_header
    from gotauth.plugins.oauth_provider import oauth_provider
    from gotauth.storage.memory import memory_adapter

    email = os.environ.get("CONFORMANCE_EMAIL", TEST_EMAIL)
    password = os.environ.get("CONFORMANCE_PASSWORD", TEST_PASSWORD)
    auth = GotAuth(
        database=memory_adapter(),
        secret=os.environ.get("GOTAUTH_SECRET", "conformance-" + "x" * 40),
        base_url=os.environ.get("GOTAUTH_BASE_URL", "http://localhost:8000"),
        email_password={"require_email_verification": False},
        plugins=[oauth_provider()],
    )
    authorize = urlsplit(auth.config.base_url + auth.config.base_path)
    authorize_path = authorize.path.rstrip("/") + "/oauth2/authorize"

    def back_to_authorize(callback: str) -> str | None:
        # Only this server's authorize endpoint: never an open redirect.
        target = urlsplit(callback)
        same_host = (target.scheme, target.netloc) == (
            authorize.scheme,
            authorize.netloc,
        )
        return callback if same_host and target.path == authorize_path else None

    @asynccontextmanager
    async def lifespan(_: Any) -> AsyncGenerator[None]:  # Any: the app
        redirect = os.environ.get(
            "CONFORMANCE_REDIRECT",
            "https://localhost.emobix.co.uk:8443/test/a/gotauth/callback",
        )
        await auth.api.call(
            "sign_up_email",
            body={"email": email, "password": password, "name": "Conformance"},
        )
        for name in ("client", "client2"):
            created = await auth.api.call(
                "create_oauth_client",
                body={
                    "name": name,
                    "type": "confidential",
                    "redirect_uris": [redirect],
                },
            )
            # Test-only credentials for the plan file; never do this in an app.
            print(  # noqa: T201 - shown to the person running the suite
                f"{name}: client_id={created.client.client_id} "
                f"client_secret={created.client_secret}"
            )
        yield
        await auth.drain()

    app = FastAPI(title="GotAuth OpenID conformance", lifespan=lifespan)

    def form(callback: str, error: str = "", status: int = 200) -> HTMLResponse:
        return HTMLResponse(
            _FORM.format(callback=html.escape(callback), error=error),
            status_code=status,
            headers={"cache-control": "no-store", "x-frame-options": "DENY"},
        )

    async def sign_in(request: Request) -> Response:
        # A plain Starlette route: it reads the form itself, so the app needs no
        # python-multipart and FastAPI never inspects these annotations.
        if request.method == "GET":
            return form(request.query_params.get("callback_url", ""))
        fields = parse_qs((await request.body()).decode("utf-8", "replace"))
        callback = fields.get("callback_url", [""])[0]
        try:
            result = await auth.api.call(
                "sign_in_email",
                body={
                    "email": fields.get("email", [""])[0],
                    "password": fields.get("password", [""])[0],
                },
                as_response=True,
            )
        except AuthError:
            return form(callback, "<p>Wrong email or password.</p>", status=401)
        response = RedirectResponse(back_to_authorize(callback) or "/", 303)
        for cookie in result.cookies:
            response.headers.append("set-cookie", set_cookie_header(cookie))
        return response

    app.router.routes.append(Route("/sign-in", sign_in, methods=["GET", "POST"]))
    app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
    auth.fastapi.add_exception_handlers(app)
    app.mount("/", auth.well_known())
    return app
