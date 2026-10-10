"""An app for the OpenID Foundation conformance suite (used by work package Q1).

Run it with uvicorn behind https (the suite needs a public URL)::

    GOTAUTH_BASE_URL=https://op.example.test uvicorn \
        gotauth.plugins.oauth_provider.conformance:create_app --factory

``plan.json`` next to this file is the matching test plan configuration. No test
needs a PKCE bypass: the suite's clients send S256 challenges.
"""

from __future__ import annotations

import os
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

__all__ = ["create_app"]


def create_app() -> Any:  # Any: a FastAPI app; FastAPI is an optional extra
    """A FastAPI app with email sign-up, the OAuth server and two test clients."""
    from fastapi import FastAPI

    from gotauth import GotAuth
    from gotauth.plugins.oauth_provider import oauth_provider
    from gotauth.storage.memory import memory_adapter

    auth = GotAuth(
        database=memory_adapter(),
        secret=os.environ.get("GOTAUTH_SECRET", "conformance-" + "x" * 40),
        base_url=os.environ.get("GOTAUTH_BASE_URL", "http://localhost:8000"),
        email_password={"require_email_verification": False},
        plugins=[oauth_provider()],
    )

    @asynccontextmanager
    async def lifespan(_: Any) -> AsyncGenerator[None]:  # Any: the app
        redirect = os.environ.get(
            "CONFORMANCE_REDIRECT",
            "https://localhost.emobix.co.uk:8443/test/a/gotauth/callback",
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
    app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
    auth.fastapi.add_exception_handlers(app)
    app.mount("/", auth.well_known())
    return app
