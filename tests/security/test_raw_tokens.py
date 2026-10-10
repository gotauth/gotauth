"""No raw secret is ever stored or logged: a full scenario on SQLite, then a scan of
every table and every captured log line."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterable, Mapping
from typing import Any

import pytest
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import StaticPool

from gotauth.storage.sqlalchemy import create_missing, sqlalchemy_adapter

from .conftest import PASSWORD, REDIRECT, RESOURCE, full_app, oauth_client, oauth_code

PREFIXED = re.compile(r"\b(gas|gak|gar|gac|gav|gcs)_[A-Za-z0-9_-]{20,}")


def scan(
    tables: Mapping[str, Iterable[Mapping[str, Any]]],  # Any: row values
    logs: str,
    seen: Iterable[str],
) -> list[str]:
    """Findings: any prefixed token in the data or logs, and any secret seen during
    the run that shows up verbatim."""
    dump = json.dumps({name: list(rows) for name, rows in tables.items()}, default=str)
    findings = [
        f"prefixed token in {where}"
        for where, text in (("tables", dump), ("logs", logs))
        if PREFIXED.search(text)
    ]
    findings += [
        f"seen secret stored: {secret[:6]}..."
        for secret in seen
        if secret and (secret in dump or secret in logs)
    ]
    return findings


def test_scan_catches_a_raw_token_stored_on_purpose() -> None:
    token = "gas_" + "B" * 43
    assert scan({"session": [{"token_hash": token}]}, "", [token])
    assert scan({}, f"user signed in with {token}", [])
    assert scan({"x": [{"code": "482913"}]}, "", ["482913"])
    assert scan({"session": [{"token_hash": "f" * 64}]}, "", [token]) == []


async def test_full_scenario_leaves_no_secret_behind(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level(logging.DEBUG)
    engine = create_async_engine("sqlite+aiosqlite://", poolclass=StaticPool)
    app = full_app(database=sqlalchemy_adapter(engine), sessions={"expose_token": True})
    await create_missing(
        engine, app.auth.schema, table_prefix=app.auth.config.advanced.table_prefix
    )
    seen: list[str] = [PASSWORD]
    async with app.client() as http:
        signed_up = await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        assert signed_up.status_code == 200
        verify = app.last_token("verify_email")
        await http.get("/verify-email", params={"token": verify})
        signed_in = await http.post(
            "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        key = await http.post(
            "/api-keys", json={"name": "ci", "scopes": ["projects:read"]}
        )
        client_id, client_secret = await oauth_client(app, "confidential")
        assert client_secret is not None
        code, verifier = await oauth_code(http, client_id, resource=RESOURCE)
        tokens = await http.post(
            "/oauth2/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "code_verifier": verifier,
                "redirect_uri": REDIRECT,
                "client_id": client_id,
                "client_secret": client_secret,
            },
        )
        await http.post(
            "/request-password-reset",
            json={"email": "ada@example.com", "redirect_to": "/reset"},
        )
        seen += [
            verify,
            signed_in.json()["token"],
            key.json()["key"],
            client_secret,
            code,
            tokens.json()["refresh_token"],
            app.last_token("reset_password"),
        ]
    tables = {name: await app.auth.database.find_many(name) for name in app.auth.schema}
    assert tables["session"] and tables["api_key"] and tables["oauth_token"]
    # GotAuth's own log lines; the test client (httpx) logs the URLs it requests.
    logs = "\n".join(
        r.getMessage() for r in caplog.records if not r.name.startswith("http")
    )
    assert scan(tables, logs, seen) == []
    await engine.dispose()
