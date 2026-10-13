"""The OpenID conformance app: its sign-in page leads the suite's browser from the
authorize request to the consent screen (issue #7)."""

from __future__ import annotations

import re
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from gotauth.plugins.oauth_provider.conformance import (
    TEST_EMAIL,
    TEST_PASSWORD,
    create_app,
)

from .conftest import pkce

BASE = "http://localhost:8000"
REDIRECT = "https://localhost.emobix.co.uk:8443/test/a/gotauth/callback"


def test_sign_in_page_leads_to_the_consent_screen(
    capsys: pytest.CaptureFixture[str],
) -> None:
    with TestClient(create_app(), base_url=BASE) as http:
        client_id = re.findall(r"client: client_id=(\S+)", capsys.readouterr().out)[0]
        _, challenge = pkce()
        authorize = http.get(
            "/api/auth/oauth2/authorize",
            params={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": REDIRECT,
                "scope": "openid email",
                "state": "s",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
            },
            follow_redirects=False,
        )
        assert authorize.status_code == 302
        login = authorize.headers["location"]
        assert login.startswith("/sign-in?callback_url=")
        page = http.get(login)
        assert page.status_code == 200 and 'id="sign-in"' in page.text
        callback = str(authorize.request.url)

        wrong = http.post(
            "/sign-in",
            content=f"email={quote(TEST_EMAIL)}&password=nope"
            f"&callback_url={quote(callback)}",
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        assert wrong.status_code == 401

        signed_in = http.post(
            "/sign-in",
            content=f"email={quote(TEST_EMAIL)}&password={quote(TEST_PASSWORD)}"
            f"&callback_url={quote(callback)}",
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        assert signed_in.status_code == 303
        assert signed_in.headers["location"] == callback
        assert "gotauth.session_token=" in signed_in.headers["set-cookie"]

        consent = http.get(callback, follow_redirects=False)
        assert consent.status_code == 200
        assert 'id="allow"' in consent.text


@pytest.mark.parametrize(
    "callback",
    [
        "https://evil.example/api/auth/oauth2/authorize",
        f"{BASE}/somewhere-else",
        "//evil.example/api/auth/oauth2/authorize",
        "",
    ],
)
def test_sign_in_never_redirects_elsewhere(callback: str) -> None:
    with TestClient(create_app(), base_url=BASE) as http:
        response = http.post(
            "/sign-in",
            content=f"email={quote(TEST_EMAIL)}&password={quote(TEST_PASSWORD)}"
            f"&callback_url={quote(callback)}",
            headers={"content-type": "application/x-www-form-urlencoded"},
            follow_redirects=False,
        )
        assert response.status_code == 303
        assert response.headers["location"] == "/"
