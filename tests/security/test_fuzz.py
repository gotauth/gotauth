"""Hypothesis fuzzing of every HTTP endpoint's input: never a 500, never an echoed
input, and always the documented error shape (section 6, or RFC 6749 for
``error_format="oauth"`` endpoints)."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import Endpoint, EndpointContext, Plugin

from .conftest import full_app

MARKER = "zqxmarker"
_PARAM = re.compile(r"\{(\w+)\}")
# Endpoints that can end the test's session or delete its fixtures run last, so every
# other session endpoint is fuzzed past the auth check.
LAST = ("delete_api_key", "delete_user", "sign_out")


def endpoints(auth: Any) -> list[Endpoint[Any, Any]]:  # Any: GotAuth
    """Every HTTP endpoint, the session-ending ones last in ``LAST`` order."""
    found = [
        e
        for plugin in auth.plugins
        for e in (*plugin.endpoints, *plugin.well_known_endpoints)
        if not e.server_only
    ]
    return sorted(found, key=lambda e: LAST.index(e.id) + 1 if e.id in LAST else 0)


def is_well_known(endpoint: Endpoint[Any, Any]) -> bool:
    return endpoint.path.startswith("/.well-known/") and "{base_path}" in endpoint.path


values = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**40), max_value=2**40),
    st.text(max_size=40).map(lambda s: f"{MARKER}{s}"),
    st.lists(st.text(max_size=8), max_size=3),
)


def bodies(endpoint: Endpoint[Any, Any]) -> st.SearchStrategy[dict[str, Any]]:
    """Inputs built from the endpoint's own fields plus one unknown key. The marker
    only goes in values: section 6 allows field names (locations) in errors."""
    fields = sorted(endpoint.input.model_fields) if endpoint.input else []
    return st.dictionaries(st.sampled_from([*fields, "unknown"]), values, max_size=6)


def problems(endpoint: Endpoint[Any, Any], response: httpx.Response) -> list[str]:
    """What is wrong with one answer to fuzzed input."""
    found: list[str] = []
    if response.status_code >= 500:
        found.append(f"{endpoint.id}: HTTP {response.status_code}")
    if response.status_code < 400:
        return found
    # Any content type: an HTML error page that prints input is reflected XSS.
    if MARKER in response.text:
        found.append(f"{endpoint.id}: input echoed in the error")
    if response.headers.get("content-type", "").startswith("application/json"):
        body = response.json()
        bearer = response.headers.get("www-authenticate", "").startswith("Bearer ")
        if endpoint.error_format == "oauth" or bearer:  # RFC 6749 / RFC 6750
            if not (isinstance(body, dict) and isinstance(body.get("error"), str)):
                found.append(f"{endpoint.id}: not an RFC 6749 error")
        elif not (
            isinstance(body, dict)
            and isinstance(body.get("error"), dict)
            and "code" in body["error"]
        ):
            found.append(f"{endpoint.id}: not a section 6 error")
    return found


async def send(
    http: httpx.AsyncClient,
    endpoint: Endpoint[Any, Any],
    body: dict[str, Any],  # Any: JSON
    params: Mapping[str, str] | None = None,
) -> httpx.Response:
    """Send ``body`` as the endpoint expects it; ``params`` fill the path."""
    path = _PARAM.sub(lambda m: (params or {}).get(m.group(1), "x"), endpoint.path)
    if endpoint.method == "GET":
        query = {
            k: json.dumps(v) if not isinstance(v, str) else v for k, v in body.items()
        }
        return await http.get(path, params=query)
    if endpoint.input_format == "form":
        form = {k: v if isinstance(v, str) else json.dumps(v) for k, v in body.items()}
        return await http.request(endpoint.method, path, data=form)
    return await http.request(endpoint.method, path, json=body)


@settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.too_slow],
)
@given(data=st.data())
async def test_every_endpoint_survives_fuzzed_input(data: st.DataObject) -> None:
    app = full_app(rate_limit={"enabled": False})
    config = app.auth.config
    root = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app.auth.well_known()),
        base_url=config.base_url.rstrip("/"),
    )
    async with app.client() as http, root:
        await app.verified_user(http)  # a session, so session endpoints get past auth
        key = await http.post("/api-keys", json={"name": "fuzz"})
        params = {
            "provider": "fake",
            "id": key.json()["api_key"]["id"],
            "base_path": config.base_path,
        }
        for endpoint in endpoints(app.auth):
            if endpoint.id == LAST[0]:
                session = await http.get("/session")
                assert session.json() is not None, "the session ended before LAST"
            body = data.draw(bodies(endpoint), label=endpoint.id)
            client = root if is_well_known(endpoint) else http
            response = await send(client, endpoint, body, params)
            assert problems(endpoint, response) == []


async def test_the_harness_catches_a_crashing_endpoint() -> None:
    async def explode(ctx: EndpointContext, _: None) -> None:
        raise RuntimeError(f"{MARKER} internal detail")

    crash = Plugin(
        id="crash", endpoints=(Endpoint("crash", "POST", "/crash", explode),)
    )
    app = full_app(plugins=[crash])
    endpoint = crash.endpoints[0]
    async with app.client() as http:
        response = await send(http, endpoint, {})
    assert response.status_code == 500  # the pipeline answers INTERNAL_ERROR...
    assert problems(endpoint, response) == [
        "crash: HTTP 500"
    ]  # ...and the harness flags it
    assert MARKER not in response.text


@pytest.mark.parametrize("bad", [b"{", b"[1,2", b"\xff\xfe"])
async def test_broken_bodies_are_400s(bad: bytes) -> None:
    app = full_app()
    async with app.client() as http:
        response = await http.post(
            "/sign-in/email", content=bad, headers={"content-type": "application/json"}
        )
    assert response.status_code == 400


def test_the_harness_catches_input_echoed_in_an_html_page() -> None:
    page = httpx.Response(
        400, html=f"<p>Unknown client {MARKER}abc</p>"
    )  # reflected XSS shape
    endpoint = Endpoint("page", "GET", "/page", None)  # type: ignore[arg-type]
    assert problems(endpoint, page) == ["page: input echoed in the error"]
