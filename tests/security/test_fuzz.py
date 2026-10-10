"""Hypothesis fuzzing of every HTTP endpoint's input: never a 500, never an echoed
input, and always the documented error shape (section 6, or RFC 6749 for
``error_format="oauth"`` endpoints)."""

from __future__ import annotations

import json
import re
from typing import Any

import httpx
import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import Endpoint, EndpointContext, Plugin

from .conftest import full_app

MARKER = "zqxmarker"
_PARAM = re.compile(r"\{(\w+)\}")


def endpoints(auth: Any) -> list[Endpoint[Any, Any]]:  # Any: GotAuth
    return [e for plugin in auth.plugins for e in plugin.endpoints if not e.server_only]


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
    if response.status_code >= 400 and response.headers.get(
        "content-type", ""
    ).startswith("application/json"):
        body = response.json()
        bearer = response.headers.get("www-authenticate", "").startswith("Bearer ")
        if endpoint.error_format == "oauth" or bearer:  # RFC 6749 / RFC 6750
            if (
                not isinstance(body, dict)
                or "error" not in body
                or not isinstance(body["error"], str)
            ):
                found.append(f"{endpoint.id}: not an RFC 6749 error")
        elif not (
            isinstance(body, dict)
            and isinstance(body.get("error"), dict)
            and "code" in body["error"]
        ):
            found.append(f"{endpoint.id}: not a section 6 error")
        if MARKER in json.dumps(body):
            found.append(f"{endpoint.id}: input echoed in the error")
    return found


async def send(
    http: httpx.AsyncClient, endpoint: Endpoint[Any, Any], body: dict[str, Any]
) -> httpx.Response:  # Any: JSON
    path = _PARAM.sub("x", endpoint.path)
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
    targets = endpoints(app.auth)
    async with app.client() as http:
        await app.verified_user(http)  # a session, so session endpoints get past auth
        for endpoint in targets:
            body = data.draw(bodies(endpoint), label=endpoint.id)
            response = await send(http, endpoint, body)
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
