"""EndpointContext.on_failure (CCR 012): writes that outlast a failed request."""

from __future__ import annotations

import logging
from typing import Any

import pytest
from pydantic import BaseModel

from gotauth.contracts import AuthError, Endpoint, EndpointContext, Plugin, Where
from gotauth.testing import call_endpoint, make_auth, make_client, make_context


class NameIn(BaseModel):
    name: str
    fail: bool = True


async def record_then(ctx: EndpointContext, data: NameIn) -> dict[str, str]:
    """Writes one user in the request and one in the failure work."""

    async def record(later: EndpointContext) -> None:
        await later.auth.create_user_record(
            later, {"email": f"{data.name}-failed@example.com"}
        )

    ctx.on_failure(record)
    await ctx.auth.create_user_record(ctx, {"email": f"{data.name}@example.com"})
    if data.fail:
        raise AuthError("FORBIDDEN", 403)
    return {"status": "ok"}


async def boom_then_fail(ctx: EndpointContext, data: NameIn) -> None:
    async def boom(later: EndpointContext) -> None:
        raise RuntimeError(f"secret detail for {data.name}")

    ctx.on_failure(boom)
    raise AuthError("FORBIDDEN", 403)


async def joined(ctx: EndpointContext, data: NameIn) -> None:
    await ctx.auth.api.call(
        "record_then", body={"name": data.name, "fail": False}, ctx=ctx
    )
    raise AuthError("FORBIDDEN", 403)  # the outer request fails afterwards


PLUGIN = Plugin(
    id="on_failure_test",
    endpoints=tuple(
        Endpoint[Any, Any](id=i, method="POST", path=p, handler=h, input=NameIn)  # type: ignore[arg-type]
        for i, p, h in [
            ("record_then", "/record", record_then),
            ("boom_then_fail", "/boom", boom_then_fail),
            ("joined", "/joined", joined),
        ]
    ),
)


async def emails(auth: Any) -> set[str]:  # Any: GotAuth
    return {row["email"] for row in await auth.database.find_many("user", [])}


async def test_failure_work_outlasts_the_rollback() -> None:
    auth: Any = make_auth(plugins=[PLUGIN])
    async with make_client(auth) as http:
        response = await http.post("/record", json={"name": "ada"})
    assert response.status_code == 403
    # The request's own write is gone; the failure work's stays.
    assert await emails(auth) == {"ada-failed@example.com"}


async def test_a_successful_request_drops_its_failure_work() -> None:
    auth: Any = make_auth(plugins=[PLUGIN])
    async with make_client(auth) as http:
        response = await http.post("/record", json={"name": "ada", "fail": False})
    assert response.status_code == 200
    assert await emails(auth) == {"ada@example.com"}


async def test_failure_work_of_a_joined_call_runs_when_the_caller_fails() -> None:
    auth: Any = make_auth(plugins=[PLUGIN])
    async with make_client(auth) as http:
        response = await http.post("/joined", json={"name": "ada"})
    assert response.status_code == 403
    assert await emails(auth) == {"ada-failed@example.com"}


async def test_errors_in_failure_work_are_logged_without_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    auth: Any = make_auth(plugins=[PLUGIN])
    with caplog.at_level(logging.WARNING, logger="gotauth"):
        async with make_client(auth) as http:
            response = await http.post("/boom", json={"name": "ada"})
    assert response.status_code == 403  # the original error, not the work's
    assert "RuntimeError" in caplog.text and "secret detail" not in caplog.text


async def test_the_testing_kit_runs_failure_work_too() -> None:
    ctx = make_context(plugins=[PLUGIN])
    endpoint = PLUGIN.endpoints[0]
    with pytest.raises(AuthError):
        await call_endpoint(endpoint, {"name": "ada"}, ctx=ctx)
    rows = await ctx.adapter.find_many(
        "user", [Where("email", "ada-failed@example.com")]
    )
    assert len(rows) == 1
