"""EndpointContext.defer (CONTRACTS 5): work after the commit, off the response path."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import BaseModel

from gotauth.contracts import AuthError, Endpoint, EndpointContext, Plugin, Where
from gotauth.testing import make_auth, make_client

GATE: dict[str, asyncio.Event] = {}
DONE: set[str] = set()


class NameIn(BaseModel):
    name: str


async def create_later(ctx: EndpointContext, data: NameIn) -> dict[str, str]:
    async def create(later: EndpointContext) -> None:
        gate = GATE.get(data.name)
        if gate is not None:
            await gate.wait()
        await later.auth.create_user_record(
            later, {"email": f"{data.name}@example.com"}
        )
        await later.emit("user.updated")
        DONE.add(data.name)

    ctx.defer(create)
    return {"status": "ok"}


async def defer_then_fail(ctx: EndpointContext, data: NameIn) -> None:
    async def create(later: EndpointContext) -> None:
        await later.auth.create_user_record(
            later, {"email": f"{data.name}@example.com"}
        )

    ctx.defer(create)
    raise AuthError("FORBIDDEN", 403)


async def defer_boom(ctx: EndpointContext, data: NameIn) -> dict[str, str]:
    async def boom(later: EndpointContext) -> None:
        await later.auth.create_user_record(
            later, {"email": f"{data.name}@example.com"}
        )
        raise RuntimeError(f"secret detail for {data.name}")

    ctx.defer(boom)
    return {"status": "ok"}


async def joined(ctx: EndpointContext, data: NameIn) -> dict[str, str]:
    await ctx.auth.api.call("create_later", body={"name": data.name}, ctx=ctx)
    return {"status": "ok"}


PLUGIN = Plugin(
    id="deferred_test",
    endpoints=tuple(
        Endpoint[Any, Any](id=i, method="POST", path=p, handler=h, input=NameIn)  # type: ignore[arg-type]
        for i, p, h in [
            ("create_later", "/later", create_later),
            ("defer_then_fail", "/later-fail", defer_then_fail),
            ("defer_boom", "/later-boom", defer_boom),
            ("joined", "/joined", joined),
        ]
    ),
)


def build(**overrides: Any) -> tuple[Any, list[str]]:  # Any: GotAuth
    events: list[str] = []

    async def record(event: Any) -> None:  # Any: AuthEvent
        events.append(event.type)

    auth = make_auth(plugins=[PLUGIN], on_event=record, **overrides)
    return auth, events


async def user(auth: Any, name: str) -> Any:  # Any: a row or None
    return await auth.database.find_one("user", [Where("email", f"{name}@example.com")])


async def test_on_localhost_deferred_work_runs_before_the_reply() -> None:
    auth, _ = build()
    async with make_client(auth) as client:
        response = await client.post("/later", json={"name": "local"})
    assert response.status_code == 200
    assert await user(auth, "local") is not None


async def test_off_localhost_the_reply_does_not_wait() -> None:
    auth, events = build(base_url="https://auth.example.com")
    GATE["remote"] = asyncio.Event()
    try:
        async with make_client(auth) as client:
            # The deferred work waits on the gate; a reply that waited would hang.
            response = await asyncio.wait_for(
                client.post("/later", json={"name": "remote"}), timeout=5
            )
        assert response.status_code == 200
        # The job is still waiting (and holds its transaction, so no reads here).
        assert "remote" not in DONE
        GATE["remote"].set()
        await auth.drain()
    finally:
        GATE.pop("remote", None)
    assert await user(auth, "remote") is not None
    assert "user.updated" in events  # events of deferred work are delivered


async def test_a_failed_request_drops_its_deferred_work() -> None:
    auth, _ = build()
    async with make_client(auth) as client:
        response = await client.post("/later-fail", json={"name": "dropped"})
    await auth.drain()
    assert response.status_code == 403
    assert await user(auth, "dropped") is None


async def test_failing_deferred_work_is_logged_without_details(
    caplog: pytest.LogCaptureFixture,
) -> None:
    auth, _ = build()
    async with make_client(auth) as client:
        response = await client.post("/later-boom", json={"name": "boom"})
    await auth.drain()
    assert response.status_code == 200
    assert await user(auth, "boom") is None  # its own transaction rolled back
    assert "deferred work failed (RuntimeError)" in caplog.text
    assert "secret detail" not in caplog.text


async def test_nested_server_calls_defer_to_the_outer_request() -> None:
    auth, _ = build()
    async with make_client(auth) as client:
        response = await client.post("/joined", json={"name": "nested"})
    assert response.status_code == 200
    assert await user(auth, "nested") is not None


async def test_server_calls_run_their_deferred_work() -> None:
    auth, _ = build()
    await auth.api.call("create_later", body={"name": "server"})
    await auth.drain()
    assert await user(auth, "server") is not None
