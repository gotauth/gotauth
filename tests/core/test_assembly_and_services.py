"""Assembly checks, hooks and the core services (CONTRACTS 5, 13)."""

from __future__ import annotations

from typing import Any

import pytest

from gotauth.contracts import (
    AuthError,
    AuthEvent,
    AuthResponse,
    ConfigError,
    DatabaseHooks,
    Field,
    Hook,
    ModelHooks,
    ModelSchema,
    Plugin,
    SchemaConflictError,
)
from gotauth.core import GotAuth
from gotauth.storage.memory import memory_adapter
from gotauth.testing import fake_mailer, fake_sessions, make_client

from .conftest import TEST_ENDPOINTS, build, endpoint, sample_plugin

SECRET = "assembly-tests-secret-0123456789abcd"


def gotauth(**overrides: Any) -> GotAuth:
    values: dict[str, Any] = {
        "database": memory_adapter(),
        "secret": SECRET,
        "base_url": "http://localhost:8000",
        "advanced": {"install_core_plugins": False, "session_service": fake_sessions()},
    }
    values.update(overrides)
    return GotAuth(**values)


# ------------------------------------------------------------------ assembly


def test_constructs_with_core_plugins_off() -> None:
    auth = gotauth(plugins=[sample_plugin()])
    assert auth.plugin_ids == frozenset({"test"})
    assert "user" in auth.schema


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"secret": "short"}, "32"),
        ({"base_url": "ftp://x"}, "absolute"),
        ({"base_url": "http://api.example.com"}, "https"),
        ({"base_path": "api"}, "base_path"),
    ],
)
def test_invalid_settings(overrides: dict[str, Any], message: str) -> None:
    with pytest.raises(ConfigError, match=message):
        gotauth(**overrides)


def test_duplicate_endpoint_id() -> None:
    other = Plugin(id="other", endpoints=(TEST_ENDPOINTS[0],))
    with pytest.raises(ConfigError, match="id"):
        gotauth(plugins=[sample_plugin(), other])


def test_duplicate_method_and_path() -> None:
    async def handler(ctx: Any, data: None) -> None:
        return None

    other = Plugin(id="other", endpoints=(endpoint("echo2", "POST", "/echo", handler),))
    with pytest.raises(ConfigError, match="share POST /echo"):
        gotauth(plugins=[sample_plugin(), other])


def test_duplicate_param_route() -> None:
    async def handler(ctx: Any, data: None) -> None:
        return None

    other = Plugin(
        id="other", endpoints=(endpoint("item2", "GET", "/items/{key}", handler),)
    )
    with pytest.raises(ConfigError):
        gotauth(plugins=[sample_plugin(), other])


def test_conflicting_error_code() -> None:
    other = Plugin(id="other", error_codes={"OAUTH_INVALID_GRANT": (401, "Other")})
    with pytest.raises(ConfigError, match="error code"):
        gotauth(plugins=[sample_plugin(), other])


def test_schema_conflict() -> None:
    clash = Plugin(
        id="clash", schema={"user": ModelSchema("user", {"email": Field("text")})}
    )
    with pytest.raises(SchemaConflictError):
        gotauth(plugins=[clash])


def test_get_with_json_input_is_rejected() -> None:
    async def handler(ctx: Any, data: None) -> None:
        return None

    bad = Plugin(
        id="bad",
        endpoints=(endpoint("bad", "GET", "/bad", handler, input_format="json"),),
    )
    with pytest.raises(ConfigError, match="GET"):
        gotauth(plugins=[bad])


def test_email_sender_required_off_localhost() -> None:
    needs = Plugin(id="magic", requires_email=True)
    with pytest.raises(ConfigError, match="email sender"):
        gotauth(base_url="https://api.example.com", plugins=[needs])
    gotauth(
        base_url="https://api.example.com", plugins=[needs], email_sender=fake_mailer()
    )
    gotauth(plugins=[needs])  # localhost: console sender


def test_core_plugins_need_their_modules(monkeypatch: pytest.MonkeyPatch) -> None:
    import gotauth.email_password

    monkeypatch.delattr(gotauth.email_password, "email_password_plugin")
    with pytest.raises(ConfigError, match="install_core_plugins"):
        GotAuth(
            database=memory_adapter(), secret=SECRET, base_url="http://localhost:8000"
        )


async def test_plugin_init_runs_once() -> None:
    calls: list[str] = []

    async def init(auth: Any) -> None:
        calls.append("init")

    auth = build(Plugin(id="init", init=init))
    async with make_client(auth) as client:
        await client.post("/echo", json={"name": "a"})
        await client.post("/echo", json={"name": "b"})
    assert calls == ["init"]


# ------------------------------------------------------------------ hooks


async def test_before_hook_short_circuits_and_after_hook_replaces() -> None:
    async def before(ctx: Any, payload: Any) -> AuthResponse | None:
        if payload.input.name == "stop":
            return AuthResponse(status=202, body={"stopped": True})
        return None

    async def after(ctx: Any, payload: Any) -> AuthResponse | None:
        return AuthResponse(body={"wrapped": payload.output.name})

    auth = build(
        hooks=[
            Hook(when="before", endpoints=("echo",), run=before),
            Hook(when="after", endpoints=("*",), run=after),
        ]
    )
    async with make_client(auth) as client:
        stopped = await client.post("/echo", json={"name": "stop"})
        wrapped = await client.post("/echo", json={"name": "go"})
    assert stopped.status_code == 202
    assert stopped.json() == {"stopped": True}
    assert wrapped.json() == {"wrapped": "go"}


async def test_raising_hook_fails_closed() -> None:
    async def broken(ctx: Any, payload: Any) -> None:
        raise RuntimeError("hook bug")

    auth = build(hooks=[Hook(when="before", endpoints=("create_marker",), run=broken)])
    async with make_client(auth) as client:
        response = await client.post("/marker", json={"name": "m"})
    assert response.status_code == 500
    assert await auth.api.call("count_users") == {"users": 0}


async def test_database_hooks_run_on_request_writes() -> None:
    seen: list[str] = []

    async def before_create(ctx: Any, row: dict[str, Any]) -> dict[str, Any]:
        seen.append("before")
        return {**row, "name": "hooked"}

    async def after_create(ctx: Any, row: dict[str, Any]) -> None:
        seen.append(f"after:{row['name']}")

    hooks = DatabaseHooks(
        hooks={
            "user": ModelHooks(before_create=before_create, after_create=after_create)
        }
    )
    auth = build(database_hooks=hooks)
    async with make_client(auth) as client:
        await client.post("/marker", json={"name": "m"})
    assert seen == ["before", "after:hooked"]


async def test_delete_user_runs_hooks_and_a_raising_hook_aborts() -> None:
    deleted: list[str] = []

    async def before_delete(ctx: Any, row: dict[str, Any]) -> None:
        if row["email"] == "keep@example.com":
            raise AuthError("FORBIDDEN", 403)

    async def after_delete(ctx: Any, row: dict[str, Any]) -> None:
        deleted.append(row["email"])

    plugin_hooks = DatabaseHooks(hooks={"user": ModelHooks(after_delete=after_delete)})
    config_hooks = DatabaseHooks(
        hooks={"user": ModelHooks(before_delete=before_delete)}
    )
    auth = build(
        Plugin(id="cleanup", database_hooks=plugin_hooks), database_hooks=config_hooks
    )
    gone = await auth.create_user_record(None, {"email": "Gone@Example.com"})
    keep = await auth.create_user_record(None, {"email": "keep@example.com"})
    await auth.delete_user(None, gone.id)
    with pytest.raises(AuthError):
        await auth.delete_user(None, keep.id)
    assert deleted == ["gone@example.com"]
    assert await auth.api.call("count_users") == {"users": 1}
    with pytest.raises(AuthError) as missing:
        await auth.delete_user(None, gone.id)
    assert missing.value.code == "NOT_FOUND"


async def test_delete_user_without_a_context_gives_hooks_one(
    events: list[AuthEvent],
) -> None:
    # CCR 011: the hooks join the delete's transaction and the events follow it.
    seen: list[Any] = []

    async def before_delete(ctx: Any, row: dict[str, Any]) -> None:
        assert ctx is not None
        seen.append(await ctx.auth.api.call("count_users", ctx=ctx))

    async def after_delete(ctx: Any, row: dict[str, Any]) -> None:
        if row["email"] == "fail@example.com":
            raise AuthError("FORBIDDEN", 403)

    async def record(event: AuthEvent) -> None:
        events.append(event)

    hooks = DatabaseHooks(
        hooks={
            "user": ModelHooks(before_delete=before_delete, after_delete=after_delete)
        }
    )
    auth = build(Plugin(id="cleanup", database_hooks=hooks), on_event=record)
    gone = await auth.create_user_record(None, {"email": "gone@example.com"})
    fail = await auth.create_user_record(None, {"email": "fail@example.com"})
    await auth.delete_user(None, gone.id)
    await auth.drain()
    assert seen == [{"users": 2}]  # read inside the delete's transaction
    assert [e.type for e in events if e.type == "user.deleted"] == ["user.deleted"]
    with pytest.raises(AuthError):
        await auth.delete_user(None, fail.id)
    await auth.drain()
    assert await auth.api.call("count_users") == {"users": 1}  # rolled back
    assert [e.type for e in events].count("user.deleted") == 1


# ------------------------------------------------------------------ server calls


async def test_joined_server_call_shares_the_transaction() -> None:
    auth = build()
    async with make_client(auth) as client:
        ok = await client.post("/caller", json={"name": "ok"})
        failed = await client.post("/caller", json={"name": "fail"})
    assert ok.status_code == 200
    assert failed.status_code == 403
    # The callee's failure rolled back the caller's user.
    assert await auth.api.call("count_users") == {"users": 1}


async def test_api_typed_member_without_endpoint_is_not_found() -> None:
    auth = build()
    with pytest.raises(AuthError) as caught:
        await auth.api.sign_up_email({"email": "a@b.c"})
    assert caught.value.code == "NOT_FOUND"


async def test_api_call_as_response() -> None:
    auth = build()
    response = await auth.api.call("echo", {"name": "a"}, as_response=True)
    assert isinstance(response, AuthResponse)
    assert response.headers["cache-control"] == "no-store"


async def test_drain_waits_for_event_delivery() -> None:
    delivered: list[str] = []

    async def slow(event: Any) -> None:
        import asyncio

        await asyncio.sleep(0.01)
        delivered.append(event.type)

    auth = build(on_event=slow)
    async with make_client(auth) as client:
        await client.post("/marker", json={"name": "m"})
    await auth.drain()
    assert delivered == ["user.created"]
