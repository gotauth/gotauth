"""The endpoint context and the hook-running adapter wrapper (CONTRACTS 5 and 13)."""

from __future__ import annotations

from collections.abc import AsyncGenerator, Mapping, Sequence
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from typing import TYPE_CHECKING, Any

from gotauth.contracts.adapter import Adapter, SortBy, Where
from gotauth.contracts.events import AuthEvent, AuthEventType
from gotauth.contracts.http import AuthRequest, SetCookie
from gotauth.contracts.principal import Principal
from gotauth.contracts.schema import Schema

if TYPE_CHECKING:
    from gotauth.contracts.config import ModelHooks
    from gotauth.contracts.crypto import CryptoKit
    from gotauth.contracts.email import EmailService
    from gotauth.contracts.primitives import Clock, IdGenerator
    from gotauth.contracts.sessions import SessionService
    from gotauth.core._auth import GotAuth

__all__ = ["HookedAdapter", "RequestContext"]


class HookedAdapter:
    """Runs the model's ``DatabaseHooks`` around writes, then calls the wrapped adapter.

    ``before_create`` and ``before_update`` may return replacement data; every hook may
    raise ``AuthError`` to abort. Hooks for update and delete run once per affected row.
    """

    def __init__(
        self, inner: Adapter, auth: GotAuth, ctx: RequestContext | None
    ) -> None:
        self.inner = inner
        self._auth = auth
        self._ctx = ctx
        self.id = inner.id

    def _hooks(self, model: str) -> list[ModelHooks]:
        return self._auth.model_hooks(model)

    async def create(self, model: str, data: Mapping[str, Any]) -> dict[str, Any]:
        """Insert a row, running ``before_create`` and ``after_create``."""
        values = dict(data)
        hooks = self._hooks(model)
        for hook in hooks:
            if hook.before_create is not None:
                changed = await hook.before_create(self._ctx, values)
                if changed is not None:
                    values = changed
        row = await self.inner.create(model, values)
        for hook in hooks:
            if hook.after_create is not None:
                await hook.after_create(self._ctx, dict(row))
        return row

    async def find_one(
        self, model: str, where: Sequence[Where]
    ) -> dict[str, Any] | None:
        """Return the first matching row."""
        return await self.inner.find_one(model, where)

    async def find_many(
        self,
        model: str,
        where: Sequence[Where] = (),
        *,
        limit: int | None = None,
        offset: int | None = None,
        sort_by: SortBy | None = None,
    ) -> list[dict[str, Any]]:
        """Return the matching rows."""
        return await self.inner.find_many(
            model, where, limit=limit, offset=offset, sort_by=sort_by
        )

    async def count(self, model: str, where: Sequence[Where] = ()) -> int:
        """Return the number of matching rows."""
        return await self.inner.count(model, where)

    async def _before_update(
        self, model: str, data: Mapping[str, Any]
    ) -> dict[str, Any]:
        values = dict(data)
        for hook in self._hooks(model):
            if hook.before_update is not None:
                changed = await hook.before_update(self._ctx, values)
                if changed is not None:
                    values = changed
        return values

    async def _after_update(self, model: str, row: dict[str, Any]) -> None:
        for hook in self._hooks(model):
            if hook.after_update is not None:
                await hook.after_update(self._ctx, dict(row))

    async def update(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> dict[str, Any] | None:
        """Update at most one row, running the update hooks when one matched."""
        if not self._hooks(model):
            return await self.inner.update(model, where, data)
        values = await self._before_update(model, data)
        row = await self.inner.update(model, where, values)
        if row is not None:
            await self._after_update(model, row)
        return row

    async def update_many(
        self, model: str, where: Sequence[Where], data: Mapping[str, Any]
    ) -> int:
        """Update every matching row, running ``after_update`` for each."""
        if not self._hooks(model):
            return await self.inner.update_many(model, where, data)
        ids = [row["id"] for row in await self.inner.find_many(model, where)]
        values = await self._before_update(model, data)
        count = await self.inner.update_many(model, where, values)
        if ids:
            for row in await self.inner.find_many(model, [Where("id", ids, "in")]):
                await self._after_update(model, row)
        return count

    async def delete(self, model: str, where: Sequence[Where]) -> int:
        """Delete the matching rows, running the delete hooks for each."""
        hooks = self._hooks(model)
        if not hooks:
            return await self.inner.delete(model, where)
        rows = await self.inner.find_many(model, where)
        for row in rows:
            for hook in hooks:
                if hook.before_delete is not None:
                    await hook.before_delete(self._ctx, dict(row))
        count = await self.inner.delete(model, where)
        for row in rows:
            for hook in hooks:
                if hook.after_delete is not None:
                    await hook.after_delete(self._ctx, dict(row))
        return count

    def transaction(self) -> AbstractAsyncContextManager[Adapter]:
        """Reuse the wrapped adapter's transaction, keeping the hooks."""
        return self._transaction()

    @asynccontextmanager
    async def _transaction(self) -> AsyncGenerator[Adapter]:
        async with self.inner.transaction() as inner:
            yield HookedAdapter(inner, self._auth, self._ctx)

    def bind_schema(self, schema: Schema, *, table_prefix: str = "auth_") -> None:
        """Not allowed on a request adapter."""
        msg = "bind_schema() must be called on the root adapter"
        raise RuntimeError(msg)


def unwrap(adapter: Adapter) -> Adapter:
    """Return the adapter under a ``HookedAdapter`` (services run hooks themselves)."""
    return adapter.inner if isinstance(adapter, HookedAdapter) else adapter


class RequestContext:
    """What a handler sees (CONTRACTS 5 ``EndpointContext``)."""

    def __init__(
        self,
        *,
        auth: GotAuth,
        request: AuthRequest,
        adapter: Adapter,
        principal: Principal | None = None,
        path_params: Mapping[str, str] | None = None,
        events: list[AuthEvent] | None = None,
        cookies: list[SetCookie] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._auth = auth
        self._request = request
        self._adapter = adapter
        self.principal: Principal | None = principal
        self._path_params: Mapping[str, str] = dict(path_params or {})
        # Shared lists, so nested server calls report to their caller.
        self.events: list[AuthEvent] = events if events is not None else []
        self.cookies: list[SetCookie] = cookies if cookies is not None else []
        self.headers: dict[str, str] = headers if headers is not None else {}

    def __repr__(self) -> str:
        return f"RequestContext({self._request.method} {self._request.path})"

    @property
    def auth(self) -> GotAuth:
        """The GotAuth instance."""
        return self._auth

    @property
    def request(self) -> AuthRequest:
        """The current request."""
        return self._request

    @property
    def adapter(self) -> Adapter:
        """Storage, bound to the request transaction."""
        return self._adapter

    @adapter.setter
    def adapter(self, value: Adapter) -> None:
        self._adapter = value

    @property
    def clock(self) -> Clock:
        """The injected clock."""
        return self._auth.clock

    @property
    def ids(self) -> IdGenerator:
        """The injected id generator."""
        return self._auth.ids

    @property
    def crypto(self) -> CryptoKit:
        """The crypto kit."""
        return self._auth.crypto

    @property
    def sessions(self) -> SessionService:
        """The session service."""
        return self._auth.sessions

    @property
    def email(self) -> EmailService:
        """The email service."""
        return self._auth.email

    @property
    def path_params(self) -> Mapping[str, str]:
        """Values of the ``{param}`` parts of the path."""
        return self._path_params

    def set_cookie(self, cookie: SetCookie) -> None:
        """Add a cookie to the response."""
        self.cookies.append(cookie)

    def set_header(self, name: str, value: str) -> None:
        """Add a header to the response."""
        self.headers[name.lower()] = value

    async def emit(
        self, event_type: AuthEventType, **data: Any
    ) -> None:  # Any: event data
        """Queue an event; it is delivered after the transaction commits."""
        user_id = data.pop("user_id", None)
        if user_id is None and self.principal is not None:
            user_id = self.principal.user_id
        self.events.append(
            AuthEvent(
                id=self.ids.new("evt"),
                type=event_type,
                at=self.clock.now(),
                user_id=user_id if isinstance(user_id, str) else None,
                principal=self.principal,
                ip_address=self._request.client_ip,
                user_agent=self._request.headers.get("user-agent"),
                data=data,
            )
        )
