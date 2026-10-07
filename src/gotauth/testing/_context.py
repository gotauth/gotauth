"""``make_context`` and ``call_endpoint``: unit-test endpoints without the core (C1).

The fakes mirror the C1 brief: input validation, principal resolution, ``auth``,
``scopes`` and ``fresh_session`` checks, one transaction per call, events kept only on
commit (``sign_in.failed`` always), the challenge cookie and the user record helpers.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
from collections.abc import Awaitable, Iterator, Mapping, Sequence
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Generic, Literal, TypeVar, cast, overload
from urllib.parse import urlencode

import httpx
from pydantic import BaseModel, SecretStr, ValidationError

from gotauth.contracts.adapter import Adapter, Where
from gotauth.contracts.config import (
    AdvancedConfig,
    ApiMethod,
    DatabaseHooks,
    ModelHooks,
    ResolvedConfig,
)
from gotauth.contracts.core_schema import CORE_SCHEMA, User
from gotauth.contracts.endpoints import (
    CHALLENGE_TTL,
    ChallengeState,
    Endpoint,
    EndpointContext,
    Plugin,
    PrincipalResolver,
    SignInChallenge,
    SignInMethod,
)
from gotauth.contracts.errors import AuthError, ConfigError
from gotauth.contracts.events import AuthEvent, AuthEventType
from gotauth.contracts.http import ASGIApp, AuthRequest, AuthResponse, SetCookie
from gotauth.contracts.http_models import (
    AccountListOut,
    ChallengeOut,
    RedirectOut,
    SessionListOut,
    SessionWithUserOut,
    SignInOut,
    StatusOut,
    UserOut,
)
from gotauth.contracts.primitives import to_timedelta
from gotauth.contracts.principal import Principal
from gotauth.contracts.protection import normalize_origin
from gotauth.contracts.schema import Schema, merge_schemas, returned_only
from gotauth.contracts.sessions import (
    TOKEN_PREFIXES,
    CreatedSession,
    SecondaryStorage,
    SessionConfig,
    SessionService,
    cookie_name,
    secure_cookies,
)
from gotauth.contracts.social import OAuthProvider
from gotauth.crypto import crypto_kit
from gotauth.storage.memory import memory_adapter
from gotauth.testing._clock import fake_clock, seq_ids
from gotauth.testing._mail import PassThroughEmailService, fake_mailer
from gotauth.testing._sessions import fake_sessions

if TYPE_CHECKING:
    from gotauth.contracts.crypto import CryptoKit
    from gotauth.contracts.email import EmailService, FakeMailer
    from gotauth.contracts.primitives import FakeClock, IdGenerator

__all__ = [
    "TEST_BASE_URL",
    "TEST_SECRET",
    "FakeApi",
    "FakeAuth",
    "FakeContext",
    "SignInCall",
    "call_endpoint",
    "make_context",
    "make_request",
]

logger = logging.getLogger("gotauth.testing")

TEST_SECRET = "test-secret-" * 4
"""The secret ``make_context`` and ``make_auth`` use (48 characters)."""

TEST_BASE_URL = "http://localhost:8000"
"""The ``base_url`` ``make_context`` and ``make_auth`` use."""

OutputT = TypeVar("OutputT")


def make_request(
    config: ResolvedConfig | None = None,
    *,
    method: str = "POST",
    path: str = "/",
    body: bytes = b"",
    query: Mapping[str, str] | None = None,
    headers: Mapping[str, str] | None = None,
    cookies: Mapping[str, str] | None = None,
    client_ip: str | None = "127.0.0.1",
) -> AuthRequest:
    """Build an ``AuthRequest`` as an integration would hand it to the core.

    By default it is a JSON POST from the ``base_url`` origin. Header names are
    lower-cased.
    """
    base_url = config.base_url if config is not None else TEST_BASE_URL
    base_path = config.base_path if config is not None else "/api/auth"
    merged = {
        "origin": normalize_origin(base_url) or base_url,
        "content-type": "application/json",
        "user-agent": "gotauth-testing",
    }
    merged.update({name.lower(): value for name, value in (headers or {}).items()})
    url = base_url.rstrip("/") + base_path + path
    if query:
        url += "?" + urlencode(query)
    return AuthRequest(
        method=method.upper(),
        path=path,
        url=url,
        query=dict(query or {}),
        headers=merged,
        cookies=dict(cookies or {}),
        body=body,
        client_ip=client_ip,
    )


class SignInCall(BaseModel):
    """A recorded ``complete_sign_in`` call."""

    user_id: str
    method: SignInMethod
    remember_me: bool


class FakeContext:
    """An ``EndpointContext`` for unit tests, built by :func:`make_context`.

    Besides the context members it records what a response would carry:

    - ``cookies``: every ``SetCookie``, in order; ``jar`` is the resulting cookie state.
    - ``headers``: response headers.
    - ``events``: emitted events (with :func:`call_endpoint`, only after a commit).

    ``principal`` may be set directly. :meth:`sign_in` creates a session and uses it.
    """

    def __init__(
        self,
        *,
        auth: FakeAuth,
        request: AuthRequest,
        adapter: Adapter,
        principal: Principal | None = None,
        path_params: Mapping[str, str] | None = None,
        root_adapter: Adapter | None = None,
    ) -> None:
        self.auth = auth
        self.request = request
        self.adapter = adapter
        self.principal = principal
        self.path_params: Mapping[str, str] = dict(path_params or {})
        self.cookies: list[SetCookie] = []
        self.headers: dict[str, str] = {}
        self.events: list[AuthEvent] = []
        self._root_adapter = root_adapter if root_adapter is not None else adapter

    def __repr__(self) -> str:
        return f"FakeContext({self.request!r}, principal={self.principal!r})"

    @property
    def clock(self) -> FakeClock:
        """The fake clock shared by every context of the same ``make_context`` call."""
        return self.auth.clock

    @property
    def ids(self) -> IdGenerator:
        """The id generator."""
        return self.auth.ids

    @property
    def crypto(self) -> CryptoKit:
        """The crypto kit (F3's when merged, else the testing stand-in)."""
        return self.auth.crypto

    @property
    def sessions(self) -> SessionService:
        """The session service (``fake_sessions()`` unless overridden)."""
        return self.auth.sessions

    @property
    def email(self) -> EmailService:
        """The email service; messages land in :attr:`mailer`."""
        return self.auth.email

    @property
    def mailer(self) -> FakeMailer:
        """The fake mailer behind the email service."""
        return self.auth.mailer

    def set_cookie(self, cookie: SetCookie) -> None:
        """Record a cookie."""
        self.cookies.append(cookie)

    def set_header(self, name: str, value: str) -> None:
        """Record a response header (lower-cased name)."""
        self.headers[name.lower()] = value

    async def emit(self, event_type: AuthEventType, **data: Any) -> None:
        """Record an event."""
        principal = self.principal
        user_id = data.get("user_id")
        if not isinstance(user_id, str):
            user_id = principal.user_id if principal is not None else None
        self.events.append(
            AuthEvent(
                id=self.ids.new("evt"),
                type=event_type,
                at=self.clock.now(),
                user_id=user_id,
                principal=principal,
                ip_address=self.request.client_ip,
                user_agent=self.request.headers.get("user-agent"),
                data=dict(data),
            )
        )

    @property
    def jar(self) -> dict[str, str]:
        """Request cookies with every recorded ``SetCookie`` applied, like a browser."""
        cookies = dict(self.request.cookies)
        for cookie in self.cookies:
            if cookie.max_age == 0:
                cookies.pop(cookie.name, None)
            else:
                cookies[cookie.name] = cookie.value
        return cookies

    def cookie(self, base: str) -> str | None:
        """Return the jar value of a GotAuth cookie by base name (``"challenge"``)."""
        return self.jar.get(self.auth.cookie_name(base))

    def event_types(self) -> list[AuthEventType]:
        """Return the types of the recorded events, in order."""
        return [event.type for event in self.events]

    def next_request(
        self,
        *,
        method: str = "POST",
        path: str = "/",
        body: bytes = b"",
        query: Mapping[str, str] | None = None,
        headers: Mapping[str, str] | None = None,
        cookies: Mapping[str, str] | None = None,
        principal: Principal | None = None,
        path_params: Mapping[str, str] | None = None,
    ) -> FakeContext:
        """Return a context for the browser's next request.

        It carries this context's cookie :attr:`jar` (plus ``cookies``) and shares the
        storage and services. ``principal`` starts empty, so :func:`call_endpoint`
        resolves it from the cookies or headers, as C1 does.
        """
        jar = self.jar
        jar.update(cookies or {})
        request = make_request(
            self.auth.config,
            method=method,
            path=path,
            body=body,
            query=query,
            headers=headers,
            cookies=jar,
            client_ip=self.request.client_ip,
        )
        return FakeContext(
            auth=self.auth,
            request=request,
            adapter=self._root_adapter,
            principal=principal,
            path_params=path_params,
        )

    async def sign_in(
        self, user_id: str, *, remember_me: bool = True
    ) -> CreatedSession:
        """Create a session for ``user_id`` and make it this context's principal."""
        created = await self.sessions.create(self, user_id, remember_me=remember_me)
        self.principal = session_principal(created)
        return created

    async def dump(self) -> dict[str, list[dict[str, Any]]]:
        """Return every row of every model, e.g. to check no raw token is stored."""
        return {
            model: await self.adapter.find_many(model) for model in self.auth.schema
        }

    def derive(self, *, adapter: Adapter, principal: Principal | None) -> FakeContext:
        """Return a child context for one call: same request, its own records."""
        return FakeContext(
            auth=self.auth,
            request=self.request,
            adapter=adapter,
            principal=principal,
            path_params=self.path_params,
            root_adapter=self._root_adapter,
        )

    def absorb(self, child: FakeContext, *, committed: bool) -> None:
        """Take over a child's records: all of them on commit, else only failures."""
        if committed:
            self.cookies.extend(child.cookies)
            self.headers.update(child.headers)
            self.events.extend(child.events)
        else:
            self.events.extend(e for e in child.events if e.type == "sign_in.failed")


def session_principal(created: CreatedSession) -> Principal:
    """Return the session principal C3's resolver would build for a session."""
    extra = created.session.model_extra or {}
    organization_id = extra.get("active_organization_id")
    return Principal(
        via="session",
        credential_id=created.session.id,
        user_id=created.session.user_id,
        organization_id=organization_id if isinstance(organization_id, str) else None,
    )


class _ApiCaller(Generic[OutputT]):
    def __init__(self, api: FakeApi, endpoint_id: str) -> None:
        self._api = api
        self._endpoint_id = endpoint_id

    @overload
    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: Literal[False] = False,
        ctx: EndpointContext | None = None,
    ) -> Awaitable[OutputT]: ...

    @overload
    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: Literal[True],
        ctx: EndpointContext | None = None,
    ) -> Awaitable[AuthResponse]: ...

    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: bool = False,
        ctx: EndpointContext | None = None,
    ) -> Awaitable[Any]:
        return self._api.call(
            self._endpoint_id,
            body,
            headers=headers,
            query=query,
            path_params=path_params,
            as_response=as_response,
            ctx=ctx,
        )


class FakeApi:
    """``auth.api`` over the endpoints of the plugins given to :func:`make_context`.

    The typed core members work once a plugin provides that endpoint id; otherwise they
    raise NOT_FOUND, as the real ``auth.api`` would for a missing endpoint.
    """

    def __init__(self, auth: FakeAuth) -> None:
        self._auth = auth
        self.sign_up_email: ApiMethod[SignInOut | StatusOut] = _ApiCaller(
            self, "sign_up_email"
        )
        self.sign_in_email: ApiMethod[SignInOut | ChallengeOut] = _ApiCaller(
            self, "sign_in_email"
        )
        self.sign_out: ApiMethod[StatusOut] = _ApiCaller(self, "sign_out")
        self.send_verification_email: ApiMethod[StatusOut] = _ApiCaller(
            self, "send_verification_email"
        )
        self.verify_email: ApiMethod[StatusOut | AuthResponse] = _ApiCaller(
            self, "verify_email"
        )
        self.request_password_reset: ApiMethod[StatusOut] = _ApiCaller(
            self, "request_password_reset"
        )
        self.reset_password: ApiMethod[StatusOut] = _ApiCaller(self, "reset_password")
        self.change_password: ApiMethod[StatusOut] = _ApiCaller(self, "change_password")
        self.change_email: ApiMethod[StatusOut] = _ApiCaller(self, "change_email")
        self.update_user: ApiMethod[UserOut] = _ApiCaller(self, "update_user")
        self.delete_user: ApiMethod[StatusOut] = _ApiCaller(self, "delete_user")
        self.get_session: ApiMethod[SessionWithUserOut | None] = _ApiCaller(
            self, "get_session"
        )
        self.list_sessions: ApiMethod[SessionListOut] = _ApiCaller(
            self, "list_sessions"
        )
        self.revoke_session: ApiMethod[StatusOut] = _ApiCaller(self, "revoke_session")
        self.revoke_other_sessions: ApiMethod[StatusOut] = _ApiCaller(
            self, "revoke_other_sessions"
        )
        self.sign_in_social: ApiMethod[RedirectOut] = _ApiCaller(self, "sign_in_social")
        self.social_callback: ApiMethod[AuthResponse] = _ApiCaller(
            self, "social_callback"
        )
        self.social_callback_post: ApiMethod[AuthResponse] = _ApiCaller(
            self, "social_callback_post"
        )
        self.link_social: ApiMethod[RedirectOut] = _ApiCaller(self, "link_social")
        self.list_accounts: ApiMethod[AccountListOut] = _ApiCaller(
            self, "list_accounts"
        )
        self.unlink_account: ApiMethod[StatusOut] = _ApiCaller(self, "unlink_account")

    async def call(
        self,
        endpoint_id: str,
        body: BaseModel | Mapping[str, Any] | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: bool = False,
        ctx: EndpointContext | None = None,
    ) -> Any:
        """Call any plugin endpoint by id, ``server_only`` ones included.

        With ``ctx`` the call joins that context's transaction and principal, as in
        CONTRACTS 12.5. Origin checks and rate limits are skipped, as for server calls.
        """
        endpoint = self._auth.endpoint(endpoint_id)
        if ctx is None:
            caller = self._auth.context(
                request=make_request(self._auth.config, headers=headers, query=query),
                path_params=path_params,
            )
        elif isinstance(ctx, FakeContext):
            caller = ctx
            if path_params is not None:
                caller = ctx.derive(adapter=ctx.adapter, principal=ctx.principal)
                caller.path_params = dict(path_params)
        else:
            msg = "the testing auth.api only accepts contexts from make_context()"
            raise TypeError(msg)
        try:
            result, child = await run_endpoint(endpoint, body, caller)
        except Exception:
            # Failure events such as sign_in.failed survive a rollback (section 14).
            if caller is not ctx and isinstance(ctx, FakeContext):
                ctx.absorb(caller, committed=False)
            raise
        if caller is not ctx and isinstance(ctx, FakeContext):
            ctx.absorb(caller, committed=True)
        if not as_response:
            return result
        if isinstance(result, AuthResponse):
            return result
        payload: BaseModel | Mapping[str, Any] | None = (
            result
            if isinstance(result, BaseModel)
            else cast("Mapping[str, Any]", result)
            if isinstance(result, Mapping)
            else None
        )
        return AuthResponse(
            body=payload, headers=dict(child.headers), cookies=list(child.cookies)
        )


class FakeAuth:
    """A stand-in for ``GotAuth`` (C1) as endpoints see it (``ctx.auth``).

    Records ``sign_ins`` (every ``complete_sign_in`` call), ``deleted_users`` and
    ``finished_challenges``. ``handle``, ``asgi``, ``well_known``, ``get_principal`` and
    ``fastapi`` need the real pipeline and raise ``NotImplementedError``: use
    :func:`gotauth.testing.make_auth` for HTTP round trips once C1 has merged.
    """

    def __init__(
        self,
        *,
        config: ResolvedConfig,
        plugins: Sequence[Plugin],
        providers: Mapping[str, OAuthProvider],
        adapter: Adapter,
        clock: FakeClock,
        ids: IdGenerator,
        crypto: CryptoKit,
        sessions: SessionService,
        email: EmailService,
        mailer: FakeMailer,
        database_hooks: DatabaseHooks | None = None,
        http: httpx.AsyncClient | None = None,
        secondary_storage: SecondaryStorage | None = None,
    ) -> None:
        self.config = config
        self.secondary_storage = secondary_storage
        self.plugins: tuple[Plugin, ...] = tuple(plugins)
        self.providers: Mapping[str, OAuthProvider] = dict(providers)
        self.plugin_ids: frozenset[str] = frozenset(
            plugin.id for plugin in self.plugins
        )
        self.schema: Schema = merge_schemas(
            CORE_SCHEMA, *(plugin.schema for plugin in self.plugins)
        )
        self.adapter = adapter
        self.clock = clock
        self.ids = ids
        self.crypto = crypto
        self.sessions = sessions
        self.email = email
        self.mailer = mailer
        self.database_hooks = database_hooks
        self.api = FakeApi(self)
        self.sign_ins: list[SignInCall] = []
        self.deleted_users: list[str] = []
        self.finished_challenges: list[str] = []
        self._http = http
        self._tasks: set[asyncio.Task[None]] = set()
        self._endpoints = self._collect_endpoints()

    def __repr__(self) -> str:
        return f"FakeAuth(plugins={sorted(self.plugin_ids)})"

    def _collect_endpoints(self) -> dict[str, Endpoint[Any, Any]]:
        endpoints: dict[str, Endpoint[Any, Any]] = {}
        routes: set[tuple[str, str]] = set()
        for plugin in self.plugins:
            for endpoint in (*plugin.endpoints, *plugin.well_known_endpoints):
                if endpoint.id in endpoints:
                    msg = (
                        f"duplicate endpoint id {endpoint.id!r} (plugin {plugin.id!r})"
                    )
                    raise ConfigError(msg)
                route = (endpoint.method, endpoint.path)
                if route in routes:
                    msg = f"duplicate route {endpoint.method} {endpoint.path}"
                    raise ConfigError(msg)
                endpoints[endpoint.id] = endpoint
                routes.add(route)
        return endpoints

    # ------------------------------------------------------------- lookups

    def endpoint(self, endpoint_id: str) -> Endpoint[Any, Any]:
        """Return a plugin endpoint by id, or raise NOT_FOUND."""
        endpoint = self._endpoints.get(endpoint_id)
        if endpoint is None:
            raise AuthError("NOT_FOUND", 404, f"No endpoint {endpoint_id!r}")
        return endpoint

    def cookie_name(self, base: str) -> str:
        """Return the configured full name of a cookie base name."""
        return cookie_name(
            base,
            base_url=self.config.base_url,
            prefix=self.config.advanced.cookie_prefix,
        )

    def context(
        self,
        *,
        request: AuthRequest | None = None,
        principal: Principal | None = None,
        path_params: Mapping[str, str] | None = None,
    ) -> FakeContext:
        """Return a new context on this fake (root adapter, fresh records)."""
        return FakeContext(
            auth=self,
            request=request if request is not None else make_request(self.config),
            adapter=self.adapter,
            principal=principal,
            path_params=path_params,
        )

    def model_hooks(self, model: str) -> Iterator[ModelHooks]:
        """Yield the hooks of ``model``: plugin hooks in plugin order, then config."""
        for plugin in self.plugins:
            if plugin.database_hooks is not None:
                hooks = plugin.database_hooks.hooks.get(model)
                if hooks is not None:
                    yield hooks
        if self.database_hooks is not None:
            hooks = self.database_hooks.hooks.get(model)
            if hooks is not None:
                yield hooks

    def resolvers(self) -> list[PrincipalResolver]:
        """Return the principal resolvers of every plugin."""
        return [r for plugin in self.plugins for r in plugin.principal_resolvers]

    @property
    def http(self) -> httpx.AsyncClient:
        """A shared HTTP client (10s timeout), created on first use."""
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=10)
        return self._http

    @property
    def fastapi(self) -> Any:  # Any: matches GotAuthInstance.fastapi
        """Not available on the fake."""
        msg = "TODO(C1): the FastAPI integration needs make_auth() and work package A1"
        raise NotImplementedError(msg)

    # ------------------------------------------------------------- sign-in

    async def complete_sign_in(
        self,
        ctx: EndpointContext,
        user: User,
        *,
        method: SignInMethod,
        remember_me: bool = True,
    ) -> SignInOut | ChallengeOut:
        """Run every interceptor, then set the challenge cookie or create a session.

        Every interceptor runs, so a later one can still block a sign-in that an earlier
        one challenged. The first challenge wins.
        """
        self.sign_ins.append(
            SignInCall(user_id=user.id, method=method, remember_me=remember_me)
        )
        challenge: SignInChallenge | None = None
        for plugin in self.plugins:
            for interceptor in plugin.sign_in_interceptors:
                result = await interceptor(ctx, user, method)
                if challenge is None:
                    challenge = result
        if challenge is not None:
            self._set_challenge(ctx, user.id, challenge, method, remember_me)
            return ChallengeOut(challenge=challenge)
        created = await ctx.sessions.create(ctx, user.id, remember_me=remember_me)
        await ctx.emit("sign_in.succeeded", user_id=user.id, method=method)
        token = created.token if self.config.sessions.expose_token else None
        return SignInOut(user=user, session=created.session, token=token)

    def _set_challenge(
        self,
        ctx: EndpointContext,
        user_id: str,
        challenge: SignInChallenge,
        method: SignInMethod,
        remember_me: bool,
    ) -> None:
        payload = {
            "user_id": user_id,
            "type": challenge.type,
            "methods": list(challenge.methods),
            "method": method,
            "remember_me": remember_me,
            "exp": int((ctx.clock.now() + CHALLENGE_TTL).timestamp()),
        }
        encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        ctx.set_cookie(
            SetCookie(
                name=self.cookie_name("challenge"),
                value=ctx.crypto.sign(encoded, purpose="challenge"),
                max_age=int(CHALLENGE_TTL.total_seconds()),
                secure=secure_cookies(self.config.base_url),
            )
        )

    def read_challenge(self, ctx: EndpointContext) -> ChallengeState | None:
        """Return the verified challenge cookie (expired included), or ``None``."""
        signed = ctx.request.cookies.get(self.cookie_name("challenge"))
        if not signed:
            return None
        encoded = ctx.crypto.unsign(signed, purpose="challenge")
        if encoded is None:
            return None
        try:
            raw = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
            payload = json.loads(raw)
            return ChallengeState(
                user_id=str(payload["user_id"]),
                type=str(payload["type"]),
                methods=tuple(str(item) for item in payload["methods"]),
                method=payload["method"],
                remember_me=bool(payload["remember_me"]),
                exp=datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
            )
        except (ValueError, KeyError, TypeError):
            return None

    async def finish_challenge(
        self, ctx: EndpointContext, *, satisfied: str
    ) -> SignInOut:
        """Finish the pending challenge with the factor ``satisfied``.

        Raises:
            AuthError: TOKEN_INVALID (missing or tampered cookie, unknown user),
                TOKEN_EXPIRED, or FORBIDDEN when ``satisfied`` is not allowed.
        """
        state = self.read_challenge(ctx)
        if state is None:
            raise AuthError("TOKEN_INVALID", 400)
        if ctx.clock.now() >= state.exp:
            raise AuthError("TOKEN_EXPIRED", 400)
        if satisfied not in state.methods:
            raise AuthError("FORBIDDEN", 403)
        row = await ctx.adapter.find_one("user", [Where("id", state.user_id)])
        if row is None:
            raise AuthError("TOKEN_INVALID", 400)
        user = User.model_validate(returned_only(self.schema["user"], row))
        created = await ctx.sessions.create(ctx, user.id, remember_me=state.remember_me)
        ctx.set_cookie(
            SetCookie(
                name=self.cookie_name("challenge"),
                value="",
                max_age=0,
                secure=secure_cookies(self.config.base_url),
            )
        )
        self.finished_challenges.append(satisfied)
        await ctx.emit("sign_in.succeeded", user_id=user.id, method=state.method)
        token = created.token if self.config.sessions.expose_token else None
        return SignInOut(user=user, session=created.session, token=token)

    # ------------------------------------------------------------- users

    async def create_user_record(
        self, ctx: EndpointContext | None, data: Mapping[str, Any]
    ) -> User:
        """Create a user: lower-cased email, user create hooks, ``user.created``."""
        if ctx is not None:
            return await self._create_user(ctx, ctx.adapter, data)
        async with self.adapter.transaction() as adapter:
            return await self._create_user(None, adapter, data)

    async def _create_user(
        self, ctx: EndpointContext | None, adapter: Adapter, data: Mapping[str, Any]
    ) -> User:
        values = dict(data)
        email = values.get("email")
        if isinstance(email, str):
            values["email"] = email.strip().lower()
        now = self.clock.now()
        values.setdefault("id", self.ids.new("usr"))
        values.setdefault("created_at", now)
        values.setdefault("updated_at", now)
        for hooks in self.model_hooks("user"):
            if hooks.before_create is not None:
                changed = await hooks.before_create(ctx, values)
                if changed is not None:
                    values = changed
        row = await adapter.create("user", values)
        for hooks in self.model_hooks("user"):
            if hooks.after_create is not None:
                await hooks.after_create(ctx, dict(row))
        user = User.model_validate(returned_only(self.schema["user"], row))
        if ctx is not None:
            await ctx.emit("user.created", user_id=user.id)
        return user

    async def delete_user(self, ctx: EndpointContext | None, user_id: str) -> None:
        """Delete a user: user delete hooks, cascade, ``user.deleted``."""
        if ctx is not None:
            await self._delete_user(ctx, ctx.adapter, user_id)
            return
        async with self.adapter.transaction() as adapter:
            await self._delete_user(None, adapter, user_id)

    async def _delete_user(
        self, ctx: EndpointContext | None, adapter: Adapter, user_id: str
    ) -> None:
        row = await adapter.find_one("user", [Where("id", user_id)])
        if row is None:
            raise AuthError("NOT_FOUND", 404)
        for hooks in self.model_hooks("user"):
            if hooks.before_delete is not None:
                await hooks.before_delete(ctx, dict(row))
        await adapter.delete("user", [Where("id", user_id)])
        for hooks in self.model_hooks("user"):
            if hooks.after_delete is not None:
                await hooks.after_delete(ctx, dict(row))
        self.deleted_users.append(user_id)
        if ctx is not None:
            await ctx.emit("user.deleted", user_id=user_id)

    # ------------------------------------------------------------- tasks

    def background(self, coro: Awaitable[None]) -> None:
        """Run ``coro`` as a tracked task; its errors are logged, never raised."""
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.error("background task failed", exc_info=task.exception())

    async def drain(self) -> None:
        """Wait for background tasks, then for the email service."""
        while self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        await self.email.drain()

    # ------------------------------------------------------------- C1 only

    async def handle(self, request: AuthRequest) -> AuthResponse:
        """Not available on the fake."""
        msg = "TODO(C1): handle() needs the real pipeline; use make_auth() after C1"
        raise NotImplementedError(msg)

    def asgi(self) -> ASGIApp:
        """Not available on the fake."""
        msg = "TODO(C1): asgi() needs the real pipeline; use make_auth() after C1"
        raise NotImplementedError(msg)

    def well_known(self) -> ASGIApp:
        """Not available on the fake."""
        msg = "TODO(C1): well_known() needs the real pipeline; use make_auth() after C1"
        raise NotImplementedError(msg)

    async def get_principal(
        self, headers: Mapping[str, str], cookies: Mapping[str, str]
    ) -> Principal | None:
        """Resolve a principal from headers and cookies, like :func:`call_endpoint`."""
        request = make_request(self.config, headers=headers, cookies=cookies)
        ctx = self.context(request=request)
        principal = await resolve_principal(ctx)
        if principal is not None:
            await run_principal_checks(ctx, principal)
        return principal


# ----------------------------------------------------------------- pipeline


def validate_input(endpoint: Endpoint[Any, Any], body: object) -> Any:
    """Validate ``body`` against ``endpoint.input`` like C1.

    Raises:
        AuthError: INVALID_REQUEST whose ``details.errors`` hold ``loc``, ``type`` and
            ``msg`` of each problem, never the submitted values.
    """
    if endpoint.input is None:
        return None
    if isinstance(body, BaseModel):
        raw: object = body.model_dump(exclude_unset=True)
    elif body is None:
        raw = {}
    else:
        raw = body
    try:
        return endpoint.input.model_validate(raw)
    except ValidationError as exc:
        errors = [
            {"loc": list(error["loc"]), "type": error["type"], "msg": error["msg"]}
            for error in exc.errors(
                include_url=False, include_input=False, include_context=False
            )
        ]
        # "from None": the ValidationError text contains the submitted values.
        raise AuthError("INVALID_REQUEST", 400, details={"errors": errors}) from None


async def resolve_principal(ctx: FakeContext) -> Principal | None:
    """Resolve the request's principal like C1: bearer or ``x-api-key``, then cookie.

    The longest matching resolver prefix wins. ``gas_`` bearer tokens go to the session
    service unless a plugin resolver owns the prefix. An unknown prefix, or a resolver
    returning ``None``, is UNAUTHENTICATED; other resolver errors are INTERNAL_ERROR.
    """
    headers = ctx.request.headers
    authorization = headers.get("authorization", "")
    credential: str | None = None
    if authorization[:7].lower() == "bearer ":
        credential = authorization[7:].strip()
    elif headers.get("x-api-key"):
        credential = headers["x-api-key"].strip()
    if credential:
        return await _resolve_credential(ctx, credential)
    token = ctx.request.cookies.get(ctx.auth.cookie_name("session_token"))
    if token:
        found = await ctx.sessions.get(ctx, token)
        if found is not None:
            return session_principal(CreatedSession(session=found.session, token=token))
    return None


async def _resolve_credential(ctx: FakeContext, credential: str) -> Principal:
    best: PrincipalResolver | None = None
    best_length = -1
    for resolver in ctx.auth.resolvers():
        for prefix in resolver.prefixes:
            if credential.startswith(prefix) and len(prefix) > best_length:
                best, best_length = resolver, len(prefix)
    session_prefix = TOKEN_PREFIXES["session_token"]
    try:
        if best is not None:
            principal = await best(ctx, credential)
        elif (
            credential.startswith(session_prefix)
            and ctx.auth.config.sessions.allow_bearer
        ):
            found = await ctx.sessions.get(ctx, credential)
            principal = (
                session_principal(
                    CreatedSession(session=found.session, token=credential)
                )
                if found is not None
                else None
            )
        else:
            principal = None
    except AuthError:
        raise
    except Exception as exc:
        # Fail closed: an unexpected resolver error never yields a principal.
        raise AuthError("INTERNAL_ERROR", 500) from exc
    if principal is None:
        raise AuthError("UNAUTHENTICATED", 401)
    return principal


async def run_principal_checks(ctx: FakeContext, principal: Principal) -> None:
    """Run every plugin's ``principal_checks``; unexpected errors are INTERNAL_ERROR."""
    for plugin in ctx.auth.plugins:
        for check in plugin.principal_checks:
            try:
                await check(ctx, principal)
            except AuthError:
                raise
            except Exception as exc:
                raise AuthError("INTERNAL_ERROR", 500) from exc


async def _check_access(
    endpoint: Endpoint[Any, Any], principal: Principal | None, ctx: FakeContext
) -> None:
    if endpoint.auth == "session" and (principal is None or principal.via != "session"):
        raise AuthError("UNAUTHENTICATED", 401)
    if endpoint.auth == "principal" and principal is None:
        raise AuthError("UNAUTHENTICATED", 401)
    if (
        endpoint.scopes
        and principal is not None
        and not principal.has_scopes(*endpoint.scopes)
    ):
        raise AuthError(
            "INSUFFICIENT_SCOPE", 403, details={"required": list(endpoint.scopes)}
        )
    if endpoint.fresh_session:
        if principal is None or principal.via != "session":
            raise AuthError("FRESH_SESSION_REQUIRED", 403)
        row = await ctx.adapter.find_one(
            "session", [Where("id", principal.credential_id)]
        )
        fresh_age = ctx.auth.config.sessions.fresh_age
        if row is None or ctx.clock.now() - row["created_at"] >= to_timedelta(
            fresh_age
        ):
            raise AuthError("FRESH_SESSION_REQUIRED", 403)


async def run_endpoint(
    endpoint: Endpoint[Any, Any], body: object, ctx: FakeContext
) -> tuple[Any, FakeContext]:
    """Run one endpoint call on a fake context; return the result and the call context.

    Steps, in C1's order: validate input; resolve the principal (skipped for
    ``auth="none"``) and run principal checks; enforce ``auth``, ``scopes`` and
    ``fresh_session``; run the handler in a transaction on a child context. On
    commit the child's cookies, headers and events move to ``ctx``; on error only
    ``sign_in.failed``
    events do.
    """
    data = validate_input(endpoint, body)
    principal: Principal | None = None
    if endpoint.auth != "none":
        principal = ctx.principal
        if principal is None:
            principal = await resolve_principal(ctx)
        if principal is not None:
            await run_principal_checks(ctx, principal)
    await _check_access(endpoint, principal, ctx)
    child: FakeContext | None = None
    try:
        async with ctx.adapter.transaction() as adapter:
            child = ctx.derive(adapter=adapter, principal=principal)
            result = await endpoint.handler(child, data)
    except BaseException:
        if child is not None:
            ctx.absorb(child, committed=False)
        raise
    ctx.absorb(child, committed=True)
    return result, child


async def call_endpoint(
    endpoint: Endpoint[Any, Any],
    body: Mapping[str, Any] | None = None,
    *,
    ctx: EndpointContext | None = None,
) -> Any:  # Any: the output of whichever endpoint runs
    """Validate the input like C1, enforce ``auth`` and ``scopes``, run the handler.

    Args:
        endpoint: The endpoint under test.
        body: The input, as the parsed JSON, form or query would be.
        ctx: A context from :func:`make_context`; a new one when omitted. Records
            (cookies, headers, events) land on it.

    Returns:
        Whatever the handler returns: the output model or an ``AuthResponse``.

    Raises:
        AuthError: INVALID_REQUEST, UNAUTHENTICATED, INSUFFICIENT_SCOPE,
            FRESH_SESSION_REQUIRED, or whatever the handler raises (its writes are then
            rolled back).
    """
    context = ctx if ctx is not None else make_context()
    if not isinstance(context, FakeContext):
        msg = "call_endpoint() needs a context from make_context()"
        raise TypeError(msg)
    result, _ = await run_endpoint(endpoint, body, context)
    return result


def make_context(
    *,
    plugins: Sequence[Plugin] = (),
    adapter: Adapter | None = None,
    clock: FakeClock | None = None,
    ids: IdGenerator | None = None,
    crypto: CryptoKit | None = None,
    sessions: SessionService | None = None,
    email: EmailService | None = None,
    mailer: FakeMailer | None = None,
    principal: Principal | None = None,
    request: AuthRequest | None = None,
    path_params: Mapping[str, str] | None = None,
    providers: Sequence[OAuthProvider] = (),
    database_hooks: DatabaseHooks | None = None,
    http: httpx.AsyncClient | None = None,
    secondary_storage: SecondaryStorage | None = None,
    config: ResolvedConfig | None = None,
    secret: str | Sequence[str] = TEST_SECRET,
    base_url: str = TEST_BASE_URL,
    base_path: str = "/api/auth",
    trusted_origins: Sequence[str] = (),
    session_config: SessionConfig | Mapping[str, Any] | None = None,
    advanced: AdvancedConfig | Mapping[str, Any] | None = None,
) -> FakeContext:
    """Return an ``EndpointContext`` with fakes for every service.

    The memory adapter is bound to ``CORE_SCHEMA`` merged with the ``plugins`` schemas.
    ``ctx.auth`` is a :class:`FakeAuth`: ``complete_sign_in`` (runs the plugins'
    interceptors), ``read_challenge``, ``finish_challenge``, ``create_user_record``,
    ``delete_user`` (runs ``database_hooks``), ``background`` and ``api.call`` over the
    plugins' endpoints.

    Every argument is optional; pass one to replace that piece, e.g.
    ``make_context(principal=..., request=..., adapter=...)``. ``config`` replaces the
    whole configuration; otherwise ``secret``, ``base_url``, ``base_path``,
    ``trusted_origins``, ``session_config`` and ``advanced`` build it.

    Raises:
        ConfigError: Two plugins define the same endpoint id or route.
        SchemaConflictError: Two schemas define the same field.
    """
    if config is None:
        config = ResolvedConfig(
            secret=tuple(
                SecretStr(value)
                for value in ((secret,) if isinstance(secret, str) else secret)
            ),
            base_url=base_url,
            base_path=base_path,
            trusted_origins=tuple(trusted_origins),
            sessions=SessionConfig.model_validate(session_config or {}),
            advanced=AdvancedConfig.model_validate(advanced or {}),
        )
    the_clock = clock if clock is not None else fake_clock()
    the_mailer = mailer if mailer is not None else fake_mailer()
    the_crypto = (
        crypto
        if crypto is not None
        else crypto_kit(
            tuple(value.get_secret_value() for value in config.secret),
            password_algorithm=config.advanced.password_algorithm,
        )
    )
    the_email: EmailService = (
        email
        if email is not None
        else PassThroughEmailService(
            the_mailer,
            app_name=config.email.app_name,
            from_address=config.email.from_address,
        )
    )
    the_adapter = adapter if adapter is not None else memory_adapter()
    auth = FakeAuth(
        config=config,
        plugins=plugins,
        providers={provider.id: provider for provider in providers},
        adapter=the_adapter,
        clock=the_clock,
        ids=ids if ids is not None else seq_ids(),
        crypto=the_crypto,
        sessions=sessions if sessions is not None else fake_sessions(),
        email=the_email,
        mailer=the_mailer,
        database_hooks=database_hooks,
        http=http,
        secondary_storage=secondary_storage,
    )
    the_adapter.bind_schema(auth.schema, table_prefix=config.advanced.table_prefix)
    return auth.context(
        request=request if request is not None else make_request(config),
        principal=principal,
        path_params=path_params,
    )
