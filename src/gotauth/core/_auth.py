"""The ``GotAuth`` class: assembly, request pipeline and core services (C1)."""

from __future__ import annotations

import asyncio
import base64
import importlib
import json
import logging
import re
from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, TypeVar, cast
from urllib.parse import quote, urlsplit

import httpx
from pydantic import BaseModel

from gotauth.contracts.adapter import Adapter, Where
from gotauth.contracts.config import (
    AccountLinkingConfig,
    AdvancedConfig,
    DatabaseHooks,
    EmailPasswordConfig,
    ModelHooks,
    ResolvedConfig,
)
from gotauth.contracts.core_schema import CORE_SCHEMA, Session, User
from gotauth.contracts.email import EmailConfig, EmailMessage, EmailSender, EmailService
from gotauth.contracts.endpoints import (
    CHALLENGE_TTL,
    ChallengeState,
    Endpoint,
    EndpointContext,
    Hook,
    HookPayload,
    Plugin,
    PrincipalResolver,
    SignInChallenge,
    SignInMethod,
)
from gotauth.contracts.errors import ERROR_CODES, AuthError, ConfigError
from gotauth.contracts.events import AuthEvent
from gotauth.contracts.http import ASGIApp, AuthRequest, AuthResponse, SetCookie
from gotauth.contracts.http_models import ChallengeOut, SignInOut
from gotauth.contracts.primitives import (
    Clock,
    IdGenerator,
    SystemClock,
    UlidIds,
    to_timedelta,
)
from gotauth.contracts.principal import Principal
from gotauth.contracts.protection import (
    RateLimitConfig,
    is_trusted_origin,
    normalize_origin,
)
from gotauth.contracts.schema import Schema, merge_schemas, returned_only
from gotauth.contracts.sessions import (
    TOKEN_PREFIXES,
    SecondaryStorage,
    SessionConfig,
    SessionService,
    cookie_name,
    is_localhost,
    secure_cookies,
)
from gotauth.contracts.social import OAuthProvider
from gotauth.core._api import Api
from gotauth.core._context import HookedAdapter, RequestContext, unwrap
from gotauth.core._http import (
    check_content_type,
    error_response,
    input_format,
    parse_body,
    validate,
)
from gotauth.core._ratelimit import EARLY_KEYS, LATE_KEYS, RATE_LIMIT_MODEL, RateLimiter
from gotauth.crypto import crypto_kit

__all__ = ["GotAuth"]

logger = logging.getLogger("gotauth")

_UNSAFE = frozenset({"POST", "PATCH", "DELETE", "PUT"})
_PARAM = re.compile(r"\{([a-z_][a-z0-9_]*)\}")


@dataclass(frozen=True)
class _Route:
    endpoint: Endpoint[Any, Any]
    pattern: re.Pattern[str] | None  # None: exact path


def _compile(path: str) -> re.Pattern[str] | None:
    if "{" not in path:
        return None
    parts = _PARAM.split(path)
    regex = ""
    for index, part in enumerate(parts):
        regex += f"(?P<{part}>[^/]+)" if index % 2 else re.escape(part)
    return re.compile(regex)


_ModelT = TypeVar("_ModelT", bound=BaseModel)


def _model_config(model: type[_ModelT], value: object) -> _ModelT:
    if value is None:
        return model()
    if isinstance(value, model):
        return value
    return model.model_validate(value)


def _session_principal(session: Session) -> Principal:
    extra = session.model_extra or {}
    organization_id = extra.get("active_organization_id")
    return Principal(
        via="session",
        credential_id=session.id,
        user_id=session.user_id,
        organization_id=organization_id if isinstance(organization_id, str) else None,
    )


class _ConsoleSender:
    """Development sender: logs the message, links included (localhost only)."""

    async def send(self, message: EmailMessage) -> None:
        logger.info("email to %s: %s\n%s", message.to, message.subject, message.text)


class _BasicEmailService:
    """Used until the email module (D1) is installed: plain text, no templates."""

    def __init__(self, sender: EmailSender | None, config: EmailConfig) -> None:
        self._sender = sender
        self._config = config

    async def send(
        self, kind: Any, to: str, **data: Any
    ) -> None:  # Any: EmailKind, data
        if self._sender is None:
            # Never log links or codes outside localhost; fail loudly instead.
            raise ConfigError("no email sender is configured (set email_sender)")
        lines = [f"{key}: {value}" for key, value in data.items()]
        await self._sender.send(
            EmailMessage(
                kind=kind,
                to=to,
                subject=f"{self._config.app_name}: {str(kind).replace('_', ' ')}",
                text="\n".join(lines),
                from_address=self._config.from_address,
                data=data,
            )
        )

    async def drain(self) -> None:
        """Nothing is sent in the background."""


# Seconds a background deferred job waits before it starts (see _run_deferred).
_DEFER_DELAY = 0.05


class GotAuth:
    """Auth for Python AI backends (CONTRACTS 13).

    Build one per app and mount :meth:`asgi` at ``base_path``::

        auth = GotAuth(database=memory_adapter(), secret=SECRET, base_url=URL)
    """

    def __init__(
        self,
        *,
        database: Adapter,
        secret: str | Sequence[str],
        base_url: str,
        base_path: str = "/api/auth",
        trusted_origins: Sequence[str] = (),
        email_password: EmailPasswordConfig | Mapping[str, Any] | None = None,
        social_providers: Sequence[OAuthProvider] = (),
        account_linking: AccountLinkingConfig | Mapping[str, Any] | None = None,
        sessions: SessionConfig | Mapping[str, Any] | None = None,
        rate_limit: RateLimitConfig | Mapping[str, Any] | bool | None = None,
        email: EmailConfig | Mapping[str, Any] | None = None,
        email_sender: EmailSender | None = None,
        secondary_storage: SecondaryStorage | None = None,
        plugins: Sequence[Plugin] = (),
        hooks: Sequence[Hook] = (),
        database_hooks: DatabaseHooks | None = None,
        on_event: Callable[[AuthEvent], Awaitable[None]] | None = None,
        advanced: AdvancedConfig | Mapping[str, Any] | None = None,
    ) -> None:
        """Validate the configuration and assemble core and plugins.

        Raises:
            ConfigError: For an invalid setting, a missing email sender, or two
                plugins that define the same endpoint, path or error code.
            SchemaConflictError: For two schemas that define the same field.
        """
        secrets_list = (secret,) if isinstance(secret, str) else tuple(secret)
        if isinstance(rate_limit, bool):
            rate_limit = {"enabled": rate_limit}
        self._config = ResolvedConfig(
            secret=secrets_list,  # pyright: ignore[reportArgumentType]  # validator wraps
            base_url=base_url.rstrip("/"),
            base_path=base_path,
            trusted_origins=tuple(trusted_origins),
            email_password=_model_config(EmailPasswordConfig, email_password),
            account_linking=_model_config(AccountLinkingConfig, account_linking),
            sessions=_model_config(SessionConfig, sessions),
            rate_limit=_model_config(RateLimitConfig, rate_limit),
            email=_model_config(EmailConfig, email),
            advanced=_model_config(AdvancedConfig, advanced),
        )
        config = self._config
        self._check_urls(config)
        advanced_config = config.advanced

        # Services
        self.crypto = advanced_config.crypto or crypto_kit(
            [value.get_secret_value() for value in config.secret],
            password_algorithm=advanced_config.password_algorithm,
        )
        self.clock: Clock = advanced_config.clock or SystemClock()
        self.ids: IdGenerator = advanced_config.ids or UlidIds(
            self.crypto, clock=self.clock
        )
        self._database = database
        self._secondary = secondary_storage
        self._on_event = on_event
        self._hooks = tuple(hooks)
        self._database_hooks = database_hooks
        self._providers = {provider.id: provider for provider in social_providers}

        # Plugins: the core ones first, then the user's.
        core = self._core_plugins(config, social_providers)
        self._core_plugin_ids = frozenset(plugin.id for plugin in core)
        self._plugins: tuple[Plugin, ...] = (*core, *plugins)
        ids = [plugin.id for plugin in self._plugins]
        if len(set(ids)) != len(ids):
            raise ConfigError(f"two plugins share an id: {ids}")
        self._check_email(config, email_sender)

        # Schema
        schemas = [plugin.schema for plugin in self._plugins]
        if config.rate_limit.storage == "database":
            schemas.append({"rate_limit": RATE_LIMIT_MODEL})
        self._schema: Schema = merge_schemas(CORE_SCHEMA, *schemas)
        database.bind_schema(self._schema, table_prefix=advanced_config.table_prefix)

        # Endpoints, routes and error codes
        self._endpoints: dict[str, Endpoint[Any, Any]] = {}
        self._routes: dict[str, list[_Route]] = {}
        self._well_known: dict[str, list[_Route]] = {}
        for plugin in self._plugins:
            for endpoint in plugin.endpoints:
                self._register(endpoint, self._routes, endpoint.path)
            for endpoint in plugin.well_known_endpoints:
                path = endpoint.path.replace(
                    "{base_path}", config.base_path.rstrip("/")
                )
                self._register(endpoint, self._well_known, path)
        self._error_codes = self._collect_error_codes()

        self._sessions: SessionService | None = advanced_config.session_service or (
            self._load_session_service(config, secondary_storage)
            if advanced_config.install_core_plugins
            else None
        )
        self._email: EmailService = advanced_config.email_service or self._load_email(
            config, email_sender
        )
        self._limiter = RateLimiter(
            enabled=config.rate_limit.enabled,
            storage=config.rate_limit.storage,
            clock=self.clock,
            ids=self.ids,
            config_rules=config.rate_limit.rules,
            plugin_rules=[
                rule for plugin in self._plugins for rule in plugin.rate_limits
            ],
            adapter=database,
            secondary=secondary_storage,
        )
        self._api = Api(self)
        self._tasks: set[asyncio.Task[None]] = set()
        self._init_lock: asyncio.Lock | None = None
        self._initialized = False
        self._http: httpx.AsyncClient | None = None
        self._fastapi: Any = None

    # ------------------------------------------------------------ assembly

    @staticmethod
    def _check_urls(config: ResolvedConfig) -> None:
        parts = urlsplit(config.base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise ConfigError("base_url must be an absolute http(s) URL")
        if parts.scheme == "http" and not is_localhost(config.base_url):
            raise ConfigError("base_url must use https outside localhost")
        if not config.base_path.startswith("/"):
            raise ConfigError("base_path must start with '/'")

    @staticmethod
    def _core_plugins(
        config: ResolvedConfig, providers: Sequence[OAuthProvider]
    ) -> list[Plugin]:
        if not config.advanced.install_core_plugins:
            return []
        plugins: list[Plugin] = []
        wanted: list[tuple[str, str, tuple[object, ...]]] = [
            ("gotauth.sessions", "sessions_plugin", ())
        ]
        if config.email_password.enabled:
            wanted.append(
                (
                    "gotauth.email_password",
                    "email_password_plugin",
                    (config.email_password,),
                )
            )
        if providers:
            wanted.append(("gotauth.social", "social_plugin", ()))
        for module_name, factory_name, args in wanted:
            factory = getattr(importlib.import_module(module_name), factory_name, None)
            if factory is None:
                msg = (
                    f"{module_name}.{factory_name} is not available; set "
                    "advanced={'install_core_plugins': False} until it exists"
                )
                raise ConfigError(msg)
            plugins.append(cast("Plugin", factory(*args)))
        return plugins

    def _check_email(self, config: ResolvedConfig, sender: EmailSender | None) -> None:
        if sender is not None or config.advanced.email_service is not None:
            return
        if is_localhost(config.base_url):
            return
        needs = [plugin.id for plugin in self._plugins if plugin.requires_email]
        if (
            config.email_password.enabled
            and config.email_password.require_email_verification
            and (config.advanced.install_core_plugins)
        ):
            needs.append("email_password")
        if needs:
            msg = (
                f"an email sender is required outside localhost for: {', '.join(needs)}"
            )
            raise ConfigError(msg)

    def _register(
        self,
        endpoint: Endpoint[Any, Any],
        table: dict[str, list[_Route]],
        path: str,
    ) -> None:
        if endpoint.id in self._endpoints:
            raise ConfigError(f"two endpoints share the id {endpoint.id!r}")
        if endpoint.method == "GET" and endpoint.input_format in ("json", "form"):
            raise ConfigError(f"GET endpoint {endpoint.id!r} cannot take a body")
        self._endpoints[endpoint.id] = endpoint
        if endpoint.server_only:
            return
        routes = table.setdefault(endpoint.method, [])
        compiled = _compile(path)
        # Two routes clash when their templates match once parameter names are ignored.
        shape = _PARAM.sub("{}", path)
        if any(_PARAM.sub("{}", route.endpoint.path) == shape for route in routes):
            raise ConfigError(f"two endpoints share {endpoint.method} {path}")
        routes.append(_Route(endpoint=_with_path(endpoint, path), pattern=compiled))

    def _collect_error_codes(self) -> dict[str, tuple[int, str]]:
        codes = dict(ERROR_CODES)
        for plugin in self._plugins:
            for code, value in plugin.error_codes.items():
                if code in codes and codes[code] != value:
                    raise ConfigError(f"error code {code!r} is defined twice")
                codes[code] = value
        return codes

    @staticmethod
    def _load_session_service(
        config: ResolvedConfig, secondary: SecondaryStorage | None
    ) -> SessionService | None:
        module = importlib.import_module("gotauth.sessions")
        factory = getattr(module, "session_service", None)
        if factory is None:
            return None
        return cast("SessionService", factory(config, secondary_storage=secondary))

    @staticmethod
    def _load_email(config: ResolvedConfig, sender: EmailSender | None) -> EmailService:
        module = importlib.import_module("gotauth.email")
        factory = getattr(module, "email_service", None)
        if factory is not None:
            return cast("EmailService", factory(config, sender))
        if sender is None and is_localhost(config.base_url):
            sender = _ConsoleSender()
        return _BasicEmailService(sender, config.email)

    # ------------------------------------------------------------ properties

    @property
    def config(self) -> ResolvedConfig:
        """Every config object with defaults applied."""
        return self._config

    @property
    def schema(self) -> Schema:
        """The merged core and plugin schema."""
        return self._schema

    @property
    def api(self) -> Api:
        """Server-side calls to every endpoint."""
        return self._api

    @property
    def providers(self) -> Mapping[str, OAuthProvider]:
        """Social providers by id."""
        return dict(self._providers)

    @property
    def plugin_ids(self) -> frozenset[str]:
        """Ids of the installed plugins, without the core plugins."""
        return frozenset(
            p.id for p in self._plugins if p.id not in self._core_plugin_ids
        )

    @property
    def plugins(self) -> tuple[Plugin, ...]:
        """Every installed plugin, core plugins first."""
        return self._plugins

    @property
    def database(self) -> Adapter:
        """The root storage adapter."""
        return self._database

    @property
    def sessions(self) -> SessionService:
        """The session service.

        Raises:
            ConfigError: When no session service is installed.
        """
        if self._sessions is None:
            msg = (
                "no session service: install the sessions module or set "
                "advanced.session_service"
            )
            raise ConfigError(msg)
        return self._sessions

    @property
    def email(self) -> EmailService:
        """The email service."""
        return self._email

    @property
    def secondary_storage(self) -> SecondaryStorage | None:
        """``GotAuth(secondary_storage=...)``, for shared counters and caches."""
        return self._secondary

    @property
    def http(self) -> httpx.AsyncClient:
        """A shared HTTP client (10 s timeout)."""
        if self._http is None:
            self._http = httpx.AsyncClient(timeout=10.0)
        return self._http

    @property
    def fastapi(self) -> Any:  # Any: the FastAPI integration object (A1)
        """The FastAPI integration (needs the ``fastapi`` extra).

        Raises:
            ConfigError: When the FastAPI integration is not available.
        """
        if self._fastapi is None:
            module = importlib.import_module("gotauth.integrations.fastapi")
            integration = getattr(module, "FastAPIIntegration", None)
            if integration is None:
                raise ConfigError("the FastAPI integration is not installed")
            self._fastapi = integration(self)
        return self._fastapi

    def cookie_name(self, base: str) -> str:
        """Return the full name of a GotAuth cookie."""
        return cookie_name(
            base,
            base_url=self._config.base_url,
            prefix=self._config.advanced.cookie_prefix,
        )

    def model_hooks(self, model: str) -> list[ModelHooks]:
        """Database hooks for a model: plugin hooks in plugin order, then config."""
        found: list[ModelHooks] = []
        for plugin in self._plugins:
            if plugin.database_hooks is not None:
                hooks = plugin.database_hooks.hooks.get(model)
                if hooks is not None:
                    found.append(hooks)
        if self._database_hooks is not None:
            hooks = self._database_hooks.hooks.get(model)
            if hooks is not None:
                found.append(hooks)
        return found

    def endpoint(self, endpoint_id: str) -> Endpoint[Any, Any]:
        """Return an endpoint by id.

        Raises:
            AuthError: NOT_FOUND.
        """
        found = self._endpoints.get(endpoint_id)
        if found is None:
            raise AuthError("NOT_FOUND", 404)
        return found

    # ------------------------------------------------------------ lifecycle

    async def _ensure_init(self) -> None:
        if self._initialized:
            return
        if self._init_lock is None:
            self._init_lock = asyncio.Lock()
        async with self._init_lock:
            if self._initialized:
                return
            for plugin in self._plugins:
                if plugin.init is not None:
                    await plugin.init(self)
            self._initialized = True

    def background(self, coro: Awaitable[None]) -> None:
        """Run ``coro`` as a tracked task; errors are logged, never raised."""
        task: asyncio.Task[None] = asyncio.ensure_future(coro)
        self._tasks.add(task)
        task.add_done_callback(self._task_done)

    def _task_done(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and task.exception() is not None:
            logger.error("background task failed", exc_info=task.exception())

    async def drain(self) -> None:
        """Wait for background tasks (events, email)."""
        while self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)
        await self._email.drain()

    async def _deliver(self, event: AuthEvent) -> None:
        if self._on_event is None:
            return
        try:
            await self._on_event(event)
        except Exception:
            logger.exception("on_event failed for %s", event.type)

    def _publish(self, events: Sequence[AuthEvent]) -> None:
        if self._on_event is None:
            return
        for event in events:
            self.background(self._deliver(event))

    # ------------------------------------------------------------ routing

    def _match(
        self, table: Mapping[str, list[_Route]], method: str, path: str
    ) -> tuple[Endpoint[Any, Any], dict[str, str]] | None:
        routes = table.get(method, [])
        for route in routes:
            if route.pattern is None and route.endpoint.path == path:
                return route.endpoint, {}
        for route in routes:
            if route.pattern is not None:
                found = route.pattern.fullmatch(path)
                if found is not None:
                    return route.endpoint, found.groupdict()
        return None

    # ------------------------------------------------------------ pipeline

    async def handle(self, request: AuthRequest) -> AuthResponse:
        """Run one HTTP request through the pipeline (CONTRACTS 5)."""
        return await self._handle(request, self._routes)

    async def handle_well_known(self, request: AuthRequest) -> AuthResponse:
        """Run one request against the host-root well-known endpoints."""
        return await self._handle(request, self._well_known)

    async def _handle(
        self, request: AuthRequest, table: Mapping[str, list[_Route]]
    ) -> AuthResponse:
        matched = self._match(table, request.method, request.path)
        if matched is None:
            return error_response(AuthError("NOT_FOUND", 404), "gotauth")
        endpoint, params = matched
        ctx = RequestContext(
            auth=self, request=request, adapter=self._database, path_params=params
        )
        try:
            await self._ensure_init()
            result = await self._run_http(ctx, endpoint)
            return self._to_response(ctx, result)
        except AuthError as error:
            return self._error(ctx, error, endpoint.error_format)
        except Exception:
            logger.exception("unexpected error in %s", endpoint.id)
            return self._error(
                ctx, AuthError("INTERNAL_ERROR", 500), endpoint.error_format
            )

    def _error(
        self, ctx: RequestContext, error: AuthError, error_format: str
    ) -> AuthResponse:
        response = error_response(error, error_format)
        # Cookies set before the failure (e.g. clearing a challenge) still apply.
        response.cookies = [*ctx.cookies, *response.cookies]
        return response

    async def _run_http(self, ctx: RequestContext, endpoint: Endpoint[Any, Any]) -> Any:
        request = ctx.request
        check_content_type(endpoint, request.headers, request.body)
        await self._limiter.check(ctx, endpoint, EARLY_KEYS)
        data = validate(endpoint, parse_body(endpoint, request.query, request.body))
        ctx.principal = await self._authenticate(ctx, endpoint)
        await self._check_access(ctx, endpoint)
        self._check_origin(request)
        await self._limiter.check(ctx, endpoint, LATE_KEYS, data)
        return await self._execute(ctx, endpoint, data, joined=False)

    def _check_origin(self, request: AuthRequest) -> None:
        if request.method not in _UNSAFE:
            return
        headers = request.headers
        if headers.get("authorization") or headers.get("x-api-key"):
            return
        prefix = self._config.advanced.cookie_prefix + "."
        if not any(
            name.startswith(prefix) or name.startswith("__Secure-" + prefix)
            for name in request.cookies
        ):
            return
        origin = headers.get("origin") or normalize_origin(headers.get("referer", ""))
        if not origin or origin == "null":
            raise AuthError("ORIGIN_NOT_ALLOWED", 403)
        normalized = normalize_origin(origin)
        if normalized is None or not is_trusted_origin(normalized, self._config):
            raise AuthError("ORIGIN_NOT_ALLOWED", 403)

    async def _authenticate(
        self, ctx: RequestContext, endpoint: Endpoint[Any, Any]
    ) -> Principal | None:
        if endpoint.auth == "none":
            return None
        principal = await self._resolve(ctx)
        if principal is not None:
            await self._run_principal_checks(ctx, principal)
        return principal

    def _resolvers(self) -> list[PrincipalResolver]:
        return [r for plugin in self._plugins for r in plugin.principal_resolvers]

    async def _resolve(self, ctx: RequestContext) -> Principal | None:
        headers = ctx.request.headers
        authorization = headers.get("authorization", "")
        credential: str | None = None
        if authorization[:7].lower() == "bearer ":
            credential = authorization[7:].strip()
        elif headers.get("x-api-key"):
            credential = headers["x-api-key"].strip()
        if credential:
            return await self._resolve_credential(ctx, credential)
        token = ctx.request.cookies.get(self.cookie_name("session_token"))
        if token and self._sessions is not None:
            try:
                found = await self._sessions.get(ctx, token)
            except AuthError:
                raise
            except Exception as exc:
                raise AuthError("INTERNAL_ERROR", 500) from exc
            if found is not None:
                return _session_principal(found.session)
        return None

    async def _resolve_credential(
        self, ctx: RequestContext, credential: str
    ) -> Principal:
        best: PrincipalResolver | None = None
        best_length = -1
        for resolver in self._resolvers():
            for prefix in resolver.prefixes:
                if credential.startswith(prefix) and len(prefix) > best_length:
                    best, best_length = resolver, len(prefix)
        try:
            if best is not None:
                principal = await best(ctx, credential)
            elif (
                credential.startswith(TOKEN_PREFIXES["session_token"])
                and self._config.sessions.allow_bearer
                and self._sessions is not None
            ):
                found = await self._sessions.get(ctx, credential)
                principal = (
                    _session_principal(found.session) if found is not None else None
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

    async def _run_principal_checks(
        self, ctx: RequestContext, principal: Principal
    ) -> None:
        for plugin in self._plugins:
            for check in plugin.principal_checks:
                try:
                    await check(ctx, principal)
                except AuthError:
                    raise
                except Exception as exc:
                    raise AuthError("INTERNAL_ERROR", 500) from exc

    async def _check_access(
        self, ctx: RequestContext, endpoint: Endpoint[Any, Any]
    ) -> None:
        principal = ctx.principal
        if endpoint.auth == "session" and (
            principal is None or principal.via != "session"
        ):
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
            row = await self._database.find_one(
                "session", [Where("id", principal.credential_id)]
            )
            fresh_age = to_timedelta(self._config.sessions.fresh_age)
            if row is None or self.clock.now() - row["created_at"] >= fresh_age:
                raise AuthError("FRESH_SESSION_REQUIRED", 403)

    def _hooks_for(self, when: str, endpoint_id: str) -> list[Hook]:
        found: list[Hook] = []
        for hook in (*(h for p in self._plugins for h in p.hooks), *self._hooks):
            if hook.when == when and (
                "*" in hook.endpoints or endpoint_id in hook.endpoints
            ):
                found.append(hook)
        return found

    async def _execute(
        self,
        ctx: RequestContext,
        endpoint: Endpoint[Any, Any],
        data: Any,
        *,
        joined: bool,
    ) -> Any:
        if joined:
            return await self._with_hooks(ctx, endpoint, data)
        first_event = len(ctx.events)
        first_deferred = len(ctx.deferred)
        try:
            async with self._database.transaction() as tx:
                ctx.adapter = HookedAdapter(tx, self, ctx)
                result = await self._with_hooks(ctx, endpoint, data)
        except BaseException:
            new = ctx.events[first_event:]
            del ctx.events[first_event:]
            del ctx.deferred[first_deferred:]  # rolled back: nothing to follow up
            # Failure events survive a rollback (CONTRACTS 14).
            self._publish([event for event in new if event.type == "sign_in.failed"])
            raise
        finally:
            ctx.adapter = self._database
        self._publish(ctx.events[first_event:])
        works = ctx.deferred[first_deferred:]
        del ctx.deferred[first_deferred:]
        if works:
            if is_localhost(self._config.base_url):
                await self._run_deferred(ctx, works)
            else:
                # After the reply, so its duration does not show (CONTRACTS 9.1).
                self.background(self._run_deferred(ctx, works, delay=_DEFER_DELAY))
        return result

    async def _run_deferred(
        self,
        ctx: RequestContext,
        works: list[Callable[[Any], Awaitable[None]]],
        *,
        delay: float = 0,
    ) -> None:
        """Run deferred work in order, each in a transaction of its own."""
        if delay:
            # Start once the reply has gone out: a job that ran while the response
            # was still being written would slow only the requests that had real
            # work to do, which is what deferring is meant to hide.
            await asyncio.sleep(delay)
        for work in works:
            first_event = len(ctx.events)
            try:
                async with self._database.transaction() as tx:
                    ctx.adapter = HookedAdapter(tx, self, ctx)
                    await work(ctx)
            except Exception as exc:
                del ctx.events[first_event:]
                # Only the type: messages can carry tokens or addresses.
                logger.warning("gotauth: deferred work failed (%s)", type(exc).__name__)
                continue
            finally:
                ctx.adapter = self._database
            self._publish(ctx.events[first_event:])

    async def _with_hooks(
        self, ctx: RequestContext, endpoint: Endpoint[Any, Any], data: Any
    ) -> Any:
        try:
            for hook in self._hooks_for("before", endpoint.id):
                replaced = await hook.run(ctx, HookPayload(endpoint.id, data, None))
                if replaced is not None:
                    return replaced
            result = await endpoint.handler(ctx, data)
            for hook in self._hooks_for("after", endpoint.id):
                replaced = await hook.run(ctx, HookPayload(endpoint.id, data, result))
                if replaced is not None:
                    result = replaced
        except AuthError:
            raise
        except Exception as exc:
            logger.exception("unexpected error in %s", endpoint.id)
            raise AuthError("INTERNAL_ERROR", 500) from exc
        return result

    def _to_response(self, ctx: RequestContext, result: Any) -> AuthResponse:
        if isinstance(result, AuthResponse):
            response = result
            response.cookies = [*ctx.cookies, *response.cookies]
            response.headers = {**ctx.headers, **response.headers}
        else:
            body: BaseModel | Mapping[str, Any] | None
            if isinstance(result, BaseModel):
                body = result
            elif isinstance(result, Mapping):
                body = cast("Mapping[str, Any]", result)
            else:
                body = None
            response = AuthResponse(
                body=body,
                headers=dict(ctx.headers),
                cookies=list(ctx.cookies),
            )
        if response.redirect is not None and response.status == 200:
            response.status = 302
        if response.html is None and response.redirect is None:
            response.headers.setdefault("cache-control", "no-store")
        return response

    # ------------------------------------------------------------ server calls

    async def server_call(
        self,
        endpoint_id: str,
        body: BaseModel | Mapping[str, Any] | None,
        *,
        headers: Mapping[str, str] | None,
        query: Mapping[str, str] | None,
        path_params: Mapping[str, str] | None,
        as_response: bool,
        ctx: EndpointContext | None,
    ) -> Any:  # Any: the endpoint's output
        """Run an endpoint from code; see :meth:`Api.call`."""
        await self._ensure_init()
        endpoint = self.endpoint(endpoint_id)
        params = dict(path_params or {})
        path = _PARAM.sub(
            lambda m: quote(params.get(m.group(1), ""), safe=""), endpoint.path
        )
        lowered = {key.lower(): value for key, value in (headers or {}).items()}
        request = AuthRequest(
            method=endpoint.method,
            path=path,
            url=self._config.base_url + self._config.base_path.rstrip("/") + path,
            query=dict(query or {}),
            headers=lowered,
            cookies=_parse_cookies(lowered.get("cookie", "")),
            body=b"",
            client_ip=ctx.request.client_ip if ctx is not None else None,
        )
        if input_format(endpoint) == "query" and body is None:
            data = validate(endpoint, dict(query or {}))
        else:
            data = validate(endpoint, body)
        if ctx is not None:
            call_ctx = RequestContext(
                auth=self,
                request=request,
                adapter=ctx.adapter,
                principal=ctx.principal,
                path_params=params,
                events=ctx.events if isinstance(ctx, RequestContext) else None,
                cookies=ctx.cookies if isinstance(ctx, RequestContext) else None,
                headers=ctx.headers if isinstance(ctx, RequestContext) else None,
                deferred=ctx.deferred if isinstance(ctx, RequestContext) else None,
            )
            await self._check_access(call_ctx, endpoint)
            result = await self._execute(call_ctx, endpoint, data, joined=True)
            if not isinstance(ctx, RequestContext):
                for event in call_ctx.events:
                    await ctx.emit(
                        event.type, user_id=event.user_id, **dict(event.data)
                    )
                for cookie in call_ctx.cookies:
                    ctx.set_cookie(cookie)
                for work in call_ctx.deferred:
                    ctx.defer(work)
        else:
            call_ctx = RequestContext(
                auth=self, request=request, adapter=self._database, path_params=params
            )
            call_ctx.principal = await self._authenticate(call_ctx, endpoint)
            await self._check_access(call_ctx, endpoint)
            result = await self._execute(call_ctx, endpoint, data, joined=False)
        if as_response:
            return self._to_response(call_ctx, result)
        return result

    async def get_principal(
        self, headers: Mapping[str, str], cookies: Mapping[str, str]
    ) -> Principal | None:
        """Resolve a principal from request headers and cookies.

        Returns ``None`` when no valid credential is present.
        """
        await self._ensure_init()
        request = AuthRequest(
            method="GET",
            path="/",
            url=self._config.base_url,
            query={},
            headers={key.lower(): value for key, value in headers.items()},
            cookies=dict(cookies),
            body=b"",
            client_ip=None,
        )
        ctx = RequestContext(auth=self, request=request, adapter=self._database)
        try:
            principal = await self._resolve(ctx)
        except AuthError as error:
            if error.code == "UNAUTHENTICATED":
                return None
            raise
        if principal is not None:
            await self._run_principal_checks(ctx, principal)
        return principal

    # ------------------------------------------------------------ serving

    def asgi(self) -> ASGIApp:
        """Return a pure ASGI app; mount it at ``base_path``."""
        from gotauth.core._asgi import AsgiApp

        return AsgiApp(self, well_known=False)

    def well_known(self) -> ASGIApp:
        """Return an ASGI app for the host root serving the well-known endpoints."""
        from gotauth.core._asgi import AsgiApp

        return AsgiApp(self, well_known=True)

    # ------------------------------------------------------------ sign-in

    async def complete_sign_in(
        self,
        ctx: EndpointContext,
        user: User,
        *,
        method: SignInMethod,
        remember_me: bool = True,
    ) -> SignInOut | ChallengeOut:
        """Run the sign-in interceptors, then set a challenge or create the session."""
        challenge: SignInChallenge | None = None
        for plugin in self._plugins:
            for interceptor in plugin.sign_in_interceptors:
                result = await interceptor(ctx, user, method)
                if challenge is None:
                    challenge = result
        if challenge is not None:
            self._set_challenge(ctx, user.id, challenge, method, remember_me)
            return ChallengeOut(challenge=challenge)
        presented = await self._presented_session_id(ctx)
        created = await ctx.sessions.create(ctx, user.id, remember_me=remember_me)
        await self._end_presented_session(ctx, presented, created.session.id)
        await ctx.emit("sign_in.succeeded", user_id=user.id, method=method)
        token = created.token if self._config.sessions.expose_token else None
        return SignInOut.model_validate(
            {
                "user": user.model_dump(),
                "session": created.session.model_dump(),
                "token": token,
            }
        )

    async def _presented_session_id(self, ctx: EndpointContext) -> str | None:
        """The session behind the request's session cookie, looked up by hash only
        (no sliding refresh, no cookie written). Bearer tokens belong to other
        clients and are left alone."""
        name = cookie_name(
            "session_token",
            base_url=self._config.base_url,
            prefix=self._config.advanced.cookie_prefix,
        )
        token = ctx.request.cookies.get(name)
        if not token:
            return None
        row = await ctx.adapter.find_one(
            "session", [Where("token_hash", ctx.crypto.hash_token(token))]
        )
        return str(row["id"]) if row is not None else None

    @staticmethod
    async def _end_presented_session(
        ctx: EndpointContext, presented: str | None, new_session_id: str
    ) -> None:
        """Re-authentication replaces the browser's session (ASVS 7.2.4)."""
        if presented is not None and presented != new_session_id:
            await ctx.sessions.revoke(ctx, presented)

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
            "exp": int((self.clock.now() + CHALLENGE_TTL).timestamp()),
        }
        encoded = (
            base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
        )
        ctx.set_cookie(
            SetCookie(
                name=self.cookie_name("challenge"),
                value=self.crypto.sign(encoded, purpose="challenge"),
                max_age=int(CHALLENGE_TTL.total_seconds()),
                secure=secure_cookies(self._config.base_url),
            )
        )

    def read_challenge(self, ctx: EndpointContext) -> ChallengeState | None:
        """Return the verified challenge cookie (expired included), or ``None``."""
        signed = ctx.request.cookies.get(self.cookie_name("challenge"))
        if not signed:
            return None
        encoded = self.crypto.unsign(signed, purpose="challenge")
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
            AuthError: TOKEN_INVALID, TOKEN_EXPIRED or FORBIDDEN.
        """
        state = self.read_challenge(ctx)
        if state is None:
            raise AuthError("TOKEN_INVALID", 400)
        if self.clock.now() >= state.exp:
            raise AuthError("TOKEN_EXPIRED", 400)
        if satisfied not in state.methods:
            raise AuthError("FORBIDDEN", 403)
        row = await ctx.adapter.find_one("user", [Where("id", state.user_id)])
        if row is None:
            raise AuthError("TOKEN_INVALID", 400)
        user = User.model_validate(returned_only(self._schema["user"], row))
        presented = await self._presented_session_id(ctx)
        created = await ctx.sessions.create(ctx, user.id, remember_me=state.remember_me)
        await self._end_presented_session(ctx, presented, created.session.id)
        ctx.set_cookie(
            SetCookie(
                name=self.cookie_name("challenge"),
                value="",
                max_age=0,
                secure=secure_cookies(self._config.base_url),
            )
        )
        await ctx.emit("sign_in.succeeded", user_id=user.id, method=state.method)
        token = created.token if self._config.sessions.expose_token else None
        return SignInOut.model_validate(
            {
                "user": user.model_dump(),
                "session": created.session.model_dump(),
                "token": token,
            }
        )

    # ------------------------------------------------------------ users

    async def create_user_record(
        self, ctx: EndpointContext | None, data: Mapping[str, Any]
    ) -> User:
        """Create a user: lower-cased email, user create hooks, ``user.created``."""
        if ctx is not None:
            return await self._create_user(ctx, unwrap(ctx.adapter), data)
        async with self._database.transaction() as adapter:
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
        hooks = self.model_hooks("user")
        for hook in hooks:
            if hook.before_create is not None:
                changed = await hook.before_create(ctx, values)
                if changed is not None:
                    values = changed
        row = await adapter.create("user", values)
        for hook in hooks:
            if hook.after_create is not None:
                await hook.after_create(ctx, dict(row))
        user = User.model_validate(returned_only(self._schema["user"], row))
        if ctx is not None:
            await ctx.emit("user.created", user_id=user.id)
        return user

    async def delete_user(self, ctx: EndpointContext | None, user_id: str) -> None:
        """Delete a user: user delete hooks around the delete, ``user.deleted``.

        Raises:
            AuthError: NOT_FOUND for an unknown user.
        """
        if ctx is not None:
            await self._delete_user(ctx, unwrap(ctx.adapter), user_id)
            return
        # No caller context: a server context, so the user delete hooks can join
        # this transaction (plugins revoke what the user owns) and the events go
        # out after the commit, as for an endpoint (CCR 011).
        await self._ensure_init()
        request = AuthRequest(
            method="DELETE",
            path="/",
            url=self._config.base_url,
            query={},
            headers={},
            cookies={},
            body=b"",
            client_ip=None,
        )
        server_ctx = RequestContext(auth=self, request=request, adapter=self._database)
        try:
            async with self._database.transaction() as tx:
                server_ctx.adapter = HookedAdapter(tx, self, server_ctx)
                await self._delete_user(server_ctx, tx, user_id)
        finally:
            server_ctx.adapter = self._database
        self._publish(server_ctx.events)
        if server_ctx.deferred:
            await self._run_deferred(server_ctx, list(server_ctx.deferred))

    async def _delete_user(
        self, ctx: EndpointContext | None, adapter: Adapter, user_id: str
    ) -> None:
        row = await adapter.find_one("user", [Where("id", user_id)])
        if row is None:
            raise AuthError("NOT_FOUND", 404)
        hooks = self.model_hooks("user")
        for hook in hooks:
            if hook.before_delete is not None:
                await hook.before_delete(ctx, dict(row))
        await adapter.delete("user", [Where("id", user_id)])
        for hook in hooks:
            if hook.after_delete is not None:
                await hook.after_delete(ctx, dict(row))
        if ctx is not None:
            await ctx.emit("user.deleted", user_id=user_id)


def _with_path(endpoint: Endpoint[Any, Any], path: str) -> Endpoint[Any, Any]:
    if endpoint.path == path:
        return endpoint
    from dataclasses import replace

    return replace(endpoint, path=path)


def _parse_cookies(header: str) -> dict[str, str]:
    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, separator, value = part.strip().partition("=")
        if separator and name:
            cookies.setdefault(name, value)
    return cookies
