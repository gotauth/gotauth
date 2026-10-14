"""CONTRACTS section 5: endpoints, plugins, hooks and sign-in interception."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from datetime import datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Any,
    Generic,
    Literal,
    Protocol,
    TypeAlias,
    TypeVar,
    cast,
    get_args,
)

from pydantic import BaseModel

from gotauth.contracts.principal import Principal
from gotauth.contracts.schema import ModelSchema, Schema

if TYPE_CHECKING:
    from gotauth.contracts.adapter import Adapter
    from gotauth.contracts.config import DatabaseHooks, GotAuthInstance
    from gotauth.contracts.core_schema import User
    from gotauth.contracts.crypto import CryptoKit
    from gotauth.contracts.email import EmailService
    from gotauth.contracts.events import AuthEventType
    from gotauth.contracts.http import AuthRequest, AuthResponse, SetCookie
    from gotauth.contracts.primitives import Clock, IdGenerator
    from gotauth.contracts.protection import RateLimitRule
    from gotauth.contracts.sessions import SessionService

__all__ = [
    "CHALLENGE_TTL",
    "SIGN_IN_METHODS",
    "ChallengeState",
    "Endpoint",
    "EndpointAuth",
    "EndpointContext",
    "EndpointSpec",
    "ErrorFormat",
    "Hook",
    "HookPayload",
    "HttpMethod",
    "InputFormat",
    "OutputKind",
    "Plugin",
    "PrincipalCheck",
    "PrincipalResolver",
    "SignInChallenge",
    "SignInInterceptor",
    "SignInMethod",
]

EndpointAuth: TypeAlias = Literal["none", "optional", "session", "principal"]
"""``none``: anonymous. ``optional``: principal resolved if present. ``session``: a
cookie or bearer session is required. ``principal``: a session, API key or OAuth access
token is required."""

SignInMethod: TypeAlias = Literal[
    "password", "social", "passkey", "magic_link", "email_otp", "sso"
]
"""Values for ``complete_sign_in(method=...)``. New values need a CCR."""
SIGN_IN_METHODS: tuple[SignInMethod, ...] = cast(
    "tuple[SignInMethod, ...]", get_args(SignInMethod)
)

HttpMethod: TypeAlias = Literal["GET", "POST", "PATCH", "DELETE"]
InputFormat: TypeAlias = Literal["json", "form", "query"]
ErrorFormat: TypeAlias = Literal["gotauth", "oauth"]

InputT = TypeVar("InputT")
OutputT = TypeVar("OutputT")


@dataclass(frozen=True)
class Endpoint(Generic[InputT, OutputT]):
    """An HTTP endpoint, also callable as ``auth.api.<id>``.

    Attributes:
        id: snake_case, verb first; also the ``auth.api`` method name.
        method: HTTP method.
        path: kebab-case path relative to the mount; may contain ``{param}``.
        handler: ``handler(ctx, input)``; returns the output or a full ``AuthResponse``.
        input: Pydantic model for the input, if any.
        input_format: ``None`` means ``"query"`` for GET and ``"json"`` otherwise.
        output: Pydantic model for the output, if any.
        auth: Who may call it.
        fresh_session: The session must be younger than ``sessions.fresh_age``.
        scopes: Required scopes when called with an API key or OAuth token.
        rate_limit: Overrides the matching default rule.
        error_format: ``"oauth"`` renders every error as RFC 6749
            ``{"error", "error_description"}``.
        server_only: Only callable through ``auth.api``, never over HTTP.
        summary: OpenAPI summary.
        tags: OpenAPI tags.
    """

    id: str
    method: HttpMethod
    path: str
    handler: Callable[[EndpointContext, InputT], Awaitable[OutputT | AuthResponse]]
    input: type[BaseModel] | None = None
    input_format: InputFormat | None = None
    output: type[BaseModel] | None = None
    auth: EndpointAuth = "none"
    fresh_session: bool = False
    scopes: tuple[str, ...] = ()
    rate_limit: RateLimitRule | None = None
    error_format: ErrorFormat = "gotauth"
    server_only: bool = False
    summary: str = ""
    tags: tuple[str, ...] = ()


class EndpointContext(Protocol):
    """What a handler sees. Every endpoint runs inside a transaction, GET included, and
    ``adapter`` is bound to it."""

    @property
    def auth(self) -> GotAuthInstance:
        """The GotAuth instance (section 13)."""
        ...

    @property
    def request(self) -> AuthRequest:
        """The current request."""
        ...

    @property
    def adapter(self) -> Adapter:
        """Storage, bound to the request transaction."""
        ...

    @property
    def clock(self) -> Clock:
        """The injected clock."""
        ...

    @property
    def ids(self) -> IdGenerator:
        """The injected id generator."""
        ...

    @property
    def crypto(self) -> CryptoKit:
        """The crypto kit."""
        ...

    @property
    def sessions(self) -> SessionService:
        """The session service."""
        ...

    @property
    def email(self) -> EmailService:
        """The email service."""
        ...

    @property
    def principal(self) -> Principal | None:
        """The resolved principal; always ``None`` for ``auth="none"`` endpoints."""
        ...

    @property
    def path_params(self) -> Mapping[str, str]:
        """Values of the ``{param}`` parts of the path."""
        ...

    def set_cookie(self, cookie: SetCookie) -> None:
        """Add a cookie to the response."""
        ...

    def set_header(self, name: str, value: str) -> None:
        """Add a header to the response."""
        ...

    async def emit(
        self, event_type: AuthEventType, **data: Any
    ) -> None:  # Any: event data
        """Queue an event; delivered to ``on_event`` after the transaction commits."""
        ...

    def defer(self, work: Callable[[EndpointContext], Awaitable[None]]) -> None:
        """Run ``work`` after the request's transaction commits, in a transaction of
        its own; ``work`` gets a context bound to that transaction.

        Off localhost it runs in the background like email delivery, so the reply
        does not wait (CONTRACTS 9.1: work done only for existing accounts must not
        show in the response time). On localhost it runs before the reply. Errors
        are logged without details and never reach the client; a request that
        rolls back drops its deferred work.
        """
        ...

    def on_failure(self, work: Callable[[EndpointContext], Awaitable[None]]) -> None:
        """Run ``work`` if the request fails, after its transaction rolled back, in a
        transaction of its own (CCR 012).

        For writes that must outlast the failure they record, such as an attempt
        counter for one-time codes: raising rolls the request back, which would
        also undo the count. Runs before the error reaches the client; errors in
        ``work`` are logged without details. A request that succeeds drops it.
        """
        ...


@dataclass(frozen=True)
class HookPayload:
    """What a hook sees.

    Attributes:
        endpoint_id: The endpoint being called.
        input: The validated input model (before hooks), or ``None``.
        output: The handler result (after hooks), or ``None``.
    """

    endpoint_id: str
    input: Any  # Any: the input model of whichever endpoint runs
    output: Any  # Any: the output of whichever endpoint runs


@dataclass(frozen=True)
class Hook:
    """A before or after hook on endpoints.

    ``before``: return an ``AuthResponse`` to short-circuit, or raise ``AuthError``.
    ``after``: return an ``AuthResponse`` to replace the result.

    Attributes:
        when: ``"before"`` or ``"after"``.
        endpoints: Endpoint ids; ``("*",)`` means all.
        run: The hook.
    """

    when: Literal["before", "after"]
    endpoints: tuple[str, ...]
    run: Callable[[EndpointContext, HookPayload], Awaitable[AuthResponse | None]]


@dataclass(frozen=True)
class SignInChallenge:
    """A further sign-in step a ``SignInInterceptor`` requires.

    Attributes:
        type: E.g. ``"two_factor"`` or ``"two_factor_setup"``.
        methods: Factors that satisfy it, e.g. ``("totp", "backup_code")``.
    """

    type: str
    methods: tuple[str, ...]


class SignInInterceptor(Protocol):
    """Runs after credentials are verified and before a session is created (any
    sign-in method)."""

    async def __call__(
        self, ctx: EndpointContext, user: User, method: SignInMethod
    ) -> SignInChallenge | None:
        """Return a challenge to require another step, ``None`` to continue, or raise
        ``AuthError`` to block the sign-in."""
        ...


PrincipalCheck: TypeAlias = Callable[[EndpointContext, Principal], Awaitable[None]]
"""Runs after any principal is resolved. Raise ``AuthError`` to reject."""


class PrincipalResolver(Protocol):
    """Turns request credentials into a :class:`Principal`."""

    prefixes: tuple[str, ...]
    """Credential prefixes it owns, e.g. ``("gak_",)``. The longest match wins."""

    async def __call__(self, ctx: EndpointContext, credential: str) -> Principal | None:
        """Return the principal, or ``None`` for a foreign or unknown credential."""
        ...


CHALLENGE_TTL = timedelta(minutes=10)
"""Lifetime of the ``challenge`` cookie (signed with purpose ``"challenge"``)."""


@dataclass(frozen=True)
class ChallengeState:
    """The verified content of the challenge cookie, from ``auth.read_challenge``.

    Attributes:
        user_id: The user signing in.
        type: The challenge type.
        methods: Factors that satisfy it.
        method: The sign-in method that started it.
        remember_me: Passed on to the session.
        exp: When the challenge expires (UTC). ``read_challenge`` returns expired states
            too, so callers can answer TOKEN_EXPIRED.
    """

    user_id: str
    type: str
    methods: tuple[str, ...]
    method: SignInMethod
    remember_me: bool
    exp: datetime


@dataclass(frozen=True)
class Plugin:
    """A plugin: schema, endpoints, hooks and checks.

    Attributes:
        id: Plugin id, e.g. ``"api_key"``; listed in ``auth.plugin_ids``.
        schema: Models and fields it adds.
        endpoints: Endpoints served under the mount.
        well_known_endpoints: Served at the host root by ``auth.well_known()``.
        hooks: Endpoint hooks.
        database_hooks: Model write hooks.
        sign_in_interceptors: Run by ``complete_sign_in``, in plugin order.
        principal_resolvers: Credential resolvers.
        principal_checks: Run after any principal is resolved.
        error_codes: ``code -> (status, message)``.
        rate_limits: Extra rate-limit rules.
        requires_email: ``ConfigError`` at construction if no email sender is available.
        init: Runs once before the first request.
    """

    id: str
    schema: Schema = dc_field(default_factory=dict[str, ModelSchema])
    endpoints: tuple[Endpoint[Any, Any], ...] = ()
    well_known_endpoints: tuple[Endpoint[Any, Any], ...] = ()
    hooks: tuple[Hook, ...] = ()
    database_hooks: DatabaseHooks | None = None
    sign_in_interceptors: tuple[SignInInterceptor, ...] = ()
    principal_resolvers: tuple[PrincipalResolver, ...] = ()
    principal_checks: tuple[PrincipalCheck, ...] = ()
    error_codes: Mapping[str, tuple[int, str]] = dc_field(
        default_factory=dict[str, tuple[int, str]]
    )
    rate_limits: tuple[RateLimitRule, ...] = ()
    requires_email: bool = False
    init: Callable[[GotAuthInstance], Awaitable[None]] | None = None


OutputKind: TypeAlias = type[BaseModel] | Literal["redirect", "null"]
"""One possible output in an endpoint table: a model, a redirect or JSON null."""


@dataclass(frozen=True)
class EndpointSpec:
    """One row of an endpoint table (CONTRACTS 12.3 and 13.1).

    Implementations compare their ``Endpoint`` objects with these rows in tests.

    Attributes:
        id: Endpoint id.
        method: HTTP method, or ``None`` for a server_only row without a fixed path.
        path: Path relative to the mount (or to the host root when ``well_known``), or
            ``None`` for a server_only row without a fixed path.
        auth: Who may call it.
        owner: Owning work package.
        fresh_session: Requires a fresh session.
        input_format: Explicit input format, if the table names one.
        output: Possible outputs.
        error_format: Error rendering.
        server_only: Only callable through ``auth.api``.
        well_known: Served by ``auth.well_known()`` at the host root.
    """

    id: str
    method: HttpMethod | None
    path: str | None
    auth: EndpointAuth
    owner: str
    fresh_session: bool = False
    input_format: InputFormat | None = None
    output: tuple[OutputKind, ...] = ()
    error_format: ErrorFormat = "gotauth"
    server_only: bool = False
    well_known: bool = False
