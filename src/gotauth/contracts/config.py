"""CONTRACTS section 13: configuration, database hooks, ``auth.api`` and the GotAuth
instance as seen by endpoint code.

``GotAuth`` itself is built by work package C1; contracts describe it as the
:class:`GotAuthInstance` Protocol so plugins never import C1's code.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import TYPE_CHECKING, Any, Literal, Protocol, TypeAlias, TypeVar, overload

from pydantic import BaseModel, ConfigDict, SecretStr, field_validator
from pydantic import Field as PydanticField

from gotauth.contracts.crypto import CryptoKit
from gotauth.contracts.email import EmailConfig, EmailService
from gotauth.contracts.primitives import Clock, Duration, IdGenerator, to_timedelta
from gotauth.contracts.protection import RateLimitConfig
from gotauth.contracts.sessions import SecondaryStorage, SessionConfig, SessionService

if TYPE_CHECKING:
    import httpx

    from gotauth.contracts.core_schema import User
    from gotauth.contracts.endpoints import (
        ChallengeState,
        EndpointContext,
        SignInMethod,
    )
    from gotauth.contracts.http import ASGIApp, AuthRequest, AuthResponse
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
    from gotauth.contracts.principal import Principal
    from gotauth.contracts.schema import Schema
    from gotauth.contracts.social import OAuthProvider

__all__ = [
    "AccountLinkingConfig",
    "AdvancedConfig",
    "ApiMethod",
    "AuthApi",
    "DatabaseHooks",
    "EmailPasswordConfig",
    "GotAuthInstance",
    "ModelHooks",
    "ResolvedConfig",
    "RowHook",
    "RowTransform",
]


class EmailPasswordConfig(BaseModel):
    """Email + password settings (C2)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    require_email_verification: bool = True
    min_password_length: int = 8
    max_password_length: int = 128
    auto_sign_in: bool = True
    reset_token_expires_in: Duration = "1h"  # noqa: S105
    verify_token_expires_in: Duration = "24h"  # noqa: S105
    revoke_sessions_on_password_reset: bool = True
    password_check: Callable[[str, str], Awaitable[str | None]] | None = None
    """The app's own password rule, for example a breached-password lookup or a list
    of words specific to the app: called with ``(password, email)`` on sign-up,
    password reset and password change, after the length check. Return a message
    to reject the password (``400 PASSWORD_REJECTED`` with that message) or
    ``None`` to accept it. An exception fails the request (500): catch your own
    network errors to fail open instead."""

    @field_validator("reset_token_expires_in", "verify_token_expires_in")
    @classmethod
    def _valid_duration(cls, value: Duration) -> Duration:
        to_timedelta(value)
        return value


class AccountLinkingConfig(BaseModel):
    """Social account linking settings (C4, section 11)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    enabled: bool = True
    trusted_providers: tuple[str, ...] = ()
    allow_different_emails: bool = False


class AdvancedConfig(BaseModel):
    """Advanced settings and test overrides.

    Attributes:
        cookie_prefix: Prefix of every cookie name (``cookie_name``).
        table_prefix: Prefix of every table name.
        ip_headers: Headers holding the client IP behind trusted proxies, e.g.
            ``("x-forwarded-for",)``.
        trusted_proxies: Proxy addresses or CIDR networks whose ``ip_headers`` are
            honored.
        password_algorithm: ``"scrypt"`` or ``"argon2id"`` (``argon2`` extra).
        clock: Clock override.
        ids: Id generator override.
        session_service: Session service override (tests, advanced use).
        crypto: Crypto kit override (tests, advanced use); the testing kit passes one
            with a low password-hash cost.
        email_service: Email service override (tests, advanced use).
        install_core_plugins: False skips the automatic sessions, email + password and
            social plugins (C1's own tests and tests that run before C2-C4 merge).
    """

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    cookie_prefix: str = "gotauth"
    table_prefix: str = "auth_"
    ip_headers: tuple[str, ...] = ()
    trusted_proxies: tuple[str, ...] = ()
    password_algorithm: Literal["scrypt", "argon2id"] = "scrypt"  # noqa: S105
    clock: Clock | None = None
    ids: IdGenerator | None = None
    session_service: SessionService | None = None
    crypto: CryptoKit | None = None
    email_service: EmailService | None = None
    install_core_plugins: bool = True


class ResolvedConfig(BaseModel):
    """Every config object with defaults applied (``auth.config``).

    Secrets are ``SecretStr``: the first signs and encrypts, all of them verify.
    """

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    secret: tuple[SecretStr, ...]
    base_url: str
    base_path: str = "/api/auth"
    trusted_origins: tuple[str, ...] = ()
    email_password: EmailPasswordConfig = EmailPasswordConfig()
    account_linking: AccountLinkingConfig = AccountLinkingConfig()
    sessions: SessionConfig = SessionConfig()
    rate_limit: RateLimitConfig = RateLimitConfig()
    email: EmailConfig = PydanticField(default_factory=EmailConfig)
    advanced: AdvancedConfig = AdvancedConfig()

    @field_validator("secret", mode="before")
    @classmethod
    def _secret_tuple(cls, value: object) -> object:
        # GotAuth(secret=...) takes one string or a [current, *previous] sequence.
        if isinstance(value, str | SecretStr):
            return (value,)
        return value


# Any in the hook signatures: rows are dicts of arbitrary field values.
RowHook: TypeAlias = Callable[
    ["EndpointContext | None", dict[str, Any]], Awaitable[None]
]
RowTransform: TypeAlias = Callable[
    ["EndpointContext | None", dict[str, Any]], Awaitable["dict[str, Any] | None"]
]


@dataclass(frozen=True)
class ModelHooks:
    """Write hooks for one model. A ``before_*`` hook may return modified data, or raise
    ``AuthError`` to abort. The core runs them for writes made through its services."""

    before_create: RowTransform | None = None
    after_create: RowHook | None = None
    before_update: RowTransform | None = None
    after_update: RowHook | None = None
    before_delete: RowHook | None = None
    after_delete: RowHook | None = None


@dataclass(frozen=True)
class DatabaseHooks:
    """Model write hooks by logical model name (from config and plugins)."""

    hooks: Mapping[str, ModelHooks] = dc_field(default_factory=dict[str, ModelHooks])


OutputT_co = TypeVar("OutputT_co", covariant=True)


class ApiMethod(Protocol[OutputT_co]):
    """A typed ``auth.api.<endpoint_id>`` method.

    It returns the output model, or the full ``AuthResponse`` (cookies included) with
    ``as_response=True``, and raises ``AuthError``. With ``ctx=`` the call joins that
    context's transaction and principal.
    """

    @overload
    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,  # Any: JSON input values
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: Literal[False] = False,
        ctx: EndpointContext | None = None,
    ) -> Awaitable[OutputT_co]: ...

    @overload
    def __call__(
        self,
        body: BaseModel | Mapping[str, Any] | None = None,  # Any: JSON input values
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: Literal[True],
        ctx: EndpointContext | None = None,
    ) -> Awaitable[AuthResponse]: ...


class AuthApi(Protocol):
    """``auth.api``: every endpoint, ``server_only`` ones included, callable from code.

    Server calls skip origin checks and rate limits. Core endpoints have typed members;
    plugin endpoints are reached through :meth:`call`.
    """

    async def call(
        self,
        endpoint_id: str,
        body: BaseModel | Mapping[str, Any] | None = None,  # Any: JSON input values
        *,
        headers: Mapping[str, str] | None = None,
        query: Mapping[str, str] | None = None,
        path_params: Mapping[str, str] | None = None,
        as_response: bool = False,
        ctx: EndpointContext | None = None,
    ) -> Any:  # Any: the output model of whichever endpoint is called
        """Call any endpoint by id."""
        ...

    @property
    def sign_up_email(self) -> ApiMethod[SignInOut | StatusOut]:
        """POST /sign-up/email (C2)."""
        ...

    @property
    def sign_in_email(self) -> ApiMethod[SignInOut | ChallengeOut]:
        """POST /sign-in/email (C2)."""
        ...

    @property
    def sign_out(self) -> ApiMethod[StatusOut]:
        """POST /sign-out (C2)."""
        ...

    @property
    def send_verification_email(self) -> ApiMethod[StatusOut]:
        """POST /send-verification-email (C2)."""
        ...

    @property
    def verify_email(self) -> ApiMethod[StatusOut | AuthResponse]:
        """GET /verify-email (C2); a redirect comes back as an ``AuthResponse``."""
        ...

    @property
    def request_password_reset(self) -> ApiMethod[StatusOut]:
        """POST /request-password-reset (C2)."""
        ...

    @property
    def reset_password(self) -> ApiMethod[StatusOut]:
        """POST /reset-password (C2)."""
        ...

    @property
    def change_password(self) -> ApiMethod[StatusOut]:
        """POST /change-password (C2)."""
        ...

    @property
    def change_email(self) -> ApiMethod[StatusOut]:
        """POST /change-email (C2)."""
        ...

    @property
    def update_user(self) -> ApiMethod[UserOut]:
        """PATCH /user (C2)."""
        ...

    @property
    def delete_user(self) -> ApiMethod[StatusOut]:
        """DELETE /user (C2)."""
        ...

    @property
    def get_session(self) -> ApiMethod[SessionWithUserOut | None]:
        """GET /session (C3)."""
        ...

    @property
    def list_sessions(self) -> ApiMethod[SessionListOut]:
        """GET /sessions (C3)."""
        ...

    @property
    def revoke_session(self) -> ApiMethod[StatusOut]:
        """POST /sessions/revoke (C3)."""
        ...

    @property
    def revoke_other_sessions(self) -> ApiMethod[StatusOut]:
        """POST /sessions/revoke-others (C3)."""
        ...

    @property
    def sign_in_social(self) -> ApiMethod[RedirectOut]:
        """POST /sign-in/social (C4)."""
        ...

    @property
    def social_callback(self) -> ApiMethod[AuthResponse]:
        """GET /callback/{provider} (C4)."""
        ...

    @property
    def social_callback_post(self) -> ApiMethod[AuthResponse]:
        """POST /callback/{provider} (C4, form_post providers)."""
        ...

    @property
    def link_social(self) -> ApiMethod[RedirectOut]:
        """POST /link-social (C4)."""
        ...

    @property
    def list_accounts(self) -> ApiMethod[AccountListOut]:
        """GET /accounts (C4)."""
        ...

    @property
    def unlink_account(self) -> ApiMethod[StatusOut]:
        """POST /unlink-account (C4)."""
        ...


class GotAuthInstance(Protocol):
    """The ``GotAuth`` object (C1) as endpoint and plugin code sees it."""

    @property
    def schema(self) -> Schema:
        """The merged core + plugin schema (used by ``gotauth generate``)."""
        ...

    @property
    def api(self) -> AuthApi:
        """Server-side calls."""
        ...

    @property
    def config(self) -> ResolvedConfig:
        """Every config object with defaults applied."""
        ...

    @property
    def providers(self) -> Mapping[str, OAuthProvider]:
        """Social providers by id."""
        ...

    @property
    def plugin_ids(self) -> frozenset[str]:
        """Ids of the user's plugins, e.g. ``{"api_key", "organization"}``."""
        ...

    @property
    def http(self) -> httpx.AsyncClient:
        """Shared HTTP client for providers, CIMD and email APIs (10s timeout)."""
        ...

    @property
    def secondary_storage(self) -> SecondaryStorage | None:
        """``GotAuth(secondary_storage=...)``, for shared counters and caches."""
        ...

    @property
    def fastapi(
        self,
    ) -> Any:  # Any: A1's FastAPIIntegration; contracts cannot import A1
        """The FastAPI integration (A1), imported lazily."""
        ...

    async def handle(self, request: AuthRequest) -> AuthResponse:
        """Run one request through the pipeline."""
        ...

    def asgi(self) -> ASGIApp:
        """ASGI app to mount at ``base_path``."""
        ...

    def well_known(self) -> ASGIApp:
        """ASGI app to mount at ``/``; serves ``Plugin.well_known_endpoints``."""
        ...

    async def get_principal(
        self, headers: Mapping[str, str], cookies: Mapping[str, str]
    ) -> Principal | None:
        """Resolve a principal from request headers and cookies."""
        ...

    async def check_principal(self, ctx: EndpointContext, principal: Principal) -> None:
        """Run every plugin's ``principal_checks`` on ``principal``.

        For code that accepts a credential outside the request pipeline, such as the
        server calls that verify API keys and OAuth tokens. Raises ``AuthError`` when a
        check refuses the principal.
        """
        ...

    async def drain(self) -> None:
        """Wait for background tasks (email, events)."""
        ...

    async def complete_sign_in(
        self,
        ctx: EndpointContext,
        user: User,
        *,
        method: SignInMethod,
        remember_me: bool = True,
    ) -> SignInOut | ChallengeOut:
        """Finish a verified sign-in: run interceptors, then create the session or set
        the challenge cookie. Every sign-in path calls this."""
        ...

    def read_challenge(self, ctx: EndpointContext) -> ChallengeState | None:
        """Return the verified challenge cookie (expired ones included), or ``None``."""
        ...

    async def finish_challenge(
        self, ctx: EndpointContext, *, satisfied: str
    ) -> SignInOut:
        """Complete a challenge with the factor used.

        Raises TOKEN_INVALID, TOKEN_EXPIRED or FORBIDDEN.
        """
        ...

    async def create_user_record(
        self,
        ctx: EndpointContext | None,
        data: Mapping[str, Any],  # Any: user field values
    ) -> User:
        """Create a user: lower-case email, hooks, ``user.created``."""
        ...

    async def delete_user(self, ctx: EndpointContext | None, user_id: str) -> None:
        """Delete a user: hooks, cascade, ``user.deleted``. The only deletion path."""
        ...

    def background(self, coro: Awaitable[None]) -> None:
        """Run a tracked background task; errors are logged."""
        ...
