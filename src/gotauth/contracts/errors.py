"""CONTRACTS section 6 (errors) and the exceptions named in section 2.2."""

from __future__ import annotations

from collections.abc import Mapping
from types import MappingProxyType
from typing import Any

from pydantic import BaseModel

__all__ = [
    "ERROR_CODES",
    "AuthError",
    "ConfigError",
    "ErrorBody",
    "ErrorOut",
    "ReferenceViolation",
    "SchemaConflictError",
    "UniqueViolation",
]

ERROR_CODES: Mapping[str, tuple[int, str]] = MappingProxyType(
    {
        "INVALID_REQUEST": (400, "The request is invalid"),
        "UNSUPPORTED_MEDIA_TYPE": (415, "Unsupported content type"),
        "INVALID_CREDENTIALS": (401, "Invalid email or password"),
        "UNAUTHENTICATED": (401, "Authentication required"),
        "FORBIDDEN": (403, "Forbidden"),
        "INSUFFICIENT_SCOPE": (403, "Insufficient scope"),
        "FRESH_SESSION_REQUIRED": (403, "A recent sign-in is required"),
        "EMAIL_NOT_VERIFIED": (403, "Email address is not verified"),
        "ORIGIN_NOT_ALLOWED": (403, "Origin not allowed"),
        "NOT_FOUND": (404, "Not found"),
        "USER_ALREADY_EXISTS": (409, "A user with this email already exists"),
        "TOKEN_INVALID": (400, "The token is invalid"),
        "TOKEN_EXPIRED": (400, "The token has expired"),
        "PASSWORD_TOO_SHORT": (400, "The password is too short"),
        "PASSWORD_TOO_LONG": (400, "The password is too long"),
        "PASSWORD_REJECTED": (400, "The password is not allowed"),
        "ACCOUNT_NOT_LINKED": (409, "The account cannot be linked"),
        "LAST_SIGN_IN_METHOD": (409, "The last sign-in method cannot be removed"),
        "PROVIDER_ERROR": (502, "The identity provider returned an error"),
        "RATE_LIMITED": (429, "Too many requests"),
        "INTERNAL_ERROR": (500, "Internal error"),
    }
)
"""Core error codes: ``code -> (HTTP status, default message)``. Plugins add their own
through ``Plugin.error_codes``, prefixed with their area."""


class AuthError(Exception):
    """An error with a code from :data:`ERROR_CODES` or a plugin's ``error_codes``.

    The message and details are sent to the client, so they must never hold secrets
    or submitted values.

    Args:
        code: The error code, e.g. ``"INVALID_CREDENTIALS"``.
        status: The HTTP status.
        message: A message for the client. Defaults to the registered message of a core
            code, else to the code itself.
        details: Extra JSON details, e.g. ``{"required": [...]}`` for
            INSUFFICIENT_SCOPE.
        headers: Extra response headers, e.g. ``Retry-After`` for a 429. Keyword-only
            addition so resolvers and handlers that raise can still set them.
    """

    def __init__(
        self,
        code: str,
        status: int,
        message: str | None = None,
        details: Mapping[str, Any] | None = None,  # Any: arbitrary JSON values
        *,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        default = ERROR_CODES.get(code)
        self.code = code
        self.status = status
        self.message = (
            message
            if message is not None
            else (default[1] if default is not None else code)
        )
        self.details: dict[str, Any] | None = (
            dict(details) if details is not None else None
        )
        self.headers: dict[str, str] = dict(headers) if headers is not None else {}
        super().__init__(f"{code}: {self.message}")

    def __repr__(self) -> str:
        return f"AuthError({self.code!r}, {self.status})"

    def to_out(self) -> ErrorOut:
        """Return the section 6 response body for this error."""
        return ErrorOut(
            error=ErrorBody(code=self.code, message=self.message, details=self.details)
        )


class ErrorBody(BaseModel):
    """The ``error`` object of :class:`ErrorOut`."""

    code: str
    message: str
    details: dict[str, Any] | None = None  # Any: arbitrary JSON values


class ErrorOut(BaseModel):
    """Error response body: ``{"error": {"code", "message", "details"?}}``.

    Serialize with ``exclude_none=True`` so ``details`` is omitted when empty.
    """

    error: ErrorBody


class ConfigError(Exception):
    """Invalid configuration, raised at ``GotAuth(...)`` construction or startup."""


class SchemaConflictError(ConfigError):
    """Two schemas define the same field, or disagree about a model (section 2)."""


class UniqueViolation(Exception):
    """A write broke a ``unique`` field or a ``unique_together`` group (section 3).

    Args:
        model: The logical model name.
        fields: The fields of the violated constraint.
    """

    def __init__(self, model: str, fields: tuple[str, ...]) -> None:
        self.model = model
        self.fields = tuple(fields)
        super().__init__(
            f"unique constraint violated on {model}({', '.join(self.fields)})"
        )


class ReferenceViolation(Exception):
    """A write or delete broke a ``Reference`` (section 3).

    Raised when a row points to a row that does not exist, or when a delete is
    blocked by ``on_delete="restrict"``.

    Args:
        model: The logical model whose rows hold the reference.
        fields: The referencing fields.
    """

    def __init__(self, model: str, fields: tuple[str, ...]) -> None:
        self.model = model
        self.fields = tuple(fields)
        super().__init__(
            f"reference constraint violated on {model}({', '.join(self.fields)})"
        )
