"""Input parsing, error rendering and responses (CONTRACTS 4, 5, 6, 10.1)."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl

from pydantic import BaseModel, ValidationError

from gotauth.contracts.endpoints import Endpoint
from gotauth.contracts.errors import AuthError
from gotauth.contracts.http import AuthResponse, SetCookie

__all__ = [
    "OAUTH_ERROR_MAP",
    "error_response",
    "input_format",
    "parse_body",
    "set_cookie_header",
    "validate",
]

OAUTH_ERROR_MAP: Mapping[str, tuple[str, int]] = {
    "INVALID_REQUEST": ("invalid_request", 400),
    "UNSUPPORTED_MEDIA_TYPE": ("invalid_request", 400),
    "UNAUTHENTICATED": ("invalid_client", 401),
    "INVALID_CREDENTIALS": ("invalid_client", 401),
    "TOKEN_INVALID": ("invalid_grant", 400),
    "TOKEN_EXPIRED": ("invalid_grant", 400),
    "INSUFFICIENT_SCOPE": ("invalid_scope", 400),
    "FORBIDDEN": ("unauthorized_client", 400),
    "RATE_LIMITED": ("temporarily_unavailable", 429),
}
"""Core error code -> (RFC 6749 error, status) for ``error_format="oauth"``. Plugin
codes named ``OAUTH_<NAME>`` render as ``<name>`` in lower case; everything else is
``server_error`` 500."""

_JSON = "application/json"
_FORM = "application/x-www-form-urlencoded"


def input_format(endpoint: Endpoint[Any, Any]) -> str:
    """Return ``json``, ``form`` or ``query`` for an endpoint (CONTRACTS 5)."""
    if endpoint.input_format is not None:
        return endpoint.input_format
    return "query" if endpoint.method == "GET" else "json"


def _media_type(headers: Mapping[str, str]) -> str:
    return headers.get("content-type", "").split(";", 1)[0].strip().lower()


def check_content_type(
    endpoint: Endpoint[Any, Any], headers: Mapping[str, str], body: bytes
) -> None:
    """Enforce the content type of a body (CONTRACTS 10.1). Empty bodies are exempt.

    Raises:
        AuthError: UNSUPPORTED_MEDIA_TYPE.
    """
    if not body:
        return
    kind = input_format(endpoint)
    wanted = {"json": _JSON, "form": _FORM}.get(kind)
    if wanted is not None and _media_type(headers) != wanted:
        raise AuthError("UNSUPPORTED_MEDIA_TYPE", 415)


def parse_body(
    endpoint: Endpoint[Any, Any], query: Mapping[str, str], body: bytes
) -> object:
    """Return the raw input of a request according to the endpoint's input format.

    Raises:
        AuthError: INVALID_REQUEST for a body that is not valid JSON or form data.
    """
    kind = input_format(endpoint)
    if kind == "query":
        return dict(query)
    if not body:
        return {}
    if kind == "form":
        try:
            return dict(parse_qsl(body.decode("utf-8"), keep_blank_values=True))
        except UnicodeDecodeError:
            raise AuthError(
                "INVALID_REQUEST", 400, "Body is not valid form data"
            ) from None
    try:
        return json.loads(body)
    except (ValueError, UnicodeDecodeError):
        raise AuthError("INVALID_REQUEST", 400, "Body is not valid JSON") from None


def validate(endpoint: Endpoint[Any, Any], raw: object) -> Any:  # Any: the input model
    """Validate raw input against ``endpoint.input``.

    Raises:
        AuthError: INVALID_REQUEST whose details hold only ``loc``, ``type`` and
            ``msg``, never the submitted values.
    """
    if endpoint.input is None:
        return None
    if isinstance(raw, BaseModel):
        raw = raw.model_dump(exclude_unset=True)
    try:
        return endpoint.input.model_validate(raw if raw is not None else {})
    except ValidationError as exc:
        errors = [
            {"loc": list(error["loc"]), "type": error["type"], "msg": error["msg"]}
            for error in exc.errors(
                include_url=False, include_input=False, include_context=False
            )
        ]
        # "from None": the ValidationError text contains the submitted values.
        raise AuthError("INVALID_REQUEST", 400, details={"errors": errors}) from None


def error_response(error: AuthError, error_format: str) -> AuthResponse:
    """Render an error in the GotAuth shape or the RFC 6749 shape."""
    headers = {"cache-control": "no-store", **error.headers}
    if error_format != "oauth":
        return AuthResponse(status=error.status, body=error.to_out(), headers=headers)
    mapped = OAUTH_ERROR_MAP.get(error.code)
    if mapped is not None:
        name, status = mapped
    elif error.code.startswith("OAUTH_"):
        name, status = error.code[len("OAUTH_") :].lower(), error.status
    else:
        name, status = "server_error", 500
    if name == "invalid_client":
        headers.setdefault("www-authenticate", 'Basic realm="gotauth"')
    body = {"error": name, "error_description": error.message}
    return AuthResponse(status=status, body=body, headers=headers)


def set_cookie_header(cookie: SetCookie) -> str:
    """Format one ``Set-Cookie`` header value."""
    parts = [f"{cookie.name}={cookie.value}", f"Path={cookie.path}"]
    if cookie.max_age is not None:
        parts.append(f"Max-Age={cookie.max_age}")
        if cookie.max_age <= 0:
            parts.append("Expires=Thu, 01 Jan 1970 00:00:00 GMT")
    if cookie.domain:
        parts.append(f"Domain={cookie.domain}")
    if cookie.secure:
        parts.append("Secure")
    if cookie.http_only:
        parts.append("HttpOnly")
    parts.append(f"SameSite={cookie.same_site.capitalize()}")
    return "; ".join(parts)


def body_bytes(response: AuthResponse) -> tuple[bytes, str]:
    """Return the serialized body and its content type."""
    if response.html is not None:
        return response.html.encode("utf-8"), "text/html; charset=utf-8"
    body = response.body
    if isinstance(body, BaseModel):
        data: object = body.model_dump(mode="json")
    else:
        data = body
    return json.dumps(data, separators=(",", ":")).encode("utf-8"), _JSON
