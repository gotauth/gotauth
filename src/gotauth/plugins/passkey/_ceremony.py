"""The WebAuthn ceremonies, through py_webauthn (imported only here, so
``gotauth.plugins.passkey`` loads without the extra until ``passkey()`` is called)."""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any, Literal, cast

from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import (
    base64url_to_bytes,
    bytes_to_base64url,
    parse_client_data_json,
)
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    CredentialDeviceType,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

__all__ = [
    "Registered",
    "Rejected",
    "assertion_ids",
    "authentication_options",
    "b64",
    "client_challenge",
    "registration_options",
    "verify_assertion",
    "verify_registration",
]

Verification = Literal["required", "preferred", "discouraged"]


class Rejected(Exception):
    """The response does not verify."""


@dataclass(frozen=True)
class Registered:
    """A verified new credential, ready to store."""

    credential_id: str
    public_key: str
    sign_count: int
    transports: list[str]
    device_type: Literal["single_device", "multi_device"]
    backed_up: bool


def b64(value: bytes) -> str:
    """base64url without padding."""
    return bytes_to_base64url(value)


def _text(value: Any) -> str | None:  # Any: JSON
    return value if isinstance(value, str) and value else None


def _bytes(value: Any) -> bytes | None:  # Any: JSON
    text = _text(value)
    if text is None:
        return None
    try:
        return base64url_to_bytes(text)
    except (ValueError, TypeError):
        return None


def client_challenge(response: dict[str, Any]) -> bytes | None:  # Any: JSON
    """The challenge inside ``response.clientDataJSON``, or None if unreadable."""
    inner = response.get("response")
    if not isinstance(inner, dict):
        return None
    raw = _bytes(cast(dict[str, Any], inner).get("clientDataJSON"))
    if raw is None:
        return None
    try:
        return parse_client_data_json(raw).challenge
    except (WebAuthnException, ValueError, KeyError, TypeError):
        return None


def assertion_ids(response: dict[str, Any]) -> tuple[str, str] | None:  # Any: JSON
    """``(credential id, user handle as text)`` of an assertion, or None."""
    raw_id = _bytes(response.get("rawId")) or _bytes(response.get("id"))
    inner = response.get("response")
    if raw_id is None or not isinstance(inner, dict):
        return None
    handle = _bytes(cast(dict[str, Any], inner).get("userHandle"))
    if handle is None:
        return None
    try:
        return b64(raw_id), handle.decode("utf-8")
    except UnicodeDecodeError:
        return None


def _uv(value: Verification) -> UserVerificationRequirement:
    return UserVerificationRequirement(value)


def _options(options: Any) -> dict[str, Any]:  # Any: py_webauthn options, JSON
    return cast(dict[str, Any], json.loads(options_to_json(options)))


def registration_options(
    *,
    rp_id: str,
    rp_name: str,
    user_id: str,
    user_name: str,
    display_name: str,
    challenge: bytes,
    exclude: Sequence[tuple[str, Sequence[str]]],
    user_verification: Verification,
) -> dict[str, Any]:  # Any: JSON
    """``PublicKeyCredentialCreationOptions`` as JSON: a discoverable credential, no
    attestation, the user handle = the user id's UTF-8 bytes (no personal data)."""
    descriptors = [
        PublicKeyCredentialDescriptor(
            id=base64url_to_bytes(credential_id),
            transports=[
                AuthenticatorTransport(t)
                for t in transports
                if t in AuthenticatorTransport._value2member_map_  # pyright: ignore[reportPrivateUsage]
            ],
        )
        for credential_id, transports in exclude
    ]
    return _options(
        generate_registration_options(
            rp_id=rp_id,
            rp_name=rp_name,
            user_name=user_name,
            user_id=user_id.encode("utf-8"),
            user_display_name=display_name,
            challenge=challenge,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.REQUIRED,
                user_verification=_uv(user_verification),
            ),
            exclude_credentials=descriptors,
        )
    )


def authentication_options(
    *, rp_id: str, challenge: bytes, user_verification: Verification
) -> dict[str, Any]:  # Any: JSON
    """``PublicKeyCredentialRequestOptions`` as JSON, with an empty allow list
    (usernameless; works with conditional UI)."""
    return _options(
        generate_authentication_options(
            rp_id=rp_id,
            challenge=challenge,
            allow_credentials=[],
            user_verification=_uv(user_verification),
        )
    )


def verify_registration(
    response: dict[str, Any],  # Any: JSON
    *,
    challenge: bytes,
    rp_id: str,
    origins: list[str],
    require_user_verification: bool,
) -> Registered:
    """Verify a ``navigator.credentials.create()`` response.

    Raises:
        Rejected: If anything does not verify.
    """
    try:
        verified = verify_registration_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origins,
            require_user_verification=require_user_verification,
        )
    except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
        raise Rejected(str(exc)) from exc
    inner = response.get("response")
    raw_transports = (
        cast(dict[str, Any], inner).get("transports")
        if isinstance(inner, dict)
        else None
    )
    transports = (
        [str(t) for t in cast(list[Any], raw_transports)]
        if isinstance(raw_transports, list)
        else []
    )
    device: Literal["single_device", "multi_device"] = (
        "multi_device"
        if verified.credential_device_type == CredentialDeviceType.MULTI_DEVICE
        else "single_device"
    )
    return Registered(
        credential_id=b64(verified.credential_id),
        public_key=b64(verified.credential_public_key),
        sign_count=verified.sign_count,
        transports=transports,
        device_type=device,
        backed_up=verified.credential_backed_up,
    )


def verify_assertion(
    response: dict[str, Any],  # Any: JSON
    *,
    challenge: bytes,
    rp_id: str,
    origins: list[str],
    public_key: str,
    current_sign_count: int,
    require_user_verification: bool,
) -> tuple[int, bool]:
    """Verify a ``navigator.credentials.get()`` response; the new sign count and
    whether the user was verified (PIN or biometrics, not presence alone).

    Raises:
        Rejected: If anything does not verify, including a sign count that did not
            go up (when either count is above 0).
    """
    try:
        verified = verify_authentication_response(
            credential=response,
            expected_challenge=challenge,
            expected_rp_id=rp_id,
            expected_origin=origins,
            credential_public_key=base64url_to_bytes(public_key),
            credential_current_sign_count=current_sign_count,
            require_user_verification=require_user_verification,
        )
    except (WebAuthnException, ValueError, KeyError, TypeError) as exc:
        raise Rejected(str(exc)) from exc
    return verified.new_sign_count, verified.user_verified
