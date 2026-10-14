"""A software authenticator for tests: WebAuthn registrations ("none" attestation)
and ES256 assertions without a browser.

Example::

    authenticator = SoftAuthenticator(origin="http://localhost:8000")
    options = (await http.post("/passkey/register/options")).json()
    await http.post("/passkey/register/verify",
                    json={"response": authenticator.create(options)})
    options = (await http.post("/passkey/sign-in/options")).json()
    await http.post("/passkey/sign-in/verify",
                    json={"response": authenticator.get(options)})
"""

from __future__ import annotations

import hashlib
import json
import secrets
import struct
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.encode_cbor import encode_cbor

__all__ = ["SoftAuthenticator", "SoftCredential"]

_UP, _UV, _BE, _BS, _AT = 0x01, 0x04, 0x08, 0x10, 0x40


@dataclass
class SoftCredential:
    """One credential the authenticator holds."""

    credential_id: bytes
    private_key: ec.EllipticCurvePrivateKey
    rp_id: str
    user_handle: bytes
    sign_count: int = 0


@dataclass
class SoftAuthenticator:
    """A platform authenticator in memory.

    Attributes:
        origin: The origin the "browser" reports in ``clientDataJSON``.
        counting: Increase the signature counter on each assertion; False behaves
            like a synced passkey, which always reports 0.
        backed_up: Report the credential as backed up (a multi-device passkey).
        credentials: What was created, by base64url credential id.
    """

    origin: str
    counting: bool = True
    backed_up: bool = False
    credentials: dict[str, SoftCredential] = field(
        default_factory=dict[str, SoftCredential]
    )

    def _client_data(self, kind: str, challenge: str) -> bytes:
        data = {
            "type": kind,
            "challenge": challenge,
            "origin": self.origin,
            "crossOrigin": False,
        }
        return json.dumps(data, separators=(",", ":")).encode()

    def _flags(self, attested: bool) -> int:
        flags = _UP | _UV
        if self.backed_up:
            flags |= _BE | _BS
        return flags | (_AT if attested else 0)

    def create(
        self, options: dict[str, Any], *, rp_id: str | None = None
    ) -> dict[str, Any]:  # Any: WebAuthn JSON
        """Answer ``PublicKeyCredentialCreationOptions`` (JSON) like
        ``navigator.credentials.create()``; returns the credential as JSON."""
        the_rp_id = rp_id or options["rp"].get("id") or urlsplit(self.origin).hostname
        credential_id = secrets.token_bytes(16)
        key = ec.generate_private_key(ec.SECP256R1())
        numbers = key.public_key().public_numbers()
        cose = encode_cbor(
            {
                1: 2,  # kty: EC2
                3: -7,  # alg: ES256
                -1: 1,  # crv: P-256
                -2: numbers.x.to_bytes(32, "big"),
                -3: numbers.y.to_bytes(32, "big"),
            }
        )
        auth_data = (
            hashlib.sha256(str(the_rp_id).encode()).digest()
            + bytes([self._flags(attested=True)])
            + struct.pack(">I", 0)
            + bytes(16)  # AAGUID
            + struct.pack(">H", len(credential_id))
            + credential_id
            + cose
        )
        attestation = encode_cbor({"fmt": "none", "attStmt": {}, "authData": auth_data})
        client_data = self._client_data("webauthn.create", options["challenge"])
        encoded_id = bytes_to_base64url(credential_id)
        self.credentials[encoded_id] = SoftCredential(
            credential_id=credential_id,
            private_key=key,
            rp_id=str(the_rp_id),
            user_handle=base64url_to_bytes(options["user"]["id"]),
        )
        return {
            "id": encoded_id,
            "rawId": encoded_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "attestationObject": bytes_to_base64url(attestation),
                "transports": ["internal"],
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        }

    def get(
        self,
        options: dict[str, Any],
        *,
        credential_id: str | None = None,
        user_handle: bytes | None = None,
    ) -> dict[str, Any]:  # Any: WebAuthn JSON
        """Answer ``PublicKeyCredentialRequestOptions`` (JSON) like
        ``navigator.credentials.get()`` with a stored credential (the only one, or
        ``credential_id``); ``user_handle`` overrides the handle sent."""
        if credential_id is None:
            credential_id = next(iter(self.credentials))
        credential = self.credentials[credential_id]
        if self.counting:
            credential.sign_count += 1
        auth_data = (
            hashlib.sha256(credential.rp_id.encode()).digest()
            + bytes([self._flags(attested=False)])
            + struct.pack(">I", credential.sign_count)
        )
        client_data = self._client_data("webauthn.get", options["challenge"])
        signature = credential.private_key.sign(
            auth_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256())
        )
        handle = credential.user_handle if user_handle is None else user_handle
        return {
            "id": credential_id,
            "rawId": credential_id,
            "type": "public-key",
            "response": {
                "clientDataJSON": bytes_to_base64url(client_data),
                "authenticatorData": bytes_to_base64url(auth_data),
                "signature": bytes_to_base64url(signature),
                "userHandle": bytes_to_base64url(handle),
            },
            "authenticatorAttachment": "platform",
            "clientExtensionResults": {},
        }
