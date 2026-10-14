"""Passkeys (work package P3): add passkeys to an account and sign in with them,
usernameless. Needs ``pip install "gotauth[passkey]"``::

    from gotauth.plugins.passkey import passkey

    auth = GotAuth(..., plugins=[passkey()])

``gotauth.plugins.passkey.testing.SoftAuthenticator`` answers the ceremonies in tests.
"""

from __future__ import annotations

from gotauth.plugins.passkey._plugin import PASSKEY_MODEL, passkey

__all__ = ["PASSKEY_MODEL", "passkey"]
