"""Passwordless sign-in (work package P4): ``magic_link()`` sends a sign-in link,
``email_otp()`` a 6-digit code that signs in, verifies an email address or resets a
password::

    from gotauth.plugins.magic_link import email_otp, magic_link

    auth = GotAuth(..., plugins=[magic_link(), email_otp()])
"""

from __future__ import annotations

from gotauth.plugins.magic_link._plugin import email_otp, magic_link

__all__ = ["email_otp", "magic_link"]
