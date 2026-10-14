"""Two-factor authentication (work package P2): TOTP, single-use backup codes and an
optional email OTP fallback, required at every sign-in::

    from gotauth.plugins.two_factor import two_factor

    auth = GotAuth(..., plugins=[two_factor()])
"""

from __future__ import annotations

from gotauth.plugins.two_factor._plugin import TWO_FACTOR_MODEL, two_factor

__all__ = ["TWO_FACTOR_MODEL", "two_factor"]
