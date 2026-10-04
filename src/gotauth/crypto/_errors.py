"""Errors raised by the crypto kit.

The kit raises the shared contract error, so ``except ConfigError`` catches the kit's
configuration errors and everyone else's alike.
"""

from __future__ import annotations

from gotauth.contracts.errors import ConfigError

__all__ = ["ConfigError"]
