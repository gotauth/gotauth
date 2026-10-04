"""Errors raised by the crypto kit."""

from __future__ import annotations

__all__ = ["ConfigError"]


# TODO(F2): import ConfigError from gotauth.contracts after merge and drop this class,
# so `except ConfigError` catches the kit's errors and everyone else's alike.
class ConfigError(Exception):
    """The crypto kit is configured wrongly.

    Raised for a secret shorter than 32 characters, an unknown password algorithm, or
    a password algorithm whose optional extra is not installed. Messages never contain
    secret values.
    """
