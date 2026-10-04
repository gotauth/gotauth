"""CONTRACTS section 1: clocks, ids and durations."""

from __future__ import annotations

import importlib
import re
from datetime import UTC, datetime, timedelta
from typing import (
    TYPE_CHECKING,
    Literal,
    Protocol,
    TypeAlias,
    cast,
    get_args,
    runtime_checkable,
)

if TYPE_CHECKING:
    from gotauth.contracts.crypto import CryptoKit

__all__ = [
    "ID_PREFIXES",
    "Clock",
    "Duration",
    "FakeClock",
    "IdGenerator",
    "IdPrefix",
    "SystemClock",
    "UlidIds",
    "to_timedelta",
]


@runtime_checkable
class Clock(Protocol):
    """Source of the current time. Inject it instead of calling ``datetime.now()``."""

    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""
        ...


IdPrefix: TypeAlias = Literal[
    "usr",
    "acc",
    "ses",
    "ver",
    "key",
    "org",
    "mem",
    "inv",
    "tem",
    "tmm",
    "agt",
    "cli",
    "ocn",
    "cod",
    "tok",
    "pky",
    "tfa",
    "jwk",
    "rlt",
    "evt",
]

ID_PREFIXES: tuple[IdPrefix, ...] = cast("tuple[IdPrefix, ...]", get_args(IdPrefix))
"""Every id prefix of section 1, in table order."""


@runtime_checkable
class IdGenerator(Protocol):
    """Creates record ids. Adapters never generate ids themselves (section 3)."""

    def new(self, prefix: IdPrefix) -> str:
        """Return a new id: ``prefix + "_" + 26-char ULID``, e.g. ``usr_01J9Z3...``."""
        ...


Duration: TypeAlias = int | timedelta | str
"""An ``int`` (seconds), a ``timedelta`` or a string such as ``"90s"``, ``"15m"``,
``"12h"`` or ``"7d"``."""

_DURATION_PATTERN = re.compile(r"([0-9]+)([smhd])")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def to_timedelta(value: Duration) -> timedelta:
    """Convert a :data:`Duration` to a ``timedelta``.

    Args:
        value: Seconds as ``int``, a ``timedelta``, or a string of digits followed
            by one unit, ``s``, ``m``, ``h`` or ``d``: ``"90s"``, ``"15m"``, ``"12h"``,
            ``"7d"``.

    Returns:
        The duration as a non-negative ``timedelta``.

    Raises:
        ValueError: On a negative value, a ``bool``, a malformed string or any
            other type.
    """
    return _parse_duration(value)


def _parse_duration(candidate: object) -> timedelta:
    # Typed callers can only pass a Duration, but configuration often comes from plain
    # dicts, so every other type is checked at runtime too.
    if isinstance(candidate, bool):
        msg = "a duration cannot be a bool"
        raise ValueError(msg)
    if isinstance(candidate, int):
        if candidate < 0:
            msg = f"a duration cannot be negative: {candidate}"
            raise ValueError(msg)
        return timedelta(seconds=candidate)
    if isinstance(candidate, timedelta):
        if candidate < timedelta(0):
            msg = "a duration cannot be negative"
            raise ValueError(msg)
        return candidate
    if isinstance(candidate, str):
        match = _DURATION_PATTERN.fullmatch(candidate)
        if match is None:
            msg = (
                f"invalid duration {candidate!r}; use e.g. '90s', '15m', '12h' or '7d'"
            )
            raise ValueError(msg)
        return timedelta(seconds=int(match.group(1)) * _UNIT_SECONDS[match.group(2)])
    msg = f"invalid duration type: {type(candidate).__name__}"
    raise ValueError(msg)


class SystemClock:
    """The default :class:`Clock`: the system time in UTC."""

    def now(self) -> datetime:
        """Return the current system time, timezone-aware UTC."""
        return datetime.now(UTC)


# new_ulid() needs no secret, but the crypto kit factory requires one of at least 32
# characters. This constant is only used for ULIDs and never signs or encrypts anything.
_ULID_ONLY_SECRET = "gotauth-ulid-only-not-a-secret-value"  # noqa: S105


class UlidIds:
    """The default :class:`IdGenerator`: monotonic ULIDs from the crypto kit.

    Args:
        crypto: The crypto kit whose ``new_ulid`` is used. GotAuth passes its own kit.
            When omitted, a kit is built lazily on first use, only for ULIDs.
        clock: The clock that timestamps the ULIDs. Defaults to :class:`SystemClock`.
    """

    def __init__(
        self, crypto: CryptoKit | None = None, *, clock: Clock | None = None
    ) -> None:
        self._crypto = crypto
        self._clock: Clock = clock if clock is not None else SystemClock()

    def new(self, prefix: IdPrefix) -> str:
        """Return ``prefix + "_" + ULID``, for example ``usr_01J9Z3...``."""
        return f"{prefix}_{self._kit().new_ulid(self._clock.now())}"

    def _kit(self) -> CryptoKit:
        if self._crypto is None:
            # TODO(F3): import gotauth.crypto.crypto_kit directly once F3 has merged.
            # Imported lazily so this module needs nothing from the crypto package.
            module = importlib.import_module("gotauth.crypto")
            factory = getattr(module, "crypto_kit", None)
            if factory is None:
                msg = "gotauth.crypto.crypto_kit is not available yet (work package F3)"
                raise RuntimeError(msg)
            self._crypto = cast("CryptoKit", factory(_ULID_ONLY_SECRET))
        return self._crypto


class FakeClock(Clock, Protocol):
    """A :class:`Clock` that tests move by hand (``gotauth.testing.fake_clock``)."""

    def advance(self, by: Duration) -> datetime:
        """Move the clock forward by ``by`` and return the new time."""
        ...

    def set(self, at: datetime) -> None:
        """Set the clock to ``at`` (timezone-aware)."""
        ...
