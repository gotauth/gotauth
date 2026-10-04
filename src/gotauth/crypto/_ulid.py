"""Monotonic ULIDs (https://github.com/ulid/spec)."""

from __future__ import annotations

import secrets
import threading
from collections.abc import Callable
from datetime import datetime

from gotauth.crypto._encoding import crockford_encode, unix_millis

__all__ = ["UlidGenerator", "new_ulid"]

_RANDOM_BITS = 80
_MAX_TIME = (1 << 48) - 1


class UlidGenerator:
    """Makes ULIDs that sort strictly increasing within one millisecond.

    For a new millisecond the 80-bit random part is fresh; for the same millisecond
    as the previous ULID it is the previous random part plus one, as the ULID spec's
    monotonic mode describes. A lock makes this safe across threads.
    """

    __slots__ = ("_last_ms", "_last_random", "_lock", "_random_bytes")

    def __init__(
        self, random_bytes: Callable[[int], bytes] = secrets.token_bytes
    ) -> None:
        """Create a generator.

        Args:
            random_bytes: Source of random bytes; tests replace it.
        """
        self._random_bytes = random_bytes
        self._lock = threading.Lock()
        self._last_ms = -1
        self._last_random = 0

    def new(self, at: datetime) -> str:
        """Make a ULID for the moment ``at``.

        Args:
            at: Timezone-aware datetime, not before 1970.

        Returns:
            26 upper-case Crockford base32 characters.

        Raises:
            ValueError: If ``at`` is naive or before 1970.
            OverflowError: If the random part would overflow within one millisecond,
                which the ULID spec treats as a failure (about 2**80 ULIDs).
        """
        ms = unix_millis(at)
        if ms > _MAX_TIME:
            msg = "datetime is past the ULID time range"
            raise ValueError(msg)
        with self._lock:
            if ms == self._last_ms:
                random_part = self._last_random + 1
                if random_part >> _RANDOM_BITS:
                    msg = "ULID random part overflowed within one millisecond"
                    raise OverflowError(msg)
            else:
                random_part = int.from_bytes(
                    self._random_bytes(_RANDOM_BITS // 8), "big"
                )
            self._last_ms = ms
            self._last_random = random_part
        return crockford_encode((ms << _RANDOM_BITS) | random_part, 26)


# One generator per process, so ULIDs from every kit instance stay monotonic.
_DEFAULT_GENERATOR = UlidGenerator()


def new_ulid(at: datetime) -> str:
    """Make a ULID for ``at`` from the process-wide monotonic generator.

    Args:
        at: Timezone-aware datetime, not before 1970.

    Returns:
        26 upper-case Crockford base32 characters.
    """
    return _DEFAULT_GENERATOR.new(at)
