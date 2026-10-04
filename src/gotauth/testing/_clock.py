"""Deterministic clock and id generator."""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime

from gotauth.contracts.primitives import Duration, IdPrefix, to_timedelta

__all__ = ["DEFAULT_START", "ManualClock", "SeqIds", "fake_clock", "seq_ids"]

DEFAULT_START = datetime(2026, 1, 1, tzinfo=UTC)
"""The default start of :func:`fake_clock`."""


def _aware(at: datetime) -> datetime:
    if at.tzinfo is None or at.utcoffset() is None:
        msg = "the clock needs a timezone-aware datetime"
        raise ValueError(msg)
    return at.astimezone(UTC)


class ManualClock:
    """A clock that only moves when told to. Implements ``FakeClock``."""

    def __init__(self, start: datetime = DEFAULT_START) -> None:
        self._now = _aware(start)

    def now(self) -> datetime:
        """Return the current fake time (UTC)."""
        return self._now

    def advance(self, by: Duration) -> datetime:
        """Move forward by ``by`` (``"15m"``, ``90``, a ``timedelta``).

        Returns the new
        time."""
        self._now = self._now + to_timedelta(by)
        return self._now

    def set(self, at: datetime) -> None:
        """Jump to ``at`` (timezone-aware; earlier times are allowed)."""
        self._now = _aware(at)

    def __repr__(self) -> str:
        return f"ManualClock({self._now.isoformat()})"


def fake_clock(start: datetime = DEFAULT_START) -> ManualClock:
    """Return a clock fixed at ``start`` (default 2026-01-01 UTC) until moved.

    Example:
        >>> clock = fake_clock()
        >>> clock.advance("15m").isoformat()
        '2026-01-01T00:15:00+00:00'
    """
    return ManualClock(start)


class SeqIds:
    """Readable sequential ids: ``usr_00000000000000000000000001``, ... per prefix."""

    def __init__(self) -> None:
        self._counters: defaultdict[str, int] = defaultdict(int)

    def new(self, prefix: IdPrefix) -> str:
        """Return the next id for ``prefix``: the prefix, ``_`` and 26 digits."""
        self._counters[prefix] += 1
        return f"{prefix}_{self._counters[prefix]:026d}"


def seq_ids() -> SeqIds:
    """Return an id generator counting per prefix from 1.

    Example:
        >>> ids = seq_ids()
        >>> ids.new("usr")
        'usr_00000000000000000000000001'
    """
    return SeqIds()
