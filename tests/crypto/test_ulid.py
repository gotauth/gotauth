"""Monotonic ULIDs."""

from __future__ import annotations

import itertools
import re
import threading
from datetime import UTC, datetime, timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gotauth.crypto import crypto_kit, new_ulid
from gotauth.crypto._ulid import UlidGenerator

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
ULID = re.compile(r"[0-7][0-9A-HJKMNP-TV-Z]{25}")
AT = datetime(2026, 10, 4, 12, 34, 56, 789000, tzinfo=UTC)


def decode(ulid: str) -> int:
    value = 0
    for char in ulid:
        value = value * 32 + CROCKFORD.index(char)
    return value


@given(
    at=st.datetimes(
        min_value=datetime(1970, 1, 1),  # noqa: DTZ001 - Hypothesis wants naive bounds
        max_value=datetime(9999, 12, 31),  # noqa: DTZ001
        timezones=st.just(UTC),
    )
)
def test_time_part_is_the_millisecond(at: datetime) -> None:
    ulid = UlidGenerator().new(at)
    assert ULID.fullmatch(ulid)
    millis = (at - datetime(1970, 1, 1, tzinfo=UTC)) // timedelta(milliseconds=1)
    assert decode(ulid) >> 80 == millis


def test_same_millisecond_is_strictly_increasing() -> None:
    generator = UlidGenerator()
    made = [generator.new(AT) for _ in range(1000)]
    assert made == sorted(made)
    assert len(set(made)) == len(made)
    numbers = [decode(ulid) for ulid in made]
    assert all(b == a + 1 for a, b in itertools.pairwise(numbers))


def test_later_millisecond_sorts_later() -> None:
    generator = UlidGenerator()
    first = generator.new(AT)
    second = generator.new(AT + timedelta(milliseconds=1))
    assert first < second


def test_threads_never_share_a_ulid() -> None:
    generator = UlidGenerator()
    results: list[list[str]] = [[] for _ in range(8)]

    def work(index: int) -> None:
        results[index].extend(generator.new(AT) for _ in range(500))

    threads = [threading.Thread(target=work, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    everything = [ulid for result in results for ulid in result]
    assert len(set(everything)) == 8 * 500
    for result in results:
        assert result == sorted(result)


def test_random_part_overflow_raises() -> None:
    generator = UlidGenerator(random_bytes=lambda size: b"\xff" * size)
    assert generator.new(AT).endswith("ZZZZZZZZZZZZZZZZ")
    with pytest.raises(OverflowError):
        generator.new(AT)
    # A new millisecond starts over.
    generator.new(AT + timedelta(milliseconds=1))


def test_naive_datetime_raises() -> None:
    with pytest.raises(ValueError, match="timezone-aware"):
        new_ulid(datetime(2026, 1, 1))  # noqa: DTZ001 - the point of the test


def test_kits_share_one_monotonic_generator() -> None:
    first = crypto_kit("ulid-tests-secret-one-0123456789abcd")
    second = crypto_kit("ulid-tests-secret-two-0123456789abcd")
    made = [first.new_ulid(AT), second.new_ulid(AT), new_ulid(AT), first.new_ulid(AT)]
    assert made == sorted(made)
    assert len(set(made)) == 4
