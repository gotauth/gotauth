"""Strict base64 decoding: only the canonical unpadded text of a value is accepted."""

from __future__ import annotations

import base64
from collections.abc import Callable

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gotauth.crypto._encoding import (
    b64_decode,
    b64_encode,
    b64url_decode,
    b64url_encode,
    crockford_encode,
)


@given(raw=st.binary())
def test_round_trips(raw: bytes) -> None:
    assert b64url_decode(b64url_encode(raw)) == raw
    assert b64_decode(b64_encode(raw)) == raw
    assert "=" not in b64url_encode(raw) + b64_encode(raw)


@given(raw=st.binary(min_size=1))
def test_padding_is_rejected(raw: bytes) -> None:
    padded = base64.urlsafe_b64encode(raw).decode()
    if padded.endswith("="):
        with pytest.raises(ValueError, match="base64"):
            b64url_decode(padded)


@pytest.mark.parametrize(
    ("decode", "text"),
    [
        (b64url_decode, "A"),  # impossible length
        (b64url_decode, "AB"),  # trailing bits set: canonical is "AA"
        (b64url_decode, "AA+/"),  # standard alphabet
        (b64url_decode, "AA AA"),
        (b64url_decode, "\u00c0AAA"),
        (b64_decode, "AA-_"),  # url alphabet
        (b64_decode, "AB"),
        (b64_decode, "AAAA\n"),
    ],
)
def test_invalid_text_is_rejected(decode: Callable[[str], bytes], text: str) -> None:

    with pytest.raises(ValueError, match="base64"):
        decode(text)


def test_crockford_encode() -> None:
    assert crockford_encode(0, 3) == "000"
    assert crockford_encode(31, 2) == "0Z"
    assert crockford_encode(32**3 - 1, 3) == "ZZZ"
    with pytest.raises(ValueError, match="fit"):
        crockford_encode(32**3, 3)
    with pytest.raises(ValueError, match="fit"):
        crockford_encode(-1, 3)
