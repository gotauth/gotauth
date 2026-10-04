"""The kit object: secrets, repr, signing, encryption, key derivation and tokens."""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import re
from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gotauth.crypto import (
    ConfigError,
    DefaultCryptoKit,
    crypto_kit,
    equal,
    hash_token,
    hkdf_sha256,
    random_token,
)
from gotauth.crypto._keys import Secret

OLD = "old-secret-for-the-kit-tests-0123456789"
NEW = "new-secret-for-the-kit-tests-9876543210"
OTHER = "some-other-secret-nobody-configured-000"
KIT = crypto_kit(NEW)
ROTATED = crypto_kit([NEW, OLD])
OLD_KIT = crypto_kit(OLD)

purposes = st.text(min_size=1, max_size=40)
values = st.text(max_size=200)


def test_crypto_kit_returns_the_default_kit() -> None:
    kit = crypto_kit(NEW)
    assert isinstance(kit, DefaultCryptoKit)
    assert kit.password_algorithm == "scrypt"


@pytest.mark.parametrize(
    "secret",
    [
        "x" * 31,
        "",
        [],
        ["x" * 32, "short"],
        ["short", "x" * 32],
        ["x" * 32 + "\ud800"],
    ],
)
def test_bad_secret_is_a_config_error(secret: Any) -> None:
    with pytest.raises(ConfigError):
        crypto_kit(secret)


def test_secret_of_32_characters_is_enough() -> None:
    crypto_kit("x" * 32)
    # Characters, not bytes: 32 two-byte letters are also fine.
    crypto_kit("\u00e9" * 32)


@pytest.mark.parametrize("bad", [b"x" * 40, None, 42])
def test_non_string_secret_in_list_is_a_config_error(bad: object) -> None:
    with pytest.raises(ConfigError, match="must be a string"):
        crypto_kit(["x" * 32, bad])  # pyright: ignore[reportArgumentType]


def test_config_error_never_shows_the_secret() -> None:
    secret = "too-short-but-secret"
    with pytest.raises(ConfigError) as info:
        crypto_kit(["y" * 40, secret])
    assert secret not in str(info.value)
    assert "secret 2" in str(info.value)


def test_unknown_password_algorithm_is_a_config_error() -> None:
    with pytest.raises(ConfigError, match="password_algorithm"):
        crypto_kit(NEW, password_algorithm="md5")  # pyright: ignore[reportArgumentType]


def test_repr_hides_the_secrets() -> None:
    for text in (repr(ROTATED), str(ROTATED)):
        assert NEW not in text
        assert OLD not in text
        assert "2 redacted" in text
        assert "scrypt" in text


def test_secret_wrapper_hides_its_bytes() -> None:
    secret = Secret(b"key material")
    assert repr(secret) == "<redacted>"
    assert "key material" not in str(secret)
    assert secret.reveal() == b"key material"


def test_kit_logs_nothing(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG)
    signed = ROTATED.sign("value", purpose="challenge")
    ROTATED.unsign(signed, purpose="challenge")
    ROTATED.decrypt(ROTATED.encrypt("value", purpose="oauth_state"), purpose="x")
    ROTATED.derive_key("app")
    assert caplog.records == []


@given(value=values, purpose=purposes)
def test_sign_round_trip(value: str, purpose: str) -> None:
    signed = KIT.sign(value, purpose=purpose)
    assert signed.startswith(value + ".")
    assert KIT.unsign(signed, purpose=purpose) == value


@given(value=values, purpose=purposes, data=st.data())
def test_tampered_signed_value_is_rejected(
    value: str, purpose: str, data: st.DataObject
) -> None:
    signed = KIT.sign(value, purpose=purpose)
    index = data.draw(st.integers(0, len(signed) - 1))
    replacement = data.draw(st.characters().filter(lambda c: c != signed[index]))
    tampered = signed[:index] + replacement + signed[index + 1 :]
    assert KIT.unsign(tampered, purpose=purpose) is None


@given(value=values, purpose=purposes, cut=st.integers(1, 43))
def test_truncated_signature_is_rejected(value: str, purpose: str, cut: int) -> None:
    signed = KIT.sign(value, purpose=purpose)
    assert KIT.unsign(signed[:-cut], purpose=purpose) is None


@given(value=values, purpose=purposes, other=purposes)
def test_wrong_purpose_is_rejected(value: str, purpose: str, other: str) -> None:
    signed = KIT.sign(value, purpose=purpose)
    expected = value if other == purpose else None
    assert KIT.unsign(signed, purpose=other) == expected


def test_wrong_secret_is_rejected() -> None:
    signed = crypto_kit(OTHER).sign("value", purpose="challenge")
    assert ROTATED.unsign(signed, purpose="challenge") is None


def test_signing_rotation() -> None:
    old_signed = OLD_KIT.sign("value", purpose="challenge")
    assert ROTATED.unsign(old_signed, purpose="challenge") == "value"
    new_signed = ROTATED.sign("value", purpose="challenge")
    # [new, old] signs with new.
    assert new_signed == KIT.sign("value", purpose="challenge")
    assert KIT.unsign(new_signed, purpose="challenge") == "value"
    assert OLD_KIT.unsign(new_signed, purpose="challenge") is None
    # Dropping the old secret ends its signatures.
    assert KIT.unsign(old_signed, purpose="challenge") is None


def test_unsign_compares_every_secret_in_constant_time(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[bytes, bytes]] = []
    real = hmac.compare_digest

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return real(a, b)

    monkeypatch.setattr(hmac, "compare_digest", spy)
    signed = OLD_KIT.sign("value", purpose="challenge")
    assert ROTATED.unsign(signed, purpose="challenge") == "value"
    # One comparison per configured secret, even though the second one matched.
    assert len(calls) == 2


@pytest.mark.parametrize("method", ["sign", "unsign", "encrypt", "decrypt"])
def test_empty_purpose_is_rejected(method: str) -> None:
    with pytest.raises(ValueError, match="purpose"):
        getattr(KIT, method)("value", purpose="")


def test_empty_purpose_is_rejected_by_derive_key() -> None:
    with pytest.raises(ValueError, match="purpose"):
        KIT.derive_key("")


@given(plaintext=values, purpose=purposes)
def test_encrypt_round_trip(plaintext: str, purpose: str) -> None:
    ciphertext = KIT.encrypt(plaintext, purpose=purpose)
    assert re.fullmatch(r"v1\.[A-Za-z0-9_-]{16}\.[A-Za-z0-9_-]{22,}", ciphertext)
    assert KIT.decrypt(ciphertext, purpose=purpose) == plaintext


def test_encrypt_uses_a_fresh_nonce() -> None:
    first = KIT.encrypt("same text", purpose="account_token")
    second = KIT.encrypt("same text", purpose="account_token")
    assert first != second
    assert first.split(".")[1] != second.split(".")[1]


def _decode(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


@given(plaintext=values, data=st.data())
def test_tampered_ciphertext_is_rejected(plaintext: str, data: st.DataObject) -> None:
    version, nonce, body = KIT.encrypt(plaintext, purpose="account_token").split(".")
    raw = bytearray(_decode(nonce) + _decode(body))
    index = data.draw(st.integers(0, len(raw) - 1))
    raw[index] ^= data.draw(st.integers(1, 255))
    tampered = f"{version}.{_encode(bytes(raw[:12]))}.{_encode(bytes(raw[12:]))}"
    assert KIT.decrypt(tampered, purpose="account_token") is None


@given(plaintext=values, data=st.data())
def test_truncated_ciphertext_is_rejected(plaintext: str, data: st.DataObject) -> None:
    ciphertext = KIT.encrypt(plaintext, purpose="account_token")
    version, nonce, body = ciphertext.split(".")
    raw = _decode(body)
    keep = data.draw(st.integers(0, len(raw) - 1))
    shortened = f"{version}.{nonce}.{_encode(raw[:keep])}"
    assert KIT.decrypt(shortened, purpose="account_token") is None
    cut = data.draw(st.integers(1, len(ciphertext)))
    assert KIT.decrypt(ciphertext[:-cut], purpose="account_token") is None


@given(plaintext=values, purpose=purposes, other=purposes)
def test_decrypt_with_wrong_purpose_is_rejected(
    plaintext: str, purpose: str, other: str
) -> None:
    ciphertext = KIT.encrypt(plaintext, purpose=purpose)
    expected = plaintext if other == purpose else None
    assert KIT.decrypt(ciphertext, purpose=other) == expected


def test_decrypt_with_wrong_secret_is_rejected() -> None:
    ciphertext = crypto_kit(OTHER).encrypt("value", purpose="account_token")
    assert ROTATED.decrypt(ciphertext, purpose="account_token") is None


def test_encryption_rotation() -> None:
    old_ciphertext = OLD_KIT.encrypt("value", purpose="account_token")
    assert ROTATED.decrypt(old_ciphertext, purpose="account_token") == "value"
    new_ciphertext = ROTATED.encrypt("value", purpose="account_token")
    assert KIT.decrypt(new_ciphertext, purpose="account_token") == "value"
    assert OLD_KIT.decrypt(new_ciphertext, purpose="account_token") is None
    assert KIT.decrypt(old_ciphertext, purpose="account_token") is None


@pytest.mark.parametrize(
    "text",
    ["", "v1", "v1..", "v1.AAAA.AAAA", "nonsense", "v1.!!!!!!!!!!!!!!!!.AAAA"],
)
def test_malformed_ciphertext_is_rejected(text: str) -> None:
    assert KIT.decrypt(text, purpose="account_token") is None


def test_derive_key_is_hkdf_of_the_first_secret() -> None:
    expected = hkdf_sha256(NEW.encode(), info=b"gotauth:app")
    assert ROTATED.derive_key("app") == expected
    assert len(ROTATED.derive_key("app", 64)) == 64
    assert ROTATED.derive_key("app") != ROTATED.derive_key("app2")
    assert ROTATED.derive_key("app", 16) == ROTATED.derive_key("app", 32)[:16]


@pytest.mark.parametrize("length", [0, -1, 255 * 32 + 1])
def test_derive_key_length_out_of_range(length: int) -> None:
    with pytest.raises(ValueError, match="length"):
        KIT.derive_key("app", length)


def test_purposes_get_separate_keys() -> None:
    # The signing key of a purpose is its own derived key, not the purpose's key.
    assert KIT.derive_key("sign:challenge") != KIT.derive_key("challenge")
    assert KIT.derive_key("encrypt") != KIT.derive_key("sign:encrypt")


@given(prefix=st.text(max_size=8), nbytes=st.integers(16, 128))
def test_random_token_format(prefix: str, nbytes: int) -> None:
    token = KIT.random_token(prefix, nbytes)
    assert token.startswith(prefix)
    body = token[len(prefix) :]
    assert re.fullmatch(r"[A-Za-z0-9_-]+", body)
    assert len(body) == -(-nbytes * 4 // 3)
    assert len(_decode(body)) == nbytes


def test_random_token_default_is_43_characters() -> None:
    assert len(random_token()) == 43
    assert re.fullmatch(r"gas_[A-Za-z0-9_-]{43}", KIT.random_token("gas_"))
    assert len({KIT.random_token() for _ in range(1000)}) == 1000


@pytest.mark.parametrize("nbytes", [0, 8, 15])
def test_random_token_refuses_short_tokens(nbytes: int) -> None:
    with pytest.raises(ValueError, match="nbytes"):
        KIT.random_token("gas_", nbytes)


@given(token=st.text())
def test_hash_token_is_sha256_hex(token: str) -> None:
    expected = hashlib.sha256(token.encode()).hexdigest()
    assert KIT.hash_token(token) == expected
    assert hash_token(token) == expected


@given(a=st.binary(), b=st.binary())
def test_equal_matches_byte_equality(a: bytes, b: bytes) -> None:
    assert KIT.equal(a, b) == (a == b)


def test_equal_compares_text_as_utf8() -> None:
    assert equal("caf\u00e9", "caf\u00e9".encode())
    assert equal("caf\u00e9".encode(), "caf\u00e9")
    assert not equal("cafe", "caf\u00e9")
    assert equal("", b"")


def test_equal_uses_compare_digest(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[bytes, bytes]] = []

    def spy(a: bytes, b: bytes) -> bool:
        calls.append((a, b))
        return a == b

    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert KIT.equal("a", "a")
    assert calls == [(b"a", b"a")]


def test_unsign_rejects_lone_surrogates_without_raising() -> None:
    surrogate = chr(0xD800)
    assert KIT.unsign(f"{surrogate}.abc", purpose="challenge") is None
    assert KIT.unsign(f"ok.{surrogate}", purpose="challenge") is None
    assert not KIT.equal(surrogate, "x")
