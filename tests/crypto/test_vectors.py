"""Spec vectors (spec/*.json): every case must pass byte for byte."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from gotauth.crypto import (
    PasswordCheck,
    crypto_kit,
    hash_token,
    hkdf_sha256,
    hotp,
    pkce_s256,
)
from gotauth.crypto._encoding import b32_decode_lenient
from gotauth.crypto._keys import Secret, encrypt_with_key
from gotauth.crypto._passwords import ScryptParams, scrypt_derive
from gotauth.crypto._tokens import encode_token
from gotauth.crypto._ulid import UlidGenerator

pytestmark = pytest.mark.vectors

SPEC = Path(__file__).resolve().parents[2] / "spec"
SPEC_FILES = [
    "encrypt",
    "hkdf",
    "hotp",
    "password-hash",
    "pkce",
    "sign",
    "token-format",
    "totp",
]
# Any secret works for the cases that do not depend on one.
ANY_SECRET = "spec-vector-tests-secret-0123456789"


# TODO(F2): switch to gotauth.testing.load_vectors after merge.
def load_vectors(name: str) -> list[dict[str, Any]]:
    """Read spec/<name>.json."""
    cases = json.loads((SPEC / f"{name}.json").read_text(encoding="utf-8"))
    assert isinstance(cases, list)
    return cases


def cases(name: str, kind: str | None = None) -> list[Any]:
    """Return the cases of one file (and kind) as pytest params with readable ids."""
    selected = [
        case for case in load_vectors(name) if kind is None or case.get("kind") == kind
    ]
    return [
        pytest.param(case, id=f"{index}-{case.get('comment', case['source'])}")
        for index, case in enumerate(selected)
    ]


@pytest.mark.parametrize("name", SPEC_FILES)
def test_file_is_a_list_of_sourced_cases(name: str) -> None:
    raw = (SPEC / f"{name}.json").read_bytes()
    assert raw.isascii(), "spec files are ASCII; use JSON escapes"
    loaded = load_vectors(name)
    assert loaded, "every spec file has cases"
    for case in loaded:
        assert isinstance(case, dict)
        assert isinstance(case["source"], str) and case["source"]


def test_every_json_file_is_listed() -> None:
    assert sorted(path.stem for path in SPEC.glob("*.json")) == SPEC_FILES


@pytest.mark.parametrize("case", cases("hotp"))
def test_hotp(case: dict[str, Any]) -> None:
    key = bytes.fromhex(case["secret_hex"])
    assert key == case["secret_ascii"].encode("ascii")
    assert b32_decode_lenient(case["secret_b32"]) == key
    mac = hmac.new(key, case["counter"].to_bytes(8, "big"), hashlib.sha1).hexdigest()
    assert mac == case["hmac_sha1_hex"]
    assert int(case["truncated_hex"], 16) == case["truncated_decimal"]
    assert hotp(key, case["counter"], digits=case["digits"]) == case["hotp"]
    # The same code through the public TOTP API: counter n is the step at n * 30 s.
    at = datetime.fromtimestamp(case["counter"] * 30, UTC)
    kit = crypto_kit(ANY_SECRET)
    assert kit.totp(case["secret_b32"], at=at) == case["hotp"]


@pytest.mark.parametrize("case", cases("totp"))
def test_totp(case: dict[str, Any]) -> None:
    kit = crypto_kit(ANY_SECRET)
    at = datetime.fromtimestamp(case["unix_time"], UTC)
    assert at == datetime.fromisoformat(case["utc"])
    step = case["unix_time"] // case["period"]
    assert f"{step:016X}" == case["time_step_hex"]
    code = kit.totp(
        case["secret_b32"], at=at, digits=case["digits"], period=case["period"]
    )
    assert code == case["totp"]
    assert kit.verify_totp(case["secret_b32"], code, at=at, digits=8) == step
    # 6-digit codes are the last 6 digits of the 8-digit ones (two_factor uses 6).
    assert kit.totp(case["secret_b32"], at=at) == case["totp"][-6:]
    assert kit.verify_totp(case["secret_b32"], case["totp"][-6:], at=at) == step


@pytest.mark.parametrize("case", cases("pkce"))
def test_pkce(case: dict[str, Any]) -> None:
    kit = crypto_kit(ANY_SECRET)
    if case["challenge"] is None:
        with pytest.raises(ValueError, match="RFC 7636"):
            kit.pkce_s256(case["verifier"])
    else:
        assert kit.pkce_s256(case["verifier"]) == case["challenge"]
        assert pkce_s256(case["verifier"]) == case["challenge"]


@pytest.mark.parametrize("case", cases("hkdf", "rfc5869"))
def test_hkdf_rfc5869(case: dict[str, Any]) -> None:
    ikm = bytes.fromhex(case["ikm_hex"])
    salt = bytes.fromhex(case["salt_hex"])
    info = bytes.fromhex(case["info_hex"])
    # HKDF-Extract with the standard library, to check the vector itself.
    prk = hmac.new(salt or bytes(32), ikm, hashlib.sha256).hexdigest()
    assert prk == case["prk_hex"]
    okm = hkdf_sha256(ikm, info=info, length=case["length"], salt=salt or None)
    assert okm.hex() == case["okm_hex"]


@pytest.mark.parametrize("case", cases("hkdf", "derive_key"))
def test_derive_key(case: dict[str, Any]) -> None:
    assert ("gotauth:" + case["purpose"]).encode().hex() == case["info_hex"]
    kit = crypto_kit(case["secret"])
    assert kit.derive_key(case["purpose"], case["length"]).hex() == case["okm_hex"]


@pytest.mark.parametrize("case", cases("sign", "sign"))
def test_sign(case: dict[str, Any]) -> None:
    kit = crypto_kit(case["secrets"])
    assert kit.sign(case["value"], purpose=case["purpose"]) == case["signed"]
    assert kit.unsign(case["signed"], purpose=case["purpose"]) == case["value"]


@pytest.mark.parametrize("case", cases("sign", "unsign"))
def test_unsign(case: dict[str, Any]) -> None:
    kit = crypto_kit(case["secrets"])
    assert kit.unsign(case["signed"], purpose=case["purpose"]) == case["value"]


@pytest.mark.parametrize("case", cases("encrypt", "encrypt"))
def test_encrypt(case: dict[str, Any], monkeypatch: pytest.MonkeyPatch) -> None:
    nonce = bytes.fromhex(case["nonce_hex"])
    kit = crypto_kit(case["secrets"])
    key = Secret(kit.derive_key("encrypt"))
    assert (
        encrypt_with_key(key, nonce, case["plaintext"], case["purpose"])
        == (case["ciphertext"])
    )

    # The public method with its random nonce pinned to the vector's.
    def fixed_nonce(size: int) -> bytes:
        assert size == len(nonce)
        return nonce

    monkeypatch.setattr(secrets, "token_bytes", fixed_nonce)
    assert kit.encrypt(case["plaintext"], purpose=case["purpose"]) == case["ciphertext"]
    assert kit.decrypt(case["ciphertext"], purpose=case["purpose"]) == case["plaintext"]


@pytest.mark.parametrize("case", cases("encrypt", "decrypt"))
def test_decrypt(case: dict[str, Any]) -> None:
    kit = crypto_kit(case["secrets"])
    assert kit.decrypt(case["ciphertext"], purpose=case["purpose"]) == case["plaintext"]


@pytest.mark.parametrize("case", cases("password-hash", "scrypt"))
def test_scrypt_rfc7914(case: dict[str, Any]) -> None:
    n = case["n"]
    params = ScryptParams(ln=n.bit_length() - 1, r=case["r"], p=case["p"])
    assert params.n == n
    key = scrypt_derive(
        case["password"].encode(), case["salt"].encode(), params, case["dk_len"]
    )
    assert key.hex() == case["derived_key_hex"]


@pytest.mark.parametrize("case", cases("password-hash", "verify"))
async def test_verify_password(case: dict[str, Any]) -> None:
    if "requires" in case:
        pytest.importorskip(case["requires"])
    kit = crypto_kit(ANY_SECRET)
    check = await kit.verify_password(case["password"], case["stored"])
    assert check == PasswordCheck(ok=case["ok"], needs_rehash=case["needs_rehash"])


@pytest.mark.parametrize("case", cases("token-format", "token"))
def test_token_format(case: dict[str, Any]) -> None:
    pattern = re.compile(case["regex"])
    kit = crypto_kit(ANY_SECRET)
    for _ in range(50):
        token = kit.random_token(case["prefix"], case["nbytes"])
        assert pattern.fullmatch(token)
        assert len(token) == len(case["prefix"]) + case["body_length"]
    _check_examples(case)


@pytest.mark.parametrize("case", cases("token-format", "token_encoding"))
def test_token_encoding(case: dict[str, Any]) -> None:
    raw = bytes.fromhex(case["random_hex"])
    assert encode_token(case["prefix"], raw) == case["token"]


@pytest.mark.parametrize("case", cases("token-format", "hash_token"))
def test_hash_token(case: dict[str, Any]) -> None:
    assert hash_token(case["token"]) == case["sha256_hex"]
    assert crypto_kit(ANY_SECRET).hash_token(case["token"]) == case["sha256_hex"]


@pytest.mark.parametrize("case", cases("token-format", "otp"))
def test_otp_format(case: dict[str, Any]) -> None:
    pattern = re.compile(case["regex"])
    kit = crypto_kit(ANY_SECRET)
    for _ in range(200):
        assert pattern.fullmatch(kit.new_otp(case["digits"]))
    _check_examples(case)


@pytest.mark.parametrize("case", cases("token-format", "totp_secret"))
def test_totp_secret_format(case: dict[str, Any]) -> None:
    pattern = re.compile(case["regex"])
    kit = crypto_kit(ANY_SECRET)
    for _ in range(50):
        secret = kit.new_totp_secret()
        assert pattern.fullmatch(secret)
        assert len(b32_decode_lenient(secret)) == case["nbytes"]
    _check_examples(case)


@pytest.mark.parametrize("case", cases("token-format", "ulid"))
def test_ulid_format(case: dict[str, Any]) -> None:
    pattern = re.compile(case["regex"])
    kit = crypto_kit(ANY_SECRET)
    at = datetime(2026, 10, 4, tzinfo=UTC)
    for _ in range(50):
        assert pattern.fullmatch(kit.new_ulid(at))
    _check_examples(case)


@pytest.mark.parametrize("case", cases("token-format", "ulid_time"))
def test_ulid_time(case: dict[str, Any]) -> None:
    at = datetime.fromisoformat(case["at"])
    since_epoch = at - datetime(1970, 1, 1, tzinfo=UTC)
    assert since_epoch // timedelta(milliseconds=1) == case["unix_ms"]
    assert UlidGenerator().new(at)[:10] == case["time_part"]


def _check_examples(case: dict[str, Any]) -> None:
    pattern = re.compile(case["regex"])
    for example in case.get("valid_examples", []):
        assert pattern.fullmatch(example), example
    for example in case.get("invalid_examples", []):
        assert not pattern.fullmatch(example), example


def test_independent_crosscheck() -> None:
    """Node's crypto (and crypt(3) through Perl) recompute every vector."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not installed")
    result = subprocess.run(
        [node, str(SPEC / "crosscheck.mjs")],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "0 mismatches" in result.stdout
