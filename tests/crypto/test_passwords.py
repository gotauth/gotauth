"""Password hashing: formats, rehash detection, the unknown-user path and threads."""

from __future__ import annotations

import asyncio
import importlib.util
import re
import sys
import time

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gotauth.crypto import ConfigError, PasswordCheck, _passwords, crypto_kit
from gotauth.crypto._passwords import (
    DEFAULT_SCRYPT,
    PasswordHasher,
    ScryptParams,
    format_scrypt,
    scrypt_derive,
)

SECRET = "password-tests-secret-0123456789abcdef"
KIT = crypto_kit(SECRET)
SCRYPT_FORMAT = re.compile(
    r"scrypt\$ln=15,r=8,p=3\$[A-Za-z0-9+/]{22}\$[A-Za-z0-9+/]{86}"
)
HAS_ARGON2 = importlib.util.find_spec("argon2") is not None
HAS_BCRYPT = importlib.util.find_spec("bcrypt") is not None
needs_argon2 = pytest.mark.skipif(not HAS_ARGON2, reason="argon2 extra not installed")
needs_bcrypt = pytest.mark.skipif(not HAS_BCRYPT, reason="bcrypt extra not installed")


def low_cost_scrypt(password: str, params: ScryptParams) -> str:
    salt = bytes(range(16))
    return format_scrypt(
        params, salt, scrypt_derive(password.encode(), salt, params, 64)
    )


async def test_hash_password_format() -> None:
    stored = await KIT.hash_password("correct horse battery staple")
    assert SCRYPT_FORMAT.fullmatch(stored)
    assert await KIT.verify_password("correct horse battery staple", stored) == (
        PasswordCheck(ok=True, needs_rehash=False)
    )


async def test_every_hash_has_a_fresh_salt() -> None:
    first = await KIT.hash_password("same password")
    second = await KIT.hash_password("same password")
    assert first != second
    assert first.split("$")[2] != second.split("$")[2]


@pytest.mark.slow
@settings(max_examples=5, deadline=None)
@given(password=st.text(max_size=64), other=st.text(max_size=64))
def test_hash_verify_round_trip(password: str, other: str) -> None:
    async def run() -> None:
        stored = await KIT.hash_password(password)
        assert await KIT.verify_password(password, stored) == PasswordCheck(
            ok=True, needs_rehash=False
        )
        expected = PasswordCheck(ok=other == password, needs_rehash=False)
        assert await KIT.verify_password(other, stored) == expected

    asyncio.run(run())


async def test_lower_cost_hash_needs_rehash() -> None:
    stored = low_cost_scrypt("pw", ScryptParams(ln=10, r=8, p=1))
    assert await KIT.verify_password("pw", stored) == PasswordCheck(
        ok=True, needs_rehash=True
    )
    # needs_rehash is only ever set together with ok.
    assert await KIT.verify_password("wrong", stored) == PasswordCheck(
        ok=False, needs_rehash=False
    )


async def test_unknown_user_runs_the_full_hash(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[ScryptParams, int]] = []

    def spy(password: bytes, salt: bytes, params: ScryptParams, length: int) -> bytes:
        calls.append((params, length))
        return scrypt_derive(password, salt, params, length)

    monkeypatch.setattr(_passwords, "scrypt_derive", spy)
    check = await KIT.verify_password("any password", "")
    assert check == PasswordCheck(ok=False, needs_rehash=False)
    assert calls == [(DEFAULT_SCRYPT, 64)]


@pytest.mark.parametrize(
    "stored",
    [
        "pbkdf2_sha256$600000$c2FsdA$aGFzaA",
        "scrypt$ln=21,r=8,p=1$AAECAwQFBgcICQoLDA0ODw$" + "A" * 86,
        "scrypt$ln=15,r=8,p=1$not base64$x",
        "no tag at all",
        "$2b$12$abcdefghijklmnopqrstuughE8Ev8uGFaUgY2cNEySvxngrb/Jzdm",
    ],
)
async def test_malformed_hash_also_runs_the_full_hash(
    stored: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls: list[ScryptParams] = []

    def spy(password: bytes, salt: bytes, params: ScryptParams, length: int) -> bytes:
        calls.append(params)
        return scrypt_derive(password, salt, params, length)

    monkeypatch.setattr(_passwords, "scrypt_derive", spy)
    assert await KIT.verify_password("pw", stored) == PasswordCheck(
        ok=False, needs_rehash=False
    )
    assert calls == [DEFAULT_SCRYPT]


@pytest.mark.slow
async def test_unknown_user_takes_comparable_time() -> None:
    stored = await KIT.hash_password("correct horse battery staple")

    async def timed(stored_hash: str) -> float:
        start = time.perf_counter()
        await KIT.verify_password("wrong password", stored_hash)
        return time.perf_counter() - start

    ratios: list[float] = []
    # Other containers share the machine, so one noisy round may retry. The fastest
    # of several interleaved runs estimates the work itself, not the noise.
    for _ in range(3):
        real: list[float] = []
        dummy: list[float] = []
        for _ in range(5):
            real.append(await timed(stored))
            dummy.append(await timed(""))
        ratios.append(min(dummy) / min(real))
        if 1 / 3 < ratios[-1] < 3:
            return
    pytest.fail(f"dummy/real time ratios {[round(r, 2) for r in ratios]}")


async def test_hashing_does_not_block_the_event_loop() -> None:
    ticks = 0
    stop = asyncio.Event()

    async def ticker() -> None:
        nonlocal ticks
        while not stop.is_set():
            ticks += 1
            await asyncio.sleep(0.001)

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0)
    before = ticks
    await KIT.hash_password("correct horse battery staple")
    await KIT.verify_password("correct horse battery staple", "")
    during = ticks - before
    stop.set()
    await task
    # scrypt at ln=15 takes tens of milliseconds; a blocked loop would not tick.
    assert during >= 5, f"the ticker ran only {during} times"


async def test_password_that_is_not_unicode() -> None:
    with pytest.raises(ValueError, match="not valid Unicode") as info:
        await KIT.hash_password("bad \ud800 password")
    assert "\ud800" not in str(info.value)
    stored = await KIT.hash_password("good password")
    assert await KIT.verify_password("bad \ud800 password", stored) == PasswordCheck(
        ok=False, needs_rehash=False
    )


def test_password_check_is_frozen() -> None:
    check = PasswordCheck(ok=True, needs_rehash=False)
    with pytest.raises(AttributeError):
        check.ok = False  # pyright: ignore[reportAttributeAccessIssue]


@needs_bcrypt
async def test_passlib_bcrypt_hash_over_72_bytes() -> None:
    import bcrypt

    password = "a long passphrase that goes on and on " * 3  # 114 bytes
    # passlib's bcrypt handler hashed only the first 72 bytes, without an error.
    passlib_hash = bcrypt.hashpw(password.encode()[:72], bcrypt.gensalt(4)).decode()
    stored = "bcrypt$" + passlib_hash
    assert await KIT.verify_password(password, stored) == PasswordCheck(
        ok=True, needs_rehash=True
    )
    assert await KIT.verify_password(password[:71], stored) == PasswordCheck(
        ok=False, needs_rehash=False
    )


def test_missing_bcrypt_extra_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "bcrypt", None)
    stored = "bcrypt$$2b$04$abcdefghijklmnopqrstuughE8Ev8uGFaUgY2cNEySvxngrb/Jzdm"
    with pytest.raises(ConfigError, match=r"gotauth\[bcrypt\]"):
        PasswordHasher().verify("password", stored)


def test_missing_argon2_extra_is_a_config_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "argon2", None)
    with pytest.raises(ConfigError, match=r"gotauth\[argon2\]"):
        crypto_kit(SECRET, password_algorithm="argon2id")
    stored = "argon2id$$argon2id$v=19$m=8192,t=1,p=1$AAECAwQFBgcICQoLDA0ODw$" + "A" * 43
    with pytest.raises(ConfigError, match=r"gotauth\[argon2\]"):
        PasswordHasher().verify("password", stored)


@needs_argon2
async def test_argon2id_configuration() -> None:
    kit = crypto_kit(SECRET, password_algorithm="argon2id")
    assert kit.password_algorithm == "argon2id"
    stored = await kit.hash_password("correct horse battery staple")
    assert stored.startswith("argon2id$$argon2id$v=19$m=65536,t=3,p=4$")
    assert await kit.verify_password("correct horse battery staple", stored) == (
        PasswordCheck(ok=True, needs_rehash=False)
    )
    assert await kit.verify_password("wrong", stored) == PasswordCheck(
        ok=False, needs_rehash=False
    )
    # Switching algorithms: each side asks to rehash the other's hashes.
    assert await KIT.verify_password("correct horse battery staple", stored) == (
        PasswordCheck(ok=True, needs_rehash=True)
    )
    scrypt_stored = await KIT.hash_password("pw")
    assert await kit.verify_password("pw", scrypt_stored) == PasswordCheck(
        ok=True, needs_rehash=True
    )


@needs_argon2
async def test_argon2id_unknown_user_runs_argon2(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import argon2

    kit = crypto_kit(SECRET, password_algorithm="argon2id")
    calls: list[str | bytes] = []
    real = argon2.PasswordHasher.hash

    def spy(
        self: argon2.PasswordHasher, password: str | bytes, **kwargs: object
    ) -> str:
        calls.append(password)
        return real(self, password)

    monkeypatch.setattr(argon2.PasswordHasher, "hash", spy)
    assert await kit.verify_password("pw", "") == PasswordCheck(
        ok=False, needs_rehash=False
    )
    assert calls == [b"pw"]


@needs_argon2
async def test_argon2id_lower_cost_needs_rehash() -> None:
    import argon2

    weak = argon2.PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
    stored = "argon2id$" + weak.hash("pw")
    kit = crypto_kit(SECRET, password_algorithm="argon2id")
    assert await kit.verify_password("pw", stored) == PasswordCheck(
        ok=True, needs_rehash=True
    )
