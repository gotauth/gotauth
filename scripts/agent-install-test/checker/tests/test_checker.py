"""The checker fails a hand-rolled app and passes a correct GotAuth app (Q2)."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from check import check

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    # The probe sets its own defaults only for variables that are not set.
    for name in ("DATABASE_URL", "BASE_URL", "GOTAUTH_SECRET"):
        monkeypatch.delenv(name, raising=False)


def test_a_correct_gotauth_app_passes() -> None:
    results = check(FIXTURES / "good_app", [sys.executable])
    failed = [f"{r.name}: {r.detail}" for r in results if not r.passed]
    assert not failed, failed
    names = {r.name for r in results}
    assert {
        "sign-in works",
        "GitHub sign-in starts",
        "an API key gets through a protected route",
        "the app's own tests pass",
    } <= names


def test_a_hand_rolled_app_fails() -> None:
    results = {r.name: r for r in check(FIXTURES / "bad_app", [sys.executable])}
    assert not results["gotauth is a dependency"].passed
    detail = results["no hand-written auth code"].detail
    assert not results["no hand-written auth code"].passed
    assert "passlib" in detail and "jose" in detail
    assert not results["gotauth check: no high findings"].passed
    assert not results["the app starts"].passed


def test_static_checks_see_through_aliases_and_ignore_relative_imports() -> None:
    import ast

    from check import forbidden_in, requirement_name

    code = """
import hashlib as h
from hashlib import pbkdf2_hmac
from pwdlib import PasswordHash
from authlib.jose import jwt
from .jwt import decode  # the app's own module: fine
h.scrypt(b"pw", salt=b"s", n=2, r=8, p=1)
"""
    found = [what for _line, what in forbidden_in(ast.parse(code))]
    assert "imports hashlib.pbkdf2_hmac" in found
    assert "imports pwdlib" in found
    assert "imports authlib.jose" in found
    assert "uses hashlib.scrypt" in found
    assert not any("jwt" in what and "authlib" not in what for what in found)
    for requirement in (
        "gotauth~=0.0.1",
        "gotauth<1",
        "GotAuth[fastapi]>=0.0.1",
        "gotauth @ file:///wheels/gotauth-0.0.1-py3-none-any.whl",
        "gotauth; python_version>='3.12'",
    ):
        assert requirement_name(requirement) == "gotauth", requirement
