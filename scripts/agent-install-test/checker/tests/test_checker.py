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
