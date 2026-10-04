"""Shared fixtures wrapping the testing kit (work package F2; frozen at M0).

Work packages add their own fixtures in ``tests/<area>/conftest.py``, never here.
"""

from __future__ import annotations

import pytest

from gotauth.contracts import Adapter
from gotauth.testing import (
    CapturingMailer,
    FakeContext,
    ManualClock,
    fake_clock,
    fake_mailer,
    make_context,
    memory_adapter,
)


@pytest.fixture
def clock() -> ManualClock:
    """A fake clock starting at 2026-01-01 00:00 UTC."""
    return fake_clock()


@pytest.fixture
def mailer() -> CapturingMailer:
    """A mailer that records every message in ``.sent``."""
    return fake_mailer()


@pytest.fixture
def adapter() -> Adapter:
    """An empty memory adapter (``make_context`` binds its schema)."""
    return memory_adapter()


@pytest.fixture
def ctx(clock: ManualClock, mailer: CapturingMailer, adapter: Adapter) -> FakeContext:
    """An endpoint context with fakes for every service and the core schema bound."""
    return make_context(clock=clock, mailer=mailer, adapter=adapter)
