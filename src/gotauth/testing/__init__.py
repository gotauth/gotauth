"""Testing kit for GotAuth and for apps that use it (CONTRACTS section 15).

Unit-test an endpoint before the request pipeline exists::

    from gotauth.testing import call_endpoint, make_context

    ctx = make_context()
    result = await call_endpoint(my_endpoint, {"email": "ada@example.com"}, ctx=ctx)

HTTP round trips through ``make_auth()`` / ``make_client()`` need the core (work
package C1). Everything here imports with the core dependencies only; pytest and the
other dev tools are imported inside the functions that need them.
"""

from __future__ import annotations

from gotauth.storage.memory import memory_adapter
from gotauth.testing._auth import make_auth, make_client
from gotauth.testing._clock import (
    DEFAULT_START,
    ManualClock,
    SeqIds,
    fake_clock,
    seq_ids,
)
from gotauth.testing._conformance import CONFORMANCE_SCHEMA, adapter_conformance
from gotauth.testing._context import (
    TEST_BASE_URL,
    TEST_SCRYPT,
    TEST_SECRET,
    FakeApi,
    FakeAuth,
    FakeContext,
    SignInCall,
    call_endpoint,
    make_context,
    make_request,
)
from gotauth.testing._database import fresh_database_url
from gotauth.testing._mail import CapturingMailer, PassThroughEmailService, fake_mailer
from gotauth.testing._oauth import StubOAuthProvider, fake_oauth_provider
from gotauth.testing._sessions import FakeSessionService, fake_sessions
from gotauth.testing._stubs import (
    StubCall,
    StubPlugin,
    StubResolver,
    stub_plugin,
    stub_resolver,
)
from gotauth.testing._vectors import find_spec_dir, load_vectors

__all__ = [
    "CONFORMANCE_SCHEMA",
    "DEFAULT_START",
    "TEST_BASE_URL",
    "TEST_SCRYPT",
    "TEST_SECRET",
    "CapturingMailer",
    "FakeApi",
    "FakeAuth",
    "FakeContext",
    "FakeSessionService",
    "ManualClock",
    "PassThroughEmailService",
    "SeqIds",
    "SignInCall",
    "StubCall",
    "StubOAuthProvider",
    "StubPlugin",
    "StubResolver",
    "adapter_conformance",
    "call_endpoint",
    "fake_clock",
    "fake_mailer",
    "fake_oauth_provider",
    "fake_sessions",
    "find_spec_dir",
    "fresh_database_url",
    "load_vectors",
    "make_auth",
    "make_client",
    "make_context",
    "make_request",
    "memory_adapter",
    "seq_ids",
    "stub_plugin",
    "stub_resolver",
]
