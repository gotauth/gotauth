"""``make_auth`` and ``make_client``: HTTP round trips through the real core (C1)."""

from __future__ import annotations

import importlib
from typing import Any, cast

import httpx

from gotauth.contracts.config import AdvancedConfig, GotAuthInstance
from gotauth.contracts.protection import normalize_origin
from gotauth.storage.memory import memory_adapter
from gotauth.testing._clock import fake_clock, seq_ids
from gotauth.testing._context import TEST_BASE_URL, TEST_SECRET
from gotauth.testing._mail import fake_mailer

__all__ = ["make_auth", "make_client"]


def _gotauth_class() -> Any:  # Any: C1's class; contracts and the kit cannot import it
    module = importlib.import_module("gotauth.core")
    cls = getattr(module, "GotAuth", None)
    if cls is None:
        msg = "TODO(C1): make_auth() needs gotauth.core.GotAuth (work package C1)"
        raise NotImplementedError(msg)
    return cls


def make_auth(**overrides: Any) -> GotAuthInstance:  # Any: GotAuth(...) keywords
    """Build a real ``GotAuth`` for tests.

    Defaults: ``memory_adapter()``, secret ``"test-secret-" * 4``, base_url
    ``"http://localhost:8000"``, a fake mailer as ``email_sender`` and a fake clock and
    sequential ids in ``advanced``. Every ``GotAuth`` keyword can be overridden. Three
    extra keywords are shortcuts: ``clock``, ``ids`` (put into ``advanced``) and
    ``mailer`` (the ``email_sender``); keep a reference to them to drive the test.

    Raises:
        NotImplementedError: Until work package C1 has merged.
    """
    cls = _gotauth_class()
    clock = overrides.pop("clock", None) or fake_clock()
    ids = overrides.pop("ids", None) or seq_ids()
    mailer = overrides.pop("mailer", None) or fake_mailer()
    advanced = overrides.pop("advanced", None)
    if isinstance(advanced, AdvancedConfig):
        options = {name: getattr(advanced, name) for name in advanced.model_fields_set}
    else:
        options = dict(cast("dict[str, Any] | None", advanced) or {})
    options.setdefault("clock", clock)
    options.setdefault("ids", ids)
    kwargs: dict[str, Any] = {
        "database": memory_adapter(),
        "secret": TEST_SECRET,
        "base_url": TEST_BASE_URL,
        "email_sender": mailer,
        "advanced": options,
    }
    kwargs.update(overrides)
    return cast("GotAuthInstance", cls(**kwargs))


async def _json_by_default(request: httpx.Request) -> None:
    # Set only when missing, so data= (forms) and files= keep their own content type.
    if "content-type" not in request.headers:
        request.headers["content-type"] = "application/json"


def make_client(auth: GotAuthInstance) -> httpx.AsyncClient:
    """Return an httpx client over ``auth.asgi()``, rooted at ``base_url + base_path``.

    It keeps cookies, sends ``Origin: <base_url origin>`` and ``Content-Type:
    application/json`` unless the request sets another content type. The ASGI scope has
    ``root_path = base_path``. Use it as ``async with make_client(auth) as client:``.
    """
    config = auth.config
    base = config.base_url.rstrip("/")
    return httpx.AsyncClient(
        transport=httpx.ASGITransport(app=auth.asgi(), root_path=config.base_path),
        base_url=base + config.base_path,
        headers={"origin": normalize_origin(base) or base},
        event_hooks={"request": [_json_by_default]},
    )
