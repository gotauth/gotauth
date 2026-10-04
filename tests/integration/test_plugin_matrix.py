"""Every merged plugin builds with every other one (work package F2).

The test discovers each ``gotauth.plugins.<name>`` module that exports a ``<name>``
factory, then builds ``make_auth(plugins=[...])`` with all of them and with each pair.
A duplicate endpoint id or path, error code, schema field or cookie name fails here at
merge time. It never needs editing when a plugin lands. It is skipped until the core
(work package C1) exists, because ``make_auth`` needs ``GotAuth``.
"""

from __future__ import annotations

import importlib
import itertools
import pkgutil
from collections.abc import Callable
from typing import Any, cast

import pytest

import gotauth.plugins
from gotauth.contracts import Plugin
from gotauth.testing import make_auth


def discover() -> dict[str, Callable[[], Plugin]]:
    factories: dict[str, Callable[[], Plugin]] = {}
    for info in pkgutil.iter_modules(gotauth.plugins.__path__):
        module = importlib.import_module(f"gotauth.plugins.{info.name}")
        factory: Any = getattr(module, info.name, None)
        if callable(factory):
            factories[info.name] = cast("Callable[[], Plugin]", factory)
    return factories


FACTORIES = discover()


def build(names: tuple[str, ...]) -> None:
    try:
        make_auth(plugins=[FACTORIES[name]() for name in names])
    except NotImplementedError:
        pytest.skip("make_auth needs the core (work package C1)")


@pytest.mark.skipif(not FACTORIES, reason="no plugin has merged yet")
def test_all_plugins_together() -> None:
    build(tuple(sorted(FACTORIES)))


@pytest.mark.parametrize(
    "pair",
    list(itertools.combinations(sorted(FACTORIES), 2))
    or [pytest.param((), marks=pytest.mark.skip(reason="fewer than two plugins"))],
)
def test_plugin_pairs(pair: tuple[str, ...]) -> None:
    build(pair)
