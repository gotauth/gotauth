"""Repository-wide pytest hooks.

Tests marked ``postgres`` or ``redis`` need a running service. They are skipped when the
service URL is not set, so the suite also runs outside the dev container. The dev
container (``compose.yaml``) and CI set both URLs.

Shared fixtures live in ``tests/conftest.py`` (work package F2), not here.
"""

from __future__ import annotations

import os

import pytest

SERVICE_MARKERS: dict[str, str] = {
    "postgres": "GOTAUTH_TEST_POSTGRES_URL",
    "redis": "GOTAUTH_TEST_REDIS_URL",
}


def pytest_collection_modifyitems(
    config: pytest.Config, items: list[pytest.Item]
) -> None:
    """Skip service tests whose service URL is not set."""
    for marker, variable in SERVICE_MARKERS.items():
        if os.environ.get(variable):
            continue
        skip = pytest.mark.skip(reason=f"{variable} is not set")
        for item in items:
            if item.get_closest_marker(marker) is not None:
                item.add_marker(skip)
