"""FastAPI integration (work package A1): ``auth.fastapi``.

Needs the ``fastapi`` extra. Importing this package does not import FastAPI; the
integration loads on first use of ``auth.fastapi``.
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

from gotauth.contracts.errors import ConfigError

if TYPE_CHECKING:
    from ._integration import FastAPIIntegration, OAuthErrorOut

__all__ = ["FastAPIIntegration", "OAuthErrorOut"]


def __getattr__(name: str) -> Any:  # Any: the lazily loaded class
    if name not in __all__:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    try:
        module = importlib.import_module("gotauth.integrations.fastapi._integration")
    except ModuleNotFoundError as exc:
        if exc.name in {"fastapi", "starlette"}:
            msg = 'auth.fastapi needs the fastapi extra: pip install "gotauth[fastapi]"'
            raise ConfigError(msg) from exc
        raise
    return getattr(module, name)
