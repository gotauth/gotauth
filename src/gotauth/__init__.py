"""GotAuth: open-source auth for Python AI backends.

The main names load lazily from the top-level package, so ``import gotauth`` is cheap
and needs no optional extras::

    from gotauth import AuthError, GotAuth, Principal, Session, User
"""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # The ignores cover the time before work packages F2 and C1 define these names.
    # They are harmless afterwards and the integrator may drop them.
    from gotauth.contracts import (
        AuthError,  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType]
        Principal,  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType]
        Session,  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType]
        User,  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType]
    )
    from gotauth.core import (
        GotAuth,  # pyright: ignore[reportAttributeAccessIssue, reportUnknownVariableType]
    )

__version__ = "0.0.1"

__all__ = ["AuthError", "GotAuth", "Principal", "Session", "User", "__version__"]

# Public name -> module that defines it (CONTRACTS 13.2).
_LAZY_EXPORTS: dict[str, str] = {
    "AuthError": "gotauth.contracts",
    "GotAuth": "gotauth.core",
    "Principal": "gotauth.contracts",
    "Session": "gotauth.contracts",
    "User": "gotauth.contracts",
}


def __getattr__(name: str) -> Any:  # Any: the type depends on the requested name.
    module_name = _LAZY_EXPORTS.get(name)
    if module_name is None:
        msg = f"module {__name__!r} has no attribute {name!r}"
        raise AttributeError(msg)
    value = getattr(importlib.import_module(module_name), name)
    # Cache the value so the import runs once per name.
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted({*globals(), *_LAZY_EXPORTS})
