"""Spec vector loading (CONTRACTS section 15)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, cast

__all__ = ["find_spec_dir", "load_vectors"]


def find_spec_dir(start: Path | None = None) -> Path:
    """Return the ``spec/`` folder, walking up from ``start`` (default: the CWD).

    Args:
        start: Where to start looking.

    Returns:
        The first ``spec`` directory found in ``start`` or one of its parents.

    Raises:
        FileNotFoundError: If no parent has a ``spec`` directory.
    """
    here = (start or Path.cwd()).resolve()
    for folder in (here, *here.parents):
        candidate = folder / "spec"
        if candidate.is_dir():
            return candidate
    msg = f"no spec/ directory in {here} or its parents"
    raise FileNotFoundError(msg)


def load_vectors(
    name: str, *, start: Path | None = None
) -> list[dict[str, Any]]:  # Any: JSON
    """Read the cases of ``spec/<name>.json``.

    Args:
        name: File name without ``.json``, for example ``"totp"``.
        start: Where to start looking for ``spec/`` (default: the CWD).

    Returns:
        The list of cases in the file.

    Raises:
        FileNotFoundError: If the file does not exist.
        ValueError: If the file is not a JSON list of objects.
    """
    path = find_spec_dir(start) / f"{name}.json"
    cases: object = json.loads(path.read_text(encoding="utf-8"))
    items = cast("list[object]", cases) if isinstance(cases, list) else None
    if items is None or not all(isinstance(case, dict) for case in items):
        msg = f"{path} must hold a JSON list of objects"
        raise ValueError(msg)
    return cast("list[dict[str, Any]]", items)
