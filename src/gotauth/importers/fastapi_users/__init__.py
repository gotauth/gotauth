"""Importer for users and accounts from fastapi-users (work package I1)::

    gotauth import fastapi-users --auth app.auth:auth --dry-run
    gotauth import fastapi-users --auth app.auth:auth --report import.json

or from Python::

    from gotauth.importers.fastapi_users import import_fastapi_users

    report = await import_fastapi_users(auth, dry_run=True)
"""

from __future__ import annotations

from gotauth.importers.fastapi_users._cli import main
from gotauth.importers.fastapi_users._importer import (
    ImportRefused,
    ImportReport,
    Problem,
    import_fastapi_users,
)

__all__ = ["ImportRefused", "ImportReport", "Problem", "import_fastapi_users", "main"]
