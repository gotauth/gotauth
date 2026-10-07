"""SQLAlchemy storage adapter and migration support (work package S1).

Needs the ``sqlalchemy`` extra plus ``postgres`` (asyncpg) or ``sqlite`` (aiosqlite).
"""

from __future__ import annotations

from ._adapter import SqlAlchemyAdapter, sqlalchemy_adapter
from ._schema import create_missing, missing_changes, schema_ddl
from ._tables import NAMING_CONVENTION, UtcDateTime, metadata_for

__all__ = [
    "NAMING_CONVENTION",
    "SqlAlchemyAdapter",
    "UtcDateTime",
    "create_missing",
    "metadata_for",
    "missing_changes",
    "schema_ddl",
    "sqlalchemy_adapter",
]
