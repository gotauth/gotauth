"""Alembic revisions for GotAuth's tables, leaving every other table alone."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from alembic.autogenerate import produce_migrations, render_python_code
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import JSON, Connection, MetaData
from sqlalchemy.ext.asyncio import AsyncEngine

from gotauth.contracts.schema import Schema
from gotauth.storage.sqlalchemy import UtcDateTime, metadata_for

__all__ = ["write_revision"]

_IMPORTS = "from sqlalchemy.dialects import postgresql"


def _render_item(type_: str, obj: Any, _: Any) -> str | bool:  # Any: alembic objects
    # The UTC decorator is GotAuth's; in the migration it is a plain zone-aware column.
    if type_ == "type" and isinstance(obj, UtcDateTime):
        return "sa.DateTime(timezone=True)"
    if type_ == "type" and isinstance(obj, JSON):
        # Alembic renders the JSONB variant with an unprefixed Text(); spell it out.
        return 'sa.JSON().with_variant(postgresql.JSONB(), "postgresql")'
    return False


def _owner_table(obj: Any) -> str | None:  # Any: a schema item
    table = getattr(obj, "table", None)
    if table is not None:
        return str(table.name)
    name = getattr(obj, "name", None)
    return str(name) if name is not None else None


def _diff(conn: Connection, metadata: MetaData) -> tuple[str, str] | None:
    ours = set(metadata.tables)

    def include_name(name: str | None, type_: str, _: Any) -> bool:  # Any: parent names
        return type_ != "table" or name in ours

    def include_object(
        obj: Any, name: str | None, type_: str, *_: Any
    ) -> bool:  # Any: items
        if type_ == "table":
            return name in ours
        return _owner_table(obj) in ours

    context = MigrationContext.configure(
        conn,
        opts={
            "target_metadata": metadata,
            "include_name": include_name,
            "include_object": include_object,
            "compare_type": True,
            "render_as_batch": conn.dialect.name == "sqlite",
        },
    )
    operations = produce_migrations(context, metadata)
    if operations.upgrade_ops is None or operations.upgrade_ops.is_empty():
        return None
    options: dict[str, Any] = {
        "render_item": _render_item,
        "render_as_batch": conn.dialect.name == "sqlite",
        "migration_context": context,
    }
    upgrade = render_python_code(operations.upgrade_ops, **options)
    downgrade = render_python_code(operations.downgrade_ops, **options)  # pyright: ignore[reportArgumentType]
    return upgrade, downgrade


async def write_revision(
    engine: AsyncEngine,
    schema: Schema,
    *,
    table_prefix: str,
    config_file: Path,
    message: str,
    rev_id: str,
) -> Path | None:
    """Write a revision with the changes from the database to ``schema``.

    Returns:
        The new file, or ``None`` when there is nothing to change.
    """
    metadata = metadata_for(schema, table_prefix=table_prefix)
    try:
        async with engine.connect() as conn:
            rendered = await conn.run_sync(_diff, metadata)
    finally:
        await engine.dispose()
    if rendered is None:
        return None
    upgrade, downgrade = rendered
    scripts = ScriptDirectory.from_config(Config(str(config_file)))
    script = scripts.generate_revision(
        rev_id,
        message,
        head="head",
        imports=_IMPORTS,
        upgrades=upgrade,
        downgrades=downgrade,
    )
    return Path(script.path) if script is not None else None
