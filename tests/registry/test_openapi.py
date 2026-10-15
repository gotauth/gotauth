"""``registry/openapi.json`` matches the backend (D2 part 2).

The typed client in ``registry/`` is type-checked against that file, so this test
and ``pnpm check`` together catch drift between the UI and the API.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "registry" / "scripts" / "export_openapi.py"


def test_openapi_json_is_up_to_date() -> None:
    spec = importlib.util.spec_from_file_location("export_openapi", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    committed = (ROOT / "registry" / "openapi.json").read_text(encoding="utf-8")
    assert committed == module.render(), (
        "registry/openapi.json is out of date: run "
        "`./dev.sh uv run python registry/scripts/export_openapi.py` and check that "
        "`./dev.sh pnpm --dir registry run typecheck` still passes"
    )
