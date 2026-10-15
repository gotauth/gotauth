"""Write ``registry/openapi.json``: the HTTP API of GotAuth with every plugin.

The typed client in ``src/lib/gotauth-client.ts`` is checked against it (``pnpm
check`` generates types from it with openapi-typescript), and
``tests/registry/test_openapi.py`` fails when this file is out of date, so a change on
either side shows up as a failing check.

Run in the dev container::

    ./dev.sh uv run python registry/scripts/export_openapi.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

OUTPUT = Path(__file__).resolve().parents[1] / "openapi.json"


def build_openapi() -> dict[str, Any]:  # Any: JSON values
    """The OpenAPI document of a GotAuth app with every plugin, mounted at
    ``/api/auth``."""
    from fastapi import FastAPI

    from gotauth import GotAuth
    from gotauth.plugins.admin import admin
    from gotauth.plugins.agent import agent
    from gotauth.plugins.api_key import api_key
    from gotauth.plugins.magic_link import email_otp, magic_link
    from gotauth.plugins.oauth_provider import oauth_provider
    from gotauth.plugins.organization import organization
    from gotauth.plugins.passkey import passkey
    from gotauth.plugins.two_factor import two_factor
    from gotauth.social import github
    from gotauth.storage.memory import memory_adapter
    from gotauth.testing import fake_mailer

    auth = GotAuth(
        database=memory_adapter(),
        secret="openapi-export-secret-" * 2,
        base_url="http://localhost:3000",
        base_path="/api/auth",
        email_sender=fake_mailer(),
        # A placeholder: the export only reads the routes.
        social_providers=[github(client_id="id", client_secret="unused")],  # noqa: S106
        plugins=[
            api_key(),
            two_factor(email_otp=True),
            passkey(),
            magic_link(),
            email_otp(),
            organization(),
            oauth_provider(),
            agent(),
            admin(),
        ],
    )
    app = FastAPI(title="GotAuth", version="0")
    app.include_router(auth.fastapi.router(), prefix="/api/auth")
    return app.openapi()


def render() -> str:
    """The file content: sorted keys, so the output is stable."""
    return json.dumps(build_openapi(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    OUTPUT.write_text(render(), encoding="utf-8")
    sys.stdout.write(f"wrote {OUTPUT}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
