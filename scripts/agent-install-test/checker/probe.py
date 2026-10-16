"""Behaviour checks, run with the app's own Python from the app's folder (check.py).

Prints one JSON line: a list of {name, passed, detail}. The app is found, not assumed:
the first FastAPI instance in ``app/main.py``, ``main.py`` or ``app/__init__.py``, and
the GotAuth instance in any of the app's modules.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import io
import json
import os
import re
import secrets
import sys
import tempfile
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlsplit

HERE = Path.cwd()
PASSWORD = "correct horse battery staple"  # noqa: S105 - a test account
EMAIL = "checker@example.com"
results: list[dict[str, Any]] = []


def record(name: str, passed: bool, detail: str = "") -> bool:
    results.append({"name": name, "passed": passed, "detail": detail[:500]})
    return passed


def dotenv_keys() -> set[str]:
    """Keys the app's own .env sets: the probe leaves those to the app."""
    path = HERE / ".env"
    if not path.is_file():
        return set()
    keys = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        name, sep, _ = line.strip().removeprefix("export ").partition("=")
        if sep and name and not name.startswith("#"):
            keys.add(name.strip())
    return keys


def environment() -> None:
    """The settings an app usually reads; set only when neither the environment nor
    the app's .env sets them."""
    work = tempfile.mkdtemp(prefix="checker-")
    own = dotenv_keys()
    defaults = {
        "GOTAUTH_SECRET": "checker-secret-" + "x" * 40,
        "SECRET_KEY": "checker-secret-" + "y" * 40,
        "GITHUB_CLIENT_ID": "checker-github-client",
        "GITHUB_CLIENT_SECRET": "checker-github-secret",
        "DATABASE_URL": f"sqlite+aiosqlite:///{work}/checker.db",
        "BASE_URL": "http://localhost:8000",
    }
    for key, value in defaults.items():
        if key not in own:
            os.environ.setdefault(key, value)


def find_app() -> tuple[Any, Any, str]:
    """(FastAPI app, GotAuth, "module:attr" of the GotAuth)."""
    from fastapi import FastAPI

    from gotauth import GotAuth

    sys.path.insert(0, str(HERE))
    app = None
    for name in ("app.main", "main", "app"):
        try:
            module = importlib.import_module(name)
        except ModuleNotFoundError as exc:
            if exc.name in (name, name.split(".")[0]):
                continue  # no such module: try the next place
            raise  # the app imports something that is not installed
        app = next((v for v in vars(module).values() if isinstance(v, FastAPI)), None)
        if app is not None:
            break
    if app is None:
        raise RuntimeError("no FastAPI app in app/main.py, main.py or app/__init__.py")
    for module_name, module in list(sys.modules.items()):
        path = getattr(module, "__file__", None) or ""
        if not path.startswith(str(HERE)) or ".venv" in path:
            continue
        for attr, value in vars(module).items():
            if isinstance(value, GotAuth):
                return app, value, f"{module_name}:{attr}"
    raise RuntimeError("no GotAuth instance in the app's modules")


async def probe() -> None:
    import httpx

    environment()
    try:
        app, auth, spec = find_app()
    except Exception as exc:  # every failure is a result
        record("the app starts", False, f"{type(exc).__name__}: {exc}")
        return
    record("the app starts", True, spec)

    from gotauth.cli import main as cli

    if type(auth.database).__name__ == "SqlAlchemyAdapter":
        # What the README says to run before starting the app.
        code = await asyncio.to_thread(cli, ["migrate", "--auth", spec])
        if code != 0:
            record(
                "the tables can be created",
                False,
                f"gotauth migrate exited with {code}",
            )
            return

    base = auth.config.base_path
    origin = auth.config.base_url.rstrip("/")
    transport = httpx.ASGITransport(app=app)
    # The app's startup and shutdown, as a server runs them.
    async with (
        app.router.lifespan_context(app),
        httpx.AsyncClient(
            transport=transport, base_url=origin, headers={"origin": origin}
        ) as client,
    ):
        await sign_up_and_in(client, base)
        await github(client, base)
        await api_key(client, base, app)


async def sign_up_and_in(client: Any, base: str) -> None:  # Any: httpx client
    body = {"email": EMAIL, "password": PASSWORD}
    console = io.StringIO()
    with contextlib.redirect_stderr(console):
        signed_up = await client.post(f"{base}/sign-up/email", json=body)
    if signed_up.status_code != 200:
        record("sign-up works", False, f"{signed_up.status_code} {signed_up.text}")
        return
    record("sign-up works", True)
    if signed_up.json().get("status") == "verification_sent":
        link = re.search(r"https?://\S+/verify-email\S*", console.getvalue())
        record(
            "the verification email has a link", bool(link), console.getvalue()[-300:]
        )
        if link is None:
            return
        url = urlsplit(link.group(0))
        await client.get(f"{url.path}?{url.query}")
    signed_in = await client.post(f"{base}/sign-in/email", json=body)
    record(
        "sign-in works",
        signed_in.status_code == 200 and "session" in signed_in.text,
        signed_in.text[:200],
    )


async def github(client: Any, base: str) -> None:  # Any: httpx client
    started = await client.post(
        f"{base}/sign-in/social", json={"provider": "github", "callback_url": "/"}
    )
    if started.status_code != 200:
        record("GitHub sign-in starts", False, f"{started.status_code} {started.text}")
        return
    url = urlsplit(started.json().get("url", ""))
    query = parse_qs(url.query)
    record(
        "GitHub sign-in starts",
        url.netloc == "github.com" and "state" in query and "code_challenge" in query,
        f"{url.netloc}{url.path} with {sorted(query)}",
    )


def protected_routes(app: Any, base: str) -> list[str]:  # Any: FastAPI
    paths = []
    for route in app.routes:
        path = getattr(route, "path", "")
        methods = getattr(route, "methods", set()) or set()
        if (
            "GET" in methods
            and "{" not in path
            and not path.startswith((base, "/docs", "/redoc", "/openapi"))
        ):
            paths.append(path)
    return paths


async def api_key(
    client: Any, base: str, app: Any
) -> None:  # Any: httpx client, FastAPI
    import httpx

    created = await client.post(f"{base}/api-keys", json={"name": "checker"})
    if created.status_code != 200:
        record(
            "an API key can be created", False, f"{created.status_code} {created.text}"
        )
        return
    key = created.json()["key"]
    record("an API key can be created", True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport, base_url=str(client.base_url)
    ) as script:
        for path in protected_routes(app, base):
            anonymous = await script.get(path)
            if anonymous.status_code not in (401, 403):
                continue
            keyed = await script.get(path, headers={"x-api-key": key})
            required = (
                keyed.json().get("error", {}).get("details", {})
                if keyed.status_code == 403
                else {}
            )
            if required and required.get("required"):
                # The route wants scopes: a key with them, as a user would create.
                scoped = await client.post(
                    f"{base}/api-keys",
                    json={"name": "checker-scoped", "scopes": required["required"]},
                )
                if scoped.status_code == 200:
                    keyed = await script.get(
                        path, headers={"x-api-key": scoped.json()["key"]}
                    )
            if keyed.status_code == 200:
                # A made-up key must not get in: the route checks the key itself, not
                # only that a header is there.
                bogus = await script.get(
                    path, headers={"x-api-key": "gak_" + secrets.token_urlsafe(32)}
                )
                if bogus.status_code not in (401, 403):
                    record(
                        "an API key gets through a protected route",
                        False,
                        f"{path} also accepted a made-up key ({bogus.status_code})",
                    )
                    return
                record("an API key gets through a protected route", True, path)
                return
        record(
            "an API key gets through a protected route",
            False,
            "no protected GET route accepted the key",
        )


def main() -> None:
    try:
        asyncio.run(probe())
    except Exception as exc:  # every failure is a result
        record("the checks ran", False, f"{type(exc).__name__}: {exc}")
    sys.stdout.write("\n" + json.dumps(results) + "\n")


if __name__ == "__main__":
    main()
