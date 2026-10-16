"""Check the external links of the built site (``apps/docs/site``).

Internal links are checked by the strict build. This script requests every external
``http(s)`` link once, with retries, and fails on links that are gone (404, 410) or keep
failing. Sites that refuse robots (401, 403, 429) are reported, not failed. Run after
``mkdocs build``::

    ./dev.sh uv run --group docs python apps/docs/scripts/check_links.py
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

import httpx

SITE = Path(__file__).resolve().parents[1] / "site"
# Our own site is checked by the build and may not be deployed yet. Links into this
# repository on GitHub point to files that exist here (hooks.py builds them from the
# checkout), and a file added in the same pull request is not on main yet.
SKIP = (
    "https://gotauth.ablacky.com",
    "http://localhost",
    "https://localhost",
    "http://127.0.0.1",
    "https://github.com/gotauth/gotauth/blob/main/",
    "https://github.com/gotauth/gotauth/tree/main/",
)
REFUSED = {401, 403, 429}
RETRIES = 3

_HREF = re.compile(r'<a [^>]*href="(https?://[^"#]+)')


def links() -> set[str]:
    found: set[str] = set()
    for page in SITE.rglob("*.html"):
        for url in _HREF.findall(page.read_text(encoding="utf-8")):
            if not url.startswith(SKIP):
                found.add(url.replace("&amp;", "&"))
    return found


async def status(client: httpx.AsyncClient, url: str) -> int | None:
    for attempt in range(RETRIES):
        try:
            response = await client.get(url)
        except httpx.HTTPError:
            response = None
        if response is not None and response.status_code < 500:
            return response.status_code
        await asyncio.sleep(2**attempt)
    return None


async def check(urls: set[str]) -> int:
    limits = httpx.Limits(max_connections=8)
    headers = {
        "user-agent": "gotauth-docs-link-check (+https://github.com/gotauth/gotauth)"
    }
    async with httpx.AsyncClient(
        follow_redirects=True, timeout=20, limits=limits, headers=headers
    ) as client:
        results = await asyncio.gather(*(status(client, url) for url in sorted(urls)))
    failed = 0
    for url, code in zip(sorted(urls), results, strict=True):
        if code is None or code in (404, 410) or (code >= 400 and code not in REFUSED):
            sys.stdout.write(f"broken  {code}  {url}\n")
            failed += 1
        elif code in REFUSED:
            sys.stdout.write(f"refused {code}  {url} (not counted)\n")
    sys.stdout.write(f"{len(urls)} external links, {failed} broken\n")
    return failed


def main() -> int:
    if not SITE.is_dir():
        sys.stdout.write("build the site first: mkdocs build -f apps/docs/mkdocs.yml\n")
        return 2
    return 1 if asyncio.run(check(links())) else 0


if __name__ == "__main__":
    raise SystemExit(main())
