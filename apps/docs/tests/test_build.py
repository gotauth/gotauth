"""The built site has what agents and crawlers need (G2): llms.txt listing every page,
a Markdown copy of each, robots.txt and sitemap.xml; and the skill's front matter is
valid. Builds the site once into a temporary directory (needs the ``docs`` group)."""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

DOCS = Path(__file__).resolve().parents[1]
ROOT = DOCS.parents[1]
SITE_URL = "https://gotauth.ablacky.com/docs/"


@pytest.fixture(scope="module")
def site(tmp_path_factory: pytest.TempPathFactory) -> Path:
    pytest.importorskip("mkdocs", reason="the docs dependency group is not installed")
    out = tmp_path_factory.mktemp("site")
    subprocess.run(
        [
            sys.executable,
            "-m",
            "mkdocs",
            "build",
            "-q",
            "-f",
            str(DOCS / "mkdocs.yml"),
            "-d",
            str(out),
        ],
        check=True,
    )
    return out


def nav_pages(site: Path) -> set[str]:
    """Every page in the navigation, as the path of its Markdown copy."""
    sitemap = (site / "sitemap.xml").read_text(encoding="utf-8")
    pages = set()
    for url in re.findall(r"<loc>(.*?)</loc>", sitemap):
        path = url.removeprefix(SITE_URL).strip("/")
        if not path.startswith("reference/gotauth"):
            pages.add(f"{path}.md" if path else "index.md")
    return pages


def test_llms_txt_lists_every_page_and_each_copy_exists(site: Path) -> None:
    listed = set(
        re.findall(
            r"\]\(" + re.escape(SITE_URL) + r"([^)]+)\)",
            (site / "llms.txt").read_text(),
        )
    )
    assert listed == nav_pages(site)
    for path in listed:
        copy = site / path
        assert copy.is_file(), path
        assert "<!-- sample:" not in copy.read_text(encoding="utf-8"), path
    full = (site / "llms-full.txt").read_text(encoding="utf-8")
    assert "# Quickstart: FastAPI" in full


def test_crawlers_get_robots_and_a_sitemap(site: Path) -> None:
    robots = (site / "robots.txt").read_text(encoding="utf-8")
    assert "Allow: /" in robots and f"{SITE_URL}sitemap.xml" in robots
    assert (site / "sitemap.xml").is_file()


def test_every_page_has_the_copy_button_script(site: Path) -> None:
    assert (site / "js" / "copy-markdown.js").is_file()
    assert "copy-markdown.js" in (site / "quickstart" / "index.html").read_text(
        encoding="utf-8"
    )


def test_skill_front_matter() -> None:
    text = (ROOT / "skills" / "gotauth" / "SKILL.md").read_text(encoding="utf-8")
    match = re.match(r"^---\n(.*?)\n---\n", text, re.DOTALL)
    assert match, "SKILL.md must start with YAML front matter"
    import yaml

    meta = yaml.safe_load(match.group(1))
    assert set(meta) == {"name", "description"}
    # Agent Skills: lower-case letters, digits and hyphens; the folder's name.
    assert re.fullmatch(r"[a-z0-9-]{1,64}", meta["name"]) and meta["name"] == "gotauth"
    assert 0 < len(meta["description"]) <= 1024
