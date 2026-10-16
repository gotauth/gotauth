"""Fail when the quickstart is 15,000 tokens or more (G2: agents read it whole).

Counts the page's Markdown with tiktoken's ``o200k_base`` encoding. Run in the dev
container::

    ./dev.sh uv run --group docs python apps/docs/scripts/count_tokens.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

LIMIT = 15_000
ENCODING = "o200k_base"
PAGE = Path(__file__).resolve().parents[1] / "docs" / "quickstart.md"


def count(text: str) -> int:
    import tiktoken

    return len(tiktoken.get_encoding(ENCODING).encode(text))


def main() -> int:
    text = re.sub(
        r"^<!-- sample:.*-->\n", "", PAGE.read_text(encoding="utf-8"), flags=re.M
    )
    tokens = count(text)
    sys.stdout.write(f"quickstart: {tokens} tokens ({ENCODING}), limit {LIMIT}\n")
    return 0 if tokens < LIMIT else 1


if __name__ == "__main__":
    raise SystemExit(main())
