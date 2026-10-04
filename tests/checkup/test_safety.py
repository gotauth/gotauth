"""Safety tests: no network, no imports of scanned code, robust parsing, speed."""

from __future__ import annotations

import json
import socket
import subprocess
import sys
import time
from pathlib import Path
from typing import NoReturn

import pytest

from gotauth.checkup import main, scan

FIXTURES = Path(__file__).parent / "fixtures"


def _no_network(*args: object, **kwargs: object) -> NoReturn:
    raise AssertionError("gotauth check tried to use the network")


@pytest.mark.parametrize("output", [[], ["--json"], ["--sarif"]])
def test_no_network(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    output: list[str],
) -> None:
    monkeypatch.setattr(socket, "socket", _no_network)
    monkeypatch.setattr(socket, "create_connection", _no_network)
    monkeypatch.setattr(socket, "getaddrinfo", _no_network)
    assert main([str(FIXTURES), *output]) == 0
    assert capsys.readouterr().out


def test_scanned_code_is_never_imported() -> None:
    bomb = FIXTURES / "import_bomb" / "explode.py"
    report = scan([bomb])
    assert report.files_scanned == 1
    assert report.skipped == ()
    # The import after the raise is found, so the file was read and parsed.
    assert [finding.rule_id for finding in report.findings] == ["GA001"]
    assert not any("explode" in name for name in sys.modules)


def test_unparsable_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "a_syntax.py").write_text("def broken(:\n    pass\n")
    (tmp_path / "b_latin1.py").write_bytes(
        b"# -*- coding: latin-1 -*-\nname = '\xe9'\n"
    )
    (tmp_path / "c_null.py").write_bytes(b"x = 1\x00\n")
    (tmp_path / "d_nested.py").write_text("x = " + "(" * 2000 + "1" + ")" * 2000 + "\n")
    (tmp_path / "e_ok.py").write_text("import passlib\n")
    (tmp_path / "f_bom.py").write_bytes(b"\xef\xbb\xbfimport jose\n")
    report = scan([tmp_path])
    assert [item.path.rsplit("/", 1)[-1] for item in report.skipped] == [
        "a_syntax.py",
        "b_latin1.py",
        "c_null.py",
        "d_nested.py",
    ]
    assert report.skipped[1].reason == "not valid UTF-8"
    assert report.files_scanned == 2
    assert [finding.rule_id for finding in report.findings] == ["GA001", "GA002"]


def test_large_files_are_skipped(tmp_path: Path) -> None:
    (tmp_path / "generated.py").write_bytes(b"x = 1\n" * (1024 * 1024))
    report = scan([tmp_path])
    assert report.files_scanned == 0
    assert [item.reason for item in report.skipped] == ["larger than 5 MiB"]


def test_folder_named_like_a_module_is_walked_not_read(tmp_path: Path) -> None:
    (tmp_path / "pkg.py").mkdir()
    (tmp_path / "pkg.py" / "inner.py").write_text("import passlib\n")
    report = scan([tmp_path])
    assert report.files_scanned == 1
    assert report.skipped == ()


def test_import_loads_only_the_standard_library() -> None:
    fixture = FIXTURES / "sample_app"
    code = (
        "import io, json, sys\n"
        "before = set(sys.modules)\n"
        "import gotauth.checkup\n"
        "out, sys.stdout = sys.stdout, io.StringIO()\n"
        f"for argv in ([{str(fixture)!r}], [{str(fixture)!r}, '--json'],"
        f" [{str(fixture)!r}, '--sarif']):\n"
        "    gotauth.checkup.main(argv)\n"
        "sys.stdout = out\n"
        "new = sorted(set(sys.modules) - before)\n"
        "allowed = set(sys.stdlib_module_names) | {'gotauth'}\n"
        "print(json.dumps([n for n in new if n.split('.')[0] not in allowed]))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, check=True
    )
    assert json.loads(result.stdout) == []


def _generated_module(index: int) -> str:
    """About 200 lines of auth-like code that exercises every rule's code path."""
    block = (
        "import hashlib\n"
        "import hmac\n"
        "import os\n"
        "\n"
        "import jwt\n"
        "import requests\n"
        "\n"
        'SECRET_KEY = os.environ["SECRET_KEY"]\n'
        "\n"
        "\n"
        "class Service{n}{i}:\n"
        '    """Generated."""\n'
        "\n"
        "    def __init__(self, client):\n"
        "        self.client = client\n"
        "        self.cache = {{}}\n"
        "\n"
        "    def token_{n}_{i}(self, user_id, scopes):\n"
        '        payload = {{"sub": user_id, "scopes": list(scopes), "n": {i}}}\n'
        '        payload["exp"] = 3600 + {i}\n'
        '        return jwt.encode(payload, SECRET_KEY, algorithm="HS256")\n'
        "\n"
        "    def check_{n}_{i}(self, token, body, signature):\n"
        '        claims = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])\n'
        "        key = SECRET_KEY.encode()\n"
        "        digest = hmac.new(key, body, hashlib.sha256).hexdigest()\n"
        "        if not hmac.compare_digest(digest, signature):\n"
        "            return None\n"
        "        values = [value * 2 for value in range({i}) if value % 3 == 0]\n"
        '        response = self.client.get("https://example.com", timeout=5)\n'
        '        return claims.get("sub"), values, response.status_code == 200\n'
        "\n"
    )
    module = "".join(block.format(n=index, i=i) for i in range(7))
    return module


def test_ten_thousand_lines_scan_in_under_two_seconds(tmp_path: Path) -> None:
    lines = 0
    index = 0
    while lines < 10_000:
        source = _generated_module(index)
        (tmp_path / f"module_{index:03d}.py").write_text(source)
        lines += source.count("\n")
        index += 1
    start = time.perf_counter()
    report = scan([tmp_path])
    elapsed = time.perf_counter() - start
    assert report.files_scanned == index
    assert report.skipped == ()
    assert report.findings == ()
    assert elapsed < 2.0, f"{lines} lines took {elapsed:.2f}s"
