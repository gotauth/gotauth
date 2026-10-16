"""Check an app a coding agent changed: did it add auth with GotAuth, and does it work?

    python check.py APP_DIR [--python "uv run python"] [--json REPORT]

Static checks run here, with the standard library only:
- ``gotauth`` is a dependency in ``pyproject.toml``
- no ``passlib``, ``jose``, ``jwt``, ``bcrypt``, ``argon2`` or ``itsdangerous`` import,
  and no ``hashlib.pbkdf2_hmac`` or ``hashlib.scrypt`` call, in the app's code
- ``gotauth check`` finds nothing of high severity

Behaviour checks run in the app's own environment (``--python``), in ``probe.py``:
the app imports and starts; sign-up (with email verification if on) and sign-in work;
GitHub sign-in returns a GitHub authorize URL with ``state`` and ``code_challenge``; an
API key gets through a route that refuses anonymous callers. Then the app's own tests
run.

Exit code 0 when every check passed.
"""

from __future__ import annotations

import argparse
import ast
import json
import shlex
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
FORBIDDEN_IMPORTS = {"passlib", "jose", "jwt", "bcrypt", "argon2", "itsdangerous"}
FORBIDDEN_CALLS = {("hashlib", "pbkdf2_hmac"), ("hashlib", "scrypt")}
SKIP_DIRS = {".venv", "venv", "tests", "node_modules", "__pycache__", ".git", ".claude"}


@dataclass
class Check:
    name: str
    passed: bool
    detail: str = ""


def app_files(app_dir: Path) -> list[Path]:
    return [
        path
        for path in app_dir.rglob("*.py")
        if not SKIP_DIRS & set(path.relative_to(app_dir).parts)
    ]


def check_dependency(app_dir: Path) -> Check:
    pyproject = app_dir / "pyproject.toml"
    if not pyproject.is_file():
        return Check("gotauth is a dependency", False, "no pyproject.toml")
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    found = [
        dep
        for dep in deps
        if dep.split("[")[0].split(">")[0].split("=")[0].strip() == "gotauth"
    ]
    return Check("gotauth is a dependency", bool(found), ", ".join(found) or str(deps))


def check_imports(app_dir: Path) -> Check:
    problems: list[str] = []
    for path in app_files(app_dir):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            problems.append(f"{path.name}: does not parse ({exc.msg})")
            continue
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                names = [node.module]
            for name in names:
                if name.split(".")[0] in FORBIDDEN_IMPORTS:
                    problems.append(
                        f"{path.relative_to(app_dir)}:{node.lineno} imports {name}"
                    )
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Name)
                and (node.func.value.id, node.func.attr) in FORBIDDEN_CALLS
            ):
                problems.append(
                    f"{path.relative_to(app_dir)}:{node.lineno} calls "
                    f"{node.func.value.id}.{node.func.attr}"
                )
    return Check("no hand-written auth code", not problems, "; ".join(problems))


def run(
    python: list[str], args: list[str], cwd: Path, timeout: int = 600
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - the checker's own commands
        [*python, *args],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def check_gotauth_check(app_dir: Path, python: list[str]) -> Check:
    done = run(
        python, ["-m", "gotauth.checkup", ".", "--json", "--exclude", "tests"], app_dir
    )
    try:
        report = json.loads(done.stdout)
    except json.JSONDecodeError:
        return Check("gotauth check: no high findings", False, done.stderr[-500:])
    high = [
        f"{f['rule_id']} {f['path']}:{f['line']}"
        for f in report["findings"]
        if f["severity"] == "high"
    ]
    return Check(
        "gotauth check: no high findings",
        not high,
        f"score {report['score']}; " + "; ".join(high),
    )


def check_behaviour(app_dir: Path, python: list[str]) -> list[Check]:
    done = run(python, [str(HERE / "probe.py")], app_dir)
    try:
        results = json.loads(done.stdout.strip().splitlines()[-1])
    except (json.JSONDecodeError, IndexError):
        return [Check("the app starts", False, (done.stderr or done.stdout)[-1500:])]
    return [Check(**item) for item in results]


def check_app_tests(app_dir: Path, python: list[str]) -> Check:
    done = run(python, ["-m", "pytest", "-q", "-p", "no:cacheprovider"], app_dir)
    tail = (done.stdout + done.stderr).strip().splitlines()[-1:] or [""]
    return Check("the app's own tests pass", done.returncode == 0, tail[0])


def check(app_dir: Path, python: list[str]) -> list[Check]:
    results = [check_dependency(app_dir), check_imports(app_dir)]
    results.append(check_gotauth_check(app_dir, python))
    results += check_behaviour(app_dir, python)
    results.append(check_app_tests(app_dir, python))
    return results


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("app_dir", type=Path)
    parser.add_argument(
        "--python", default="uv run python", help="how to run the app's Python"
    )
    parser.add_argument("--json", type=Path, help="write the results here")
    args = parser.parse_args(argv)
    results = check(args.app_dir.resolve(), shlex.split(args.python))
    for item in results:
        mark = "PASS" if item.passed else "FAIL"
        sys.stdout.write(
            f"{mark}  {item.name}"
            + (f"  ({item.detail})" if item.detail else "")
            + "\n"
        )
    if args.json:
        args.json.write_text(
            json.dumps([asdict(item) for item in results], indent=2) + "\n"
        )
    return 0 if all(item.passed for item in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
