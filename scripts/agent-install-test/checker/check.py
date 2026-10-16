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
import re
import shlex
import subprocess
import sys
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

HERE = Path(__file__).resolve().parent
# Libraries for hashing passwords or making tokens by hand: an app on GotAuth needs
# none of them.
FORBIDDEN_IMPORTS = {
    "passlib",
    "pwdlib",
    "jose",
    "jwt",
    "joserfc",
    "jwcrypto",
    "authlib",
    "bcrypt",
    "argon2",
    "itsdangerous",
}
# Password key derivation from the standard library, however it is imported.
FORBIDDEN_HASHLIB = {"pbkdf2_hmac", "scrypt"}
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
    found = [dep for dep in deps if requirement_name(dep) == "gotauth"]
    return Check("gotauth is a dependency", bool(found), ", ".join(found) or str(deps))


def requirement_name(requirement: str) -> str:
    """The normalized project name of a requirement string (PEP 503)."""
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    return re.sub(r"[-_.]+", "-", match.group(1)).lower() if match else ""


def forbidden_in(tree: ast.AST) -> list[tuple[int, str]]:
    """(line, what) for each import or call of hand-rolled auth tooling."""
    found: list[tuple[int, str]] = []
    hashlib_names = {"hashlib"}  # names bound to the hashlib module
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name.split(".")[0] in FORBIDDEN_IMPORTS:
                    found.append((node.lineno, f"imports {alias.name}"))
                if alias.name == "hashlib" and alias.asname:
                    hashlib_names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            if node.module.split(".")[0] in FORBIDDEN_IMPORTS:
                found.append((node.lineno, f"imports {node.module}"))
            if node.module == "hashlib":
                for alias in node.names:
                    if alias.name in FORBIDDEN_HASHLIB:
                        found.append((node.lineno, f"imports hashlib.{alias.name}"))
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in hashlib_names
            and node.attr in FORBIDDEN_HASHLIB
        ):
            found.append((node.lineno, f"uses hashlib.{node.attr}"))
    return found


def check_imports(app_dir: Path) -> Check:
    problems: list[str] = []
    for path in app_files(app_dir):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError as exc:
            problems.append(f"{path.name}: does not parse ({exc.msg})")
            continue
        for line, what in forbidden_in(tree):
            problems.append(f"{path.relative_to(app_dir)}:{line} {what}")
    return Check("no hand-written auth code", not problems, "; ".join(problems))


def run(
    python: list[str], args: list[str], cwd: Path, timeout: int = 600
) -> subprocess.CompletedProcess[str]:
    """Run a command; a timeout is a failed command (exit code 124), not a crash."""
    try:
        return subprocess.run(  # noqa: S603 - the checker's own commands
            [*python, *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(
            [*python, *args], 124, "", f"timed out after {timeout}s"
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
