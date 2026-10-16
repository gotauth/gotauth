"""Summarize an agent-install test (run.sh calls it): checker results, auth lines added,
libraries added, the model, the CLI version and the date. Only measured values.

    python report.py RESULTS_DIR --cli-version "2.1.287 (Claude Code)" --mode skill
    python report.py RESULTS_DIR ... --write docs/launch/agent-baseline.md
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

# The default prompt of run.sh.
PROMPT = "Add email + password and GitHub login and API keys to this FastAPI app."


@dataclass
class Run:
    name: str
    checks: list[dict[str, object]] = field(default_factory=list)
    auth_lines: int = 0
    added_dependencies: list[str] = field(default_factory=list)
    model: str = "unknown"

    @property
    def passed(self) -> bool:
        return bool(self.checks) and all(bool(c["passed"]) for c in self.checks)


def read_run(path: Path) -> Run:
    run = Run(path.name)
    report = path / "check.json"
    if report.is_file():
        run.checks = json.loads(report.read_text())
    diff = path / "diff.patch"
    if diff.is_file():
        current = ""
        for line in diff.read_text(errors="replace").splitlines():
            if line.startswith("+++ "):
                current = line[4:]
            elif line.startswith("+") and not line.startswith("+++"):
                body = line[1:].strip()
                # Code lines in the app's Python files, not tests or blank lines.
                if (
                    current.endswith(".py")
                    and "/tests/" not in current
                    and body
                    and not body.startswith("#")
                ):
                    run.auth_lines += 1
                if current.endswith("pyproject.toml"):
                    match = re.match(r'"([A-Za-z0-9_.\-\[\],]+)', body)
                    if match:
                        run.added_dependencies.append(match.group(1))
    transcript = path / "transcript.jsonl"
    if transcript.is_file():
        for line in transcript.read_text(errors="replace").splitlines():
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("type") == "system" and event.get("model"):
                run.model = str(event["model"])
                break
    return run


def render(runs: list[Run], mode: str, cli_version: str, prompt: str = PROMPT) -> str:
    date = datetime.now(UTC).strftime("%Y-%m-%d")
    passed = sum(run.passed for run in runs)
    baseline = mode == "baseline"
    command = "run.sh --baseline" if baseline else "run.sh"
    model = runs[0].model if runs else "unknown"
    with_skill = (
        "without GotAuth's skill or llms.txt"
        if baseline
        else "with GotAuth's skill and llms.txt"
    )
    lines = [
        f"# Agent-install {'baseline' if baseline else 'test'} ({date})",
        "",
        f"Measured by `scripts/agent-install-test/{command}` on {date}: Claude Code "
        f"{cli_version}, model {model}, the prompt {prompt!r} {with_skill}.",
        "",
        f"**{passed} of {len(runs)} runs passed the checker.**",
        "",
        "| Run | Checker | Lines of app code added | Libraries added |",
        "|---|---|---|---|",
    ]
    for run in runs:
        failed = [str(c["name"]) for c in run.checks if not c["passed"]]
        verdict = (
            "pass"
            if run.passed
            else ("failed: " + ", ".join(failed) if failed else "no result")
        )
        deps = ", ".join(f"`{d}`" for d in run.added_dependencies) or "none"
        lines.append(f"| {run.name} | {verdict} | {run.auth_lines} | {deps} |")
    lines += [
        "",
        "Lines of app code: added non-blank, non-comment lines in the app's Python "
        "files, tests excluded.",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("results", type=Path)
    parser.add_argument("--cli-version", default="unknown")
    parser.add_argument("--mode", choices=["skill", "baseline"], default="skill")
    parser.add_argument("--write", type=Path)
    parser.add_argument("--prompt", default=PROMPT, help="the prompt run.sh used")
    args = parser.parse_args(argv)
    runs = [
        read_run(path) for path in sorted(args.results.glob("run-*")) if path.is_dir()
    ]
    text = render(runs, args.mode, args.cli_version, args.prompt)
    sys.stdout.write(text)
    (args.results / "summary.md").write_text(text)
    if args.write:
        args.write.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
