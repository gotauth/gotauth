"""Check that the GotAuth plan can be executed by parallel agents.

Run after any edit to docs/plan (standard library only):

    python docs/plan/tools/verify_plan.py

Checks:
1. Every work package in the README table has a brief, and every brief is in the table.
2. No two work packages have overlapping write scopes (except the documented exclusions).
3. The README schedule starts every work package only after its hard dependencies merge,
   and work packages running in the same week in different slots never share a write scope.
4. Plugins call each other only through the CONTRACTS 12.5 endpoint ids.
5. Writing style: ASCII only, no em or en dashes.
"""
from __future__ import annotations

import itertools
import pathlib
import re
import sys

PLAN = pathlib.Path(__file__).resolve().parents[1]
WP_DIR = PLAN / "wp"
problems: list[str] = []

# Hard dependencies: must be merged before the work package starts. Testing-kit ("soft")
# dependencies are left out on purpose. Keep in sync with the "Depends on" rows of the briefs.
HARD: dict[str, list[str]] = {
    "F2": ["F1"], "F3": ["F1"], "G1": [], "R1": [],
    "C1": ["F2", "F3"], "C2": ["F2", "F3"], "C3": ["F2", "F3"], "C4": ["F2", "F3"],
    "S1": ["F2", "F3"], "D1": ["F2", "F3"], "D2a": ["F2"], "P1": ["F2", "F3"], "G3": ["F1"],
    "A1": ["C1", "C2", "C3"], "A2": ["C1"], "O1": ["C1", "C2", "C3"],
    "G4a": ["A1", "S1", "C4", "P1", "D2a"], "Q1": ["C1", "C2", "C3", "C4", "S1"],
    "P2": ["C1", "C2", "C3"], "P3": ["C1", "C3"], "P4": ["C1", "C3", "D1"], "P5": ["C3", "A1", "D1"],
    "P6": ["C1", "C3"], "O2": ["O1"], "O3": ["P1", "O1"], "I1": ["S1", "F3"],
    "G2": ["A1", "A2", "S1"], "D2b": ["P1", "P2", "P3", "P5", "O1"], "G4b": ["G4a", "P2", "P3", "P5"],
    "Q2": ["G4a", "G4b", "G2", "O2"], "G5": ["G3", "G4a", "O2"],
}
# Intentional, documented scope exclusions.
ALLOWED_OVERLAPS = {frozenset({"O3", "O4"}), frozenset({"G5", "R1"}), frozenset({"G5", "Q2"})}
PHASE_4_5 = {"O4", "E1", "A3", "S2", "B1", "X"}


def base(wp: str) -> str:
    return re.sub(r"[ab]$", "", wp)


# ------------------------------------------------------------------ 1. table vs briefs
readme = (PLAN / "README.md").read_text(encoding="utf-8")
table_files = set(re.findall(r"\(wp/([A-Za-z0-9-]+\.md)\)", readme))
disk_files = {p.name for p in WP_DIR.glob("*.md")}
for f in sorted(table_files - disk_files):
    problems.append(f"table links a missing brief: {f}")
for f in sorted(disk_files - table_files):
    problems.append(f"brief not in the README table: {f}")
briefs = {p.name.split("-")[0].removesuffix(".md"): p.read_text(encoding="utf-8") for p in sorted(WP_DIR.glob("*.md"))}

# ------------------------------------------------------------------ 2. write scopes
def scopes(text: str) -> list[str]:
    m = re.search(r"^\| Write scope \| (.*) \|\s*$", text, re.M)
    if not m:
        return []
    return [p.rstrip("/") for p in re.findall(r"`([^`]+)`", m.group(1))
            if not p.startswith("src/gotauth/**/__init__.py") and " " not in p and not p.startswith("<")]


def overlaps(a: str, b: str) -> bool:
    if "*" in a.split("/")[-1] or "*" in b.split("/")[-1]:
        ra, rb = (re.escape(x).replace(r"\*", ".*") for x in (a, b))
        return bool(re.fullmatch(ra, b.replace("*", "X")) or re.fullmatch(rb, a.replace("*", "X")))
    na, nb = (x.replace("/**", "").replace("**", "").rstrip("/") for x in (a, b))
    return na == nb or na.startswith(nb + "/") or nb.startswith(na + "/")


scope_map = {k: scopes(v) for k, v in briefs.items()}
for k, v in scope_map.items():
    if not v:
        problems.append(f"{k}: no write scope found")
for (a, sa), (b, sb) in itertools.combinations(scope_map.items(), 2):
    if frozenset({a, b}) in ALLOWED_OVERLAPS:
        continue
    for x in sa:
        for y in sb:
            if overlaps(x, y):
                problems.append(f"write scopes overlap: {a} `{x}` and {b} `{y}`")

# ------------------------------------------------------------------ 3. schedule
ALIASES = {"D2 part 1": "D2a", "D2 part 2": "D2b", "G4 part 1": "G4a", "G4 part 2": "G4b"}
sched_rows = re.findall(r"^\| (\d+)(?: \([^)]*\))? \| (.*) \|\s*$", readme, re.M)
items: list[tuple[str, int, int, int]] = []  # (wp, week, slot, order)
for week_s, rest in sched_rows:
    week = int(week_s)
    for slot, cell in enumerate(rest.split(" | "), start=1):
        order = 0
        for part in cell.split("->"):
            name = re.sub(r"\*\*[^*]+\*\*", "", part)
            name = re.sub(r"\([^)]*\)", "", name).strip()
            for alias, wp in ALIASES.items():
                name = name.replace(alias, wp)
            for wp in re.findall(r"\b([A-Z]\d[ab]?)\b", name):
                items.append((wp, week, slot, order))
                order += 1
# A work package listed in several weeks runs from its first to its last week.
span: dict[str, tuple[int, int, int, int]] = {}
for wp, week, slot, order in items:
    if wp in span:
        s, _, sl, o = span[wp]
        span[wp] = (s, week, sl if week == s else slot, o if week == s else order)
    else:
        span[wp] = (week, week, slot, order)
first_pos = {wp: (week, slot, order) for wp, week, slot, order in reversed(items)}
last_pos = {wp: (week, slot, order) for wp, week, slot, order in items}
SAME_WEEK_AFTER = {("F3", "F1")}  # "(after F1) F3": F1 is size S
for wp, deps in HARD.items():
    if wp not in first_pos:
        problems.append(f"{wp} is not in the schedule")
        continue
    w_week, w_slot, w_order = first_pos[wp]
    for d in deps:
        if d not in last_pos:
            problems.append(f"{wp} depends on {d}, which is not scheduled")
            continue
        d_week, d_slot, d_order = last_pos[d]
        ok = d_week < w_week or (d_week == w_week and d_slot == w_slot and d_order < w_order) or (wp, d) in SAME_WEEK_AFTER
        if not ok:
            problems.append(f"schedule: {wp} starts in week {w_week} before {d} (last in week {d_week}) has merged")
v01 = {base(k) for k in HARD} | {base(k) for k in briefs if k not in PHASE_4_5}
for wp in sorted(v01 - {base(w) for w, *_ in items}):
    problems.append(f"v0.1 work package {wp} is missing from the schedule")
for (w1, wk1, sl1, _), (w2, wk2, sl2, _) in itertools.combinations(items, 2):
    if wk1 == wk2 and sl1 != sl2 and base(w1) != base(w2) and frozenset({base(w1), base(w2)}) not in ALLOWED_OVERLAPS:
        for x in scope_map.get(base(w1), []):
            for y in scope_map.get(base(w2), []):
                if overlaps(x, y):
                    problems.append(f"week {wk1}: {w1} and {w2} run in parallel and share `{x}`")

# ------------------------------------------------------------------ 4. cross-plugin calls
contracts = (PLAN / "CONTRACTS.md").read_text(encoding="utf-8")
start = contracts.index("### 12.5 Cross-plugin calls")
section = contracts[start:contracts.index("\n## ", start)]
allowed = set(re.findall(r"^\| `([a-z_]+)` \(", section, re.M))
for k, text in briefs.items():
    for call in re.findall(r"api\.call\(\s*\"([a-z_]+)\"", text):
        if call not in allowed:
            problems.append(f"{k} calls `{call}` through auth.api.call; not a CONTRACTS 12.5 id")

# ------------------------------------------------------------------ 5. style
for p in [*PLAN.rglob("*.md"), *PLAN.rglob("*.py")]:
    text = p.read_text(encoding="utf-8")
    for n, line in enumerate(text.splitlines(), 1):
        if any(ord(c) > 127 for c in line):
            problems.append(f"non-ASCII character: {p.relative_to(PLAN)}:{n}")

print(f"briefs: {len(briefs)}  scheduled items: {len(items)}  12.5 ids: {len(allowed)}")
if problems:
    print("PROBLEMS:")
    for line in problems:
        print(f"  - {line}")
    sys.exit(1)
print("PASS: briefs match the table, no scope overlaps, the schedule respects every hard dependency,")
print("      parallel cells never share files, and cross-plugin calls use CONTRACTS 12.5 ids.")
