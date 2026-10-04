"""Score tests: fixed examples and Hypothesis properties."""

from __future__ import annotations

from hypothesis import given
from hypothesis import strategies as st

from gotauth.checkup import RULES, Finding, Severity, score

SEVERITIES: list[Severity] = ["high", "medium", "low"]


def finding(rule_id: str, severity: Severity = "high", line: int = 1) -> Finding:
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path="app.py",
        line=line,
        column=1,
        end_line=line,
        end_column=2,
        message="message",
        hint="hint",
    )


findings_strategy = st.builds(
    finding,
    rule_id=st.sampled_from(sorted(RULES)),
    severity=st.sampled_from(SEVERITIES),
    line=st.integers(min_value=1, max_value=10_000),
)


def test_weights() -> None:
    assert score([]) == 100
    assert score([finding("GA001", "high")]) == 85
    assert score([finding("GA005", "medium")]) == 94
    assert score([finding("GA005", "low")]) == 98


def test_each_rule_counts_at_most_three_times() -> None:
    three = [finding("GA008", line=line) for line in range(3)]
    ten = [finding("GA008", line=line) for line in range(10)]
    assert score(three) == score(ten) == 55


def test_score_never_goes_below_zero() -> None:
    every_rule = [finding(rule_id, line=line) for rule_id in RULES for line in range(3)]
    assert score(every_rule) == 0


@given(st.lists(findings_strategy, max_size=80))
def test_score_stays_between_0_and_100(findings: list[Finding]) -> None:
    assert 0 <= score(findings) <= 100


@given(st.lists(findings_strategy, max_size=80), findings_strategy)
def test_adding_a_finding_never_raises_the_score(
    findings: list[Finding], extra: Finding
) -> None:
    assert score([*findings, extra]) <= score(findings)


@given(st.lists(findings_strategy, max_size=40))
def test_score_ignores_order(findings: list[Finding]) -> None:
    assert score(findings) == score(list(reversed(findings)))
