"""The code constants match the tables in docs/plan/CONTRACTS.md.

These tests parse the document itself, so a change to either side fails here.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from gotauth.contracts import (
    AUTH_EVENT_TYPES,
    COOKIE_NAMES,
    CORE_ENDPOINTS,
    CORE_SCHEMA,
    CROSS_PLUGIN_CALLS,
    CRYPTO_PURPOSES,
    DEFAULT_RATE_LIMITS,
    ERROR_CODES,
    ID_PREFIXES,
    PLUGIN_ENDPOINTS,
    TOKEN_PREFIXES,
)

CONTRACTS = (Path(__file__).resolve().parents[2] / "docs/plan/CONTRACTS.md").read_text(
    encoding="utf-8"
)


def section(start: str, end: str) -> str:
    return CONTRACTS[CONTRACTS.index(start) : CONTRACTS.index(end)]


def literal(name: str) -> list[str]:
    block = CONTRACTS[CONTRACTS.index(f"{name} = Literal[") :]
    block = block[: block.index("]")]
    return re.findall(r'"([^"]+)"', block)


def first_column_ids(text: str) -> list[str]:
    ids: list[str] = []
    for line in text.splitlines():
        if line.startswith("| `"):
            cell = line.split("|")[1]
            ids.extend(re.findall(r"`([a-z_]+)`", cell))
    return ids


def test_id_prefixes() -> None:
    assert list(ID_PREFIXES) == literal("IdPrefix")


def test_error_codes() -> None:
    rows = re.findall(r"^\| `([A-Z_]+)` \| (\d{3}) \|", section("## 6.", "## 7."), re.M)
    assert {code: status for code, (status, _) in ERROR_CODES.items()} == {
        code: int(status) for code, status in rows
    }
    assert "UNSUPPORTED_MEDIA_TYPE" in ERROR_CODES


def test_event_types() -> None:
    assert list(AUTH_EVENT_TYPES) == literal("AuthEventType")


def test_core_endpoints() -> None:
    rows = re.findall(
        r"^\| `([a-z_]+)` \| (GET|POST|PATCH|DELETE) `([^`]+)`",
        section("### 13.1", "### 13.2"),
        re.M,
    )
    assert [(spec.id, spec.method, spec.path) for spec in CORE_ENDPOINTS] == rows


def test_plugin_endpoint_ids() -> None:
    documented = set(first_column_ids(section("### 12.3", "**OAuth server rules")))
    documented.discard("has_permission")  # listed in its own table in 12.3
    in_code = {spec.id for spec in PLUGIN_ENDPOINTS}
    assert documented <= in_code
    assert in_code - documented <= {"has_permission"}


def test_cross_plugin_call_ids() -> None:
    documented = re.findall(
        r"^\| `([a-z_]+)` \(", section("### 12.5", "### 12.4"), re.M
    )
    assert sorted(CROSS_PLUGIN_CALLS) == sorted(documented)


def test_cookie_names() -> None:
    table = section(
        "**Cookie names in use.**",
        "```python\n@dataclass(frozen=True)\nclass CreatedSession",
    )
    documented: dict[str, str] = {}
    for line in table.splitlines():
        match = re.match(r"^\s*\| (.+?) \| ([A-Z]\d) \|", line)
        if match:
            for name in re.findall(r"`([a-z_]+)`", match[1]):
                documented[name] = match[2]
    assert dict(COOKIE_NAMES) == documented


def test_crypto_purposes() -> None:
    block = section("**Purpose strings in use**", "**Spec vectors**")
    documented: dict[str, str] = {}
    for line in block.splitlines():
        owner = re.search(r"\(([A-Z]\d)(?:, [A-Z]\d)*\)", line)
        if owner:
            for name in re.findall(r'`"([a-z_]+)"`', line):
                documented[name] = owner[1]
    assert dict(CRYPTO_PURPOSES) == documented


def test_token_prefixes() -> None:
    documented = set(re.findall(r"`(g[a-z]{2}_)`", section("## 7.", "## 8.")))
    assert set(TOKEN_PREFIXES.values()) == documented


def test_default_rate_limits_include_identifier_and_passkey_rules() -> None:
    keys = {(rule.path, rule.key) for rule in DEFAULT_RATE_LIMITS}
    assert ("/passkey/*", "ip_path") in keys
    assert ("/sign-in/email", "identifier") in keys
    assert ("/oauth2/token", "ip_path") in keys
    assert ("*", "ip_path") in keys


@pytest.mark.parametrize("model", ["user", "account", "session", "verification"])
def test_core_schema_fields(model: str) -> None:
    row = next(
        line
        for line in section("### 2.1", "### 2.2").splitlines()
        if line.startswith(f"| `{model}` |")
    )
    documented = set(re.findall(r"`([a-z_]+)`", row.split("|")[2]))
    fields = set(CORE_SCHEMA[model].fields)
    # Every field the table names (minus model references such as "user") exists.
    assert documented - {"user", "credential"} <= fields | {"provider_id", "account_id"}
    assert fields <= documented | {"created_at", "updated_at", "expires_at"}
