"""Small contract helpers: durations, schemas, scopes, cookies, IPs and redirects."""

from __future__ import annotations

from datetime import timedelta

import pytest
from hypothesis import given
from hypothesis import strategies as st

from gotauth.contracts import (
    AdvancedConfig,
    AuthError,
    Field,
    ModelSchema,
    Principal,
    ResolvedConfig,
    SchemaConflictError,
    cookie_name,
    merge_schemas,
    resolve_client_ip,
    secure_cookies,
    to_timedelta,
    validate_redirect,
)

SECRET = "helper-tests-secret-0123456789abcdef"


def config(**advanced: object) -> ResolvedConfig:
    return ResolvedConfig(
        secret=SECRET,  # pyright: ignore[reportArgumentType]  # validator wraps it
        base_url="https://app.example.com",
        trusted_origins=("https://*.example.org", "https://admin.example.net"),
        advanced=AdvancedConfig.model_validate(advanced),
    )


# ------------------------------------------------------------------ durations


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (90, timedelta(seconds=90)),
        (timedelta(minutes=2), timedelta(minutes=2)),
        ("90s", timedelta(seconds=90)),
        ("15m", timedelta(minutes=15)),
        ("12h", timedelta(hours=12)),
        ("7d", timedelta(days=7)),
    ],
)
def test_to_timedelta(value: int | timedelta | str, expected: timedelta) -> None:
    assert to_timedelta(value) == expected


@pytest.mark.parametrize("value", ["", "15", "m", "1w", "-5m", "1.5h", "15 m", True])
def test_to_timedelta_rejects(value: object) -> None:
    with pytest.raises(ValueError):
        to_timedelta(value)  # pyright: ignore[reportArgumentType]


# ------------------------------------------------------------------ schemas


def test_merge_schemas_adds_models_and_fields() -> None:
    base = {"user": ModelSchema("user", {"email": Field("string")})}
    extra = {
        "user": ModelSchema("user", {"role": Field("string", required=False)}),
        "pet": ModelSchema("pet", {"name": Field("string")}),
    }
    merged = merge_schemas(base, extra)
    assert set(merged["user"].fields) == {"email", "role"}
    assert "pet" in merged


def test_merge_schemas_conflict() -> None:
    base = {"user": ModelSchema("user", {"email": Field("string")})}
    clash = {"user": ModelSchema("user", {"email": Field("text")})}
    with pytest.raises(SchemaConflictError):
        merge_schemas(base, clash)


# ------------------------------------------------------------------ scopes

scope = st.from_regex(r"[a-z]{1,6}:[a-z]{1,6}", fullmatch=True)


@given(granted=st.frozensets(scope, max_size=6), required=st.lists(scope, max_size=4))
def test_has_scopes(granted: frozenset[str], required: list[str]) -> None:
    principal = Principal(
        via="api_key", credential_id="key_1", user_id=None, scopes=granted
    )
    assert principal.has_scopes(*required) == set(required).issubset(granted)


@given(required=st.lists(scope, max_size=4))
def test_session_principal_has_every_scope(required: list[str]) -> None:
    principal = Principal(via="session", credential_id="ses_1", user_id="usr_1")
    assert principal.has_scopes(*required)


# ------------------------------------------------------------------ cookies


def test_cookie_names_and_secure_flag() -> None:
    https = "https://app.example.com"
    assert cookie_name("challenge", base_url=https, prefix="gotauth") == (
        "__Secure-gotauth.challenge"
    )
    assert secure_cookies(https)
    for local in ("http://localhost:8000", "http://127.0.0.1:8000"):
        assert cookie_name("challenge", base_url=local, prefix="gotauth") == (
            "gotauth.challenge"
        )
        assert not secure_cookies(local)


# ------------------------------------------------------------------ client ip


def test_client_ip_ignores_headers_from_untrusted_peers() -> None:
    cfg = config(ip_headers=("x-forwarded-for",), trusted_proxies=("10.0.0.0/8",))
    headers = {"x-forwarded-for": "1.2.3.4"}
    assert resolve_client_ip("203.0.113.9", headers, cfg) == "203.0.113.9"


def test_client_ip_without_configured_headers_is_the_peer() -> None:
    headers = {"x-forwarded-for": "1.2.3.4"}
    assert resolve_client_ip("10.0.0.1", headers, config()) == "10.0.0.1"


octet = st.integers(min_value=1, max_value=254)
public_ip = st.builds(lambda a, b: f"198.51.{a}.{b}", octet, octet)


@given(
    spoofed=st.lists(public_ip, max_size=3), client=public_ip, hops=st.integers(0, 3)
)
def test_client_ip_is_the_rightmost_untrusted_entry(
    spoofed: list[str], client: str, hops: int
) -> None:
    cfg = config(ip_headers=("x-forwarded-for",), trusted_proxies=("10.0.0.0/8",))
    proxies = [f"10.0.0.{index + 1}" for index in range(hops)]
    # The client may prepend anything; trusted proxies append behind the real client.
    chain = [*spoofed, client, *proxies]
    headers = {"x-forwarded-for": ", ".join(chain)}
    assert resolve_client_ip("10.9.9.9", headers, cfg) == client


# ------------------------------------------------------------------ redirects


@pytest.mark.parametrize(
    "url",
    [
        "/dashboard",
        "/a/b?c=d",
        "https://app.example.com/after",
        "https://docs.example.org/x",
        "https://admin.example.net/",
    ],
)
def test_validate_redirect_allows(url: str) -> None:
    assert validate_redirect(url, config()) == url


@pytest.mark.parametrize(
    "url",
    [
        "//evil.com",
        "/\\evil.com",
        "https://evil.com",
        "https://app.example.com.evil.com/",
        "https://evil.com@app.example.com/",
        "https://example.org.evil.com/",
        "javascript:alert(1)",
        "http://app.example.com/",
        " /dashboard",
        "",
    ],
)
def test_validate_redirect_rejects(url: str) -> None:
    with pytest.raises(AuthError) as caught:
        validate_redirect(url, config())
    assert caught.value.code == "INVALID_REQUEST"
