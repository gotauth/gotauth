"""Rule metadata for ``gotauth check``: ids, severities, descriptions and fix hints.

The detection logic lives in ``_visitor.py``. This module holds only the text that the
outputs show, so the rule table in the README, the SARIF rule descriptors and the
findings all come from one place.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Final, Literal

__all__ = [
    "HELP_URI_BASE",
    "MAX_COUNTED_PER_RULE",
    "RULES",
    "SEVERITY_WEIGHTS",
    "Rule",
    "Severity",
    "resolve_rule_ids",
]

Severity = Literal["high", "medium", "low"]

SEVERITY_WEIGHTS: Final[dict[Severity, int]] = {"high": 15, "medium": 6, "low": 2}
"""Points one finding takes off the score of 100."""

MAX_COUNTED_PER_RULE: Final = 3
"""How many findings of the same rule count towards the score."""

HELP_URI_BASE: Final = "https://gotauth.ablacky.com/check/"


@dataclass(frozen=True, slots=True)
class Rule:
    """One check of ``gotauth check``.

    Attributes:
        id: Stable rule id, for example ``"GA001"``.
        name: Short kebab-case name, for example ``"passlib-import"``.
        severity: ``"high"``, ``"medium"`` or ``"low"``.
        title: One line that says what the rule finds.
        description: Why the finding matters.
        hint: How to fix it. Hints name several options and never only one product.
        precision: How often a finding is a real problem (``"high"`` or ``"medium"``),
            reported to SARIF consumers. Heuristic rules are ``"medium"``.
    """

    id: str
    name: str
    severity: Severity
    title: str
    description: str
    hint: str
    precision: Literal["high", "medium"] = "high"

    @property
    def help_uri(self) -> str:
        """The documentation page of the rule."""
        return HELP_URI_BASE + self.id


_RULE_LIST: Final = (
    Rule(
        id="GA001",
        name="passlib-import",
        severity="high",
        title="passlib is imported",
        description=(
            "passlib's last release is 1.7.4 from October 2020. With bcrypt 4.1.1 and "
            "later its bcrypt backend logs an error while reading the bcrypt version "
            "(pyca/bcrypt#684), and the FastAPI docs replaced passlib with pwdlib in "
            "September 2025."
        ),
        hint=(
            "Hash new passwords with argon2-cffi, pwdlib or bcrypt. To keep accepting "
            "existing hashes, verify them with a maintained library that reads the "
            "same format (for example libpass, a passlib fork, or bcrypt for $2b$ "
            "hashes) and rehash on the next sign-in. An auth library such as GotAuth "
            "can also handle this."
        ),
    ),
    Rule(
        id="GA002",
        name="python-jose-import",
        severity="high",
        title="python-jose is imported",
        description=(
            "python-jose had no release between 3.3.0 (June 2021) and 3.4.0 "
            "(February 2025). CVE-2024-33663 (algorithm confusion) and CVE-2024-33664 "
            "(JWE decompression bomb) were published in April 2024 and fixed only in "
            "3.4.0. The FastAPI docs replaced python-jose with PyJWT in May 2024."
        ),
        hint=(
            "Use PyJWT or joserfc and pass the accepted algorithms explicitly. If you "
            "keep python-jose, require version 3.4.0 or later."
        ),
    ),
    Rule(
        id="GA003",
        name="jwt-hardcoded-hmac-secret",
        severity="high",
        title="JWT signed with HMAC and a hard-coded secret",
        description=(
            "Tokens signed with HS256 or another HMAC algorithm are only as strong as "
            "the secret. A secret in the source code is shared with everyone who can "
            "read the repository, and a short one can be brute-forced offline from a "
            "single token."
        ),
        hint=(
            "Load the key from the environment or a secret manager and use at least 32 "
            "random bytes (for example secrets.token_urlsafe(32)), or switch to an "
            "asymmetric algorithm such as RS256, ES256 or EdDSA."
        ),
    ),
    Rule(
        id="GA004",
        name="jwt-decode-unverified",
        severity="high",
        title="JWT decoded without signature verification or pinned algorithms",
        description=(
            "With signature verification off, anyone can forge a token. Without an "
            "explicit algorithms list, older PyJWT releases and python-jose accept the "
            "algorithm the token header names, which allows algorithm confusion "
            "attacks."
        ),
        hint=(
            "Keep signature verification on and pass algorithms=[...] with exactly "
            'the algorithms you issue, for example algorithms=["HS256"].'
        ),
    ),
    Rule(
        id="GA005",
        name="jwt-without-exp",
        severity="medium",
        title="JWT payload without an exp claim",
        description=(
            "A token without an expiry stays valid forever, so a leaked token can only "
            "be stopped by rotating the signing key. The rule checks payloads written "
            "as dict literals in the same function."
        ),
        hint=(
            "Add an exp claim, for example datetime.now(timezone.utc) + "
            "timedelta(minutes=15). PyJWT and python-jose check exp when decoding."
        ),
        precision="medium",
    ),
    Rule(
        id="GA006",
        name="non-constant-time-compare",
        severity="medium",
        title="Secret compared with == or !=",
        description=(
            "== and != stop at the first differing character, so response times can "
            "reveal how much of a guessed token, signature or password is right. The "
            "rule matches names that contain token, password, secret, signature or "
            "digest."
        ),
        hint=(
            "Compare secrets with hmac.compare_digest (or secrets.compare_digest). For "
            "passwords, store a password hash and use the hashing library's verify "
            "function."
        ),
        precision="medium",
    ),
    Rule(
        id="GA007",
        name="login-without-rate-limit",
        severity="medium",
        title="Login-like POST route and no rate limiter in the project",
        description=(
            "Sign-in, token and password endpoints without rate limits allow online "
            "password guessing and credential stuffing. The rule looks for POST routes "
            "whose path or function name mentions login, sign-in, token or password, "
            "and stays quiet when the scanned project uses slowapi, limits, "
            "fastapi-limiter, Flask-Limiter, django-ratelimit or gotauth."
        ),
        hint=(
            "Rate-limit these routes per IP address and per account, for example with "
            "slowapi, limits or fastapi-limiter, or use an auth library with built-in "
            "rate limits such as GotAuth. If a proxy or gateway already limits them, "
            "suppress the finding with # gotauth: ignore[GA007]."
        ),
        precision="medium",
    ),
    Rule(
        id="GA008",
        name="tls-verify-disabled",
        severity="high",
        title="TLS certificate verification turned off",
        description=(
            "verify=False makes requests and httpx accept any certificate, so anyone "
            "on the network path can read and change the traffic, including tokens "
            "and passwords."
        ),
        hint=(
            "Remove verify=False. For a private certificate authority, pass its bundle "
            '(verify="/path/to/ca.pem") or an ssl.SSLContext.'
        ),
    ),
    Rule(
        id="GA009",
        name="hardcoded-secret",
        severity="high",
        title="Hard-coded secret",
        description=(
            "A high-entropy string assigned to a secret-like name (SECRET_KEY, "
            "JWT_SECRET, *_TOKEN, *_PASSWORD, *_API_KEY) is most likely a real "
            "credential. Anything committed stays in the git history and in every "
            "clone."
        ),
        hint=(
            "Read the value from an environment variable or a secret manager, rotate "
            "the exposed secret, and remove it from the git history."
        ),
    ),
    Rule(
        id="GA010",
        name="fast-password-hash",
        severity="high",
        title="Password hashed with a fast hash",
        description=(
            "MD5, SHA-1 and SHA-2 are built for speed. A single GPU computes billions "
            "of them per second, so leaked hashes of real passwords are cracked "
            "quickly, with or without a salt."
        ),
        hint=(
            "Use a slow, salted password hash: Argon2id (argon2-cffi, pwdlib), bcrypt "
            "or hashlib.scrypt."
        ),
    ),
    Rule(
        id="GA011",
        name="low-bcrypt-cost",
        severity="medium",
        title="bcrypt cost factor below 10",
        description=(
            "Each step of the bcrypt cost factor doubles the work. Costs from 4 to 9 "
            "make offline cracking much cheaper; the bcrypt library defaults to 12."
        ),
        hint=(
            "Use a cost of 12 or more in production (the bcrypt default). Lower values "
            "belong only in tests."
        ),
    ),
    Rule(
        id="GA012",
        name="insecure-cookie",
        severity="medium",
        title="Cookie set without httponly=True or secure=True",
        description=(
            "Without HttpOnly, any script injected into the page can read the cookie. "
            "Without Secure, the browser also sends it over plain HTTP."
        ),
        hint=(
            "Pass httponly=True, secure=True and a samesite value (lax or strict) for "
            "session and auth cookies."
        ),
    ),
    Rule(
        id="GA013",
        name="cors-wildcard-credentials",
        severity="high",
        title="CORS allows every origin with credentials",
        description=(
            'With allow_origins=["*"] and allow_credentials=True, Starlette\'s '
            "CORSMiddleware (used by FastAPI) echoes the caller's Origin and allows "
            "credentials, so any website can send requests with your users' cookies "
            "and read the responses."
        ),
        hint=(
            "List the exact origins you trust in allow_origins, or set "
            "allow_credentials=False if cross-origin requests do not need cookies."
        ),
    ),
)

RULES: Final[dict[str, Rule]] = {rule.id: rule for rule in _RULE_LIST}
"""Every rule, keyed by id, in id order."""


def _split_ids(values: Iterable[str]) -> list[str]:
    ids: list[str] = []
    for value in values:
        ids.extend(part.strip().upper() for part in value.split(",") if part.strip())
    return ids


def resolve_rule_ids(
    select: Iterable[str] | None = None, ignore: Iterable[str] = ()
) -> frozenset[str]:
    """Return the enabled rule ids.

    Args:
        select: Rule ids to run, as single ids or comma-separated lists. ``None`` or an
            empty list means every rule.
        ignore: Rule ids to leave out, in the same format.

    Returns:
        The ids of the rules to run.

    Raises:
        ValueError: If an id is not a known rule.
    """
    selected = _split_ids(select or ())
    ignored = _split_ids(ignore)
    unknown = sorted({*selected, *ignored} - RULES.keys())
    if unknown:
        known = f"{min(RULES)} to {max(RULES)}"
        msg = f"unknown rule id: {', '.join(unknown)} (known: {known})"
        raise ValueError(msg)
    enabled = set(selected) if selected else set(RULES)
    return frozenset(enabled - set(ignored))
