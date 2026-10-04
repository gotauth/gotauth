"""Per-rule tests: one positive and one negative fixture per rule, plus edge cases."""

from __future__ import annotations

from pathlib import Path

import pytest

from gotauth.checkup import RULES, Finding, scan, scan_source
from gotauth.checkup._visitor import looks_random, words

FIXTURES = Path(__file__).parent / "fixtures"

# How many findings of its own rule each positive fixture must produce.
POSITIVE_COUNTS = {
    "GA001": 1,
    "GA002": 1,
    "GA003": 3,
    "GA004": 3,
    "GA005": 2,
    "GA006": 3,
    "GA007": 2,
    "GA008": 3,
    "GA009": 4,
    "GA010": 3,
    "GA011": 3,
    "GA012": 3,
    "GA013": 2,
}


def rule_ids(findings: list[Finding] | tuple[Finding, ...]) -> list[str]:
    return [finding.rule_id for finding in findings]


def test_every_rule_has_a_positive_and_a_negative_fixture() -> None:
    assert set(POSITIVE_COUNTS) == set(RULES)
    for rule_id in RULES:
        assert (FIXTURES / rule_id / "positive.py").is_file()
        assert (FIXTURES / rule_id / "negative.py").is_file()


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_positive_fixture_triggers_the_rule(rule_id: str) -> None:
    report = scan([FIXTURES / rule_id / "positive.py"])
    assert report.skipped == ()
    found = [finding for finding in report.findings if finding.rule_id == rule_id]
    assert len(found) == POSITIVE_COUNTS[rule_id], report.findings
    rule = RULES[rule_id]
    for finding in found:
        assert finding.severity == rule.severity
        assert finding.hint == rule.hint
        assert finding.path.endswith(f"{rule_id}/positive.py")
        assert finding.line >= 1
        assert finding.column >= 1
        assert finding.message


@pytest.mark.parametrize("rule_id", sorted(RULES))
def test_negative_fixture_is_clean(rule_id: str) -> None:
    report = scan([FIXTURES / rule_id / "negative.py"])
    assert report.files_scanned == 1
    assert report.findings == ()
    assert report.score == 100


def test_finding_positions_point_at_the_code() -> None:
    source = 'import requests\nx = "été"; requests.get(u, verify=False)\n'
    (finding,) = scan_source(source, "app.py")
    assert finding.rule_id == "GA008"
    assert (finding.line, finding.column) == (2, 12)
    assert (finding.end_line, finding.end_column) == (2, 41)
    assert finding.location == "app.py:2:12"


def test_findings_never_include_the_secret_value() -> None:
    secret = "q8Zt3LxV0pN6bR1mK4yW7cD2fH5jS9gA"
    findings = scan_source(f'SECRET_KEY = "{secret}"\n')
    assert rule_ids(findings) == ["GA009"]
    assert secret not in findings[0].message
    assert secret not in findings[0].fingerprint


# ---------------------------------------------------------------- suppression


def test_suppression_silences_only_the_named_rule() -> None:
    source = (
        "import requests\n"
        "def check(token, expected_token, url):\n"
        "    return token == expected_token and requests.get(url, verify=False)"
        "  # gotauth: ignore[GA006]\n"
    )
    assert rule_ids(scan_source(source)) == ["GA008"]


def test_suppression_accepts_several_ids() -> None:
    source = (
        "import requests\n"
        "def check(token, expected_token, url):\n"
        "    return token == expected_token and requests.get(url, verify=False)"
        "  # gotauth: ignore[ga006, GA008]\n"
    )
    assert scan_source(source) == []


def test_suppression_applies_to_its_own_line_only() -> None:
    source = (
        "import requests\n"
        "# gotauth: ignore[GA008]\n"
        "requests.get('https://example.com', verify=False)\n"
    )
    assert rule_ids(scan_source(source)) == ["GA008"]


def test_bare_ignore_comment_does_not_suppress() -> None:
    source = "import passlib  # gotauth: ignore\n"
    assert rule_ids(scan_source(source)) == ["GA001"]


# ---------------------------------------------------------------- select


def test_select_and_ignore() -> None:
    source = "import passlib\nimport jose\n"
    assert rule_ids(scan_source(source, select=["GA002"])) == ["GA002"]
    assert rule_ids(scan_source(source, ignore=["ga001"])) == ["GA002"]
    assert rule_ids(scan_source(source, select=["GA001,GA002"], ignore=["GA002"])) == [
        "GA001"
    ]


def test_unknown_rule_id_is_an_error() -> None:
    with pytest.raises(ValueError, match="GA999"):
        scan_source("x = 1\n", select=["GA999"])


def test_scan_source_rejects_unparsable_code() -> None:
    with pytest.raises(ValueError, match="syntax error"):
        scan_source("def broken(:\n")


# ---------------------------------------------------------------- GA001, GA002


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("import passlib.hash\n", ["GA001"]),
        ("from passlib import hash as h\n", ["GA001"]),
        ("import jose\n", ["GA002"]),
        ("from jose.jwt import decode\n", ["GA002"]),
        ("from authlib.jose import jwt\n", []),
        ("from .jose import jwt\n", []),
        ("import libpass\n", []),
    ],
)
def test_import_rules(source: str, expected: list[str]) -> None:
    assert rule_ids(scan_source(source)) == expected


# ---------------------------------------------------------------- JWT rules


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        # import aliases are resolved
        ("import jwt as pyjwt\npyjwt.decode(t, k)\n", ["GA004"]),
        ("from jwt import decode\ndecode(t, k)\n", ["GA004"]),
        (
            "from jose import jwt\njwt.decode(t, k, algorithms=None)\n",
            ["GA002", "GA004"],
        ),
        # other objects called jwt are not PyJWT
        ("self.jwt.decode(t, k)\n", []),
        ("from authlib.jose import jwt\njwt.decode(t, k)\n", []),
        # **kwargs may carry algorithms=
        ("import jwt\njwt.decode(t, k, **options)\n", []),
        ("import jwt\njwt.decode(t, k, ['HS256'])\n", []),
        ("import jwt\njwt.decode(t, k, verify=False)\n", ["GA004"]),
    ],
)
def test_jwt_decode(source: str, expected: list[str]) -> None:
    assert rule_ids(scan_source(source)) == expected


def test_jwt_decode_messages() -> None:
    messages = [
        finding.message
        for finding in scan_source(
            "import jwt\n"
            "jwt.decode(t, k)\n"
            "jwt.decode(t, options={'verify_signature': False})\n"
            "jwt.decode(t, k, algorithms=['none'])\n"
        )
    ]
    assert messages == [
        "jwt.decode does not pass algorithms=[...].",
        "jwt.decode turns off signature verification.",
        'jwt.decode accepts the "none" algorithm.',
    ]


@pytest.mark.parametrize(
    ("source", "message"),
    [
        (
            "import jwt\njwt.encode({'exp': 1}, 'abc', algorithm='HS384')\n",
            "jwt.encode signs HS384 tokens with a hard-coded 3-character secret.",
        ),
        (
            "import jwt\nALG = 'HS256'\nKEY = 'k'\n"
            "jwt.encode({'exp': 1}, KEY, algorithm=ALG)\n",
            "jwt.encode signs HS256 tokens with a hard-coded 1-character secret.",
        ),
        ("import jwt\njwt.encode({'exp': 1}, 'a' * 40, algorithm='HS256')\n", None),
        (
            "import jwt\njwt.encode({'exp': 1}, '" + "k" * 40 + "', algorithm=alg)\n",
            "jwt.encode signs tokens with a hard-coded secret.",
        ),
        (
            "import os, jwt\n"
            "jwt.encode({'exp': 1}, os.getenv('S', 'dev'), algorithm='HS256')\n",
            "jwt.encode signs HS256 tokens with a secret that falls back to a "
            "hard-coded value when the environment variable is not set.",
        ),
        ("import jwt\njwt.encode({'exp': 1}, 'abc', algorithm='ES256')\n", None),
        ("import jwt\njwt.encode({'exp': 1}, None, algorithm=None)\n", None),
        ("import jwt\njwt.encode({'exp': 1}, settings.KEY)\n", None),
    ],
)
def test_jwt_encode_secret(source: str, message: str | None) -> None:
    findings = [item for item in scan_source(source) if item.rule_id == "GA003"]
    assert [item.message for item in findings] == ([message] if message else [])


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("jwt.encode({'sub': 1}, k)", True),
        ("jwt.encode(payload={'sub': 1}, key=k)", True),
        ("jwt.encode(dict(sub=1), k)", True),
        ("jwt.encode(dict(sub=1, exp=2), k)", False),
        ("jwt.encode({**base}, k)", False),
        ("jwt.encode({**base, 'sub': 1}, k)", False),
        ("jwt.encode({**base, 'exp': 2}, k)", False),
        ("jwt.encode({key_name: 1}, k)", False),
        ("jwt.encode(build(), k)", False),
    ],
)
def test_jwt_encode_exp(source: str, flagged: bool) -> None:
    findings = scan_source(f"import jwt\n{source}\n", select=["GA005"])
    assert bool(findings) is flagged


def test_jwt_exp_tracking_follows_local_dicts() -> None:
    source = (
        "import jwt\n"
        "def a(k):\n"
        "    claims = {'sub': 1}\n"
        "    claims |= extra\n"
        "    return jwt.encode(claims, k)\n"
        "def b(k):\n"
        "    claims = {'sub': 1}\n"
        "    claims.setdefault('exp', 5)\n"
        "    return jwt.encode(claims, k)\n"
        "def c(k):\n"
        "    claims = {'sub': 1}\n"
        "    claims = add_expiry(claims)\n"
        "    return jwt.encode(claims, k)\n"
        "def d(k):\n"
        "    return jwt.encode(claims, k)\n"
    )
    assert scan_source(source, select=["GA005"]) == []


# ---------------------------------------------------------------- GA006


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("if token == stored: pass", True),
        ("if request.headers.get('X-Hub-Signature-256') != expected: pass", True),
        ("if hashlib.sha256(body).digest() == mac: pass", True),
        ("if accessToken == other: pass", True),
        ("if user.password == form.password: pass", True),
        ("if current_password == user.password: pass", True),
        ("if password1 != password2: pass", False),
        ("if form.password != form.password_confirmation: pass", False),
        ("if password == None: pass", False),
        ("if token == 'Bearer': pass", False),
        ("if len(token) == 32: pass", False),
        ("if token_count == max_tokens: pass", False),
        ("if tokens == expected_tokens: pass", False),
        ("if token is other: pass", False),
        ("if token in allowed: pass", False),
        ("assert token == expected", False),
    ],
)
def test_non_constant_time_compare(source: str, flagged: bool) -> None:
    findings = scan_source(source + "\n", select=["GA006"])
    assert bool(findings) is flagged


# ---------------------------------------------------------------- GA007


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("@app.post('/api/v1/login')\ndef handler(): ...", True),
        ("@router.post('/password/forgot')\nasync def forgot(): ...", True),
        ("@app.post(path)\ndef signin(): ...", True),
        ("@post('/sign-in')\nasync def handler() -> None: ...", True),
        ("@app.route('/login', methods=['GET', 'POST'])\ndef login(): ...", True),
        ("@app.route('/login')\ndef login(): ...", False),
        ("@app.get('/login')\ndef login(): ...", False),
        ("@app.post('/count-tokens')\ndef count(): ...", False),
        ("@app.post('/tokenize')\ndef tokenize(): ...", False),
        ("routes = [Route('/login', endpoint=login, methods=['POST'])]", True),
        (
            "app.add_url_rule('/login', 'login', view_func=login, methods=['POST'])",
            True,
        ),
        ("app.add_api_route('/token', issue, methods=['POST'])", True),
        ("routes = [Route('/login', endpoint=login)]", False),
    ],
)
def test_login_route_detection(source: str, flagged: bool) -> None:
    findings = scan_source(source + "\n", select=["GA007"])
    assert bool(findings) is flagged


@pytest.mark.parametrize(
    "limiter_import",
    [
        "from slowapi import Limiter",
        "import limits",
        "from fastapi_limiter.depends import RateLimiter",
        "from flask_limiter import Limiter",
        "import gotauth",
    ],
)
def test_rate_limiter_import_silences_login_routes(limiter_import: str) -> None:
    source = f"{limiter_import}\n@app.post('/login')\ndef login(): ...\n"
    assert scan_source(source, select=["GA007"]) == []


@pytest.mark.parametrize(
    ("name", "content", "silenced"),
    [
        ("requirements.txt", "fastapi\nslowapi==0.1.9\n", True),
        ("requirements-dev.txt", "fastapi-limiter>=0.1\n", True),
        (
            "pyproject.toml",
            '[project]\ndependencies = ["fastapi", "limits>=3"]\n',
            True,
        ),
        ("pyproject.toml", '[tool.poetry.dependencies]\ngotauth = "^0.1"\n', True),
        ("requirements.txt", "fastapi\nslowapi-extra-tools\n", False),
        ("README.md", "slowapi\n", False),
    ],
)
def test_rate_limiter_in_dependency_files(
    tmp_path: Path, name: str, content: str, silenced: bool
) -> None:
    (tmp_path / "app.py").write_text("@app.post('/login')\ndef login(): ...\n")
    (tmp_path / name).write_text(content)
    report = scan([tmp_path], select=["GA007"])
    assert (report.findings == ()) is silenced


def test_rate_limiter_in_another_file_silences_the_project(tmp_path: Path) -> None:
    (tmp_path / "routes.py").write_text("@app.post('/login')\ndef login(): ...\n")
    (tmp_path / "limits_setup.py").write_text("from slowapi import Limiter\n")
    assert scan([tmp_path]).findings == ()
    # The same route alone is reported.
    assert rule_ids(scan([tmp_path / "routes.py"]).findings) == ["GA007"]


# ---------------------------------------------------------------- GA008


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("import requests\nrequests.post(u, json=d, verify=False)", True),
        ("import httpx as h\nh.Client(verify=False)", True),
        ("from requests import Session\nSession().get(u, verify=False)", True),
        ("import httpx\nclient.stream('GET', u, verify=False)", True),
        ("client.get(u, verify=False)", False),
        ("import requests\nrequests.get(u, verify=True)", False),
        ("import requests\nrequests.get(u, verify=ca_bundle)", False),
        ("import jwt\njwt.decode(t, k, algorithms=['HS256'], verify=False)", False),
    ],
)
def test_tls_verification(source: str, flagged: bool) -> None:
    findings = scan_source(source + "\n", select=["GA008"])
    assert bool(findings) is flagged


# ---------------------------------------------------------------- GA009


@pytest.mark.parametrize(
    ("text", "random"),
    [
        ("09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7", True),
        ("django-insecure-6j#k2!m@x0p$w9z^&v5r*q8t(y)u+e=a1b3c4d5f7g", True),
        ("Hq3vZ8kT1mR6pW0xL5cN9bF2jD7sG4aY", True),
        ("MyS3cr3tP@ssw0rd2024", True),
        ("my-secret-key-123456", False),
        ("your-secret-key-here", False),
        ("change-me-in-production", False),
        ("test-secret-key-for-tests", False),
        ("AKIAIOSFODNN7EXAMPLE", False),
        ("abcdefghijklmnopqrst", False),
        ("1234567890123456", False),
        ("short1A!", False),
        ("https://example.com/a1B2c3D4", False),
        ("/var/run/secrets/a1B2c3D4e5", False),
        ("with spaces Zx8Qp2Lm9Rt4", False),
        ("${SECRET_KEY_FROM_ENV_1}", False),
    ],
)
def test_looks_random(text: str, random: bool) -> None:
    assert looks_random(text) is random


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("app.config['SECRET_KEY'] = '{value}'", True),
        ("def create_app():\n    app.config['SECRET_KEY'] = '{value}'", True),
        ("SETTINGS = {{'api_key': '{value}'}}", True),
        ("client = Client(api_key='{value}')", True),
        ("PRIVATE_KEY = b'{value}'", True),
        ("import os\nSECRET = os.getenv('JWT_SECRET', '{value}')", True),
        ("STRIPE_TOKEN: str = '{value}'", True),
        ("def setup():\n    token = '{value}'", False),
        ("def setup():\n    os.environ['API_TOKEN'] = '{value}'", False),
        ("login(password='{value}')", False),
        ("SECRET_KEY_HASH = '{value}'", False),
        ("CACHE_KEY = '{value}'", False),
        ("SECRET_KEY = os.environ['SECRET_KEY']", False),
    ],
)
def test_hardcoded_secret(source: str, flagged: bool) -> None:
    code = source.format(value="Hq3vZ8kT1mR6pW0xL5cN9bF2jD7sG4aY") + "\n"
    findings = scan_source(code, select=["GA009"])
    assert bool(findings) is flagged


# ---------------------------------------------------------------- GA010 to GA013


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("hashlib.new('sha256', password.encode())", True),
        ("hashlib.sha512(data=f'{salt}{user_password}'.encode())", True),
        ("from hashlib import md5\nmd5(pw)", True),
        ("hashlib.pbkdf2_hmac('sha256', password, salt, 600_000)", False),
        ("hashlib.sha256(token.encode())", False),
        ("h = make_hasher()\nh.update(password)", False),
    ],
)
def test_fast_password_hash(source: str, flagged: bool) -> None:
    findings = scan_source(f"import hashlib\n{source}\n", select=["GA010"])
    assert bool(findings) is flagged


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("CryptContext(schemes=['bcrypt'], bcrypt__rounds=6)", True),
        ("from passlib.hash import bcrypt\nbcrypt.using(rounds=5)", True),
        (
            "from pwdlib.hashers.bcrypt import BcryptHasher\nBcryptHasher(rounds=4)",
            True,
        ),
        ("app.config['BCRYPT_LOG_ROUNDS'] = 4", True),
        ("import bcrypt\nbcrypt.gensalt(rounds=10)", False),
        ("import bcrypt\nbcrypt.gensalt(rounds=settings.ROUNDS)", False),
        ("random.gensalt(4)", False),
    ],
)
def test_low_bcrypt_cost(source: str, flagged: bool) -> None:
    findings = scan_source(source + "\n", select=["GA011"])
    assert bool(findings) is flagged


def test_cookie_messages() -> None:
    source = (
        "r.set_cookie('a', v)\n"
        "r.set_cookie('b', v, httponly=True)\n"
        "r.set_cookie('c', v, secure=True)\n"
        "r.set_cookie('d', v, secure=flag, httponly=flag)\n"
        "r.set_cookie('XSRF-TOKEN', v, secure=True)\n"
    )
    assert [finding.message for finding in scan_source(source)] == [
        "r.set_cookie is called without httponly=True and secure=True.",
        "r.set_cookie is called without secure=True.",
        "r.set_cookie is called without httponly=True.",
    ]


@pytest.mark.parametrize(
    ("source", "flagged"),
    [
        ("CORSMiddleware(app, allow_origins='*', allow_credentials=True)", True),
        (
            "ORIGINS = ['*']\n"
            "CORSConfig(allow_origins=ORIGINS, allow_credentials=True)",
            True,
        ),
        ("CORS(app, origins='*', supports_credentials=True)", True),
        ("CORS(app, origins=['https://a.example'], supports_credentials=True)", False),
        ("add_middleware(M, allow_origins=['*'], allow_credentials=False)", False),
        (
            "add_middleware(M, allow_origin_regex=r'https://.*\\.example\\.com', "
            "allow_credentials=True)",
            False,
        ),
    ],
)
def test_cors(source: str, flagged: bool) -> None:
    findings = scan_source(source + "\n", select=["GA013"])
    assert bool(findings) is flagged


def test_words() -> None:
    assert words("accessToken") == ("access", "token")
    assert words("X-Hub-Signature-256") == ("x", "hub", "signature", "256")
    assert words("APIKey") == ("api", "key")
    assert words("password2") == ("password", "2")
