"""The AST visitor behind ``gotauth check``: one pass per file, every rule at once.

The visitor only reads the syntax tree. It never imports, compiles or runs the code
it looks at. Names are resolved through the file's own import statements, so with
``from jose import jwt`` the call ``jwt.decode`` resolves to ``jose.jwt.decode``.

The heuristics prefer silence over noise: when a value is not a literal the visitor
can see (a function argument, a settings attribute, ``**kwargs``), the rules assume
the code is fine.
"""

from __future__ import annotations

import ast
import math
import re
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Final

__all__ = ["FileFacts", "RawFinding", "analyze", "looks_random", "words"]

_Located = ast.stmt | ast.expr | ast.keyword


@dataclass(frozen=True, slots=True)
class RawFinding:
    """A finding at its raw ``ast`` position (columns are UTF-8 byte offsets)."""

    rule_id: str
    message: str
    line: int
    col: int
    end_line: int
    end_col: int


@dataclass(slots=True)
class FileFacts:
    """What one pass over a file found.

    Attributes:
        findings: The findings, before suppression comments are applied.
        imports: Every absolute module name the file imports, including
            ``module.name`` for ``from module import name``. Project-level checks
            (GA007) use them.
    """

    findings: list[RawFinding] = field(default_factory=lambda: list[RawFinding]())
    imports: set[str] = field(default_factory=lambda: set[str]())


def analyze(tree: ast.Module, enabled: frozenset[str]) -> FileFacts:
    """Run the enabled rules over one parsed module.

    Args:
        tree: The module returned by ``ast.parse``.
        enabled: Ids of the rules to run.

    Returns:
        The findings, sorted by position, and the imported module names.
    """
    visitor = _Visitor(enabled)
    visitor.visit(tree)
    return visitor.finish()


# ---------------------------------------------------------------------------- words

_CAMEL_ACRONYM: Final = re.compile(r"([A-Z]+)([A-Z][a-z])")
_CAMEL: Final = re.compile(r"([a-z0-9])([A-Z])")
_LETTER_DIGIT: Final = re.compile(r"([A-Za-z])([0-9])")
_NOT_ALNUM: Final = re.compile(r"[^A-Za-z0-9]+")


@lru_cache(maxsize=8192)
def words(name: str) -> tuple[str, ...]:
    """Split an identifier, header name or URL path into lower-case words.

    ``accessToken``, ``ACCESS_TOKEN`` and ``x-access-token`` all give ``("access",
    "token")``, and ``password2`` gives ``("password", "2")``.

    Args:
        name: The text to split.

    Returns:
        The words, in order.
    """
    name = _CAMEL_ACRONYM.sub(r"\1_\2", name)
    name = _CAMEL.sub(r"\1_\2", name)
    name = _LETTER_DIGIT.sub(r"\1_\2", name)
    return tuple(part for part in _NOT_ALNUM.split(name.lower()) if part)


def _has_pair(parts: tuple[str, ...], first: str, second: str) -> bool:
    return any(
        parts[index] == first and parts[index + 1] == second
        for index in range(len(parts) - 1)
    )


# GA006: names whose value is a secret worth comparing in constant time. Whole words
# only, so "tokens" and "tokenizer" (LLM code) do not match.
_COMPARE_SECRET_WORDS: Final = frozenset(
    "apikey digest hexdigest hmac otp passphrase passwd password secret sig signature "
    "token".split()
)
# Words that turn a secret-sounding name into metadata about the secret, as in
# token_type, password_length or secret_name.
_METADATA_WORDS: Final = frozenset(
    "age alg algorithm count endpoint exp expiration expires expiry field format id "
    "ids idx index kind label len length limit max method min mode name names num "
    "number path policy prefix scheme size status suffix total ttl type uri url usage "
    "used version".split()
)
_CONFIRM_WORDS: Final = frozenset(
    "again confirm confirmation confirmed repeat repeated retype".split()
)
_EARLIER_WORDS: Final = frozenset("current old prev previous".split())

# GA009: words that make a name secret-like anywhere, keyword arguments included...
_STRONG_SECRET_WORDS: Final = frozenset({"apikey", "secret"})
_STRONG_SECRET_PAIRS: Final = (
    ("access", "key"),
    ("api", "key"),
    ("encryption", "key"),
    ("private", "key"),
    ("signing", "key"),
)
# ...and words that count only outside functions, because test code passes sample
# passwords and tokens around all the time.
_WEAK_SECRET_WORDS: Final = frozenset({"passphrase", "passwd", "password", "token"})
_ASSIGN_METADATA_WORDS: Final = _METADATA_WORDS | frozenset(
    "dir env file hash hashed header lifetime location pattern re regex rounds "
    "template timeout var variable".split()
)

# GA010: names that hold a password.
_PASSWORD_WORDS: Final = frozenset({"passphrase", "passwd", "password", "pw", "pwd"})

# GA007: route paths and function names that look like sign-in endpoints.
_LOGIN_WORDS: Final = frozenset("login logon passwd password signin token".split())
_LOGIN_PAIRS: Final = (("log", "in"), ("sign", "in"))


def _is_compare_secret(parts: tuple[str, ...]) -> bool:
    if not parts or any(part in _METADATA_WORDS for part in parts):
        return False
    return any(part in _COMPARE_SECRET_WORDS for part in parts) or _has_pair(
        parts, "api", "key"
    )


def _secret_strength(parts: tuple[str, ...]) -> int:
    """Return 2 for a clearly secret name, 1 for a password or token name, else 0."""
    if not parts or any(part in _ASSIGN_METADATA_WORDS for part in parts):
        return 0
    if any(part in _STRONG_SECRET_WORDS for part in parts) or any(
        _has_pair(parts, first, second) for first, second in _STRONG_SECRET_PAIRS
    ):
        return 2
    if any(part in _WEAK_SECRET_WORDS for part in parts):
        return 1
    return 0


def _is_login_like(text: str) -> bool:
    parts = words(text)
    return any(part in _LOGIN_WORDS for part in parts) or any(
        _has_pair(parts, first, second) for first, second in _LOGIN_PAIRS
    )


# ---------------------------------------------------------------------------- entropy

_HEX: Final = re.compile(r"[0-9a-f]+|[0-9A-F]+")
# Parts of placeholders and sample values ("change-me", "your-secret-here",
# "test-key"). A random 64-character secret contains one of them by chance with well
# under 1% probability.
_PLACEHOLDER_PARTS: Final = tuple(
    "admin bar change default dev dummy example fake fixme foo hello insert key local "
    "mock notreal passw placeholder qwerty replace sample secret super test todo token "
    "xxxx your".split()
)


def _shannon_entropy(text: str) -> float:
    length = len(text)
    return -sum(
        count / length * math.log2(count / length) for count in Counter(text).values()
    )


def looks_random(text: str) -> bool:
    """Return True for a string that looks like a generated secret.

    The string needs 16 or more characters, no whitespace, at least two character
    classes (lower case, upper case, digits, other), no placeholder words such as
    "change" or "example", and a Shannon entropy of at least 3.0 bits per character
    for hex strings or 3.5 for others.

    Args:
        text: The string literal.

    Returns:
        Whether the string looks like a real secret.
    """
    if len(text) < 16 or any(char.isspace() for char in text):
        return False
    if "://" in text or any(char in text for char in "<>{}"):
        return False
    if text.startswith(("./", "../", "~/")) or (
        text.startswith("/") and text.count("/") > 1
    ):
        return False
    lowered = text.lower()
    if any(part in lowered for part in _PLACEHOLDER_PARTS):
        return False
    classes = (
        any(char.islower() for char in text)
        + any(char.isupper() for char in text)
        + any(char.isdigit() for char in text)
        + any(not char.isalnum() for char in text)
    )
    if classes < 2:
        return False
    threshold = 3.0 if _HEX.fullmatch(text) else 3.5
    return _shannon_entropy(text) >= threshold


# ---------------------------------------------------------------------------- names

_JWT_ENCODE: Final = frozenset({"jwt.encode", "jwt.api_jwt.encode", "jose.jwt.encode"})
_JWT_DECODE: Final = frozenset(
    {
        "jwt.decode",
        "jwt.decode_complete",
        "jwt.api_jwt.decode",
        "jwt.api_jwt.decode_complete",
        "jose.jwt.decode",
    }
)
_HASHLIB_FAST: Final = frozenset(
    "hashlib." + name
    for name in (
        "blake2b blake2s md5 new sha1 sha224 sha256 sha384 sha3_224 sha3_256 sha3_384 "
        "sha3_512 sha512".split()
    )
)
_ENV_GETTERS: Final = frozenset(
    {"os.environ.get", "os.environ.setdefault", "os.getenv"}
)
_HTTP_CLIENT_ROOTS: Final = frozenset({"httpx", "requests"})
# Calls on a client or session object whose type the visitor cannot see.
_HTTP_CLIENT_METHODS: Final = frozenset(
    "AsyncClient Client Session build_request delete get head options patch post put "
    "request send stream".split()
)
_ROUTE_CALLS: Final = frozenset({"Route", "add_api_route", "add_route", "add_url_rule"})
_BCRYPT_ROUNDS_KEYWORDS: Final = ("bcrypt__rounds", "bcrypt__default_rounds")
_CLAIM_MUTATORS: Final = frozenset({"__setitem__", "setdefault", "update"})
_WILDCARD_ORIGIN_REGEXES: Final = frozenset(
    {".*", ".+", "^.*", "^.+", ".*$", ".+$", "^.*$", "^.+$", "(.*)", "^(.*)$"}
)


def _written_name(expr: ast.expr) -> str:
    """Return a call target as written in the source, for messages."""
    parts: list[str] = []
    while isinstance(expr, ast.Attribute):
        parts.append(expr.attr)
        expr = expr.value
    if isinstance(expr, ast.Name):
        parts.append(expr.id)
    elif parts:
        parts.append("...")
    else:
        return "call"
    return ".".join(reversed(parts))


def _bool_literal(expr: ast.expr | None) -> bool | None:
    if isinstance(expr, ast.Constant) and isinstance(expr.value, bool):
        return expr.value
    return None


def _int_literal(expr: ast.expr | None) -> int | None:
    if (
        isinstance(expr, ast.Constant)
        and isinstance(expr.value, int)
        and not isinstance(expr.value, bool)
    ):
        return expr.value
    return None


def _str_constant(expr: ast.expr | None) -> str | None:
    if isinstance(expr, ast.Constant):
        if isinstance(expr.value, str):
            return expr.value
        if isinstance(expr.value, bytes):
            return expr.value.decode("latin-1")
    return None


def _is_none(expr: ast.expr | None) -> bool:
    return isinstance(expr, ast.Constant) and expr.value is None


def _is_trivial_literal(expr: ast.expr) -> bool:
    """Return True for a literal that is no secret: None, numbers, short words."""
    if not isinstance(expr, ast.Constant):
        return False
    text = _str_constant(expr)
    if text is None:
        return True
    return len(text) < 8 or any(char.isspace() for char in text)


def _keyword_map(call: ast.Call) -> tuple[dict[str, ast.expr], bool]:
    """Return the named keyword arguments and whether ``**kwargs`` is present."""
    named: dict[str, ast.expr] = {}
    star = False
    for keyword in call.keywords:
        if keyword.arg is None:
            star = True
        else:
            named[keyword.arg] = keyword.value
    return named, star


def _argument(
    call: ast.Call, keywords: dict[str, ast.expr], index: int, *names: str
) -> ast.expr | None:
    """Return an argument given by keyword or at a position, or None."""
    for name in names:
        if name in keywords:
            return keywords[name]
    if index < len(call.args) and not any(
        isinstance(arg, ast.Starred) for arg in call.args[: index + 1]
    ):
        return call.args[index]
    return None


# ---------------------------------------------------------------------------- visitor


@dataclass(slots=True)
class _Scope:
    kind: str
    values: dict[str, ast.expr] = field(default_factory=lambda: dict[str, ast.expr]())
    # Dict variables that hold JWT claims: True when they may contain "exp".
    claims: dict[str, bool] = field(default_factory=lambda: dict[str, bool]())
    hashers: set[str] = field(default_factory=lambda: set[str]())


class _Visitor(ast.NodeVisitor):
    def __init__(self, enabled: frozenset[str]) -> None:
        self._on = enabled
        self._aliases: dict[str, str] = {}
        self._facts = FileFacts()
        self._module = _Scope("module")
        self._scopes: list[_Scope] = [self._module]
        self._in_assert = 0
        # GA008 findings on objects of unknown type, kept only when the file imports
        # requests or httpx.
        self._tls_candidates: list[RawFinding] = []

    # ------------------------------------------------------------------ plumbing

    def finish(self) -> FileFacts:
        if self._tls_candidates and any(
            name.split(".", 1)[0] in _HTTP_CLIENT_ROOTS for name in self._facts.imports
        ):
            self._facts.findings.extend(self._tls_candidates)
        self._facts.findings.sort(key=lambda item: (item.line, item.col, item.rule_id))
        return self._facts

    @staticmethod
    def _finding(rule_id: str, node: _Located, message: str) -> RawFinding:
        end_line = node.end_lineno if node.end_lineno is not None else node.lineno
        end_col = (
            node.end_col_offset if node.end_col_offset is not None else node.col_offset
        )
        return RawFinding(
            rule_id=rule_id,
            message=message,
            line=node.lineno,
            col=node.col_offset,
            end_line=end_line,
            end_col=end_col,
        )

    def _report(self, rule_id: str, node: _Located, message: str) -> None:
        self._facts.findings.append(self._finding(rule_id, node, message))

    @property
    def _scope(self) -> _Scope:
        return self._scopes[-1]

    def _visit_scoped(self, node: ast.AST, kind: str) -> None:
        self._scopes.append(_Scope(kind))
        try:
            self.generic_visit(node)
        finally:
            self._scopes.pop()

    def _lookup(self, name: str) -> ast.expr | None:
        value = self._scope.values.get(name)
        if value is None and self._scope is not self._module:
            value = self._module.values.get(name)
        return value

    def _resolve(self, expr: ast.expr) -> str | None:
        """Return the dotted name of ``expr`` with import aliases expanded."""
        parts: list[str] = []
        while isinstance(expr, ast.Attribute):
            parts.append(expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        parts.append(self._aliases.get(expr.id, expr.id))
        return ".".join(reversed(parts))

    def _literal(self, expr: ast.expr | None, depth: int = 0) -> str | None:
        """Return the string literal ``expr`` holds, following simple names."""
        value = _str_constant(expr)
        if value is not None or depth > 2 or not isinstance(expr, ast.Name):
            return value
        return self._literal(self._lookup(expr.id), depth + 1)

    def _env_default(self, expr: ast.expr | None) -> str | None:
        """Return the literal default of ``os.getenv("NAME", "default")``."""
        if isinstance(expr, ast.Name):
            expr = self._lookup(expr.id)
        if (
            not isinstance(expr, ast.Call)
            or self._resolve(expr.func) not in _ENV_GETTERS
        ):
            return None
        keywords, _ = _keyword_map(expr)
        return _str_constant(_argument(expr, keywords, 1, "default"))

    # ------------------------------------------------------------------ scopes

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_route_decorators(node)
        self._visit_scoped(node, "function")

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_route_decorators(node)
        self._visit_scoped(node, "function")

    def visit_Lambda(self, node: ast.Lambda) -> None:
        self._visit_scoped(node, "function")

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self._visit_scoped(node, "class")

    def visit_Assert(self, node: ast.Assert) -> None:
        self._in_assert += 1
        try:
            self.generic_visit(node)
        finally:
            self._in_assert -= 1

    # ------------------------------------------------------------------ imports

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            self._facts.imports.add(alias.name)
            if alias.asname:
                self._aliases[alias.asname] = alias.name
            else:
                root = alias.name.split(".", 1)[0]
                self._aliases[root] = root
            self._check_import(node, alias.name)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        if node.level:
            module = "." * node.level + (node.module or "")
        else:
            module = node.module or ""
            self._facts.imports.add(module)
            self._check_import(node, module)
        for alias in node.names:
            if alias.name == "*":
                continue
            full = f"{module}.{alias.name}" if module else alias.name
            if not node.level:
                self._facts.imports.add(full)
            self._aliases[alias.asname or alias.name] = full

    def _check_import(self, node: ast.stmt, module: str) -> None:
        root = module.split(".", 1)[0]
        if root == "passlib" and "GA001" in self._on:
            self._report(
                "GA001",
                node,
                "passlib is imported; its last release is 1.7.4 (October 2020).",
            )
        elif root == "jose" and "GA002" in self._on:
            self._report(
                "GA002",
                node,
                "python-jose is imported; releases before 3.4.0 are affected by "
                "CVE-2024-33663 and CVE-2024-33664.",
            )

    # ------------------------------------------------------------------ assignments

    def visit_Assign(self, node: ast.Assign) -> None:
        self.generic_visit(node)
        for target in node.targets:
            self._check_assignment(node, target, node.value)
            self._bind(target, node.value)

    def visit_AnnAssign(self, node: ast.AnnAssign) -> None:
        self.generic_visit(node)
        if node.value is not None:
            self._check_assignment(node, node.target, node.value)
            self._bind(node.target, node.value)

    def visit_AugAssign(self, node: ast.AugAssign) -> None:
        self.generic_visit(node)
        if isinstance(node.target, ast.Name) and node.target.id in self._scope.claims:
            self._scope.claims[node.target.id] = True  # payload |= {...}

    def _bind(self, target: ast.expr, value: ast.expr) -> None:
        scope = self._scope
        if isinstance(target, ast.Name):
            name = target.id
            scope.values[name] = value
            has_exp = self._claims_have_exp(value, follow_names=False)
            if has_exp is None:
                scope.claims.pop(name, None)
            else:
                scope.claims[name] = has_exp
            if (
                isinstance(value, ast.Call)
                and self._resolve(value.func) in _HASHLIB_FAST
            ):
                scope.hashers.add(name)
            else:
                scope.hashers.discard(name)
        elif isinstance(target, ast.Subscript) and isinstance(target.value, ast.Name):
            # payload["exp"] = ..., or a key the visitor cannot read: assume exp.
            if target.value.id in scope.claims:
                scope.claims[target.value.id] = True

    def _check_assignment(
        self, node: ast.stmt, target: ast.expr, value: ast.expr
    ) -> None:
        if isinstance(target, ast.Name):
            name = target.id
        elif isinstance(target, ast.Attribute):
            name = target.attr
            if (
                name == "verify"
                and _bool_literal(value) is False
                and "GA008" in self._on
            ):
                # session.verify = False on a requests.Session
                self._tls_candidates.append(
                    self._finding(
                        "GA008", node, f"{_written_name(target)} is set to False."
                    )
                )
                return
        elif isinstance(target, ast.Subscript):
            # app.config["SECRET_KEY"] = ..., os.environ["API_TOKEN"] = ...
            subscript = _str_constant(target.slice)
            if subscript is None:
                return
            name = subscript
        else:
            return
        if "GA009" in self._on:
            strength = _secret_strength(words(name))
            outside_function = self._scope.kind != "function"
            literal = _str_constant(value)
            if (
                literal is not None
                and (strength == 2 or (strength == 1 and outside_function))
                and looks_random(literal)
            ):
                self._report(
                    "GA009",
                    node,
                    f"{name} is assigned a hard-coded high-entropy string.",
                )
        if "GA011" in self._on and name.upper() == "BCRYPT_LOG_ROUNDS":
            self._check_rounds(node, _int_literal(value))  # Flask-Bcrypt setting

    # ------------------------------------------------------------------ expressions

    def visit_Dict(self, node: ast.Dict) -> None:
        self.generic_visit(node)
        if "GA009" not in self._on:
            return
        for key, value in zip(node.keys, node.values, strict=True):
            name = _str_constant(key)
            literal = _str_constant(value)
            if (
                key is not None
                and name is not None
                and literal is not None
                and _secret_strength(words(name)) == 2
                and looks_random(literal)
            ):
                self._report(
                    "GA009",
                    key,
                    f'"{name}" is set to a hard-coded high-entropy string.',
                )

    def visit_Compare(self, node: ast.Compare) -> None:
        self.generic_visit(node)
        if "GA006" not in self._on or self._in_assert:
            return
        operands = [node.left, *node.comparators]
        for index, op in enumerate(node.ops):
            if not isinstance(op, ast.Eq | ast.NotEq):
                continue
            name = self._timing_unsafe_name(operands[index], operands[index + 1])
            if name is not None:
                symbol = "==" if isinstance(op, ast.Eq) else "!="
                message = f"{name} is compared with {symbol}"
                self._report("GA006", node, message + " instead of in constant time.")
                return

    def visit_Call(self, node: ast.Call) -> None:
        self.generic_visit(node)
        on = self._on
        name = self._resolve(node.func)
        keywords, star = _keyword_map(node)
        if name in _JWT_ENCODE:
            if "GA003" in on:
                self._check_jwt_secret(node, keywords)
            if "GA005" in on:
                self._check_jwt_exp(node, keywords)
        elif name in _JWT_DECODE:
            if "GA004" in on:
                self._check_jwt_decode(node, keywords, star)
        elif name in _HASHLIB_FAST and "GA010" in on:
            data = _argument(
                node, keywords, 1 if name == "hashlib.new" else 0, "data", "string"
            )
            if data is not None and self._mentions_password(data):
                self._report(
                    "GA010",
                    node,
                    f"{_written_name(node.func)} is applied to a password-like value.",
                )
        if isinstance(node.func, ast.Attribute):
            self._check_method_call(node, node.func, keywords, star)
        if "GA008" in on and _bool_literal(keywords.get("verify")) is False:
            self._check_tls(node, name)
        if "GA009" in on:
            self._check_secret_keywords(node, name)
        if "GA011" in on:
            self._check_bcrypt_call(node, name, keywords)
        if "GA013" in on:
            self._check_cors(node, keywords)
        if (
            "GA007" in on
            and name is not None
            and name.rsplit(".", 1)[-1] in _ROUTE_CALLS
        ):
            self._check_route_call(node, keywords)

    def _check_method_call(
        self,
        node: ast.Call,
        func: ast.Attribute,
        keywords: dict[str, ast.expr],
        star: bool,
    ) -> None:
        receiver = func.value
        if isinstance(receiver, ast.Name):
            scope = self._scope
            if func.attr in _CLAIM_MUTATORS and receiver.id in scope.claims:
                scope.claims[receiver.id] = True
            if (
                func.attr == "update"
                and receiver.id in scope.hashers
                and "GA010" in self._on
                and node.args
                and self._mentions_password(node.args[0])
            ):
                self._report(
                    "GA010",
                    node,
                    f"{receiver.id}.update is applied to a password-like value.",
                )
        if func.attr == "set_cookie" and "GA012" in self._on and not star:
            self._check_cookie(node, keywords)

    # ------------------------------------------------------------------ GA003 to GA005

    def _check_jwt_secret(self, node: ast.Call, keywords: dict[str, ast.expr]) -> None:
        algorithm_expr = _argument(node, keywords, 2, "algorithm")
        if algorithm_expr is None:
            algorithm: str | None = "HS256"  # the PyJWT and python-jose default
        elif _is_none(algorithm_expr):
            return  # unsigned tokens: no secret involved
        else:
            algorithm = self._literal(algorithm_expr)  # None when not a literal
        if algorithm is not None and not algorithm.upper().startswith("HS"):
            return
        key_expr = _argument(node, keywords, 1, "key")
        if key_expr is None:
            return
        tokens = f"{algorithm} tokens" if algorithm is not None else "tokens"
        call = _written_name(node.func)
        literal = self._literal(key_expr)
        if literal is not None:
            size = f" {len(literal)}-character" if len(literal) < 32 else ""
            self._report(
                "GA003", node, f"{call} signs {tokens} with a hard-coded{size} secret."
            )
        elif self._env_default(key_expr) is not None:
            self._report(
                "GA003",
                node,
                f"{call} signs {tokens} with a secret that falls back to a hard-coded "
                "value when the environment variable is not set.",
            )

    def _claims_have_exp(self, expr: ast.expr, *, follow_names: bool) -> bool | None:
        """Return whether a claims dict has "exp": True, False or None (unknown)."""
        if isinstance(expr, ast.Dict):
            unknown = False
            for key in expr.keys:
                key_name = _str_constant(key)
                if key_name == "exp":
                    return True
                if key_name is None:
                    unknown = True  # {**other} or a computed key
            return None if unknown else False
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Name)
            and expr.func.id == "dict"
            and "dict" not in self._aliases
        ):
            if expr.args:
                return None
            names = [keyword.arg for keyword in expr.keywords]
            if "exp" in names:
                return True
            return None if None in names else False
        if follow_names and isinstance(expr, ast.Name):
            return self._scope.claims.get(expr.id)
        return None

    def _check_jwt_exp(self, node: ast.Call, keywords: dict[str, ast.expr]) -> None:
        payload = _argument(node, keywords, 0, "payload", "claims")
        if (
            payload is not None
            and self._claims_have_exp(payload, follow_names=True) is False
        ):
            self._report(
                "GA005",
                payload,
                f"{_written_name(node.func)} payload has no exp claim.",
            )

    def _check_jwt_decode(
        self, node: ast.Call, keywords: dict[str, ast.expr], star: bool
    ) -> None:
        call = _written_name(node.func)
        options = keywords.get("options")
        if isinstance(options, ast.Dict):
            for key, value in zip(options.keys, options.values, strict=True):
                if (
                    _str_constant(key) == "verify_signature"
                    and _bool_literal(value) is False
                ):
                    self._report(
                        "GA004", node, f"{call} turns off signature verification."
                    )
                    return
        if _bool_literal(keywords.get("verify")) is False:  # PyJWT 1.x
            self._report("GA004", node, f"{call} turns off signature verification.")
            return
        algorithms = _argument(node, keywords, 2, "algorithms")
        if algorithms is None:
            if not star and not any(isinstance(arg, ast.Starred) for arg in node.args):
                self._report("GA004", node, f"{call} does not pass algorithms=[...].")
        elif _is_none(algorithms):
            self._report("GA004", node, f"{call} passes algorithms=None.")
        elif isinstance(algorithms, ast.List | ast.Tuple | ast.Set) and any(
            (_str_constant(item) or "").lower() == "none" for item in algorithms.elts
        ):
            self._report("GA004", node, f'{call} accepts the "none" algorithm.')

    # ------------------------------------------------------------------ GA006

    @staticmethod
    def _operand_name(expr: ast.expr) -> str | None:
        if isinstance(expr, ast.Name):
            return expr.id
        if isinstance(expr, ast.Attribute):
            return expr.attr
        if isinstance(expr, ast.Subscript):
            return _str_constant(expr.slice)
        if isinstance(expr, ast.Call):
            func = expr.func
            if isinstance(func, ast.Attribute):
                if func.attr == "get" and expr.args:
                    return _str_constant(expr.args[0])  # headers.get("X-Signature")
                return func.attr  # .hexdigest(), .compute_signature()
            if isinstance(func, ast.Name):
                return func.id
        return None

    def _timing_unsafe_name(self, left: ast.expr, right: ast.expr) -> str | None:
        if _is_trivial_literal(left) or _is_trivial_literal(right):
            return None
        left_name = self._operand_name(left)
        right_name = self._operand_name(right)
        left_words = words(left_name) if left_name else ()
        right_words = words(right_name) if right_name else ()
        left_secret = _is_compare_secret(left_words)
        right_secret = _is_compare_secret(right_words)
        if not (left_secret or right_secret):
            return None
        if _CONFIRM_WORDS.intersection(left_words) or _CONFIRM_WORDS.intersection(
            right_words
        ):
            return None  # password == confirm_password
        if left_secret and right_secret:
            left_core = tuple(part for part in left_words if not part.isdigit())
            right_core = tuple(part for part in right_words if not part.isdigit())
            if left_core == right_core and left_words != right_words:
                return None  # password1 != password2
            if ("new" in left_words and _EARLIER_WORDS.intersection(right_words)) or (
                "new" in right_words and _EARLIER_WORDS.intersection(left_words)
            ):
                return None  # new_password == old_password
        return left_name if left_secret else right_name

    # ------------------------------------------------------------------ GA007

    def _check_route_decorators(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        if "GA007" not in self._on:
            return
        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call):
                continue
            func = decorator.func
            if isinstance(func, ast.Attribute):
                method = func.attr
            elif isinstance(func, ast.Name):
                method = func.id
            else:
                continue
            keywords, _ = _keyword_map(decorator)
            if method == "post":
                pass
            elif method in ("route", "api_route"):
                if not self._methods_include_post(keywords.get("methods")):
                    continue
            else:
                continue
            path = _str_constant(_argument(decorator, keywords, 0, "path", "rule"))
            if self._report_login_route(decorator, path, node.name):
                return

    def _check_route_call(self, node: ast.Call, keywords: dict[str, ast.expr]) -> None:
        if not self._methods_include_post(keywords.get("methods")):
            return
        path = _str_constant(_argument(node, keywords, 0, "path", "rule"))
        endpoint: str | None = None
        for candidate in (
            keywords.get("endpoint"),
            keywords.get("view_func"),
            *node.args[1:3],
        ):
            if isinstance(candidate, ast.Name):
                endpoint = candidate.id
                break
            if isinstance(candidate, ast.Attribute):
                endpoint = candidate.attr
                break
        self._report_login_route(node, path, endpoint)

    def _methods_include_post(self, methods: ast.expr | None) -> bool:
        if isinstance(methods, ast.Name):
            methods = self._lookup(methods.id)
        if not isinstance(methods, ast.List | ast.Tuple | ast.Set):
            return False
        return any(
            (_str_constant(item) or "").upper() == "POST" for item in methods.elts
        )

    def _report_login_route(
        self, node: ast.Call, path: str | None, function: str | None
    ) -> bool:
        if path is not None and _is_login_like(path):
            label = f'POST route "{path}"'
        elif function is not None and _is_login_like(function):
            label = (
                f"POST route {function}()"
                if path is None
                else f'POST route "{path}" ({function})'
            )
        else:
            return False
        message = f"{label} looks like a sign-in endpoint"
        self._report("GA007", node, message + " and the project has no rate limiter.")
        return True

    # ------------------------------------------------------------------ GA008

    def _check_tls(self, node: ast.Call, name: str | None) -> None:
        message = f"{_written_name(node.func)} is called with verify=False."
        if name is not None and name.split(".", 1)[0] in _HTTP_CLIENT_ROOTS:
            self._report("GA008", node, message)
        elif (
            isinstance(node.func, ast.Attribute)
            and node.func.attr in _HTTP_CLIENT_METHODS
        ):
            self._tls_candidates.append(self._finding("GA008", node, message))

    # ------------------------------------------------------------------ GA009

    def _check_secret_keywords(self, node: ast.Call, name: str | None) -> None:
        for keyword in node.keywords:
            if keyword.arg is None:
                continue
            literal = _str_constant(keyword.value)
            if (
                literal is not None
                and _secret_strength(words(keyword.arg)) == 2
                and looks_random(literal)
            ):
                self._report(
                    "GA009",
                    keyword,
                    f"{keyword.arg}= is passed a hard-coded high-entropy string.",
                )
        if name in _ENV_GETTERS and len(node.args) >= 2:
            variable = _str_constant(node.args[0])
            default = _str_constant(node.args[1])
            if (
                variable is not None
                and default is not None
                and _secret_strength(words(variable)) > 0
                and looks_random(default)
            ):
                self._report(
                    "GA009",
                    node.args[1],
                    f"{variable} falls back to a hard-coded high-entropy string.",
                )

    # ------------------------------------------------------------------ GA010

    @staticmethod
    def _mentions_password(expr: ast.expr) -> bool:
        for child in ast.walk(expr):
            if isinstance(child, ast.Name):
                name: str | None = child.id
            elif isinstance(child, ast.Attribute):
                name = child.attr
            elif isinstance(child, ast.Subscript):
                name = _str_constant(child.slice)
            else:
                continue
            if name is not None and _PASSWORD_WORDS.intersection(words(name)):
                return True
        return False

    # ------------------------------------------------------------------ GA011

    def _check_bcrypt_call(
        self, node: ast.Call, name: str | None, keywords: dict[str, ast.expr]
    ) -> None:
        for keyword in _BCRYPT_ROUNDS_KEYWORDS:
            if keyword in keywords:  # passlib CryptContext(bcrypt__rounds=...)
                self._check_rounds(node, _int_literal(keywords[keyword]))
                return
        if name is None:
            return
        if name == "bcrypt.gensalt" or name.endswith("hashers.bcrypt.BcryptHasher"):
            rounds = _argument(node, keywords, 0, "rounds")
            self._check_rounds(node, _int_literal(rounds))
        elif name.startswith("passlib.hash.bcrypt") and name.endswith(".using"):
            rounds = keywords.get("rounds", keywords.get("default_rounds"))
            self._check_rounds(node, _int_literal(rounds))

    def _check_rounds(self, node: _Located, rounds: int | None) -> None:
        if rounds is not None and rounds < 10:
            self._report("GA011", node, f"bcrypt cost factor {rounds} is below 10.")

    # ------------------------------------------------------------------ GA012

    def _check_cookie(self, node: ast.Call, keywords: dict[str, ast.expr]) -> None:
        # Starlette, Werkzeug (Flask) and Django share the positional order
        # (key, value, max_age, expires, path, domain, secure, httponly, samesite).
        secure = _argument(node, keywords, 6, "secure")
        httponly = _argument(node, keywords, 7, "httponly")
        cookie = (_str_constant(_argument(node, keywords, 0, "key")) or "").lower()
        # A CSRF cookie has to be readable by JavaScript in the double-submit pattern.
        csrf_cookie = "csrf" in cookie or "xsrf" in cookie
        missing: list[str] = []
        if not csrf_cookie and (
            httponly is None or _is_none(httponly) or _bool_literal(httponly) is False
        ):
            missing.append("httponly=True")
        if secure is None or _is_none(secure) or _bool_literal(secure) is False:
            missing.append("secure=True")
        if missing:
            without = " and ".join(missing)
            message = f"{_written_name(node.func)} is called without {without}."
            self._report("GA012", node, message)

    # ------------------------------------------------------------------ GA013

    def _check_cors(self, node: ast.Call, keywords: dict[str, ast.expr]) -> None:
        credentials = keywords.get(
            "allow_credentials", keywords.get("supports_credentials")
        )
        if _bool_literal(credentials) is not True:
            return
        origins = keywords.get("allow_origins", keywords.get("origins"))
        if isinstance(origins, ast.Name):
            origins = self._lookup(origins.id)
        wildcard = _str_constant(origins) == "*"
        if isinstance(origins, ast.List | ast.Tuple | ast.Set):
            wildcard = any(_str_constant(item) == "*" for item in origins.elts)
        regex = self._literal(keywords.get("allow_origin_regex"))
        if wildcard or regex in _WILDCARD_ORIGIN_REGEXES:
            self._report(
                "GA013", node, "CORS allows every origin together with credentials."
            )
