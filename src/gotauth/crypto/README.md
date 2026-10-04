# gotauth.crypto

The crypto kit: every cryptographic operation GotAuth performs, behind the `CryptoKit` protocol of CONTRACTS section 8. Other modules use it as `ctx.crypto` and never call `secrets`, `hmac` or `hashlib` themselves.

## Example

```python
import asyncio
from datetime import UTC, datetime

from gotauth.crypto import crypto_kit

# The first secret signs and encrypts; every secret in the list verifies.
kit = crypto_kit(
    [
        "new-secret-with-at-least-32-characters",
        "old-secret-kept-until-its-values-expire",
    ]
)


async def main() -> None:
    # Passwords (scrypt by default, in a worker thread).
    stored = await kit.hash_password("correct horse battery staple")
    check = await kit.verify_password("correct horse battery staple", stored)
    assert check.ok and not check.needs_rehash
    # Unknown user: pass "" so the response takes as long as a wrong password.
    assert not (await kit.verify_password("guess", "")).ok

    # Tokens: show the raw value once, store only the hash.
    token = kit.random_token("gas_")
    token_hash = kit.hash_token(token)
    assert kit.equal(kit.hash_token(token), token_hash)

    # Signed and encrypted values, bound to a purpose.
    cookie = kit.sign("usr_123", purpose="challenge")
    assert kit.unsign(cookie, purpose="challenge") == "usr_123"
    assert kit.unsign(cookie, purpose="oauth_state") is None
    sealed = kit.encrypt("provider-access-token", purpose="account_token")
    assert kit.decrypt(sealed, purpose="account_token") == "provider-access-token"

    # TOTP: verify_totp returns the time step, so a caller can refuse its reuse.
    secret = kit.new_totp_secret()
    now = datetime.now(UTC)
    step = kit.verify_totp(secret, kit.totp(secret, at=now), at=now)
    assert step is not None


asyncio.run(main())
```

Code without an endpoint context (an id generator, a CLI command) can use the functions that need no secret directly: `random_token`, `hash_token`, `equal`, `pkce_s256`, `new_ulid`, `new_otp`, `new_totp_secret`, `totp` and `verify_totp` are exported by `gotauth.crypto`.

## What it does and with which parameters

| Operation | Algorithm and format |
|---|---|
| `random_token(prefix, nbytes=32)` | `secrets.token_bytes`, base64url without padding: 32 bytes give 43 characters. At least 16 bytes |
| `hash_token(token)` | SHA-256 of the UTF-8 bytes, lower-case hex |
| `equal(a, b)` | `hmac.compare_digest` on bytes (text as UTF-8) |
| `hash_password` | `scrypt$ln=15,r=8,p=1$<salt>$<hash>`: `hashlib.scrypt`, N = 2**15, 16-byte salt, 64-byte key, standard base64 without padding, `maxmem` 64 MiB. With `password_algorithm="argon2id"`: `argon2id$<PHC string>` with argon2-cffi's defaults (t=3, m=64 MiB, p=4) |
| `verify_password` | Accepts `scrypt$`, `argon2id$` and `bcrypt$<$2a$, $2b$ or $2y$ hash>` (verify-only, for imports; the password is cut to 72 bytes first, as passlib did). Limits on stored hashes: scrypt ln at most 20, r at most 32, p at most 16 and 128 * r * N at most 1 GiB; bcrypt cost 4 to 16; argon2 memory at most 1 GiB, t and p at most 32 |
| `derive_key(purpose, length=32)` | HKDF-SHA256 over the first secret, no salt, `info = b"gotauth:" + purpose` |
| `sign(value, purpose=)` | `"<value>.<b64url HMAC-SHA256>"` keyed with `derive_key("sign:" + purpose)` |
| `encrypt(plaintext, purpose=)` | AES-256-GCM keyed with `derive_key("encrypt")`, random 12-byte nonce, the purpose as associated data: `"v1.<b64url nonce>.<b64url ciphertext and tag>"` |
| `totp`, `verify_totp` | RFC 6238 with HMAC-SHA-1, 30-second steps, 6 digits by default (6 to 8), `window=1` step on each side (0 to 10) |
| `new_totp_secret()` | 20 random bytes, upper-case base32 without padding (32 characters) |
| `new_otp(digits=6)` | `secrets.randbelow(10**digits)`, zero-padded, so every code is equally likely. 4 to 12 digits |
| `pkce_s256(verifier)` | RFC 7636 S256; the verifier must be 43 to 128 unreserved characters |
| `new_ulid(at)` | 26-character ULID, strictly increasing within one millisecond across all kits in the process |

## Rules worth knowing

- **Secrets:** each one has at least 32 characters, otherwise `crypto_kit` raises `ConfigError`. To rotate, put the new secret first and keep the old one until everything signed or encrypted with it has expired. `repr(kit)` and error messages never show a secret, and the kit logs nothing.
- **Purposes** are opaque strings that separate keys and ciphertexts: a value signed or encrypted for one purpose never verifies for another. The registry of who owns which purpose is CONTRACTS section 8; reusing another module's purpose is a bug. An empty purpose raises `ValueError`.
- **Failures return None or `ok=False`.** `unsign` and `decrypt` return None for anything tampered with, truncated, malformed, signed for another purpose or under a removed secret. `verify_password` returns `ok=False` for a wrong password, an empty `stored`, an unknown tag or a malformed hash, and in all of these cases first runs a full hash with the configured algorithm, so the time taken does not tell them apart. `needs_rehash` is only True when `ok` is True.
- **Optional extras:** `password_algorithm="argon2id"` without the `argon2` extra raises `ConfigError` at construction. Verifying a stored `argon2id$` or `bcrypt$` hash without its extra (`gotauth[argon2]`, `gotauth[bcrypt]`) raises `ConfigError` at verification, so a missing dependency shows up as a server error with the install hint, never as a silent "wrong password".
- **Threads and memory:** password hashing runs through `asyncio.to_thread`, so the event loop keeps serving requests. One scrypt hash at the default cost needs 32 MiB while it runs; the default thread pool runs at most `min(32, CPU count + 4)` of them at once.
- **Nonces:** AES-GCM nonces are random, which is safe for about 2**32 encryptions per secret. Rotating the secret starts a new key.
- **Datetimes** passed to `totp`, `verify_totp` and `new_ulid` must be timezone-aware and not before 1970.

## Spec vectors

`spec/*.json` holds the test vectors every implementation must pass byte for byte, and `spec/crosscheck.mjs` recomputes them with Node's crypto and the system `crypt(3)`. See [spec/README.md](../../../spec/README.md). Run them with `./dev.sh uv run poe vectors`.

## Versions

Built and tested against Python 3.11 to 3.14, cryptography 50.0 (the core dependency asks for 44 or later), argon2-cffi 25.1, bcrypt 5.0 and OpenSSL 3.5. bcrypt 5 raises for passwords over 72 bytes instead of cutting them, which is why `verify_password` cuts them first.

## Pending work package F2

`ConfigError` and `PasswordCheck` are defined here until `gotauth.contracts` (work package F2) merges; then they are imported from there (see the `TODO(F2)` notes). `tests/crypto/test_contracts.py` checks the kit against the `CryptoKit` protocol once it exists.
