# F3: Crypto kit and spec vectors

| | |
|---|---|
| Lane / wave | Foundation / **Phase 0**, parallel with F2 |
| Size | M (2 agent-days) |
| Depends on | F1; F2 types (`contracts/crypto.py`) |
| Can start | when F1 is merged; code against CONTRACTS section 8 and import the Protocol once F2 merges |
| Write scope | `src/gotauth/crypto/**`, `spec/**`, `tests/crypto/`, `changes/F3.*.md` |
| Allowed new deps | none (`cryptography` is core; `argon2-cffi` and `bcrypt` are existing extras, imported lazily) |

## Goal
One place for every cryptographic operation, matching CONTRACTS section 8 exactly, plus language-neutral spec vectors every port must pass byte for byte.

## Build
- Entry point used by C1: `crypto_kit(secret: str | Sequence[str], *, password_algorithm: Literal["scrypt", "argon2id"] = "scrypt") -> CryptoKit`. Each secret >= 32 chars, else ConfigError. The first secret signs and encrypts; all verify. `repr()` never shows secrets.
- `random_token(prefix, nbytes=32)`: `secrets.token_bytes`, base64url, no padding (32 bytes -> 43 chars). `hash_token`: SHA-256 hex of UTF-8. `equal`: `hmac.compare_digest` on bytes.
- Passwords, always through `asyncio.to_thread`:
  - default `scrypt$ln=15,r=8,p=1$<salt>$<hash>`: `hashlib.scrypt`, 16-byte salt, 64-byte key, `maxmem=64 MiB` (N=2^15, r=8 needs 32 MiB, which OpenSSL's default limit rejects); standard base64 without padding, pinned by the vectors.
  - `argon2id$<PHC>` via argon2-cffi when configured; extra missing -> ConfigError with the install hint.
  - `bcrypt$<$2b$...>`: verify only, always `needs_rehash=True`.
  - `verify_password`: unknown or malformed tag -> `ok=False`; empty `stored` -> full dummy hash with the configured algorithm, then `ok=False`; `needs_rehash` when algorithm or parameters differ from the default. Cap parsed scrypt cost (ln <= 20).
- `derive_key(purpose, length=32)`: HKDF-SHA256 (`cryptography`), `salt=None`, `info=b"gotauth:" + purpose`.
- `sign(value, purpose)`: `"<value>.<b64url HMAC-SHA256>"`, key `derive_key("sign:" + purpose)`. `unsign`: split on the last ".", try every secret, compare with `equal`, None on any failure.
- `encrypt` / `decrypt`: AESGCM, key `derive_key("encrypt")`, 12-byte random nonce, `purpose` as associated data, `"v1.<b64url nonce>.<b64url ciphertext+tag>"`. `decrypt` tries every secret; None on tamper, wrong purpose or bad format.
- HOTP/TOTP (RFC 4226 / 6238, SHA-1): `new_totp_secret` (20 bytes, base32, no padding); `totp(secret_b32, at=, digits=6, period=30)`; `verify_totp(..., window=1)` returns the matched time step or None. Accept lower-case and unpadded base32; reject non-digit codes; constant-time compare.
- `new_otp(digits=6)`: uniform numeric code, `secrets.randbelow(10**digits)` zero-padded (no modulo bias). Callers store `hash_token(identifier + ":" + code)` (CONTRACTS 2.1); the kit only makes the code.
- `pkce_s256(verifier)`: base64url(SHA-256(ASCII)), no padding; ValueError outside RFC 7636 (43-128 unreserved chars).
- `new_ulid(at)`: 26-char Crockford base32, monotonic within one millisecond (increment the random part; thread-safe).
- Spec vectors (section 8 table), each case with a `source` field; `spec/README.md` documents the format:
  - `hotp.json` (RFC 4226 appendix D), `totp.json` (RFC 6238 appendix B, SHA-1 rows), `pkce.json` (RFC 7636 appendix B), `hkdf.json` (RFC 5869 SHA-256 cases).
  - `password-hash.json`: RFC 7914 section 12 scrypt vectors with small N, GotAuth-format scrypt hashes, known bcrypt hashes.
  - `sign.json`: fixed secrets; valid, tampered, wrong purpose, rotated.
  - `token-format.json`: prefixes `gas_` `gak_` `gar_` `gac_` `gav_` `gcs_` (section 7), 43-char bodies, regexes; OTP format (`new_otp`).

## Acceptance tests
- `poe vectors` passes every file.
- Hypothesis round trips: sign/unsign, encrypt/decrypt, totp/verify_totp at the same step, random_token format; hash/verify with few examples (slow).
- Tampered value or signature, wrong purpose, wrong secret, truncated ciphertext -> None.
- Rotation: signed or encrypted with `[old]` verifies under `[new, old]`; `[new, old]` signs with `new`.
- Unknown user: `verify_password(pw, "")` runs the full hash (spy) and takes comparable time to a real check (loose ratio, `slow` marker).
- Secret under 32 chars -> ConfigError; `repr(kit)` has no secret.
- A ticker task keeps running during `hash_password` (no loop blocking).
- passlib-made bcrypt hashes verify, including passwords over 72 bytes.
- ULIDs made in one millisecond are strictly increasing.
- `new_otp`: always `digits` ASCII digits, leading zeros kept; a loose frequency test over 10k codes per digit position.

## Out of scope
- Where tokens are stored and compared (C2, C3, P1, O1); JWT access tokens and signing keys (O1).

## Notes
- bcrypt 5 raises on passwords over 72 bytes, while passlib hashed the first 72 bytes: truncate before `checkpw`. Check the current bcrypt and argon2-cffi docs; record versions in the module README.
- Cross-check the GotAuth-format scrypt vectors with an independent implementation, for example Node's `crypto.scrypt` in the dev container.
- Purposes are opaque to the kit. The registry of who owns which purpose string is CONTRACTS section 8; `sign.json` uses two purposes to prove cross-purpose rejection.
