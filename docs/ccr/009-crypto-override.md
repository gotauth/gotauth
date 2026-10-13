# CCR: a crypto kit override and scrypt parameters

- Requested by: integrator (issue #16)
- Status: accepted 2026-10-13 (CONTRACT_VERSION 9)
- CONTRACTS sections: 8 (crypto kit), 13 (`AdvancedConfig`), 13.2 (`crypto_kit`)
- Affected work packages: F2 (testing kit), F3 (crypto kit), C1 (builds the kit)

## Change
- `crypto_kit(secret, *, password_algorithm="scrypt", scrypt_params=None)`. `scrypt_params` sets the cost of new scrypt hashes; `None` means `DEFAULT_SCRYPT` (`ln=15,r=8,p=3`). A stored hash with other parameters still verifies and reports `needs_rehash`.
- `gotauth.crypto` exports `ScryptParams` and `DEFAULT_SCRYPT`.
- `AdvancedConfig.crypto: CryptoKit | None = None`. When set, `GotAuth` uses it instead of building one from `secret` and `password_algorithm`.
- The testing kit: `make_auth` and `make_context` hash passwords with `gotauth.testing.TEST_SCRYPT` (`ln=10,r=8,p=1`, about 1/100 of the default cost). A test that passes its own `advanced.crypto` gets that kit instead.

## Why
Since CCR 004 raised the default to `p=3`, every password hash in a test costs three times as much, and the Python test jobs went from about 1.5 to about 3.5 minutes. Tests of sign-up, sign-in and password changes do not test the hash cost; the crypto tests and the spec vectors do, and they keep using the default.

## Compatibility
Additive. Production code that does not set the new options is unchanged. An app that sets `advanced.crypto` takes over all of the kit's behaviour, so it must keep its secrets in step with `secret`.

## Blocked work
None.
