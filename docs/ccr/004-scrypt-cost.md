# CCR: scrypt cost at the OWASP minimum

- Requested by: Q1 ([request](../requests/Q1-F3-scrypt-cost.md), issue #6)
- Status: accepted 2026-10-12 (CONTRACT_VERSION 4)
- CONTRACTS section: 8, password hash format
- Affected work packages: F3 (crypto kit), C2 (rehash at sign-in), I1 (imports keep their own format)

## Change
The default scrypt parameters go from `ln=15, r=8, p=1` to `ln=15, r=8, p=3`:

- before: `scrypt$ln=15,r=8,p=1$<b64 salt>$<b64 hash>`
- after: `scrypt$ln=15,r=8,p=3$<b64 salt>$<b64 hash>`

## Why
The OWASP Password Storage Cheat Sheet (checked 2026-10-10) sets the scrypt minimum at N=2^17, r=8, p=1, or an equivalent such as N=2^15, r=8, p=3. The old default cost a third of that. ASVS 11.4.2 (Level 2) asks for parameters from current guidance. `p=3` keeps the memory at 32 MiB per hash, which matters for small containers, and triples the CPU cost.

## Compatibility
- **Stored hashes:** every hash carries its own parameters, so `p=1` hashes still verify. `verify_password` reports `needs_rehash`, and C2 rehashes at the next successful sign-in. The spec vectors include this case.
- **Sign-in time:** about three times the old hashing time.
- **Spec vectors:** the default-parameter vectors in `spec/password-hash.json` are regenerated at `p=3` and checked by `spec/crosscheck.mjs`.

## Blocked work
None.
