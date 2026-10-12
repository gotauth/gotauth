# Q1: raise the default scrypt cost to the OWASP minimum

| | |
|---|---|
| From | Q1 (ASVS mapping, 11.4.2) |
| For | F3 (`src/gotauth/crypto/_passwords.py`) |
| Date | 2026-10-10 |
| Status | Applied 2026-10-12 as [CCR 004](../ccr/004-scrypt-cost.md) (issue #6) |

## What
`DEFAULT_SCRYPT = ScryptParams(ln=15, r=8, p=1)` is below the OWASP Password Storage Cheat Sheet minimum (checked 2026-10-10). The minimum is N=2^17, r=8, p=1. These equivalent settings give the same protection:

| N | Memory | r | p |
|---|---|---|---|
| 2^17 | 128 MiB | 8 | 1 |
| 2^16 | 64 MiB | 8 | 2 |
| 2^15 | 32 MiB | 8 | 3 |
| 2^14 | 16 MiB | 8 | 5 |

Today's default uses the 32 MiB row with p=1 instead of p=3, so it costs a third of the minimum.

## Why
ASVS 11.4.2 (Level 2) asks for parameters set from current guidance. The mapping in `docs/security/asvs.md` records it as partial until this changes.

No migration is needed. Hashes carry their parameters, and C2 already rehashes weak hashes at the next sign-in (`tests/email_password/test_flows.py::test_weak_hashes_are_upgraded_after_sign_in`).

## Proposed diff
```diff
-DEFAULT_SCRYPT = ScryptParams(ln=15, r=8, p=1)
+DEFAULT_SCRYPT = ScryptParams(ln=15, r=8, p=3)
```
This keeps memory at 32 MiB per hash, which matters for small containers, and triples the CPU cost. Update the spec vectors and the CONTRACTS 8 text, which names the parameters, through a CCR.

The argon2id extra is not affected: argon2-cffi's defaults are above the OWASP minimum.
