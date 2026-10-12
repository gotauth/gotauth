# Q1: email and password gaps from the ASVS mapping

| | |
|---|---|
| From | Q1 (`docs/security/asvs.md`) |
| For | C2 (`src/gotauth/email_password/`); items 2 and 3 add config, so they need a CCR |
| Date | 2026-10-10 |

## What and why

### 1. `change_email` without a fresh session (ASVS 7.5.1, Level 2)
`change_password`, `delete_user` and `unlink_account` are declared with `fresh_session=True`; `change_email` is not. A stolen session older than `fresh_age` can therefore start an email change. The link goes to the new address, which the thief controls, and the old address only gets a notice after the change.

**Applied 2026-10-12** as [CCR 005](../ccr/005-change-email-fresh.md).

**Proposed:** add `fresh_session=True` to the `change_email` endpoint and mark it "session, fresh" in the CONTRACTS 13.1 table. It is a one-line code change plus the table edit.

### 2. No check against common passwords (ASVS 6.2.4, Level 1)
Sign-up, reset and change accept any password of 8 to 128 characters.

**Proposed:** ship a list of the top 10,000 passwords of 8 or more characters as package data. Reject matches with `PASSWORD_TOO_WEAK` (a new code, so a CCR). Add `email_password={"check_common_passwords": True}` to turn it off.

### 3. No breached-password or context-word hook (ASVS 6.2.12, 6.1.2, 6.2.11, Level 2)
**Proposed:** add `email_password={"password_check": async (password, user_or_email) -> str | None}` that returns an error message or `None`. It runs after the length and common-password checks. The docs show a k-anonymity Have I Been Pwned example, and the app's own word list for 6.1.2. GotAuth does not call any external service by default.

## In the meantime
`docs/security/asvs.md` lists 6.1.2, 6.2.4, 6.2.11 and 6.2.12 as not met, and 7.5.1 as partial.
