# D1: Email senders and templates

| | |
|---|---|
| Lane / wave | Email / **Wave 1** |
| Size | S-M (1-2 agent-days) |
| Depends on | M0 |
| Can start | after M0 |
| Write scope | `src/gotauth/email/**`, `tests/email/`, `changes/D1.*.md` |
| Allowed new deps | none at runtime (`aiosmtplib` is the existing `smtp` extra, imported lazily; Resend uses core httpx). Dev: aiosmtpd (already in F1's dev group) |

## Goal
The EmailService of CONTRACTS section 9: turns `(kind, to, data)` into a plain-text + HTML message and hands it to a sender (console, SMTP or Resend). Callers (C2, P2, P4, P5) decide what to send; D1 decides how it looks and how it leaves.

## Build
- Entry point (13.2): `email_service(config: ResolvedConfig, sender: EmailSender | None) -> EmailService`. Apps configure it through `GotAuth(email=EmailConfig(...), email_sender=...)`: `config.email` gives `app_name` (default `"GotAuth"`), `from_address`, `templates`, `render`. No sender and a localhost `base_url` -> console sender. No sender off localhost -> a service whose `send` raises ConfigError; C1 raises at construction when a feature needs email (`requires_email`, section 9).
- Public `TemplatedEmailService(sender, *, base_url, base_path, email_config, background=False)`, also usable as the `advanced.email_service` override (tests, advanced use). `send(kind, to, **data)` renders an EmailMessage whose `data` is the caller's data unchanged, then calls `sender.send`.
- `background=True`: render now (so template errors still raise), deliver on an asyncio task (strong references kept, failures logged), `await service.drain()` waits (section 9; `auth.drain()` calls it). `email_service()` turns it on when `base_url` is not localhost, so response time does not reveal whether an account exists (9.1).
- Data keys per kind (callers must use these):

  | Kind | Data |
  |---|---|
  | `verify_email`, `magic_link` | `url` |
  | `reset_password` | `url` (absolute: the app's `redirect_to` page + `?token=gav_...`; there is no GET reset endpoint) |
  | `change_email` | `url`, `new_email` |
  | `otp` | `code`, `purpose` (`sign_in`, `verify_email`, `reset_password`, `two_factor`) |
  | `invitation` | `url`, `organization_name`, `inviter_name` |
  | `sign_up_existing_account` | `url` (sign-in page) |
  | `security_notice` | `event` (an AuthEventType), `at`, `ip_address?` |

  A `url` starting with "/" is joined to `base_url + base_path`; absolute URLs pass through (callers validate them per 10.1). Only http and https.
- Default templates for all eight kinds: subject, plain text, simple HTML with inline styles only (no remote images, fonts, CSS or tracking pixels). Every value is HTML-escaped. Overrides from `EmailConfig`: `templates={kind: EmailTemplate(subject, text, html)}` with `string.Template` placeholders (`$url`, `$app_name`), or `render(kind, to, data) -> EmailMessage`.
- Senders:
  - `console_sender()`: logs recipient, subject and the text body for local development. Raises ConfigError when `base_url` is not `localhost` / `127.0.0.1`.
  - `smtp_sender(host, port=587, *, username=None, password=None, from_address=None, start_tls=True, use_tls=False, timeout=10)`: aiosmtplib, multipart/alternative, certificate checks on.
  - `resend_sender(api_key, *, from_address=None, http=None)`: `POST https://api.resend.com/emails` with a bearer key. Non-2xx -> `EmailSendError` without body or key.
  - A sender's own `from_address` wins; else `email_service()` gives D1's senders `EmailConfig.from_address`; neither -> ConfigError at construction (EmailMessage has no sender field).
- CR or LF in `to`, subject or from address -> ValueError (header injection). Secrets as SecretStr; outside the console sender, never log tokens, URLs or bodies.
- `EmailMessage.from_address` (CONTRACTS 9) is filled from `EmailConfig.from_address` when rendering; senders use it unless they are configured with their own sender address.

## Acceptance tests
- Every kind renders text and HTML; Hypothesis: arbitrary data values are escaped in HTML (no `<script>` survives) and `data` reaches `EmailMessage.data` unchanged.
- Relative `url` joined correctly; `javascript:` URL rejected.
- `EmailConfig` overrides: `app_name` appears in subjects; a `templates` entry and a `render` callable replace the defaults.
- SMTP against an in-process aiosmtpd server: both parts arrive, headers and `from_address` fallback correct, injection rejected.
- Resend via `httpx.MockTransport`: request shape, auth header, error mapping; the key never appears in logs or exceptions (caplog).
- Console sender with a non-localhost `base_url` -> ConfigError; `email_service(config, None)` on localhost (console) and off it (`send` raises ConfigError).
- Background mode: `send` returns before delivery; `drain()` delivers; a failing sender is logged, not raised.

## Out of scope
- When to send and what tokens to create (C2, P2, P4, P5); the construction-time `requires_email` check (C1); retries, queues, bounce handling; more providers (later, by request).

## Notes
- Check the current Resend API docs (fields, idempotency header) and aiosmtplib docs; record versions in the module README.
- Background delivery can send a link for a transaction that later rolls back; the link then fails with TOKEN_INVALID. Accepted.
