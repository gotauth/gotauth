# gotauth.email

The email service, default templates and senders. Work package D1. Built against
aiosmtplib 5.1.3 (tested with aiosmtpd 1.4.6) and the Resend `POST /emails` API
(checked 2026-10-07).

```python
from gotauth.contracts import EmailConfig
from gotauth.email import smtp_sender

auth = GotAuth(
    ...,
    email=EmailConfig(app_name="Acme", from_address="Acme <no-reply@acme.com>"),
    email_sender=smtp_sender("smtp.acme.com", username="...", password="..."),
)
```

## Senders

| Sender | Notes |
|---|---|
| none, on `localhost` / `127.0.0.1` | The console sender prints each message, links included, to stderr |
| none, elsewhere | Sending raises `ConfigError`; features that need email fail at construction |
| `console_sender()` | Development only: `ConfigError` off localhost |
| `smtp_sender(host, port=587, *, username, password, from_address, start_tls=True, use_tls=False, timeout=10)` | aiosmtplib (the `smtp` extra, checked when the sender is built); multipart/alternative; certificates always checked |
| `resend_sender(api_key, *, from_address, http=None)` | `POST https://api.resend.com/emails` with a bearer key and an `Idempotency-Key` |
| your own | Anything with `async def send(self, message: EmailMessage)` |

The sender's own `from_address` wins; otherwise `EmailConfig.from_address` is used. The
SMTP and Resend senders with neither raise `ConfigError` at construction.

## Templates

Every kind has a default subject, plain text and HTML body (inline styles only: no
remote images, fonts, CSS or tracking pixels). Every value is HTML-escaped. Override per
kind with `EmailConfig(templates={"magic_link": EmailTemplate(subject, text, html)})`
(`string.Template` placeholders such as `$url` and `$app_name`), or replace rendering
completely with `EmailConfig(render=...)`.

| Kind | Data |
|---|---|
| `verify_email`, `magic_link` | `url` |
| `reset_password` | `url` (absolute) |
| `change_email` | `url`, `new_email` |
| `otp` | `code`, `purpose` |
| `invitation` | `url`, `organization_name`, `inviter_name` |
| `sign_up_existing_account` | `url` |
| `security_notice` | `event`, `at`, `ip_address?` |

A `url` starting with `/` is joined to `base_url + base_path`; only http and https links
are allowed. `EmailMessage.data` is the caller's data, unchanged. Each template that
carries a link tells people to ignore emails they did not ask for.

## Safety

- CR or LF in the recipient, subject or from address raises `ValueError`.
- Off localhost, delivery runs in the background so response time does not reveal
  whether an account exists; `auth.drain()` waits for it. Failures are logged with the
  kind and error type only, never links, codes or bodies.
- `EmailSendError` never contains the body, links or credentials. Passwords and API
  keys are kept as `SecretStr`.
- A background email can be sent for a request whose transaction later rolls back; its
  link then fails with `TOKEN_INVALID`.
