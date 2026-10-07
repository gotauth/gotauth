"""Email senders: console (development), SMTP and Resend."""

from __future__ import annotations

import importlib
import logging
import uuid
from email.message import EmailMessage as MimeMessage
from typing import Any

import httpx
from pydantic import SecretStr

from gotauth.contracts.email import EmailMessage
from gotauth.contracts.errors import ConfigError
from gotauth.contracts.sessions import is_localhost

__all__ = [
    "ConsoleSender",
    "EmailSendError",
    "ResendSender",
    "SmtpSender",
    "check_headers",
    "console_sender",
    "resend_sender",
    "smtp_sender",
]

logger = logging.getLogger("gotauth.email")

RESEND_URL = "https://api.resend.com/emails"


class EmailSendError(Exception):
    """Delivery failed. The message never holds the body, links or credentials."""


def check_headers(*values: str | None) -> None:
    """Reject CR and LF in header values (header injection).

    Raises:
        ValueError: When a value contains a line break.
    """
    for value in values:
        if value is not None and ("\r" in value or "\n" in value):
            msg = "email header values must not contain line breaks"
            raise ValueError(msg)


def _from(own: str | None, message: EmailMessage) -> str:
    address = own or message.from_address
    if not address:
        msg = "no from address: set it on the sender or in EmailConfig.from_address"
        raise ConfigError(msg)
    return address


class ConsoleSender:
    """Logs each message, links included. Development only (localhost)."""

    needs_from_address = False
    from_address: str | None = None

    async def send(self, message: EmailMessage) -> None:
        """Log recipient, subject and the text body."""
        logger.info("email to %s: %s\n%s", message.to, message.subject, message.text)


def console_sender(*, base_url: str = "http://localhost") -> ConsoleSender:
    """Return the console sender.

    Raises:
        ConfigError: When ``base_url`` is not localhost or 127.0.0.1: the console
            would log working links.
    """
    if not is_localhost(base_url):
        msg = "the console email sender is for localhost only; configure email_sender"
        raise ConfigError(msg)
    return ConsoleSender()


class SmtpSender:
    """Sends multipart/alternative mail with aiosmtplib (the ``smtp`` extra)."""

    needs_from_address = True

    def __init__(
        self,
        host: str,
        port: int = 587,
        *,
        username: str | None = None,
        password: str | SecretStr | None = None,
        from_address: str | None = None,
        start_tls: bool = True,
        use_tls: bool = False,
        timeout: float = 10,
    ) -> None:
        check_headers(from_address)
        self.host = host
        self.port = port
        self.username = username
        self._password = SecretStr(password) if isinstance(password, str) else password
        self.from_address = from_address
        self.start_tls = start_tls and not use_tls
        self.use_tls = use_tls
        self.timeout = timeout

    def __repr__(self) -> str:
        return f"SmtpSender(host={self.host!r}, port={self.port})"

    def mime(self, message: EmailMessage) -> MimeMessage:
        """Build the MIME message."""
        sender = _from(self.from_address, message)
        check_headers(message.to, message.subject, sender)
        mime = MimeMessage()
        mime["From"] = sender
        mime["To"] = message.to
        mime["Subject"] = message.subject
        mime.set_content(message.text)
        if message.html is not None:
            mime.add_alternative(message.html, subtype="html")
        return mime

    async def send(self, message: EmailMessage) -> None:
        """Deliver over SMTP; certificates are always checked."""
        mime = self.mime(message)
        aiosmtplib: Any = importlib.import_module("aiosmtplib")  # Any: optional extra
        try:
            await aiosmtplib.send(
                mime,
                hostname=self.host,
                port=self.port,
                username=self.username,
                password=self._password.get_secret_value() if self._password else None,
                start_tls=self.start_tls,
                use_tls=self.use_tls,
                timeout=self.timeout,
                validate_certs=True,
            )
        except Exception as exc:
            msg = f"SMTP delivery failed ({type(exc).__name__})"
            raise EmailSendError(msg) from None


def smtp_sender(
    host: str,
    port: int = 587,
    *,
    username: str | None = None,
    password: str | SecretStr | None = None,
    from_address: str | None = None,
    start_tls: bool = True,
    use_tls: bool = False,
    timeout: float = 10,
) -> SmtpSender:
    """Return an SMTP sender (needs the ``smtp`` extra)."""
    return SmtpSender(
        host,
        port,
        username=username,
        password=password,
        from_address=from_address,
        start_tls=start_tls,
        use_tls=use_tls,
        timeout=timeout,
    )


class ResendSender:
    """Sends through the Resend HTTP API."""

    needs_from_address = True

    def __init__(
        self,
        api_key: str | SecretStr,
        *,
        from_address: str | None = None,
        http: httpx.AsyncClient | None = None,
    ) -> None:
        check_headers(from_address)
        self._api_key = SecretStr(api_key) if isinstance(api_key, str) else api_key
        self.from_address = from_address
        self._http = http

    def __repr__(self) -> str:
        return "ResendSender()"

    async def send(self, message: EmailMessage) -> None:
        """POST the message to Resend."""
        sender = _from(self.from_address, message)
        check_headers(message.to, message.subject, sender)
        body: dict[str, Any] = {  # Any: JSON
            "from": sender,
            "to": [message.to],
            "subject": message.subject,
            "text": message.text,
        }
        if message.html is not None:
            body["html"] = message.html
        headers = {
            "authorization": f"Bearer {self._api_key.get_secret_value()}",
            # Resend drops a repeated request with the same key.
            "idempotency-key": str(uuid.uuid4()),
        }
        try:
            if self._http is not None:
                response = await self._http.post(RESEND_URL, json=body, headers=headers)
            else:
                async with httpx.AsyncClient(timeout=10) as http:
                    response = await http.post(RESEND_URL, json=body, headers=headers)
        except httpx.HTTPError as exc:
            msg = f"Resend request failed ({type(exc).__name__})"
            raise EmailSendError(msg) from None
        if response.status_code >= 300:
            msg = f"Resend returned HTTP {response.status_code}"
            raise EmailSendError(msg)


def resend_sender(
    api_key: str | SecretStr,
    *,
    from_address: str | None = None,
    http: httpx.AsyncClient | None = None,
) -> ResendSender:
    """Return a Resend sender."""
    return ResendSender(api_key, from_address=from_address, http=http)
