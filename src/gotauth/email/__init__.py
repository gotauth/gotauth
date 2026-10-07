"""Email service, senders and templates (work package D1).

``GotAuth(email=EmailConfig(...), email_sender=smtp_sender(...))``. Without a sender,
localhost apps use the console sender; elsewhere sending fails loudly.
"""

from __future__ import annotations

from ._senders import (
    ConsoleSender,
    EmailSendError,
    ResendSender,
    SmtpSender,
    console_sender,
    resend_sender,
    smtp_sender,
)
from ._service import TemplatedEmailService, email_service
from ._templates import DEFAULT_TEMPLATES

__all__ = [
    "DEFAULT_TEMPLATES",
    "ConsoleSender",
    "EmailSendError",
    "ResendSender",
    "SmtpSender",
    "TemplatedEmailService",
    "console_sender",
    "email_service",
    "resend_sender",
    "smtp_sender",
]
