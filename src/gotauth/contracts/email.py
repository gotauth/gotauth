"""CONTRACTS section 9: email messages, senders and the email service."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from dataclasses import field as dc_field
from typing import Any, Literal, Protocol, TypeAlias, cast, get_args, runtime_checkable

from pydantic import BaseModel, ConfigDict
from pydantic import Field as PydanticField

__all__ = [
    "EMAIL_KINDS",
    "EmailConfig",
    "EmailKind",
    "EmailMessage",
    "EmailRenderer",
    "EmailSender",
    "EmailService",
    "EmailTemplate",
    "FakeMailer",
]

EmailKind: TypeAlias = Literal[
    "verify_email",
    "reset_password",
    "change_email",
    "magic_link",
    "otp",
    "invitation",
    "sign_up_existing_account",
    "security_notice",
]
EMAIL_KINDS: tuple[EmailKind, ...] = cast("tuple[EmailKind, ...]", get_args(EmailKind))


@dataclass(frozen=True)
class EmailMessage:
    """A rendered email.

    Text, HTML and data are left out of ``repr()`` because they carry links with
    tokens.

    Attributes:
        kind: What the email is for.
        to: Recipient address.
        subject: Subject line.
        text: Plain-text body.
        html: HTML body, if any.
        from_address: Sender address; ``EmailConfig.from_address`` unless a sender
            overrides it.
        data: The data the caller passed (url, code, org name, ...), unchanged.
    """

    kind: EmailKind
    to: str
    subject: str
    text: str = dc_field(repr=False)
    html: str | None = dc_field(default=None, repr=False)
    from_address: str | None = None
    # Any: template data values are arbitrary.
    data: Mapping[str, Any] = dc_field(default_factory=dict[str, Any], repr=False)


@runtime_checkable
class EmailSender(Protocol):
    """Delivers a rendered message (console, SMTP, Resend, ...)."""

    async def send(self, message: EmailMessage) -> None:
        """Deliver the message."""
        ...


@runtime_checkable
class EmailService(Protocol):
    """Renders an email of a kind and hands it to a sender (D1)."""

    async def send(self, kind: EmailKind, to: str, **data: Any) -> None:
        """Render and send. Off localhost delivery runs in the background."""
        ...

    async def drain(self) -> None:
        """Wait for background deliveries (tests, shutdown)."""
        ...


@dataclass(frozen=True)
class EmailTemplate:
    """A per-kind template override. Placeholders use ``string.Template``: ``$url``,
    ``$app_name``, ..."""

    subject: str
    text: str
    html: str | None = None


EmailRenderer: TypeAlias = Callable[[EmailKind, str, Mapping[str, Any]], EmailMessage]
"""``render(kind, to, data) -> EmailMessage``, replacing the default renderer."""


class EmailConfig(BaseModel):
    """Email settings (section 9)."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    app_name: str = "GotAuth"
    from_address: str | None = None
    templates: dict[EmailKind, EmailTemplate] = PydanticField(
        default_factory=dict[EmailKind, EmailTemplate]
    )
    render: EmailRenderer | None = None


class FakeMailer(EmailSender, Protocol):
    """An :class:`EmailSender` that keeps messages in memory
    (``gotauth.testing.fake_mailer``)."""

    @property
    def sent(self) -> list[EmailMessage]:
        """Every message sent so far, oldest first."""
        ...

    def last(
        self, kind: EmailKind | None = None, to: str | None = None
    ) -> EmailMessage:
        """Return the newest message matching ``kind`` and ``to``; raise ``LookupError``
        if there is none."""
        ...
