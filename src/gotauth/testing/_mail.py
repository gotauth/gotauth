"""In-memory mailer and a pass-through email service."""

from __future__ import annotations

from typing import Any

from gotauth.contracts.email import EmailKind, EmailMessage, EmailSender

__all__ = ["CapturingMailer", "PassThroughEmailService", "fake_mailer"]


class CapturingMailer:
    """An email sender that keeps every message. Implements ``FakeMailer``."""

    def __init__(self) -> None:
        self._sent: list[EmailMessage] = []

    @property
    def sent(self) -> list[EmailMessage]:
        """Every message sent so far, oldest first."""
        return self._sent

    async def send(self, message: EmailMessage) -> None:
        """Record the message."""
        self._sent.append(message)

    def last(
        self, kind: EmailKind | None = None, to: str | None = None
    ) -> EmailMessage:
        """Return the newest message matching ``kind`` and ``to`` (both optional).

        Raises:
            LookupError: No message matches.
        """
        for message in reversed(self._sent):
            if kind is not None and message.kind != kind:
                continue
            if to is not None and message.to.lower() != to.lower():
                continue
            return message
        msg = (
            f"no email sent (kind={kind!r}, to={to!r}); {len(self._sent)} sent in total"
        )
        raise LookupError(msg)

    def clear(self) -> None:
        """Forget every recorded message."""
        self._sent.clear()

    def __repr__(self) -> str:
        return f"CapturingMailer(sent={len(self._sent)})"


def fake_mailer() -> CapturingMailer:
    """Return a sender that records messages in ``.sent``.

    ``.last(kind, to)`` finds one.

    Example:
        >>> mailer = fake_mailer()
        >>> mailer.sent
        []
    """
    return CapturingMailer()


class PassThroughEmailService:
    """An ``EmailService`` for unit tests.

    No templates; ``data`` is passed through unchanged.

    Delivery is immediate, so ``drain()`` has nothing to wait for. Relative URLs in
    ``data`` stay relative (the real service, D1, joins them to the mount).

    Args:
        sender: Where messages go, usually a :func:`fake_mailer`.
        app_name: Used in the subject.
        from_address: Set on every message.
    """

    def __init__(
        self,
        sender: EmailSender,
        *,
        app_name: str = "GotAuth",
        from_address: str | None = None,
    ) -> None:
        self._sender = sender
        self._app_name = app_name
        self._from_address = from_address

    async def send(self, kind: EmailKind, to: str, **data: Any) -> None:
        """Build a plain message from ``data`` and hand it to the sender."""
        lines = [f"{key}: {value}" for key, value in data.items()]
        message = EmailMessage(
            kind=kind,
            to=to,
            subject=f"{self._app_name}: {kind}",
            text="\n".join(lines),
            from_address=self._from_address,
            data=dict(data),
        )
        await self._sender.send(message)

    async def drain(self) -> None:
        """Nothing to wait for: delivery is immediate."""
