"""The templated email service (CONTRACTS 9)."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from typing import Any
from urllib.parse import urlsplit

from gotauth.contracts.config import ResolvedConfig
from gotauth.contracts.email import EmailConfig, EmailKind, EmailMessage, EmailSender
from gotauth.contracts.errors import ConfigError
from gotauth.contracts.sessions import is_localhost

from ._senders import ConsoleSender, check_headers, console_sender
from ._templates import render_default, render_override

__all__ = ["TemplatedEmailService", "email_service"]

logger = logging.getLogger("gotauth.email")


class TemplatedEmailService:
    """Renders a kind into an ``EmailMessage`` and hands it to the sender.

    With ``background=True`` the message is rendered at once (template errors still
    raise) and delivered on a task; ``drain()`` waits for pending deliveries.
    """

    def __init__(
        self,
        sender: EmailSender | None,
        *,
        base_url: str,
        base_path: str = "/api/auth",
        email_config: EmailConfig | None = None,
        background: bool = False,
    ) -> None:
        self._sender = sender
        self._base = base_url.rstrip("/") + base_path.rstrip("/")
        self._config = email_config or EmailConfig()
        self._background = background
        self._tasks: set[asyncio.Task[None]] = set()

    def _link(self, url: object) -> str | None:
        if url is None:
            return None
        link = str(url)
        if link.startswith("/") and not link.startswith("//"):
            link = self._base + link
        if urlsplit(link).scheme not in ("http", "https"):
            msg = "email links must be http or https URLs"
            raise ValueError(msg)
        return link

    def render(
        self, kind: EmailKind, to: str, data: Mapping[str, Any]
    ) -> EmailMessage:  # Any: data
        """Render without sending (``data`` is kept unchanged on the message)."""
        config = self._config
        if config.render is not None:
            message = config.render(kind, to, data)
            if message.from_address is None and config.from_address is not None:
                message = EmailMessage(
                    kind=message.kind,
                    to=message.to,
                    subject=message.subject,
                    text=message.text,
                    html=message.html,
                    from_address=config.from_address,
                    data=message.data,
                )
            check_headers(message.to, message.subject, message.from_address)
            return message
        link = self._link(data.get("url"))
        override = config.templates.get(kind)
        if override is not None:
            rendered = render_override(
                override.subject,
                override.text,
                override.html,
                config.app_name,
                link,
                data,
            )
        else:
            rendered = render_default(kind, config.app_name, link, data)
        check_headers(to, rendered.subject, config.from_address)
        return EmailMessage(
            kind=kind,
            to=to,
            subject=rendered.subject,
            text=rendered.text,
            html=rendered.html,
            from_address=config.from_address,
            data=dict(data),
        )

    async def send(self, kind: EmailKind, to: str, **data: Any) -> None:  # Any: data
        """Render and deliver (in the background when configured)."""
        sender = self._sender
        if sender is None:
            # Never log links or codes outside localhost: fail loudly instead.
            msg = "no email sender is configured (set email_sender)"
            raise ConfigError(msg)
        message = self.render(kind, to, data)
        if not self._background:
            await sender.send(message)
            return
        task = asyncio.create_task(self._deliver(sender, message))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    @staticmethod
    async def _deliver(sender: EmailSender, message: EmailMessage) -> None:
        try:
            await sender.send(message)
        except Exception as exc:
            # The kind and the error type only: messages can carry links and codes.
            logger.warning(
                "gotauth: background %s email failed (%s)",
                message.kind,
                type(exc).__name__,
            )

    async def drain(self) -> None:
        """Wait until every background delivery has finished."""
        while self._tasks:
            await asyncio.gather(*list(self._tasks), return_exceptions=True)


def email_service(
    config: ResolvedConfig, sender: EmailSender | None
) -> TemplatedEmailService:
    """Build the email service (CONTRACTS 13.2).

    No sender on localhost uses the console sender; no sender elsewhere gives a service
    whose ``send`` raises ``ConfigError``. Off localhost, delivery runs in the
    background, so response time does not reveal whether an account exists.

    Raises:
        ConfigError: The console sender off localhost, or a GotAuth sender (SMTP,
            Resend) with no from address on it or in ``EmailConfig.from_address``.
    """
    local = is_localhost(config.base_url)
    if sender is None and local:
        sender = console_sender(base_url=config.base_url)
    if isinstance(sender, ConsoleSender) and not local:
        msg = "the console email sender is for localhost only; configure email_sender"
        raise ConfigError(msg)
    if (
        sender is not None
        and getattr(sender, "needs_from_address", False)
        and not getattr(sender, "from_address", None)
        and not config.email.from_address
    ):
        msg = "set from_address on the email sender or in EmailConfig.from_address"
        raise ConfigError(msg)
    return TemplatedEmailService(
        sender,
        base_url=config.base_url,
        base_path=config.base_path,
        email_config=config.email,
        background=not local,
    )
