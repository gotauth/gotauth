"""Email service, templates and senders."""

from __future__ import annotations

import asyncio
import email
import json
import logging
import socket
from collections.abc import Iterator
from email.message import Message
from typing import Any

import httpx
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from gotauth.contracts import EmailConfig, EmailMessage, EmailTemplate
from gotauth.contracts.email import EMAIL_KINDS, EmailKind
from gotauth.contracts.errors import ConfigError
from gotauth.email import (
    ConsoleSender,
    EmailSendError,
    TemplatedEmailService,
    console_sender,
    email_service,
    resend_sender,
    smtp_sender,
)
from gotauth.testing import fake_mailer, make_context

LINE_BREAKS = chr(13) + chr(10)  # header values never contain them

DATA: dict[EmailKind, dict[str, Any]] = {
    "verify_email": {"url": "/verify-email?token=gav_x"},
    "reset_password": {"url": "https://app.example.com/reset?token=gav_x"},
    "change_email": {
        "url": "/verify-email?token=gav_y",
        "new_email": "new@example.com",
    },
    "magic_link": {"url": "/magic-link/verify?token=gav_z"},
    "otp": {"code": "123456", "purpose": "sign_in"},
    "invitation": {
        "url": "https://app.example.com/invite?id=1",
        "organization_name": "Acme",
        "inviter_name": "Ada",
    },
    "sign_up_existing_account": {"url": "https://app.example.com/sign-in"},
    "security_notice": {
        "event": "password.reset",
        "at": "2026-10-07T10:00:00+00:00",
        "ip_address": "203.0.113.9",
    },
}


def service(**kwargs: Any) -> tuple[TemplatedEmailService, Any]:
    mailer = fake_mailer()
    kwargs.setdefault("base_url", "http://localhost:8000")
    return TemplatedEmailService(mailer, **kwargs), mailer


def config(base_url: str, **email: Any) -> Any:  # Any: ResolvedConfig
    base = make_context().auth.config
    return base.model_copy(update={"base_url": base_url, "email": EmailConfig(**email)})


# ---------------------------------------------------------------- templates


@pytest.mark.parametrize("kind", EMAIL_KINDS)
async def test_every_kind_renders_text_and_html(kind: EmailKind) -> None:
    svc, mailer = service(
        email_config=EmailConfig(app_name="Acme App", from_address="no-reply@acme.test")
    )
    await svc.send(kind, "ada@example.com", **DATA[kind])
    message: EmailMessage = mailer.last(kind)
    assert "Acme App" in message.subject
    assert message.text.strip()
    assert message.html is not None and "<div" in message.html
    assert message.data == DATA[kind]
    assert message.from_address == "no-reply@acme.test"
    for blocked in ("<img", "<link", "<style", "<script", "@import", "url("):
        assert blocked not in message.html  # no remote content or tracking


async def test_relative_urls_are_joined_to_the_mount() -> None:
    svc, mailer = service(base_path="/api/auth")
    await svc.send("verify_email", "ada@example.com", url="/verify-email?token=gav_x")
    message = mailer.last()
    assert "http://localhost:8000/api/auth/verify-email?token=gav_x" in message.text
    assert message.data["url"] == "/verify-email?token=gav_x"


@pytest.mark.parametrize(
    "url", ["javascript:alert(1)", "//evil.test/x", "data:text/html,x"]
)
async def test_non_http_urls_are_rejected(url: str) -> None:
    svc, _ = service()
    with pytest.raises(ValueError, match="http"):
        await svc.send("magic_link", "ada@example.com", url=url)


async def test_security_notice_reads_well() -> None:
    svc, mailer = service()
    await svc.send("security_notice", "ada@example.com", **DATA["security_notice"])
    text = mailer.last().text
    assert "your password was reset" in text
    assert "203.0.113.9" in text


@settings(max_examples=60, deadline=None)
@given(
    value=st.text(
        min_size=1, max_size=40, alphabet=st.characters(exclude_characters=LINE_BREAKS)
    )
)
async def test_values_are_escaped_in_html(value: str) -> None:
    svc, mailer = service()
    hostile = f"<script>{value}</script>"
    await svc.send(
        "invitation",
        "ada@example.com",
        url="https://app.example.com/invite",
        organization_name=hostile,
        inviter_name="Ada",
    )
    message = mailer.last()
    assert message.html is not None
    assert "<script>" not in message.html
    assert message.data["organization_name"] == hostile


async def test_template_override_and_render_callable() -> None:
    template = EmailTemplate(
        subject="Hi from $app_name", text="Go: $url", html="<b>$url</b>"
    )
    svc, mailer = service(
        email_config=EmailConfig(app_name="Acme", templates={"magic_link": template})
    )
    await svc.send(
        "magic_link", "ada@example.com", url="https://app.example.com/m?t=<x>"
    )
    message = mailer.last()
    assert message.subject == "Hi from Acme"
    assert message.text == "Go: https://app.example.com/m?t=<x>"
    assert message.html == "<b>https://app.example.com/m?t=&lt;x&gt;</b>"

    def render(kind: EmailKind, to: str, data: Any) -> EmailMessage:
        return EmailMessage(kind=kind, to=to, subject="custom", text="body", data=data)

    svc, mailer = service(
        email_config=EmailConfig(render=render, from_address="a@acme.test")
    )
    await svc.send("otp", "ada@example.com", code="1", purpose="sign_in")
    message = mailer.last()
    assert (message.subject, message.from_address) == ("custom", "a@acme.test")


@pytest.mark.parametrize("field", ["to", "organization_name"])
async def test_header_injection_is_rejected(field: str) -> None:
    svc, _ = service()
    data = dict(DATA["invitation"])
    to = "ada@example.com"
    if field == "to":
        to = "ada@example.com\r\nBcc: eve@example.com"
    else:
        data["organization_name"] = "Acme\nBcc: eve@example.com"
    with pytest.raises(ValueError, match="line breaks"):
        await svc.send("invitation", to, **data)


# ---------------------------------------------------------------- email_service


def test_email_service_on_localhost_uses_the_console() -> None:
    svc = email_service(config("http://localhost:8000"), None)
    assert isinstance(svc._sender, ConsoleSender)  # pyright: ignore[reportPrivateUsage]


async def test_email_service_off_localhost_without_sender_fails_on_send() -> None:
    svc = email_service(config("https://app.example.com"), None)
    with pytest.raises(ConfigError):
        await svc.send("otp", "ada@example.com", code="1", purpose="sign_in")


def test_console_sender_off_localhost() -> None:
    with pytest.raises(ConfigError):
        console_sender(base_url="https://app.example.com")
    with pytest.raises(ConfigError):
        email_service(config("https://app.example.com"), ConsoleSender())


def test_from_address_is_required_for_gotauth_senders() -> None:
    with pytest.raises(ConfigError, match="from_address"):
        email_service(config("https://app.example.com"), resend_sender("re_key"))
    email_service(
        config("https://app.example.com", from_address="a@acme.test"),
        resend_sender("re_key"),
    )
    email_service(
        config("https://app.example.com"),
        resend_sender("re_key", from_address="a@acme.test"),
    )
    email_service(
        config("https://app.example.com"), fake_mailer()
    )  # other senders: no rule


async def test_console_sender_logs(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.INFO, logger="gotauth.email")
    svc = email_service(config("http://localhost:8000"), None)
    await svc.send("otp", "ada@example.com", code="424242", purpose="sign_in")
    assert "424242" in caplog.text


# ---------------------------------------------------------------- background


class SlowSender:
    def __init__(self, fail: bool = False) -> None:
        self.sent: list[EmailMessage] = []
        self.release = asyncio.Event()
        self.fail = fail

    async def send(self, message: EmailMessage) -> None:
        await self.release.wait()
        if self.fail:
            raise RuntimeError("smtp down: token gav_secret")
        self.sent.append(message)


async def test_background_send_returns_before_delivery() -> None:
    sender = SlowSender()
    svc = TemplatedEmailService(
        sender, base_url="https://app.example.com", background=True
    )
    await svc.send("otp", "ada@example.com", code="1", purpose="sign_in")
    assert sender.sent == []
    sender.release.set()
    await svc.drain()
    assert len(sender.sent) == 1


async def test_background_failures_are_logged_not_raised(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sender = SlowSender(fail=True)
    svc = TemplatedEmailService(
        sender, base_url="https://app.example.com", background=True
    )
    await svc.send(
        "magic_link",
        "ada@example.com",
        url="https://app.example.com/m?token=gav_secret",
    )
    sender.release.set()
    await svc.drain()
    assert "magic_link email failed (RuntimeError)" in caplog.text
    assert "gav_secret" not in caplog.text


async def test_background_template_errors_still_raise() -> None:
    svc = TemplatedEmailService(
        SlowSender(), base_url="https://app.example.com", background=True
    )
    with pytest.raises(ValueError):
        await svc.send("magic_link", "ada@example.com", url="javascript:x")


# ---------------------------------------------------------------- SMTP


@pytest.fixture
def smtp_server() -> Iterator[tuple[int, list[Message]]]:
    from aiosmtpd.controller import Controller

    received: list[Message] = []

    class Handler:
        async def handle_DATA(self, server: Any, session: Any, envelope: Any) -> str:
            received.append(email.message_from_bytes(envelope.content))
            return "250 OK"

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    controller = Controller(Handler(), hostname="127.0.0.1", port=port)
    controller.start()
    try:
        yield port, received
    finally:
        controller.stop()


async def test_smtp_delivers_both_parts(smtp_server: tuple[int, list[Message]]) -> None:
    port, received = smtp_server
    sender = smtp_sender("127.0.0.1", port, start_tls=False)
    svc = TemplatedEmailService(
        sender,
        base_url="http://localhost:8000",
        email_config=EmailConfig(from_address="GotAuth <no-reply@acme.test>"),
    )
    await svc.send("verify_email", "ada@example.com", url="/verify-email?token=gav_x")
    [message] = received
    assert message["To"] == "ada@example.com"
    assert message["From"] == "GotAuth <no-reply@acme.test>"
    assert message.is_multipart()
    types = [part.get_content_type() for part in message.walk()]
    assert "text/plain" in types and "text/html" in types


async def test_smtp_own_from_address_wins(
    smtp_server: tuple[int, list[Message]],
) -> None:
    port, received = smtp_server
    sender = smtp_sender(
        "127.0.0.1", port, start_tls=False, from_address="own@acme.test"
    )
    svc = TemplatedEmailService(
        sender,
        base_url="http://localhost:8000",
        email_config=EmailConfig(from_address="cfg@acme.test"),
    )
    await svc.send("otp", "ada@example.com", code="1", purpose="sign_in")
    assert received[0]["From"] == "own@acme.test"


async def test_smtp_rejects_injection_and_reports_failures() -> None:
    sender = smtp_sender("127.0.0.1", 1, start_tls=False, from_address="a@acme.test")
    with pytest.raises(ValueError, match="line breaks"):
        sender.mime(
            EmailMessage(
                kind="otp", to="a@b.test\nBcc: x@y.test", subject="s", text="t"
            )
        )
    with pytest.raises(ValueError):
        smtp_sender("h", from_address="a@acme.test\r\nX: y")
    with pytest.raises(EmailSendError, match="SMTP delivery failed"):
        await sender.send(
            EmailMessage(kind="otp", to="a@b.test", subject="s", text="t")
        )


def test_smtp_password_is_not_in_repr() -> None:
    sender = smtp_sender("smtp.test", username="u", password="hunter2-secret")
    assert "hunter2" not in repr(sender) and "hunter2" not in repr(vars(sender))


# ---------------------------------------------------------------- Resend


async def test_resend_request_shape() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"id": "email_1"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        sender = resend_sender("re_secret_key", http=http)
        await sender.send(
            EmailMessage(
                kind="otp",
                to="ada@example.com",
                subject="Code",
                text="1",
                html="<b>1</b>",
                from_address="a@acme.test",
            )
        )
    [request] = seen
    assert str(request.url) == "https://api.resend.com/emails"
    assert request.headers["authorization"] == "Bearer re_secret_key"
    assert request.headers["idempotency-key"]
    assert json.loads(request.content) == {
        "from": "a@acme.test",
        "to": ["ada@example.com"],
        "subject": "Code",
        "text": "1",
        "html": "<b>1</b>",
    }


@pytest.mark.parametrize("status", [401, 422, 500])
async def test_resend_errors_hide_the_key_and_body(
    status: int, caplog: pytest.LogCaptureFixture
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"message": "bad key re_secret_key"})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        sender = resend_sender("re_secret_key", http=http, from_address="a@acme.test")
        with pytest.raises(EmailSendError) as error:
            await sender.send(
                EmailMessage(kind="otp", to="a@b.test", subject="s", text="body-secret")
            )
    assert str(status) in str(error.value)
    for text in (str(error.value), repr(error.value), caplog.text, repr(sender)):
        assert "re_secret_key" not in text and "body-secret" not in text


async def test_resend_network_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("boom", request=request)

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        sender = resend_sender("re_k", http=http, from_address="a@acme.test")
        with pytest.raises(EmailSendError, match="ConnectError"):
            await sender.send(
                EmailMessage(kind="otp", to="a@b.test", subject="s", text="t")
            )
