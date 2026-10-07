"""Default email templates: subject, plain text and simple HTML (inline styles only)."""

from __future__ import annotations

import html
from collections.abc import Mapping
from dataclasses import dataclass
from string import Template
from typing import Any

from gotauth.contracts.email import EmailKind

__all__ = ["DEFAULT_TEMPLATES", "Rendered", "render_default", "render_override"]

_IGNORE = "If you did not ask for this, you can ignore this email."

# kind -> (subject, intro, button label or None, closing line)
_COPY: dict[EmailKind, tuple[str, str, str | None, str]] = {
    "verify_email": (
        "Verify your email for $app_name",
        "Confirm that this address belongs to you to finish setting up your "
        "$app_name account.",
        "Verify email",
        _IGNORE,
    ),
    "reset_password": (
        "Reset your $app_name password",
        "Someone asked to reset the password of your $app_name account.",
        "Choose a new password",
        _IGNORE + " Your password stays the same.",
    ),
    "change_email": (
        "Confirm your new email for $app_name",
        "Confirm that you want to use $new_email for your $app_name account.",
        "Confirm new email",
        _IGNORE,
    ),
    "magic_link": (
        "Your $app_name sign-in link",
        "Use this link to sign in to $app_name. It works once.",
        "Sign in",
        _IGNORE,
    ),
    "otp": (
        "Your $app_name code: $code",
        "Your one-time code for $app_name is $code.",
        None,
        _IGNORE,
    ),
    "invitation": (
        "Join $organization_name on $app_name",
        "$inviter_name invited you to join $organization_name on $app_name.",
        "Accept invitation",
        "If you were not expecting this invitation, you can ignore this email.",
    ),
    "sign_up_existing_account": (
        "You already have a $app_name account",
        "Someone tried to sign up for $app_name with this address, but it already "
        "has an account. Sign in instead, or reset your password if you forgot it.",
        "Sign in",
        "If this was not you, no action is needed. Nobody can sign in without your "
        "password.",
    ),
    "security_notice": (
        "Security notice from $app_name",
        "There was a change to your $app_name account: $event_text, at $at$from_ip.",
        None,
        "If this was not you, reset your password and review your account now.",
    ),
}

_EVENTS = {
    "password.reset": "your password was reset",
    "password.changed": "your password was changed",
    "user.email_changed": "a change of your email address was requested",
    "two_factor.disabled": "two-factor authentication was turned off",
    "passkey.removed": "a passkey was removed",
}

DEFAULT_TEMPLATES: Mapping[EmailKind, tuple[str, str, str | None, str]] = _COPY
"""The default copy per kind: subject, intro, button label and closing line."""


@dataclass(frozen=True)
class Rendered:
    """A rendered email body."""

    subject: str
    text: str
    html: str | None


def _values(
    app_name: str, link: str | None, data: Mapping[str, Any]
) -> dict[str, str]:  # Any: data
    values = {key: "" if value is None else str(value) for key, value in data.items()}
    values["app_name"] = app_name
    if link is not None:
        values["url"] = link
    event = str(data.get("event", ""))
    values["event_text"] = _EVENTS.get(event, event.replace("_", " ").replace(".", " "))
    ip = data.get("ip_address")
    values["from_ip"] = f" from IP address {ip}" if ip else ""
    for key in ("new_email", "code", "organization_name", "inviter_name", "at"):
        values.setdefault(key, "")
    return values


def _html(intro: str, button: str | None, link: str | None, closing: str) -> str:
    parts = [
        '<div style="font-family: Arial, Helvetica, sans-serif; font-size: 16px; '
        'line-height: 1.5; color: #1f2328; max-width: 560px;">',
        f'<p style="margin: 0 0 16px;">{intro}</p>',
    ]
    if button and link:
        parts.append(
            '<p style="margin: 0 0 16px;"><a href="' + link + '" style="display: '
            "inline-block; padding: 10px 18px; background: #1f2328; color: #ffffff; "
            'text-decoration: none; border-radius: 6px;">' + button + "</a></p>"
        )
        parts.append(
            '<p style="margin: 0 0 16px; font-size: 13px; color: #59636e;">'
            f"Or open this link: {link}</p>"
        )
    parts.append(
        f'<p style="margin: 0; font-size: 13px; color: #59636e;">{closing}</p>'
    )
    parts.append("</div>")
    return "\n".join(parts)


def render_default(
    kind: EmailKind, app_name: str, link: str | None, data: Mapping[str, Any]
) -> Rendered:  # Any: data
    """Render a default template. HTML gets every value escaped."""
    subject_t, intro_t, button, closing_t = _COPY[kind]
    values = _values(app_name, link, data)
    escaped = {key: html.escape(value, quote=True) for key, value in values.items()}
    subject = Template(subject_t).safe_substitute(values)
    intro = Template(intro_t).safe_substitute(values)
    closing = Template(closing_t).safe_substitute(values)
    lines = [intro, ""]
    if link is not None and button is not None:
        lines += [f"{button}: {link}", ""]
    lines.append(closing)
    body_html = _html(
        Template(intro_t).safe_substitute(escaped),
        html.escape(button) if button else None,
        escaped.get("url") if link is not None else None,
        Template(closing_t).safe_substitute(escaped),
    )
    return Rendered(subject=subject, text="\n".join(lines) + "\n", html=body_html)


def render_override(
    subject_t: str,
    text_t: str,
    html_t: str | None,
    app_name: str,
    link: str | None,
    data: Mapping[str, Any],  # Any: data
) -> Rendered:
    """Render an ``EmailTemplate`` override (``string.Template`` placeholders)."""
    values = _values(app_name, link, data)
    escaped = {key: html.escape(value, quote=True) for key, value in values.items()}
    return Rendered(
        subject=Template(subject_t).safe_substitute(values),
        text=Template(text_t).safe_substitute(values),
        html=Template(html_t).safe_substitute(escaped) if html_t is not None else None,
    )
