"""Helpers for the organization tests: a GotAuth with organizations and API keys,
signed-in users, and invitation links from the captured emails."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx

from gotauth.plugins.api_key import api_key
from gotauth.plugins.organization import access_control, organization
from gotauth.testing import fake_clock, fake_mailer, make_auth, make_client

PASSWORD = "correct horse battery"
ACCESS = access_control(
    statements={"project": ["create", "read", "update", "delete"]},
    roles={"member": {"project": ["read"]}},
)


@dataclass
class World:
    auth: Any  # Any: GotAuth
    clock: Any  # Any: ManualClock
    mailer: Any  # Any: CapturingMailer
    users: dict[str, httpx.AsyncClient] = field(
        default_factory=dict[str, httpx.AsyncClient]
    )
    ids: dict[str, str] = field(default_factory=dict[str, str])

    async def user(self, name: str) -> httpx.AsyncClient:
        """A signed-in browser for ``<name>@example.com``."""
        if name not in self.users:
            http = make_client(self.auth)
            response = await http.post(
                "/sign-up/email",
                json={"email": f"{name}@example.com", "password": PASSWORD},
            )
            assert response.status_code == 200, response.text
            self.users[name] = http
            self.ids[name] = str(response.json()["user"]["id"])
        return self.users[name]

    async def org(self, owner: str, slug: str = "acme") -> str:
        http = await self.user(owner)
        created = await http.post(
            "/organization/create", json={"name": slug.title(), "slug": slug}
        )
        assert created.status_code == 200, created.text
        return str(created.json()["id"])

    async def invite(
        self, inviter: str, org_id: str, invitee: str, role: str = "member"
    ) -> tuple[str, str]:
        """Invite ``<invitee>@example.com``; the (invitation id, token) of the link."""
        http = await self.user(inviter)
        response = await http.post(
            "/organization/invite-member",
            json={
                "organization_id": org_id,
                "email": f"{invitee}@example.com",
                "role": role,
            },
        )
        assert response.status_code == 200, response.text
        text = self.mailer.last("invitation", f"{invitee}@example.com").text
        url = re.search(r"https?://\S+", text)
        assert url is not None
        query = parse_qs(urlsplit(url.group(0)).query)
        return query["invitation_id"][0], query["token"][0]

    async def join(
        self, inviter: str, org_id: str, invitee: str, role: str = "member"
    ) -> None:
        invitation_id, token = await self.invite(inviter, org_id, invitee, role)
        http = await self.user(invitee)
        accepted = await http.post(
            "/organization/accept-invitation",
            json={"invitation_id": invitation_id, "token": token},
        )
        assert accepted.status_code == 200, accepted.text


def world(**options: Any) -> World:
    clock = fake_clock()
    mailer = fake_mailer()
    plugins = options.pop("plugins", None) or [
        api_key(allowed_scopes=["project:read", "project:create"]),
        organization(access=ACCESS),
    ]
    auth = make_auth(
        clock=clock,
        mailer=mailer,
        email_password={"require_email_verification": False},
        plugins=plugins,
        **options,
    )
    return World(auth=auth, clock=clock, mailer=mailer)
