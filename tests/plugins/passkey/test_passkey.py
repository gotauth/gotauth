"""Passkeys (work package P3): registration and usernameless sign-in through the
WebAuthn ceremonies, challenge binding, verification failures, sign counts and
management."""

from __future__ import annotations

import base64
import json
import uuid
from dataclasses import dataclass
from typing import Any

import httpx
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from gotauth.contracts import Where
from gotauth.plugins.passkey import passkey
from gotauth.plugins.passkey.testing import SoftAuthenticator
from gotauth.plugins.two_factor import two_factor
from gotauth.testing import fake_clock, make_auth, make_client

ORIGIN = "http://localhost:8000"
PASSWORD = "correct horse battery"


@dataclass
class World:
    auth: Any  # Any: GotAuth
    http: httpx.AsyncClient
    clock: Any  # Any: ManualClock
    device: SoftAuthenticator
    user_id: str

    async def register(
        self, http: httpx.AsyncClient | None = None, name: str | None = "Laptop"
    ) -> httpx.Response:
        client = http or self.http
        options = (await client.post("/passkey/register/options")).json()
        return await client.post(
            "/passkey/register/verify",
            json={"response": self.device.create(options), "name": name},
        )

    async def options(
        self, http: httpx.AsyncClient | None = None
    ) -> dict[str, Any]:  # Any: JSON
        response = await (http or self.http).post("/passkey/sign-in/options")
        assert response.status_code == 200, response.text
        return response.json()

    async def sign_in(
        self, credential: dict[str, Any], http: httpx.AsyncClient | None = None
    ) -> httpx.Response:  # Any: JSON
        return await (http or self.http).post(
            "/passkey/sign-in/verify", json={"response": credential}
        )


async def world(**options: Any) -> World:
    clock = fake_clock()
    plugins = options.pop("plugins", None) or [passkey()]
    auth: Any = make_auth(
        clock=clock,
        email_password={"require_email_verification": False},
        plugins=plugins,
        **options,
    )
    http = make_client(auth)
    signed_up = await http.post(
        "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
    )
    assert signed_up.status_code == 200, signed_up.text
    user = await auth.database.find_one("user", [Where("email", "ada@example.com")])
    return World(
        auth=auth,
        http=http,
        clock=clock,
        device=SoftAuthenticator(origin=ORIGIN),
        user_id=user["id"],
    )


def _edit(
    credential: dict[str, Any], part: str, change: Any
) -> dict[str, Any]:  # Any: JSON
    """A copy of ``credential`` with ``response[part]`` changed by ``change(bytes)``."""
    copy = json.loads(json.dumps(credential))
    raw = base64.urlsafe_b64decode(copy["response"][part] + "==")
    changed = change(raw)
    copy["response"][part] = base64.urlsafe_b64encode(changed).rstrip(b"=").decode()
    return copy


def _client_data(
    credential: dict[str, Any], **fields: Any
) -> dict[str, Any]:  # Any: JSON
    def change(raw: bytes) -> bytes:
        data = json.loads(raw)
        data.update(fields)
        return json.dumps(data).encode()

    return _edit(credential, "clientDataJSON", change)


# ---------------------------------------------------------------- flows


async def test_register_then_sign_in_without_a_username() -> None:
    w = await world()
    registered = await w.register()
    assert registered.status_code == 200, registered.text
    body = registered.json()
    assert body["name"] == "Laptop" and "public_key" not in body
    async with make_client(w.auth) as browser:
        options = await w.options(browser)
        assert options["allowCredentials"] == []
        signed_in = await w.sign_in(w.device.get(options), browser)
        assert signed_in.status_code == 200, signed_in.text
        assert signed_in.json()["user"]["id"] == w.user_id
        session = await browser.get("/session")
        assert session.json()["user"]["id"] == w.user_id
    listed = (await w.http.get("/passkeys")).json()["passkeys"]
    assert len(listed) == 1 and "public_key" not in listed[0]
    assert listed[0]["last_used_at"] is not None


async def test_registering_the_same_credential_twice_is_refused() -> None:
    w = await world()
    options = (await w.http.post("/passkey/register/options")).json()
    assert options["authenticatorSelection"]["residentKey"] == "required"
    assert options["attestation"] == "none"
    created = w.device.create(options)
    assert (
        await w.http.post("/passkey/register/verify", json={"response": created})
    ).status_code == 200
    again_options = (await w.http.post("/passkey/register/options")).json()
    assert len(again_options["excludeCredentials"]) == 1
    again = _client_data(created, challenge=again_options["challenge"])
    response = await w.http.post("/passkey/register/verify", json={"response": again})
    assert response.status_code == 409
    assert response.json()["error"]["code"] == "PASSKEY_ALREADY_REGISTERED"


# ---------------------------------------------------------------- challenges


async def test_the_challenge_is_single_use_and_bound_to_the_browser() -> None:
    w = await world()
    await w.register()
    options = await w.options()
    credential = w.device.get(options)
    assert (await w.sign_in(credential)).status_code == 200
    replay = await w.sign_in(credential)
    assert replay.json()["error"]["code"] == "PASSKEY_CHALLENGE_INVALID"
    # Missing cookie: another browser.
    late_options = await w.options()
    late = w.device.get(late_options)
    async with make_client(w.auth) as other:
        missing = await w.sign_in(late, other)
        assert missing.json()["error"]["code"] == "PASSKEY_CHALLENGE_INVALID"
        # Foreign cookie: that browser's own challenge, not the signed one.
        await w.options(other)
        foreign = await w.sign_in(late, other)
        assert foreign.json()["error"]["code"] == "PASSKEY_CHALLENGE_INVALID"
    # Expired.
    expiring = w.device.get(await w.options())
    w.clock.advance("6m")
    expired = await w.sign_in(expiring)
    assert expired.json()["error"]["code"] == "PASSKEY_CHALLENGE_INVALID"


# ---------------------------------------------------------------- verification


async def test_responses_that_do_not_verify() -> None:
    w = await world()
    await w.register()
    bob = SoftAuthenticator(origin=ORIGIN)
    cases = {
        "origin": lambda c: _client_data(c, origin="https://evil.example"),
        "type": lambda c: _client_data(c, type="webauthn.create"),
        "rp id": lambda c: _edit(c, "authenticatorData", lambda b: bytes(32) + b[32:]),
        "signature": lambda c: _edit(
            c, "signature", lambda b: b[:-1] + bytes([b[-1] ^ 1])
        ),
        "user handle": lambda c: _edit(c, "userHandle", lambda b: b"usr_someone_else"),
    }
    for name, tamper in cases.items():
        credential = tamper(w.device.get(await w.options()))
        response = await w.sign_in(credential)
        assert response.status_code == 401, (name, response.text)
        assert response.json()["error"]["code"] == "PASSKEY_VERIFICATION_FAILED", name
    # An unknown credential looks the same as a bad signature.
    bob.create((await w.http.post("/passkey/register/options")).json())
    unknown = await w.sign_in(bob.get(await w.options()))
    assert unknown.json()["error"]["code"] == "PASSKEY_VERIFICATION_FAILED"


async def test_a_sign_count_must_go_up_unless_both_are_zero() -> None:
    w = await world()
    await w.register()
    assert (await w.sign_in(w.device.get(await w.options()))).status_code == 200
    credential = next(iter(w.device.credentials.values()))
    credential.sign_count = 0  # a cloned authenticator: the next count is 1 again
    cloned = await w.sign_in(w.device.get(await w.options()))
    assert cloned.json()["error"]["code"] == "PASSKEY_VERIFICATION_FAILED"
    synced = await world()
    synced.device.counting = False
    await synced.register()
    for _ in range(2):
        ok = await synced.sign_in(synced.device.get(await synced.options()))
        assert ok.status_code == 200, ok.text


@settings(
    max_examples=20,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    part=st.sampled_from(["authenticatorData", "clientDataJSON", "signature"]),
    position=st.integers(min_value=0, max_value=10_000),
    bit=st.integers(min_value=0, max_value=7),
)
async def test_any_flipped_byte_fails(part: str, position: int, bit: int) -> None:
    w = await world()
    await w.register()
    credential = w.device.get(await w.options())

    def flip(raw: bytes) -> bytes:
        index = position % len(raw)
        return raw[:index] + bytes([raw[index] ^ (1 << bit)]) + raw[index + 1 :]

    response = await w.sign_in(_edit(credential, part, flip))
    assert response.status_code in (400, 401), response.text


# ---------------------------------------------------------------- with P2


async def test_a_passkey_sign_in_skips_the_two_factor_step() -> None:
    required = {"on": False}
    w = await world(
        plugins=[passkey(), two_factor(enforce=lambda user: required["on"])]
    )
    await w.register()
    required["on"] = True
    password = await w.http.post(
        "/sign-in/email", json={"email": "ada@example.com", "password": PASSWORD}
    )
    assert "challenge" in password.json()
    async with make_client(w.auth) as browser:
        signed_in = await w.sign_in(w.device.get(await w.options(browser)), browser)
        assert "session" in signed_in.json()


# ---------------------------------------------------------------- management


async def test_rename_and_delete_with_their_rules() -> None:
    w = await world()
    passkey_id = (await w.register()).json()["id"]
    renamed = await w.http.patch(f"/passkeys/{passkey_id}", json={"name": "Phone"})
    assert renamed.json()["name"] == "Phone"
    async with make_client(w.auth) as bob:
        await bob.post(
            "/sign-up/email", json={"email": "bob@example.com", "password": PASSWORD}
        )
        assert (await bob.delete(f"/passkeys/{passkey_id}")).status_code == 404
        assert (
            await bob.patch(f"/passkeys/{passkey_id}", json={"name": "x"})
        ).status_code == 404
    # A passkey-only account keeps its last passkey.
    await w.auth.database.delete("account", [Where("user_id", w.user_id)])
    last = await w.http.delete(f"/passkeys/{passkey_id}")
    assert last.json()["error"]["code"] == "LAST_SIGN_IN_METHOD"
    w.device = SoftAuthenticator(origin=ORIGIN)  # a second device
    await w.register(name="Second")
    assert (await w.http.delete(f"/passkeys/{passkey_id}")).status_code == 200


async def test_an_imported_user_with_a_uuid_id() -> None:
    clock = fake_clock()
    auth: Any = make_auth(
        clock=clock,
        email_password={"require_email_verification": False},
        plugins=[passkey()],
    )
    user_id = str(uuid.uuid4())
    await auth.database.create(
        "user",
        {
            "id": user_id,
            "email": "imported@example.com",
            "email_verified": True,
            "created_at": clock.now(),
            "updated_at": clock.now(),
        },
    )
    await auth.database.create(
        "account",
        {
            "id": "acc_imported",
            "user_id": user_id,
            "provider_id": "credential",
            "account_id": user_id,
            "password_hash": await auth.crypto.hash_password(PASSWORD),
            "created_at": clock.now(),
            "updated_at": clock.now(),
        },
    )
    http = make_client(auth)
    signed_in = await http.post(
        "/sign-in/email", json={"email": "imported@example.com", "password": PASSWORD}
    )
    assert signed_in.status_code == 200, signed_in.text
    device = SoftAuthenticator(origin=ORIGIN)
    options = (await http.post("/passkey/register/options")).json()
    assert (
        await http.post(
            "/passkey/register/verify", json={"response": device.create(options)}
        )
    ).status_code == 200
    async with make_client(auth) as browser:
        options = (await browser.post("/passkey/sign-in/options")).json()
        done = await browser.post(
            "/passkey/sign-in/verify", json={"response": device.get(options)}
        )
        assert done.json()["user"]["id"] == user_id


async def test_rp_id_must_cover_every_origin() -> None:
    import pytest

    from gotauth.contracts import ConfigError

    auth: Any = make_auth(
        base_url="https://app.example.com",
        trusted_origins=["https://admin.example.com", "https://*.preview.example"],
        plugins=[passkey(rp_id="other.example")],
    )
    with pytest.raises(ConfigError, match="rp_id"):
        await auth.get_principal({}, {})
    fine: Any = make_auth(
        base_url="https://app.example.com",
        trusted_origins=["https://admin.example.com", "https://*.preview.example"],
        plugins=[passkey(rp_id="example.com")],
    )
    await fine.get_principal({}, {})  # wildcard origins are ignored


# ---------------------------------------------------------------- review fixes


async def test_without_user_verification_a_passkey_is_not_a_sign_in() -> None:
    # Possession alone must not pass as a passkey sign-in, which two-factor skips.
    w = await world()
    w.device.user_verified = False
    await w.register()
    refused = await w.sign_in(w.device.get(await w.options()))
    assert refused.json()["error"]["code"] == "PASSKEY_VERIFICATION_FAILED"
    lax = await world(plugins=[passkey(user_verification="discouraged")])
    lax.device.user_verified = False
    await lax.register()
    assert (await lax.sign_in(lax.device.get(await lax.options()))).status_code == 200


async def test_origins_are_compared_as_browsers_report_them() -> None:
    clock = fake_clock()
    auth: Any = make_auth(
        clock=clock,
        base_url="https://Auth.Example.com:443",
        email_password={"require_email_verification": False},
        plugins=[passkey()],
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=auth.asgi()),
        base_url="https://auth.example.com/api/auth",
        headers={"origin": "https://auth.example.com"},
    ) as http:
        await http.post(
            "/sign-up/email", json={"email": "ada@example.com", "password": PASSWORD}
        )
        device = SoftAuthenticator(origin="https://auth.example.com")
        options = (await http.post("/passkey/register/options")).json()
        registered = await http.post(
            "/passkey/register/verify", json={"response": device.create(options)}
        )
        assert registered.status_code == 200, registered.text


async def test_a_password_that_was_never_set_is_not_a_sign_in_method() -> None:
    w = await world()
    passkey_id = (await w.register()).json()["id"]
    await w.auth.database.update(
        "account", [Where("user_id", w.user_id)], {"password_hash": None}
    )
    last = await w.http.delete(f"/passkeys/{passkey_id}")
    assert last.json()["error"]["code"] == "LAST_SIGN_IN_METHOD"


async def test_both_ceremonies_can_be_pending_in_one_browser() -> None:
    w = await world()
    register_options = (await w.http.post("/passkey/register/options")).json()
    await w.options()  # e.g. conditional UI in another tab
    registered = await w.http.post(
        "/passkey/register/verify",
        json={"response": w.device.create(register_options)},
    )
    assert registered.status_code == 200, registered.text


async def test_challenges_do_not_pile_up() -> None:
    w = await world()
    for _ in range(3):
        await w.http.post("/passkey/register/options")
    rows = await w.auth.database.find_many("verification", [])
    assert (
        len([r for r in rows if r["identifier"].startswith("passkey:register:")]) == 1
    )
    await w.options()
    w.clock.advance("6m")
    await w.options()
    rows = await w.auth.database.find_many("verification", [])
    assert len([r for r in rows if r["identifier"] == "passkey:sign_in"]) == 1
