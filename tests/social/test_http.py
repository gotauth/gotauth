"""Social sign-in over HTTP on a real GotAuth (C1 pipeline, C3 sessions)."""

from __future__ import annotations

from urllib.parse import urlsplit

from gotauth.testing import make_auth, make_client

from .conftest import person, provider


async def test_round_trip_sets_a_session() -> None:
    fake = provider(users={"c1": person()})
    auth = make_auth(social_providers=[fake])
    async with make_client(auth) as client:
        started = await client.post(
            "/sign-in/social", json={"provider": "fake", "callback_url": "/home"}
        )
        assert started.status_code == 200, started.text
        query = fake.approve(started.json()["url"], "c1")
        done = await client.get("/callback/fake", params=query)
        assert done.status_code == 302
        assert done.headers["location"] == "/home"
        session = (await client.get("/session")).json()
        assert session["user"]["email"] == "ada@example.com"
        # The state cookie was cleared, so replaying the callback fails.
        again = await client.get("/callback/fake", params=query)
        assert again.status_code == 400


async def test_callback_without_state_cookie_is_rejected() -> None:
    fake = provider(users={"c1": person()})
    auth = make_auth(social_providers=[fake])
    async with make_client(auth) as client:
        started = await client.post("/sign-in/social", json={"provider": "fake"})
        query = fake.approve(started.json()["url"], "c1")
        client.cookies.clear()
        response = await client.get("/callback/fake", params=query)
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "TOKEN_INVALID"
        assert (await client.get("/session")).json() is None


async def test_form_post_round_trip() -> None:
    apple = provider("apple", users={"c1": person()}, callback_method="POST")
    auth = make_auth(social_providers=[apple])
    async with make_client(auth) as client:
        started = await client.post(
            "/sign-in/social", json={"provider": "apple", "callback_url": "/home"}
        )
        query = apple.approve(started.json()["url"], "c1")
        jar = dict(client.cookies)
        client.cookies.clear()  # the cross-site POST carries no Lax cookie
        posted = await client.post(
            "/callback/apple",
            data=query,
            headers={"origin": "https://appleid.apple.com"},
        )
        assert posted.status_code == 302, posted.text
        location = urlsplit(posted.headers["location"])
        client.cookies.update(jar)
        done = await client.get(
            location.path.removeprefix("/api/auth") + "?" + location.query
        )
        assert done.status_code == 302
        assert done.headers["location"] == "/home"
