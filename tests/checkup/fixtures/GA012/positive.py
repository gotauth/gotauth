# type: ignore
# ruff: noqa
"""GA012 positive: session cookies without HttpOnly or Secure."""


def start_session(response, session_id: str) -> None:
    response.set_cookie("session", session_id)


def remember_me(response, token: str) -> None:
    response.set_cookie(key="remember_me", value=token, httponly=True)


def flask_session(resp, session_id: str) -> None:
    resp.set_cookie("sid", session_id, secure=True, httponly=False)
