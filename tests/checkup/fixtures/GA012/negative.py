# type: ignore
# ruff: noqa
"""GA012 negative: HttpOnly and Secure cookies, a readable CSRF cookie, settings."""


def start_session(response, session_id: str) -> None:
    response.set_cookie(
        "session", session_id, httponly=True, secure=True, samesite="lax"
    )


def django_session(response, session_id: str) -> None:
    # Positional (key, value, max_age, expires, path, domain, secure, httponly)
    response.set_cookie("sessionid", session_id, 3600, None, "/", None, True, True)


def set_csrf_cookie(response, csrf_token: str) -> None:
    response.set_cookie("csrftoken", csrf_token, secure=True, samesite="strict")


def from_settings(response, value: str, options: dict) -> None:
    response.set_cookie("session", value, **options)
