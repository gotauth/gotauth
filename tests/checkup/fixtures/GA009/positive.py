# type: ignore
# ruff: noqa
"""GA009 positive: generated secrets committed to the source.

The values are random strings made up for this fixture, not real credentials.
"""

from starlette.middleware.sessions import SessionMiddleware

SECRET_KEY = "q8Zt3LxV0pN6bR1mK4yW7cD2fH5jS9gA"
API_TOKEN = "f3a9c1e7b2d84f6a9e0c5b7d1a3f8e2c"


class Settings:
    jwt_secret: str = "Xr7pL2mQ9vT4kW8nB3cF6hJ1sD5gZ0aY"


def install(app) -> None:
    app.add_middleware(SessionMiddleware, secret_key="Nw4tH8yR2kP6vC1xM9bL3qZ7fJ5dS0gE")
