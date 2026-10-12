# FastAPI reads these annotations at runtime, and they use the `auth` argument of
# create_app, so they must not become strings: no `from __future__ import annotations`.
"""The example API: GotAuth's routes plus two protected project routes."""

from typing import Annotated

from fastapi import Depends, FastAPI
from pydantic import BaseModel

from app.auth import SCOPES
from gotauth import AuthError, GotAuth, Principal, User


class Project(BaseModel):
    id: int
    name: str


class Provider(BaseModel):
    id: str
    name: str


class Config(BaseModel):
    social_providers: list[Provider]
    api_key_scopes: list[str]


# Demo data, kept in memory per user.
_projects: dict[str, list[Project]] = {}


def projects_of(user_id: str) -> list[Project]:
    if user_id not in _projects:
        names = ("Website redesign", "Mobile app", "Data pipeline")
        _projects[user_id] = [Project(id=i + 1, name=n) for i, n in enumerate(names)]
    return _projects[user_id]


def create_app(auth: GotAuth) -> FastAPI:
    app = FastAPI(title="GotAuth fastapi-nextjs example")
    app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
    auth.fastapi.add_exception_handlers(app)

    current_user = Depends(auth.fastapi.current_user)
    api_key = Depends(auth.fastapi.api_key_principal)
    can_read = Depends(auth.fastapi.require("projects:read"))

    @app.get("/api/config")
    async def config() -> Config:
        """What the frontend needs: which sign-in buttons and key scopes to offer."""
        providers = [Provider(id=p.id, name=p.name) for p in auth.providers.values()]
        return Config(social_providers=providers, api_key_scopes=list(SCOPES))

    @app.get("/api/projects")
    async def projects(user: Annotated[User, current_user]) -> list[Project]:
        """For the browser: the session cookie identifies the user."""
        return projects_of(user.id)

    @app.get("/api/v1/projects")
    async def projects_by_key(
        key: Annotated[Principal, api_key], _: Annotated[Principal, can_read]
    ) -> list[Project]:
        """For scripts: an API key with the projects:read scope."""
        if key.user_id is None:  # the demo data belongs to users, not organizations
            raise AuthError("FORBIDDEN", 403)
        return projects_of(key.user_id)

    return app


def _default_app() -> FastAPI:
    from app.auth import auth  # reads the environment

    return create_app(auth)


app = _default_app()
