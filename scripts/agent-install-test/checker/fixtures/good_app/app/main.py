"""The template app with GotAuth (seeded for the checker's tests)."""

from typing import Annotated

from fastapi import Depends, FastAPI

from app.auth import auth
from gotauth import Principal, User

app = FastAPI(title="Projects API")
app.include_router(auth.fastapi.router(), prefix=auth.config.base_path)
auth.fastapi.add_exception_handlers(app)

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]
CanRead = Annotated[Principal, Depends(auth.fastapi.require("projects:read"))]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/me")
async def me(user: CurrentUser) -> dict[str, str]:
    return {"email": user.email}


@app.get("/projects")
async def projects(principal: CanRead) -> list[str]:
    return ["Website redesign", "Mobile app"]
