from typing import Annotated

from fastapi import Depends, FastAPI
from gotauth import GotAuth, User
from gotauth.storage.sqlalchemy import sqlalchemy_adapter

auth = GotAuth(
    database=sqlalchemy_adapter(engine),
    secret=settings.GOTAUTH_SECRET,
    base_url="https://api.example.com",
    email_password={"enabled": True, "require_email_verification": True},
)

app = FastAPI()
app.include_router(auth.fastapi.router(), prefix="/api/auth")

CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]

@app.get("/projects")
async def list_projects(user: CurrentUser):
    ...
