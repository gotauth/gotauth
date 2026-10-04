# type: ignore
# ruff: noqa
"""GA007 positive: sign-in routes and no rate limiter anywhere in the project."""

from fastapi import Depends, FastAPI
from fastapi.security import OAuth2PasswordRequestForm

app = FastAPI()


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    return {"access_token": "...", "token_type": "bearer"}


@app.post("/auth/sign-in")
async def sign_in(form_data: OAuth2PasswordRequestForm = Depends()):
    return {"ok": True}


@app.get("/users/me")
async def read_me():
    return {"name": "Ada"}


@app.post("/items")
async def create_item():
    return {"ok": True}
