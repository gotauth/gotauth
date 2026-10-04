# type: ignore
# ruff: noqa
"""GA007 negative: the same sign-in route behind slowapi."""

from fastapi import Depends, FastAPI, Request
from fastapi.security import OAuth2PasswordRequestForm
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter


@app.post("/token")
@limiter.limit("5/minute")
async def login_for_access_token(
    request: Request, form_data: OAuth2PasswordRequestForm = Depends()
):
    return {"access_token": "...", "token_type": "bearer"}
