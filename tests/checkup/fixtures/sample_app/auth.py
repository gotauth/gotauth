# type: ignore
# ruff: noqa
"""A small FastAPI app in the style of older tutorials, used for the JSON snapshot.

The secret below is a random string made up for this fixture.
"""

from datetime import datetime, timedelta, timezone

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext

SECRET_KEY = "Hq3vZ8kT1mR6pW0xL5cN9bF2jD7sG4aY"
ALGORITHM = "HS256"

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
app = FastAPI()


def create_access_token(data: dict, expires_delta: timedelta) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc) + expires_delta})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def read_subject(token: str) -> str:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])["sub"]
    except JWTError as error:
        raise HTTPException(status_code=401) from error


@app.post("/token")
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    token = create_access_token({"sub": form_data.username}, timedelta(minutes=30))
    return {"access_token": token, "token_type": "bearer"}
