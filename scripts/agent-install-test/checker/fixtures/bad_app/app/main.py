"""Hand-rolled auth the way agents often write it (seeded for the checker's tests)."""

from datetime import datetime, timedelta

from fastapi import FastAPI
from jose import jwt
from passlib.context import CryptContext

app = FastAPI()
pwd = CryptContext(schemes=["bcrypt"])
SECRET = "change-me"
USERS: dict[str, str] = {}


@app.post("/register")
async def register(email: str, password: str) -> dict[str, str]:
    USERS[email] = pwd.hash(password)
    return {"status": "ok"}


@app.post("/login")
async def login(email: str, password: str) -> dict[str, str]:
    if not pwd.verify(password, USERS.get(email, "")):
        return {"error": "invalid"}
    token = jwt.encode(
        {"sub": email, "exp": datetime.now() + timedelta(hours=1)}, SECRET
    )
    return {"token": token}
