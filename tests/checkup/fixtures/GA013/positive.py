# type: ignore
# ruff: noqa
"""GA013 positive: every origin may send credentialed requests."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware import Middleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

middleware = [
    Middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True),
]
