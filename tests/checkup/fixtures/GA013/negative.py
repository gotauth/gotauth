# type: ignore
# ruff: noqa
"""GA013 negative: listed origins with credentials, or any origin without them."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://app.example.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
)

public_api = FastAPI()
public_api.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["GET"])
