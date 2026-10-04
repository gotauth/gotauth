# type: ignore
# ruff: noqa
"""Scores 70: two high findings (GA008 and GA013) and nothing else."""

import requests
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True)


def fetch(url: str) -> requests.Response:
    return requests.get(url, verify=False, timeout=5)
