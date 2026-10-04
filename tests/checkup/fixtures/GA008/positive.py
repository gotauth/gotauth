# type: ignore
# ruff: noqa
"""GA008 positive: TLS certificate checks turned off."""

import httpx
import requests


def fetch_profile(url: str) -> dict:
    return requests.get(url, verify=False, timeout=10).json()


async def fetch_keys(url: str) -> dict:
    async with httpx.AsyncClient(verify=False) as client:
        return (await client.get(url)).json()


def make_session() -> requests.Session:
    session = requests.Session()
    session.verify = False
    return session
