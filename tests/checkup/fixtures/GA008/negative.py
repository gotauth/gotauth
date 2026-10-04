# type: ignore
# ruff: noqa
"""GA008 negative: certificates are checked, against a private CA where needed."""

import httpx
import requests

INTERNAL_CA = "/etc/ssl/certs/internal-ca.pem"


def fetch_profile(url: str) -> dict:
    return requests.get(url, timeout=10).json()


async def fetch_keys(url: str) -> dict:
    async with httpx.AsyncClient(verify=INTERNAL_CA) as client:
        return (await client.get(url)).json()


def make_session() -> requests.Session:
    session = requests.Session()
    session.verify = INTERNAL_CA
    return session
