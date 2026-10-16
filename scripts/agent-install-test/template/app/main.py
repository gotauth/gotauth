"""A small API: a list of projects."""

from fastapi import FastAPI
from pydantic import BaseModel

app = FastAPI(title="Projects API")


class Project(BaseModel):
    id: int
    name: str


PROJECTS = [Project(id=1, name="Website redesign"), Project(id=2, name="Mobile app")]


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/projects")
async def projects() -> list[Project]:
    return PROJECTS
