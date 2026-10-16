import os

os.environ.setdefault("GOTAUTH_SECRET", "test-secret-" + "x" * 40)
os.environ.setdefault("GITHUB_CLIENT_ID", "id")
os.environ.setdefault("GITHUB_CLIENT_SECRET", "secret")

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402


def test_health() -> None:
    assert TestClient(app).get("/health").json() == {"status": "ok"}


def test_projects_need_a_credential() -> None:
    assert TestClient(app).get("/projects").status_code == 401
