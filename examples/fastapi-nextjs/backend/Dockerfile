# The example backend. Built by ../compose.yaml, which passes this repository as the
# "gotauth" build context for the library (a path dependency in pyproject.toml).
FROM ghcr.io/astral-sh/uv:0.12.22 AS uv

FROM python:3.14.8-slim-trixie
COPY --from=uv /uv /bin/
ENV UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Same layout as the repository, so the path dependency "../../.." resolves.
WORKDIR /repo
COPY --from=gotauth pyproject.toml README.md LICENSE ./
COPY --from=gotauth src ./src
WORKDIR /repo/examples/fastapi-nextjs/backend
COPY pyproject.toml uv.lock ./
RUN uv sync --locked --no-dev
COPY . ./

RUN useradd --create-home app && mkdir /data && chown app /data
USER app
EXPOSE 8000
# Migrations first (GotAuth's tables come from `gotauth generate`), then the API.
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn app.main:app --host 0.0.0.0 --port 8000"]
