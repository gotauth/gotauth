# gotauth CLI

The `gotauth` command. Work package S1. Importing `gotauth.cli` loads no optional
extras, so `uvx gotauth check` works on a bare install.

| Command | What it does |
|---|---|
| `gotauth init [--dir .] [--database-url URL] [--force]` | Writes `auth.py` (never overwrites without `--force`) and adds `GOTAUTH_SECRET` to `.env` (never replaces an existing one; mode 0600 on POSIX), then prints the FastAPI setup |
| `gotauth migrate [--auth module:attr] [--dry-run]` | Creates missing tables and columns; never drops or alters |
| `gotauth generate [--auth module:attr] [-m MESSAGE] [--config alembic.ini]` | Writes an Alembic revision for GotAuth's tables |
| `gotauth generate --sql --dialect postgresql\|sqlite` | Prints the DDL |
| `gotauth secret` | Prints a new 43-character secret |
| `gotauth check ...` | Scans a project for risky auth code (`gotauth.checkup`) |
| `gotauth import ...` | Imports users from another library (when available) |

`--auth` defaults to `auth:auth`: the `auth` object in `auth.py` in the current
directory. A missing extra prints the `pip install "gotauth[sqlalchemy]"` hint. Errors
exit with 1, unavailable commands with 2.
