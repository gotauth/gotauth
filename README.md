# GotAuth

**Got auth?** Open-source auth for Python AI backends: users, sessions, social login, 2FA, passkeys, organizations, API keys, agent identities and a built-in OAuth 2.1 server for your MCP servers. All of it lives in your own database.

Status: pre-alpha. The package layout, dev environment, tooling and CI are in place. The auth modules are being built as separate work packages (see the engineering plan below) and nothing is ready for production use yet.

## Quickstart for contributors

You need Git and Docker (Docker Desktop on Windows and macOS). Python, uv, Node and pnpm run inside the dev container, so there is nothing else to install.

```bash
git clone https://github.com/gotauth/gotauth.git
cd gotauth
./dev.sh uv sync --locked --all-extras   # PowerShell: .\dev.ps1 uv sync --locked --all-extras
./dev.sh uv run poe check                # format check, lint, types and tests
```

The first run builds the dev image and fills the dependency cache, which takes a few minutes. [CONTRIBUTING.md](CONTRIBUTING.md) covers the dev container, git worktrees, commits and pinned versions. Agents start with [AGENTS.md](AGENTS.md).

## Repository layout

| Path | Contents |
|---|---|
| `src/gotauth/` | The library: one subpackage per module or plugin |
| `tests/` | Tests, one folder per area |
| `spec/` | Language-neutral test vectors |
| `changes/` | News fragments for the changelog |
| `registry/` | UI components (shadcn registry) and the typed fetch client |
| `apps/landing/`, `apps/docs/` | Landing page and docs site |
| `examples/` | Runnable example apps |
| `docker/`, `compose.yaml`, `dev.sh`, `dev.ps1` | Dev container |
| `docs/` | Build plan, engineering plan, research, requests and contract change requests |

## Documents

| Document | What it covers |
|---|---|
| [docs/build-plan.md](docs/build-plan.md) | Strategy, positioning, phases, launch, money, risks |
| [docs/plan/README.md](docs/plan/README.md) | Engineering plan: work packages that several agents can build in parallel |
| [docs/plan/CONTRACTS.md](docs/plan/CONTRACTS.md) | Shared interfaces, frozen at milestone M0 |
| [AGENTS.md](AGENTS.md) | Rules every agent follows (copy of [docs/plan/AGENT-RULES.md](docs/plan/AGENT-RULES.md)) |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Dev environment, worktrees, commits, pinned versions |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability |
| [docs/research/validation-research.md](docs/research/validation-research.md) | Public evidence, competitors and validation gates (no interviews) |

## License

[MIT](LICENSE)
