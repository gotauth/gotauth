# News fragments

Every pull request that changes published code (`src/gotauth/**`, `pyproject.toml`) adds a news fragment here. [towncrier](https://towncrier.readthedocs.io) turns the fragments into a section of [CHANGELOG.md](../CHANGELOG.md) at release time and deletes them.

## File name

`<WP-id>.<type>.md`, for example `C3.feature.md` or `P1.security.md`. The work-package ID appears after the entry in the changelog. For a second fragment of the same type, add a number: `C3.feature.2.md`.

| Type | Use it for |
|---|---|
| `feature` | New features and new public API |
| `bugfix` | Bug fixes |
| `security` | Security fixes and hardening that users should know about |
| `removal` | Removals, deprecations and breaking changes |
| `doc` | Documentation changes worth announcing |

## Content

One or two sentences in Markdown, written for users of the library: what changed and how it affects them, not how it was implemented. Example:

```markdown
Store session tokens as SHA-256 hashes, so a database leak does not expose live sessions.
```

## Preview

```bash
./dev.sh uv run towncrier build --draft
```

CI renders the draft too, so a fragment with an unknown type fails the build.
