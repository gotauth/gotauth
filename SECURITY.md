# Security policy

## Supported versions

GotAuth is pre-1.0. Security fixes go into the latest minor release only.

| Version | Supported |
|---|---|
| latest `0.x` release | yes |
| older `0.x` releases | no: upgrade to the latest |

The support policy for 1.0 and later will be set before 1.0 ships.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. Do not open a public issue, discussion or pull request for a suspected vulnerability, and do not test against systems you do not own.

Include what you can:
- the affected module, endpoint or function, and the version or commit
- steps to reproduce, or a proof of concept
- the impact you expect, for example account takeover, token disclosure or account enumeration

## What happens next

These are targets, not guarantees. GotAuth is maintained by one person.

| Step | Target |
|---|---|
| Acknowledge the report | 3 business days |
| Triage: confirm, assess severity (CVSS 4.0), agree on a timeline | 7 days |
| Fix for critical and high severity | 30 days |
| Fix for medium and low severity | the next planned release, at most 90 days |

**The process:**
1. Fixes are developed in a private fork of the advisory.
2. They are released as a patch version, published to PyPI with attestations.
3. A GitHub security advisory, with a CVE where it applies, goes out at the same time.
4. The changelog entry appears under "Security".

We will keep you informed at each step. If we cannot meet a target, we will tell you why and agree on a new date with you. If 90 days pass without a fix, you may disclose after giving us a week's notice.

## Credit

Reporters are credited by name, or by handle, in the advisory and the changelog, unless they ask to stay anonymous. GotAuth has no bug bounty.

## Scope

**In scope:** the `gotauth` Python package, the UI registry in `registry/`, and the examples' auth wiring.

**Out of scope:**
- vulnerabilities that need a misconfiguration the docs warn against, for example `trusted_proxies` set to any address or the cookie cache with a long `max_age`
- the host application's own authorization logic
- denial of service by volume alone
- findings in dependencies that GotAuth's code cannot reach

Report those upstream.

## Verifying releases

Every release on PyPI is published with trusted publishing from `.github/workflows/release.yml` and carries PEP 740 attestations. They are shown on each file's page on PyPI, and the `pypi-attestations` tool can check them against this repository's release workflow.

## Security design

- [Threat model](docs/security/threat-model.md)
- [OWASP ASVS 5.0 Level 2 mapping](docs/security/asvs.md)
- [Review checklist](docs/security/review-checklist.md)
- [OpenID conformance runs](docs/security/conformance/README.md)
