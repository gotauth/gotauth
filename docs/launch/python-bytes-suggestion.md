# Python Bytes topic suggestion

**How:** by email; the site's "Suggest a headline" section asks for topic ideas.
Cached copies of the site give contact@pythonbytes.fm; confirm the address on the live
site (https://pythonbytes.fm) before sending. The show covers Python, developer tools
and open-source projects in short items, so pitch one item, not an interview.

## Subject

Topic idea: a scanner for risky hand-written Python auth (uvx gotauth check)

## Email

Hi Michael and Brian,

An item that might fit the show: `uvx gotauth check`, a free scanner for risky
hand-written auth code in Python projects. It reads files with `ast` only (no imports,
no network, standard library only) and flags 13 patterns, among them passlib and
python-jose imports, HS256 JWTs signed with a literal secret, `jwt.decode` with
verification off, `==` on tokens, `verify=False` on httpx and requests, and login routes
without a rate limiter. Each finding comes with a fix, and it can write SARIF for
GitHub code scanning.

Why now: FastAPI's docs moved from python-jose to PyJWT in 2024 and from passlib to
pwdlib in 2025, but a February 2026 benchmark found coding agents still writing
passlib and python-jose for Python auth.

It is part of GotAuth (https://github.com/gotauth/gotauth, MIT), an auth library for
FastAPI that also runs an OAuth 2.1 server for MCP servers, but the scanner works on
any project.

Thanks for the show,
<name>
