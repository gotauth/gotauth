# PyCon US 2027 talk proposal

**Dates:** not announced when checked on 2026-10-16. PyCon US 2027 is in Long Beach,
California. For 2026 the call for proposals closed on 2025-12-19, and for 2025 on
2024-12-19, so expect the 2027 call to close in mid-December 2026. Check
https://us.pycon.org and https://pythondeadlin.es, and submit well before the deadline.

**Format:** a 30-minute talk. Check the current call for the allowed lengths and the
fields of the form; the text below fits the usual title, description, audience,
outline and notes fields.

**Keep it about the problem, not the product.** A talk that reads as advertising is
unlikely to be accepted. GotAuth appears as one worked example among the options, and the
talk must be useful to someone who never installs it.

## Title

Auth for MCP servers in Python

## Description (abstract)

Claude, IDEs and other MCP clients now sign users into MCP servers with OAuth 2.1. If
you build an MCP server in Python, someone has to run the authorization server, and
the Python SDK's advice is to hand that to your identity provider. What if your users
are in your own database?

This talk walks through what the MCP authorization spec asks of a Python server, one
request at a time: the 401 that starts discovery, protected resource metadata (RFC
9728), the authorization code flow with PKCE, tokens bound to one server (RFC 8707),
and client ID metadata documents, which replace dynamic registration in the 2026-07-28
revision and bring a server-side request forgery risk with them. Then it looks at what
changes when the caller is an AI agent acting for a user: its own credentials, the
`act` claim, and revoking one agent without signing the user out.

You will leave knowing what to check in any MCP auth setup, hosted or self-hosted, and
how to wire a FastMCP server to your own user table.

## Audience

Python developers who build or plan MCP servers or AI backends with FastAPI or another
ASGI framework. It helps to have used OAuth sign-in before; no spec knowledge needed.
Intermediate level.

## Outline (30 minutes)

| Minutes | Part |
|---|---|
| 0-3 | The setting: an MCP client wants to call your tools as one of your users |
| 3-9 | Discovery: the 401, `WWW-Authenticate`, RFC 9728 and RFC 8414 documents, live with MCP Inspector |
| 9-14 | The flow: PKCE, `resource`, consent, and why a token for one server must fail at another |
| 14-19 | Who is the client? Dynamic registration versus client ID metadata documents, and how to fetch a URL a stranger chose without opening a hole into your network |
| 19-24 | Agents: delegated credentials, the `act` claim, scopes that step up, revoking one agent |
| 24-27 | Options in Python today: hosted identity providers through FastMCP, Authlib's building blocks, an embedded server (GotAuth as the worked example); what each costs you |
| 27-30 | A checklist for your own MCP server, and questions |

## Why now (notes for reviewers)

- The MCP authorization spec changed twice in a year: client ID metadata documents
  became the preferred registration method (revision 2025-11-25), and the 2026-07-28
  revision deprecates dynamic registration.
- Python is where many MCP servers are written (FastMCP, the MCP Python SDK), but the
  SDK's docs leave the authorization server to an identity provider.
- In a February 2026 benchmark of coding agents, Python auth came out "100%
  Custom/DIY: JWT + passlib + python-jose". People are building this now, often with
  an agent, and often without a checklist.

**Speaker notes:** I maintain GotAuth, an open-source library that runs an OAuth 2.1
server for MCP inside FastAPI apps; the talk's demo uses its example app, and every
slide also shows what to check when you use a hosted provider instead. <Add prior
talks or writing here, if any.>
