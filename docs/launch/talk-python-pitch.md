# Talk Python To Me pitch

**How:** by email. The show's about page (https://talkpython.fm/about) asks listeners
to send show ideas to contact@talkpython.fm; confirm it on the live page before
sending. Episodes are about an hour and conversational.

## Subject

Episode idea: auth for MCP servers and AI agents in Python

## Email

Hi Michael,

An episode idea: how a Python app signs users in for its MCP servers and AI agents,
and what changes when the caller is an agent rather than a person.

**Angle.** MCP clients such as Claude now sign users into MCP servers with OAuth 2.1.
In Python, the usual advice is to hand that to a hosted identity provider. I build
GotAuth (https://github.com/gotauth/gotauth, MIT), a FastAPI auth library that runs
the authorization server inside the app, on the app's own user table. The episode
would be about the problems, not the library: what an MCP server needs from OAuth, and
how to get it right in Python.

**Three talking points:**
1. **What the MCP auth spec asks for, in plain terms:** discovery from a 401,
   PKCE, tokens bound to one server (RFC 8707), and client ID metadata documents,
   which the 2026-07-28 revision prefers to dynamic registration, and the server-side
   request forgery risk that comes with fetching them.
2. **Agents as principals:** an agent acting for a user should not hold the user's
   password or session. Its own keys and tokens, an `act` claim that names it, and
   revoking one agent without signing the user out.
3. **Why AI-written Python auth still uses passlib and python-jose,** after
   FastAPI's docs moved off them (python-jose in 2024, passlib in 2025), and what a static check (`uvx gotauth check`) finds
   in that code.

**About me:** <two or three sentences: who you are, what you have built, where you
work or have spoken. Fill in before sending.>

Thanks,
<name>
