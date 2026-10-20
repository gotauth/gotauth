# Social threads

For X, Bluesky and LinkedIn. Every post below is at most 280 characters (X's limit;
Bluesky allows 300), checked with the script in [fact-check.md](fact-check.md). On
LinkedIn, join a thread into one post. Links count toward the length on Bluesky; X
shortens them to 23 characters.

Post one technical thread a week after launch. Add a screenshot or a short clip from
[hero-clip-scripts.md](hero-clip-scripts.md) where it says [image] or [clip].

## Launch thread

1/
GotAuth 0.1 is out: open-source auth for Python AI backends. Users, sessions, social login, 2FA, passkeys, organizations, API keys, agent identities and an OAuth 2.1 server for your MCP servers. All in your own database.
https://github.com/gotauth/gotauth

2/
The MCP part: your FastAPI app becomes the authorization server. Claude or any MCP client signs your users in from your own user table, and your FastMCP server accepts only tokens issued for it.
[clip: MCP login and revoke]

3/
One line on the FastMCP side:
auth=fastmcp_auth(auth, resource=MCP_URL, scopes=["projects:read"])
Tools read the caller with current_access(). A missing scope is a 403 the client can step up from.

4/
For agents: an agent owned by a user or an organization gets its own API keys and OAuth clients. Its tokens carry an act claim naming it, so your code can tell a user from the user's agent. Revoke one agent and the rest keep working.

5/
Not using GotAuth? `uvx gotauth check` scans any Python project for risky hand-written auth: passlib, python-jose, HS256 with a literal secret, verify=False and 9 more rules. Standard library only, no network.
[clip: gotauth check]

6/
It's 0.1 with one maintainer. Not done yet: the OpenID conformance run, SAML and SCIM, token exchange for sub-agents. Docs: https://gotauth.ablacky.com/docs/
Feedback and issues welcome.

## Thread: CIMD for MCP clients

1/
How does an MCP server know who a client is, when anyone can write a client? The 2026-07-28 MCP spec answers with client ID metadata documents (CIMD), and deprecates dynamic registration in their favor. A thread on what that means for your server.

2/
With CIMD the client_id is an https URL. Your authorization server fetches the JSON document at that URL, which lists the client's name and redirect URIs. The client needs no registration step.

3/
The catch: your server now fetches URLs that strangers choose. GotAuth resolves the host first and only connects to public addresses. Private, loopback, link-local and unique-local ranges are refused, with no redirects, a 5 s timeout and a 5 KB limit.

4/
Loopback redirects are a special case: any program on the user's machine could claim them. So a CIMD client with a localhost redirect always sees the consent screen again, even if the user said yes before.

5/
In GotAuth, CIMD is on by default, and always on with mcp=True. Dynamic registration (RFC 7591) is one option for clients that still need it:
oauth_provider(mcp=True, resources=[...], allow_dynamic_registration=True)

## Thread: hashed session tokens

1/
A database dump should not let anyone sign in as your users. If your sessions table holds the tokens as they are, it does. GotAuth stores only hashes, for every bearer secret it issues.

2/
A session token is random and opaque. The cookie holds the token, the table holds its SHA-256 hash. Lookups hash what the browser sends and compare in constant time. A leaked table or backup gives hashes, not sessions.

3/
The same rule covers API keys, email links, OAuth codes, refresh tokens and client secrets. Each is shown once, to its owner, and stored hashed. A test runs a full scenario on SQLite and scans every table and log line for raw secrets.

4/
Revoking deletes the row, so the session ends on the next request. An optional signed cookie cache saves a database read per request; while it is on, a revoked session works until the cache expires (max_age, 5 minutes by default).

## Thread: act claims for agents

1/
When an AI agent calls your API for a user, whose request is it? If the token just says "user 42", you can't tell the user from their agent, limit the agent, or revoke it alone. That's what the act claim is for.

2/
act (actor) comes from OAuth token exchange, RFC 8693. A token with sub: user 42 and act: {sub: agent 7} says "agent 7 acting for user 42". Your logs, permissions and audits can see both.

3/
In GotAuth an agent is a principal owned by a user or an organization. It gets its own API keys and OAuth clients. Tokens from a client linked to the agent carry act: {"sub": "<agent id>"}.

4/
Revoke one agent: its API keys are revoked and its OAuth clients' tokens stop working, in one transaction. The user's own session and other agents keep going. In a tool, current_access() gives you both the user and the agent.

## Thread: no account enumeration

1/
"No account with that email" tells an attacker which emails have accounts. Sign-in, password reset and magic-link endpoints should answer the same either way. Getting the message right is not enough: the timing can leak it too.

2/
GotAuth answers sign-in, reset and magic links the same for known and unknown emails, and sign-up too while email verification is on. A sign-in for an unknown email still checks a dummy password hash, so it takes as long as a real one.

3/
The slow part of a reset is sending the email. GotAuth sends it after the reply, for every address alike, so the response time says nothing about the account. Timing tests in the security suite check sign-in, reset and verification.
