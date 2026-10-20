# Launch content

Drafts for launch week (work package G5). The owner posts them; nothing here is posted
automatically. Every number and claim is listed with its source in
[fact-check.md](fact-check.md).

## Before posting anything

Each draft assumes these are true on the day it goes out. Check them first:

1. **v0.1.0 is on PyPI**, so `pip install gotauth` and `uvx gotauth check` install the
   release the drafts describe. Today only the 0.0.1 placeholder is published.
2. **The docs site is live** at https://gotauth.ablacky.com/docs/ (the drafts link to it).
3. **The agent-install runs are done** and `agent-baseline.md` exists (work package Q2).
   Until then, every agent comparison number in these drafts reads `[pending
   measurement]`. Fill those in from `agent-baseline.md` only, never from estimates.
4. **The facts marked "re-check on posting day"** in [fact-check.md](fact-check.md)
   still hold: competitor versions, stars and downloads, the passlib and python-jose
   release dates, the MCP spec revision.
5. **The comparison page is current.** `comparison.md` (work package R1) still marks
   every GotAuth feature "planned"; update those cells to what v0.1.0 ships, with
   links, before any draft links to it.
6. **Each venue's rules** have been read again (links in each draft). Reddit blocks
   automated reads, so the subreddit rules in these drafts could not be checked here.

## The drafts

| File | Venue | Lead message |
|---|---|---|
| [show-hn.md](show-hn.md) | Hacker News | Login for your Python MCP server from your own user table |
| [reddit-mcp.md](reddit-mcp.md) | r/mcp | An embeddable OAuth 2.1 server for Python MCP servers |
| [reddit-fastapi.md](reddit-fastapi.md) | r/FastAPI | Full auth for FastAPI, plus MCP; fastapi-users migration second |
| [reddit-python-showcase.md](reddit-python-showcase.md) | r/Python | Showcase format: What My Project Does, Target Audience, Comparison |
| [devto-tutorial-fastmcp.md](devto-tutorial-fastmcp.md) | Dev.to | Tutorial: login for a FastMCP server from your own user table |
| [fastmcp-docs-pr.md](fastmcp-docs-pr.md) | FastMCP GitHub | Issue first, then a docs page PR |
| [social-threads.md](social-threads.md) | X, Bluesky, LinkedIn | Launch thread and four technical threads |
| [hero-clip-scripts.md](hero-clip-scripts.md) | Video | The three clips: shot lists and exact commands |
| [pycoders-submission.md](pycoders-submission.md) | PyCoder's Weekly | Link submission |
| [python-bytes-suggestion.md](python-bytes-suggestion.md) | Python Bytes | Topic suggestion |
| [talk-python-pitch.md](talk-python-pitch.md) | Talk Python To Me | Episode pitch |
| [pycon-2027-proposal.md](pycon-2027-proposal.md) | PyCon US 2027 | Talk proposal |
| [faq.md](faq.md) | Docs, replies | Security questions people will ask |
| [comparison.md](comparison.md) | Docs | The comparison page (work package R1) |

## Order

The build plan leads with the MCP and agent angle; the fastapi-users migration is the
second message.

1. Day 1: Show HN, then the launch thread.
2. Day 2: r/mcp, and the FastMCP issue.
3. Day 3: r/FastAPI and the Dev.to tutorial.
4. Day 4 or later: r/Python (Showcase), PyCoder's, Python Bytes, Talk Python.
5. One technical thread a week after that.

Answer questions in every thread on the day it goes out. Do not ask anyone to upvote
(Hacker News and Reddit both forbid it).
