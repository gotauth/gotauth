import { screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { http, HttpResponse } from "msw"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ApiKeyManager } from "@/components/gotauth/api-key-manager"
import { SessionList } from "@/components/gotauth/session-list"
import { SignInForm } from "@/components/gotauth/sign-in-form"
import { SignUpForm } from "@/components/gotauth/sign-up-form"
import { SocialButtons } from "@/components/gotauth/social-buttons"
import { UserButton } from "@/components/gotauth/user-button"

import { SESSION, USER, expectAccessible, renderWith } from "./helpers"
import { BASE, server } from "./server"

afterEach(() => {
  vi.restoreAllMocks()
})

async function fillSignIn(email = "ada@example.com", password = "correct horse") {
  const user = userEvent.setup()
  await user.type(screen.getByLabelText("Email"), email)
  await user.type(screen.getByLabelText("Password"), password)
  await user.click(screen.getByRole("button", { name: "Sign in" }))
  return user
}

describe("SignInForm", () => {
  it("signs in", async () => {
    let body: unknown
    server.use(
      http.post(`${BASE}/sign-in/email`, async ({ request }) => {
        body = await request.json()
        return HttpResponse.json({ user: USER, session: SESSION })
      }),
      http.get(`${BASE}/session`, () => HttpResponse.json({ user: USER, session: SESSION })),
    )
    const onSuccess = vi.fn()
    const { container } = renderWith(<SignInForm onSuccess={onSuccess} />)
    await expectAccessible(container)
    expect(screen.getByLabelText("Email")).toHaveProperty("autocomplete", "email")
    expect(screen.getByLabelText("Password")).toHaveProperty("autocomplete", "current-password")
    await fillSignIn()
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
    expect(body).toEqual({ email: "ada@example.com", password: "correct horse", remember_me: true })
  })

  it("shows errors in a live region", async () => {
    server.use(
      http.post(`${BASE}/sign-in/email`, () =>
        HttpResponse.json(
          { error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password" } },
          { status: 401 },
        ),
      ),
    )
    renderWith(<SignInForm />)
    await fillSignIn()
    const region = await screen.findByRole("status")
    await waitFor(() => expect(region.textContent).toContain("don't match"))
    expect(region.getAttribute("aria-live")).toBe("polite")
  })

  it("hands challenges to onChallenge, or explains them inline", async () => {
    server.use(
      http.post(`${BASE}/sign-in/email`, () =>
        HttpResponse.json({ challenge: { type: "two_factor", methods: ["totp"] } }),
      ),
    )
    const onChallenge = vi.fn()
    const onSuccess = vi.fn()
    renderWith(<SignInForm onChallenge={onChallenge} onSuccess={onSuccess} />)
    await fillSignIn()
    await waitFor(() =>
      expect(onChallenge).toHaveBeenCalledWith({ type: "two_factor", methods: ["totp"] }),
    )
    expect(onSuccess).not.toHaveBeenCalled()
  })

  it("shows the two-factor step itself without onChallenge", async () => {
    server.use(
      http.post(`${BASE}/sign-in/email`, () =>
        HttpResponse.json({ challenge: { type: "two_factor", methods: ["totp"] } }),
      ),
      http.post(`${BASE}/two-factor/verify-totp`, () =>
        HttpResponse.json({ user: USER, session: SESSION }),
      ),
      http.get(`${BASE}/session`, () => HttpResponse.json({ user: USER, session: SESSION })),
    )
    const onSuccess = vi.fn()
    renderWith(<SignInForm onSuccess={onSuccess} />)
    const user = await fillSignIn()
    await user.type(await screen.findByLabelText(/authenticator app/), "123456")
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
  })
})

describe("SignUpForm", () => {
  it("shows the same message for every verification_sent", async () => {
    server.use(
      http.post(`${BASE}/sign-up/email`, () => HttpResponse.json({ status: "verification_sent" })),
    )
    const { container } = renderWith(<SignUpForm />)
    await expectAccessible(container)
    expect(screen.getByLabelText("Password")).toHaveProperty("autocomplete", "new-password")
    const user = userEvent.setup()
    await user.type(screen.getByLabelText("Email"), "ada@example.com")
    await user.type(screen.getByLabelText("Password"), "correct horse")
    await user.click(screen.getByRole("button", { name: "Create account" }))
    expect(await screen.findByText("Check your email for a link to finish signing up.")).toBeTruthy()
  })
})

describe("SocialButtons", () => {
  it("sends the browser to the provider", async () => {
    let body: unknown
    server.use(
      http.post(`${BASE}/sign-in/social`, async ({ request }) => {
        body = await request.json()
        return HttpResponse.json({ url: "https://github.test/authorize?state=x" })
      }),
    )
    const assign = vi.fn()
    vi.stubGlobal("location", { ...window.location, assign })
    const { container } = renderWith(
      <SocialButtons providers={[{ id: "github", name: "GitHub" }]} callbackURL="/home" />,
    )
    await expectAccessible(container)
    await userEvent.setup().click(screen.getByRole("button", { name: "Continue with GitHub" }))
    await waitFor(() => expect(assign).toHaveBeenCalledWith("https://github.test/authorize?state=x"))
    expect(body).toEqual({ provider: "github", callback_url: "/home" })
    vi.unstubAllGlobals()
  })
})

describe("UserButton", () => {
  it("shows the user and signs out", async () => {
    let signedIn = true
    server.use(
      http.get(`${BASE}/session`, () =>
        HttpResponse.json(signedIn ? { user: USER, session: SESSION } : null),
      ),
      http.post(`${BASE}/sign-out`, () => {
        signedIn = false
        return HttpResponse.json({ status: "ok" })
      }),
    )
    const onSignOut = vi.fn()
    const { container } = renderWith(<UserButton onSignOut={onSignOut} signInHref="/sign-in" />)
    const trigger = await screen.findByRole("button", { name: "Account menu" })
    expect(trigger.textContent).toContain("AL")
    await expectAccessible(container)
    const user = userEvent.setup()
    await user.click(trigger)
    await user.click(await screen.findByRole("menuitem", { name: "Sign out" }))
    await waitFor(() => expect(onSignOut).toHaveBeenCalledOnce())
    expect(await screen.findByRole("link", { name: "Sign in" })).toBeTruthy()
  })
})

describe("SessionList", () => {
  it("marks the current session and revokes others", async () => {
    const other = { ...SESSION, id: "ses_2", user_agent: "Mozilla/5.0 (iPhone) Safari/604.1" }
    let sessions = [SESSION, other]
    const revoked: unknown[] = []
    server.use(
      http.get(`${BASE}/sessions`, () =>
        HttpResponse.json({ sessions, current_session_id: "ses_1" }),
      ),
      http.post(`${BASE}/sessions/revoke`, async ({ request }) => {
        revoked.push(await request.json())
        sessions = [SESSION]
        return HttpResponse.json({ status: "ok" })
      }),
      http.get(`${BASE}/session`, () => HttpResponse.json({ user: USER, session: SESSION })),
    )
    const { container } = renderWith(<SessionList />)
    expect(await screen.findByText("(this device)")).toBeTruthy()
    await expectAccessible(container)
    expect(screen.getByText("Safari on iOS")).toBeTruthy()
    await userEvent.setup().click(screen.getByRole("button", { name: "Sign out Safari on iOS" }))
    await waitFor(() => expect(revoked).toEqual([{ session_id: "ses_2" }]))
    expect(await screen.findByText("Signed out that device.")).toBeTruthy()
    expect(screen.queryByText("Safari on iOS")).toBeNull()
  })

  it("signs out every other device", async () => {
    let calls = 0
    server.use(
      http.get(`${BASE}/sessions`, () =>
        HttpResponse.json({ sessions: [SESSION, { ...SESSION, id: "ses_2" }], current_session_id: "ses_1" }),
      ),
      http.post(`${BASE}/sessions/revoke-others`, () => {
        calls += 1
        return HttpResponse.json({ status: "ok" })
      }),
    )
    renderWith(<SessionList />)
    await userEvent.setup().click(await screen.findByRole("button", { name: "Sign out all other devices" }))
    await waitFor(() => expect(calls).toBe(1))
  })
})

describe("ApiKeyManager", () => {
  it("shows a new key once and drops it when the dialog closes", async () => {
    const key = `gak_${"A".repeat(43)}`
    const apiKey = {
      id: "key_1",
      name: "ci",
      start: "AAAAAA",
      owner_type: "user",
      owner_id: "usr_1",
      user_id: "usr_1",
      scopes: ["projects:read"],
      expires_at: null,
      last_used_at: null,
      rate_limit_max: null,
      rate_limit_window: null,
      enabled: true,
      created_by: "usr_1",
      created_at: "2026-10-01T10:00:00Z",
      metadata: {},
    }
    let keys: (typeof apiKey)[] = []
    let created: unknown
    server.use(
      http.get(`${BASE}/api-keys`, () => HttpResponse.json({ api_keys: keys })),
      http.post(`${BASE}/api-keys`, async ({ request }) => {
        created = await request.json()
        keys = [apiKey]
        return HttpResponse.json({ api_key: apiKey, key })
      }),
    )
    const { container } = renderWith(<ApiKeyManager scopes={["projects:read", "projects:write"]} />)
    expect(await screen.findByText("No API keys yet.")).toBeTruthy()
    await expectAccessible(container)
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Create key" }))
    const dialog = await screen.findByRole("dialog")
    await expectAccessible(dialog)
    await user.type(within(dialog).getByLabelText("Name"), "ci")
    await user.click(within(dialog).getByLabelText("projects:read"))
    await user.click(within(dialog).getByRole("button", { name: "Create key" }))
    expect(await screen.findByTestId("new-api-key")).toHaveProperty("textContent", key)
    expect(created).toEqual({ name: "ci", scopes: ["projects:read"] })
    await user.click(screen.getByRole("button", { name: "Done" }))
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(document.body.textContent).not.toContain(key)
    expect(screen.getByText("gak_AAAAAA...")).toBeTruthy()
    // Opening the dialog again starts empty: the key is gone from state.
    await user.click(screen.getByRole("button", { name: "Create key" }))
    expect(await screen.findByRole("dialog")).toBeTruthy()
    expect(document.body.textContent).not.toContain(key)
  })
})
