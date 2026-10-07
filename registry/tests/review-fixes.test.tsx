import { act, fireEvent, renderHook, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { delay, http, HttpResponse } from "msw"
import type { ReactNode } from "react"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ApiKeyManager } from "@/components/gotauth/api-key-manager"
import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"
import { SessionList } from "@/components/gotauth/session-list"
import { SocialButtons } from "@/components/gotauth/social-buttons"
import { UserButton } from "@/components/gotauth/user-button"
import { useSession } from "@/hooks/use-session"
import { createGotAuthClient } from "@/lib/gotauth-client"

import { SESSION, USER, renderWith } from "./helpers"
import { BASE, server } from "./server"

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

describe("review fixes", () => {
  it("useSession publishes only the newest answer", async () => {
    let calls = 0
    server.use(
      http.get(`${BASE}/session`, async () => {
        calls += 1
        if (calls === 1) {
          // The fetch that started before sign-in: slow, and signed out.
          await delay(150)
          return HttpResponse.json(null)
        }
        return HttpResponse.json({ session: SESSION, user: USER })
      }),
    )
    const client = createGotAuthClient({ baseURL: BASE })
    const wrapper = ({ children }: { children: ReactNode }) => (
      <GotAuthProvider client={client}>{children}</GotAuthProvider>
    )
    const { result } = renderHook(() => useSession(), { wrapper })
    act(() => client.notify()) // sign-in finished while the first fetch is pending
    await waitFor(() => expect(result.current.data?.user.id).toBe("usr_1"))
    await act(() => delay(250))
    expect(result.current.data?.user.id).toBe("usr_1")
  })

  it("a body that fails mid-read is a NETWORK_ERROR", async () => {
    const broken = new ReadableStream({
      pull(controller) {
        controller.error(new TypeError("terminated"))
      },
    })
    const client = createGotAuthClient({
      fetch: async () => new Response(broken, { status: 200 }),
    })
    const result = await client.getSession()
    expect(result.error?.code).toBe("NETWORK_ERROR")
  })

  it("verifyEmail never sends callback_url", async () => {
    const urls: string[] = []
    const client = createGotAuthClient({
      baseURL: "https://api.test",
      fetch: async (url) => {
        urls.push(String(url))
        return new Response(JSON.stringify({ status: "ok" }), { status: 200 })
      },
    })
    await client.verifyEmail({ token: "gav_x", callback_url: "/home" } as { token: string })
    expect(urls).toEqual(["https://api.test/verify-email?token=gav_x"])
  })

  it("UserButton keeps the avatar while refetching", async () => {
    server.use(
      http.get(`${BASE}/session`, async () => {
        await delay(100)
        return HttpResponse.json({ session: SESSION, user: USER })
      }),
    )
    const { client } = renderWith(<UserButton />)
    await screen.findByRole("button", { name: "Account menu" })
    act(() => client.notify())
    expect(screen.getByRole("button", { name: "Account menu" })).toBeTruthy()
  })

  it("SessionList explains a revoked current session without a callback", async () => {
    server.use(
      http.get(`${BASE}/sessions`, () =>
        HttpResponse.json({ sessions: [SESSION], current_session_id: "ses_1" }),
      ),
      http.post(`${BASE}/sessions/revoke`, () => HttpResponse.json({ status: "ok" })),
      http.get(`${BASE}/session`, () => HttpResponse.json(null)),
    )
    renderWith(<SessionList />)
    await userEvent.setup().click(await screen.findByRole("button", { name: "Sign out of this device" }))
    expect(await screen.findByText("You signed out of this device.")).toBeTruthy()
    expect(screen.queryByRole("table")).toBeNull()
  })

  it("SocialButtons are enabled again after a back-forward cache restore", async () => {
    server.use(
      http.post(`${BASE}/sign-in/social`, () => HttpResponse.json({ url: "https://github.test/a" })),
    )
    vi.stubGlobal("location", { ...window.location, assign: vi.fn() })
    renderWith(<SocialButtons providers={[{ id: "github", name: "GitHub" }]} />)
    await userEvent.setup().click(screen.getByRole("button", { name: "Continue with GitHub" }))
    await waitFor(() => expect(screen.getByRole("button")).toHaveProperty("disabled", true))
    const event = new Event("pageshow") as PageTransitionEvent
    Object.defineProperty(event, "persisted", { value: true })
    act(() => {
      window.dispatchEvent(event)
    })
    expect(screen.getByRole("button", { name: "Continue with GitHub" })).toHaveProperty("disabled", false)
  })

  it("ApiKeyManager handles a missing clipboard and clears errors on close", async () => {
    let fail = true
    server.use(
      http.get(`${BASE}/api-keys`, () => HttpResponse.json({ api_keys: [] })),
      http.post(`${BASE}/api-keys`, () =>
        fail
          ? HttpResponse.json({ error: { code: "INVALID_REQUEST", message: "bad" } }, { status: 400 })
          : HttpResponse.json({
              api_key: {
                id: "key_1", name: "ci", start: "AAAAAA", owner_type: "user", owner_id: "usr_1",
                user_id: "usr_1", scopes: [], expires_at: null, last_used_at: null,
                rate_limit_max: null, rate_limit_window: null, enabled: true,
                created_by: "usr_1", created_at: "2026-10-01T10:00:00Z", metadata: {},
              },
              key: `gak_${"A".repeat(43)}`,
            }),
      ),
    )
    renderWith(<ApiKeyManager />)
    const user = userEvent.setup()
    // After setup: user-event installs its own clipboard stub on navigator.
    Object.defineProperty(navigator, "clipboard", { value: undefined, configurable: true })
    await user.click(await screen.findByRole("button", { name: "Create key" }))
    let dialog = await screen.findByRole("dialog")
    await user.type(within(dialog).getByLabelText("Name"), "ci")
    await user.click(within(dialog).getByRole("button", { name: "Create key" }))
    expect(await within(dialog).findByText("Check the form and try again.")).toBeTruthy()
    fireEvent.keyDown(dialog, { key: "Escape" })
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull())
    expect(screen.queryByText("Check the form and try again.")).toBeNull()
    fail = false
    await user.click(screen.getByRole("button", { name: "Create key" }))
    dialog = await screen.findByRole("dialog")
    expect(within(dialog).queryByText("Check the form and try again.")).toBeNull()
    await user.type(within(dialog).getByLabelText("Name"), "ci")
    await user.click(within(dialog).getByRole("button", { name: "Create key" }))
    await user.click(await screen.findByRole("button", { name: "Copy key" }))
    expect(await screen.findByText(/Copying didn't work/)).toBeTruthy()
  })
})
