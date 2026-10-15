import { act, renderHook, waitFor } from "@testing-library/react"
import { http, HttpResponse } from "msw"
import type { ReactNode } from "react"
import { describe, expect, expectTypeOf, it } from "vitest"

import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"
import { useSession } from "@/hooks/use-session"
import { createGotAuthClient, type SessionWithUserOut } from "@/lib/gotauth-client"

import { SESSION, USER } from "./helpers"
import { BASE, server } from "./server"

describe("useSession", () => {
  it("loads once, is shared and refetches after sign-out", async () => {
    let signedIn = true
    let loads = 0
    server.use(
      http.get(`${BASE}/session`, () => {
        loads += 1
        return HttpResponse.json(signedIn ? { session: SESSION, user: USER } : null)
      }),
      http.post(`${BASE}/sign-out`, () => {
        signedIn = false
        return HttpResponse.json({ status: "ok" })
      }),
    )
    const client = createGotAuthClient({ baseURL: BASE })
    const wrapper = ({ children }: { children: ReactNode }) => (
      <GotAuthProvider client={client}>{children}</GotAuthProvider>
    )
    const first = renderHook(() => useSession(), { wrapper })
    const second = renderHook(() => useSession(), { wrapper })
    expect(first.result.current.isPending).toBe(true)
    await waitFor(() => expect(first.result.current.data?.user.email).toBe("ada@example.com"))
    expect(second.result.current.data?.user.id).toBe("usr_1")
    expect(loads).toBe(1)
    expectTypeOf(first.result.current.data).toEqualTypeOf<SessionWithUserOut | null>()
    await act(async () => {
      await client.signOut()
    })
    await waitFor(() => expect(first.result.current.data).toBeNull())
    expect(second.result.current.data).toBeNull()
    expect(loads).toBe(2)
  })

  it("keeps the last answer while it refetches", async () => {
    let release: (() => void) | undefined
    let calls = 0
    server.use(
      http.get(`${BASE}/session`, async () => {
        calls += 1
        if (calls > 1) await new Promise<void>((resolve) => (release = resolve))
        return HttpResponse.json({ session: SESSION, user: USER })
      }),
    )
    const client = createGotAuthClient({ baseURL: BASE })
    const { result } = renderHook(() => useSession(client))
    await waitFor(() => expect(result.current.data?.user.id).toBe("usr_1"))
    act(() => client.notify())
    await waitFor(() => expect(result.current.isRefetching).toBe(true))
    // Pages that wait for isPending keep their forms (and their state) mounted.
    expect(result.current.isPending).toBe(false)
    expect(result.current.data?.user.id).toBe("usr_1")
    await waitFor(() => expect(release).toBeDefined())
    act(() => release?.())
    await waitFor(() => expect(result.current.isRefetching).toBe(false))
  })

  it("works with an explicit client and no provider", async () => {
    server.use(http.get(`${BASE}/session`, () => HttpResponse.json(null)))
    const client = createGotAuthClient({ baseURL: BASE })
    const { result } = renderHook(() => useSession(client))
    await waitFor(() => expect(result.current.isPending).toBe(false))
    expect(result.current.data).toBeNull()
  })
})
