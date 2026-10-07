import { render, type RenderResult } from "@testing-library/react"
import axe from "axe-core"
import type { ReactElement } from "react"
import { expect } from "vitest"

import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"
import { createGotAuthClient, type GotAuthClient } from "@/lib/gotauth-client"

import { BASE } from "./server"

export const USER = {
  id: "usr_1",
  email: "ada@example.com",
  email_verified: true,
  name: "Ada Lovelace",
  image: null,
  created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-01T10:00:00Z",
}

export const SESSION = {
  id: "ses_1",
  user_id: "usr_1",
  expires_at: "2026-10-08T10:00:00Z",
  remember_me: true,
  created_at: "2026-10-01T10:00:00Z",
  updated_at: "2026-10-01T10:00:00Z",
  ip_address: "203.0.113.9",
  user_agent: "Mozilla/5.0 (Windows NT 10.0) Chrome/140.0 Safari/537.36",
}

export function renderWith(ui: ReactElement): RenderResult & { client: GotAuthClient } {
  const client = createGotAuthClient({ baseURL: BASE })
  const result = render(<GotAuthProvider client={client}>{ui}</GotAuthProvider>)
  return { ...result, client }
}

/** axe in jsdom; color contrast needs layout, which jsdom does not do. */
export async function expectAccessible(container: Element) {
  const results = await axe.run(container, { rules: { "color-contrast": { enabled: false } } })
  expect(results.violations.map((v) => `${v.id}: ${v.help}`)).toEqual([])
}
