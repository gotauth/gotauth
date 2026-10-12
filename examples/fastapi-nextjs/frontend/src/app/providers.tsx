"use client"

import type { ReactNode } from "react"

import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"

/** GotAuth's routes are at /api/auth on this origin (next.config.ts proxies them). */
export function Providers({ children }: { children: ReactNode }) {
  return <GotAuthProvider baseURL="/api/auth">{children}</GotAuthProvider>
}
