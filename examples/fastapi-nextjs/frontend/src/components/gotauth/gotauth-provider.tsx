"use client"

import { createContext, useContext, useMemo, type ReactNode } from "react"

import { createGotAuthClient, type GotAuthClient } from "@/lib/gotauth-client"

const GotAuthContext = createContext<GotAuthClient | null>(null)

/** Supplies the GotAuth client to every GotAuth component below it. */
export function GotAuthProvider({
  client,
  baseURL,
  children,
}: {
  client?: GotAuthClient
  baseURL?: string
  children: ReactNode
}) {
  const value = useMemo(() => client ?? createGotAuthClient({ baseURL }), [client, baseURL])
  return <GotAuthContext.Provider value={value}>{children}</GotAuthContext.Provider>
}

/** The client from the nearest GotAuthProvider, or null outside one. */
export function useOptionalGotAuthClient(): GotAuthClient | null {
  return useContext(GotAuthContext)
}

/** The client from the nearest GotAuthProvider. */
export function useGotAuthClient(): GotAuthClient {
  const client = useContext(GotAuthContext)
  if (!client) {
    throw new Error("Wrap your app in <GotAuthProvider> to use GotAuth components.")
  }
  return client
}
