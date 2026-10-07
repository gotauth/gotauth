"use client"

import { useCallback, useEffect, useSyncExternalStore } from "react"

import { useOptionalGotAuthClient } from "@/components/gotauth/gotauth-provider"
import type { GotAuthClient, GotAuthError, SessionWithUserOut } from "@/lib/gotauth-client"

type Snapshot = {
  data: SessionWithUserOut | null
  error: GotAuthError | null
  isPending: boolean
}

type Store = {
  snapshot: Snapshot
  listeners: Set<() => void>
  inFlight: Promise<void> | null
  loaded: boolean
}

// One store per client, shared by every component that calls useSession.
const stores = new WeakMap<GotAuthClient, Store>()

function storeFor(client: GotAuthClient): Store {
  let store = stores.get(client)
  if (!store) {
    store = {
      snapshot: { data: null, error: null, isPending: true },
      listeners: new Set(),
      inFlight: null,
      loaded: false,
    }
    stores.set(client, store)
    const created = store
    client.subscribe(() => {
      void load(client, created)
    })
  }
  return store
}

function publish(store: Store, snapshot: Snapshot) {
  store.snapshot = snapshot
  for (const listener of store.listeners) listener()
}

function load(client: GotAuthClient, store: Store): Promise<void> {
  if (store.inFlight) return store.inFlight
  if (!store.snapshot.isPending) publish(store, { ...store.snapshot, isPending: true })
  store.inFlight = client.getSession().then((result) => {
    store.inFlight = null
    store.loaded = true
    publish(store, { data: result.data ?? null, error: result.error, isPending: false })
  })
  return store.inFlight
}

const SERVER_SNAPSHOT: Snapshot = { data: null, error: null, isPending: true }

/** The current session from GET /session, shared and refetched after sign-in,
 * sign-out and revoke. */
export function useSession(explicit?: GotAuthClient) {
  const fromContext = useOptionalGotAuthClient()
  const client = explicit ?? fromContext
  if (!client) {
    throw new Error("Wrap your app in <GotAuthProvider> or pass a client to useSession.")
  }
  const store = storeFor(client)
  const subscribe = useCallback(
    (listener: () => void) => {
      store.listeners.add(listener)
      return () => {
        store.listeners.delete(listener)
      }
    },
    [store],
  )
  const snapshot = useSyncExternalStore(
    subscribe,
    () => store.snapshot,
    () => SERVER_SNAPSHOT,
  )
  useEffect(() => {
    if (!store.loaded) void load(client, store)
  }, [client, store])
  const refetch = useCallback(() => load(client, store), [client, store])
  return { ...snapshot, refetch }
}

