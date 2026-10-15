"use client"

import { useCallback, useEffect, useSyncExternalStore } from "react"

import { useOptionalGotAuthClient } from "@/components/gotauth/gotauth-provider"
import type { GotAuthClient, GotAuthError, SessionWithUserOut } from "@/lib/gotauth-client"

type Snapshot = {
  data: SessionWithUserOut | null
  error: GotAuthError | null
  /** Only until the first answer: later refetches keep showing the last one. */
  isPending: boolean
  /** A refetch after sign-in, sign-out or another change is under way. */
  isRefetching: boolean
}

type Store = {
  snapshot: Snapshot
  listeners: Set<() => void>
  inFlight: Promise<void> | null
  // Bumped by every load: only the newest answer is published, so a fetch that
  // started before a sign-in or sign-out can never overwrite the newer state.
  generation: number
  loaded: boolean
}

// One store per client, shared by every component that calls useSession.
const stores = new WeakMap<GotAuthClient, Store>()

function storeFor(client: GotAuthClient): Store {
  let store = stores.get(client)
  if (!store) {
    store = {
      snapshot: { data: null, error: null, isPending: true, isRefetching: false },
      listeners: new Set(),
      inFlight: null,
      generation: 0,
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
  const generation = ++store.generation
  // Pages keep what they show (and forms keep their state) while this runs.
  if (store.loaded && !store.snapshot.isRefetching) {
    publish(store, { ...store.snapshot, isRefetching: true })
  }
  const request = client.getSession().then((result) => {
    if (generation !== store.generation) return // a newer load is on its way
    store.inFlight = null
    store.loaded = true
    publish(store, {
      data: result.data ?? null,
      error: result.error,
      isPending: false,
      isRefetching: false,
    })
  })
  store.inFlight = request
  return request
}

function ensureLoaded(client: GotAuthClient, store: Store): void {
  if (!store.loaded && !store.inFlight) void load(client, store)
}

const SERVER_SNAPSHOT: Snapshot = { data: null, error: null, isPending: true, isRefetching: false }

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
    ensureLoaded(client, store)
  }, [client, store])
  const refetch = useCallback(() => load(client, store), [client, store])
  return { ...snapshot, refetch }
}

