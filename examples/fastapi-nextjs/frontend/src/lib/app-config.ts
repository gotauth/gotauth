"use client"

import { useEffect, useState } from "react"

import type { SocialProvider } from "@/components/gotauth/social-buttons"

/** What the backend's GET /api/config says: sign-in buttons and API key scopes. */
export type AppConfig = { social_providers: SocialProvider[]; api_key_scopes: string[] }

export function useAppConfig(): AppConfig | null {
  const [config, setConfig] = useState<AppConfig | null>(null)
  useEffect(() => {
    let live = true
    fetch("/api/config")
      .then((response) => response.json() as Promise<AppConfig>)
      .then((value) => {
        if (live) setConfig(value)
      })
      .catch(() => {
        if (live) setConfig({ social_providers: [], api_key_scopes: [] })
      })
    return () => {
      live = false
    }
  }, [])
  return config
}
