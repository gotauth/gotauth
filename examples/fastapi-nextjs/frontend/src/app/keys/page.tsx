"use client"

import Link from "next/link"

import { ApiKeyManager } from "@/components/gotauth/api-key-manager"
import { useSession } from "@/hooks/use-session"
import { useAppConfig } from "@/lib/app-config"

export default function KeysPage() {
  const { data, isPending } = useSession()
  const config = useAppConfig()
  if (isPending || !config) return null
  if (!data) {
    return (
      <p>
        <Link href="/sign-in" className="underline">Sign in</Link> to manage API keys.
      </p>
    )
  }
  return (
    <section className="grid gap-4">
      <h1 className="text-2xl font-semibold">API keys</h1>
      <p className="text-muted-foreground text-sm">
        For scripts:{" "}
        <code className="rounded bg-muted px-1 py-0.5">
          curl -H &quot;x-api-key: gak_...&quot; http://localhost:3000/api/v1/projects
        </code>
      </p>
      {/* The backend's api_key(allowed_scopes=...), from GET /api/config. */}
      <ApiKeyManager scopes={config.api_key_scopes} />
    </section>
  )
}
