"use client"

import { useState } from "react"

import { Button } from "@/components/ui/button"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import type { GotAuthError } from "@/lib/gotauth-client"

export type SocialProvider = { id: string; name: string }

/** One button per provider; sends the browser to the provider's sign-in page. */
export function SocialButtons({
  providers,
  callbackURL,
  errorCallbackURL,
}: {
  providers: SocialProvider[]
  callbackURL?: string
  errorCallbackURL?: string
}) {
  const client = useGotAuthClient()
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState<GotAuthError | null>(null)

  async function start(provider: SocialProvider) {
    setPending(provider.id)
    setError(null)
    const result = await client.signInSocial({
      provider: provider.id,
      callback_url: callbackURL,
      error_callback_url: errorCallbackURL,
    })
    if (result.error) {
      setError(result.error)
      setPending(null)
      return
    }
    window.location.assign(result.data.url)
  }

  if (providers.length === 0) return null
  return (
    <div className="grid gap-2">
      {providers.map((provider) => (
        <Button
          key={provider.id}
          type="button"
          variant="outline"
          disabled={pending !== null}
          onClick={() => void start(provider)}
        >
          {pending === provider.id ? "Redirecting..." : `Continue with ${provider.name}`}
        </Button>
      ))}
      <FormMessage error={error} />
    </div>
  )
}
