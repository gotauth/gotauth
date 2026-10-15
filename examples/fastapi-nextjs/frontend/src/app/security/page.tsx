"use client"

import Link from "next/link"
import { useCallback, useEffect, useState } from "react"

import { Button } from "@/components/ui/button"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { PasskeyButton } from "@/components/gotauth/passkey-button"
import { TwoFactorSetup } from "@/components/gotauth/two-factor-setup"
import { useSession } from "@/hooks/use-session"
import type { GotAuthError, PasskeyOut } from "@/lib/gotauth-client"

function Passkeys() {
  const client = useGotAuthClient()
  const [passkeys, setPasskeys] = useState<PasskeyOut[] | null>(null)
  const [error, setError] = useState<GotAuthError | null>(null)

  const load = useCallback(async () => {
    const result = await client.passkey.listPasskeys()
    if (result.error) setError(result.error)
    else setPasskeys(result.data.passkeys)
  }, [client])

  useEffect(() => {
    let live = true
    void client.passkey.listPasskeys().then((result) => {
      if (!live) return
      if (result.error) setError(result.error)
      else setPasskeys(result.data.passkeys)
    })
    return () => {
      live = false
    }
  }, [client])

  async function remove(passkey: PasskeyOut) {
    setError(null)
    const result = await client.passkey.deletePasskey(passkey.id)
    if (result.error) setError(result.error)
    else await load()
  }

  return (
    <section className="grid gap-3">
      <h2 className="text-lg font-semibold">Passkeys</h2>
      <p className="text-muted-foreground text-sm">
        Sign in with your fingerprint, face or device PIN instead of a password.
      </p>
      {passkeys && passkeys.length > 0 ? (
        <ul className="grid gap-2" data-testid="passkeys">
          {passkeys.map((passkey) => (
            <li key={passkey.id} className="flex items-center justify-between rounded-md border px-4 py-2">
              <span>{passkey.name ?? "Passkey"}</span>
              <Button
                variant="outline"
                size="sm"
                onClick={() => void remove(passkey)}
                aria-label={`Remove passkey ${passkey.name ?? passkey.id}`}
              >
                Remove
              </Button>
            </li>
          ))}
        </ul>
      ) : passkeys ? (
        <p className="text-sm">No passkeys yet.</p>
      ) : null}
      <div className="max-w-sm">
        <PasskeyButton mode="register" name="This device" onRegistered={() => void load()} />
      </div>
      <FormMessage error={error} />
    </section>
  )
}

export default function SecurityPage() {
  const client = useGotAuthClient()
  const { data, isPending } = useSession()
  // Users who only sign in with GitHub have no password to confirm with.
  const [hasPassword, setHasPassword] = useState<boolean | null>(null)
  const signedIn = Boolean(data)

  useEffect(() => {
    if (!signedIn) return
    let live = true
    void client.listAccounts().then((result) => {
      if (live) {
        setHasPassword(
          result.error ? true : result.data.accounts.some((a) => a.provider_id === "credential"),
        )
      }
    })
    return () => {
      live = false
    }
  }, [client, signedIn])

  if (isPending) return null
  if (!data) {
    return (
      <p>
        <Link href="/sign-in" className="underline">Sign in</Link> to manage your security
        settings.
      </p>
    )
  }
  return (
    <section className="grid gap-8">
      <h1 className="text-2xl font-semibold">Security</h1>
      {hasPassword === null ? null : <TwoFactorSetup hasPassword={hasPassword} />}
      <Passkeys />
    </section>
  )
}
