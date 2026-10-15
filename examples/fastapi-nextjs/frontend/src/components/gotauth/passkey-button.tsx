"use client"

import { useState, useSyncExternalStore, type ReactNode } from "react"

import { Button } from "@/components/ui/button"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import {
  isChallenge,
  type GotAuthError,
  type PasskeyOut,
  type SignInChallenge,
  type SignInOut,
} from "@/lib/gotauth-client"
import { creationOptionsFromJSON, credentialToJSON, requestOptionsFromJSON } from "@/lib/webauthn"

type CreationJSON = Parameters<typeof creationOptionsFromJSON>[0]
type RequestJSON = Parameters<typeof requestOptionsFromJSON>[0]

const noop = () => () => {}
function supported(): boolean {
  return typeof window !== "undefined" && typeof window.PublicKeyCredential === "function"
}

function cancelled(cause: unknown): boolean {
  // The user closed the browser's passkey prompt, or it timed out.
  return cause instanceof DOMException && (cause.name === "NotAllowedError" || cause.name === "AbortError")
}

/** Sign in with a passkey (no email needed), or add one to the signed-in account. */
export function PasskeyButton({
  mode = "sign-in",
  name,
  rememberMe = true,
  onSuccess,
  onChallenge,
  onRegistered,
  children,
}: {
  mode?: "sign-in" | "register"
  /** A name for the new passkey (register), e.g. "MacBook". */
  name?: string
  rememberMe?: boolean
  onSuccess?: (result: SignInOut) => void
  onChallenge?: (challenge: SignInChallenge) => void
  onRegistered?: (passkey: PasskeyOut) => void
  children?: ReactNode
}) {
  const client = useGotAuthClient()
  // false on the server and in browsers without WebAuthn.
  const available = useSyncExternalStore(noop, supported, () => false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  function fail(cause: unknown) {
    setNotice(
      cancelled(cause)
        ? "The passkey prompt was closed. Try again when you're ready."
        : "Your browser couldn't use a passkey. Try again or use another way.",
    )
  }

  async function signIn() {
    const options = await client.passkey.getPasskeySignInOptions()
    if (options.error) {
      setError(options.error)
      return
    }
    let credential: Credential | null
    try {
      credential = await navigator.credentials.get({
        publicKey: requestOptionsFromJSON(options.data as RequestJSON),
      })
    } catch (cause) {
      fail(cause)
      return
    }
    if (!credential) return
    const result = await client.passkey.signInPasskey({
      response: credentialToJSON(credential as PublicKeyCredential) as Record<string, unknown>,
      remember_me: rememberMe,
    })
    if (result.error) setError(result.error)
    else if (isChallenge(result.data)) onChallenge?.(result.data.challenge)
    else onSuccess?.(result.data)
  }

  async function register() {
    const options = await client.passkey.getPasskeyRegistrationOptions()
    if (options.error) {
      setError(options.error)
      return
    }
    let credential: Credential | null
    try {
      credential = await navigator.credentials.create({
        publicKey: creationOptionsFromJSON(options.data as unknown as CreationJSON),
      })
    } catch (cause) {
      fail(cause)
      return
    }
    if (!credential) return
    const result = await client.passkey.verifyPasskeyRegistration({
      response: credentialToJSON(credential as PublicKeyCredential) as Record<string, unknown>,
      ...(name ? { name } : {}),
    })
    if (result.error) {
      setError(result.error)
      return
    }
    setNotice("Passkey added.")
    onRegistered?.(result.data)
  }

  async function run() {
    setPending(true)
    setError(null)
    setNotice(null)
    try {
      await (mode === "register" ? register() : signIn())
    } finally {
      setPending(false)
    }
  }

  return (
    <div className="grid gap-2">
      <Button
        type="button"
        variant="outline"
        disabled={!available || pending}
        onClick={() => void run()}
      >
        {children ?? (mode === "register" ? "Add a passkey" : "Sign in with a passkey")}
      </Button>
      <FormMessage
        error={error}
        message={available ? notice : "This browser doesn't support passkeys."}
      />
    </div>
  )
}
