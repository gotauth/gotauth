"use client"

import { useId, useState, type FormEvent } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { TwoFactorSetup } from "@/components/gotauth/two-factor-setup"
import type { GotAuthError, SignInChallenge, SignInOut } from "@/lib/gotauth-client"

type Method = "totp" | "backup_code" | "email_otp"

const LABELS: Record<Method, { field: string; switchTo: string; help: string }> = {
  totp: {
    field: "Code from your authenticator app",
    switchTo: "Use your authenticator app",
    help: "Open your authenticator app and enter the 6-digit code.",
  },
  backup_code: {
    field: "Backup code",
    switchTo: "Use a backup code",
    help: "Enter one of the backup codes you saved. Each works once.",
  },
  email_otp: {
    field: "Code from your email",
    switchTo: "Email me a code",
    help: "We send a 6-digit code to your email address.",
  },
}

/** The second sign-in step, after SignInForm (or another method) got a challenge. */
export function TwoFactorChallenge({
  challenge,
  onSuccess,
  onCancel,
}: {
  challenge: SignInChallenge
  onSuccess?: (result: SignInOut) => void
  /** Adds "Sign in again", for example when the step has expired (10 minutes). */
  onCancel?: () => void
}) {
  const client = useGotAuthClient()
  const id = useId()
  const methods = challenge.methods.filter((m): m is Method => m in LABELS)
  const [method, setMethod] = useState<Method>(methods[0] ?? "totp")
  const [sent, setSent] = useState(false)
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const back = onCancel ? (
    <Button variant="link" type="button" onClick={onCancel}>
      Sign in again
    </Button>
  ) : null

  if (challenge.type === "two_factor_setup") {
    return (
      <div className="grid gap-2">
        <TwoFactorSetup duringSignIn onSignIn={onSuccess} />
        {back}
      </div>
    )
  }

  async function send() {
    setPending(true)
    setError(null)
    const result = await client.twoFactor.sendTwoFactorOtp()
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    setSent(true)
    setNotice("We sent a code to your email. It works for 5 minutes.")
  }

  async function verify(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const body = {
      code: String(form.get("code") ?? "").trim(),
      trust_device: form.get("trust_device") === "on",
    }
    setPending(true)
    setError(null)
    const result =
      method === "totp"
        ? await client.twoFactor.verifyTotp(body)
        : method === "backup_code"
          ? await client.twoFactor.verifyBackupCode(body)
          : await client.twoFactor.verifyTwoFactorOtp(body)
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    if ("session" in result.data) onSuccess?.(result.data)
  }

  function switchTo(next: Method) {
    setMethod(next)
    setError(null)
    setNotice(null)
    setSent(false)
  }

  const needsSend = method === "email_otp" && !sent
  const numeric = method !== "backup_code"
  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Confirm it's you</CardTitle>
        <CardDescription>{LABELS[method].help}</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {needsSend ? (
          <div className="grid gap-4">
            <FormMessage error={error} />
            <Button onClick={() => void send()} disabled={pending}>
              {pending ? "Sending..." : "Send code"}
            </Button>
          </div>
        ) : (
          <form className="grid gap-4" onSubmit={(event) => void verify(event)}>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-code`}>{LABELS[method].field}</Label>
              <Input
                key={method}
                id={`${id}-code`}
                name="code"
                autoComplete="one-time-code"
                inputMode={numeric ? "numeric" : "text"}
                autoCapitalize="off"
                spellCheck={false}
                required
                autoFocus
              />
            </div>
            <div className="flex items-center gap-2">
              <input id={`${id}-trust`} name="trust_device" type="checkbox" className="size-4" />
              <Label htmlFor={`${id}-trust`}>Don't ask again on this device</Label>
            </div>
            <FormMessage error={error} message={notice} />
            <Button type="submit" disabled={pending}>
              {pending ? "Checking..." : "Continue"}
            </Button>
            {method === "email_otp" ? (
              <Button variant="link" type="button" disabled={pending} onClick={() => void send()}>
                Send a new code
              </Button>
            ) : null}
          </form>
        )}
        {methods.length > 1 ? (
          <div className="grid gap-1">
            {methods
              .filter((other) => other !== method)
              .map((other) => (
                <Button key={other} variant="link" type="button" onClick={() => switchTo(other)}>
                  {LABELS[other].switchTo}
                </Button>
              ))}
          </div>
        ) : null}
        {back}
      </CardContent>
    </Card>
  )
}
