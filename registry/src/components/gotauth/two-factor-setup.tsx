"use client"

import { useId, useState, type FormEvent } from "react"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { QrCode } from "@/components/gotauth/qr-code"
import { useSession } from "@/hooks/use-session"
import type { GotAuthError, SignInOut } from "@/lib/gotauth-client"

type Step =
  | { name: "start" }
  | { name: "scan"; totpURI: string; backupCodes: string[] }
  | { name: "codes"; backupCodes: string[] }

function secretOf(totpURI: string): string {
  try {
    return new URL(totpURI).searchParams.get("secret") ?? ""
  } catch {
    return ""
  }
}

/** Turn two-factor authentication on (authenticator app + backup codes) or off.
 *
 * During a sign-in that requires setup (challenge type "two_factor_setup"), pass
 * `duringSignIn`: no password is asked and the confirming code finishes the sign-in. */
export function TwoFactorSetup({
  hasPassword = true,
  duringSignIn = false,
  onSignIn,
  onChange,
}: {
  /** Ask for the password first; false for users who sign in without one. */
  hasPassword?: boolean
  duringSignIn?: boolean
  /** Called when the confirming code finishes a sign-in (duringSignIn). */
  onSignIn?: (result: SignInOut) => void
  /** Called after two-factor is turned on or off. */
  onChange?: (enabled: boolean) => void
}) {
  const client = useGotAuthClient()
  const session = useSession()
  const id = useId()
  const [step, setStep] = useState<Step>({ name: "start" })
  const [error, setError] = useState<GotAuthError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)
  const [pending, setPending] = useState(false)
  const [copied, setCopied] = useState(false)
  const enabled = !duringSignIn && session.data?.user.two_factor_enabled === true

  function password(form: FormData): { password?: string } {
    const value = String(form.get("password") ?? "")
    return value ? { password: value } : {}
  }

  async function start(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setPending(true)
    setError(null)
    const result = await client.twoFactor.enableTwoFactor(duringSignIn ? {} : password(form))
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    setStep({ name: "scan", totpURI: result.data.totp_uri, backupCodes: result.data.backup_codes })
  }

  async function confirm(event: FormEvent<HTMLFormElement>, backupCodes: string[]) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setPending(true)
    setError(null)
    const result = await client.twoFactor.verifyTotp({ code: String(form.get("code") ?? "").trim() })
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    setStep({ name: "codes", backupCodes })
    if ("session" in result.data) onSignIn?.(result.data)
    else onChange?.(true)
  }

  async function turnOff(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setPending(true)
    setError(null)
    const result = await client.twoFactor.disableTwoFactor(password(form))
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    setNotice("Two-factor authentication is off.")
    onChange?.(false)
  }

  async function newCodes() {
    setPending(true)
    setError(null)
    const result = await client.twoFactor.regenerateBackupCodes()
    setPending(false)
    if (result.error) setError(result.error)
    else setStep({ name: "codes", backupCodes: result.data.backup_codes })
  }

  async function copy(codes: string[]) {
    try {
      await navigator.clipboard.writeText(codes.join("\n"))
      setCopied(true)
    } catch {
      setNotice("Copying didn't work. Select the codes and copy them yourself.")
    }
  }

  function done() {
    // The codes are dropped here: they are shown once.
    setStep({ name: "start" })
    setCopied(false)
    setNotice(null)
  }

  const passwordField =
    hasPassword && !duringSignIn ? (
      <div className="grid gap-2">
        <Label htmlFor={`${id}-password`}>Password</Label>
        <Input
          id={`${id}-password`}
          name="password"
          type="password"
          autoComplete="current-password"
          required
        />
      </div>
    ) : null

  let content
  if (step.name === "scan") {
    const secret = secretOf(step.totpURI)
    content = (
      <form className="grid gap-4" onSubmit={(event) => void confirm(event, step.backupCodes)}>
        <p className="text-sm">
          Scan this code with your authenticator app, then enter the 6-digit code it shows.
        </p>
        <div className="flex justify-center">
          <QrCode value={step.totpURI} label="QR code for your authenticator app" />
        </div>
        {secret ? (
          <p className="text-muted-foreground text-sm">
            Can't scan it? Enter this key instead:{" "}
            <code className="break-all" data-testid="totp-secret">
              {secret}
            </code>
          </p>
        ) : null}
        <div className="grid gap-2">
          <Label htmlFor={`${id}-code`}>Code from the app</Label>
          <Input
            id={`${id}-code`}
            name="code"
            inputMode="numeric"
            autoComplete="one-time-code"
            pattern="[0-9]{6}"
            maxLength={6}
            required
          />
        </div>
        <FormMessage error={error} />
        <Button type="submit" disabled={pending}>
          {pending ? "Checking..." : "Turn on"}
        </Button>
      </form>
    )
  } else if (step.name === "codes") {
    content = (
      <div className="grid gap-4">
        <Alert>
          <AlertTitle>Save your backup codes</AlertTitle>
          <AlertDescription>
            Each code signs you in once if you lose your phone. They are shown only now.
          </AlertDescription>
        </Alert>
        <ul className="grid grid-cols-2 gap-1 font-mono text-sm" data-testid="backup-codes">
          {step.backupCodes.map((code) => (
            <li key={code}>{code}</li>
          ))}
        </ul>
        <FormMessage message={notice} />
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void copy(step.backupCodes)}>
            {copied ? "Copied" : "Copy codes"}
          </Button>
          <Button onClick={done}>Done</Button>
        </div>
      </div>
    )
  } else if (enabled) {
    content = (
      <div className="grid gap-4">
        <p className="text-sm">Two-factor authentication is on.</p>
        <Button variant="outline" disabled={pending} onClick={() => void newCodes()}>
          Get new backup codes
        </Button>
        <form className="grid gap-4" onSubmit={(event) => void turnOff(event)}>
          {passwordField}
          <FormMessage error={error} message={notice} />
          <Button type="submit" variant="destructive" disabled={pending}>
            Turn off two-factor
          </Button>
        </form>
      </div>
    )
  } else {
    content = (
      <form className="grid gap-4" onSubmit={(event) => void start(event)}>
        <p className="text-sm">
          {duringSignIn
            ? "Your account needs a second step at sign-in. Set up an authenticator app to continue."
            : "Add a second step at sign-in with an authenticator app."}
        </p>
        {passwordField}
        <FormMessage error={error} message={notice} />
        <Button type="submit" disabled={pending}>
          {pending ? "Starting..." : "Set up"}
        </Button>
      </form>
    )
  }

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Two-factor authentication</CardTitle>
        <CardDescription>Protect your account with a code from your phone.</CardDescription>
      </CardHeader>
      <CardContent>{content}</CardContent>
    </Card>
  )
}
