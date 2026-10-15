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
  | { name: "done" }

function secretOf(totpURI: string): string {
  try {
    return new URL(totpURI).searchParams.get("secret") ?? ""
  } catch {
    return ""
  }
}

function BackupCodes({ codes }: { codes: string[] }) {
  const [copied, setCopied] = useState<"yes" | "failed" | null>(null)
  async function copy() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"))
      setCopied("yes")
    } catch {
      setCopied("failed")
    }
  }
  return (
    <div className="grid gap-2">
      <Alert>
        <AlertTitle>Your backup codes</AlertTitle>
        <AlertDescription>
          Each code signs you in once if you lose your phone. They are shown only now: save
          them somewhere safe.
        </AlertDescription>
      </Alert>
      <ul className="grid grid-cols-2 gap-1 font-mono text-sm" data-testid="backup-codes">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <Button type="button" variant="outline" onClick={() => void copy()}>
        {copied === "yes" ? "Copied" : "Copy codes"}
      </Button>
      <FormMessage
        message={copied === "failed" ? "Copying didn't work. Select the codes and copy them yourself." : null}
      />
    </div>
  )
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
    setNotice(null)
    const result = await client.twoFactor.enableTwoFactor(duringSignIn ? {} : password(form))
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    setStep({ name: "scan", totpURI: result.data.totp_uri, backupCodes: result.data.backup_codes })
  }

  async function confirm(event: FormEvent<HTMLFormElement>) {
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
    // The backup codes were shown (and saved) before this point, so they are dropped.
    if ("session" in result.data) {
      setStep({ name: "done" })
      onSignIn?.(result.data)
    } else {
      setStep({ name: "start" })
      setNotice("Two-factor authentication is on.")
      onChange?.(true)
    }
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
    setNotice(null)
    const result = await client.twoFactor.regenerateBackupCodes()
    setPending(false)
    if (result.error) setError(result.error)
    else setStep({ name: "codes", backupCodes: result.data.backup_codes })
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
      <form className="grid gap-4" onSubmit={(event) => void confirm(event)}>
        <p className="text-sm">
          1. Scan this code with your authenticator app.
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
        <p className="text-sm">2. Save your backup codes.</p>
        <BackupCodes codes={step.backupCodes} />
        <div className="flex items-center gap-2">
          <input id={`${id}-saved`} name="saved" type="checkbox" required className="size-4" />
          <Label htmlFor={`${id}-saved`}>I saved my backup codes</Label>
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-code`}>3. Enter the code from the app</Label>
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
        <BackupCodes codes={step.backupCodes} />
        <Button onClick={() => setStep({ name: "start" })}>Done</Button>
      </div>
    )
  } else if (step.name === "done") {
    content = <p className="text-sm">Two-factor authentication is on.</p>
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
