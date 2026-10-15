"use client"

import { useId, useState, type FormEvent } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { SocialButtons, type SocialProvider } from "@/components/gotauth/social-buttons"
import { TwoFactorChallenge } from "@/components/gotauth/two-factor-challenge"
import {
  isChallenge,
  type GotAuthError,
  type SignInChallenge,
  type SignInOut,
} from "@/lib/gotauth-client"

/** Email and password sign-in, with optional social buttons. */
export function SignInForm({
  onSuccess,
  onChallenge,
  socialProviders = [],
  callbackURL,
  forgotPasswordHref,
}: {
  onSuccess?: (result: SignInOut) => void
  /** Called when the sign-in needs another step, for example two-factor. Without
   * it, the form shows TwoFactorChallenge itself. */
  onChallenge?: (challenge: SignInChallenge) => void
  socialProviders?: SocialProvider[]
  callbackURL?: string
  forgotPasswordHref?: string
}) {
  const client = useGotAuthClient()
  const id = useId()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [challenge, setChallenge] = useState<SignInChallenge | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    setPending(true)
    setError(null)
    const result = await client.signInEmail({
      email: String(form.get("email") ?? ""),
      password: String(form.get("password") ?? ""),
      remember_me: form.get("remember_me") === "on",
    })
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    if (isChallenge(result.data)) {
      if (onChallenge) onChallenge(result.data.challenge)
      else setChallenge(result.data.challenge)
      return
    }
    onSuccess?.(result.data)
  }

  if (challenge) {
    return (
      <TwoFactorChallenge
        challenge={challenge}
        onSuccess={onSuccess}
        onCancel={() => setChallenge(null)}
      />
    )
  }

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Sign in</CardTitle>
        <CardDescription>Enter your email and password.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        <form className="grid gap-4" onSubmit={(event) => void submit(event)} noValidate>
          <div className="grid gap-2">
            <Label htmlFor={`${id}-email`}>Email</Label>
            <Input id={`${id}-email`} name="email" type="email" autoComplete="email" required />
          </div>
          <div className="grid gap-2">
            <div className="flex items-center justify-between">
              <Label htmlFor={`${id}-password`}>Password</Label>
              {forgotPasswordHref ? (
                <a href={forgotPasswordHref} className="text-sm underline-offset-4 hover:underline">
                  Forgot password?
                </a>
              ) : null}
            </div>
            <Input
              id={`${id}-password`}
              name="password"
              type="password"
              autoComplete="current-password"
              required
            />
          </div>
          <div className="flex items-center gap-2">
            <input
              id={`${id}-remember`}
              name="remember_me"
              type="checkbox"
              defaultChecked
              className="size-4"
            />
            <Label htmlFor={`${id}-remember`}>Keep me signed in</Label>
          </div>
          <FormMessage error={error} />
          <Button type="submit" disabled={pending}>
            {pending ? "Signing in..." : "Sign in"}
          </Button>
        </form>
        <SocialButtons providers={socialProviders} callbackURL={callbackURL} />
      </CardContent>
    </Card>
  )
}
