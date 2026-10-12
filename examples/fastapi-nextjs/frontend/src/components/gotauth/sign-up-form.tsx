"use client"

import { useId, useState, type FormEvent } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { SocialButtons, type SocialProvider } from "@/components/gotauth/social-buttons"
import {
  isChallenge,
  type GotAuthError,
  type SignInChallenge,
  type SignInOut,
} from "@/lib/gotauth-client"

// The same text whether or not the address already had an account, so the form never
// reveals who has signed up.
const CHECK_EMAIL = "Check your email for a link to finish signing up."

/** Email and password sign-up, with optional social buttons. */
export function SignUpForm({
  onSuccess,
  onChallenge,
  socialProviders = [],
  callbackURL,
  minPasswordLength = 8,
}: {
  onSuccess?: (result: SignInOut) => void
  onChallenge?: (challenge: SignInChallenge) => void
  socialProviders?: SocialProvider[]
  callbackURL?: string
  minPasswordLength?: number
}) {
  const client = useGotAuthClient()
  const id = useId()
  const [pending, setPending] = useState(false)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [done, setDone] = useState<string | null>(null)

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const form = new FormData(event.currentTarget)
    const name = String(form.get("name") ?? "").trim()
    setPending(true)
    setError(null)
    const result = await client.signUpEmail({
      email: String(form.get("email") ?? ""),
      password: String(form.get("password") ?? ""),
      ...(name ? { name } : {}),
      ...(callbackURL ? { callback_url: callbackURL } : {}),
    })
    setPending(false)
    if (result.error) {
      setError(result.error)
      return
    }
    if ("status" in result.data) {
      setDone(result.data.status === "verification_sent" ? CHECK_EMAIL : "You're signed up.")
      return
    }
    if (isChallenge(result.data)) {
      onChallenge?.(result.data.challenge)
      return
    }
    onSuccess?.(result.data)
  }

  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>Create an account</CardTitle>
        <CardDescription>Sign up with your email address.</CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {done ? (
          <FormMessage message={done} />
        ) : (
          <form className="grid gap-4" onSubmit={(event) => void submit(event)} noValidate>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-name`}>Name (optional)</Label>
              <Input id={`${id}-name`} name="name" autoComplete="name" />
            </div>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-email`}>Email</Label>
              <Input id={`${id}-email`} name="email" type="email" autoComplete="email" required />
            </div>
            <div className="grid gap-2">
              <Label htmlFor={`${id}-password`}>Password</Label>
              <Input
                id={`${id}-password`}
                name="password"
                type="password"
                autoComplete="new-password"
                minLength={minPasswordLength}
                aria-describedby={`${id}-password-hint`}
                required
              />
              <p id={`${id}-password-hint`} className="text-muted-foreground text-sm">
                At least {minPasswordLength} characters.
              </p>
            </div>
            <FormMessage error={error} />
            <Button type="submit" disabled={pending}>
              {pending ? "Creating account..." : "Create account"}
            </Button>
          </form>
        )}
        {done ? null : <SocialButtons providers={socialProviders} callbackURL={callbackURL} />}
      </CardContent>
    </Card>
  )
}
