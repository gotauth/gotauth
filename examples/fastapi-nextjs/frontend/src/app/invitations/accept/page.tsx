"use client"

import { usePathname, useRouter, useSearchParams } from "next/navigation"
import { Suspense, useState } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { PasskeyButton } from "@/components/gotauth/passkey-button"
import { SignInForm } from "@/components/gotauth/sign-in-form"
import { SignUpForm } from "@/components/gotauth/sign-up-form"
import { useSession } from "@/hooks/use-session"
import { useAppConfig } from "@/lib/app-config"
import type { GotAuthError } from "@/lib/gotauth-client"

/** Signed out: sign in, or create the account first. Every way back lands here. */
function SignInFirst({ here }: { here: string }) {
  const config = useAppConfig()
  const [creating, setCreating] = useState(false)
  if (!config) return null
  return (
    <div className="grid justify-items-center gap-4">
      <p>Sign in with the email address the invitation was sent to.</p>
      {creating ? (
        // The verification email links back to this page.
        <SignUpForm callbackURL={here} />
      ) : (
        <>
          {/* Signing in updates the session, and this page then shows the invitation. */}
          <SignInForm socialProviders={config.social_providers} callbackURL={here} />
          <div className="w-full max-w-sm">
            <PasskeyButton />
          </div>
        </>
      )}
      <Button variant="link" onClick={() => setCreating(!creating)}>
        {creating ? "I have an account: sign in" : "No account yet? Create one"}
      </Button>
    </div>
  )
}

/** Where the invitation email links to: ?invitation_id=...&token=... */
function Accept() {
  const client = useGotAuthClient()
  const router = useRouter()
  const pathname = usePathname()
  const params = useSearchParams()
  const { data, isPending } = useSession()
  const [error, setError] = useState<GotAuthError | null>(null)
  const [pending, setPending] = useState(false)
  const [declined, setDeclined] = useState(false)
  const invitation = {
    invitation_id: params.get("invitation_id") ?? "",
    token: params.get("token") ?? "",
  }

  if (!invitation.invitation_id || !invitation.token) {
    return <p role="alert">This invitation link is incomplete. Open it from the email again.</p>
  }
  if (isPending) return null
  if (!data) return <SignInFirst here={`${pathname}?${params.toString()}`} />

  async function accept() {
    setPending(true)
    setError(null)
    const joined = await client.organization.acceptInvitation(invitation)
    if (joined.error) {
      setPending(false)
      setError(joined.error)
      return
    }
    await client.organization.setActiveOrganization({
      organization_id: joined.data.organization_id,
    })
    router.push("/organizations")
  }

  async function decline() {
    setPending(true)
    setError(null)
    const result = await client.organization.rejectInvitation(invitation)
    setPending(false)
    if (result.error) setError(result.error)
    else setDeclined(true)
  }

  // The server only accepts an invitation for the signed-in email, and says nothing
  // more, so the page names the likely causes.
  const wrongAccount =
    error?.code === "ORG_INVITATION_INVALID"
      ? `This invitation can't be used by ${data.user.email}. It may be for another email address (sign out and sign in with that one), or it has expired or been used.`
      : null

  return (
    <Card className="w-full max-w-sm" data-testid="invitation">
      <CardHeader>
        <CardTitle>Join an organization</CardTitle>
        <CardDescription>
          Signed in as {data.user.email}. The invitation must be for this address.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {declined ? (
          <p>You declined the invitation.</p>
        ) : (
          <div className="flex gap-2">
            <Button variant="outline" disabled={pending} onClick={() => void decline()}>
              Decline
            </Button>
            <Button disabled={pending} onClick={() => void accept()}>
              Join
            </Button>
          </div>
        )}
        <FormMessage error={wrongAccount ? null : error} message={wrongAccount} />
      </CardContent>
    </Card>
  )
}

export default function AcceptInvitationPage() {
  // useSearchParams needs a Suspense boundary in a statically built page.
  return (
    <section className="grid justify-items-center">
      <Suspense fallback={null}>
        <Accept />
      </Suspense>
    </section>
  )
}
