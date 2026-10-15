"use client"

import { useRouter, useSearchParams } from "next/navigation"
import { Suspense, useState } from "react"

import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { SignInForm } from "@/components/gotauth/sign-in-form"
import { useSession } from "@/hooks/use-session"
import type { GotAuthError } from "@/lib/gotauth-client"

/** Where the invitation email links to: ?invitation_id=...&token=... */
function Accept() {
  const client = useGotAuthClient()
  const router = useRouter()
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
  if (!data) {
    return (
      <div className="grid justify-items-center gap-4">
        <p>Sign in with the email address the invitation was sent to.</p>
        {/* Signing in updates the session, and this page shows the invitation. */}
        <SignInForm />
      </div>
    )
  }

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

  return (
    <Card className="w-full max-w-sm" data-testid="invitation">
      <CardHeader>
        <CardTitle>Join an organization</CardTitle>
        <CardDescription>You were invited as {data.user.email}.</CardDescription>
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
        <FormMessage error={error} />
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
