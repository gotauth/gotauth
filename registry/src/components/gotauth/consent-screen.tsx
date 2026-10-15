"use client"

import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert"
import { Button } from "@/components/ui/button"
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import type { OAuthConsentOut } from "@/lib/gotauth-client"

/** The OAuth consent screen for an app (for example an MCP client) asking for access.
 *
 * Get `consent` from `client.oauth2.oauthAuthorize(query)` (see `isConsent`). The
 * buttons submit a native form POST, so the browser follows GotAuth's redirect back
 * to the app; no fetch is involved. */
export function ConsentScreen({
  consent,
  scopeDescriptions = {},
}: {
  consent: OAuthConsentOut
  /** Readable text per scope, e.g. { "projects:read": "See your projects" }. */
  scopeDescriptions?: Record<string, string>
}) {
  const client = useGotAuthClient()
  const { name, host } = consent.client
  return (
    <Card className="w-full max-w-md">
      <CardHeader>
        <CardTitle>Allow {name} to access your account?</CardTitle>
        <CardDescription>
          {host ? (
            <>
              Client details come from <strong>{host}</strong>.{" "}
            </>
          ) : null}
          You will be sent back to <strong data-testid="redirect-host">{consent.redirect_host}</strong>.
        </CardDescription>
      </CardHeader>
      <CardContent className="grid gap-4">
        {consent.loopback_only ? (
          <Alert variant="destructive" data-testid="loopback-warning">
            <AlertTitle>Only continue if you started this</AlertTitle>
            <AlertDescription>
              This app only uses local addresses, so any program on your computer could be
              asking. Continue only if you just started this sign-in yourself.
            </AlertDescription>
          </Alert>
        ) : null}
        <div className="grid gap-2">
          <p className="text-sm font-medium">It will be able to:</p>
          <ul className="list-disc pl-5 text-sm">
            {consent.scopes.length > 0 ? (
              consent.scopes.map((scope) => (
                <li key={scope}>
                  {scopeDescriptions[scope] ?? <code>{scope}</code>}
                </li>
              ))
            ) : (
              <li>Basic access</li>
            )}
          </ul>
          {consent.resource ? (
            <p className="text-muted-foreground text-sm">
              Access is for <code>{consent.resource}</code>.
            </p>
          ) : null}
        </div>
      </CardContent>
      <CardFooter>
        <form method="post" action={client.oauth2.consentURL} className="flex w-full gap-2">
          <input type="hidden" name="consent_id" value={consent.consent_id} />
          <Button type="submit" name="accept" value="false" variant="outline" className="flex-1">
            Deny
          </Button>
          <Button type="submit" name="accept" value="true" className="flex-1">
            Allow
          </Button>
        </form>
      </CardFooter>
    </Card>
  )
}
