"use client"

import { useCallback, useEffect, useState } from "react"

import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCaption,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import type { GotAuthError, OAuthGrantListOut, OAuthGrantOut, Result } from "@/lib/gotauth-client"

/** Apps the user has let into their account through OAuth (for example MCP clients),
 * with a way to revoke each. Revoking stops its tokens at once. */
export function ConnectedApps() {
  const client = useGotAuthClient()
  const [grants, setGrants] = useState<OAuthGrantOut[] | null>(null)
  const [error, setError] = useState<GotAuthError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const show = useCallback((result: Result<OAuthGrantListOut>) => {
    if (result.error) setError(result.error)
    else setGrants(result.data.grants)
  }, [])

  useEffect(() => {
    let live = true
    void client.oauth2.listOauthGrants().then((result) => {
      if (live) show(result)
    })
    return () => {
      live = false
    }
  }, [client, show])

  async function revoke(grant: OAuthGrantOut) {
    setError(null)
    setNotice(null)
    const result = await client.oauth2.revokeOauthGrant({ client_id: grant.client_id })
    if (result.error) {
      setError(result.error)
      return
    }
    setNotice(`${grant.client_name} no longer has access.`)
    show(await client.oauth2.listOauthGrants())
  }

  return (
    <div className="grid gap-4">
      <h2 className="text-lg font-semibold">Connected apps</h2>
      {grants && grants.length > 0 ? (
        <Table>
          <TableCaption>Apps that can use your account</TableCaption>
          <TableHeader>
            <TableRow>
              <TableHead>App</TableHead>
              <TableHead>Access</TableHead>
              <TableHead>Last used</TableHead>
              <TableHead>
                <span className="sr-only">Actions</span>
              </TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {grants.map((grant) => (
              <TableRow key={grant.client_id}>
                <TableCell>{grant.client_name}</TableCell>
                <TableCell>
                  {grant.scopes.join(", ") || "Basic access"}
                  {grant.resources.length > 0 ? (
                    <span className="text-muted-foreground block text-xs">
                      {grant.resources.join(", ")}
                    </span>
                  ) : null}
                </TableCell>
                <TableCell>
                  {grant.last_used_at ? new Date(grant.last_used_at).toLocaleString() : "Never"}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void revoke(grant)}
                    aria-label={`Revoke access for ${grant.client_name}`}
                  >
                    Revoke
                  </Button>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      ) : grants ? (
        <p className="text-muted-foreground text-sm">No apps are connected.</p>
      ) : null}
      <FormMessage error={error} message={notice} />
    </div>
  )
}
