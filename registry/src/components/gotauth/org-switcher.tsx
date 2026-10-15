"use client"

import { useEffect, useState } from "react"
import { ChevronsUpDown } from "lucide-react"

import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuRadioGroup,
  DropdownMenuRadioItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { useSession } from "@/hooks/use-session"
import type { GotAuthError, OrganizationWithRoleOut } from "@/lib/gotauth-client"

const PERSONAL = "personal"

/** Pick the organization the session acts in (the session's active organization). */
export function OrgSwitcher({
  showPersonal = true,
  onCreate,
  onSwitch,
}: {
  /** Offer "Personal account" (no active organization). */
  showPersonal?: boolean
  /** Adds a "Create organization" item that calls this. */
  onCreate?: () => void
  onSwitch?: (organizationId: string | null) => void
}) {
  const client = useGotAuthClient()
  const session = useSession()
  const [orgs, setOrgs] = useState<OrganizationWithRoleOut[] | null>(null)
  const [error, setError] = useState<GotAuthError | null>(null)
  const signedIn = Boolean(session.data)

  useEffect(() => {
    if (!signedIn) return
    let live = true
    let latest = 0
    function load() {
      // Only the newest answer counts when changes come quickly.
      const call = ++latest
      void client.organization.listOrganizations().then((result) => {
        if (!live || call !== latest) return
        if (result.error) setError(result.error)
        else setOrgs(result.data.organizations)
      })
    }
    load()
    // Creating, deleting, leaving or joining an organization notifies the client.
    const stop = client.subscribe(load)
    return () => {
      live = false
      stop()
    }
  }, [client, signedIn])

  if (!session.data) return null
  const active = session.data.session.active_organization_id
  const activeId = typeof active === "string" ? active : null
  const current = orgs?.find((org) => org.id === activeId)
  const label = current?.name ?? (activeId ? "Organization" : "Personal account")

  async function choose(value: string) {
    const organizationId = value === PERSONAL ? null : value
    if (organizationId === activeId) return
    setError(null)
    const result = await client.organization.setActiveOrganization({
      organization_id: organizationId,
    })
    if (result.error) setError(result.error)
    else onSwitch?.(organizationId)
  }

  return (
    <div className="grid gap-1">
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <Button variant="outline" className="justify-between gap-2" aria-label={`Organization: ${label}`}>
            <span className="truncate">{label}</span>
            <ChevronsUpDown className="size-4 opacity-60" aria-hidden />
          </Button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuLabel>Act as</DropdownMenuLabel>
          <DropdownMenuRadioGroup
            value={activeId ?? PERSONAL}
            onValueChange={(value) => void choose(value)}
          >
            {showPersonal ? (
              <DropdownMenuRadioItem value={PERSONAL}>Personal account</DropdownMenuRadioItem>
            ) : null}
            {(orgs ?? []).map((org) => (
              <DropdownMenuRadioItem key={org.id} value={org.id}>
                {org.name}
              </DropdownMenuRadioItem>
            ))}
          </DropdownMenuRadioGroup>
          {onCreate ? (
            <>
              <DropdownMenuSeparator />
              <DropdownMenuItem onSelect={() => onCreate()}>Create organization</DropdownMenuItem>
            </>
          ) : null}
        </DropdownMenuContent>
      </DropdownMenu>
      {error ? <FormMessage error={error} /> : null}
    </div>
  )
}
