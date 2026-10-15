"use client"

import Link from "next/link"
import { useCallback, useEffect, useId, useState, type FormEvent } from "react"

import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { FormMessage } from "@/components/gotauth/form-message"
import { useSession } from "@/hooks/use-session"
import type { FullOrganizationOut, GotAuthError, InvitationOut } from "@/lib/gotauth-client"

function slugify(name: string): string {
  return name
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 48)
}

/** Create an organization; it becomes the one this session acts in. */
function CreateOrganization() {
  const client = useGotAuthClient()
  const id = useId()
  const [error, setError] = useState<GotAuthError | null>(null)
  const [pending, setPending] = useState(false)

  async function create(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    const name = String(form.get("name") ?? "").trim()
    setPending(true)
    setError(null)
    const created = await client.organization.createOrganization({ name, slug: slugify(name) })
    if (created.error) {
      setPending(false)
      setError(created.error)
      return
    }
    const active = await client.organization.setActiveOrganization({
      organization_id: created.data.id,
    })
    setPending(false)
    if (active.error) setError(active.error)
    else formElement.reset()
  }

  return (
    <form className="grid max-w-sm gap-3" onSubmit={(event) => void create(event)}>
      <h2 className="text-lg font-semibold">Create an organization</h2>
      <div className="grid gap-2">
        <Label htmlFor={`${id}-name`}>Name</Label>
        <Input id={`${id}-name`} name="name" required minLength={3} maxLength={48} />
      </div>
      <FormMessage error={error} />
      <Button type="submit" disabled={pending}>
        {pending ? "Creating..." : "Create organization"}
      </Button>
    </form>
  )
}

/** Members, pending invitations and an invite form for the active organization. */
function ActiveOrganization({ organizationId }: { organizationId: string }) {
  const client = useGotAuthClient()
  const id = useId()
  const [org, setOrg] = useState<FullOrganizationOut | null>(null)
  const [invitations, setInvitations] = useState<InvitationOut[]>([])
  const [error, setError] = useState<GotAuthError | null>(null)
  const [notice, setNotice] = useState<string | null>(null)

  const fetchAll = useCallback(
    () =>
      Promise.all([
        client.organization.getOrganization({ organization_id: organizationId }),
        client.organization.listInvitations({ organization_id: organizationId }),
      ]),
    [client, organizationId],
  )

  const show = useCallback(
    ([full, pending]: Awaited<ReturnType<typeof fetchAll>>) => {
      if (full.error) setError(full.error)
      else setOrg(full.data)
      // Members without the right to invite can't list invitations: show none.
      setInvitations(pending.error ? [] : pending.data.invitations)
    },
    [],
  )

  useEffect(() => {
    let live = true
    void fetchAll().then((results) => {
      if (live) show(results)
    })
    return () => {
      live = false
    }
  }, [fetchAll, show])

  async function invite(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const formElement = event.currentTarget
    const form = new FormData(formElement)
    setError(null)
    setNotice(null)
    const email = String(form.get("email") ?? "")
    const result = await client.organization.inviteMember({
      email,
      role: String(form.get("role") ?? "member"),
      organization_id: organizationId,
    })
    if (result.error) {
      setError(result.error)
      return
    }
    formElement.reset()
    setNotice(`Invitation sent to ${email}.`)
    show(await fetchAll())
  }

  async function cancel(invitation: InvitationOut) {
    setError(null)
    const result = await client.organization.cancelInvitation({ invitation_id: invitation.id })
    if (result.error) setError(result.error)
    else show(await fetchAll())
  }

  if (!org) return <FormMessage error={error} />
  return (
    <section className="grid gap-6" data-testid="active-organization">
      <div>
        <h2 className="text-lg font-semibold">{org.organization.name}</h2>
        <p className="text-muted-foreground text-sm">Your role: {org.role}</p>
      </div>
      <div className="grid gap-2">
        <h3 className="font-medium">Members</h3>
        <ul className="grid gap-1 text-sm" data-testid="members">
          {org.members.map((member) => (
            <li key={member.id}>
              {member.email ?? member.user_id} ({member.role})
            </li>
          ))}
        </ul>
      </div>
      {invitations.length > 0 ? (
        <div className="grid gap-2">
          <h3 className="font-medium">Pending invitations</h3>
          <ul className="grid gap-1 text-sm" data-testid="invitations">
            {invitations
              .filter((invitation) => invitation.status === "pending")
              .map((invitation) => (
                <li key={invitation.id} className="flex items-center justify-between">
                  <span>
                    {invitation.email} ({invitation.role})
                  </span>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => void cancel(invitation)}
                    aria-label={`Cancel the invitation for ${invitation.email}`}
                  >
                    Cancel
                  </Button>
                </li>
              ))}
          </ul>
        </div>
      ) : null}
      <form className="grid max-w-sm gap-3" onSubmit={(event) => void invite(event)}>
        <h3 className="font-medium">Invite someone</h3>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-email`}>Email</Label>
          <Input id={`${id}-email`} name="email" type="email" autoComplete="off" required />
        </div>
        <div className="grid gap-2">
          <Label htmlFor={`${id}-role`}>Role</Label>
          <select
            id={`${id}-role`}
            name="role"
            defaultValue="member"
            className="h-9 rounded-md border bg-transparent px-3 text-sm"
          >
            <option value="member">Member</option>
            <option value="admin">Admin</option>
          </select>
        </div>
        <FormMessage error={error} message={notice} />
        <Button type="submit">Send invitation</Button>
      </form>
    </section>
  )
}

export default function OrganizationsPage() {
  const { data, isPending } = useSession()
  if (isPending) return null
  if (!data) {
    return (
      <p>
        <Link href="/sign-in" className="underline">Sign in</Link> to manage organizations.
      </p>
    )
  }
  const active = data.session.active_organization_id
  return (
    <section className="grid gap-8">
      <h1 className="text-2xl font-semibold">Organizations</h1>
      {typeof active === "string" ? (
        <ActiveOrganization key={active} organizationId={active} />
      ) : (
        <p className="text-muted-foreground text-sm">
          You are acting as yourself. Pick an organization at the top, or create one.
        </p>
      )}
      <CreateOrganization />
    </section>
  )
}
