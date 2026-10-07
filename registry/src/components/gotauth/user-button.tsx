"use client"

import { Avatar, AvatarFallback, AvatarImage } from "@/components/ui/avatar"
import { Button } from "@/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"
import { useGotAuthClient } from "@/components/gotauth/gotauth-provider"
import { useSession } from "@/hooks/use-session"

function initials(name: string | null, email: string): string {
  const source = name?.trim() || email
  const parts = source.split(/[\s@._-]+/).filter(Boolean)
  return ((parts[0]?.[0] ?? "") + (parts[1]?.[0] ?? "")).toUpperCase() || "?"
}

/** The signed-in user's avatar with a menu to sign out. Renders nothing when signed out,
 * unless a signInHref is given. */
export function UserButton({
  signInHref,
  onSignOut,
}: {
  signInHref?: string
  onSignOut?: () => void
}) {
  const client = useGotAuthClient()
  const { data, isPending } = useSession()

  // Only before the first answer: refetches keep the avatar (and an open menu) in place.
  if (isPending && !data) return null
  if (!data) {
    return signInHref ? (
      <Button asChild variant="outline">
        <a href={signInHref}>Sign in</a>
      </Button>
    ) : null
  }
  const { user } = data

  async function signOut() {
    const result = await client.signOut()
    if (!result.error) onSignOut?.()
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="ghost" className="rounded-full p-0" aria-label="Account menu">
          <Avatar>
            {user.image ? <AvatarImage src={user.image} alt="" /> : null}
            <AvatarFallback>{initials(user.name, user.email)}</AvatarFallback>
          </Avatar>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        <DropdownMenuLabel>
          {user.name ? <div>{user.name}</div> : null}
          <div className="text-muted-foreground text-sm font-normal">{user.email}</div>
        </DropdownMenuLabel>
        <DropdownMenuSeparator />
        <DropdownMenuItem onSelect={() => void signOut()}>Sign out</DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
