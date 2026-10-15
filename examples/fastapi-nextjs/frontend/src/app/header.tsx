"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { OrgSwitcher } from "@/components/gotauth/org-switcher"
import { UserButton } from "@/components/gotauth/user-button"

const LINKS = [
  { href: "/keys", label: "API keys" },
  { href: "/organizations", label: "Organizations" },
  { href: "/security", label: "Security" },
]

export function Header() {
  const router = useRouter()
  return (
    <header className="flex items-center justify-between border-b px-6 py-3">
      <nav className="flex items-center gap-6 text-sm">
        <Link href="/" className="font-semibold">
          Projects
        </Link>
        {LINKS.map((link) => (
          <Link key={link.href} href={link.href} className="text-muted-foreground hover:text-foreground">
            {link.label}
          </Link>
        ))}
      </nav>
      <div className="flex items-center gap-3">
        {/* Renders nothing when signed out. */}
        <OrgSwitcher onCreate={() => router.push("/organizations")} />
        <UserButton signInHref="/sign-in" onSignOut={() => router.push("/")} />
      </div>
    </header>
  )
}
