"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { UserButton } from "@/components/gotauth/user-button"

export function Header() {
  const router = useRouter()
  return (
    <header className="flex items-center justify-between border-b px-6 py-3">
      <nav className="flex items-center gap-6 text-sm">
        <Link href="/" className="font-semibold">
          Projects
        </Link>
        <Link href="/keys" className="text-muted-foreground hover:text-foreground">
          API keys
        </Link>
      </nav>
      <UserButton signInHref="/sign-in" onSignOut={() => router.push("/")} />
    </header>
  )
}
