"use client"

import { ApiKeyManager } from "@/components/gotauth/api-key-manager"
import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"
import { SessionList } from "@/components/gotauth/session-list"
import { SignInForm } from "@/components/gotauth/sign-in-form"
import { SignUpForm } from "@/components/gotauth/sign-up-form"
import { UserButton } from "@/components/gotauth/user-button"
import { useSession } from "@/hooks/use-session"

function Account() {
  const { data } = useSession()
  return data ? <p>Signed in as {data.user.email}</p> : null
}

export function Demo() {
  return (
    <GotAuthProvider baseURL="/api/auth">
      <UserButton signInHref="/sign-in" />
      <Account />
      <SignInForm socialProviders={[{ id: "github", name: "GitHub" }]} />
      <SignUpForm />
      <SessionList />
      <ApiKeyManager scopes={["projects:read"]} />
    </GotAuthProvider>
  )
}
