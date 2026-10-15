"use client"

import { ApiKeyManager } from "@/components/gotauth/api-key-manager"
import { ConnectedApps } from "@/components/gotauth/connected-apps"
import { ConsentScreen } from "@/components/gotauth/consent-screen"
import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"
import { OrgSwitcher } from "@/components/gotauth/org-switcher"
import { PasskeyButton } from "@/components/gotauth/passkey-button"
import { SessionList } from "@/components/gotauth/session-list"
import { SignInForm } from "@/components/gotauth/sign-in-form"
import { SignUpForm } from "@/components/gotauth/sign-up-form"
import { TwoFactorChallenge } from "@/components/gotauth/two-factor-challenge"
import { TwoFactorSetup } from "@/components/gotauth/two-factor-setup"
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
      <OrgSwitcher onCreate={() => undefined} />
      <Account />
      <SignInForm socialProviders={[{ id: "github", name: "GitHub" }]} />
      <PasskeyButton />
      <PasskeyButton mode="register" name="Laptop" />
      <SignUpForm />
      <TwoFactorSetup />
      <TwoFactorChallenge challenge={{ type: "two_factor", methods: ["totp", "backup_code"] }} />
      <SessionList />
      <ApiKeyManager scopes={["projects:read"]} />
      <ConnectedApps />
      <ConsentScreen
        consent={{
          consent_id: "demo",
          client: { client_id: "cli_demo", name: "Demo app", host: null },
          scopes: ["projects:read"],
          resource: null,
          redirect_host: "app.example.com",
          loopback_only: false,
        }}
      />
    </GotAuthProvider>
  )
}
