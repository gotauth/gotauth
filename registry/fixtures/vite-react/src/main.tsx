import { StrictMode } from "react"
import { createRoot } from "react-dom/client"

import { ApiKeyManager } from "@/components/gotauth/api-key-manager"
import { GotAuthProvider } from "@/components/gotauth/gotauth-provider"
import { SessionList } from "@/components/gotauth/session-list"
import { SignInForm } from "@/components/gotauth/sign-in-form"
import { SignUpForm } from "@/components/gotauth/sign-up-form"
import { UserButton } from "@/components/gotauth/user-button"

import "./index.css"

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <GotAuthProvider baseURL="http://localhost:8000/api/auth">
      <main className="mx-auto grid max-w-3xl gap-8 p-8">
        <UserButton />
        <SignInForm />
        <SignUpForm />
        <SessionList />
        <ApiKeyManager />
      </main>
    </GotAuthProvider>
  </StrictMode>,
)
