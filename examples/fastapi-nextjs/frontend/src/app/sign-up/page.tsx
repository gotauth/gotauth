"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { SignUpForm } from "@/components/gotauth/sign-up-form"
import { useAppConfig } from "@/lib/app-config"

export default function SignUpPage() {
  const router = useRouter()
  const config = useAppConfig()
  if (!config) return null
  return (
    <section className="grid justify-items-center gap-4">
      {/* Verifying does not sign in: the emailed link (printed by the backend on
          localhost) comes back to the sign-in page. */}
      <SignUpForm
        socialProviders={config.social_providers}
        callbackURL="/sign-in"
        onSuccess={() => router.push("/")}
      />
      <p className="text-muted-foreground text-sm">
        Have an account? <Link href="/sign-in" className="underline">Sign in</Link>
      </p>
    </section>
  )
}
