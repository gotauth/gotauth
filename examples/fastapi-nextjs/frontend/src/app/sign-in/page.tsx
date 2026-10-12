"use client"

import Link from "next/link"
import { useRouter } from "next/navigation"

import { SignInForm } from "@/components/gotauth/sign-in-form"
import { useAppConfig } from "@/lib/app-config"

export default function SignInPage() {
  const router = useRouter()
  const config = useAppConfig()
  if (!config) return null
  return (
    <section className="grid justify-items-center gap-4">
      <SignInForm
        socialProviders={config.social_providers}
        callbackURL="/"
        onSuccess={() => router.push("/")}
      />
      <p className="text-muted-foreground text-sm">
        No account? <Link href="/sign-up" className="underline">Create one</Link>
      </p>
    </section>
  )
}
