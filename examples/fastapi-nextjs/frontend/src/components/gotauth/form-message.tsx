"use client"

import type { GotAuthError } from "@/lib/gotauth-client"

const MESSAGES: Record<string, string> = {
  INVALID_CREDENTIALS: "That email and password don't match.",
  EMAIL_NOT_VERIFIED: "Verify your email first. Check your inbox for the link.",
  USER_ALREADY_EXISTS: "An account with this email already exists.",
  PASSWORD_TOO_SHORT: "Use a longer password.",
  PASSWORD_TOO_LONG: "Use a shorter password.",
  RATE_LIMITED: "Too many attempts. Wait a minute and try again.",
  NETWORK_ERROR: "Can't reach the server. Check your connection and try again.",
  INVALID_REQUEST: "Check the form and try again.",
}

/** A readable sentence for a GotAuth error. */
export function errorMessage(error: GotAuthError): string {
  return MESSAGES[error.code] ?? error.message ?? "Something went wrong. Try again."
}

/** A polite live region, so screen readers announce errors and confirmations. */
export function FormMessage({
  error,
  message,
}: {
  error?: GotAuthError | null
  message?: string | null
}) {
  const text = error ? errorMessage(error) : message
  return (
    <div aria-live="polite" role="status" className="min-h-5 text-sm">
      {text ? (
        <p className={error ? "text-destructive" : "text-muted-foreground"}>{text}</p>
      ) : null}
    </div>
  )
}
