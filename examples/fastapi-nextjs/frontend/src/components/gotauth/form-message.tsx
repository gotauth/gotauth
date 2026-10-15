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
  FRESH_SESSION_REQUIRED: "For your security, sign in again to do this.",
  TOKEN_EXPIRED: "This has expired. Start again.",
  TWO_FACTOR_INVALID_CODE: "That code didn't work. Check it and try again.",
  TWO_FACTOR_ALREADY_ENABLED: "Two-factor authentication is already on.",
  PASSKEY_VERIFICATION_FAILED: "That passkey didn't work. Try again or use another way.",
  PASSKEY_CHALLENGE_INVALID: "The passkey request expired. Try again.",
  PASSKEY_ALREADY_REGISTERED: "This passkey is already on your account.",
  ORG_SLUG_TAKEN: "That URL name is taken. Pick another.",
  ORG_INVITATION_INVALID: "This invitation is no longer valid. Ask for a new one.",
  ORG_FORBIDDEN: "Your role in this organization doesn't allow that.",
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
