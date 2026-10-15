// GotAuth typed fetch client. Talks to GotAuth's HTTP API with cookies.
// Types mirror gotauth.contracts.http_models; JSON field names stay snake_case.

export type User = {
  id: string
  email: string
  email_verified: boolean
  name: string | null
  image: string | null
  created_at: string
  updated_at: string
  [extra: string]: unknown
}

export type Session = {
  id: string
  user_id: string
  expires_at: string
  remember_me: boolean
  created_at: string
  updated_at: string
  ip_address: string | null
  user_agent: string | null
  [extra: string]: unknown
}

export type SessionWithUserOut = { session: Session; user: User }
export type SignInOut = { user: User; session: Session; token?: string | null }
export type SignInChallenge = { type: string; methods: string[] }
export type ChallengeOut = { challenge: SignInChallenge }
export type StatusOut = { status: string }
export type RedirectOut = { url: string }
export type SessionListOut = { sessions: Session[]; current_session_id: string | null }
export type AccountOut = {
  id: string
  provider_id: string
  account_id: string
  scope: string | null
  created_at: string
}
export type AccountListOut = { accounts: AccountOut[] }

export type ApiKeyOut = {
  id: string
  name: string
  start: string
  owner_type: "user" | "organization" | "agent"
  owner_id: string
  user_id: string | null
  scopes: string[]
  expires_at: string | null
  last_used_at: string | null
  rate_limit_max: number | null
  rate_limit_window: number | null
  enabled: boolean
  created_by: string | null
  created_at: string
  metadata: Record<string, unknown>
}
export type IssueApiKeyOut = { api_key: ApiKeyOut; key: string }
export type ApiKeyListOut = { api_keys: ApiKeyOut[] }

export type EnableOut = { totp_uri: string; backup_codes: string[] }
export type BackupCodesOut = { backup_codes: string[] }

/** WebAuthn options as JSON (base64url strings); see lib/webauthn.ts. */
export type CreationOptionsOut = {
  challenge: string
  rp: Record<string, unknown>
  user: Record<string, unknown>
  pubKeyCredParams: Record<string, unknown>[]
  excludeCredentials?: Record<string, unknown>[]
  [extra: string]: unknown
}
export type RequestOptionsOut = {
  challenge: string
  rpId: string
  allowCredentials?: Record<string, unknown>[]
  [extra: string]: unknown
}
export type PasskeyOut = {
  id: string
  name: string | null
  credential_id: string
  device_type: "single_device" | "multi_device"
  backed_up: boolean
  transports: string[]
  created_at: string
  last_used_at: string | null
}
export type PasskeyListOut = { passkeys: PasskeyOut[] }

export type EmailOtpType = "sign_in" | "verify_email" | "reset_password"

export type OrganizationOut = {
  id: string
  name: string
  slug: string
  logo: string | null
  metadata: Record<string, unknown>
  created_at: string
}
export type OrganizationWithRoleOut = OrganizationOut & { role: string }
export type OrganizationListOut = { organizations: OrganizationWithRoleOut[] }
export type MemberOut = {
  id: string
  organization_id: string
  user_id: string
  role: string
  created_at: string
  email?: string | null
  name?: string | null
}
export type FullOrganizationOut = {
  organization: OrganizationOut
  members: MemberOut[]
  role: string
}
export type InvitationOut = {
  id: string
  organization_id: string
  email: string
  role: string
  status: "pending" | "accepted" | "rejected" | "canceled"
  inviter_id: string | null
  expires_at: string
  created_at: string
}
export type InvitationListOut = { invitations: InvitationOut[] }
export type SetActiveOut = { organization_id: string | null }
export type HasPermissionOut = { success: boolean }

export type OAuthGrantOut = {
  client_id: string
  client_name: string
  scopes: string[]
  resources: string[]
  created_at: string
  last_used_at: string | null
}
export type OAuthGrantListOut = { grants: OAuthGrantOut[] }
export type OAuthGrantRevokedOut = { revoked: number }

/** What a consent screen shows (oauth_authorize in JSON mode, O1). */
export type OAuthConsentOut = {
  consent_id: string
  client: { client_id: string; name: string; host: string | null }
  scopes: string[]
  resource: string | null
  /** Where the browser goes after approval; must be on screen (MCP 2026-07-28). */
  redirect_host: string
  /** Every redirect URI of the client is a loopback address: a local app. */
  loopback_only: boolean
}
export type OAuthAuthorizeQuery = {
  response_type?: string
  client_id?: string
  redirect_uri?: string
  scope?: string
  state?: string
  code_challenge?: string
  code_challenge_method?: string
  nonce?: string
  prompt?: string
  resource?: string
}

/** True when oauthAuthorize needs a consent screen; otherwise navigate to `url`. */
export function isConsent(value: OAuthConsentOut | RedirectOut): value is OAuthConsentOut {
  return "consent_id" in value
}

export type ErrorOut = {
  error: { code: string; message: string; details?: Record<string, unknown> | null }
}

export type GotAuthError = { code: string; message: string; status: number }
export type Result<T> = { data: T; error: null } | { data: null; error: GotAuthError }

/** True when a sign-in needs another step (for example two-factor). */
export function isChallenge(value: SignInOut | ChallengeOut): value is ChallengeOut {
  return "challenge" in value
}

type Method = "GET" | "POST" | "PATCH" | "DELETE"
type Query = Record<string, string | number | boolean | null | undefined>

export type GotAuthClientOptions = {
  /** Where GotAuth is mounted; default "/api/auth". */
  baseURL?: string
  /** A fetch implementation; default globalThis.fetch. */
  fetch?: typeof fetch
}

export type GotAuthClient = ReturnType<typeof createGotAuthClient>

export function createGotAuthClient(options: GotAuthClientOptions = {}) {
  const baseURL = (options.baseURL ?? "/api/auth").replace(/\/+$/, "")
  const doFetch: typeof fetch = options.fetch ?? ((...args) => globalThis.fetch(...args))
  const listeners = new Set<() => void>()

  function withQuery(path: string, query: Query | undefined): string {
    let url = baseURL + path
    if (query) {
      const params = new URLSearchParams()
      for (const [key, value] of Object.entries(query)) {
        if (value !== undefined && value !== null) params.set(key, String(value))
      }
      const text = params.toString()
      if (text) url += `?${text}`
    }
    return url
  }

  async function request<T>(
    method: Method,
    path: string,
    input: { body?: unknown; query?: Query; redirect?: RequestRedirect } = {},
  ): Promise<Result<T>> {
    const url = withQuery(path, input.query)
    const headers: Record<string, string> = { Accept: "application/json" }
    const init: RequestInit = { method, credentials: "include", headers }
    if (input.redirect) init.redirect = input.redirect
    if (method !== "GET") {
      // GotAuth answers 415 to JSON endpoints called without this header.
      headers["Content-Type"] = "application/json"
      init.body = JSON.stringify(input.body ?? {})
    }
    let response: Response
    try {
      response = await doFetch(url, init)
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Network error"
      return { data: null, error: { code: "NETWORK_ERROR", message, status: 0 } }
    }
    if (
      input.redirect === "manual" &&
      (response.type === "opaqueredirect" || (response.status >= 300 && response.status < 400))
    ) {
      // Browsers hide where a redirect goes; the page navigates to the same URL itself.
      return { data: { url } as T, error: null }
    }
    let payload: unknown = null
    let text: string
    try {
      text = await response.text()
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : "Network error"
      return { data: null, error: { code: "NETWORK_ERROR", message, status: 0 } }
    }
    if (text) {
      try {
        payload = JSON.parse(text)
      } catch {
        payload = null
      }
    }
    if (!response.ok) {
      const body = payload as Partial<ErrorOut> | null
      return {
        data: null,
        error: {
          code: body?.error?.code ?? `HTTP_${response.status}`,
          message: body?.error?.message ?? response.statusText,
          status: response.status,
        },
      }
    }
    return { data: payload as T, error: null }
  }

  /** Tell useSession (and other listeners) that the session may have changed. */
  function notify() {
    for (const listener of listeners) listener()
  }

  async function changing<T>(result: Promise<Result<T>>): Promise<Result<T>> {
    const value = await result
    if (value.error === null) notify()
    return value
  }

  return {
    baseURL,
    /** Subscribe to session changes; returns the unsubscribe function. */
    subscribe(listener: () => void) {
      listeners.add(listener)
      return () => {
        listeners.delete(listener)
      }
    },
    notify,

    // ------------------------------------------------------------ email + password (C2)
    signUpEmail(body: {
      email: string
      password: string
      name?: string | null
      image?: string | null
      callback_url?: string | null
      remember_me?: boolean
    }) {
      return changing(request<SignInOut | ChallengeOut | StatusOut>("POST", "/sign-up/email", { body }))
    },
    signInEmail(body: { email: string; password: string; remember_me?: boolean }) {
      return changing(request<SignInOut | ChallengeOut>("POST", "/sign-in/email", { body }))
    },
    signOut() {
      return changing(request<StatusOut>("POST", "/sign-out"))
    },
    sendVerificationEmail(body: { email: string; callback_url?: string | null }) {
      return request<StatusOut>("POST", "/send-verification-email", { body })
    },
    /** Verify from app code. The emailed link (with callback_url) is for the browser;
     * here no callback_url is sent, so the answer is always JSON. */
    verifyEmail(query: { token: string }) {
      return changing(request<StatusOut>("GET", "/verify-email", { query: { token: query.token } }))
    },
    requestPasswordReset(body: { email: string; redirect_to: string }) {
      return request<StatusOut>("POST", "/request-password-reset", { body })
    },
    resetPassword(body: { token: string; new_password: string }) {
      return request<StatusOut>("POST", "/reset-password", { body })
    },
    changePassword(body: {
      current_password: string
      new_password: string
      revoke_other_sessions?: boolean
    }) {
      return request<StatusOut>("POST", "/change-password", { body })
    },
    changeEmail(body: { new_email: string; callback_url?: string | null }) {
      return request<StatusOut>("POST", "/change-email", { body })
    },
    updateUser(body: { name?: string | null; image?: string | null }) {
      return changing(request<User>("PATCH", "/user", { body }))
    },
    deleteUser(body: { password?: string | null } = {}) {
      return changing(request<StatusOut>("DELETE", "/user", { body }))
    },

    // ------------------------------------------------------------ sessions (C3)
    getSession() {
      return request<SessionWithUserOut | null>("GET", "/session")
    },
    listSessions() {
      return request<SessionListOut>("GET", "/sessions")
    },
    revokeSession(body: { session_id: string }) {
      return changing(request<StatusOut>("POST", "/sessions/revoke", { body }))
    },
    revokeOtherSessions() {
      return request<StatusOut>("POST", "/sessions/revoke-others")
    },

    // ------------------------------------------------------------ social (C4)
    signInSocial(body: {
      provider: string
      callback_url?: string | null
      error_callback_url?: string | null
      scopes?: string[] | null
      remember_me?: boolean
    }) {
      return request<RedirectOut>("POST", "/sign-in/social", { body })
    },
    linkSocial(body: {
      provider: string
      callback_url?: string | null
      scopes?: string[] | null
    }) {
      return request<RedirectOut>("POST", "/link-social", { body })
    },
    listAccounts() {
      return request<AccountListOut>("GET", "/accounts")
    },
    unlinkAccount(body: { provider_id: string; account_id?: string | null }) {
      return request<StatusOut>("POST", "/unlink-account", { body })
    },

    // ------------------------------------------------------------ API keys (P1)
    apiKeys: {
      createApiKey(body: {
        name: string
        scopes?: string[]
        expires_in?: string | number | null
        organization_id?: string | null
        metadata?: Record<string, unknown> | null
        rate_limit_max?: number | null
        rate_limit_window?: number | null
      }) {
        return request<IssueApiKeyOut>("POST", "/api-keys", { body })
      },
      listApiKeys(query: { organization_id?: string } = {}) {
        return request<ApiKeyListOut>("GET", "/api-keys", { query })
      },
      updateApiKey(
        id: string,
        body: {
          name?: string | null
          scopes?: string[] | null
          enabled?: boolean | null
          expires_at?: string | null
        },
      ) {
        return request<ApiKeyOut>("PATCH", `/api-keys/${encodeURIComponent(id)}`, { body })
      },
      deleteApiKey(id: string) {
        return request<StatusOut>("DELETE", `/api-keys/${encodeURIComponent(id)}`)
      },
    },

    // ------------------------------------------------------------ two-factor (P2)
    twoFactor: {
      /** Starts setup: show `totp_uri` as a QR code and the backup codes once. Two-factor
       * turns on when verifyTotp confirms a code. */
      enableTwoFactor(body: { password?: string | null } = {}) {
        return request<EnableOut>("POST", "/two-factor/enable", { body })
      },
      /** Confirms setup (StatusOut) or answers a sign-in challenge (SignInOut). */
      verifyTotp(body: { code: string; trust_device?: boolean }) {
        return changing(request<SignInOut | StatusOut>("POST", "/two-factor/verify-totp", { body }))
      },
      verifyBackupCode(body: { code: string; trust_device?: boolean }) {
        return changing(request<SignInOut>("POST", "/two-factor/verify-backup-code", { body }))
      },
      sendTwoFactorOtp() {
        return request<StatusOut>("POST", "/two-factor/send-otp")
      },
      verifyTwoFactorOtp(body: { code: string; trust_device?: boolean }) {
        return changing(request<SignInOut>("POST", "/two-factor/verify-otp", { body }))
      },
      disableTwoFactor(body: { password?: string | null } = {}) {
        return changing(request<StatusOut>("POST", "/two-factor/disable", { body }))
      },
      regenerateBackupCodes() {
        return request<BackupCodesOut>("POST", "/two-factor/regenerate-backup-codes")
      },
    },

    // ------------------------------------------------------------ passkeys (P3)
    passkey: {
      getPasskeyRegistrationOptions() {
        return request<CreationOptionsOut>("POST", "/passkey/register/options")
      },
      verifyPasskeyRegistration(body: { response: Record<string, unknown>; name?: string | null }) {
        return request<PasskeyOut>("POST", "/passkey/register/verify", { body })
      },
      getPasskeySignInOptions() {
        return request<RequestOptionsOut>("POST", "/passkey/sign-in/options")
      },
      signInPasskey(body: { response: Record<string, unknown>; remember_me?: boolean }) {
        return changing(request<SignInOut | ChallengeOut>("POST", "/passkey/sign-in/verify", { body }))
      },
      listPasskeys() {
        return request<PasskeyListOut>("GET", "/passkeys")
      },
      renamePasskey(id: string, body: { name: string }) {
        return request<PasskeyOut>("PATCH", `/passkeys/${encodeURIComponent(id)}`, { body })
      },
      deletePasskey(id: string) {
        return request<StatusOut>("DELETE", `/passkeys/${encodeURIComponent(id)}`)
      },
    },

    // ------------------------------------------------------------ passwordless (P4)
    magicLink: {
      /** The emailed link (verify_magic_link) is for the browser; the client never calls it. */
      sendMagicLink(body: { email: string; callback_url?: string; error_callback_url?: string | null }) {
        return request<StatusOut>("POST", "/magic-link/send", { body })
      },
    },
    emailOtp: {
      sendEmailOtp(body: { email: string; type: EmailOtpType }) {
        return request<StatusOut>("POST", "/email-otp/send", { body })
      },
      verifyEmailOtp(body: {
        email: string
        otp: string
        type: EmailOtpType
        new_password?: string | null
      }) {
        return changing(
          request<SignInOut | ChallengeOut | StatusOut>("POST", "/email-otp/verify", { body }),
        )
      },
    },

    // ------------------------------------------------------------ organizations (P5)
    organization: {
      createOrganization(body: {
        name: string
        slug: string
        logo?: string | null
        metadata?: Record<string, unknown> | null
      }) {
        return request<OrganizationOut>("POST", "/organization/create", { body })
      },
      listOrganizations() {
        return request<OrganizationListOut>("GET", "/organization/list")
      },
      /** Without organization_id: the session's active organization. */
      getOrganization(query: { organization_id?: string } = {}) {
        return request<FullOrganizationOut>("GET", "/organization/get", { query })
      },
      updateOrganization(body: {
        organization_id?: string | null
        name?: string | null
        slug?: string | null
        logo?: string | null
        metadata?: Record<string, unknown> | null
      }) {
        return request<OrganizationOut>("POST", "/organization/update", { body })
      },
      deleteOrganization(body: { organization_id?: string | null } = {}) {
        return changing(request<StatusOut>("POST", "/organization/delete", { body }))
      },
      /** null switches to no organization (personal). */
      setActiveOrganization(body: { organization_id: string | null }) {
        return changing(request<SetActiveOut>("POST", "/organization/set-active", { body }))
      },
      inviteMember(body: { email: string; role?: string; organization_id?: string | null }) {
        return request<InvitationOut>("POST", "/organization/invite-member", { body })
      },
      acceptInvitation(body: { invitation_id: string; token: string }) {
        return changing(request<MemberOut>("POST", "/organization/accept-invitation", { body }))
      },
      rejectInvitation(body: { invitation_id: string; token: string }) {
        return request<StatusOut>("POST", "/organization/reject-invitation", { body })
      },
      cancelInvitation(body: { invitation_id: string }) {
        return request<StatusOut>("POST", "/organization/cancel-invitation", { body })
      },
      listInvitations(query: { organization_id?: string } = {}) {
        return request<InvitationListOut>("GET", "/organization/list-invitations", { query })
      },
      removeMember(body: { user_id: string; organization_id?: string | null }) {
        return request<StatusOut>("POST", "/organization/remove-member", { body })
      },
      updateMemberRole(body: { user_id: string; role: string; organization_id?: string | null }) {
        return request<MemberOut>("POST", "/organization/update-member-role", { body })
      },
      leaveOrganization(body: { organization_id?: string | null } = {}) {
        return changing(request<StatusOut>("POST", "/organization/leave", { body }))
      },
      hasPermission(body: {
        permissions: Record<string, string[]>
        organization_id?: string | null
      }) {
        return request<HasPermissionOut>("POST", "/organization/has-permission", { body })
      },
    },

    // ------------------------------------------------------------ OAuth server (O1)
    oauth2: {
      /** The authorization request in JSON mode. Returns what a consent screen shows,
       * or `{ url }`: sign in first, or consent is already given, so navigate there
       * with `window.location.assign(url)`. */
      oauthAuthorize(query: OAuthAuthorizeQuery) {
        return request<OAuthConsentOut | RedirectOut>("GET", "/oauth2/authorize", {
          query,
          redirect: "manual",
        })
      },
      /** Where a consent form posts (form-encoded; see ConsentScreen). */
      consentURL: `${baseURL}/oauth2/consent`,
      /** The apps the user has authorized ("connected apps"). */
      listOauthGrants() {
        return request<OAuthGrantListOut>("GET", "/oauth2/grants")
      },
      /** Revoke an app: its tokens stop working and consent is asked again. */
      revokeOauthGrant(body: { client_id: string }) {
        return request<OAuthGrantRevokedOut>("POST", "/oauth2/grants/revoke", { body })
      },
    },
  }
}
