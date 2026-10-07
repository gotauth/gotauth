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

  async function request<T>(
    method: Method,
    path: string,
    input: { body?: unknown; query?: Query } = {},
  ): Promise<Result<T>> {
    let url = baseURL + path
    if (input.query) {
      const params = new URLSearchParams()
      for (const [key, value] of Object.entries(input.query)) {
        if (value !== undefined && value !== null) params.set(key, String(value))
      }
      const text = params.toString()
      if (text) url += `?${text}`
    }
    const headers: Record<string, string> = { Accept: "application/json" }
    const init: RequestInit = { method, credentials: "include", headers }
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
      name?: string
      image?: string
      callback_url?: string
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
    sendVerificationEmail(body: { email: string; callback_url?: string }) {
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
    changeEmail(body: { new_email: string; callback_url?: string }) {
      return request<StatusOut>("POST", "/change-email", { body })
    },
    updateUser(body: { name?: string | null; image?: string | null }) {
      return changing(request<User>("PATCH", "/user", { body }))
    },
    deleteUser(body: { password?: string } = {}) {
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
      callback_url?: string
      error_callback_url?: string
      scopes?: string[]
      remember_me?: boolean
    }) {
      return request<RedirectOut>("POST", "/sign-in/social", { body })
    },
    linkSocial(body: { provider: string; callback_url?: string; scopes?: string[] }) {
      return request<RedirectOut>("POST", "/link-social", { body })
    },
    listAccounts() {
      return request<AccountListOut>("GET", "/accounts")
    },
    unlinkAccount(body: { provider_id: string; account_id?: string }) {
      return request<StatusOut>("POST", "/unlink-account", { body })
    },

    // ------------------------------------------------------------ API keys (P1)
    apiKeys: {
      createApiKey(body: {
        name: string
        scopes?: string[]
        expires_in?: string | number
        organization_id?: string
        metadata?: Record<string, unknown>
        rate_limit_max?: number
        rate_limit_window?: number
      }) {
        return request<IssueApiKeyOut>("POST", "/api-keys", { body })
      },
      listApiKeys(query: { organization_id?: string } = {}) {
        return request<ApiKeyListOut>("GET", "/api-keys", { query })
      },
      updateApiKey(
        id: string,
        body: { name?: string; scopes?: string[]; enabled?: boolean; expires_at?: string | null },
      ) {
        return request<ApiKeyOut>("PATCH", `/api-keys/${encodeURIComponent(id)}`, { body })
      },
      deleteApiKey(id: string) {
        return request<StatusOut>("DELETE", `/api-keys/${encodeURIComponent(id)}`)
      },
    },
  }
}
