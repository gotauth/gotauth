import { describe, expect, it, vi } from "vitest"

import { createGotAuthClient, isChallenge, isConsent } from "@/lib/gotauth-client"

type Call = { url: string; init: RequestInit }

function recorder(status = 200, body: unknown = { status: "ok" }) {
  const calls: Call[] = []
  const fetchSpy = vi.fn(async (url: RequestInfo | URL, init?: RequestInit) => {
    calls.push({ url: String(url), init: init ?? {} })
    return new Response(body === null ? "" : JSON.stringify(body), {
      status,
      headers: { "Content-Type": "application/json" },
    })
  })
  const client = createGotAuthClient({ baseURL: "https://api.test/api/auth/", fetch: fetchSpy })
  return { client, calls }
}

// Every client method with its expected method and path.
const CASES: [string, (c: ReturnType<typeof createGotAuthClient>) => Promise<unknown>, string, string][] = [
  ["signUpEmail", (c) => c.signUpEmail({ email: "a@b.test", password: "p" }), "POST", "/sign-up/email"],
  ["signInEmail", (c) => c.signInEmail({ email: "a@b.test", password: "p" }), "POST", "/sign-in/email"],
  ["signOut", (c) => c.signOut(), "POST", "/sign-out"],
  ["sendVerificationEmail", (c) => c.sendVerificationEmail({ email: "a@b.test" }), "POST", "/send-verification-email"],
  ["verifyEmail", (c) => c.verifyEmail({ token: "gav_x" }), "GET", "/verify-email?token=gav_x"],
  ["requestPasswordReset", (c) => c.requestPasswordReset({ email: "a@b.test", redirect_to: "/reset" }), "POST", "/request-password-reset"],
  ["resetPassword", (c) => c.resetPassword({ token: "t", new_password: "p" }), "POST", "/reset-password"],
  ["changePassword", (c) => c.changePassword({ current_password: "a", new_password: "b" }), "POST", "/change-password"],
  ["changeEmail", (c) => c.changeEmail({ new_email: "n@b.test" }), "POST", "/change-email"],
  ["updateUser", (c) => c.updateUser({ name: "Ada" }), "PATCH", "/user"],
  ["deleteUser", (c) => c.deleteUser({ password: "p" }), "DELETE", "/user"],
  ["getSession", (c) => c.getSession(), "GET", "/session"],
  ["listSessions", (c) => c.listSessions(), "GET", "/sessions"],
  ["revokeSession", (c) => c.revokeSession({ session_id: "ses_1" }), "POST", "/sessions/revoke"],
  ["revokeOtherSessions", (c) => c.revokeOtherSessions(), "POST", "/sessions/revoke-others"],
  ["signInSocial", (c) => c.signInSocial({ provider: "github" }), "POST", "/sign-in/social"],
  ["linkSocial", (c) => c.linkSocial({ provider: "github" }), "POST", "/link-social"],
  ["listAccounts", (c) => c.listAccounts(), "GET", "/accounts"],
  ["unlinkAccount", (c) => c.unlinkAccount({ provider_id: "github" }), "POST", "/unlink-account"],
  ["createApiKey", (c) => c.apiKeys.createApiKey({ name: "ci" }), "POST", "/api-keys"],
  ["listApiKeys", (c) => c.apiKeys.listApiKeys({ organization_id: "org_1" }), "GET", "/api-keys?organization_id=org_1"],
  ["updateApiKey", (c) => c.apiKeys.updateApiKey("key_1", { name: "x" }), "PATCH", "/api-keys/key_1"],
  ["deleteApiKey", (c) => c.apiKeys.deleteApiKey("key_1"), "DELETE", "/api-keys/key_1"],
  ["enableTwoFactor", (c) => c.twoFactor.enableTwoFactor({ password: "p" }), "POST", "/two-factor/enable"],
  ["verifyTotp", (c) => c.twoFactor.verifyTotp({ code: "123456" }), "POST", "/two-factor/verify-totp"],
  ["verifyBackupCode", (c) => c.twoFactor.verifyBackupCode({ code: "abcd-efgh" }), "POST", "/two-factor/verify-backup-code"],
  ["sendTwoFactorOtp", (c) => c.twoFactor.sendTwoFactorOtp(), "POST", "/two-factor/send-otp"],
  ["verifyTwoFactorOtp", (c) => c.twoFactor.verifyTwoFactorOtp({ code: "123456" }), "POST", "/two-factor/verify-otp"],
  ["disableTwoFactor", (c) => c.twoFactor.disableTwoFactor({ password: "p" }), "POST", "/two-factor/disable"],
  ["regenerateBackupCodes", (c) => c.twoFactor.regenerateBackupCodes(), "POST", "/two-factor/regenerate-backup-codes"],
  ["getPasskeyRegistrationOptions", (c) => c.passkey.getPasskeyRegistrationOptions(), "POST", "/passkey/register/options"],
  ["verifyPasskeyRegistration", (c) => c.passkey.verifyPasskeyRegistration({ response: {} }), "POST", "/passkey/register/verify"],
  ["getPasskeySignInOptions", (c) => c.passkey.getPasskeySignInOptions(), "POST", "/passkey/sign-in/options"],
  ["signInPasskey", (c) => c.passkey.signInPasskey({ response: {} }), "POST", "/passkey/sign-in/verify"],
  ["listPasskeys", (c) => c.passkey.listPasskeys(), "GET", "/passkeys"],
  ["renamePasskey", (c) => c.passkey.renamePasskey("pk_1", { name: "Laptop" }), "PATCH", "/passkeys/pk_1"],
  ["deletePasskey", (c) => c.passkey.deletePasskey("pk_1"), "DELETE", "/passkeys/pk_1"],
  ["sendMagicLink", (c) => c.magicLink.sendMagicLink({ email: "a@b.test" }), "POST", "/magic-link/send"],
  ["sendEmailOtp", (c) => c.emailOtp.sendEmailOtp({ email: "a@b.test", type: "sign_in" }), "POST", "/email-otp/send"],
  ["verifyEmailOtp", (c) => c.emailOtp.verifyEmailOtp({ email: "a@b.test", otp: "123456", type: "sign_in" }), "POST", "/email-otp/verify"],
  ["createOrganization", (c) => c.organization.createOrganization({ name: "Acme", slug: "acme" }), "POST", "/organization/create"],
  ["listOrganizations", (c) => c.organization.listOrganizations(), "GET", "/organization/list"],
  ["getOrganization", (c) => c.organization.getOrganization({ organization_id: "org_1" }), "GET", "/organization/get?organization_id=org_1"],
  ["updateOrganization", (c) => c.organization.updateOrganization({ name: "Acme 2" }), "POST", "/organization/update"],
  ["deleteOrganization", (c) => c.organization.deleteOrganization({ organization_id: "org_1" }), "POST", "/organization/delete"],
  ["setActiveOrganization", (c) => c.organization.setActiveOrganization({ organization_id: null }), "POST", "/organization/set-active"],
  ["inviteMember", (c) => c.organization.inviteMember({ email: "b@b.test" }), "POST", "/organization/invite-member"],
  ["acceptInvitation", (c) => c.organization.acceptInvitation({ invitation_id: "inv_1", token: "gav_x" }), "POST", "/organization/accept-invitation"],
  ["rejectInvitation", (c) => c.organization.rejectInvitation({ invitation_id: "inv_1", token: "gav_x" }), "POST", "/organization/reject-invitation"],
  ["cancelInvitation", (c) => c.organization.cancelInvitation({ invitation_id: "inv_1" }), "POST", "/organization/cancel-invitation"],
  ["listInvitations", (c) => c.organization.listInvitations(), "GET", "/organization/list-invitations"],
  ["removeMember", (c) => c.organization.removeMember({ user_id: "usr_2" }), "POST", "/organization/remove-member"],
  ["updateMemberRole", (c) => c.organization.updateMemberRole({ user_id: "usr_2", role: "admin" }), "POST", "/organization/update-member-role"],
  ["leaveOrganization", (c) => c.organization.leaveOrganization(), "POST", "/organization/leave"],
  ["hasPermission", (c) => c.organization.hasPermission({ permissions: { project: ["read"] } }), "POST", "/organization/has-permission"],
  ["oauthAuthorize", (c) => c.oauth2.oauthAuthorize({ client_id: "cli_1", scope: "openid" }), "GET", "/oauth2/authorize?client_id=cli_1&scope=openid"],
  ["listOauthGrants", (c) => c.oauth2.listOauthGrants(), "GET", "/oauth2/grants"],
  ["revokeOauthGrant", (c) => c.oauth2.revokeOauthGrant({ client_id: "cli_1" }), "POST", "/oauth2/grants/revoke"],
]

describe("createGotAuthClient", () => {
  it.each(CASES)("%s uses the right method, path and transport", async (_, call, method, path) => {
    const { client, calls } = recorder()
    await call(client)
    const [request] = calls
    expect(request?.url).toBe(`https://api.test/api/auth${path}`)
    expect(request?.init.method).toBe(method)
    expect(request?.init.credentials).toBe("include")
    const headers = request?.init.headers as Record<string, string>
    if (method === "GET") {
      expect(request?.init.body).toBeUndefined()
      expect(headers["Content-Type"]).toBeUndefined()
    } else {
      expect(headers["Content-Type"]).toBe("application/json")
      expect(typeof request?.init.body).toBe("string")
    }
  })

  it("sends deleteUser as DELETE with a JSON body", async () => {
    const { client, calls } = recorder()
    await client.deleteUser({ password: "secret pw" })
    expect(calls[0]?.init.method).toBe("DELETE")
    expect(JSON.parse(String(calls[0]?.init.body))).toEqual({ password: "secret pw" })
  })

  it("parses ErrorOut", async () => {
    const { client } = recorder(401, {
      error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password", details: null },
    })
    const result = await client.signInEmail({ email: "a@b.test", password: "x" })
    expect(result).toEqual({
      data: null,
      error: { code: "INVALID_CREDENTIALS", message: "Invalid email or password", status: 401 },
    })
  })

  it("falls back to HTTP_<status> for non-JSON errors", async () => {
    const fetchSpy = vi.fn(async () => new Response("<html>bad gateway</html>", { status: 502, statusText: "Bad Gateway" }))
    const client = createGotAuthClient({ baseURL: "https://api.test", fetch: fetchSpy })
    const result = await client.getSession()
    expect(result.error).toEqual({ code: "HTTP_502", message: "Bad Gateway", status: 502 })
  })

  it("reports network failures as NETWORK_ERROR", async () => {
    const fetchSpy = vi.fn(async () => {
      throw new TypeError("fetch failed")
    })
    const client = createGotAuthClient({ fetch: fetchSpy })
    const result = await client.listSessions()
    expect(result.error?.code).toBe("NETWORK_ERROR")
    expect(result.error?.status).toBe(0)
  })

  it("returns null for a signed-out getSession", async () => {
    const { client } = recorder(200, null)
    expect(await client.getSession()).toEqual({ data: null, error: null })
  })

  it("tells subscribers about sign-in and sign-out, but not failures", async () => {
    const { client } = recorder()
    const listener = vi.fn()
    const stop = client.subscribe(listener)
    await client.signOut()
    expect(listener).toHaveBeenCalledTimes(1)
    stop()
    await client.signOut()
    expect(listener).toHaveBeenCalledTimes(1)
    const failing = recorder(401, { error: { code: "X", message: "x" } }).client
    const other = vi.fn()
    failing.subscribe(other)
    await failing.signInEmail({ email: "a", password: "b" })
    expect(other).not.toHaveBeenCalled()
  })

  it("never touches web storage", async () => {
    const local = vi.spyOn(Storage.prototype, "setItem")
    const { client } = recorder(200, { user: {}, session: {}, token: "gas_secret" })
    await client.signInEmail({ email: "a@b.test", password: "p" })
    await client.getSession()
    expect(local).not.toHaveBeenCalled()
    local.mockRestore()
  })

  it("returns the authorize URL to navigate to when authorize redirects", async () => {
    const fetchSpy = vi.fn(async (_url: RequestInfo | URL, init?: RequestInit) => {
      expect(init?.redirect).toBe("manual")
      return new Response(null, { status: 302, headers: { Location: "https://client.test/cb?code=x" } })
    })
    const client = createGotAuthClient({ baseURL: "https://api.test/api/auth", fetch: fetchSpy })
    const result = await client.oauth2.oauthAuthorize({ client_id: "cli_1", state: "s" })
    expect(result).toEqual({
      data: { url: "https://api.test/api/auth/oauth2/authorize?client_id=cli_1&state=s" },
      error: null,
    })
    expect(result.data && isConsent(result.data)).toBe(false)
  })

  it("returns consent details from authorize in JSON mode", async () => {
    const consent = {
      consent_id: "c1",
      client: { client_id: "cli_1", name: "Claude", host: null },
      scopes: ["openid"],
      resource: null,
      redirect_host: "claude.ai",
      loopback_only: false,
    }
    const { client } = recorder(200, consent)
    const result = await client.oauth2.oauthAuthorize({ client_id: "cli_1" })
    expect(result.data && isConsent(result.data)).toBe(true)
    expect(client.oauth2.consentURL).toBe("https://api.test/api/auth/oauth2/consent")
  })

  it("only treats redirects specially for authorize", async () => {
    const { client } = recorder(302, null)
    const result = await client.getSession()
    expect(result.error?.code).toBe("HTTP_302")
  })

  it("tells challenges apart from sign-ins", () => {
    expect(isChallenge({ challenge: { type: "two_factor", methods: ["totp"] } })).toBe(true)
    expect(isChallenge({ user: {} as never, session: {} as never })).toBe(false)
  })
})
