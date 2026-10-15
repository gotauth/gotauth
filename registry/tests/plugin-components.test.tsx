import { screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { http, HttpResponse } from "msw"
import { afterEach, describe, expect, it, vi } from "vitest"

import { ConnectedApps } from "@/components/gotauth/connected-apps"
import { ConsentScreen } from "@/components/gotauth/consent-screen"
import { OrgSwitcher } from "@/components/gotauth/org-switcher"
import { PasskeyButton } from "@/components/gotauth/passkey-button"
import { TwoFactorChallenge } from "@/components/gotauth/two-factor-challenge"
import { TwoFactorSetup } from "@/components/gotauth/two-factor-setup"

import { SESSION, USER, expectAccessible, renderWith } from "./helpers"
import { BASE, server } from "./server"

const TOTP_URI = "otpauth://totp/Example:ada%40example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example"
const CODES = ["aaaa-bbbb", "cccc-dddd"]

afterEach(() => {
  vi.restoreAllMocks()
  vi.unstubAllGlobals()
})

function signedIn(user: Record<string, unknown> = USER, session: Record<string, unknown> = SESSION) {
  return http.get(`${BASE}/session`, () => HttpResponse.json({ user, session }))
}

function bodies() {
  const seen: Record<string, unknown> = {}
  const record = (path: string, reply: Parameters<typeof HttpResponse.json>[0]) =>
    http.post(`${BASE}${path}`, async ({ request }) => {
      seen[path] = await request.json()
      return HttpResponse.json(reply)
    })
  return { seen, record }
}

describe("TwoFactorSetup", () => {
  it("shows a local QR code, confirms a code and shows backup codes once", async () => {
    const { seen, record } = bodies()
    server.use(
      signedIn(),
      record("/two-factor/enable", { totp_uri: TOTP_URI, backup_codes: CODES }),
      record("/two-factor/verify-totp", { status: "enabled" }),
    )
    const onChange = vi.fn()
    const { container } = renderWith(<TwoFactorSetup onChange={onChange} />)
    await expectAccessible(container)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText("Password"), "correct horse")
    await user.click(screen.getByRole("button", { name: "Set up" }))
    expect(await screen.findByRole("img", { name: /authenticator app/ })).toBeTruthy()
    expect(screen.getByTestId("totp-secret").textContent).toBe("JBSWY3DPEHPK3PXP")
    expect(seen["/two-factor/enable"]).toEqual({ password: "correct horse" })
    await expectAccessible(container)
    const code = screen.getByLabelText("Code from the app")
    expect(code).toHaveProperty("autocomplete", "one-time-code")
    await user.type(code, "123456")
    await user.click(screen.getByRole("button", { name: "Turn on" }))
    const list = await screen.findByTestId("backup-codes")
    expect(list.textContent).toContain("aaaa-bbbb")
    expect(seen["/two-factor/verify-totp"]).toEqual({ code: "123456" })
    expect(onChange).toHaveBeenCalledWith(true)
    await user.click(screen.getByRole("button", { name: "Done" }))
    expect(screen.queryByTestId("backup-codes")).toBeNull()
    expect(container.textContent).not.toContain("aaaa-bbbb")
  })

  it("turns two-factor off and makes new backup codes when it is on", async () => {
    const { seen, record } = bodies()
    server.use(
      signedIn({ ...USER, two_factor_enabled: true }),
      record("/two-factor/disable", { status: "disabled" }),
      record("/two-factor/regenerate-backup-codes", { backup_codes: ["eeee-ffff"] }),
    )
    const onChange = vi.fn()
    renderWith(<TwoFactorSetup onChange={onChange} />)
    const user = userEvent.setup()
    await user.click(await screen.findByRole("button", { name: "Get new backup codes" }))
    expect((await screen.findByTestId("backup-codes")).textContent).toContain("eeee-ffff")
    await user.click(screen.getByRole("button", { name: "Done" }))
    await user.type(screen.getByLabelText("Password"), "correct horse")
    await user.click(screen.getByRole("button", { name: "Turn off two-factor" }))
    await waitFor(() => expect(onChange).toHaveBeenCalledWith(false))
    expect(seen["/two-factor/disable"]).toEqual({ password: "correct horse" })
  })

  it("finishes an enforced setup during sign-in without a password", async () => {
    server.use(
      http.get(`${BASE}/session`, () => HttpResponse.json(null)),
      http.post(`${BASE}/two-factor/enable`, () =>
        HttpResponse.json({ totp_uri: TOTP_URI, backup_codes: CODES }),
      ),
      http.post(`${BASE}/two-factor/verify-totp`, () =>
        HttpResponse.json({ user: USER, session: SESSION }),
      ),
    )
    const onSuccess = vi.fn()
    renderWith(
      <TwoFactorChallenge
        challenge={{ type: "two_factor_setup", methods: ["totp"] }}
        onSuccess={onSuccess}
      />,
    )
    expect(screen.queryByLabelText("Password")).toBeNull()
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Set up" }))
    await user.type(await screen.findByLabelText("Code from the app"), "123456")
    await user.click(screen.getByRole("button", { name: "Turn on" }))
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
    expect(await screen.findByTestId("backup-codes")).toBeTruthy()
  })
})

describe("TwoFactorChallenge", () => {
  it("verifies an authenticator code and can trust the device", async () => {
    const { seen, record } = bodies()
    server.use(record("/two-factor/verify-totp", { user: USER, session: SESSION }))
    const onSuccess = vi.fn()
    const { container } = renderWith(
      <TwoFactorChallenge
        challenge={{ type: "two_factor", methods: ["totp", "backup_code"] }}
        onSuccess={onSuccess}
      />,
    )
    await expectAccessible(container)
    const user = userEvent.setup()
    await user.type(screen.getByLabelText(/authenticator app/), "654321")
    await user.click(screen.getByLabelText("Don't ask again on this device"))
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
    expect(seen["/two-factor/verify-totp"]).toEqual({ code: "654321", trust_device: true })
  })

  it("switches to a backup code and shows wrong codes in the live region", async () => {
    server.use(
      http.post(`${BASE}/two-factor/verify-backup-code`, () =>
        HttpResponse.json(
          { error: { code: "TWO_FACTOR_INVALID_CODE", message: "The code is not valid" } },
          { status: 401 },
        ),
      ),
    )
    renderWith(
      <TwoFactorChallenge challenge={{ type: "two_factor", methods: ["totp", "backup_code"] }} />,
    )
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Use a backup code" }))
    await user.type(screen.getByLabelText("Backup code"), "aaaa-bbbb")
    await user.click(screen.getByRole("button", { name: "Continue" }))
    const region = await screen.findByRole("status")
    await waitFor(() => expect(region.textContent).toContain("didn't work"))
  })

  it("sends an email code before asking for it", async () => {
    const { seen, record } = bodies()
    let sent = 0
    server.use(
      http.post(`${BASE}/two-factor/send-otp`, () => {
        sent += 1
        return HttpResponse.json({ status: "sent" })
      }),
      record("/two-factor/verify-otp", { user: USER, session: SESSION }),
    )
    const onSuccess = vi.fn()
    renderWith(
      <TwoFactorChallenge
        challenge={{ type: "two_factor", methods: ["email_otp"] }}
        onSuccess={onSuccess}
      />,
    )
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Send code" }))
    await user.type(await screen.findByLabelText("Code from your email"), "111222")
    await user.click(screen.getByRole("button", { name: "Continue" }))
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
    expect(sent).toBe(1)
    expect(seen["/two-factor/verify-otp"]).toEqual({ code: "111222", trust_device: false })
  })
})

function bytes(...values: number[]): ArrayBuffer {
  return new Uint8Array(values).buffer
}

function fakeCredential() {
  return {
    id: "cred-1",
    type: "public-key",
    toJSON: () => ({ id: "cred-1", rawId: "cred-1", type: "public-key", response: {} }),
  }
}

describe("PasskeyButton", () => {
  it("signs in with a passkey", async () => {
    const { seen, record } = bodies()
    server.use(
      record("/passkey/sign-in/options", { challenge: "AQID", rpId: "localhost" }),
      record("/passkey/sign-in/verify", { user: USER, session: SESSION }),
      signedIn(),
    )
    vi.stubGlobal("PublicKeyCredential", class {})
    const get = vi.fn(async () => fakeCredential())
    vi.stubGlobal("navigator", { ...navigator, credentials: { get } })
    const onSuccess = vi.fn()
    const { container } = renderWith(<PasskeyButton onSuccess={onSuccess} />)
    await expectAccessible(container)
    const user = userEvent.setup()
    await user.click(screen.getByRole("button", { name: "Sign in with a passkey" }))
    await waitFor(() => expect(onSuccess).toHaveBeenCalledOnce())
    const options = (get.mock.calls[0] as unknown as [CredentialRequestOptions])[0].publicKey
    expect(new Uint8Array(options?.challenge as ArrayBuffer)).toEqual(new Uint8Array(bytes(1, 2, 3)))
    expect(seen["/passkey/sign-in/verify"]).toEqual({
      response: { id: "cred-1", rawId: "cred-1", type: "public-key", response: {} },
      remember_me: true,
    })
  })

  it("says so when the prompt is closed", async () => {
    server.use(
      http.post(`${BASE}/passkey/sign-in/options`, () =>
        HttpResponse.json({ challenge: "AQID", rpId: "localhost" }),
      ),
    )
    vi.stubGlobal("PublicKeyCredential", class {})
    vi.stubGlobal("navigator", {
      ...navigator,
      credentials: {
        get: vi.fn(async () => {
          throw new DOMException("cancelled", "NotAllowedError")
        }),
      },
    })
    renderWith(<PasskeyButton />)
    await userEvent.setup().click(screen.getByRole("button", { name: "Sign in with a passkey" }))
    expect(await screen.findByText(/prompt was closed/)).toBeTruthy()
  })

  it("adds a passkey with a name", async () => {
    const { seen, record } = bodies()
    const passkey = {
      id: "pk_1",
      name: "Laptop",
      credential_id: "cred-1",
      device_type: "multi_device",
      backed_up: true,
      transports: ["internal"],
      created_at: "2026-10-01T10:00:00Z",
      last_used_at: null,
    }
    server.use(
      record("/passkey/register/options", {
        challenge: "AQID",
        rp: { name: "Example", id: "localhost" },
        user: { id: "BAUG", name: "ada@example.com", displayName: "Ada" },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      }),
      record("/passkey/register/verify", passkey),
    )
    vi.stubGlobal("PublicKeyCredential", class {})
    const create = vi.fn(async () => fakeCredential())
    vi.stubGlobal("navigator", { ...navigator, credentials: { create } })
    const onRegistered = vi.fn()
    renderWith(<PasskeyButton mode="register" name="Laptop" onRegistered={onRegistered} />)
    await userEvent.setup().click(screen.getByRole("button", { name: "Add a passkey" }))
    await waitFor(() => expect(onRegistered).toHaveBeenCalledWith(passkey))
    const options = (create.mock.calls[0] as unknown as [CredentialCreationOptions])[0].publicKey
    expect(new Uint8Array(options?.user.id as ArrayBuffer)).toEqual(new Uint8Array(bytes(4, 5, 6)))
    expect(seen["/passkey/register/verify"]).toMatchObject({ name: "Laptop" })
  })

  it("is disabled where passkeys are not supported", async () => {
    vi.stubGlobal("PublicKeyCredential", undefined)
    renderWith(<PasskeyButton />)
    expect(screen.getByRole("button", { name: "Sign in with a passkey" })).toHaveProperty(
      "disabled",
      true,
    )
    expect(screen.getByText(/doesn't support passkeys/)).toBeTruthy()
  })
})

describe("OrgSwitcher", () => {
  it("lists organizations and switches the active one", async () => {
    let active: string | null = "org_2"
    const chosen: unknown[] = []
    server.use(
      http.get(`${BASE}/session`, () =>
        HttpResponse.json({ user: USER, session: { ...SESSION, active_organization_id: active } }),
      ),
      http.get(`${BASE}/organization/list`, () =>
        HttpResponse.json({
          organizations: [
            { id: "org_1", name: "Acme", slug: "acme", logo: null, metadata: {}, role: "owner", created_at: "2026-10-01T10:00:00Z" },
            { id: "org_2", name: "Globex", slug: "globex", logo: null, metadata: {}, role: "member", created_at: "2026-10-01T10:00:00Z" },
          ],
        }),
      ),
      http.post(`${BASE}/organization/set-active`, async ({ request }) => {
        const body = (await request.json()) as { organization_id: string | null }
        chosen.push(body)
        active = body.organization_id
        return HttpResponse.json(body)
      }),
    )
    const onSwitch = vi.fn()
    const onCreate = vi.fn()
    const { container } = renderWith(<OrgSwitcher onSwitch={onSwitch} onCreate={onCreate} />)
    const trigger = await screen.findByRole("button", { name: "Organization: Globex" })
    await expectAccessible(container)
    const user = userEvent.setup()
    await user.click(trigger)
    expect(await screen.findByRole("menuitemradio", { name: "Globex" })).toHaveProperty(
      "ariaChecked",
      "true",
    )
    await user.click(screen.getByRole("menuitemradio", { name: "Personal account" }))
    await waitFor(() => expect(onSwitch).toHaveBeenCalledWith(null))
    expect(chosen).toEqual([{ organization_id: null }])
    expect(await screen.findByRole("button", { name: "Organization: Personal account" })).toBeTruthy()
    await user.click(screen.getByRole("button", { name: "Organization: Personal account" }))
    await user.click(await screen.findByRole("menuitem", { name: "Create organization" }))
    expect(onCreate).toHaveBeenCalledOnce()
  })

  it("renders nothing when signed out", async () => {
    server.use(http.get(`${BASE}/session`, () => HttpResponse.json(null)))
    const { container } = renderWith(<OrgSwitcher />)
    await waitFor(() => expect(container.textContent).toBe(""))
  })
})

const CONSENT = {
  consent_id: "signed-consent",
  client: { client_id: "https://app.example/client.json", name: "Example MCP", host: "app.example" },
  scopes: ["projects:read", "openid"],
  resource: "https://api.example/mcp",
  redirect_host: "app.example",
  loopback_only: false,
}

describe("ConsentScreen", () => {
  it("is a native form that posts the consent, with no fetch", async () => {
    const fetchSpy = vi.spyOn(globalThis, "fetch")
    const { container } = renderWith(
      <ConsentScreen consent={CONSENT} scopeDescriptions={{ "projects:read": "See your projects" }} />,
    )
    await expectAccessible(container)
    const form = container.querySelector("form")
    expect(form?.getAttribute("method")).toBe("post")
    expect(form?.getAttribute("action")).toBe(`${BASE}/oauth2/consent`)
    expect(form?.enctype).toBe("application/x-www-form-urlencoded")
    expect((form?.querySelector('input[name="consent_id"]') as HTMLInputElement).value).toBe(
      "signed-consent",
    )
    const allow = screen.getByRole("button", { name: "Allow" })
    const deny = screen.getByRole("button", { name: "Deny" })
    expect([allow.getAttribute("name"), allow.getAttribute("value")]).toEqual(["accept", "true"])
    expect([deny.getAttribute("name"), deny.getAttribute("value")]).toEqual(["accept", "false"])
    expect(screen.getByTestId("redirect-host").textContent).toBe("app.example")
    expect(screen.getByText("See your projects")).toBeTruthy()
    expect(screen.getByText("https://api.example/mcp")).toBeTruthy()
    expect(screen.queryByTestId("loopback-warning")).toBeNull()
    expect(fetchSpy).not.toHaveBeenCalled()
  })

  it("warns about loopback-only clients, and only then", async () => {
    const { container } = renderWith(<ConsentScreen consent={{ ...CONSENT, loopback_only: true }} />)
    expect(screen.getByTestId("loopback-warning")).toBeTruthy()
    await expectAccessible(container)
  })
})

describe("ConnectedApps", () => {
  it("lists apps and revokes one", async () => {
    let grants = [
      {
        client_id: "cli_1",
        client_name: "Claude",
        scopes: ["projects:read"],
        resources: ["https://api.example/mcp"],
        created_at: "2026-10-01T10:00:00Z",
        last_used_at: null,
      },
    ]
    const revoked: unknown[] = []
    server.use(
      http.get(`${BASE}/oauth2/grants`, () => HttpResponse.json({ grants })),
      http.post(`${BASE}/oauth2/grants/revoke`, async ({ request }) => {
        revoked.push(await request.json())
        grants = []
        return HttpResponse.json({ revoked: 2 })
      }),
    )
    const { container } = renderWith(<ConnectedApps />)
    const button = await screen.findByRole("button", { name: "Revoke access for Claude" })
    await expectAccessible(container)
    await userEvent.setup().click(button)
    expect(await screen.findByText("No apps are connected.")).toBeTruthy()
    expect(revoked).toEqual([{ client_id: "cli_1" }])
    expect(screen.getByRole("status").textContent).toContain("Claude no longer has access")
  })
})
