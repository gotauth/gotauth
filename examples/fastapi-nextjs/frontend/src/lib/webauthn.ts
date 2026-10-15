// base64url <-> ArrayBuffer helpers for WebAuthn options and responses.
// Uses the browser's JSON helpers when present, manual conversion otherwise.

export function base64urlToBuffer(value: string): ArrayBuffer {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/")
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i)
  return bytes.buffer
}

export function bufferToBase64url(value: ArrayBuffer | ArrayBufferView): string {
  const bytes =
    value instanceof ArrayBuffer
      ? new Uint8Array(value)
      : new Uint8Array(value.buffer, value.byteOffset, value.byteLength)
  let binary = ""
  for (const byte of bytes) binary += String.fromCharCode(byte)
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
}

type Descriptor = { id: string; type: string; transports?: string[] }

type CreationJSON = {
  challenge: string
  user: { id: string; name: string; displayName: string }
  excludeCredentials?: Descriptor[]
  [key: string]: unknown
}

type RequestJSON = {
  challenge: string
  allowCredentials?: Descriptor[]
  [key: string]: unknown
}

type JsonHelpers = {
  parseCreationOptionsFromJSON?: (json: unknown) => PublicKeyCredentialCreationOptions
  parseRequestOptionsFromJSON?: (json: unknown) => PublicKeyCredentialRequestOptions
}

function helpers(): JsonHelpers {
  const pkc = (globalThis as { PublicKeyCredential?: unknown }).PublicKeyCredential
  return (pkc ?? {}) as JsonHelpers
}

function descriptors(list: Descriptor[] | undefined): PublicKeyCredentialDescriptor[] | undefined {
  return list?.map((item) => ({
    ...item,
    id: base64urlToBuffer(item.id),
    type: "public-key",
    transports: item.transports as AuthenticatorTransport[] | undefined,
  }))
}

export function creationOptionsFromJSON(json: CreationJSON): PublicKeyCredentialCreationOptions {
  const parse = helpers().parseCreationOptionsFromJSON
  if (parse) return parse(json)
  return {
    ...(json as unknown as PublicKeyCredentialCreationOptions),
    challenge: base64urlToBuffer(json.challenge),
    user: { ...json.user, id: base64urlToBuffer(json.user.id) },
    excludeCredentials: descriptors(json.excludeCredentials),
  }
}

export function requestOptionsFromJSON(json: RequestJSON): PublicKeyCredentialRequestOptions {
  const parse = helpers().parseRequestOptionsFromJSON
  if (parse) return parse(json)
  return {
    ...(json as unknown as PublicKeyCredentialRequestOptions),
    challenge: base64urlToBuffer(json.challenge),
    allowCredentials: descriptors(json.allowCredentials),
  }
}

/** Serialize a credential from navigator.credentials.create or get for the server. */
export function credentialToJSON(credential: PublicKeyCredential): object {
  const withJSON = credential as Omit<PublicKeyCredential, "toJSON"> & {
    toJSON?: () => object
  }
  if (typeof withJSON.toJSON === "function") return withJSON.toJSON()
  const response = credential.response as AuthenticatorResponse & Record<string, unknown>
  const encoded: Record<string, unknown> = {}
  for (const key of [
    "clientDataJSON",
    "attestationObject",
    "authenticatorData",
    "signature",
    "userHandle",
  ]) {
    const value = response[key]
    if (value instanceof ArrayBuffer) encoded[key] = bufferToBase64url(value)
  }
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    response: encoded,
    authenticatorAttachment: credential.authenticatorAttachment ?? null,
    clientExtensionResults: credential.getClientExtensionResults(),
  }
}
