import { describe, expect, it } from "vitest"

import {
  base64urlToBuffer,
  bufferToBase64url,
  creationOptionsFromJSON,
  requestOptionsFromJSON,
} from "@/lib/webauthn"

describe("webauthn helpers", () => {
  it("round-trips random byte arrays", () => {
    for (let length = 0; length < 200; length += 7) {
      const bytes = crypto.getRandomValues(new Uint8Array(length))
      const encoded = bufferToBase64url(bytes)
      expect(encoded).toMatch(/^[A-Za-z0-9_-]*$/)
      expect(new Uint8Array(base64urlToBuffer(encoded))).toEqual(bytes)
    }
  })

  it("converts options without the browser JSON helpers", () => {
    const challenge = bufferToBase64url(new Uint8Array([1, 2, 3]))
    const creation = creationOptionsFromJSON({
      challenge,
      rp: { name: "Acme" },
      user: { id: bufferToBase64url(new Uint8Array([9])), name: "ada", displayName: "Ada" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
      excludeCredentials: [{ id: challenge, type: "public-key" }],
    })
    expect(new Uint8Array(creation.challenge as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]))
    expect(new Uint8Array(creation.user.id as ArrayBuffer)).toEqual(new Uint8Array([9]))
    const request = requestOptionsFromJSON({ challenge, allowCredentials: [{ id: challenge, type: "public-key" }] })
    expect(new Uint8Array(request.allowCredentials?.[0]?.id as ArrayBuffer)).toEqual(new Uint8Array([1, 2, 3]))
  })
})
