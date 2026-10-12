// Recomputes every spec vector with implementations independent of GotAuth.
//
//   node spec/crosscheck.mjs
//
// Node's own crypto module recomputes HMAC, HKDF, AES-GCM, scrypt and SHA-256 values,
// and argon2id when this Node has crypto.argon2Sync (Node 24.7 and later). bcrypt
// hashes are checked with the C library's crypt(3) (libxcrypt) through Perl. A missing
// tool skips its cases and says so. Any mismatch prints the case and exits with 1.
//
// The parsing rules below mirror the Python kit on purpose: this file is also a small
// second implementation that shows the vectors are language-neutral.

import * as nodeCrypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, scryptSync } =
  nodeCrypto;
const here = dirname(fileURLToPath(import.meta.url));
const load = (name) => JSON.parse(readFileSync(join(here, `${name}.json`), "utf8"));

let checked = 0;
const failures = [];
const skipped = new Map();

function expect(file, index, what, actual, expected) {
  checked += 1;
  const same = JSON.stringify(actual) === JSON.stringify(expected);
  if (!same) {
    failures.push(`${file}[${index}] ${what}: got ${JSON.stringify(actual)}, want ${JSON.stringify(expected)}`);
  }
}

function skip(reason) {
  skipped.set(reason, (skipped.get(reason) ?? 0) + 1);
}

const utf8 = (text) => Buffer.from(text, "utf8");

// Strict decoders: unpadded, canonical text only.
function b64urlDecode(text) {
  if (!/^[A-Za-z0-9_-]*$/.test(text) || text.length % 4 === 1) return null;
  const raw = Buffer.from(text, "base64url");
  return raw.toString("base64url") === text ? raw : null;
}

function b64Decode(text) {
  if (!/^[A-Za-z0-9+/]*$/.test(text) || text.length % 4 === 1) return null;
  const raw = Buffer.from(text, "base64");
  return raw.toString("base64").replace(/=+$/, "") === text ? raw : null;
}

function b32Decode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of text.replace(/=+$/, "").toUpperCase()) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

function hotp(key, counter, digits) {
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(BigInt(counter));
  const mac = createHmac("sha1", key).update(message).digest();
  const offset = mac[mac.length - 1] & 0x0f;
  const value = mac.readUInt32BE(offset) & 0x7fffffff;
  return { mac: mac.toString("hex"), value, code: String(value % 10 ** digits).padStart(digits, "0") };
}

const deriveKey = (secret, purpose, length = 32) =>
  Buffer.from(hkdfSync("sha256", utf8(secret), Buffer.alloc(0), utf8(`gotauth:${purpose}`), length));

const signature = (secret, purpose, value) =>
  createHmac("sha256", deriveKey(secret, `sign:${purpose}`)).update(utf8(value)).digest("base64url");

function unsign(secrets, purpose, signed) {
  const dot = signed.lastIndexOf(".");
  if (dot < 0) return null;
  const value = signed.slice(0, dot);
  const given = signed.slice(dot + 1);
  return secrets.some((secret) => signature(secret, purpose, value) === given) ? value : null;
}

function encrypt(secret, purpose, plaintext, nonce) {
  const cipher = createCipheriv("aes-256-gcm", deriveKey(secret, "encrypt"), nonce);
  cipher.setAAD(utf8(purpose));
  const body = Buffer.concat([cipher.update(utf8(plaintext)), cipher.final(), cipher.getAuthTag()]);
  return `v1.${nonce.toString("base64url")}.${body.toString("base64url")}`;
}

function decrypt(secrets, purpose, text) {
  const parts = text.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const nonce = b64urlDecode(parts[1]);
  const body = b64urlDecode(parts[2]);
  if (nonce === null || body === null || nonce.length !== 12 || body.length < 16) return null;
  for (const secret of secrets) {
    try {
      const decipher = createDecipheriv("aes-256-gcm", deriveKey(secret, "encrypt"), nonce);
      decipher.setAAD(utf8(purpose));
      decipher.setAuthTag(body.subarray(body.length - 16));
      const plain = Buffer.concat([decipher.update(body.subarray(0, body.length - 16)), decipher.final()]);
      return new TextDecoder("utf-8", { fatal: true }).decode(plain);
    } catch {
      // Wrong key, purpose or bytes: try the next secret.
    }
  }
  return null;
}

let perlWorks = null;
function perlCrypt(password, setting) {
  if (perlWorks === null) {
    try {
      const probe = execFileSync("perl", ["-e", "print crypt($ARGV[0], $ARGV[1])", "x", "$2b$04$GotAuthSpecVectorSaltu"]);
      perlWorks = probe.toString("latin1").startsWith("$2b$04$");
    } catch {
      perlWorks = false;
    }
  }
  if (!perlWorks) return null;
  return execFileSync("perl", ["-e", "print crypt($ARGV[0], $ARGV[1])", password, setting]).toString("latin1");
}

const FAIL = { ok: false, needs_rehash: false };

// Mirrors the Python kit's verify_password with the default configuration (scrypt).
function verifyPassword(password, stored) {
  const dollar = stored.indexOf("$");
  if (dollar < 0) return FAIL;
  const tag = stored.slice(0, dollar);
  const body = stored.slice(dollar + 1);
  if (tag === "scrypt") {
    const parts = body.split("$");
    if (parts.length !== 3) return FAIL;
    const cost = /^ln=([1-9][0-9]?),r=([1-9][0-9]{0,2}),p=([1-9][0-9]{0,2})$/.exec(parts[0]);
    if (cost === null) return FAIL;
    const [ln, r, p] = cost.slice(1).map(Number);
    if (ln > 20 || r > 32 || p > 16 || 128 * r * 2 ** ln > 2 ** 30) return FAIL;
    const salt = b64Decode(parts[1]);
    const key = b64Decode(parts[2]);
    if (salt === null || key === null) return FAIL;
    if (salt.length < 8 || salt.length > 128 || key.length < 16 || key.length > 128) return FAIL;
    const maxmem = 128 * r * (2 ** ln + 2 + p) + 2 ** 26;
    const ok = scryptSync(utf8(password), salt, key.length, { N: 2 ** ln, r, p, maxmem }).equals(key);
    // The default since CONTRACT_VERSION 4 (CCR 004): ln=15, r=8, p=3.
    const standard = ln === 15 && r === 8 && p === 3 && salt.length === 16 && key.length === 64;
    return { ok, needs_rehash: ok && !standard };
  }
  if (tag === "bcrypt") {
    const match = /^\$2[aby]\$([0-9]{2})\$[./A-Za-z0-9]{53}$/.exec(body);
    if (match === null || Number(match[1]) < 4 || Number(match[1]) > 16) return FAIL;
    const computed = perlCrypt(password, body);
    if (computed === null) return { skip: "bcrypt: perl with a bcrypt-capable crypt(3) not found" };
    const ok = computed === body;
    return { ok, needs_rehash: ok };
  }
  if (tag === "argon2id") {
    const match = /^\$argon2id\$v=19\$m=([0-9]+),t=([0-9]+),p=([0-9]+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/.exec(body);
    if (match === null) return FAIL;
    const [memory, passes, parallelism] = match.slice(1, 4).map(Number);
    if (memory > 2 ** 20 || passes > 32 || parallelism > 32) return FAIL;
    if (typeof nodeCrypto.argon2Sync !== "function") {
      return { skip: "argon2id: this Node has no crypto.argon2Sync (Node 24.7 or later)" };
    }
    const nonce = b64Decode(match[4]);
    const hash = b64Decode(match[5]);
    if (nonce === null || hash === null) return FAIL;
    const computed = nodeCrypto.argon2Sync("argon2id", {
      message: utf8(password),
      nonce,
      parallelism,
      tagLength: hash.length,
      memory,
      passes,
    });
    const ok = Buffer.from(computed).equals(hash);
    // The default configuration hashes with scrypt, so a matching argon2id hash is outdated.
    return { ok, needs_rehash: ok };
  }
  return FAIL;
}

function crockford(value, length) {
  const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
  let rest = BigInt(value);
  let out = "";
  for (let i = 0; i < length; i += 1) {
    out = alphabet[Number(rest % 32n)] + out;
    rest /= 32n;
  }
  return out;
}

function checkExamples(file, index, test) {
  const pattern = new RegExp(test.regex);
  for (const example of test.valid_examples ?? []) expect(file, index, `regex accepts ${example}`, pattern.test(example), true);
  for (const example of test.invalid_examples ?? []) expect(file, index, `regex rejects ${example}`, pattern.test(example), false);
}

load("hotp").forEach((test, i) => {
  expect("hotp", i, "base32 secret", b32Decode(test.secret_b32).toString("hex"), test.secret_hex);
  expect("hotp", i, "ascii secret", utf8(test.secret_ascii).toString("hex"), test.secret_hex);
  const result = hotp(Buffer.from(test.secret_hex, "hex"), test.counter, test.digits);
  expect("hotp", i, "hmac", result.mac, test.hmac_sha1_hex);
  expect("hotp", i, "truncated", result.value, test.truncated_decimal);
  expect("hotp", i, "truncated hex", result.value, Number.parseInt(test.truncated_hex, 16));
  expect("hotp", i, "code", result.code, test.hotp);
});

load("totp").forEach((test, i) => {
  const step = Math.floor(test.unix_time / test.period);
  expect("totp", i, "time step", step.toString(16).toUpperCase().padStart(16, "0"), test.time_step_hex);
  expect("totp", i, "utc", new Date(test.unix_time * 1000).toISOString().replace(".000Z", "Z"), test.utc);
  expect("totp", i, "base32 secret", b32Decode(test.secret_b32).toString("hex"), test.secret_hex);
  expect("totp", i, "code", hotp(Buffer.from(test.secret_hex, "hex"), step, test.digits).code, test.totp);
});

load("pkce").forEach((test, i) => {
  const valid = /^[A-Za-z0-9._~-]{43,128}$/.test(test.verifier);
  const challenge = valid ? createHash("sha256").update(Buffer.from(test.verifier, "ascii")).digest("base64url") : null;
  expect("pkce", i, "challenge", challenge, test.challenge);
});

load("hkdf").forEach((test, i) => {
  if (test.kind === "rfc5869") {
    const ikm = Buffer.from(test.ikm_hex, "hex");
    const salt = Buffer.from(test.salt_hex, "hex");
    const info = Buffer.from(test.info_hex, "hex");
    const prk = createHmac("sha256", salt.length > 0 ? salt : Buffer.alloc(32)).update(ikm).digest("hex");
    expect("hkdf", i, "prk", prk, test.prk_hex);
    expect("hkdf", i, "okm", Buffer.from(hkdfSync("sha256", ikm, salt, info, test.length)).toString("hex"), test.okm_hex);
  } else {
    expect("hkdf", i, "info", utf8(`gotauth:${test.purpose}`).toString("hex"), test.info_hex);
    expect("hkdf", i, "okm", deriveKey(test.secret, test.purpose, test.length).toString("hex"), test.okm_hex);
  }
});

load("sign").forEach((test, i) => {
  if (test.kind === "sign") {
    expect("sign", i, "signed", `${test.value}.${signature(test.secrets[0], test.purpose, test.value)}`, test.signed);
    expect("sign", i, "round trip", unsign(test.secrets, test.purpose, test.signed), test.value);
  } else {
    expect("sign", i, "unsign", unsign(test.secrets, test.purpose, test.signed), test.value);
  }
});

load("encrypt").forEach((test, i) => {
  if (test.kind === "encrypt") {
    const nonce = Buffer.from(test.nonce_hex, "hex");
    expect("encrypt", i, "ciphertext", encrypt(test.secrets[0], test.purpose, test.plaintext, nonce), test.ciphertext);
    expect("encrypt", i, "round trip", decrypt(test.secrets, test.purpose, test.ciphertext), test.plaintext);
  } else {
    expect("encrypt", i, "decrypt", decrypt(test.secrets, test.purpose, test.ciphertext), test.plaintext);
  }
});

load("password-hash").forEach((test, i) => {
  if (test.kind === "scrypt") {
    const key = scryptSync(utf8(test.password), utf8(test.salt), test.dk_len, {
      N: test.n,
      r: test.r,
      p: test.p,
      maxmem: 2 ** 27,
    });
    expect("password-hash", i, "derived key", key.toString("hex"), test.derived_key_hex);
    return;
  }
  const result = verifyPassword(test.password, test.stored);
  if (result.skip) {
    skip(result.skip);
    return;
  }
  expect("password-hash", i, "verify", result, { ok: test.ok, needs_rehash: test.needs_rehash });
});

load("token-format").forEach((test, i) => {
  if (test.kind === "token") {
    expect("token-format", i, "body length", Math.ceil((test.nbytes * 4) / 3), test.body_length);
    checkExamples("token-format", i, test);
  } else if (test.kind === "token_encoding") {
    expect("token-format", i, "token", test.prefix + Buffer.from(test.random_hex, "hex").toString("base64url"), test.token);
  } else if (test.kind === "hash_token") {
    expect("token-format", i, "sha256", createHash("sha256").update(utf8(test.token)).digest("hex"), test.sha256_hex);
  } else if (test.kind === "ulid_time") {
    expect("token-format", i, "unix ms", Date.parse(test.at), test.unix_ms);
    expect("token-format", i, "time part", crockford(test.unix_ms, 10), test.time_part);
  } else {
    checkExamples("token-format", i, test);
  }
});

for (const [reason, count] of skipped) console.log(`skipped ${count} case(s): ${reason}`);
for (const failure of failures) console.log(`MISMATCH ${failure}`);
console.log(`crosscheck: ${checked} values checked, ${failures.length} mismatches`);
process.exit(failures.length === 0 ? 0 : 1);
