// A stand-in form backend for local testing:
// - JSON response for fetch() posts (Accept: application/json), with CORS
// - a redirect to THANKS_URL (or a plain page) for posts without JavaScript
// - a filled honeypot field is ignored, never stored
// Every accepted or ignored post is printed as one JSON line.
//
// RESPONSE picks the JSON answer to a valid fetch() post:
//   formspree (default)  200 {"ok": true}
//   web3forms            200 {"success": true, ...}
//   reject               200 {"success": false, ...}  (a 2xx that is still a failure)
//   text                 200 with a plain-text body
//
// Usage: PORT=8787 HONEYPOT=_gotcha RESPONSE=formspree THANKS_URL=http://localhost:4321/thanks/ node scripts/mock-waitlist.mjs
import { createServer } from "node:http";

const port = Number(process.env.PORT ?? 8787);
const honeypot = process.env.HONEYPOT ?? "_gotcha";
const thanksUrl = process.env.THANKS_URL;
const mode = process.env.RESPONSE ?? "formspree";
const ANSWERS = {
  formspree: { ok: true, next: "/thanks" },
  web3forms: { success: true, message: "Email sent successfully!" },
  reject: { success: false, message: "Something went wrong." },
};
if (mode !== "text" && !(mode in ANSWERS)) throw new Error(`unknown RESPONSE: ${mode}`);

const server = createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Accept, Content-Type");
  if (req.method === "OPTIONS") return void res.writeHead(204).end();
  if (req.method !== "POST") return void res.writeHead(405, { Allow: "POST" }).end();

  let body = "";
  for await (const chunk of req) body += chunk;
  const type = req.headers["content-type"] ?? "";
  const fields = type.includes("multipart/form-data") ? parseMultipart(body, type) : new URLSearchParams(body);
  const email = fields.get("email") ?? "";
  const bot = Boolean(fields.get(honeypot));
  const valid = /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email);

  const rejected = wantsJson(req) && mode === "reject";
  console.log(
    JSON.stringify({ via: wantsJson(req) ? "fetch" : "form", email, honeypotFilled: bot, stored: valid && !bot && !rejected }),
  );

  if (wantsJson(req)) {
    if (!valid) {
      res.writeHead(422, { "Content-Type": "application/json" });
      return void res.end(JSON.stringify({ errors: [{ field: "email", message: "invalid" }] }));
    }
    // Like Formspree, a bot gets the same answer as a person and nothing is stored.
    if (mode === "text") return void res.writeHead(200, { "Content-Type": "text/plain" }).end("Received");
    res.writeHead(200, { "Content-Type": "application/json" });
    return void res.end(JSON.stringify(ANSWERS[mode]));
  }
  if (thanksUrl && valid) return void res.writeHead(303, { Location: thanksUrl }).end();
  res.writeHead(valid ? 200 : 422, { "Content-Type": "text/html; charset=utf-8" });
  res.end(`<!doctype html><title>Mock form backend</title><p>${valid ? "Received" : "Invalid email"}</p>`);
});

server.listen(port, () => console.log(`mock waitlist endpoint on http://localhost:${port}/submit`));

function wantsJson(req) {
  return (req.headers.accept ?? "").includes("application/json");
}

function parseMultipart(body, type) {
  const boundary = /boundary=(?:"([^"]+)"|([^;]+))/.exec(type);
  const fields = new URLSearchParams();
  if (!boundary) return fields;
  for (const part of body.split(`--${boundary[1] ?? boundary[2]}`)) {
    const match = /name="([^"]+)"\r\n\r\n([\s\S]*?)\r\n$/.exec(part);
    if (match) fields.append(match[1], match[2]);
  }
  return fields;
}
