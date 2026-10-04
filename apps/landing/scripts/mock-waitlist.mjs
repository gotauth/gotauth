// A stand-in form backend for local testing. It behaves like Formspree:
// - JSON response for fetch() posts (Accept: application/json), with CORS
// - a redirect to THANKS_URL (or a plain page) for posts without JavaScript
// - a filled honeypot field is ignored, never stored
// Every accepted or ignored post is printed as one JSON line.
//
// Usage: PORT=8787 HONEYPOT=_gotcha THANKS_URL=http://localhost:4321/thanks/ node scripts/mock-waitlist.mjs
import { createServer } from "node:http";

const port = Number(process.env.PORT ?? 8787);
const honeypot = process.env.HONEYPOT ?? "_gotcha";
const thanksUrl = process.env.THANKS_URL;

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

  console.log(JSON.stringify({ via: wantsJson(req) ? "fetch" : "form", email, honeypotFilled: bot, stored: valid && !bot }));

  if (wantsJson(req)) {
    // Like Formspree, a bot gets the same success answer and nothing is stored.
    res.writeHead(valid ? 200 : 422, { "Content-Type": "application/json" });
    return void res.end(JSON.stringify(valid ? { ok: true } : { errors: [{ field: "email", message: "invalid" }] }));
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
