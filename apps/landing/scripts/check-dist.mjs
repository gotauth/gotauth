// Acceptance checks for the built site (run after `pnpm build`):
// - dist/ holds only static files
// - pages load nothing from a third-party origin; only the form may post to one
// - required SEO files and tags exist
// - the waitlist form (or the "opens soon" fallback) is wired correctly
// - every code snippet carries the "Planned API, may change" label and matches the plan
// - copy has no em or en dashes, emojis or banned filler words
// Usage: node scripts/check-dist.mjs
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const dist = join(root, "dist");
const SITE = "https://gotauth.dev";
const STATIC_EXT = new Set([".html", ".xml", ".txt", ".js", ".css", ".png", ".svg", ".ico", ".webmanifest", ""]);
// U+2013 en dash and U+2014 em dash, built from char codes so this file stays ASCII.
const DASHES = new RegExp(`[${String.fromCharCode(0x2013, 0x2014)}]`);
const FILLER = ["seamless", "robust", "leverage", "comprehensive", "unlock", "empower", "cutting-edge", "game-changer"];

const failures = [];
const fail = (message) => failures.push(message);
const pass = (message) => console.log(`ok   ${message}`);

if (!existsSync(dist)) {
  console.error("dist/ does not exist. Run `pnpm build` first.");
  process.exit(1);
}

// 1. Only static files.
const files = walk(dist);
const odd = files.filter((file) => !STATIC_EXT.has(extname(file)) || /(^|\/)_worker\.js$/.test(file));
if (odd.length) fail(`unexpected non-static files: ${odd.join(", ")}`);
else pass(`dist/ holds ${files.length} static files`);

// 2. No third-party resources.
const htmlFiles = files.filter((file) => file.endsWith(".html"));
let formOrigin;
for (const file of htmlFiles) {
  const html = read(file);
  const resources = [
    ...attrs(html, "script", "src"),
    ...attrs(html, "img", "src"),
    ...attrs(html, "img", "srcset"),
    ...attrs(html, "source", "src"),
    ...attrs(html, "source", "srcset"),
    ...attrs(html, "iframe", "src"),
    ...attrs(html, "video", "src"),
    ...attrs(html, "audio", "src"),
    ...attrs(html, "embed", "src"),
    ...attrs(html, "object", "data"),
    ...linkResources(html),
    ...[...html.matchAll(/url\(\s*['"]?([^'")]+)/g)].map((m) => m[1]),
    ...[...html.matchAll(/@import\s+(?:url\()?['"]?([^'");\s]+)/g)].map((m) => m[1]),
    ...metaContent(html, "og:image"),
  ];
  const external = resources.filter((url) => isThirdParty(url));
  if (external.length) fail(`${file} loads third-party resources: ${external.join(", ")}`);

  for (const action of attrs(html, "form", "action")) {
    if (!/^https:\/\//.test(action) && !/^http:\/\/(localhost|127\.0\.0\.1)[:/]/.test(action)) {
      fail(`${file}: form action is not https: ${action}`);
    }
    formOrigin = new URL(action).origin;
  }
}
for (const file of files.filter((f) => f.endsWith(".js") || f.endsWith(".css"))) {
  const urls = [...read(file).matchAll(/https?:\/\/[^\s"'`)]+/g)].map((m) => m[0]);
  const external = urls.filter((url) => isThirdParty(url) && !url.startsWith("http://www.w3.org/"));
  if (external.length) fail(`${file} references third-party URLs: ${external.join(", ")}`);
}
if (!failures.length) pass(`no third-party resources in ${htmlFiles.length} pages${formOrigin ? `; form posts to ${formOrigin}` : ""}`);

// 3. SEO and metadata.
for (const name of ["robots.txt", "sitemap-index.xml", "favicon.svg", "favicon-32.png", "apple-touch-icon.png", "og.png", "404.html"]) {
  if (!existsSync(join(dist, name))) fail(`missing dist/${name}`);
}
const og = readFileSync(join(dist, "og.png"));
if (og.readUInt32BE(16) !== 1200 || og.readUInt32BE(20) !== 630) fail("og.png is not 1200x630");
if (!read("robots.txt").includes(`Sitemap: ${SITE}/sitemap-index.xml`)) fail("robots.txt does not point to the sitemap");
const sitemap = files.filter((f) => /^sitemap-\d+\.xml$/.test(f)).map(read).join("");
if (!sitemap.includes(`<loc>${SITE}/</loc>`)) fail("sitemap does not list the home page");
if (/thanks|404/.test(sitemap)) fail("sitemap lists /thanks/ or 404");
for (const file of htmlFiles) {
  const html = read(file);
  const checks = {
    'lang="en"': /<html lang="en"/.test(html),
    "<title>": /<title>[^<]{10,}<\/title>/.test(html),
    "meta description": /<meta name="description" content="[^"]{20,}"/.test(html),
    "viewport": /<meta name="viewport"/.test(html),
    "color-scheme": /<meta name="color-scheme" content="light dark"/.test(html),
    "CSP meta": /<meta http-equiv="content-security-policy"/i.test(html),
    "og:image": metaContent(html, "og:image").includes(`${SITE}/og.png`),
  };
  if (file === "index.html") checks.canonical = html.includes(`<link rel="canonical" href="${SITE}/"`);
  else checks.noindex = html.includes('<meta name="robots" content="noindex"');
  const missing = Object.entries(checks).filter(([, ok]) => !ok).map(([name]) => name);
  if (missing.length) fail(`${file} is missing: ${missing.join(", ")}`);
}
pass("SEO files and meta tags");

// 4. Waitlist form.
const index = read("index.html");
const csp = /<meta http-equiv="content-security-policy" content="([^"]+)"/i.exec(index)?.[1] ?? "";
const forms = [...index.matchAll(/<form\b[^>]*>[\s\S]*?<\/form>/g)].map((m) => m[0]);
if (forms.length === 0) {
  if (!index.includes("Waitlist opens soon")) fail('no form and no "Waitlist opens soon" fallback');
  if (!/form-action 'none'/.test(csp)) fail("CSP should have form-action 'none' when there is no form");
  pass('no endpoint configured: "Waitlist opens soon" fallback with a GitHub link');
} else {
  const form = forms[0];
  const origin = new URL(attrs(form, "form", "action")[0]).origin;
  const expect = {
    'method="post"': /<form\b[^>]*method="post"/.test(form),
    "email input": /<input\b[^>]*name="email"[^>]*type="email"[^>]*required/.test(form),
    "label for the email input": /<label for="waitlist-email">/.test(form) && /id="waitlist-email"/.test(form),
    "aria-live error region": /id="waitlist-error"[^>]*aria-live="polite"|aria-live="polite"[^>]*id="waitlist-error"/.test(form),
    "status region": /role="status"/.test(form),
    "honeypot hidden with display: none": /<div class="honeypot">/.test(form) && /\.honeypot\{display:none\}/.test(index),
    "CSP form-action allows the endpoint": csp.includes(`form-action 'self' ${origin}`),
    "CSP connect-src allows the endpoint": csp.includes(`connect-src 'self' ${origin}`),
  };
  const missing = Object.entries(expect).filter(([, ok]) => !ok).map(([name]) => name);
  if (missing.length) fail(`waitlist form is missing: ${missing.join(", ")}`);
  else pass(`waitlist form posts to ${origin} and works without JavaScript`);
}

// 5. Code snippets.
const labels = index.match(/<figcaption class="badge">Planned API, may change<\/figcaption>/g) ?? [];
if (labels.length !== 3) fail(`expected 3 "Planned API, may change" labels, found ${labels.length}`);
const planPath = join(root, "../../docs/build-plan.md");
if (!existsSync(planPath)) {
  console.error("docs/build-plan.md not found: run this from a full checkout (the snippet check compares against it).");
  process.exit(1);
}
const plan = readFileSync(planPath, "utf8");
const fastapi = readFileSync(join(root, "src/snippets/fastapi.py"), "utf8");
const notInPlan = fastapi.split("\n").filter((line) => line.trim() && !plan.includes(line));
if (notInPlan.length) fail(`fastapi.py lines not in docs/build-plan.md: ${notInPlan.join(" | ")}`);
const required = {
  "fastapi.py": [
    'app.include_router(auth.fastapi.router(), prefix="/api/auth")',
    "CurrentUser = Annotated[User, Depends(auth.fastapi.current_user)]",
  ],
  "mcp.py": [
    "from gotauth.integrations.mcp import fastmcp_auth",
    '    auth=fastmcp_auth(auth, resource="https://mcp.example.com/mcp", scopes=["projects:read"]),',
  ],
  "api-keys.py": ["from gotauth.plugins.api_key import api_key", "plugins=[api_key()],"],
  "api-keys.sh": ['curl -H "x-api-key: gak_..."'],
};
// The API names that must match the plan exactly (the brief and the integrator list them).
const inPlan = [
  required["fastapi.py"][0],
  required["fastapi.py"][1],
  required["mcp.py"][0],
  required["mcp.py"][1],
  required["api-keys.py"][0],
];
for (const [name, lines] of Object.entries(required)) {
  const source = readFileSync(join(root, "src/snippets", name), "utf8");
  for (const line of lines) if (!source.includes(line)) fail(`src/snippets/${name} lacks: ${line}`);
  for (const line of lines) if (inPlan.includes(line) && !plan.includes(line)) fail(`not in docs/build-plan.md: ${line}`);
}
pass("3 snippets labelled; API lines match docs/build-plan.md");

// 6. Copy style: built pages, sources and the README.
const sources = [
  ...walk(join(root, "src")).map((f) => join("src", f)),
  ...walk(join(root, "scripts")).map((f) => join("scripts", f)),
  ...walk(join(root, "design")).map((f) => join("design", f)),
  "README.md",
  "astro.config.mjs",
  "package.json",
  ".env.example",
  "public/robots.txt",
  "public/_headers",
  "public/favicon.svg",
].map((f) => join(root, f));
const texts = [...htmlFiles.map((f) => join(dist, f)), ...sources].filter((f) => existsSync(f));
for (const file of texts) {
  const text = readFileSync(file, "utf8");
  const name = relative(root, file);
  if (DASHES.test(text)) fail(`${name} contains an en or em dash`);
  if (/\p{Extended_Pictographic}/u.test(text)) fail(`${name} contains an emoji or pictograph`);
  // The script's own word list is the only allowed mention.
  if (!name.endsWith("check-dist.mjs")) {
    const words = FILLER.filter((word) => new RegExp(`\\b${word}`, "i").test(text));
    if (words.length) fail(`${name} uses filler words: ${words.join(", ")}`);
  }
}
pass(`copy style in ${texts.length} files: no dashes, emojis or filler words`);

if (failures.length) {
  console.error(`\n${failures.length} check(s) failed:`);
  for (const message of failures) console.error(`FAIL ${message}`);
  process.exit(1);
}
console.log("\nAll dist checks passed");

function walk(dir) {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    return statSync(path).isDirectory() ? walk(path).map((f) => `${name}/${f}`) : [name];
  });
}

function read(file) {
  return readFileSync(join(dist, file), "utf8");
}

function attrs(html, tag, attr) {
  const pattern = new RegExp(`<${tag}\\b[^>]*\\s${attr}="([^"]*)"`, "gi");
  return [...html.matchAll(pattern)].flatMap((m) => (attr === "srcset" ? m[1].split(",").map((s) => s.trim().split(/\s+/)[0]) : [m[1]]));
}

function linkResources(html) {
  // Every <link> except navigation links (canonical) counts as a resource.
  return [...html.matchAll(/<link\b([^>]*)>/gi)]
    .map((m) => m[1])
    .filter((link) => !/rel="canonical"/.test(link))
    .map((link) => /href="([^"]*)"/.exec(link)?.[1])
    .filter(Boolean);
}

function metaContent(html, property) {
  const pattern = new RegExp(`<meta property="${property}" content="([^"]*)"`, "g");
  return [...html.matchAll(pattern)].map((m) => m[1]);
}

function isThirdParty(url) {
  if (!/^(https?:)?\/\//i.test(url)) return false; // relative or data: URL
  return new URL(url, SITE).origin !== SITE;
}
