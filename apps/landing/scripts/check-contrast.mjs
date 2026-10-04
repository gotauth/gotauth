// Checks WCAG 2.1 contrast for the color tokens in src/styles/global.css,
// in both the light (:root) and dark (prefers-color-scheme) themes.
// Usage: node scripts/check-contrast.mjs
import { readFileSync } from "node:fs";

const css = readFileSync(new URL("../src/styles/global.css", import.meta.url), "utf8");

const light = readTokens(css.slice(css.indexOf(":root {"), css.indexOf("@media (prefers-color-scheme: dark)")));
const darkStart = css.indexOf("@media (prefers-color-scheme: dark)");
const dark = { ...light, ...readTokens(css.slice(darkStart, css.indexOf("@layer reset {"))) };

// [foreground, background, minimum ratio, what it is]
const TEXT = 4.5;
const UI = 3;
const pairs = [
  ["ink", "paper", TEXT, "body text"],
  ["ink-2", "paper", TEXT, "secondary text"],
  ["ink", "paper-2", TEXT, "text on the waitlist band and table header"],
  ["ink-2", "paper-2", TEXT, "secondary text on the waitlist band"],
  ["accent", "paper", TEXT, "links"],
  ["accent", "paper-2", TEXT, "links on the waitlist band"],
  ["on-accent", "accent", TEXT, "primary button"],
  ["on-accent", "accent-hover", TEXT, "primary button, hover"],
  ["ink", "field-bg", TEXT, "input text"],
  ["error", "paper-2", TEXT, "field error"],
  ["success", "paper-2", TEXT, "success message"],
  ["badge-ink", "badge-bg", TEXT, "'Planned API' badge"],
  ["code-label", "paper", TEXT, "code file label"],
  ["paper-2", "error", UI, "error icon glyph"],
  ["paper-2", "success", UI, "success icon glyph"],
  ["focus", "paper", UI, "focus ring"],
  ["focus", "paper-2", UI, "focus ring on the waitlist band"],
  ["field-border", "field-bg", UI, "input border"],
  ["field-border", "paper-2", UI, "input border against the band"],
  ["error", "field-bg", UI, "invalid input border"],
  ["line-strong", "paper", UI, "secondary button border"],
  ...["tk-plain", "tk-comment", "tk-keyword", "tk-string", "tk-function", "tk-constant", "tk-type"].map(
    (token) => [token, "code-bg", TEXT, `code ${token}`],
  ),
];

let failed = 0;
for (const [theme, tokens] of [
  ["light", light],
  ["dark", dark],
]) {
  for (const [fg, bg, min, label] of pairs) {
    const ratio = contrast(tokens[fg], tokens[bg]);
    const ok = ratio >= min;
    if (!ok) failed++;
    console.log(`${ok ? "ok  " : "FAIL"} ${theme.padEnd(5)} ${ratio.toFixed(2).padStart(5)}:1 (>= ${min}) ${label}`);
  }
}
if (failed) {
  console.error(`\n${failed} contrast check(s) failed`);
  process.exit(1);
}
console.log("\nAll contrast checks passed");

function readTokens(block) {
  const tokens = {};
  for (const [, name, value] of block.matchAll(/--([a-z0-9-]+):\s*(#[0-9a-f]{6})\s*;/gi)) tokens[name] = value;
  return tokens;
}

function luminance(hex) {
  if (!hex) throw new Error("missing color token");
  const channels = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255);
  const [r, g, b] = channels.map((c) => (c <= 0.04045 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4));
  return 0.2126 * r + 0.7152 * g + 0.0722 * b;
}

function contrast(a, b) {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
}
