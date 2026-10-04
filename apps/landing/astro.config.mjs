// @ts-check
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

const site = "https://gotauth.dev";

export default defineConfig({
  site,
  output: "static",
  trailingSlash: "ignore",
  build: {
    // One small stylesheet: inlining it saves a render-blocking request.
    inlineStylesheets: "always",
  },
  // No dev toolbar: it injects scripts that the production page never has.
  devToolbar: { enabled: false },
  // No Markdown pages. Code blocks use <Code /> with a transformer that
  // replaces Shiki's inline styles, so they pass the CSP below.
  markdown: { syntaxHighlight: false },
  integrations: [
    sitemap({
      // /thanks/ is only reached after a form post, and 404 is not a page.
      filter: (page) => !page.includes("/thanks") && !page.includes("/404"),
    }),
  ],
  security: {
    // Astro hashes its own scripts and styles into a CSP <meta> tag.
    // src/layouts/Base.astro adds connect-src and form-action for the
    // configured waitlist endpoint, so the policy always matches the form.
    csp: {
      algorithm: "SHA-256",
      directives: [
        "default-src 'none'",
        "img-src 'self'",
        "base-uri 'none'",
      ],
    },
  },
});
