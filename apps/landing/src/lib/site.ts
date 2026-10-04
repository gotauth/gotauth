// Build-time settings. Every value comes from a PUBLIC_ environment variable
// (see README.md and .env.example), so the same source builds for any host.

const env = import.meta.env;

/** The day the "Why now" numbers and the comparison table were last checked. */
export const LAST_CHECKED = "2026-10-03";

export const SITE_NAME = "GotAuth";

export const GITHUB_URL = clean(env.PUBLIC_GITHUB_URL) ?? "https://github.com/gotauth/gotauth";

export const LICENSE_URL = `${GITHUB_URL.replace(/\/$/, "")}/blob/main/LICENSE`;

export const ISSUES_URL = `${GITHUB_URL.replace(/\/$/, "")}/issues`;

export const CONTACT_EMAIL = clean(env.PUBLIC_CONTACT_EMAIL);

export interface WaitlistConfig {
  /** Where the form posts. Its origin is added to the page CSP. */
  endpoint: URL;
  /** Name of the hidden honeypot field the form service checks. */
  honeypot: string;
  /** Extra hidden fields the form service needs, such as an access key. */
  fields: [string, string][];
  /** Shown in the privacy note, e.g. "Formspree". */
  provider: string | undefined;
}

/** `undefined` when PUBLIC_WAITLIST_ENDPOINT is unset: the page then shows "Waitlist opens soon". */
export const WAITLIST: WaitlistConfig | undefined = readWaitlist();

function readWaitlist(): WaitlistConfig | undefined {
  const raw = clean(env.PUBLIC_WAITLIST_ENDPOINT);
  if (raw === undefined) return undefined;

  let endpoint: URL;
  try {
    endpoint = new URL(raw);
  } catch {
    throw new Error(`PUBLIC_WAITLIST_ENDPOINT is not a URL: ${raw}`);
  }
  const local = endpoint.hostname === "localhost" || endpoint.hostname === "127.0.0.1";
  if (endpoint.protocol !== "https:" && !(local && endpoint.protocol === "http:")) {
    // gotauth.dev is HTTPS only, and browsers block a form post from HTTPS to HTTP.
    throw new Error(`PUBLIC_WAITLIST_ENDPOINT must use https: ${raw}`);
  }

  const fields = [...new URLSearchParams(clean(env.PUBLIC_WAITLIST_FIELDS) ?? "")];
  const honeypot = clean(env.PUBLIC_WAITLIST_HONEYPOT) ?? "_gotcha";
  for (const [name] of fields) {
    if (name === "email" || name === honeypot) {
      throw new Error(`PUBLIC_WAITLIST_FIELDS must not set "${name}"`);
    }
  }

  if (CONTACT_EMAIL === undefined) {
    // The privacy note then sends removal requests to GitHub issues, which
    // are public. A contact address lets people ask privately.
    console.warn("PUBLIC_WAITLIST_ENDPOINT is set without PUBLIC_CONTACT_EMAIL: removal requests go to public GitHub issues.");
  }

  return { endpoint, honeypot, fields, provider: clean(env.PUBLIC_WAITLIST_PROVIDER) };
}

function clean(value: string | undefined): string | undefined {
  const trimmed = value?.trim();
  return trimmed ? trimmed : undefined;
}
