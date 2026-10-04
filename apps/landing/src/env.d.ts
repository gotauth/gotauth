interface ImportMetaEnv {
  /** Form backend URL. Unset: the page shows "Waitlist opens soon". */
  readonly PUBLIC_WAITLIST_ENDPOINT?: string;
  /** Honeypot field name the form backend checks. Default: _gotcha. */
  readonly PUBLIC_WAITLIST_HONEYPOT?: string;
  /** Extra hidden fields, URL-encoded: "access_key=abc&subject=Waitlist". */
  readonly PUBLIC_WAITLIST_FIELDS?: string;
  /** Form backend name shown in the privacy note, e.g. "Formspree". */
  readonly PUBLIC_WAITLIST_PROVIDER?: string;
  /** Repository link. Default: https://github.com/gotauth/gotauth */
  readonly PUBLIC_GITHUB_URL?: string;
  /** Contact address shown in the footer and the privacy note. */
  readonly PUBLIC_CONTACT_EMAIL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
