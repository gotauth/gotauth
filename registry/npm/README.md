# gotauth (JavaScript client)

A typed `fetch` client for [GotAuth](https://github.com/gotauth/gotauth), open-source auth for Python AI backends. The server side is the [`gotauth` Python package](https://pypi.org/project/gotauth/); this package talks to its HTTP API from browsers, Node 18+, Deno and Bun. No dependencies.

```bash
npm install gotauth
```

```ts
import { createGotAuthClient } from "gotauth"

const auth = createGotAuthClient({ baseURL: "/api/auth" })

const { data, error } = await auth.signInEmail({ email, password })
if (error) {
  console.log(error.code) // for example "INVALID_CREDENTIALS"
} else {
  console.log(data.user.email)
}

const keys = await auth.apiKeys.listApiKeys()
```

- **Cookies:** every request sends `credentials: "include"`, so the session cookie does the work. Tokens are never stored by the client.
- **Results:** each method returns `{ data, error }`; errors carry GotAuth's `code`, `message` and `status`, and network failures are `NETWORK_ERROR`.
- **Types:** request and response types mirror GotAuth's models; JSON fields stay snake_case.
- **Outside a browser:** pass an absolute `baseURL`, for example `http://localhost:8000/api/auth`.

React components (sign-in and sign-up forms, the user menu, the API key manager) are copy-in [shadcn registry items](https://github.com/gotauth/gotauth/tree/main/registry) that use this client.

Status: pre-alpha (`0.0.x`). The API can change between versions.

## License

MIT
