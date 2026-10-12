import type { NextConfig } from "next"

// The browser only ever talks to this origin. Requests under /api go to FastAPI, so
// GotAuth's cookies, the OAuth callback and the API share one origin: no CORS.
// Rewrites are fixed at build time; the Docker build sets BACKEND_URL.
const backend = process.env.BACKEND_URL ?? "http://localhost:8000"

const config: NextConfig = {
  async rewrites() {
    return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }]
  },
}

export default config
