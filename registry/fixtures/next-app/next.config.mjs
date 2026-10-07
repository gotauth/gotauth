import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const here = dirname(fileURLToPath(import.meta.url))

/** @type {import("next").NextConfig} */
export default {
  // The fixture uses the registry project's node_modules, two levels up.
  turbopack: { root: join(here, "..", "..") },
  outputFileTracingRoot: join(here, "..", ".."),
}
