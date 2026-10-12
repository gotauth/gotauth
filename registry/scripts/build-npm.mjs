// Builds the npm package "@gotauth/client" (registry/npm) from src/lib/gotauth-client.ts, then
// imports the result and makes one call with a fake fetch, so a broken build fails here.
import { execFileSync } from "node:child_process"
import { copyFileSync, readFileSync, rmSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")
const npm = join(root, "npm")

rmSync(join(npm, "dist"), { recursive: true, force: true })
execFileSync(join(root, "node_modules", ".bin", "tsc"), ["-p", join(npm, "tsconfig.json")], {
  stdio: "inherit",
})
copyFileSync(join(root, "..", "LICENSE"), join(npm, "LICENSE"))

const pkg = JSON.parse(readFileSync(join(npm, "package.json"), "utf8"))
const entry = join(npm, pkg.exports["."].default)
const client = await import(pathToFileURL(entry).href)
if (typeof client.createGotAuthClient !== "function") {
  throw new Error("createGotAuthClient is not exported")
}
const seen = []
const fakeFetch = async (url, init) => {
  seen.push({ url, init })
  return new Response(JSON.stringify({ session: { id: "ses_1" }, user: { id: "usr_1" } }), {
    status: 200,
    headers: { "content-type": "application/json" },
  })
}
const auth = client.createGotAuthClient({ baseURL: "http://localhost:8000/api/auth/", fetch: fakeFetch })
const result = await auth.getSession()
if (result.error || result.data.user.id !== "usr_1") throw new Error("getSession did not return data")
if (seen[0].url !== "http://localhost:8000/api/auth/session") throw new Error(`unexpected URL ${seen[0].url}`)
if (seen[0].init.credentials !== "include") throw new Error("credentials are not included")
console.log(`built ${pkg.name}@${pkg.version}: ${entry}`)
