// Installs the built registry items into the fixtures, the way `shadcn add` would:
// every file of every item in public/r goes to <fixture>/src/<target>. The shadcn
// primitives (button, card, ...) and lib/utils.ts come from this project's own copies,
// which `shadcn add` wrote, so the check needs no network.
import { cpSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs"
import { dirname, join } from "node:path"
import { fileURLToPath } from "node:url"

const root = join(dirname(fileURLToPath(import.meta.url)), "..")
const built = join(root, "public", "r")
const fixtures = ["next-app", "vite-react"]

const items = readdirSync(built)
  .filter((name) => name.endsWith(".json") && name !== "registry.json")
  .map((name) => JSON.parse(readFileSync(join(built, name), "utf8")))

for (const fixture of fixtures) {
  const src = join(root, "fixtures", fixture, "src")
  for (const dir of ["components", "lib", "hooks"]) rmSync(join(src, dir), { recursive: true, force: true })
  for (const item of items) {
    for (const file of item.files ?? []) {
      if (typeof file.content !== "string" || !file.target) {
        throw new Error(`${item.name}: built file without content or target`)
      }
      const target = join(src, file.target)
      mkdirSync(dirname(target), { recursive: true })
      writeFileSync(target, file.content)
    }
  }
  cpSync(join(root, "src", "components", "ui"), join(src, "components", "ui"), { recursive: true })
  cpSync(join(root, "src", "lib", "utils.ts"), join(src, "lib", "utils.ts"))
  console.log(`installed ${items.length} items into fixtures/${fixture}`)
}
