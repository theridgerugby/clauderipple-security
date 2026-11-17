// The app's CommonJS rootDir cannot import the router source. Keep the reviewed private-storage
// policies as exact generated copies; --check is the build gate and never rewrites source files.
import fs from "node:fs";
const check = process.argv.length === 3 && process.argv[2] === "--check";
if (!check && process.argv.length !== 2) throw new Error("Usage: sync-private-acl.mjs [--check]");
for (const name of ["windows-private-acl.ts", "secret-storage.ts"]) {
  const canonical = new URL(`../../router/src/${name}`, import.meta.url);
  const generated = new URL(`../src/${name}`, import.meta.url);
  const expected = fs.readFileSync(canonical, "utf8");
  if (check) {
    if (fs.readFileSync(generated, "utf8") !== expected) throw new Error(`App ${name} copy is stale; run npm run sync:private-acl --workspace @clauderipple/app`);
  } else fs.writeFileSync(generated, expected);
}
