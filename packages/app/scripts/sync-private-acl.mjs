// The app's CommonJS rootDir cannot import the router source. Keep one reviewed ACL policy
// and a checked-in exact copy; --check is the build gate and never rewrites source files.
import fs from "node:fs";
const canonical = new URL("../../router/src/windows-private-acl.ts", import.meta.url);
const generated = new URL("../src/windows-private-acl.ts", import.meta.url);
const expected = fs.readFileSync(canonical, "utf8");
if (process.argv.length === 3 && process.argv[2] === "--check") {
  if (fs.readFileSync(generated, "utf8") !== expected) throw new Error("App Windows ACL copy is stale; run npm run sync:private-acl --workspace @clauderipple/app");
} else if (process.argv.length === 2) {
  fs.writeFileSync(generated, expected);
} else throw new Error("Usage: sync-private-acl.mjs [--check]");
