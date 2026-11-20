// The Electron app has an independent CommonJS rootDir. Keep owned diagnostic cleanup identical
// to the CLI helper, including its Windows guard against taskkill after direct-child exit.
import fs from "node:fs";

const args = process.argv.slice(2);
if (args.length > 1 || (args.length === 1 && args[0] !== "--check")) {
  throw new Error("Usage: node sync-bounded-exec.mjs [--check]");
}
const source = new URL("../../cli/src/bounded-exec.ts", import.meta.url);
const target = new URL("../src/bounded-exec.ts", import.meta.url);
const expected = fs.readFileSync(source, "utf8");
if (args[0] === "--check") {
  if (!fs.existsSync(target) || fs.readFileSync(target, "utf8") !== expected) {
    throw new Error("app bounded exec differs from canonical CLI helper; run node packages/app/scripts/sync-bounded-exec.mjs");
  }
} else {
  fs.writeFileSync(target, expected);
}
