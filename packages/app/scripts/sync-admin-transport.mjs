// The app has an independent CommonJS rootDir. Keep the transport identical to the native CLI's.
import fs from "node:fs";

const source = new URL("../../router/src/admin-transport-client.ts", import.meta.url);
const target = new URL("../src/admin-transport-client.ts", import.meta.url);
const expected = fs.readFileSync(source, "utf8");
if (process.argv.includes("--check")) {
  if (!fs.existsSync(target) || fs.readFileSync(target, "utf8") !== expected) {
    throw new Error("app admin transport differs from canonical router transport; run node packages/app/scripts/sync-admin-transport.mjs");
  }
} else {
  fs.writeFileSync(target, expected);
}
