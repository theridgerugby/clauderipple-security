// A real Electron regression gate. Missing native dependencies fail this command; it never
// silently skips or opts out of Chromium's sandbox to make a CI/container run pass.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { ensureAdminTlsIdentity } from "../../router/src/admin-transport-state.ts";
import { ensureAdminToken } from "../../router/src/admin-auth.ts";
import { verifySystemSandboxHelper } from "./linux-sandbox.mjs";

if (process.argv.length !== 2 || process.env.ELECTRON_DISABLE_SANDBOX || process.env.ELECTRON_RUN_AS_NODE ||
    process.getuid?.() === 0) throw new Error("Native security tests require an unmodified sandbox-enabled Electron process running as a normal user");
const require = createRequire(import.meta.url);
const executable = require("electron");
// Ubuntu restricts unprivileged user namespaces for downloaded developer binaries. Use the
// runner's already-installed, root-owned Chrome helper when explicitly configured, without
// changing AppArmor/sysctls, installing setuid files, or disabling Chromium's sandbox.
if (process.platform === "linux" && process.env.CHROME_DEVEL_SANDBOX) {
  verifySystemSandboxHelper(process.env.CHROME_DEVEL_SANDBOX);
}
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-security-"));
try {
  // Node 24 prepares real disposable, owner-protected TLS state before Electron starts. These
  // test-only CAs are never installed in an OS/browser trust store or used as release signers.
  ensureAdminTlsIdentity(fixture);
  ensureAdminToken(fixture);
  ensureAdminTlsIdentity(path.join(fixture, "rogue"));
  const child = spawn(executable, [
    fileURLToPath(new URL("smoke.cjs", import.meta.url)),
    `--user-data-dir=${path.join(fixture, "profile")}`, "--enable-sandbox", "--no-first-run",
  ], { stdio: "inherit", env: { ...process.env, RIPPLE_NATIVE_FIXTURE: fixture }, windowsHide: true });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, 60_000);
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (status, signal) => resolve(signal ? 1 : status ?? 1));
  }).finally(() => clearTimeout(timer));
  if (timedOut) throw new Error("Native Electron security test exceeded 60 seconds");
  process.exitCode = code;
} finally {
  fs.rmSync(fixture, { recursive: true, force: true });
}
