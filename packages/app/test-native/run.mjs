// A real Electron regression gate. Missing native dependencies fail this command; it never
// silently skips or opts out of Chromium's sandbox to make a CI/container run pass.
import fs from "node:fs";
import assert from "node:assert/strict";
import os from "node:os";
import path from "node:path";
import { createRequire } from "node:module";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";
import { ensureAdminTlsIdentity } from "../../router/src/admin-transport-state.ts";
import { ensureAdminToken } from "../../router/src/admin-auth.ts";
import { writePrivateFileAtomic, writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { verifySystemSandboxHelper } from "./linux-sandbox.mjs";

if (process.argv.length !== 2 || process.env.ELECTRON_DISABLE_SANDBOX || process.env.ELECTRON_RUN_AS_NODE ||
    process.getuid?.() === 0) throw new Error("Native security tests require an unmodified sandbox-enabled Electron process running as a normal user");
const require = createRequire(import.meta.url);
const executable = require("electron");
const { processIsRunning } = require("./diagnostic-tree.cjs");
// Ubuntu restricts unprivileged user namespaces for downloaded developer binaries. Use the
// runner's already-installed, root-owned Chrome helper when explicitly configured, without
// changing AppArmor/sysctls, installing setuid files, or disabling Chromium's sandbox.
if (process.platform === "linux" && process.env.CHROME_DEVEL_SANDBOX) {
  verifySystemSandboxHelper(process.env.CHROME_DEVEL_SANDBOX);
}
const fixture = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-security-"));
async function runElectron(script, home, extraEnv = {}) {
  const child = spawn(executable, [
    fileURLToPath(new URL(script, import.meta.url)),
    `--user-data-dir=${path.join(home, "profile")}`, "--enable-sandbox", "--no-first-run",
  ], { stdio: "inherit", env: { ...process.env, RIPPLE_NATIVE_FIXTURE: home, ...extraEnv }, windowsHide: true });
  let timedOut = false;
  const timer = setTimeout(() => { timedOut = true; child.kill(); }, 60_000);
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", (status, signal) => resolve(signal ? 1 : status ?? 1));
  }).finally(() => clearTimeout(timer));
  if (timedOut) throw new Error(`Native Electron ${script} test exceeded 60 seconds`);
  if (code !== 0) throw new Error(`Native Electron ${script} exited with ${code}`);
}
try {
  // Node 24 prepares real disposable, owner-protected TLS state before Electron starts. These
  // test-only CAs are never installed in an OS/browser trust store or used as release signers.
  ensureAdminTlsIdentity(fixture);
  ensureAdminToken(fixture);
  ensureAdminTlsIdentity(path.join(fixture, "rogue"));
  await runElectron("smoke.cjs", fixture);
  for (const scenario of ["missing", "invalid", "personal", "pending"]) {
    const home = path.join(fixture, `lifecycle-${scenario}`);
    fs.mkdirSync(home, { mode: 0o700 });
    if (scenario === "invalid") writePrivateFileAtomic(path.join(home, "config.json"), "{invalid");
    if (scenario === "personal") writeSecretJsonAtomic(path.join(home, "config.json"), { security: { mode: "personal", approvedOrigins: [] } });
    await runElectron("lifecycle.cjs", home, { RIPPLE_NATIVE_LIFECYCLE_CASE: scenario });
    if (scenario === "pending") {
      const pids = JSON.parse(fs.readFileSync(path.join(home, "diagnostic-processes.json"), "utf8"));
      assert.equal(Object.keys(pids).sort().join(","), "descendant,root");
      const deadline = Date.now() + 5000;
      while (Object.values(pids).some(processIsRunning) && Date.now() < deadline) {
        await new Promise(resolve => setTimeout(resolve, 25));
      }
      assert.equal(processIsRunning(pids.root), false, "closing the actual Electron app must leave no running owned diagnostic");
      assert.equal(processIsRunning(pids.descendant), false, "closing the actual Electron app must leave no running diagnostic grandchild");
      console.log("PASS native dashboard close cleaned its actual pending diagnostic process tree");
    }
  }
} finally {
  fs.rmSync(fixture, { recursive: true, force: true });
}
