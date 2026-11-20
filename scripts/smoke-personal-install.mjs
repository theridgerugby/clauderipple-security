// Execute the actual lean compiled entrypoints against disposable empty state. This does not
// register a service, change a trust store, open the native UI or use a real account/provider.
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { verifyPersonalInstall } from "./check-personal-install.mjs";
import { verifyBuiltPersonalRuntime } from "./build-personal.mjs";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

export async function smokePersonalInstall(root = checkout) {
  const installed = verifyPersonalInstall(root);
  const built = verifyBuiltPersonalRuntime(path.join(root, "dist"));
  const state = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-smoke-"));
  const env = {
    PATH: path.dirname(process.execPath), HOME: state, USERPROFILE: state,
    APPDATA: path.join(state, "appdata"), LOCALAPPDATA: path.join(state, "localappdata"),
    CLAUDERIPPLE_HOME: path.join(state, "router"), RIPPLE_REMOTE_HOME: path.join(state, "remote"),
    NODE_PATH: "", NODE_OPTIONS: "",
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}),
  };
  try {
    const cli = path.join(root, "dist/cli/src/index.js");
    const router = path.join(root, "dist/router/src/index.js");
    const help = execFileSync(process.execPath, [cli, "--help"], { cwd: state, env, encoding: "utf8", timeout: 20_000 });
    assert.match(help, /clauderipple/);
    assert.deepEqual(fs.readdirSync(state), [], "CLI help must not write any application or account state");
    const { runtime } = await import(pathToFileURL(path.join(root, "dist/cli/src/runtime.js")).href);
    const rt = runtime();
    assert.equal(rt.cli, cli);
    assert.equal(rt.router, router);
    const { captureRouterCodeIdentity } = await import(pathToFileURL(path.join(root, "dist/cli/src/install-runtime.js")).href);
    const fingerprint = captureRouterCodeIdentity(rt);
    assert.match(fingerprint.sha256, /^[a-f0-9]{64}$/);
    assert.deepEqual(captureRouterCodeIdentity(rt), fingerprint, "compiled runtime identity must be stable");

    // Missing certificates are checked before opening listeners or reaching provider traffic.
    // This proves module resolution and early fail-closed startup, not live Desktop routing.
    const result = spawnSync(process.execPath, [router], { cwd: state, env, encoding: "utf8", timeout: 20_000 });
    assert.ifError(result.error);
    assert.equal(result.status, 2, "an empty personal installation must fail closed");
    // Personal logging deliberately keeps the certificate diagnostic in memory only.
    assert.match(result.stderr + result.stdout, /config is missing or inaccessible/);
    assert.doesNotMatch(result.stderr + result.stdout, /ERR_MODULE_NOT_FOUND|MODULE_NOT_FOUND/);
    return { packages: installed.packages, dependencyBytes: installed.bytes, buildFiles: built.files, buildBytes: built.bytes,
      compiledCliHelp: "passed without state writes", runtimeFingerprint: "passed", emptyStateRouter: "failed closed as expected",
      nativeDesktop: "not exercised", electronBinaryInstalled: installed.electronBinaryInstalled };
  } finally { fs.rmSync(state, { recursive: true, force: true }); }
}

if (import.meta.main) {
  try { console.log(JSON.stringify(await smokePersonalInstall(), null, 2)); }
  catch (error) { console.error(error.message); process.exitCode = 1; }
}
