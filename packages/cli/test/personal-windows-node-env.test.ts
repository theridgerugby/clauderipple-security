import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { renderLauncher } from "../src/schtasks.ts";
import { runtime } from "../src/runtime.ts";
import {
  PERSONAL_WINDOWS_UNTRUSTED_ENV, assertPersonalWindowsNodeEnv, personalWindowsNodeEnvProblems,
} from "../../router/src/windows-node-env.ts";

test("personal Windows Node guard refuses altered TLS, extra CAs, proxy delegation and injected code", () => {
  const env: NodeJS.ProcessEnv = {
    NODE_TLS_REJECT_UNAUTHORIZED: "0", NODE_EXTRA_CA_CERTS: "PRIVATE-SYNTHETIC-CA-PATH",
    NODE_OPTIONS: "--import=PRIVATE-SYNTHETIC-LOADER", NODE_USE_ENV_PROXY: "1",
    NODE_USE_SYSTEM_CA: "1", SSL_CERT_FILE: "PRIVATE-SYNTHETIC-SSL-PATH",
    SSL_CERT_DIR: "PRIVATE-SYNTHETIC-SSL-DIR", OPENSSL_CONF: "PRIVATE-SYNTHETIC-OPENSSL",
    SSLKEYLOGFILE: "PRIVATE-SYNTHETIC-KEYLOG", NODE_DEBUG: "http,tls",
    NODE_V8_COVERAGE: "PRIVATE-SYNTHETIC-COVERAGE", HTTPS_PROXY: "https://PRIVATE-SYNTHETIC-PROXY",
    http_proxy: "http://PRIVATE-SYNTHETIC-PROXY-LOWER",
  };
  const problems = personalWindowsNodeEnvProblems(env, ["--tls-keylog=PRIVATE-SYNTHETIC-SESSIONS"]);
  for (const name of ["NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS", "NODE_OPTIONS",
    "NODE_USE_ENV_PROXY", "NODE_USE_SYSTEM_CA", "SSL_CERT_FILE", "SSL_CERT_DIR",
    "OPENSSL_CONF", "SSLKEYLOGFILE", "NODE_DEBUG", "NODE_V8_COVERAGE", "HTTPS_PROXY", "HTTP_PROXY", "Node startup flags"]) {
    assert.ok(problems.includes(name), `${name} is rejected`);
  }
  let message = "";
  try { assertPersonalWindowsNodeEnv(env, ["--tls-keylog=PRIVATE-SYNTHETIC-SESSIONS"]); }
  catch (error) { message = (error as Error).message; }
  assert.match(message, /refused unsafe startup settings/);
  assert.doesNotMatch(message, /PRIVATE-SYNTHETIC|--tls-keylog/);
  assert.deepEqual(personalWindowsNodeEnvProblems({ NODE_TLS_REJECT_UNAUTHORIZED: "1",
    NODE_USE_SYSTEM_CA: "0", NODE_USE_ENV_PROXY: "0", NODE_OPTIONS: "" }), []);
});

test("scheduled Windows launcher removes every untrusted ambient variable before its first Node child", () => {
  const script = renderLauncher({ program: "C:\\Program Files\\nodejs\\node.exe",
    args: ["C:\\source\\router.ts"], home: "C:\\private-home" });
  const start = script.indexOf("Start-Process -FilePath");
  const reader = script.indexOf("function Get-AdminPort {");
  assert.ok(start > 0 && reader > 0);
  for (const name of PERSONAL_WINDOWS_UNTRUSTED_ENV) {
    const clear = `Remove-Item -LiteralPath 'Env:${name}' -ErrorAction SilentlyContinue`;
    const i = script.indexOf(clear);
    assert.ok(i > 0 && i < reader && i < start, `${name} must be cleared before Node starts`);
  }
  assert.ok(script.indexOf("$env:CLAUDERIPPLE_HOME = 'C:\\private-home'") > script.indexOf("Env:NODE_OPTIONS"));
  assert.doesNotMatch(script, /PRIVATE-SYNTHETIC/);
  assert.throws(() => renderLauncher({ program: "C:\\node.exe", args: [], home: "C:\\home",
    env: { NODE_OPTIONS: "--import=PRIVATE-SYNTHETIC-LOADER" } }), /NODE_OPTIONS/);
  assert.throws(() => renderLauncher({ program: "C:\\node.exe", args: [], home: "C:\\home",
    env: { "HTTPS_PROXY": "https://PRIVATE-SYNTHETIC-PROXY" } }), /HTTPS_PROXY/);
  assert.throws(() => renderLauncher({ program: "C:\\node.exe", args: [], home: "C:\\home",
    env: { "NODE_OPTIONS;Write-Host": "PRIVATE-SYNTHETIC" } }), /invalid environment variable name/);
});

test("native Windows PowerShell clears hostile inherited settings before spawning Node", {
  skip: process.platform !== "win32", timeout: 30_000,
}, () => {
  const launcher = renderLauncher({ program: "C:\\node.exe", args: ["C:\\router.ts"], home: "C:\\fixture-home" });
  const prelude = launcher.slice(1, launcher.indexOf("$routerArgs = @("));
  const script = prelude + "\r\n" +
    "if ($env:NODE_OPTIONS -or $env:NODE_TLS_REJECT_UNAUTHORIZED -or $env:NODE_EXTRA_CA_CERTS -or $env:NODE_USE_ENV_PROXY -or $env:HTTPS_PROXY) { exit 91 }\r\n" +
    "if ($env:CLAUDERIPPLE_HOME -ne 'C:\\fixture-home') { exit 92 }\r\n" +
    "[Console]::Write('cleared')\r\n";
  const env = { ...process.env, NODE_OPTIONS: "--no-warnings", NODE_TLS_REJECT_UNAUTHORIZED: "0",
    NODE_EXTRA_CA_CERTS: "C:\\SYNTHETIC-OTHER-CA.pem", NODE_USE_ENV_PROXY: "1",
    HTTPS_PROXY: "http://127.0.0.1:1" };
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script],
    { env, encoding: "utf8", timeout: 20_000, windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "cleared");
});

test("unsafe Windows install refuses before creating a personal data home", {
  skip: process.platform !== "win32", timeout: 45_000,
}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-personal-env-refusal-"));
  const home = path.join(root, "must-not-be-created");
  try {
    const env: NodeJS.ProcessEnv = { ...process.env, CLAUDERIPPLE_HOME: home,
      CLAUDE_SETTINGS_PATH: path.join(root, "must-not-be-written.json"), NODE_TLS_REJECT_UNAUTHORIZED: "0" };
    // Delete an unrelated inherited preload: the expected refusal is the TLS setting itself.
    delete env.NODE_OPTIONS;
    const result = spawnSync(process.execPath, [runtime().cli, "install"],
      { env, encoding: "utf8", timeout: 30_000, windowsHide: true });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr + result.stdout, /NODE_TLS_REJECT_UNAUTHORIZED/);
    assert.equal(fs.existsSync(home), false);
    assert.equal(fs.existsSync(env.CLAUDE_SETTINGS_PATH!), false);
  } finally { fs.rmSync(root, { recursive: true, force: true }); }
});
