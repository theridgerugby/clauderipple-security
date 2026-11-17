import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { readWatchdogAdminPort } from "../src/watchdog-port.ts";
import { renderLauncher } from "../src/schtasks.ts";
import { windowsPowerShellEnv } from "../src/windows-powershell.ts";
import { writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { SECRET_FILE_PREFIX, type SecretProtector } from "../../router/src/secret-storage.ts";

function fixture(t: TestContext): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-watchdog-private-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const home = path.join(root, "owner's 학생 home");
  fs.mkdirSync(home, { mode: 0o700 });
  return home;
}

// No platform spoofing or environment hook: this cryptographic seam is an explicit test argument.
function ephemeralProtector(): SecretProtector {
  const key = crypto.randomBytes(32);
  return { kind: "test-only-watchdog-aes-gcm",
    protect(bytes, entropy) {
      const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      cipher.setAAD(entropy);
      return Buffer.concat([iv, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
    },
    unprotect(bytes, entropy) {
      const cipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
      cipher.setAAD(entropy); cipher.setAuthTag(bytes.subarray(-16));
      return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]);
    },
  };
}

test("watchdog reads custom public ports from sealed config through the canonical decoder", t => {
  const home = fixture(t), protector = ephemeralProtector(), file = path.join(home, "config.json");
  const providers = { fixture: { type: "google", auth: "api-key", apiKey: "synthetic-watchdog-provider-key" } };
  for (const [config, expected] of [
    [{ providers, listen: { host: "127.0.0.1", port: 19890 }, admin: { port: 19895 } }, 19895],
    [{ providers, listen: { host: "127.0.0.1", port: 19890 } }, 19891],
    [{ providers }, 8791],
  ] as const) {
    writeSecretJsonAtomic(file, config, { protector });
    const bytes = fs.readFileSync(file);
    assert.ok(bytes.toString().startsWith(SECRET_FILE_PREFIX));
    assert.equal(bytes.includes(providers.fixture.apiKey), false);
    assert.equal(readWatchdogAdminPort(home, { protector }), expected);
    assert.deepEqual(fs.readFileSync(file), bytes, "the watchdog helper never migrates or rewrites config");
  }
});

test("unreadable, damaged or invalid config disables watchdog instead of guessing a port", t => {
  const home = fixture(t), file = path.join(home, "config.json"), protector = ephemeralProtector();
  assert.equal(readWatchdogAdminPort(home), 8791, "a genuinely absent config matches the router's defaults");
  for (const value of [null, [], { admin: { port: 65536 } }, { listen: { host: "127.0.0.1", port: 65535 } }, { listen: { port: "19890" } }]) {
    writeSecretJsonAtomic(file, value, { protector });
    assert.equal(readWatchdogAdminPort(home, { protector }), 0);
  }
  writeSecretJsonAtomic(file, { admin: { port: 19895 } }, { protector });
  assert.equal(readWatchdogAdminPort(home, { protector: ephemeralProtector() }), 0, "a different key never triggers plaintext fallback");
  const bytes = fs.readFileSync(file); bytes[bytes.length - 8] = bytes[bytes.length - 8]! ^ 1; fs.writeFileSync(file, bytes);
  assert.equal(readWatchdogAdminPort(home, { protector }), 0);
  assert.equal(readWatchdogAdminPort("relative-home"), 0);
  assert.equal(readWatchdogAdminPort("//server/share"), 0);
});

test("port helper emits only a bounded number, with no provider credential or parser diagnostic", t => {
  const home = fixture(t), file = path.join(home, "config.json");
  const env: NodeJS.ProcessEnv = { ...process.env, CLAUDERIPPLE_HOME: home };
  delete env.NODE_OPTIONS;
  writeSecretJsonAtomic(file, { admin: { port: 19895 }, providers: { fixture: { type: "google", auth: "api-key", apiKey: "synthetic-never-log-this-key" } } });
  const helper = path.resolve(import.meta.dirname, "../src/watchdog-port.ts");
  const result = spawnSync(process.execPath, [helper], { env, encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "19895");
  assert.equal(result.stderr, "");
  writeSecretJsonAtomic(file, { admin: { port: "synthetic-never-log-this-key" } });
  const invalid = spawnSync(process.execPath, [helper], { env, encoding: "utf8", timeout: 30_000 });
  assert.equal(invalid.status, 0);
  assert.equal(invalid.stdout, "0");
  assert.equal(invalid.stderr, "");
});

test("native Windows launcher resolves a DPAPI-sealed custom port through its bounded fixed helper", { skip: process.platform !== "win32", timeout: 60_000 }, t => {
  const home = fixture(t), file = path.join(home, "config.json");
  writeSecretJsonAtomic(file, { listen: { host: "127.0.0.1", port: 19890 }, admin: { port: 19895 },
    providers: { fixture: { type: "google", auth: "api-key", apiKey: "synthetic-native-dpapi-watchdog-key" } } });
  assert.ok(fs.readFileSync(file).toString().startsWith(SECRET_FILE_PREFIX));
  const launcher = renderLauncher({ program: process.execPath, args: [path.resolve(import.meta.dirname, "../../router/src/index.ts")], home });
  const start = launcher.indexOf("function Get-AdminPort {"), end = launcher.indexOf("function Test-RouterAnswers(");
  assert.ok(start >= 0 && end > start);
  // Execute only the reader function, not the task, supervision loop, router, or any HTTP probe.
  const script = "[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false);\n" +
    launcher.slice(start, end) + "\n[Console]::Write((Get-AdminPort))";
  const env = windowsPowerShellEnv({ ...process.env, CLAUDERIPPLE_HOME: home });
  delete env.NODE_OPTIONS;
  const result = spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], { env, encoding: "utf8", timeout: 45_000, windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stdout, "19895");
  assert.equal(result.stderr, "");
  assert.equal(result.stdout.includes("synthetic-native"), false);
});
