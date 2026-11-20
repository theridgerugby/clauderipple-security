import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import { SECRET_FILE_PREFIX, WINDOWS_DPAPI_SCRIPT, createWindowsDpapiProtector, sealSecretBytes, unsealSecretBytes, unsealSecretBytesAsync, type SecretProtector } from "../src/secret-storage.ts";
import { readPrivateFile, readPrivateFileStrict, readPrivateFilesStrict } from "../src/private-file.ts";
import { migrateSecretFile, writePrivateFileAtomic, writeSecretJsonAtomic } from "../src/locked-file.ts";
import { execBounded } from "../../cli/src/bounded-exec.ts";

function fixture(t: TestContext): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-sealed-secret-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

function contaminatedModulePath(t: TestContext): void {
  const keys = ["PSModulePath", "PSMODULEPATH", "PsMoDuLePaTh", "CR_TEST_DPAPI_KEEP"] as const;
  const saved = keys.map(key => process.env[key]);
  t.after(() => keys.forEach((key, i) => {
    if (saved[i] === undefined) delete process.env[key];
    else process.env[key] = saved[i];
  }));
  const modules = path.win32.join(process.env.ProgramFiles ?? "C:\\Program Files", "PowerShell", "7", "Modules");
  for (const key of keys.slice(0, 3)) process.env[key] = modules;
  process.env.CR_TEST_DPAPI_KEEP = "synthetic-nonsecret-marker";
}

function assertCleanPowerShellEnv(env: NodeJS.ProcessEnv): void {
  assert.equal(Object.keys(env).some(key => key.toLowerCase() === "psmodulepath"), false);
  assert.equal(env.CR_TEST_DPAPI_KEEP, "synthetic-nonsecret-marker");
  const expected = Object.entries(process.env).filter(([key]) => key.toLowerCase() !== "psmodulepath");
  assert.deepEqual(Object.keys(env).sort(), expected.map(([key]) => key).sort());
  for (const [key, value] of expected) assert.ok(env[key] === value, `preserve inherited key ${key}`);
}

// Cryptographic test seam with an ephemeral RAM key. This is never selected by production code
// or configured through an environment variable, and no test key is written to the filesystem.
function testProtector(): SecretProtector & { reads: number } {
  const key = crypto.randomBytes(32);
  return {
    kind: "test-only-ephemeral-aes-gcm", reads: 0,
    protect(bytes, entropy) {
      const iv = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
      cipher.setAAD(entropy);
      return Buffer.concat([iv, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
    },
    unprotect(bytes, entropy) {
      this.reads++;
      const cipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
      cipher.setAAD(entropy);
      cipher.setAuthTag(bytes.subarray(-16));
      return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]);
    },
  };
}

test("explicit secret writer never writes plaintext, including its atomic temporary file", t => {
  const home = fixture(t), file = path.join(home, "config.json"), protector = testProtector();
  const secret = "synthetic-private-research-school-api-key";
  const writes: Buffer[] = [], write = fs.writeFileSync;
  t.mock.method(fs, "writeFileSync", (...args: Parameters<typeof fs.writeFileSync>) => {
    writes.push(Buffer.from(args[1] as string | Uint8Array));
    return write(...args);
  });
  writeSecretJsonAtomic(file, { apiKey: secret }, { protector });
  assert.ok(writes.length > 0);
  for (const bytes of writes) { assert.equal(bytes.includes(secret), false); assert.ok(bytes.toString().startsWith(SECRET_FILE_PREFIX)); }
  assert.equal(fs.readFileSync(file).includes(secret), false);
  assert.deepEqual(JSON.parse(readPrivateFile(file, 1024, { protector }).toString()), { apiKey: secret });
  assert.deepEqual(fs.readdirSync(home), ["config.json"], "no backup or plaintext master key exists");
});

test("sync strict and batched readers decode after their filesystem checks and preserve bounds", async t => {
  const home = fixture(t), file = path.join(home, "accounts.json"), protector = testProtector();
  writeSecretJsonAtomic(file, { token: "synthetic-secret" }, { protector });
  const expected = readPrivateFileStrict(file, 1024, { protector });
  assert.deepEqual(JSON.parse(expected.toString()), { token: "synthetic-secret" });
  assert.equal(protector.reads, 1);
  assert.deepEqual((await readPrivateFilesStrict([{ file, maxBytes: 1024 }], { protector }))[0], expected);
  assert.equal(protector.reads, 1, "unchanged checked ciphertext may use the bounded RAM cache");
  assert.throws(() => readPrivateFileStrict(file, 2, { protector }), /size bound/);
  await assert.rejects(readPrivateFilesStrict([{ file, maxBytes: 2 }], { protector }), /size bound/);
});

test("a cache hit cannot bypass changed owner-only permissions or linked-file rejection", { skip: process.platform === "win32" }, async t => {
  const home = fixture(t), file = path.join(home, "accounts.json"), protector = testProtector();
  writeSecretJsonAtomic(file, { token: "synthetic-secret" }, { protector });
  readPrivateFileStrict(file, 1024, { protector });
  fs.chmodSync(file, 0o644);
  assert.throws(() => readPrivateFileStrict(file, 1024, { protector }), /owner-only/);
  await assert.rejects(readPrivateFilesStrict([{ file, maxBytes: 1024 }], { protector }), /owner-only/);
  fs.chmodSync(file, 0o600);
  const link = path.join(home, "link");
  fs.linkSync(file, link);
  assert.throws(() => readPrivateFile(file, 1024, { protector }), /regular/);
  await assert.rejects(readPrivateFilesStrict([{ file, maxBytes: 1024 }], { protector }), /regular/);
  assert.equal(protector.reads, 1);
});

test("tampered, wrong-purpose, unknown-version and unknown-protector envelopes fail closed", () => {
  const protector = testProtector(), file = "config.json", clear = Buffer.from("synthetic-secret");
  const bytes = sealSecretBytes(file, clear, protector);
  assert.deepEqual(unsealSecretBytes(file, bytes, 1024, protector), clear);
  const envelope = JSON.parse(bytes.subarray(SECRET_FILE_PREFIX.length).toString());
  const cipher = Buffer.from(envelope.ciphertext, "base64");
  cipher[15] = cipher[15]! ^ 1;
  const changed = Buffer.from(SECRET_FILE_PREFIX + JSON.stringify({ ...envelope, ciphertext: cipher.toString("base64") }));
  assert.throws(() => unsealSecretBytes(file, changed, 1024, protector), /protection failed/);
  assert.throws(() => unsealSecretBytes("other.json", bytes, 1024, protector), /protection failed/);
  const relabelled = Buffer.from(SECRET_FILE_PREFIX + JSON.stringify({ ...envelope, purpose: "other.json" }));
  assert.throws(() => unsealSecretBytes("other.json", relabelled, 1024, protector), /protection failed/, "purpose is cryptographically bound, not just a label");
  assert.throws(() => unsealSecretBytes(file, Buffer.from(bytes.toString().replace("SECRET-V1", "SECRET-V99")), 1024, protector), /protection failed/);
  assert.throws(() => unsealSecretBytes(file, bytes, 1024, { ...testProtector(), kind: "other-protector" }), /protection failed/);
  assert.throws(() => unsealSecretBytes(file, bytes, 1024, testProtector()), /protection failed/, "another ephemeral test identity cannot decrypt");
});

test("legacy migration is locked, encrypted, idempotent and preserves original data on protection failure", t => {
  const home = fixture(t), file = path.join(home, "config.json"), protector = testProtector();
  writePrivateFileAtomic(file, JSON.stringify({ apiKey: "synthetic-legacy-key" }));
  assert.equal(migrateSecretFile(file, { protector }), true);
  const sealed = fs.readFileSync(file);
  assert.equal(sealed.includes("synthetic-legacy-key"), false);
  assert.equal(migrateSecretFile(file, { protector }), false);
  assert.deepEqual(fs.readFileSync(file), sealed);
  assert.equal(JSON.parse(readPrivateFile(file, 1024, { protector }).toString()).apiKey, "synthetic-legacy-key");
  const other = path.join(home, "other.json"), previous = Buffer.from('{"apiKey":"synthetic-second-key"}');
  writePrivateFileAtomic(other, previous);
  assert.throws(() => migrateSecretFile(other, { protector: { ...protector, protect() { throw new Error("synthetic-sensitive-content"); } } }), error => error instanceof Error && !error.message.includes("synthetic-sensitive-content"));
  assert.deepEqual(fs.readFileSync(other), previous);
  assert.deepEqual(fs.readdirSync(home).sort(), ["config.json", "other.json"]);
});

test("cancelled async unprotect returns nothing and never populates a successful cache entry", async t => {
  const home = fixture(t), file = path.join(home, "accounts.json"), protector = testProtector();
  writeSecretJsonAtomic(file, { token: "synthetic-secret" }, { protector });
  const controller = new AbortController();
  let calls = 0;
  const blocking: SecretProtector = { ...protector, async unprotectAsync(bytes, entropy) { calls++; controller.abort(); return protector.unprotect(bytes, entropy); } };
  await assert.rejects(readPrivateFilesStrict([{ file, maxBytes: 1024 }], { protector: blocking, signal: controller.signal }), { code: "PRIVATE_STORAGE_ABORTED" });
  assert.equal(calls, 1);
  assert.deepEqual(JSON.parse(readPrivateFileStrict(file, 1024, { protector }).toString()), { token: "synthetic-secret" });
  assert.equal(protector.reads, 2, "cancelled result is not made reusable");
});

test("Windows helper uses only CurrentUser, fixed source/argv, bounded data-only stdin and sanitized errors", () => {
  const secret = Buffer.from("synthetic '$() secret\0\n"), entropy = Buffer.from("synthetic-purpose");
  const protector = createWindowsDpapiProtector((executable, args, options) => {
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_DPAPI_SCRIPT]);
    assert.ok(args.every(arg => !arg.includes(secret.toString()) && !arg.includes(secret.toString("base64"))));
    assert.deepEqual(JSON.parse(options.input), { operation: "protect", data: secret.toString("base64"), entropy: entropy.toString("base64") });
    assert.ok(options.timeout <= 10_000);
    assert.equal(options.windowsHide, true);
    return { status: 0, stdout: Buffer.from("synthetic-protected-data").toString("base64") };
  }, "C:\\Windows");
  assert.equal(protector.protect(secret, entropy).toString(), "synthetic-protected-data");
  assert.match(WINDOWS_DPAPI_SCRIPT, /DataProtectionScope\]::CurrentUser/);
  assert.doesNotMatch(WINDOWS_DPAPI_SCRIPT, /LocalMachine/);
  for (const run of [() => ({ status: 1, stdout: secret.toString() }), () => { throw new Error(secret.toString()); }, () => ({ status: 0, stdout: "malformed response!" })]) {
    assert.throws(() => createWindowsDpapiProtector(run, "C:\\Windows").protect(secret, entropy), error => error instanceof Error && /protection failed/.test(error.message) && !error.message.includes("synthetic"));
  }
});

test("sync and async DPAPI runners omit inherited PSModulePath in every case without mutating other environment values", async t => {
  contaminatedModulePath(t);
  const secret = Buffer.from("synthetic-env-regression-secret"), entropy = Buffer.from("synthetic-purpose");
  const modulePath = process.env.PSModulePath;
  let syncCalls = 0;
  const protector = createWindowsDpapiProtector((_executable, _args, options) => {
    syncCalls++;
    assertCleanPowerShellEnv(options.env);
    return { status: 0, stdout: secret.toString("base64") };
  }, "C:\\Windows");
  assert.deepEqual(protector.protect(secret, entropy), secret);
  assert.deepEqual(protector.unprotect(secret, entropy), secret);
  assert.equal(syncCalls, 2);
  let asyncCalls = 0;
  assert.ok(protector.unprotectAsync);
  assert.deepEqual(await protector.unprotectAsync(secret, entropy, { run: async (executable, args, options) => {
    asyncCalls++;
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_DPAPI_SCRIPT]);
    assertCleanPowerShellEnv(options.env);
    assert.deepEqual(JSON.parse(options.input), { operation: "unprotect", data: secret.toString("base64"), entropy: entropy.toString("base64") });
    assert.equal(options.timeoutMs, 10_000);
    assert.equal(options.windowsHide, true);
    return secret.toString("base64");
  } }), secret);
  assert.equal(asyncCalls, 1);
  assert.equal(process.env.PSModulePath, modulePath, "only the child's environment is filtered");
});

test("native Windows DPAPI round trips with a PowerShell 7 module path inherited through Node", { skip: process.platform !== "win32", timeout: 60_000 }, async t => {
  contaminatedModulePath(t);
  const secret = Buffer.from("synthetic-native-modulepath-secret-" + crypto.randomUUID());
  const file = "config.json";
  const protector = createWindowsDpapiProtector();
  const sealed = sealSecretBytes(file, secret, protector);
  assert.equal(sealed.includes(secret), false);
  assert.deepEqual(unsealSecretBytes(file, sealed, 1024, protector), secret);
  // A new protector identity avoids the RAM cache and exercises the real async subprocess too.
  assert.deepEqual(await unsealSecretBytesAsync(file, sealed, 1024, {
    protector: createWindowsDpapiProtector(),
    run: (executable, args, options) => {
      assertCleanPowerShellEnv(options.env);
      return execBounded(executable, args, options);
    },
  }), secret);
});

test("public PEM/generic private files remain raw interoperable bytes", t => {
  const home = fixture(t), file = path.join(home, "ca.pem"), pem = "-----BEGIN CERTIFICATE-----\nsynthetic-public-pem\n-----END CERTIFICATE-----\n";
  writePrivateFileAtomic(file, pem);
  assert.equal(fs.readFileSync(file, "utf8"), pem);
  assert.equal(readPrivateFile(file).toString(), pem);
});

test("native Windows DPAPI hides synthetic credentials on disk and decrypts in a fresh process, rejecting damage", { skip: process.platform !== "win32", timeout: 60_000 }, t => {
  const home = fixture(t), file = path.join(home, "config.json");
  const secret = "synthetic-native-windows-school-key-" + crypto.randomUUID();
  writeSecretJsonAtomic(file, { apiKey: secret, refreshToken: "synthetic-native-refresh" });
  const stored = fs.readFileSync(file);
  assert.ok(stored.toString().startsWith(SECRET_FILE_PREFIX));
  assert.equal(stored.includes(secret), false);
  assert.equal(stored.includes("synthetic-native-refresh"), false);
  const reader = pathToFileURL(path.resolve(import.meta.dirname, "../src/private-file.ts")).href;
  const result = spawnSync(process.execPath, ["--input-type=module", "-e", `import { readPrivateFile } from ${JSON.stringify(reader)}; const doc = JSON.parse(readPrivateFile(process.argv[1]).toString()); console.log(JSON.stringify({ digest: (await import('node:crypto')).createHash('sha256').update(doc.apiKey).digest('hex'), refresh: doc.refreshToken === 'synthetic-native-refresh' }));`, file], { encoding: "utf8", timeout: 30_000, windowsHide: true, maxBuffer: 4096 });
  assert.equal(result.status, 0, "fresh native process must be able to decrypt");
  assert.deepEqual(JSON.parse(result.stdout), { digest: crypto.createHash("sha256").update(secret).digest("hex"), refresh: true });
  const envelope = JSON.parse(stored.subarray(SECRET_FILE_PREFIX.length).toString());
  const damaged = Buffer.from(envelope.ciphertext, "base64");
  damaged[Math.floor(damaged.length / 2)] = damaged[Math.floor(damaged.length / 2)]! ^ 1;
  writePrivateFileAtomic(file, SECRET_FILE_PREFIX + JSON.stringify({ ...envelope, ciphertext: damaged.toString("base64") }));
  assert.throws(() => readPrivateFile(file), /protection failed/);
  assert.deepEqual(fs.readdirSync(home), ["config.json"]);
});
