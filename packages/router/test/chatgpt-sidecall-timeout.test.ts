import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ChatGptAdapter } from "../src/providers/chatgpt/index.ts";
import { saveChatGptAccount } from "../src/providers/chatgpt/accounts.ts";
import { Logger } from "../src/log.ts";
import { WINDOWS_PRIVATE_ACL_SCRIPT } from "../src/windows-private-acl.ts";

const quota = { rate_limit: { primary_window: { used_percent: 25, limit_window_seconds: 18000 } } };
const catalog = { models: [{ slug: "timeout-test-model", visibility: "list" }] };
const cases = [
  { name: "quota", timeout: 10_000, body: quota, read: (adapter: ChatGptAdapter) => adapter.fetchRateLimits() },
  { name: "catalog", timeout: 15_000, body: catalog, read: (adapter: ChatGptAdapter) => adapter.fetchModels() },
];

// Account fixtures still use the production Windows private-file writer. Permit only its
// fixed ACL program, with its exact bounded options and a target inside this temporary home.
// Every other child process remains blocked, including PowerShell credential-store readers.
function isFixtureAclCall(home: string, command: unknown, args: unknown, options: unknown, systemRoot = process.env.SystemRoot): boolean {
  if (!systemRoot || !path.win32.isAbsolute(systemRoot) ||
      command !== path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")) return false;
  const expected = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_SCRIPT];
  if (!Array.isArray(args) || args.length !== expected.length || !args.every((arg, i) => arg === expected[i])) return false;
  if (!options || typeof options !== "object" || Array.isArray(options)) return false;
  const opts = options as Record<string, unknown>;
  if (Object.keys(opts).sort().join(",") !== "encoding,input,maxBuffer,timeout,windowsHide" ||
      opts.encoding !== "utf8" || opts.timeout !== 10_000 || opts.maxBuffer !== 16 * 1024 || opts.windowsHide !== true ||
      typeof opts.input !== "string" || opts.input.length > 128 * 1024) return false;
  let request: unknown;
  try { request = JSON.parse(opts.input); } catch { return false; }
  if (!request || typeof request !== "object" || Array.isArray(request)) return false;
  const record = request as Record<string, unknown>;
  if (Object.keys(record).some(key => !["path", "directory", "verifyOnly"].includes(key)) ||
      typeof record.path !== "string" || !path.isAbsolute(record.path) || record.path.includes("\0") ||
      typeof record.directory !== "boolean" || (record.verifyOnly !== undefined && record.verifyOnly !== true)) return false;
  const relative = path.relative(home, record.path);
  return relative === "" || relative !== ".." && !relative.startsWith(`..${path.sep}`) && !path.isAbsolute(relative);
}

function rig(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-sidecall-timeout-"));
  const keys = ["HOME", "CODEX_HOME", "CLAUDERIPPLE_HOME"] as const;
  const previous = keys.map((key) => process.env[key]);
  for (const key of keys) process.env[key] = home;
  // Fail closed if a future import/caller tries to consult OS credential readers.
  const noOsCredentials = () => { throw new Error("OS credential readers are disabled in this test"); };
  t.mock.method(childProcess, "execFileSync", noOsCredentials);
  t.mock.method(childProcess, "execSync", noOsCredentials);
  const realSpawnSync = childProcess.spawnSync;
  t.mock.method(childProcess, "spawnSync", (command: string, args?: readonly string[], options?: childProcess.SpawnSyncOptions) => {
    if (process.platform !== "win32" || !isFixtureAclCall(home, command, args, options)) return noOsCredentials();
    return realSpawnSync(command, args ?? [], options ?? {});
  });
  syncBuiltinESMExports();
  t.after(() => {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    keys.forEach((key, i) => {
      if (previous[i] === undefined) delete process.env[key];
      else process.env[key] = previous[i];
    });
    fs.rmSync(home, { recursive: true, force: true });
  });
  t.mock.timers.enable({ apis: ["setTimeout", "Date"], now: 1_000_000 });
  saveChatGptAccount(home, { accessToken: "fixture-token", refreshToken: "fixture-refresh", accountId: "fixture-workspace", expiresAt: Date.now() + 86_400_000 });
  let refreshes = 0;
  const adapter = new ChatGptAdapter("timeout-test", { type: "chatgpt", auth: "own", url: "https://backend.invalid" }, home, new Logger(null, 1e9, 0, false), undefined, async () => {
    refreshes++;
    return Response.json({ access_token: "fixture-fresh", refresh_token: "fixture-next", expires_in: 86400 });
  });
  const signals: AbortSignal[] = [];
  let calls = 0;
  let reply: (signal: AbortSignal) => Response = () => Response.json(quota);
  t.mock.method(globalThis, "fetch", async (input: string | URL | Request, init?: RequestInit) => {
    const url = String(input);
    if (url === "https://registry.npmjs.org/@openai/codex/latest") return Response.json({ version: "0.159.0" });
    assert.ok(url.startsWith("https://backend.invalid/"), "no real network or OAuth refresh");
    assert.ok(init?.signal);
    signals.push(init.signal);
    calls++;
    return reply(init.signal);
  });
  return { adapter, signals, calls: () => calls, refreshes: () => refreshes, reply: (next: typeof reply) => { reply = next; } };
}

test("the credential-isolation exception accepts only the fixed private ACL helper inside the fixture home", () => {
  const home = path.resolve(os.tmpdir(), "cr-sidecall-allowlist");
  const root = "C:\\Windows";
  const command = path.win32.join(root, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const args = ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_SCRIPT];
  const options = { input: JSON.stringify({ path: path.join(home, "account.json"), directory: false }),
    encoding: "utf8", timeout: 10_000, maxBuffer: 16 * 1024, windowsHide: true };
  assert.equal(isFixtureAclCall(home, command, args, options, root), true);
  assert.equal(isFixtureAclCall(home, command, args, { ...options, input: JSON.stringify({ path: home, directory: true, verifyOnly: true }) }, root), true);
  for (const unsafe of ["powershell.exe", "security", "cmdkey.exe", `${command}.exe`]) {
    assert.equal(isFixtureAclCall(home, unsafe, args, options, root), false);
  }
  for (const altered of [[...args, "extra"], args.slice(1), [...args.slice(0, -1), `${WINDOWS_PRIVATE_ACL_SCRIPT}\nGet-StoredCredential`]]) {
    assert.equal(isFixtureAclCall(home, command, altered, options, root), false);
  }
  for (const altered of [
    { ...options, shell: true }, { ...options, env: {} }, { ...options, timeout: 0 },
    { ...options, maxBuffer: Infinity }, { ...options, encoding: "buffer" }, { ...options, windowsHide: false },
    { ...options, input: "malformed" },
    ...[path.join(home, "..", "outside.json"), path.join(`${home}-sibling`, "account.json"), "relative.json"].map(file =>
      ({ ...options, input: JSON.stringify({ path: file, directory: false }) })),
    { ...options, input: JSON.stringify({ path: home, directory: true, extra: "forbidden" }) },
  ]) assert.equal(isFixtureAclCall(home, command, args, altered, root), false);
});

test("timeout fixtures keep OS credential readers blocked while using private account storage", t => {
  rig(t);
  assert.throws(() => childProcess.execFileSync("security", ["find-generic-password"]), /OS credential readers are disabled/);
  assert.throws(() => childProcess.execSync("cmdkey /list"), /OS credential readers are disabled/);
  assert.throws(() => childProcess.spawnSync("powershell.exe", ["-NoProfile", "-Command", "Get-StoredCredential"]), /OS credential readers are disabled/);
});

function stalledBody(signal: AbortSignal) {
  const reading = Promise.withResolvers<void>();
  let controller: ReadableStreamDefaultController<Uint8Array>;
  const stream = new ReadableStream<Uint8Array>({
    start(value) { controller = value; },
    pull() { reading.resolve(); },
  }, { highWaterMark: 0 });
  signal.addEventListener("abort", () => controller.error(signal.reason), { once: true });
  return { response: new Response(stream), reading: reading.promise };
}

for (const spec of cases) {
  test(`${spec.name}: the deadline aborts a stalled JSON body and releases singleflight for a later lookup`, async (t) => {
    const r = rig(t);
    const started = Promise.withResolvers<void>();
    r.reply((signal) => {
      const stalled = stalledBody(signal);
      void stalled.reading.then(started.resolve);
      return stalled.response;
    });
    const first = spec.read(r.adapter);
    assert.equal(spec.read(r.adapter), first, "concurrent callers share the entire body read");
    await started.promise;
    t.mock.timers.tick(spec.timeout - 1);
    assert.equal(r.signals[0]!.aborted, false);
    t.mock.timers.tick(1);
    assert.equal(r.signals[0]!.aborted, true, "the original deadline must remain active after headers");
    assert.equal(await first, null);
    assert.equal(r.calls(), 1);
    r.reply(() => Response.json(spec.body));
    assert.ok(await spec.read(r.adapter), "a timeout does not wedge the next lookup");
    assert.equal(r.calls(), 2);
    t.mock.timers.tick(spec.timeout);
    assert.equal(r.signals[1]!.aborted, false, "successful body consumption clears the timer");
  });

  for (const failure of ["invalid-json", "http", "fetch"] as const) {
    test(`${spec.name}: ${failure} releases its timer and allows a fresh lookup`, async (t) => {
      const r = rig(t);
      r.reply(() => {
        if (failure === "fetch") throw new Error("fixture connection failure");
        return new Response(failure === "http" ? "unavailable" : "{broken", { status: failure === "http" ? 503 : 200 });
      });
      assert.equal(await spec.read(r.adapter), null);
      t.mock.timers.tick(spec.timeout);
      assert.equal(r.signals[0]!.aborted, false, "every completed failure clears its timer");
      r.reply(() => Response.json(spec.body));
      assert.ok(await spec.read(r.adapter));
      assert.equal(r.calls(), 2);
    });
  }
}

test("quota: a 401 refreshes once and the replay keeps its own body deadline", async (t) => {
  const r = rig(t);
  const started = Promise.withResolvers<void>();
  r.reply((signal) => {
    if (r.calls() === 1) return new Response(null, { status: 401 });
    const stalled = stalledBody(signal);
    void stalled.reading.then(started.resolve);
    return stalled.response;
  });
  const pending = r.adapter.fetchRateLimits();
  await started.promise;
  assert.equal(r.refreshes(), 1);
  assert.equal(r.calls(), 2);
  t.mock.timers.tick(10_000);
  assert.equal(r.signals[0]!.aborted, false, "the original 401 attempt cleared its timer");
  assert.equal(r.signals[1]!.aborted, true, "the replay's body is still bounded");
  assert.equal(await pending, null);
  assert.equal(r.refreshes(), 1, "a body timeout must not refresh credentials again");
});

test("quota: a repeated 401 stops after one refresh and replay", async (t) => {
  const r = rig(t);
  r.reply(() => new Response(null, { status: 401 }));
  assert.equal(await r.adapter.fetchRateLimits(), null);
  assert.equal(r.refreshes(), 1);
  assert.equal(r.calls(), 2);
  t.mock.timers.tick(10_000);
  assert.ok(r.signals.every((signal) => !signal.aborted));
});

test("quota: a timed-out refresh preserves the last good snapshot", async (t) => {
  const r = rig(t);
  const good = await r.adapter.fetchRateLimits();
  assert.ok(good);
  const started = Promise.withResolvers<void>();
  r.reply((signal) => {
    const stalled = stalledBody(signal);
    void stalled.reading.then(started.resolve);
    return stalled.response;
  });
  const pending = r.adapter.fetchRateLimits();
  await started.promise;
  t.mock.timers.tick(10_000);
  assert.equal(await pending, null);
  assert.equal(r.adapter.lastRateLimits, good);
});

test("catalog: a timed-out refresh preserves the last good expired catalog", async (t) => {
  const r = rig(t);
  r.reply(() => Response.json(catalog));
  const good = await r.adapter.fetchModels();
  assert.ok(good);
  assert.equal(await r.adapter.fetchModels(), good);
  assert.equal(r.calls(), 1, "an unexpired catalog stays cached");
  t.mock.timers.tick(60 * 60 * 1000);
  const started = Promise.withResolvers<void>();
  r.reply((signal) => {
    const stalled = stalledBody(signal);
    void stalled.reading.then(started.resolve);
    return stalled.response;
  });
  const pending = r.adapter.fetchModels();
  await started.promise;
  t.mock.timers.tick(15_000);
  assert.equal(await pending, good);
  r.reply(() => Response.json(catalog));
  assert.ok(await r.adapter.fetchModels());
  assert.equal(r.calls(), 3, "a timed-out refresh releases singleflight without renewing the cache");
});
