import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { readPrivateFile } from "../src/private-file.ts";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import { spawn } from "node:child_process";
import { DEFAULTS, type Config } from "../src/config.ts";
import type { AdminDeps } from "../src/admin.ts";
import { startAdmin, unauthenticatedFetch as fetch, adminTestTlsOptions, adminTestAuthHeaders } from "./admin-client.ts";
import { ADMIN_TOKEN_HEADER, ADMIN_INSTANCE_HEADER } from "../src/admin-auth.ts";
import { readAdminEndpoint, readAdminTlsIdentity } from "../src/admin-transport-state.ts";
import { adminTlsFetch } from "../src/admin-transport-client.ts";
import { REDACTED_SECRET } from "../src/admin-config-secrets.ts";
import { Logger } from "../src/log.ts";
import { RequestLog } from "../src/requestlog.ts";

function rawRequest(base: string, target: string, headers: string[]): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const request = https.request({ ...adminTestTlsOptions(base), path: target, headers }, response => {
      const chunks: Buffer[] = [];
      response.on("data", chunk => chunks.push(chunk));
      response.on("end", () => resolve({ status: response.statusCode!, body: Buffer.concat(chunks).toString("utf8") }));
      response.on("error", reject);
    });
    request.on("error", reject);
    request.end();
  });
}

async function fixture(t: TestContext, providers: Config["providers"] = {}, extra: Partial<AdminDeps> = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-security-"));
  const previousHome = process.env.CLAUDERIPPLE_HOME;
  const previousSettings = process.env.CLAUDE_SETTINGS_PATH;
  process.env.CLAUDERIPPLE_HOME = home;
  process.env.CLAUDE_SETTINGS_PATH = path.join(home, "claude-settings.json");
  const configFile = path.join(home, "config.json");
  const cfg = { ...DEFAULTS, autoUpdate: false, admin: { port: 0 }, providers };
  fs.writeFileSync(configFile, JSON.stringify(cfg));
  const readConfig = () => JSON.parse(readPrivateFile(configFile).toString("utf8")) as Config;
  const log = new Logger(null, 1_000_000, 1, false);
  t.mock.method(log, "line", () => {});
  const servers: Awaited<ReturnType<typeof startAdmin>>[] = [];
  t.after(() => {
    for (const server of servers) server.close();
    if (previousHome === undefined) delete process.env.CLAUDERIPPLE_HOME; else process.env.CLAUDERIPPLE_HOME = previousHome;
    if (previousSettings === undefined) delete process.env.CLAUDE_SETTINGS_PATH; else process.env.CLAUDE_SETTINGS_PATH = previousSettings;
    fs.rmSync(home, { recursive: true, force: true });
  });
  const deps: AdminDeps = {
    config: readConfig, configFile, agentDir: path.join(home, "agents"),
    version: "security-test", log,
    requests: new RequestLog(path.join(home, "requests.jsonl")), health: () => 0,
    stats: () => ({ inFlight: 0, messagesInFlight: 0, started: 0, completed: 0, failed: 0 }),
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    ...extra,
  };
  const start = async (overrides: Partial<AdminDeps> = {}) => {
    const server = await startAdmin({ ...deps, ...overrides });
    servers.push(server);
    return server;
  };
  const server = await start();
  return {
    base: `https://127.0.0.1:${server.tlsPort}`, publicBase: `http://127.0.0.1:${server.port}`, home, configFile, readConfig,
    headers: { ...adminTestAuthHeaders(`https://127.0.0.1:${server.tlsPort}`), "content-type": "application/json" } as Record<string, string>,
    server, start,
  };
}

test("legacy HTTP is liveness-only and never serves privileged APIs, redirects, or dashboard code", async t => {
  let changes = 0;
  const f = await fixture(t, {}, { shutdown: () => { changes++; } });
  for (const method of ["GET", "HEAD"]) {
    const response = await globalThis.fetch(`${f.publicBase}/api/ping`, { method });
    assert.equal(response.status, 200);
    assert.equal(await response.text(), method === "HEAD" ? "" : '{"ok":true}');
  }
  for (const [target, method] of [
    ["/", "GET"], ["/app.js", "GET"], ["/readyz", "GET"], ["/api/config", "GET"],
    ["/api/config", "PUT"], ["/api/shutdown", "POST"], ["/api/ping", "POST"],
    ["/api/ping?ignored=1", "GET"], ["/%61pi/config", "GET"], ["/api%2fconfig", "GET"],
  ] as const) {
    // Even a former client mistakenly sending a capability gets no privileged response here.
    const response = await globalThis.fetch(f.publicBase + target, { method, headers: f.headers });
    assert.equal(response.status, 410, `${method} ${target}`);
    assert.equal(response.headers.has("location"), false);
    const body = await response.text();
    assert.doesNotMatch(body, /<script|<!doctype/i);
    assert.ok(!body.includes(f.headers[ADMIN_TOKEN_HEADER]!));
  }
  assert.equal(changes, 0);
});

test("TLS requests require the current generation and never accept the legacy HTTP capability", async t => {
  const f = await fixture(t);
  const endpoint = readAdminEndpoint(f.home)!;
  assert.equal(endpoint.publicPort, f.server.port);
  assert.equal(endpoint.tlsPort, f.server.tlsPort);
  assert.notEqual(endpoint.publicPort, endpoint.tlsPort);
  const old = "a".repeat(64);
  fs.writeFileSync(path.join(f.home, "admin-token"), old, { mode: 0o600 });
  const legacy = await fetch(`${f.base}/api/config`, { headers: { ...f.headers, [ADMIN_TOKEN_HEADER]: old } });
  assert.equal(legacy.status, 401);
  const missing = { ...f.headers };
  delete missing[ADMIN_INSTANCE_HEADER];
  assert.equal((await fetch(`${f.base}/api/config`, { headers: missing })).status, 401);
  const stale = { ...endpoint, instanceId: endpoint.instanceId === "b".repeat(32) ? "c".repeat(32) : "b".repeat(32) };
  // Same authentic certificate and current capability, but stale endpoint metadata, is refused.
  assert.equal((await adminTlsFetch(stale, readAdminTlsIdentity(f.home)!, f.headers[ADMIN_TOKEN_HEADER]!, "/api/config")).status, 401);
  assert.equal((await adminTlsFetch(endpoint, readAdminTlsIdentity(f.home)!, f.headers[ADMIN_TOKEN_HEADER]!, "/api/config")).status, 200);
  const state = fs.readFileSync(path.join(f.home, "admin-tls-endpoint.json"), "utf8");
  assert.ok(!state.includes(f.headers[ADMIN_TOKEN_HEADER]!));
  assert.ok(!state.includes("PRIVATE KEY"));
});

test("closing an old instance retires both listeners without deleting a newer endpoint", async t => {
  const f = await fixture(t);
  const oldEndpoint = readAdminEndpoint(f.home)!;
  const second = await f.start();
  const current = readAdminEndpoint(f.home)!;
  assert.notEqual(current.instanceId, oldEndpoint.instanceId);
  assert.equal(current.tlsPort, second.tlsPort);
  const identity = readAdminTlsIdentity(f.home)!;
  f.server.close();
  assert.deepEqual(readAdminEndpoint(f.home), current);
  await assert.rejects(globalThis.fetch(`${f.publicBase}/api/ping`));
  await assert.rejects(adminTlsFetch(oldEndpoint, identity, f.headers[ADMIN_TOKEN_HEADER]!, "/api/ping"));
  assert.equal((await adminTlsFetch(current, identity, f.headers[ADMIN_TOKEN_HEADER]!, "/api/config")).status, 200);
  second.close();
  assert.equal(readAdminEndpoint(f.home), undefined);
  await assert.rejects(globalThis.fetch(`http://127.0.0.1:${second.port}/api/ping`));
  await assert.rejects(adminTlsFetch(current, identity, f.headers[ADMIN_TOKEN_HEADER]!, "/api/ping"));
});

test("a startup bind failure leaves the running instance and its private endpoint unchanged", async t => {
  const f = await fixture(t);
  const endpoint = readAdminEndpoint(f.home)!;
  await assert.rejects(f.start({ config: () => ({ ...f.readConfig(), admin: { port: endpoint.publicPort } }) }),
    error => (error as NodeJS.ErrnoException).code === "EADDRINUSE");
  assert.deepEqual(readAdminEndpoint(f.home), endpoint);
  assert.equal((await fetch(`${f.base}/api/config`, { headers: f.headers })).status, 200);
});

test("all administrative APIs require a capability, including reads; ping and static assets expose none", async t => {
  let calls = 0;
  const f = await fixture(t, { google: { type: "google", auth: "api-key", apiKey: "fixture-google-secret" } }, { shutdown: () => { calls++; } });
  for (const [route, method] of [["config", "GET"], ["config", "HEAD"], ["config", "PUT"], ["providers/probe", "POST"], ["status", "GET"], ["logs", "GET"], ["shutdown", "POST"]] as const) {
    for (const headers of [{}, { [ADMIN_TOKEN_HEADER]: "0".repeat(64) }]) {
      const response = await fetch(`${f.base}/api/${route}`, { method, headers });
      assert.equal(response.status, 401, `${method} ${route}`);
      assert.doesNotMatch(await response.text(), /fixture-google-secret/);
    }
  }
  assert.equal(calls, 0);
  assert.equal((await fetch(`${f.base}/readyz`)).status, 401);
  for (const route of ["/", "/app.js", "/api/ping"]) {
    const response = await fetch(f.base + route);
    assert.equal(response.status, 200);
    const body = await response.text();
    assert.ok(!body.includes(f.headers[ADMIN_TOKEN_HEADER]!));
    assert.ok(!body.includes("fixture-google-secret"));
  }
  const own = await fetch(`${f.base}/api/shutdown`, { method: "POST", headers: f.headers });
  assert.equal(own.status, 202);
  assert.equal(calls, 1);
});

test("ambiguous security headers and cross-site authenticated reads fail closed", async t => {
  const f = await fixture(t);
  const host = new URL(f.base).host;
  const token = f.headers[ADMIN_TOKEN_HEADER]!;
  for (const headers of [
    ["Host", host, "Host", "collector.example", ADMIN_TOKEN_HEADER, token],
    ["Host", host, "HOST", host, ADMIN_TOKEN_HEADER, token],
    ["Host", host, "Origin", f.base, "origin", f.base, ADMIN_TOKEN_HEADER, token],
    ["Host", host, ADMIN_TOKEN_HEADER, token, ADMIN_TOKEN_HEADER, token],
    ["Host", host, ADMIN_INSTANCE_HEADER, f.headers[ADMIN_INSTANCE_HEADER]!, ADMIN_INSTANCE_HEADER, f.headers[ADMIN_INSTANCE_HEADER]!],
  ]) {
    assert.equal((await rawRequest(f.base, "/api/config", headers)).status, 400);
  }
  for (const headers of [
    { origin: "https://collector.example" },
    { origin: "null" },
    { origin: f.base.replace(/^https:/, "http:") },
    { "sec-fetch-site": "cross-site" },
  ]) {
    const response = await fetch(`${f.base}/api/config`, { headers: { ...f.headers, ...headers } });
    assert.equal(response.status, 403);
  }
  assert.equal((await fetch(`${f.base}/api/config`, { headers: { ...f.headers, origin: f.base } })).status, 200);
  assert.equal((await fetch(`${f.base}/api/config`, { headers: f.headers })).status, 200);
});

test("malformed JSON never exposes parser excerpts in responses or logs", async t => {
  const log = new Logger(null, 1_000_000, 1, false);
  const lines: string[] = [];
  t.mock.method(log, "error", (message: string) => { lines.push(message); });
  const f = await fixture(t, {}, { log });
  const response = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: '{"apiKey":dummy-secret-parser}' });
  assert.equal(response.status, 400);
  assert.doesNotMatch(await response.text(), /dummy-sec/);
  fs.writeFileSync(f.configFile, '{"apiKey":dummy-secret-parser}');
  const invalidSaved = await fetch(`${f.base}/api/config`, { headers: f.headers });
  assert.equal(invalidSaved.status, 500);
  assert.doesNotMatch(await invalidSaved.text(), /dummy-sec/);
  assert.doesNotMatch(lines.join("\n"), /dummy-sec/);
});

test("config revision comparison and secret restoration share the cross-process write lock", async t => {
  const f = await fixture(t, { google: { type: "google", auth: "api-key", apiKey: "fixture-original-key" } });
  const draft = await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as Config;
  draft.autoUpdate = true;
  const newer = f.readConfig();
  (newer.providers.google as { apiKey: string }).apiKey = "fixture-newer-key";
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
    import { withFileLock, writeJsonAtomic } from ${JSON.stringify(new URL("../src/locked-file.ts", import.meta.url).href)};
    const [file, data] = process.argv.slice(1);
    withFileLock(file, () => {
      process.stdout.write("locked\\n");
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 500);
      writeJsonAtomic(file, JSON.parse(data));
    });
  `, f.configFile, JSON.stringify(newer)], { stdio: ["ignore", "pipe", "pipe"] });
  t.after(() => { if (child.exitCode === null) child.kill(); });
  let stderr = "";
  child.stderr.on("data", chunk => { stderr += chunk; });
  const finished = new Promise<number | null>((resolve, reject) => { child.once("exit", resolve); child.once("error", reject); });
  await new Promise<void>((resolve, reject) => {
    child.stdout.once("data", chunk => chunk.toString().includes("locked") ? resolve() : reject(new Error("writer did not acquire the lock")));
    child.once("error", reject);
    child.once("exit", code => { if (code !== 0) reject(new Error(`writer exited ${code}: ${stderr}`)); });
  });
  const response = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(draft) });
  assert.equal(await finished, 0, stderr);
  assert.equal(response.status, 409, await response.text());
  assert.equal((f.readConfig().providers.google as { apiKey: string }).apiKey, "fixture-newer-key");
  assert.equal(f.readConfig().autoUpdate, false);
});

test("deeply nested config and probe input is rejected before recursive processing", async t => {
  const f = await fixture(t);
  const nested = "[".repeat(10_000) + "0" + "]".repeat(10_000);
  for (const [route, method, body] of [
    ["config", "PUT", `{"unused":${nested},"providers":{}}`],
    ["providers/probe", "POST", `{"type":"google","auth":"api-key","unused":${nested}}`],
  ] as const) {
    const response = await fetch(`${f.base}/api/${route}`, { method, headers: f.headers, body });
    assert.equal(response.status, 400);
    assert.match(await response.text(), /nesting/);
  }
  assert.equal((await fetch(`${f.base}/api/ping`)).status, 200);
});

test("encoded paths cannot bypass API authentication or expose traversal targets", async t => {
  let calls = 0;
  const f = await fixture(t, { google: { type: "google", auth: "api-key", apiKey: "fixture-private-config" } }, { shutdown: () => { calls++; } });
  const headers = ["Host", new URL(f.base).host];
  for (const target of ["/api/config?anything=1", "/api//config", "/api/%63onfig", "/readyz?anything=1"]) {
    assert.equal((await rawRequest(f.base, target, headers)).status, 401, target);
  }
  for (const target of ["/%61pi/config", "/api%2fconfig", "/%252e%252e/config.json", "/api%2fshutdown"]) {
    const response = await rawRequest(f.base, target, headers);
    assert.doesNotMatch(response.body, /fixture-private-config/);
    assert.ok(!response.body.includes(f.headers[ADMIN_TOKEN_HEADER]!));
  }
  for (const target of ["/%2e%2e/config.json", "/%", "/%00"]) {
    assert.equal((await rawRequest(f.base, target, headers)).status, 400, target);
  }
  assert.equal(calls, 0);
});

test("the TLS dashboard sets anti-framing headers and rejects oversized headers", async t => {
  const f = await fixture(t);
  const page = await fetch(f.base);
  assert.match(page.headers.get("content-security-policy") ?? "", /frame-ancestors 'none'/);
  assert.match(page.headers.get("content-security-policy") ?? "", /worker-src 'none'/);
  assert.equal(page.headers.get("x-content-type-options"), "nosniff");
  assert.equal(page.headers.get("referrer-policy"), "no-referrer");
  assert.equal(page.headers.get("x-frame-options"), "DENY");
  // Drain the real dashboard response before the fixture closes its TLS client. Leaving the
  // streamed body unread can trip Undici's paused-parser assertion during Windows teardown.
  await page.arrayBuffer();
  assert.equal((await rawRequest(f.base, "/api/ping", ["Host", new URL(f.base).host, "x-padding", "x".repeat(17 * 1024)])).status, 431);
});

test("probe JSON parser failures never reveal partial outbound credentials", async t => {
  const f = await fixture(t, {}, {
    probeFetch: async () => new Response('{"models":[dummy-key-parse-secret]}'),
  });
  const response = await fetch(`${f.base}/api/providers/probe`, {
    method: "POST", headers: f.headers,
    body: JSON.stringify({ type: "google", auth: "api-key", apiKey: "dummy-key-parse-secret" }),
  });
  assert.equal(response.status, 200);
  const body = await response.text();
  assert.doesNotMatch(body, /dummy-key/);
  assert.match(body, /invalid JSON/);
});

test("probe error responses stop reading and cancel above their bounded size", async t => {
  let pulls = 0, cancelled = false;
  const f = await fixture(t, {}, {
    probeFetch: async () => new Response(new ReadableStream<Uint8Array>({
      pull(controller) {
        if (pulls++ === 20) { controller.close(); return; }
        controller.enqueue(new Uint8Array(16 * 1024).fill(120));
      },
      cancel() { cancelled = true; },
    }), { status: 500 }),
  });
  const response = await fetch(`${f.base}/api/providers/probe`, {
    method: "POST", headers: f.headers,
    body: JSON.stringify({ type: "google", auth: "api-key", apiKey: "fixture-key" }),
  });
  assert.equal(response.status, 200);
  assert.match(await response.text(), /size limit/);
  assert.equal(cancelled, true);
  assert.ok(pulls < 20);
});

test("measurement errors are redacted before truncation, storage, and logging", async t => {
  const key = `dummy-measure-secret-${"x".repeat(300)}`;
  const lines: string[] = [];
  const log = new Logger(null, 1_000_000, 1, false);
  t.mock.method(log, "info", (message: string) => { lines.push(message); });
  t.mock.method(log, "warn", (message: string) => { lines.push(message); });
  const f = await fixture(t, { custom: {
    type: "openai-compatible", url: "https://vendor.example/v1", headers: { authorization: `Bearer ${key}` },
    models: [{ id: "model" }],
  } }, { log, measureFetch: async () => new Response(`upstream reflected ${key}`, { status: 500 }) });
  const started = await fetch(`${f.base}/api/providers/measure`, { method: "POST", headers: f.headers, body: JSON.stringify({ provider: "custom", models: ["model"] }) });
  assert.equal(started.status, 202);
  const { jobId } = await started.json() as { jobId: string };
  let output = "";
  for (let i = 0; i < 100; i++) {
    output = await (await fetch(`${f.base}/api/providers/measure/${jobId}`, { headers: f.headers })).text();
    if (JSON.parse(output).state !== "running") break;
    await new Promise(resolve => setTimeout(resolve, 5));
  }
  assert.equal(JSON.parse(output).state, "done");
  assert.doesNotMatch(output, /dummy-measure-secret/);
  assert.doesNotMatch(lines.join("\n"), /dummy-measure-secret/);
  assert.match(output, /REDACTED/);
});

test("measurement admission bounds model queues and active jobs, then recovers", async t => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  t.after(release);
  const providers = Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`p${i}`, {
    type: "openai-compatible" as const, url: "https://vendor.example/v1", models: [{ id: "model" }],
  }]));
  let calls = 0;
  const f = await fixture(t, providers, { measureFetch: async () => { calls++; await gate; return new Response("", { status: 401 }); } });
  const start = (provider: string, models: unknown = ["model"]) => fetch(`${f.base}/api/providers/measure`, { method: "POST", headers: f.headers, body: JSON.stringify({ provider, models }) });
  for (const models of [[], [""], ["model", "model"], ["x".repeat(1001)], Array.from({ length: 1001 }, (_, i) => `m${i}`)]) {
    assert.equal((await start("p0", models)).status, 400);
  }
  assert.equal(calls, 0);
  const jobs: string[] = [];
  for (let i = 0; i < 8; i++) {
    const response = await start(`p${i}`);
    assert.equal(response.status, 202, await response.clone().text());
    jobs.push((await response.json() as { jobId: string }).jobId);
  }
  const busy = await start("p8");
  assert.equal(busy.status, 429);
  assert.equal(busy.headers.get("retry-after"), "5");
  assert.equal((await start("p0")).status, 429);
  assert.equal(calls, 8);
  release();
  for (const jobId of jobs) {
    for (let i = 0; i < 100; i++) {
      const job = await (await fetch(`${f.base}/api/providers/measure/${jobId}`, { headers: f.headers })).json() as { state: string; scope?: unknown };
      assert.equal(job.scope, undefined);
      if (job.state === "done") break;
      assert.ok(i < 99, "measurement did not settle");
      await new Promise(resolve => setTimeout(resolve, 5));
    }
  }
  assert.equal((await start("p8")).status, 202);
});

test("completed measurement retention is bounded without dropping running work", async t => {
  const f = await fixture(t, { custom: { type: "openai-compatible", url: "https://vendor.example/v1", models: [{ id: "model" }] } }, {
    measureFetch: async () => new Response("", { status: 401 }),
  });
  let first = "", latest = "";
  for (let i = 0; i < 129; i++) {
    const response = await fetch(`${f.base}/api/providers/measure`, { method: "POST", headers: f.headers, body: JSON.stringify({ provider: "custom", models: ["model"] }) });
    assert.equal(response.status, 202);
    latest = (await response.json() as { jobId: string }).jobId;
    first ||= latest;
    for (let poll = 0; poll < 100; poll++) {
      const job = await (await fetch(`${f.base}/api/providers/measure/${latest}`, { headers: f.headers })).json() as { state: string };
      if (job.state === "done") break;
      assert.ok(poll < 99, "measurement did not settle");
      await new Promise(resolve => setTimeout(resolve, 5));
    }
  }
  assert.equal((await fetch(`${f.base}/api/providers/measure/${first}`, { headers: f.headers })).status, 404);
  assert.equal((await fetch(`${f.base}/api/providers/measure/${latest}`, { headers: f.headers })).status, 200);
});

test("config and conflict snapshots are redacted; edits keep, replace, and clear secrets without returning them", async t => {
  const f = await fixture(t, {
    google: { type: "google", auth: "api-key", apiKey: "fixture-google-secret" },
    custom: { type: "openai-compatible", url: "https://vendor.example/v1", headers: { authorization: "Bearer fixture-custom-secret", "x-private": "fixture-extra-secret" }, credentials: [{ id: "second", headers: { authorization: "Bearer fixture-pool-secret" } }] },
  });
  const response = await fetch(`${f.base}/api/config`, { headers: f.headers });
  const text = await response.text();
  assert.doesNotMatch(text, /fixture-(google|custom|extra|pool)-secret/);
  const config = JSON.parse(text);
  assert.equal(config.providers.google.apiKey, REDACTED_SECRET);
  assert.equal(config.providers.custom.headers.authorization, `Bearer ${REDACTED_SECRET}`);
  config.aliases = { helpful: "custom/model" };
  const save = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
  assert.equal(save.status, 200, await save.text());
  assert.equal((f.readConfig().providers.google as { apiKey: string }).apiKey, "fixture-google-secret");
  assert.equal((f.readConfig().providers.custom as { headers: Record<string, string> }).headers.authorization, "Bearer fixture-custom-secret");
  const conflict = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
  assert.equal(conflict.status, 409);
  assert.doesNotMatch(await conflict.text(), /fixture-(google|custom|extra|pool)-secret/);
  const changed = await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as typeof config;
  changed.providers.google.apiKey = "fixture-replacement";
  assert.equal((await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(changed) })).status, 200);
  assert.equal((f.readConfig().providers.google as { apiKey: string }).apiKey, "fixture-replacement");
  const clear = await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as typeof config;
  delete clear.providers.google.apiKey;
  assert.equal((await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(clear) })).status, 200);
  assert.equal((f.readConfig().providers.google as { apiKey?: string }).apiKey, undefined);
});

test("saved secrets cannot be carried to changed endpoints or model overrides through placeholders", async t => {
  const f = await fixture(t, { google: { type: "google", auth: "api-key", apiKey: "fixture-google-secret" } });
  for (const change of [
    { url: "https://collector.example" },
    { type: "anthropic" },
    { models: [{ id: "carbon", url: "https://collector.example/v1" }] },
  ]) {
    const config = await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as Config;
    Object.assign(config.providers.google!, change);
    const response = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
    assert.equal(response.status, 400);
  }
  assert.equal((f.readConfig().providers.google as { apiKey: string }).apiKey, "fixture-google-secret");
});

test("normalized legacy provider snapshots preserve credentials and revision conflicts", async t => {
  const f = await fixture(t, {
    "legacy-responses": { type: "openai-compatible", preset: "opencode-go", url: "https://opencode.ai/go/v1", wire: "responses", headers: { authorization: "Bearer fixture-legacy-key" }, models: [{ id: "response-model" }] },
    "legacy-chat": { type: "openai-compatible", preset: "opencode-go-chat", url: "https://opencode.ai/go/v1/chat", wire: "chat", headers: { authorization: "Bearer fixture-legacy-key" }, models: [{ id: "chat-model" }] },
  });
  const config = await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as Config;
  assert.deepEqual(Object.keys(config.providers), ["opencode-go"]);
  config.processPriority = "normal";
  const save = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
  assert.equal(save.status, 200, await save.text());
  const saved = f.readConfig();
  assert.deepEqual(Object.keys(saved.providers), ["opencode-go"]);
  assert.equal((saved.providers["opencode-go"] as { headers: Record<string, string> }).headers.authorization, "Bearer fixture-legacy-key");
  const stale = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
  assert.equal(stale.status, 409);
  const conflict = await stale.text();
  assert.ok(!conflict.includes("fixture-legacy-key"));
  assert.deepEqual(Object.keys(JSON.parse(conflict).config.providers), ["opencode-go"]);
});

test("removing a model destination can preserve a key while changing the primary endpoint cannot", async t => {
  const f = await fixture(t, { custom: { type: "openai-compatible", url: "https://vendor.example/v1", headers: { authorization: "Bearer fixture-key" }, models: [{ id: "extra", url: "https://other.vendor.example/v1" }] } });
  const config = await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as Config;
  const primaryChanged = structuredClone(config);
  (primaryChanged.providers.custom as { url: string }).url = "https://other.vendor.example/v1";
  assert.equal((await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(primaryChanged) })).status, 400);
  config.providers.custom!.models = [];
  const save = await fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
  assert.equal(save.status, 200, await save.text());
  assert.equal((f.readConfig().providers.custom as { headers: Record<string, string> }).headers.authorization, "Bearer fixture-key");
});

test("single-key promotion and primary-key removal preserve the correct pool identities", async t => {
  const f = await fixture(t, { custom: { type: "openai-compatible", url: "https://vendor.example/v1", headers: { authorization: "Bearer fixture-first-key", "x-vendor-token": "fixture-vendor-secret" } } });
  const read = async () => await (await fetch(`${f.base}/api/config`, { headers: f.headers })).json() as Config;
  const put = (config: Config) => fetch(`${f.base}/api/config`, { method: "PUT", headers: f.headers, body: JSON.stringify(config) });
  const config = await read();
  const provider = config.providers.custom as Extract<Config["providers"][string], { type: "openai-compatible" }>;
  provider.credentials = [
    { id: "default", headers: { ...provider.headers! } },
    { id: "second", headers: { ...provider.headers!, authorization: "Bearer fixture-second-key" } },
  ];
  let response = await put(config);
  assert.equal(response.status, 200, await response.text());
  const initial = f.readConfig().providers.custom as typeof provider;
  assert.equal(initial.credentials![0]!.headers.authorization, "Bearer fixture-first-key");
  assert.equal(initial.credentials![1]!.headers["x-vendor-token"], "fixture-vendor-secret");
  const next = await read();
  const nextProvider = next.providers.custom as typeof provider;
  nextProvider.credentials = [nextProvider.credentials![1]!];
  nextProvider.headers = { ...nextProvider.credentials[0]!.headers };
  response = await put(next);
  assert.equal(response.status, 200, await response.text());
  const saved = f.readConfig().providers.custom as typeof provider;
  assert.equal(saved.headers!.authorization, "Bearer fixture-second-key");
  assert.equal(saved.credentials![0]!.headers.authorization, "Bearer fixture-second-key");
  assert.equal(saved.credentials![0]!.id, "second");
});

test("Google probe will not forward environment credentials to custom destinations or through redirects", async t => {
  const old = process.env.GEMINI_API_KEY;
  process.env.GEMINI_API_KEY = "fixture-environment-secret";
  t.after(() => { if (old === undefined) delete process.env.GEMINI_API_KEY; else process.env.GEMINI_API_KEY = old; });
  const calls: { url: string; init: RequestInit }[] = [];
  const f = await fixture(t, {}, { probeFetch: async (url, init) => { calls.push({ url, init }); return Response.json({ models: [] }); } });
  const probe = (body: unknown) => fetch(`${f.base}/api/providers/probe`, { method: "POST", headers: f.headers, body: JSON.stringify({ type: "google", auth: "api-key", ...(body as object) }) });
  for (const url of ["https://collector.example", "http://127.0.0.1:9876", "http://generativelanguage.googleapis.com", "https://generativelanguage.googleapis.com.evil.example", "https://generativelanguage.googleapis.com@collector.example"]) {
    const response = await probe({ url });
    assert.equal((await response.json() as { ok: boolean }).ok, false);
  }
  assert.equal(calls.length, 0);
  assert.equal((await (await probe({})).json() as { ok: boolean }).ok, true);
  assert.equal(new Headers(calls[0]!.init.headers).get("x-goog-api-key"), "fixture-environment-secret");
  assert.equal(calls[0]!.init.redirect, "manual");
  await probe({ url: "https://custom.example", apiKey: "fixture-custom-key" });
  assert.equal(new Headers(calls[1]!.init.headers).get("x-goog-api-key"), "fixture-custom-key");
  assert.equal(calls[1]!.init.redirect, "manual");
});

test("Google probe restores a masked saved key only for its named original destination", async t => {
  const sent: string[] = [];
  const f = await fixture(t, { google: { type: "google", auth: "api-key", apiKey: "fixture-google-secret" } }, {
    probeFetch: async (_url, init) => { sent.push(new Headers(init.headers).get("x-goog-api-key")!); return Response.json({ models: [] }); },
  });
  const probe = (extra: object) => fetch(`${f.base}/api/providers/probe`, { method: "POST", headers: f.headers, body: JSON.stringify({ type: "google", auth: "api-key", apiKey: REDACTED_SECRET, ...extra }) });
  assert.equal((await probe({})).status, 400);
  assert.equal((await probe({ name: "google", url: "https://collector.example" })).status, 400);
  assert.equal((await probe({ name: "google" })).status, 200);
  assert.deepEqual(sent, ["fixture-google-secret"]);
});

test("Grok ambient credentials require its official origin or an unchanged saved provider", async t => {
  const calls: { url: string; init: RequestInit }[] = [];
  const f = await fixture(t, {}, { probeFetch: async (url, init) => { calls.push({ url, init }); return Response.json({ data: [{ id: "grok-4.7" }] }); } });
  const home = path.join(f.home, "grok");
  fs.mkdirSync(home);
  fs.writeFileSync(path.join(home, "auth.json"), JSON.stringify({ "https://auth.x.ai::fixture": { key: "fixture-grok-credential", expires_at: new Date(Date.now() + 5 * 3600_000).toISOString() } }));
  const cfg = f.readConfig();
  cfg.providers.saved = { type: "grok", url: "https://custom.grok.example/v1", home, clientVersion: "1.0.46" };
  fs.writeFileSync(f.configFile, JSON.stringify(cfg));
  const probe = (changes: object) => fetch(`${f.base}/api/providers/probe`, { method: "POST", headers: f.headers, body: JSON.stringify({ type: "grok", home, clientVersion: "1.0.46", ...changes }) });
  for (const changes of [
    { url: "https://collector.example" },
    { url: "http://cli-chat-proxy.grok.com/v1" },
    { url: "https://cli-chat-proxy.grok.com.evil.example/v1" },
    { url: "https://cli-chat-proxy.grok.com@collector.example/v1" },
    { name: "saved", url: "https://collector.example" },
    { name: "saved", url: "https://custom.grok.example/v1", home: `${home}-different` },
    { name: "saved", url: "https://custom.grok.example/v1", cli: "unconfigured-cli" },
  ]) {
    assert.equal((await (await probe(changes)).json() as { ok: boolean }).ok, false);
  }
  assert.equal(calls.length, 0, "rejected destinations never fetch or read an alternate credential source");
  assert.equal((await (await probe({})).json() as { ok: boolean }).ok, true);
  assert.equal((await (await probe({ name: "saved", url: "https://custom.grok.example/v1" })).json() as { ok: boolean }).ok, true);
  assert.equal(calls.length, 2);
  for (const call of calls) {
    assert.equal(new Headers(call.init.headers).get("authorization"), "Bearer fixture-grok-credential");
    assert.equal(call.init.redirect, "manual");
  }
});

test("a live redirecting custom Google probe never sends its explicit key to the redirect target", async t => {
  let collected = 0;
  let originalCalls = 0;
  let originalKey: string | string[] | undefined;
  const collector = http.createServer((req, res) => { collected++; req.resume(); res.end("{}"); });
  await new Promise<void>(resolve => collector.listen(0, "127.0.0.1", resolve));
  const address = collector.address() as import("node:net").AddressInfo;
  const redirect = http.createServer((req, res) => {
    originalCalls++;
    originalKey = req.headers["x-goog-api-key"];
    req.resume();
    res.writeHead(302, { location: `http://127.0.0.1:${address.port}/stolen` }).end();
  });
  await new Promise<void>(resolve => redirect.listen(0, "127.0.0.1", resolve));
  t.after(() => { collector.closeAllConnections(); collector.close(); redirect.closeAllConnections(); redirect.close(); });
  const source = redirect.address() as import("node:net").AddressInfo;
  const f = await fixture(t);
  const response = await fetch(`${f.base}/api/providers/probe`, { method: "POST", headers: f.headers, body: JSON.stringify({ type: "google", auth: "api-key", url: `http://127.0.0.1:${source.port}`, apiKey: "fixture-explicit-secret" }) });
  assert.equal(response.status, 403);
  const body = await response.text();
  assert.match(body, /redirect refused/i);
  assert.doesNotMatch(body, /fixture-explicit-secret|\/stolen/);
  assert.equal(originalCalls, 1, "security refusals do not start a second probe or pagination request");
  assert.equal(originalKey, "fixture-explicit-secret");
  assert.equal(collected, 0);
});

for (const provider of ["google", "anthropic", "openai-compatible"] as const) {
  test(`${provider} probe errors do not reflect the outbound secret`, async t => {
    const key = `fixture-opaque-${provider}-credential`;
    let throwError = false;
    const probeFetch = async () => {
      if (throwError) throw new Error(`upstream failed with ${key}`);
      return new Response(`refused credential ${key}`, { status: 400 });
    };
    const f = await fixture(t, {}, { probeFetch, probeModelFetch: probeFetch });
    const body = provider === "openai-compatible"
      ? { type: provider, url: "https://vendor.example/v1", headers: { authorization: `Bearer ${key}` } }
      : { type: provider, auth: "api-key", apiKey: key };
    for (const throws of [false, true]) {
      throwError = throws;
      const response = await fetch(`${f.base}/api/providers/probe`, { method: "POST", headers: f.headers, body: JSON.stringify(body) });
      assert.equal(response.status, 200);
      const result = await response.text();
      assert.ok(!result.includes(key), "neither response bodies nor transport exceptions reveal the key");
      assert.match(result, /REDACTED/);
    }
  });
}
