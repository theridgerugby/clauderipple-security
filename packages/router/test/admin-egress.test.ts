import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { DEFAULTS, type Config } from "../src/config.ts";
import { Logger } from "../src/log.ts";
import { RequestLog } from "../src/requestlog.ts";
import { writePrivateFileAtomic } from "../src/locked-file.ts";
import { GrokAuth } from "../src/providers/grok/auth.ts";
import type { AdminDeps } from "../src/admin.ts";
import { startAdmin, fetch as adminFetch } from "./admin-client.ts";

const SECRET = "synthetic-probe-key-not-a-real-credential";

async function fixture(t: TestContext) {
  let destinationCalls = 0;
  const requests: { url: string; body: string; authorization: string | undefined }[] = [];
  let destination = "";
  const sink = http.createServer((req, res) => { destinationCalls++; req.resume(); res.end("unexpected"); });
  const source = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    requests.push({ url: req.url ?? "", body, authorization: req.headers.authorization ?? req.headers["x-api-key"] as string | undefined });
    res.writeHead(307, { location: `${destination}/sink?secret=${SECRET}` }).end(SECRET);
  });
  t.after(async () => {
    for (const server of [source, sink]) {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });
  sink.listen(0, "127.0.0.1"); await once(sink, "listening");
  destination = `http://127.0.0.1:${(sink.address() as { port: number }).port}`;
  source.listen(0, "127.0.0.1"); await once(source, "listening");
  const url = `http://127.0.0.1:${(source.address() as { port: number }).port}`;
  const attempts: { url: string; signal: AbortSignal | null | undefined }[] = [];
  const transport = async (requested: string, init: RequestInit): Promise<Response> => {
    assert.equal(init.redirect, "manual");
    attempts.push({ url: requested, signal: init.signal });
    return fetch(url, init);
  };
  return { requests, attempts, transport, destinationCalls: () => destinationCalls };
}

async function admin(t: TestContext, cfg: Config, transport: NonNullable<AdminDeps["probeFetch"]>, extraDeps: Partial<AdminDeps> = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-egress-"));
  const previousHome = process.env.CLAUDERIPPLE_HOME;
  const previousSettings = process.env.CLAUDE_SETTINGS_PATH;
  process.env.CLAUDERIPPLE_HOME = home;
  process.env.CLAUDE_SETTINGS_PATH = path.join(home, "fixture-claude-settings.json");
  let server: Awaited<ReturnType<typeof startAdmin>> | undefined;
  t.after(() => {
    server?.close();
    if (previousHome === undefined) delete process.env.CLAUDERIPPLE_HOME;
    else process.env.CLAUDERIPPLE_HOME = previousHome;
    if (previousSettings === undefined) delete process.env.CLAUDE_SETTINGS_PATH;
    else process.env.CLAUDE_SETTINGS_PATH = previousSettings;
    fs.rmSync(home, { recursive: true, force: true });
  });
  const configFile = path.join(home, "config.json");
  writePrivateFileAtomic(configFile, JSON.stringify(cfg));
  server = await startAdmin({
    config: () => cfg, configFile,
    log: new Logger(null, 1_000_000, 1, false),
    stats: () => ({ inFlight: 0, messagesInFlight: 0, started: 0, completed: 0, failed: 0 }),
    health: () => 0, version: "0.0.0-egress-test",
    requests: new RequestLog(path.join(home, "requests.jsonl")),
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    probeFetch: transport, probeModelFetch: transport, measureFetch: transport,
    modelCatalog: async () => undefined,
    ...extraDeps,
  });
  const origin = `http://127.0.0.1:${server.port}`;
  const post = (resource: string, body: unknown) => adminFetch(origin + resource, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { configFile, origin, post };
}

const probes: [string, Record<string, unknown>][] = [
  ["Anthropic key catalogue before inference", { type: "anthropic", auth: "api-key", apiKey: SECRET }],
  ["Google key catalogue before pagination", { type: "google", auth: "api-key", apiKey: SECRET }],
  ["compatible catalogue before second endpoint", {
    type: "openai-compatible", url: "https://second-fixture.invalid/v1", modelsUrl: "https://catalogue-fixture.invalid/models",
    headers: { authorization: `Bearer ${SECRET}` },
  }],
];

for (const [label, request] of probes) {
  test(`admin probe: ${label} refuses a redirect without sending a follow-up probe`, async t => {
    const upstream = await fixture(t);
    const server = await admin(t, { ...DEFAULTS, admin: { port: 0 }, providers: {} }, upstream.transport);
    const response = await server.post("/api/providers/probe", request);
    assert.equal(response.status, 403);
    const text = await response.text();
    assert.match(text, /redirect refused/i);
    assert.doesNotMatch(text, /synthetic-probe-key|\/sink|second-fixture/);
    assert.equal(upstream.attempts.length, 1);
    assert.equal(upstream.requests.length, 1);
    assert.equal(upstream.destinationCalls(), 0);
  });
}

test("a measurement redirect cancels siblings, stops queued candidates and leaves config untouched", async t => {
  const upstream = await fixture(t);
  const ids = Array.from({ length: 12 }, (_, n) => `fixture-model-${n}`);
  const cfg: Config = { ...DEFAULTS, admin: { port: 0 }, providers: {
    test: { type: "openai-compatible", wire: "chat", url: "https://provider-fixture.invalid/v1", headers: { authorization: `Bearer ${SECRET}` }, models: ids.map(id => ({ id })) },
  } };
  const server = await admin(t, cfg, upstream.transport);
  const before = fs.readFileSync(server.configFile);
  const response = await server.post("/api/providers/measure", { provider: "test", models: ids });
  assert.equal(response.status, 202);
  const { jobId } = await response.json() as { jobId: string };
  let job: { state: string; error?: string } | undefined;
  for (let n = 0; n < 40; n++) {
    job = await (await adminFetch(`${server.origin}/api/providers/measure/${jobId}`)).json() as typeof job;
    if (job?.state !== "running") break;
    await new Promise<void>(resolve => setTimeout(resolve, 25));
  }
  assert.equal(job?.state, "failed");
  assert.match(job?.error ?? "", /redirect refused/i);
  assert.doesNotMatch(job?.error ?? "", /synthetic-probe-key|\/sink/);
  assert.ok(upstream.attempts.length > 0 && upstream.attempts.length <= 4, "only already-started parallel workers may contact the original endpoint");
  assert.ok(upstream.attempts.every(attempt => attempt.url.endsWith("/chat/completions")), "no alternative wire was attempted");
  assert.ok(upstream.attempts.every(attempt => attempt.signal?.aborted), "all outstanding transports were cancelled");
  assert.equal(upstream.destinationCalls(), 0);
  assert.deepEqual(fs.readFileSync(server.configFile), before);
});

for (const type of ["grok", "antigravity"] as const) {
  test(`personal admin refuses an unsaved ${type} probe before credential or CLI access`, async t => {
    let credentialCalls = 0;
    let transportCalls = 0;
    t.mock.method(GrokAuth.prototype, "token", async () => { credentialCalls++; throw new Error("unexpected synthetic credential lookup"); });
    t.mock.method(GrokAuth.prototype, "clientVersion", async () => { credentialCalls++; throw new Error("unexpected external CLI version lookup"); });
    const server = await admin(t, { ...DEFAULTS, admin: { port: 0 }, providers: {},
      security: { mode: "personal", approvedOrigins: [] },
    }, async () => { transportCalls++; throw new Error("unexpected provider transport"); }, {
      google: () => { credentialCalls++; throw new Error("unexpected Google account lookup"); },
    });
    const before = fs.readFileSync(server.configFile);
    const response = await server.post("/api/providers/probe", type === "grok"
      ? { type: "grok", home: path.join(path.dirname(server.configFile), "unavailable-grok-home"), cli: process.execPath }
      : { type: "google", auth: "antigravity" });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /disabled in personal mode/i);
    assert.equal(credentialCalls, 0);
    assert.equal(transportCalls, 0);
    assert.deepEqual(fs.readFileSync(server.configFile), before);
  });
}

test("personal admin refuses Google subscription login and code submission before starting OAuth", async t => {
  let browserCalls = 0;
  let transportCalls = 0;
  const server = await admin(t, { ...DEFAULTS, admin: { port: 0 }, providers: {},
    security: { mode: "personal", approvedOrigins: [] },
  }, async () => { transportCalls++; throw new Error("unexpected provider transport"); }, {
    googleOAuthPort: 0,
    googleOAuthFetch: async () => { transportCalls++; throw new Error("unexpected OAuth transport"); },
    openBrowser: () => { browserCalls++; return false; },
  });
  const before = fs.readFileSync(server.configFile);
  for (const resource of ["/api/google-login", "/api/google-login/code"]) {
    const response = await server.post(resource, { code: "synthetic-unused-code" });
    assert.equal(response.status, 403);
    assert.match(await response.text(), /disabled in the personal Desktop profile/i);
  }
  // The complete subscription-login surface stays unavailable; no OAuth session or browser
  // launch was created by either POST, and status/cancel cannot reopen that integration.
  const state = await adminFetch(`${server.origin}/api/google-login`);
  assert.equal(state.status, 403);
  assert.match(await state.text(), /disabled in the personal Desktop profile/i);
  const cancelled = await server.post("/api/google-login/cancel", {});
  assert.equal(cancelled.status, 403);
  await cancelled.arrayBuffer();
  assert.equal(browserCalls, 0);
  assert.equal(transportCalls, 0);
  assert.deepEqual(fs.readFileSync(server.configFile), before);
});
