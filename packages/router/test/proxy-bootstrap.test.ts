// Local TLS fixtures only: no Desktop installation, real accounts, trust changes or public calls.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import zlib from "node:zlib";
import { once } from "node:events";
import type { Duplex } from "node:stream";
import { CertStore } from "../src/certs.ts";
import { normalizeConfig, type Config } from "../src/config.ts";
import { UpstreamHealth } from "../src/health.ts";
import { Logger } from "../src/log.ts";
import { BOOTSTRAP_BUFFER_LIMIT, BOOTSTRAP_DECODE_LIMIT, Proxy } from "../src/proxy.ts";
import { RequestLog } from "../src/requestlog.ts";
import { DESKTOP_PICKER_ROW_LIMIT } from "../src/picker.ts";
import { createCa, createLeaf } from "../src/x509.ts";

const GOOGLE_MODEL = "gemini-bootstrap-fixture";
const PRIVATE = "SYNTHETIC-PRIVATE-BOOTSTRAP-PAYLOAD-7b7b";
const HEADER_SECRET = "SYNTHETIC-PRIVATE-HEADER-3a3a";
const QUERY_SECRET = "SYNTHETIC-PRIVATE-QUERY-2c2c";
const PROVIDER_SECRET = "SYNTHETIC-GOOGLE-BOOTSTRAP-KEY";
const fixture = () => ({
  account: { privateResearch: PRIVATE },
  model_selector_config: [
    { id: "chat", models: [{ id: "claude-opus-5-5", name: "Native chat" }] },
    { id: "code", models: [{ id: "claude-opus-5-5", name: "Native Opus", context_window: 200_000 }] },
  ],
  model_selector_state: [{ id: "code", model: "claude-opus-5-5" }],
});
const nativeHeaders = { "content-type": "application/json", etag: '"native-version"',
  "last-modified": "Tue, 17 Nov 2026 00:00:00 GMT", "cache-control": "private, max-age=30", "set-cookie": "fixture=native; Secure", "x-fixture-secret": HEADER_SECRET };
type Reply = { status: number; headers: http.IncomingHttpHeaders; rawHeaders: string[]; body: Buffer };
type Handler = (req: http.IncomingMessage, res: http.ServerResponse, body: Buffer) => void;
type SendOptions = { method?: string; body?: Buffer | string; headers?: http.OutgoingHttpHeaders; signal?: AbortSignal };

async function rig(t: TestContext, host = "claude.ai") {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-bootstrap-"));
  const ca = createCa({ cn: "Synthetic bootstrap CA" });
  const leaf = createLeaf({ host, caCertPem: ca.certPem, caKeyPem: ca.keyPem });
  let cfg: Config = normalizeConfig({
    security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com", "https://claude.ai", "https://generativelanguage.googleapis.com"] },
    listen: { host: "127.0.0.1", port: 0 }, picker: { enabled: true }, autoUpdate: false,
    providers: { google: { type: "google", auth: "api-key", apiKey: PROVIDER_SECRET, models: [{ id: GOOGLE_MODEL }] } },
    aliases: {}, routes: {}, direct: [], cli: { extraModels: [{ model: GOOGLE_MODEL, name: "Fixture Gemini" }] },
  });
  const sockets = new Set<Duplex>();
  const agents: https.Agent[] = [];
  const captured: { method: string; path: string; headers: http.IncomingHttpHeaders; rawHeaders: string[]; body: Buffer }[] = [];
  const log = new Logger(null, 4096, 1, false, true);
  const certs = new CertStore(home);
  certs.register(host, Buffer.from(leaf.certPem), Buffer.from(leaf.keyPem));
  let handler: Handler = (_req, res) => res.writeHead(200, nativeHeaders).end(JSON.stringify(fixture()));
  const upstream = https.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", chunk => chunks.push(chunk));
    req.once("end", () => {
      const body = Buffer.concat(chunks);
      captured.push({ method: req.method!, path: req.url!, headers: { ...req.headers }, rawHeaders: [...req.rawHeaders], body });
      handler(req, res, body);
    });
  });
  upstream.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
  upstream.listen(0, "127.0.0.1");
  await once(upstream, "listening");
  const upstreamPort = (upstream.address() as net.AddressInfo).port;
  const upstreamAgent = new https.Agent({ keepAlive: false });
  agents.push(upstreamAgent);
  upstreamAgent.createConnection = options => {
    assert.equal(options.host, host, "only the selected local fixture may be dialled");
    return tls.connect({ host: "127.0.0.1", port: upstreamPort, servername: host, ca: ca.certPem, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
  };
  const proxy = new Proxy({ config: () => cfg, home, log, certs, upstreamAgent,
    requests: new RequestLog(path.join(home, "requests.jsonl"), 10, 4096, true),
    health: new UpstreamHealth(() => 100, () => {}), agentDir: path.join(home, "agents"),
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    claudeLoginKey: () => undefined, claudeProfileFetch: async () => new Response("{}", { status: 404 }),
  });
  const internals = proxy as unknown as { server: net.Server; providerAgents: Map<string, https.Agent> };
  if (host === "claude.ai") internals.providerAgents.set("host:claude.ai|https:", upstreamAgent);
  await proxy.listen();
  const proxyPort = (internals.server.address() as net.AddressInfo).port;
  t.after(async () => {
    proxy.close();
    for (const agent of agents) agent.destroy();
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => upstream.close(() => resolve()));
    log.close();
    fs.rmSync(home, { recursive: true, force: true });
  });
  const send = async (requestPath = `/api/bootstrap/synthetic-fixture-org/app_start?private=${QUERY_SECRET}`, onData?: (chunk: Buffer) => void, options: SendOptions = {}): Promise<Reply> => {
    const socket = net.connect({ host: "127.0.0.1", port: proxyPort });
    sockets.add(socket); socket.on("error", () => {});
    await once(socket, "connect");
    const accepted = once(socket, "data");
    socket.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`);
    assert.match(String((await accepted)[0]), /^HTTP\/1\.1 200 /);
    const secure = tls.connect({ socket, servername: host, ca: ca.certPem, rejectUnauthorized: true });
    sockets.add(secure); secure.on("error", () => {});
    await once(secure, "secureConnect");
    const agent = new https.Agent({ keepAlive: false }); agents.push(agent);
    agent.createConnection = () => secure;
    return await new Promise<Reply>((resolve, reject) => {
      const request = https.request({ host, port: 443, path: requestPath, agent, method: options.method ?? "GET",
        ...(options.signal ? { signal: options.signal } : {}),
        headers: { connection: "close", "x-fixture-secret": HEADER_SECRET, cookie: `fixture=${HEADER_SECRET}`,
          ...(options.body !== undefined ? { "content-type": "application/json", "content-length": Buffer.byteLength(options.body) } : {}), ...options.headers } }, response => {
        const chunks: Buffer[] = [];
        response.on("data", chunk => { chunks.push(chunk); onData?.(chunk); });
        response.once("error", reject);
        response.once("end", () => resolve({ status: response.statusCode!, headers: response.headers, rawHeaders: response.rawHeaders, body: Buffer.concat(chunks) }));
      });
      request.once("error", reject);
      request.setTimeout(10_000, () => request.destroy(new Error("synthetic bootstrap fixture timed out")));
      request.end(options.body);
    });
  };
  return { proxy, log, send, captured, setHandler: (next: Handler) => { handler = next; },
    change: (next: (old: Config) => Config) => { cfg = next(cfg); proxy.reconcileConfig(cfg); },
    reply: (body: Buffer, headers: http.OutgoingHttpHeaders = {}, status = 200) => {
      handler = (_req, res) => res.writeHead(status, { ...nativeHeaders, "content-length": body.length, ...headers }).end(body);
    },
  };
}

function assertNative(reply: Reply, body: Buffer, encoding?: string, status = 200) {
  assert.equal(reply.status, status);
  assert.deepEqual(reply.body, body);
  assert.equal(reply.headers["content-encoding"], encoding);
  assert.equal(reply.headers.etag, nativeHeaders.etag);
  assert.equal(reply.headers["last-modified"], nativeHeaders["last-modified"]);
  assert.equal(reply.headers["cache-control"], nativeHeaders["cache-control"]);
  assert.deepEqual(reply.headers["set-cookie"], [nativeHeaders["set-cookie"]]);
  assert.equal(reply.headers["x-fixture-secret"], HEADER_SECRET);
}

function assertNoSensitiveDiagnostics(r: Awaited<ReturnType<typeof rig>>) {
  const output = `${r.log.memoryTail(500)}${JSON.stringify(r.proxy.lastPickerInjection)}`;
  for (const value of [PRIVATE, HEADER_SECRET, QUERY_SECRET, PROVIDER_SECRET]) assert.ok(!output.includes(value), `diagnostics included ${value}`);
  assert.ok(!output.includes("/api/bootstrap"), "diagnostics contain no request path");
}

for (const encoding of ["identity", "gzip", "deflate", "br", "zstd"] as const) {
  test(`bootstrap ${encoding}: successful edit updates only the response representation and gives bounded diagnostics`, { timeout: 15_000 }, async t => {
    const r = await rig(t);
    const json = fixture();
    const plain = Buffer.from(JSON.stringify(json));
    const raw = encoding === "gzip" ? zlib.gzipSync(plain) : encoding === "deflate" ? zlib.deflateSync(plain)
      : encoding === "br" ? zlib.brotliCompressSync(plain) : encoding === "zstd" ? zlib.zstdCompressSync(plain) : plain;
    r.reply(raw, encoding === "identity" ? {} : { "content-encoding": encoding });
    const reply = await r.send();
    assert.equal(reply.status, 200);
    assert.equal(reply.headers["content-encoding"], undefined);
    assert.equal(reply.headers["content-length"], String(reply.body.length));
    assert.equal(reply.headers.etag, undefined);
    assert.equal(reply.headers["last-modified"], undefined);
    assert.equal(reply.headers["cache-control"], "no-store");
    const parsed = JSON.parse(reply.body.toString("utf8"));
    assert.deepEqual(parsed.model_selector_config[0], json.model_selector_config[0], "native Chat entries stay untouched");
    assert.deepEqual(parsed.model_selector_config[1].models.map((model: { id: string }) => model.id), ["claude-opus-5-5", GOOGLE_MODEL]);
    assert.equal(r.proxy.lastPickerInjection?.injected, 1);
    assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "injected");
    assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 1);
    assert.deepEqual(r.proxy.lastPickerInjection?.observation.schema, { config: "array", state: "array", surfaces: 2, codeSurfaces: 1, models: 1 });
    assert.deepEqual(r.proxy.lastPickerInjection?.surfaces.map(surface => surface.id), ["code"]);
    assertNoSensitiveDiagnostics(r);
  });
}

for (const [name, body, encoding, outcome] of [
  ["unknown schema", Buffer.from(JSON.stringify({ [PRIVATE]: { account: HEADER_SECRET }, model_selector_state: { private: PRIVATE } })), "gzip", "unsupported-schema"],
  ["malformed schema", Buffer.from(JSON.stringify({ model_selector_config: [{ id: "code", models: [null] }], private: PRIVATE })), "br", "unsupported-schema"],
  ["unknown surface", Buffer.from(JSON.stringify({ model_selector_config: [{ id: PRIVATE, models: [{ id: HEADER_SECRET }] }] })), "identity", "unsupported-schema"],
  ["invalid JSON", Buffer.from(`${PRIVATE} invalid-json-with-private-data`), "gzip", "invalid-json"],
  ["invalid UTF-8", Buffer.concat([Buffer.from('{"secret":"'), Buffer.from([0xff]), Buffer.from('"}')]), "identity", "invalid-json"],
  ["truncated gzip", Buffer.from(PRIVATE), "gzip", "decode-failed"],
  ["unsupported encoding", Buffer.from(PRIVATE), "future-secret-encoding", "unsupported-encoding"],
] as const) {
  test(`bootstrap ${name} preserves native bytes and headers and clears stale picker success`, { timeout: 15_000 }, async t => {
    const r = await rig(t);
    await r.send();
    assert.equal(r.proxy.lastPickerInjection?.injected, 1);
    const raw = name === "truncated gzip" || encoding === "identity" || encoding === "future-secret-encoding" ? body
      : encoding === "br" ? zlib.brotliCompressSync(body) : zlib.gzipSync(body);
    r.reply(raw, encoding === "identity" ? {} : { "content-encoding": encoding });
    assertNative(await r.send(), raw, encoding === "identity" ? undefined : encoding);
    assert.equal(r.proxy.lastPickerInjection?.observation.outcome, outcome);
    assert.equal(r.proxy.lastPickerInjection?.injected, 0);
    assert.deepEqual(r.proxy.lastPickerInjection?.surfaces, []);
    assertNoSensitiveDiagnostics(r);
  });
}

test("zero additions retain exact compressed bytes and native caching headers", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const j = fixture();
  j.model_selector_config[1]!.models.push({ id: GOOGLE_MODEL, name: "Already native-listed fixture", context_window: 200_000 });
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify(j, null, 3)));
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "unchanged");
  assert.equal(r.proxy.lastPickerInjection?.injected, 0);
  r.change(cfg => ({ ...cfg, cli: { ...cfg.cli, extraModels: [] } }));
  assertNative(await r.send(), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "no-extra-models");
  assertNoSensitiveDiagnostics(r);
});

for (const status of [401, 403, 429, 500]) {
  test(`native bootstrap ${status} retains error bytes and headers without leaking content or waiting on a consumed stream`, { timeout: 15_000 }, async t => {
    const r = await rig(t);
    const raw = zlib.gzipSync(Buffer.from(JSON.stringify({ error: PRIVATE })));
    r.reply(raw, { "content-encoding": "gzip" }, status);
    assertNative(await r.send(), raw, "gzip", status);
    assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "upstream-status");
    assert.equal(r.proxy.stats.inFlight, 0);
    assertNoSensitiveDiagnostics(r);
  });
}

test("native bootstrap 304 remains bodyless and keeps its native cache validator", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  r.reply(Buffer.alloc(0), {}, 304);
  assertNative(await r.send(), Buffer.alloc(0), undefined, 304);
  assert.equal(r.proxy.lastPickerInjection?.observation.status, 304);
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "upstream-status");
});

test("declared oversized bootstrap passes through with its original encoding and clears stale success", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  await r.send();
  const raw = Buffer.alloc(BOOTSTRAP_BUFFER_LIMIT + 1, 0x61);
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "encoded-limit");
  assert.deepEqual(r.proxy.lastPickerInjection?.surfaces, []);
});

test("chunked oversized bootstrap starts transparent forwarding before upstream end and loses no prefix", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const first = Buffer.alloc(BOOTSTRAP_BUFFER_LIMIT + 65536, 0x62), tail = Buffer.from("fixture tail");
  let endUpstream: (() => void) | undefined;
  r.setHandler((_req, res) => {
    res.writeHead(200, nativeHeaders);
    res.write(first);
    endUpstream = () => res.end(tail);
  });
  const received = Promise.withResolvers<void>();
  const reply = r.send(undefined, () => received.resolve());
  const deadline = setTimeout(() => received.reject(new Error("oversized bootstrap was not streamed before end")), 5000);
  try {
    await received.promise;
    assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "encoded-limit");
    assert.equal(r.proxy.stats.inFlight, 1);
  } finally { clearTimeout(deadline); endUpstream?.(); }
  assertNative(await reply, Buffer.concat([first, tail]));
  assert.equal(r.proxy.stats.inFlight, 0);
});

test("compressed expansion is bounded and returns the native compressed representation unchanged", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  await r.send();
  const raw = zlib.gzipSync(Buffer.alloc(BOOTSTRAP_DECODE_LIMIT + 1, 0x63));
  assert.ok(raw.length < BOOTSTRAP_BUFFER_LIMIT);
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "decoded-limit");
  assert.deepEqual(r.proxy.lastPickerInjection?.surfaces, []);
  assertNoSensitiveDiagnostics(r);
});

test("a truncated bootstrap stream clears stale success, releases the request and leaves the next bootstrap usable", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  await r.send();
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "injected");
  r.setHandler((_req, res) => {
    res.writeHead(200, { ...nativeHeaders, "content-length": 4096 });
    res.write(`{"secret":"${PRIVATE}`);
    setImmediate(() => res.destroy(new Error(PRIVATE)));
  });
  await assert.rejects(r.send());
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "stream-failed");
  assert.deepEqual(r.proxy.lastPickerInjection?.surfaces, []);
  assert.equal(r.proxy.stats.inFlight, 0);
  assertNoSensitiveDiagnostics(r);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal((await r.send()).status, 200);
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "injected");
});

test("integrity-protected native bootstrap is not edited and retains its integrity headers", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify(fixture())));
  r.reply(raw, { "content-encoding": "gzip", "content-digest": "sha-256=:synthetic-integrity:" });
  const reply = await r.send();
  assertNative(reply, raw, "gzip");
  assert.equal(reply.headers["content-digest"], "sha-256=:synthetic-integrity:");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "integrity-protected");
});

test("admin catalogue is bounded and excludes unknown surface names and model object fields", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const j = fixture();
  j.model_selector_config[1]!.models = Array.from({ length: 300 }, (_, i) => ({ id: `claude-fixture-${i}`, name: `Native ${i} ${"n".repeat(300)}`, context_window: 200_000, privateField: PRIVATE }));
  j.model_selector_config.push({ id: PRIVATE, models: [{ id: "claude-secret-surface", name: HEADER_SECRET, context_window: 200_000 }] });
  r.reply(Buffer.from(JSON.stringify(j)));
  await r.send();
  const saved = r.proxy.lastPickerInjection!;
  assert.deepEqual(saved.surfaces.map(surface => surface.id), ["code"]);
  assert.equal(saved.surfaces[0]!.entries.length, 256);
  assert.ok(saved.surfaces[0]!.entries.every(entry => entry.name.length <= 161 && Object.keys(entry).length === 2));
  assertNoSensitiveDiagnostics(r);
});

test("CLI bootstrap also preserves invalid compression and zero-edit native bodies", { timeout: 15_000 }, async t => {
  const r = await rig(t, "api.anthropic.com");
  const requestPath = `/api/claude_cli/bootstrap?private=${QUERY_SECRET}`;
  const broken = Buffer.from(PRIVATE);
  r.reply(broken, { "content-encoding": "gzip" });
  assertNative(await r.send(requestPath), broken, "gzip");
  r.change(cfg => ({ ...cfg, cli: { ...cfg.cli, extraModels: [] } }));
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify({ private: PRIVATE }, null, 2)));
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(requestPath), raw, "gzip");
  assertNoSensitiveDiagnostics(r);
});

const STATE_ORG = "synthetic-private-org-45d9";
const STATE_BOOTSTRAP = `/edge-api/bootstrap/${STATE_ORG}/app_start?private=${QUERY_SECRET}`;
const STATE_PATH = `/api/organizations/${STATE_ORG}/model_selector_state/code?private=${QUERY_SECRET}`;
const STATE_REFUSAL = Buffer.from(JSON.stringify({ error: { details: { error_code: "model_not_selectable" } } }));
const extraWrite = JSON.stringify({ model: GOOGLE_MODEL });
const nativeState = (model = "claude-opus-5-5") => ({ id: "code", model });
const selectedModel = (reply: Reply): string => JSON.parse(reply.body.toString("utf8")).model_selector_state[0].model;
const stateWrite = (r: Awaited<ReturnType<typeof rig>>, body = extraWrite, requestPath = STATE_PATH, options: SendOptions = {}) =>
  r.send(requestPath, undefined, { method: "PATCH", body, ...options });

function assertStatePrivacy(r: Awaited<ReturnType<typeof rig>>) {
  assertNoSensitiveDiagnostics(r);
  const diagnostics = `${r.log.memoryTail(500)}${JSON.stringify(r.proxy.lastPickerInjection)}`;
  assert.ok(!diagnostics.includes(STATE_ORG), "raw organization never appears in diagnostics");
  assert.ok(!diagnostics.includes("/model_selector_state/"), "native state path never appears in diagnostics");
  for (const req of r.captured) {
    assert.ok(!JSON.stringify(req.headers).includes(PROVIDER_SECRET), "Google key never reaches native Claude bootstrap/state");
    assert.ok(!req.body.includes(PROVIDER_SECRET), "Google key never appears in native request bodies");
    assert.equal(req.headers["x-goog-api-key"], undefined);
  }
}

test("Desktop state round trip: Gemini selection is local, native selection is byte-preserving, subscription state returns", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  let selectedNative = "claude-opus-5-5";
  let nativeReply = Buffer.alloc(0);
  r.setHandler((req, res, body) => {
    if (req.method === "PATCH") {
      const asked = JSON.parse(body.toString("utf8")) as { model: string };
      if (asked.model === GOOGLE_MODEL) {
        res.writeHead(400, { ...nativeHeaders, "content-length": STATE_REFUSAL.length }).end(STATE_REFUSAL);
      } else {
        selectedNative = asked.model;
        nativeReply = zlib.gzipSync(Buffer.from(JSON.stringify(nativeState(selectedNative), null, 3)));
        res.writeHead(200, { ...nativeHeaders, "content-encoding": "gzip", "content-length": nativeReply.length }).end(nativeReply);
      }
    } else {
      const j = fixture(); j.model_selector_state = [nativeState(selectedNative)];
      res.writeHead(200, nativeHeaders).end(JSON.stringify(j));
    }
  });
  const boot = await r.send(STATE_BOOTSTRAP);
  assert.equal(selectedModel(boot), "claude-opus-5-5");
  const chosen = await stateWrite(r);
  assert.equal(chosen.status, 200);
  assert.deepEqual(JSON.parse(chosen.body.toString("utf8")), { id: "code", model: GOOGLE_MODEL, thinking_by_model: [] });
  assert.equal(chosen.headers.etag, undefined);
  assert.equal(chosen.headers["cache-control"], "no-store");
  assert.equal(chosen.headers["content-length"], String(chosen.body.length));
  assert.deepEqual(chosen.headers["set-cookie"], [nativeHeaders["set-cookie"]]);
  assert.equal(selectedNative, "claude-opus-5-5", "native account default never changed to a third-party model");
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), GOOGLE_MODEL);
  const nativeRequest = '{  "model": "claude-sonnet-5-5"  }';
  const switchedBack = await stateWrite(r, nativeRequest);
  assertNative(switchedBack, nativeReply, "gzip");
  const restored = await r.send(STATE_BOOTSTRAP);
  assert.equal(selectedModel(restored), "claude-sonnet-5-5");
  assert.deepEqual(JSON.parse(restored.body.toString("utf8")).model_selector_config[0], fixture().model_selector_config[0]);
  assert.deepEqual(r.captured.filter(req => req.method === "PATCH").map(req => req.body.toString("utf8")), [extraWrite, nativeRequest], "native request bodies are forwarded exactly");
  assert.ok(r.captured.every(req => req.headers.cookie === `fixture=${HEADER_SECRET}`), "native authentication is unchanged");
  assert.equal(r.proxy.stats.inFlight, 0);
  assertStatePrivacy(r);
});

for (const encoding of ["gzip", "deflate", "br", "zstd"] as const) {
  test(`Desktop extra ${encoding} refusal is decoded once and answered only in known selector-state shape`, { timeout: 15_000 }, async t => {
    const r = await rig(t);
    await r.send(STATE_BOOTSTRAP);
    const body = encoding === "gzip" ? zlib.gzipSync(STATE_REFUSAL) : encoding === "deflate" ? zlib.deflateSync(STATE_REFUSAL)
      : encoding === "br" ? zlib.brotliCompressSync(STATE_REFUSAL) : zlib.zstdCompressSync(STATE_REFUSAL);
    r.reply(body, { "content-encoding": encoding }, 400);
    const reply = await stateWrite(r);
    assert.equal(reply.status, 200);
    assert.equal(reply.headers["content-encoding"], undefined);
    assert.equal(reply.headers["content-type"], "application/json");
    assert.equal(reply.headers["content-length"], String(reply.body.length));
    assert.deepEqual(JSON.parse(reply.body.toString("utf8")), { id: "code", model: GOOGLE_MODEL, thinking_by_model: [] });
    assertStatePrivacy(r);
  });
}

for (const [name, status, raw] of [
  ["unauthenticated", 401, STATE_REFUSAL], ["forbidden", 403, STATE_REFUSAL], ["throttled", 429, STATE_REFUSAL], ["server error", 500, STATE_REFUSAL],
  ["unknown error", 400, Buffer.from(JSON.stringify({ error: { details: { error_code: "unknown_error" }, message: PRIVATE } }))],
  ["malformed error", 400, Buffer.from(`${PRIVATE} not JSON`)], ["wrong error shape", 400, Buffer.from(JSON.stringify({ model_not_selectable: true, private: PRIVATE }))],
] as const) {
  test(`Desktop extra ${name} remains exact native status, compressed bytes and headers`, { timeout: 15_000 }, async t => {
    const r = await rig(t);
    await r.send(STATE_BOOTSTRAP);
    const compressed = zlib.gzipSync(raw);
    r.reply(compressed, { "content-encoding": "gzip" }, status);
    assertNative(await stateWrite(r), compressed, "gzip", status);
    r.reply(Buffer.from(JSON.stringify(fixture())));
    assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
    assert.equal(r.proxy.stats.inFlight, 0);
    assertStatePrivacy(r);
  });
}

test("Desktop state scoping rejects another cookie or organization and keeps original request auth", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400);
  assertNative(await stateWrite(r, extraWrite, STATE_PATH, { headers: { cookie: "fixture=other-synthetic-account" } }), STATE_REFUSAL, undefined, 400);
  assertNative(await stateWrite(r, extraWrite, STATE_PATH.replace(STATE_ORG, "other-synthetic-org")), STATE_REFUSAL, undefined, 400);
  assert.equal(r.captured.at(-2)!.headers.cookie, "fixture=other-synthetic-account");
  assert.equal((await stateWrite(r)).status, 200, "the original authenticated scope still works");
  assertStatePrivacy(r);
});

test("additive Desktop updates keep the extra usable and retain new native metadata", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const j = { ...fixture(), schema_version: "synthetic-next-version", future_bootstrap_metadata: { native: true },
    model_selector_state: [{ ...nativeState(), future_native_field: { preserve: true }, revision: 1 }] };
  j.model_selector_config[1]!.models.push({ id: "future-native-model", name: "New native model", context_window: 200_000 });
  r.setHandler((req, res) => {
    if (req.method === "PATCH") res.writeHead(400, { ...nativeHeaders, "content-length": STATE_REFUSAL.length }).end(STATE_REFUSAL);
    else res.writeHead(200, nativeHeaders).end(JSON.stringify(j));
  });
  const boot = await r.send(STATE_BOOTSTRAP);
  const parsed = JSON.parse(boot.body.toString("utf8"));
  assert.deepEqual(parsed.model_selector_state, j.model_selector_state);
  assert.deepEqual(parsed.model_selector_config[1].models.slice(0, 2), j.model_selector_config[1]!.models);
  assert.equal(parsed.model_selector_config[1].models.at(-1).id, GOOGLE_MODEL);
  assert.equal(parsed.schema_version, j.schema_version);
  assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 1);
  const selected = await stateWrite(r);
  assert.equal(selected.status, 200);
  assert.deepEqual(JSON.parse(selected.body.toString("utf8")), { ...j.model_selector_state[0], model: GOOGLE_MODEL, thinking_by_model: [] });
  j.model_selector_state[0]!.revision = 2;
  const refreshed = JSON.parse((await r.send(STATE_BOOTSTRAP)).body.toString("utf8"));
  assert.deepEqual(refreshed.model_selector_state, [{ ...j.model_selector_state[0], model: GOOGLE_MODEL, thinking_by_model: [] }]);
  assert.deepEqual(refreshed.future_bootstrap_metadata, j.future_bootstrap_metadata);
  assertStatePrivacy(r);
});

test("an incompatible selector update hides unusable extras, preserves native bytes and recovers on the next compatible bootstrap", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400);
  assert.equal((await stateWrite(r)).status, 200);
  const j = { ...fixture(), model_selector_state: [{ ...nativeState(), thinking: { type: "future-thinking", effort: "high" } }] };
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify(j, null, 3)));
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(STATE_BOOTSTRAP), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.injected, 0);
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "unsupported-selection");
  assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 0);
  r.reply(STATE_REFUSAL, {}, 400);
  assertNative(await stateWrite(r), STATE_REFUSAL, undefined, 400);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  const restored = await r.send(STATE_BOOTSTRAP);
  assert.equal(selectedModel(restored), "claude-opus-5-5", "an unsupported shape cannot resurrect a stale extra choice");
  assert.equal(r.proxy.lastPickerInjection?.injected, 1);
  r.reply(STATE_REFUSAL, {}, 400);
  assert.equal((await stateWrite(r)).status, 200, "a new explicit extra selection succeeds after recovery");
  assertStatePrivacy(r);
});

test("mixed updated Code surfaces expose extras only where the selection contract is supported", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const j: Record<string, unknown> = { ...fixture(), model_selector_state: [nativeState(), { id: "ccd", model: { native: "changed-layout" } }] };
  const surfaces = j.model_selector_config as { id: string; models: { id: string; name: string }[] }[];
  surfaces.push({ id: "ccd", models: [{ id: "claude-opus-5-5", name: "Native desktop menu" }] });
  surfaces.push({ id: "future-code", models: [{ id: "claude-opus-5-5", name: "Native future surface" }] });
  r.reply(Buffer.from(JSON.stringify(j)));
  const parsed = JSON.parse((await r.send(STATE_BOOTSTRAP)).body.toString("utf8"));
  assert.equal(parsed.model_selector_config[1].models.at(-1).id, GOOGLE_MODEL);
  assert.deepEqual(parsed.model_selector_config[2], surfaces[2]);
  assert.deepEqual(parsed.model_selector_config[3], surfaces[3]);
  assert.deepEqual(parsed.model_selector_state, j.model_selector_state);
  assert.equal(r.proxy.lastPickerInjection?.injected, 1);
  assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 1);
  r.reply(STATE_REFUSAL, {}, 400);
  assertNative(await stateWrite(r, extraWrite, STATE_PATH.replace("/code?", "/ccd?")), STATE_REFUSAL, undefined, 400);
  assert.equal((await stateWrite(r)).status, 200);
  (j.model_selector_state as unknown[])[1] = { id: "ccd", model: "claude-opus-5-5", optional_metadata: "new-compatible-version" };
  r.reply(Buffer.from(JSON.stringify(j)));
  const recovered = JSON.parse((await r.send(STATE_BOOTSTRAP)).body.toString("utf8"));
  assert.equal(recovered.model_selector_config[2].models.at(-1).id, GOOGLE_MODEL);
  assert.deepEqual(recovered.model_selector_config[3], surfaces[3]);
  assert.equal(r.proxy.lastPickerInjection?.injected, 2);
  assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 2);
  assertStatePrivacy(r);
});

test("a full native menu stays byte-exact while a near-full menu adds only its safe remaining extras", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const json = fixture();
  const native = Array.from({ length: DESKTOP_PICKER_ROW_LIMIT }, (_, i) => ({ id: `claude-native-${i}`, name: `Native ${i}`, context_window: 200_000 }));
  json.model_selector_config[1]!.models = native;
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify(json, null, 2)));
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(STATE_BOOTSTRAP), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.injected, 0);
  assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 0);
  r.reply(STATE_REFUSAL, {}, 400);
  assertNative(await stateWrite(r), STATE_REFUSAL, undefined, 400);
  json.model_selector_config[1]!.models = native.slice(0, -1);
  r.reply(Buffer.from(JSON.stringify(json)));
  const partial = JSON.parse((await r.send(STATE_BOOTSTRAP)).body.toString("utf8"));
  assert.equal(partial.model_selector_config[1].models.length, DESKTOP_PICKER_ROW_LIMIT);
  assert.deepEqual(partial.model_selector_config[1].models.slice(0, -1), native.slice(0, -1));
  assert.equal(partial.model_selector_config[1].models.at(-1).id, GOOGLE_MODEL);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  r.reply(Buffer.from(JSON.stringify(json)));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), GOOGLE_MODEL);
  assertStatePrivacy(r);
});

test("an exact-bound native preference list accepts and replays one extra without losing native rows", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  r.change(cfg => ({ ...cfg, providers: { ...cfg.providers, google: { ...cfg.providers.google!, models: [{ id: GOOGLE_MODEL, effortLevels: ["high"] }] } } }));
  const rows = Array.from({ length: DESKTOP_PICKER_ROW_LIMIT }, (_, i) => ({ id: `claude-native-${i}`, thinking: { type: "effort", effort: "high" } }));
  const json = { ...fixture(), model_selector_state: [{ ...nativeState(), thinking_by_model: rows }] };
  r.reply(Buffer.from(JSON.stringify(json))); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400);
  const chosen = await stateWrite(r, JSON.stringify({ model: GOOGLE_MODEL, thinking: { type: "effort", effort: "high" } }));
  assert.equal(chosen.status, 200);
  const selectedRows = JSON.parse(chosen.body.toString("utf8")).thinking_by_model;
  assert.equal(selectedRows.length, DESKTOP_PICKER_ROW_LIMIT + 1);
  assert.deepEqual(selectedRows.slice(0, rows.length), rows);
  r.reply(Buffer.from(JSON.stringify(json)));
  const replay = JSON.parse((await r.send(STATE_BOOTSTRAP)).body.toString("utf8"));
  assert.equal(replay.model_selector_state[0].model, GOOGLE_MODEL);
  assert.deepEqual(replay.model_selector_state[0].thinking_by_model, selectedRows);
  assertStatePrivacy(r);
});

for (const [name, change] of [
  ["absent selector", (j: Record<string, unknown>) => { delete j.model_selector_state; }],
  ["object selector", (j: Record<string, unknown>) => { j.model_selector_state = { code: nativeState() }; }],
  ["duplicate state", (j: Record<string, unknown>) => { j.model_selector_state = [nativeState(), nativeState()]; }],
  ["duplicate menu", (j: Record<string, unknown>) => { (j.model_selector_config as unknown[]).push(fixture().model_selector_config[1]); }],
  ["oversized optional selector metadata", (j: Record<string, unknown>) => { (j.model_selector_state as Record<string, unknown>[])[0]!.optional_metadata = "测".repeat(22_000); }],
  ["conflicting active effort", (j: Record<string, unknown>) => { j.model_selector_state = [{ ...nativeState(), thinking: { type: "effort", effort: "high" },
    thinking_by_model: [{ id: "claude-opus-5-5", thinking: { type: "effort", effort: "low" } }] }]; }],
] as const) {
  test(`bootstrap ${name} never offers an unusable extra and preserves its native representation`, { timeout: 15_000 }, async t => {
    const r = await rig(t); const json: Record<string, unknown> = fixture(); change(json);
    const raw = zlib.brotliCompressSync(Buffer.from(JSON.stringify(json, null, 2)));
    r.reply(raw, { "content-encoding": "br" });
    assertNative(await r.send(STATE_BOOTSTRAP), raw, "br");
    assert.equal(r.proxy.lastPickerInjection?.injected, 0);
    assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "unsupported-selection");
    assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 0);
    assertStatePrivacy(r);
  });
}

test("an unrecognized bootstrap target remains native without erasing an unrelated supported selection", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify(fixture(), null, 2)));
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(STATE_BOOTSTRAP.replace("/app_start?", "/app_start_v2?")), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "unsupported-selection");
  assert.equal(r.proxy.lastPickerInjection?.injected, 0);
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), GOOGLE_MODEL);
  assertStatePrivacy(r);
});

test("an unsupported selector in another authenticated scope leaves the original account's choice intact", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify({ ...fixture(), model_selector_state: { updated_layout: true } }, null, 2)));
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await r.send(STATE_BOOTSTRAP.replace(STATE_ORG, "other-synthetic-org"), undefined,
    { headers: { cookie: "fixture=other-synthetic-account" } }), raw, "gzip");
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "unsupported-selection");
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), GOOGLE_MODEL);
  assertStatePrivacy(r);
});

test("an unscoped bootstrap with a familiar menu remains byte-preserving", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const raw = Buffer.from(JSON.stringify(fixture(), null, 4));
  r.reply(raw);
  assertNative(await r.send(`/api/bootstrap?private=${QUERY_SECRET}`), raw);
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "unsupported-selection");
  assert.equal(r.proxy.lastPickerInjection?.observation.compatibleCodeSurfaces, 0);
  assertStatePrivacy(r);
});

test("oversized optional metadata on a native selection reply stays exact and drops its old extra template", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  const raw = zlib.brotliCompressSync(Buffer.from(JSON.stringify({ ...nativeState(), optional_metadata: "测".repeat(22_000) }, null, 2)));
  r.reply(raw, { "content-encoding": "br" });
  assertNative(await stateWrite(r, JSON.stringify(nativeState())), raw, "br");
  r.reply(STATE_REFUSAL, {}, 400);
  assertNative(await stateWrite(r), STATE_REFUSAL, undefined, 400);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  assertStatePrivacy(r);
});

test("deep optional metadata in a small native state reply stays byte-exact without failing the router", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  const plain = Buffer.from(`{"id":"code","model":"claude-opus-5-5","optional_metadata":${"[".repeat(20_000)}0${"]".repeat(20_000)}}`);
  assert.ok(plain.length < 64 * 1024);
  const raw = zlib.gzipSync(plain);
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await stateWrite(r, JSON.stringify({ model: "claude-opus-5-5" })), raw, "gzip");
  r.reply(STATE_REFUSAL, {}, 400);
  assertNative(await stateWrite(r), STATE_REFUSAL, undefined, 400);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal((await r.send(STATE_BOOTSTRAP)).status, 200);
  assert.equal(r.proxy.lastPickerInjection?.injected, 1);
  assert.equal(r.proxy.stats.inFlight, 0);
  assertStatePrivacy(r);
});

test("native and unsupported Desktop state requests keep their exact failure representation", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  const raw = zlib.brotliCompressSync(STATE_REFUSAL);
  r.reply(raw, { "content-encoding": "br" }, 400);
  for (const body of ['{ "model" : "claude-opus-5-5" }', '{"model":"unknown-model"}', JSON.stringify({ model: GOOGLE_MODEL, fast_mode: "off" })]) {
    assertNative(await stateWrite(r, body), raw, "br", 400);
    assert.equal(r.captured.at(-1)!.body.toString("utf8"), body);
  }
  assertStatePrivacy(r);
});

test("effort-only native success passes through unchanged and clears a remembered Google choice", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  const native = { ...nativeState(), thinking: { type: "effort", effort: "low" } };
  const raw = zlib.gzipSync(Buffer.from(JSON.stringify(native, null, 2)));
  const request = '{ "thinking": { "type": "effort", "effort": "low" } }';
  r.reply(raw, { "content-encoding": "gzip" });
  assertNative(await stateWrite(r, request), raw, "gzip");
  assert.equal(r.captured.at(-1)!.body.toString("utf8"), request);
  r.reply(Buffer.from(JSON.stringify({ ...fixture(), model_selector_state: [native] })));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  assertStatePrivacy(r);
});

test("pending Google refusal cannot survive a config revoke/reapprove cycle before upstream finishes", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  const started = Promise.withResolvers<http.ServerResponse>();
  r.setHandler((_req, res) => { started.resolve(res); });
  const pending = stateWrite(r);
  const upstream = await started.promise;
  r.change(cfg => ({ ...cfg, security: { ...cfg.security!, approvedOrigins: ["https://api.anthropic.com", "https://claude.ai"] } }));
  r.change(cfg => ({ ...cfg, security: { ...cfg.security!, approvedOrigins: [...cfg.security!.approvedOrigins, "https://generativelanguage.googleapis.com"] } }));
  upstream.writeHead(400, { ...nativeHeaders, "content-length": STATE_REFUSAL.length }).end(STATE_REFUSAL);
  assertNative(await pending, STATE_REFUSAL, undefined, 400);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  r.reply(STATE_REFUSAL, {}, 400);
  assert.equal((await stateWrite(r)).status, 200, "a fresh selection works only after fresh bootstrap with the reapproved config");
  assertStatePrivacy(r);
});

test("late Google 400 cannot resurrect a selection after a newer native PATCH succeeds", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  const started = Promise.withResolvers<http.ServerResponse>();
  r.setHandler((_req, res, body) => {
    if (JSON.parse(body.toString("utf8")).model === GOOGLE_MODEL) started.resolve(res);
    else res.writeHead(200, nativeHeaders).end(JSON.stringify(nativeState("claude-sonnet-5-5")));
  });
  const pending = stateWrite(r);
  const held = await started.promise;
  assert.equal((await stateWrite(r, JSON.stringify({ model: "claude-sonnet-5-5" }))).status, 200);
  held.writeHead(400, { ...nativeHeaders, "content-length": STATE_REFUSAL.length }).end(STATE_REFUSAL);
  assertNative(await pending, STATE_REFUSAL, undefined, 400);
  const j = fixture(); j.model_selector_state = [nativeState("claude-sonnet-5-5")];
  r.reply(Buffer.from(JSON.stringify(j)));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-sonnet-5-5");
  assertStatePrivacy(r);
});

test("late code extra cannot overwrite a newer ccd native choice in the linked Desktop picker", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const j = fixture();
  j.model_selector_config.push({ id: "ccd", models: [{ id: "claude-opus-5-5", name: "Native Opus", context_window: 200_000 }] });
  j.model_selector_state.push({ id: "ccd", model: "claude-opus-5-5" });
  r.reply(Buffer.from(JSON.stringify(j))); await r.send(STATE_BOOTSTRAP);
  const started = Promise.withResolvers<http.ServerResponse>();
  r.setHandler((req, res) => {
    if (req.url?.includes("/code?")) started.resolve(res);
    else res.writeHead(200, nativeHeaders).end(JSON.stringify({ id: "ccd", model: "claude-opus-5-5" }));
  });
  const pending = stateWrite(r); const held = await started.promise;
  assert.equal((await stateWrite(r, JSON.stringify({ model: "claude-opus-5-5" }), STATE_PATH.replace("/code?", "/ccd?"))).status, 200);
  held.writeHead(400, { ...nativeHeaders, "content-length": STATE_REFUSAL.length }).end(STATE_REFUSAL);
  assertNative(await pending, STATE_REFUSAL, undefined, 400);
  r.reply(Buffer.from(JSON.stringify(j)));
  assert.deepEqual(JSON.parse((await r.send(STATE_BOOTSTRAP)).body.toString("utf8")).model_selector_state, j.model_selector_state);
  assertStatePrivacy(r);
});

test("pre-header native bootstrap failure clears stale selector success and remembered extra", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), GOOGLE_MODEL);
  r.setHandler((_req, res) => res.destroy(new Error(PRIVATE)));
  assert.equal((await r.send(STATE_BOOTSTRAP)).status, 502);
  assert.equal(r.proxy.lastPickerInjection?.observation.outcome, "upstream-error");
  assert.equal(r.proxy.lastPickerInjection?.injected, 0);
  assert.deepEqual(r.proxy.lastPickerInjection?.surfaces, []);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  assertStatePrivacy(r);
});

test("integrity-protected selector refusal is never rewritten", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  const raw = zlib.gzipSync(STATE_REFUSAL);
  r.reply(raw, { "content-encoding": "gzip", "content-digest": "sha-256=:synthetic-native-integrity:" }, 400);
  const reply = await stateWrite(r);
  assertNative(reply, raw, "gzip", 400);
  assert.equal(reply.headers["content-digest"], "sha-256=:synthetic-native-integrity:");
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  assertStatePrivacy(r);
});

test("oversized native state success streams unchanged and removes stale local choice", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  r.reply(STATE_REFUSAL, {}, 400); assert.equal((await stateWrite(r)).status, 200);
  const raw = Buffer.alloc(BOOTSTRAP_BUFFER_LIMIT + 1, 0x64);
  r.reply(raw, {}, 200);
  assertNative(await stateWrite(r, JSON.stringify({ model: "claude-opus-5-5" })), raw);
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  assert.equal(r.proxy.stats.inFlight, 0);
  assertStatePrivacy(r);
});

test("cancelled incomplete Google refusal never installs a remembered selection", { timeout: 15_000 }, async t => {
  const r = await rig(t); await r.send(STATE_BOOTSTRAP);
  const started = Promise.withResolvers<http.ServerResponse>();
  const clientClosed = Promise.withResolvers<void>();
  const proxyHttp = (r.proxy as unknown as { httpServer: http.Server }).httpServer;
  const onClientRequest = (req: http.IncomingMessage, res: http.ServerResponse): void => {
    if (req.method === "PATCH" && req.url === STATE_PATH) res.once("close", () => clientClosed.resolve());
  };
  proxyHttp.on("request", onClientRequest);
  t.after(() => proxyHttp.off("request", onClientRequest));
  r.setHandler((_req, res) => {
    res.writeHead(400, { ...nativeHeaders, "content-length": STATE_REFUSAL.length });
    res.write(STATE_REFUSAL.subarray(0, 8));
    started.resolve(res);
  });
  const controller = new AbortController();
  const pending = stateWrite(r, extraWrite, STATE_PATH, { signal: controller.signal });
  const rejected = assert.rejects(pending);
  const held = await started.promise;
  controller.abort(); await rejected;
  // AbortSignal rejects locally before its socket close reaches the proxy. Wait for the actual
  // remote close, then release upstream, so this tests cancellation rather than network ordering.
  await clientClosed.promise;
  held.end(STATE_REFUSAL.subarray(8));
  r.reply(Buffer.from(JSON.stringify(fixture())));
  assert.equal(selectedModel(await r.send(STATE_BOOTSTRAP)), "claude-opus-5-5");
  assertStatePrivacy(r);
});
