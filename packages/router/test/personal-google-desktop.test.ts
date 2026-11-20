// Personal Desktop's additional Google model and unchanged native subscription path through
// actual CONNECT/TLS. All credentials, replies and research text are synthetic. No Google or
// Anthropic account, public endpoint, Windows trust store or live Desktop installation is used.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { once } from "node:events";
import type { Duplex } from "node:stream";
import { Agent, getGlobalDispatcher, setGlobalDispatcher } from "undici";
import { CertStore } from "../src/certs.ts";
import { normalizeConfig, validate, type Config } from "../src/config.ts";
import { UpstreamHealth } from "../src/health.ts";
import { Logger } from "../src/log.ts";
import { configurePersonalEgressPolicy } from "../src/personal-policy.ts";
import { chatPickerModels } from "../src/picker.ts";
import { Proxy } from "../src/proxy.ts";
import { RequestLog } from "../src/requestlog.ts";
import { ObservedClaudeCodeAuth } from "../src/providers/anthropic-observed.ts";
import { createCa, createLeaf } from "../src/x509.ts";
import { workerLadderLine } from "../../mod/hooks/ladder.ts";

const NATIVE_MODEL = "claude-native-fixture";
const GOOGLE_MODEL = "gemini-4-carbon";
const ALTERNATE_MODEL = "gemini-synthetic-alternate";
const UNKNOWN_MODEL = "gemini-synthetic-undeclared";
const MAIN_AUTH = "Bearer sk-ant-oat01-SYNTHETIC-DESKTOP-ONLY";
const MAIN_COOKIE = "sessionKey=SYNTHETIC-DESKTOP-COOKIE";
const MAIN_KEY = "SYNTHETIC-DESKTOP-CLIENT-KEY";
const GOOGLE_KEY = "SYNTHETIC-GOOGLE-AI-STUDIO-KEY";
const ALTERNATE_KEY = "SYNTHETIC-ALTERNATE-PROVIDER-KEY";
const RESEARCH = "SYNTHETIC-PRIVATE-RESEARCH-GOOGLE-DESKTOP-9cf1";
const GOOGLE_ANSWER = "Synthetic Google response.";
const NATIVE_ANSWER = "Synthetic native subscription response.";
type Hit = { url: string; raw: string; headers: http.IncomingHttpHeaders };
type Reply = { status: number; headers: http.IncomingHttpHeaders; body: string };

const payload = (model: string, stream = false) => ({ model, max_tokens: 128, stream, messages: [{ role: "user", content: RESEARCH }] });

async function rig(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-google-desktop-"));
  const ca = createCa({ cn: "Synthetic personal Google Desktop CA" });
  const nativeLeaf = createLeaf({ host: "api.anthropic.com", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
  const googleLeaf = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
  const native: Hit[] = [], google: Hit[] = [];
  const sockets = new Set<Duplex>();
  const servers: https.Server[] = [];
  const connections = { native: 0, google: 0 };
  const accountCalls = { observed: 0, profile: 0, keychain: 0, credentialsFile: 0, loginKey: 0 };
  const observedAuth = new ObservedClaudeCodeAuth();
  const observe = observedAuth.observe.bind(observedAuth);
  t.mock.method(observedAuth, "observe", (headers: readonly string[], at?: number) => {
    accountCalls.observed++;
    observe(headers, at);
  });
  let googleMode: "ok" | "hold" | "redirect" | "retired" = "ok";
  let nativeFailure: number | "reset" | undefined;
  let googleParts: Record<string, unknown>[] = [{ text: GOOGLE_ANSWER }];
  let closedGoogleStreams = 0;
  let redirectTarget = "";
  let proxy: Proxy | undefined;
  let nativeAgent: https.Agent | undefined;
  let dispatcher: Agent | undefined;
  let priorDispatcher: ReturnType<typeof getGlobalDispatcher> | undefined;
  const log = new Logger(path.join(home, "logs", "router.log"), 4096, 1, true, true);
  const requests = new RequestLog(path.join(home, "logs", "requests.jsonl"), 30, 4096, true);
  t.after(async () => {
    configurePersonalEgressPolicy(undefined);
    if (priorDispatcher) setGlobalDispatcher(priorDispatcher);
    proxy?.close();
    nativeAgent?.destroy();
    await dispatcher?.destroy();
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    log.close();
    fs.rmSync(home, { recursive: true, force: true });
  });
  const server = (kind: "native" | "google", leaf: ReturnType<typeof createLeaf>) => {
    const instance = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("error", () => res.destroy());
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        (kind === "native" ? native : google).push({ url: req.url ?? "", raw, headers: { ...req.headers } });
        if (kind === "native") {
          if (nativeFailure === "reset") { res.destroy(); return; }
          if (nativeFailure !== undefined) {
            res.writeHead(nativeFailure, { "content-type": "application/json" }).end(JSON.stringify({
              type: "error", error: { type: "api_error", message: `Synthetic native ${nativeFailure} refusal.` },
            }));
            return;
          }
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({
            id: "msg_native_fixture", type: "message", role: "assistant", model: NATIVE_MODEL,
            content: [{ type: "text", text: NATIVE_ANSWER }], stop_reason: "end_turn", stop_sequence: null,
            usage: { input_tokens: 8, output_tokens: 5 },
          }));
          return;
        }
        if (googleMode === "redirect") { res.writeHead(307, { location: redirectTarget }).end(); return; }
        if (googleMode === "retired" && req.url?.startsWith(`/v1beta/models/${GOOGLE_MODEL}:`)) {
          res.writeHead(404, { "content-type": "application/json" }).end(JSON.stringify({
            error: { code: 404, status: "NOT_FOUND", message: `Model ${GOOGLE_MODEL} has been deprecated (synthetic fixture).` },
          }));
          return;
        }
        const answer = { candidates: [{ content: { role: "model", parts: googleParts }, finishReason: "STOP" }],
          usageMetadata: { promptTokenCount: 8, candidatesTokenCount: 5 } };
        if (!req.url?.includes(":streamGenerateContent")) {
          res.writeHead(200, { "content-type": "application/json", "set-cookie": "must-not-reach-Claude=synthetic" }).end(JSON.stringify(answer));
          return;
        }
        res.writeHead(200, { "content-type": "text/event-stream", "set-cookie": "must-not-reach-Claude=synthetic" });
        if (googleMode === "hold") {
          res.on("close", () => { closedGoogleStreams++; });
          res.write(`data: ${JSON.stringify({ candidates: [{ content: { parts: [{ text: "Synthetic partial response" }] } }] })}\n\n`);
        } else res.end(`data: ${JSON.stringify(answer)}\n\n`);
      });
    });
    instance.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
    instance.on("secureConnection", () => { connections[kind]++; });
    servers.push(instance);
    return instance;
  };
  const nativeServer = server("native", nativeLeaf), googleServer = server("google", googleLeaf);
  await Promise.all(servers.map(async instance => { instance.listen(0, "127.0.0.1"); await once(instance, "listening"); }));
  const nativePort = (nativeServer.address() as net.AddressInfo).port;
  const googleOrigin = `https://127.0.0.1:${(googleServer.address() as net.AddressInfo).port}`;
  // An already approved second origin is still forbidden as a redirect target.
  redirectTarget = `${googleOrigin}/never-follow-provider-redirect`;
  let cfg: Config = normalizeConfig({
    upstream: "api.anthropic.com", listen: { host: "127.0.0.1", port: 0 }, autoUpdate: false,
    security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com", "https://claude.ai", `https://api.anthropic.com:${nativePort}`, googleOrigin] },
    picker: { enabled: true },
    providers: { google: { type: "google", auth: "api-key", url: googleOrigin, apiKey: GOOGLE_KEY, models: [{ id: GOOGLE_MODEL, contextWindow: 1_000_000 }] } },
    routes: {}, direct: [], aliases: {},
    cli: { extraModels: [{ model: GOOGLE_MODEL, name: "Gemini 4 Carbon" }] },
  });
  configurePersonalEgressPolicy(() => cfg.security);
  nativeAgent = new https.Agent({ ca: ca.certPem, rejectUnauthorized: true,
    lookup: (host, _options, callback) => {
      assert.equal(host, "api.anthropic.com");
      callback(null, [{ address: "127.0.0.1", family: 4 }]);
    },
  });
  dispatcher = new Agent({ connect: { ca: ca.certPem, rejectUnauthorized: true } });
  priorDispatcher = getGlobalDispatcher();
  setGlobalDispatcher(dispatcher);
  const certs = new CertStore(home);
  certs.register("api.anthropic.com", Buffer.from(nativeLeaf.certPem), Buffer.from(nativeLeaf.keyPem));
  proxy = new Proxy({ config: () => cfg, home, certs, log, requests,
    health: new UpstreamHealth(() => 100, () => {}), agentDir: path.join(home, "fixture-agents"),
    upstreamPort: nativePort, upstreamAgent: nativeAgent,
    observedClaudeCodeAuth: observedAuth,
    claudeCodeCredentialReaders: { keychain: () => { accountCalls.keychain++; return null; }, credentialsFile: () => { accountCalls.credentialsFile++; return null; } },
    claudeLoginKey: () => { accountCalls.loginKey++; return undefined; },
    claudeProfileFetch: async () => { accountCalls.profile++; return new Response("{}", { status: 404 }); },
  });
  await proxy.listen();
  const proxyPort = ((proxy as unknown as { server: net.Server }).server.address() as net.AddressInfo).port;
  cfg = { ...cfg, listen: { host: "127.0.0.1", port: proxyPort } };
  assert.deepEqual(validate(cfg), []);

  async function send(body: Record<string, unknown>, cancelAfterFirstChunk = false, extraHeaders: Record<string, string> = {}): Promise<Reply> {
    const socket = net.connect(proxyPort, "127.0.0.1");
    let secure: tls.TLSSocket | undefined;
    let clientAgent: https.Agent | undefined;
    const deadline = setTimeout(() => { socket.destroy(new Error("personal Google fixture deadline")); secure?.destroy(); }, 10_000);
    try {
      await once(socket, "connect");
      const connected = new Promise<string>((resolve, reject) => {
        let head = "";
        const data = (chunk: Buffer) => {
          head += chunk.toString("latin1");
          if (head.length > 8192) reject(new Error("oversized CONNECT reply"));
          else if (head.includes("\r\n\r\n")) { socket.off("data", data); resolve(head); }
        };
        socket.on("data", data);
        socket.once("error", reject);
      });
      socket.write("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n");
      assert.match(await connected, /^HTTP\/1\.1 200 /);
      secure = tls.connect({ socket, servername: "api.anthropic.com", ca: ca.certPem, rejectUnauthorized: true });
      await once(secure, "secureConnect");
      assert.equal(secure.authorized, true);
      clientAgent = new https.Agent({ keepAlive: false });
      const verifiedSocket = secure;
      clientAgent.createConnection = () => verifiedSocket;
      const raw = JSON.stringify(body);
      return await new Promise<Reply>((resolve, reject) => {
        const request = https.request({ host: "api.anthropic.com", port: 443, method: "POST", path: "/v1/messages", agent: clientAgent,
          headers: { host: "api.anthropic.com", authorization: MAIN_AUTH, cookie: MAIN_COOKIE, "x-api-key": MAIN_KEY,
            "x-client-secret": MAIN_KEY, "proxy-authorization": "Basic SYNTHETIC-LOCAL-PROXY",
            "content-type": "application/json", "content-length": String(Buffer.byteLength(raw)),
            "anthropic-version": "2023-06-01", connection: "close", ...extraHeaders },
        }, response => {
          const chunks: Buffer[] = [];
          const result = () => ({ status: response.statusCode!, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") });
          response.on("data", (chunk: Buffer) => {
            chunks.push(chunk);
            if (cancelAfterFirstChunk) { resolve(result()); response.destroy(); request.destroy(); }
          });
          response.once("error", reject);
          response.once("end", () => resolve(result()));
        });
        request.once("error", reject);
        request.end(raw);
      });
    } finally {
      clearTimeout(deadline);
      clientAgent?.destroy();
      secure?.destroy();
      socket.destroy();
    }
  }
  return { home, native, google, connections, send, log, proxy, requests, accountCalls, observedAuth,
    reconcile: () => proxy!.reconcileConfig(cfg),
    picker: () => chatPickerModels(cfg), closedGoogleStreams: () => closedGoogleStreams,
    mode: (value: typeof googleMode) => { googleMode = value; },
    failNative: (value: typeof nativeFailure) => { nativeFailure = value; },
    parts: (value: Record<string, unknown>[]) => { googleParts = value; },
    // Deliberately bypass activation validation to simulate legacy settings reappearing while
    // Desktop is running. Every extra provider below still points at this synthetic TLS origin.
    change: (update: (current: Config) => Config) => { cfg = update(cfg); },
    approveGoogle: (allowed: boolean) => {
      const other = cfg.security!.approvedOrigins.filter(origin => origin !== googleOrigin);
      cfg = { ...cfg, security: { mode: "personal", approvedOrigins: allowed ? [...other, googleOrigin] : other } };
    },
  };
}

test("personal Google Desktop: native credentials are forwarded without observation, identity lookup or local login access", async t => {
  const r = await rig(t);
  assert.equal((await r.send(payload(NATIVE_MODEL))).status, 200);
  assert.equal((await r.send(payload(GOOGLE_MODEL))).status, 200);
  await r.proxy.rows.settled();
  assert.equal(await r.proxy.claudeIdentity.identify(), null, "even an identity callback cannot read the native login in personal mode");
  assert.equal(await r.proxy.claudeIdentity.identifyWith({ authorization: MAIN_AUTH }), null);
  r.change(cfg => ({ ...cfg, providers: { ...cfg.providers, legacy: { type: "anthropic", auth: "claude-code", accountPool: true } } }));
  assert.deepEqual(r.proxy.credentialHealth(), {}, "legacy account-pool status cannot discover native credentials");
  assert.deepEqual(r.accountCalls, { observed: 0, profile: 0, keychain: 0, credentialsFile: 0, loginKey: 0 });
  assert.equal(r.observedAuth.getFresh(), null, "no reusable native OAuth snapshot is retained");
  assert.equal(r.native[0]!.headers.authorization, MAIN_AUTH);
  assert.equal(r.native[0]!.headers.cookie, MAIN_COOKIE);
  assert.equal(r.native[0]!.headers["x-api-key"], MAIN_KEY);
  assert.equal(r.google[0]!.headers["x-goog-api-key"], GOOGLE_KEY);
  assert.equal(r.google[0]!.headers.authorization, undefined);
});

test("personal Google Desktop: entering personal mode discards generic observation and identity cache without changing native forwarding", async t => {
  const r = await rig(t);
  let security: Config["security"];
  r.change(current => { security = current.security; const { security: _old, ...next } = current; return next; });
  // This library-level generic-mode positive control keeps the fixture's exact origin policy.
  // A production personal entry point would reject a missing policy rather than disable it.
  configurePersonalEgressPolicy(() => security);
  assert.equal((await r.send(payload(NATIVE_MODEL))).status, 200);
  await r.proxy.rows.settled();
  assert.equal(r.accountCalls.observed, 1, "generic positive control retains account-pool observation");
  assert.equal(r.accountCalls.profile, 1, "generic positive control performs its ordinary identity lookup");
  assert.equal(r.observedAuth.getFresh()?.authorization, MAIN_AUTH);
  r.change(current => ({ ...current, security: security! }));
  r.reconcile();
  assert.equal(r.observedAuth.getFresh(), null);
  assert.equal((await r.send(payload(NATIVE_MODEL))).status, 200);
  await r.proxy.rows.settled();
  assert.equal(r.accountCalls.observed, 1);
  assert.equal(r.accountCalls.profile, 1);
  assert.equal(r.accountCalls.keychain + r.accountCalls.credentialsFile + r.accountCalls.loginKey, 0);
  assert.equal(r.native.length, 2);
  for (const hit of r.native) assert.equal(hit.headers.authorization, MAIN_AUTH);
  r.change(current => { const { security: _old, ...next } = current; return next; });
  assert.equal((await r.send(payload(NATIVE_MODEL))).status, 200);
  await r.proxy.rows.settled();
  assert.equal(r.accountCalls.profile, 2, "returning to generic mode cannot reuse the discarded identity cache");
});

for (const stream of [false, true]) {
  test(`personal Google Desktop: ${stream ? "streamed" : "JSON"} Google reply uses only its own key`, async t => {
    const r = await rig(t);
    assert.equal(r.picker()[0]?.model, GOOGLE_MODEL);
    const reply = await r.send(payload(GOOGLE_MODEL, stream));
    assert.equal(reply.status, 200, reply.body);
    assert.match(reply.body, new RegExp(GOOGLE_ANSWER));
    assert.match(reply.body, /"stop_reason":"end_turn"/);
    assert.equal(reply.headers["set-cookie"], undefined);
    assert.equal(r.google.length, 1);
    const hit = r.google[0]!;
    assert.equal(hit.url, `/v1beta/models/${GOOGLE_MODEL}:${stream ? "streamGenerateContent?alt=sse" : "generateContent"}`);
    assert.equal(hit.headers["x-goog-api-key"], GOOGLE_KEY);
    for (const name of ["authorization", "cookie", "x-api-key", "proxy-authorization", "x-client-secret"]) assert.equal(hit.headers[name], undefined, name);
    for (const secret of [MAIN_AUTH, MAIN_COOKIE, MAIN_KEY]) assert.ok(!JSON.stringify(hit).includes(secret));
    assert.match(hit.raw, new RegExp(RESEARCH));
    assert.equal(r.native.length, 0, "no prompt is also spent on the native subscription");
    if (stream) assert.match(reply.body, /event: message_stop/);
    await r.proxy.rows.settled();
    assert.equal(fs.existsSync(path.join(r.home, "logs", "router.log")), false);
    assert.equal(fs.existsSync(path.join(r.home, "logs", "requests.jsonl")), false);
  });
}

test("personal Google Desktop: selecting native Claude preserves its request and subscription credentials", async t => {
  const r = await rig(t);
  assert.equal((await r.send(payload(GOOGLE_MODEL))).status, 200);
  const body = payload(NATIVE_MODEL);
  const reply = await r.send(body);
  assert.equal(reply.status, 200, reply.body);
  assert.match(reply.body, new RegExp(NATIVE_ANSWER));
  assert.equal(r.native.length, 1);
  const hit = r.native[0]!;
  assert.equal(hit.raw, JSON.stringify(body));
  assert.equal(hit.headers.authorization, MAIN_AUTH);
  assert.equal(hit.headers.cookie, MAIN_COOKIE);
  assert.equal(hit.headers["x-api-key"], MAIN_KEY);
  assert.equal(hit.headers["proxy-authorization"], undefined);
  assert.equal(hit.headers["x-goog-api-key"], undefined);
  assert.ok(!JSON.stringify(hit).includes(GOOGLE_KEY));
  assert.equal(r.google.length, 1, "the native turn is not routed through Google");
});

test("personal Google Desktop: concurrent native turns and native auxiliaries keep their own transport counts and credentials", async t => {
  const r = await rig(t);
  const googleSession = "synthetic-google-main-session";
  const nativeSession = "synthetic-native-main-session";
  const concurrentAuth = "Bearer sk-ant-oat01-SYNTHETIC-CONCURRENT-NATIVE";
  const concurrentCookie = "sessionKey=SYNTHETIC-CONCURRENT-NATIVE";
  const nativeCases: { label: string; model: string; headers: Record<string, string> }[] = [
    { label: "independent native main", model: "claude-new-native-fixture", headers: {
      "x-claude-code-session-id": nativeSession, "x-claude-code-request-class": "main",
      authorization: concurrentAuth, cookie: concurrentCookie,
    } },
    { label: "native title beside a Google main", model: "claude-haiku-native-fixture", headers: {
      "x-claude-code-session-id": googleSession, "x-claude-code-request-class": "auxiliary",
    } },
    { label: "native suggestion beside a Google main", model: "claude-haiku-native-fixture", headers: {
      "x-claude-code-session-id": googleSession, "x-claude-code-request-class": "auxiliary",
    } },
    { label: "native compaction beside a Google main", model: NATIVE_MODEL, headers: {
      "x-claude-code-session-id": googleSession, "x-claude-code-request-class": "compaction",
    } },
    { label: "native subagent beside a Google main", model: "claude-sonnet-native-fixture", headers: {
      "x-claude-code-session-id": googleSession, "x-claude-code-request-class": "subagent",
      "x-claude-code-agent-id": "synthetic-native-worker",
    } },
    { label: "unscoped native auxiliary", model: "claude-haiku-native-fixture", headers: {
      "x-claude-code-request-class": "auxiliary",
    } },
  ];
  const nativeBodies = nativeCases.map(entry => ({ ...payload(entry.model), messages: [{ role: "user", content: `${RESEARCH}: ${entry.label}` }] }));
  const replies = await Promise.all([
    r.send(payload(GOOGLE_MODEL), false, { "x-claude-code-session-id": googleSession, "x-claude-code-request-class": "main" }),
    ...nativeCases.map((entry, index) => r.send(nativeBodies[index]!, false, entry.headers)),
  ]);
  for (const reply of replies) assert.equal(reply.status, 200, reply.body);
  assert.equal(r.google.length, 1, "only the explicitly selected Google request reaches Google");
  assert.equal(r.native.length, nativeCases.length, "each client-issued native request reaches Anthropic once; the add-on creates no extra inference");
  for (const [index, entry] of nativeCases.entries()) {
    const raw = JSON.stringify(nativeBodies[index]);
    const matches = r.native.filter(hit => hit.raw === raw);
    assert.equal(matches.length, 1, entry.label);
    const hit = matches[0]!;
    assert.equal(hit.url, "/v1/messages");
    assert.equal(hit.headers.authorization, entry.headers.authorization ?? MAIN_AUTH);
    assert.equal(hit.headers.cookie, entry.headers.cookie ?? MAIN_COOKIE);
    assert.equal(hit.headers["x-api-key"], MAIN_KEY);
    for (const [name, value] of Object.entries(entry.headers)) assert.equal(hit.headers[name], value, `${entry.label}: ${name}`);
    assert.equal(hit.headers["x-goog-api-key"], undefined);
    assert.ok(!JSON.stringify(hit).includes(GOOGLE_KEY));
  }
  for (const secret of [MAIN_AUTH, MAIN_COOKIE, MAIN_KEY, concurrentAuth, concurrentCookie]) {
    assert.ok(!JSON.stringify(r.google).includes(secret), "native account credentials never enter the Google request");
  }
  // These are client-request transport counts. The fixture neither invokes Desktop to generate
  // auxiliaries nor makes claims about how Anthropic's billing ledger charges those requests.
});

test("personal Google Desktop: a Google success and failure make no native calls, then the exact native model is restored", async t => {
  const r = await rig(t);
  const headers = { "x-claude-code-session-id": "synthetic-switch-back-session", "x-claude-code-request-class": "main" };
  assert.equal((await r.send(payload(GOOGLE_MODEL), false, headers)).status, 200);
  assert.equal(r.native.length, 0);
  assert.equal(r.google.length, 1);
  r.mode("retired");
  const failed = await r.send(payload(GOOGLE_MODEL), false, headers);
  assert.equal(failed.status, 400, failed.body);
  assert.equal(r.google.length, 2);
  assert.equal(r.native.length, 0, "the Google error creates no fallback Anthropic inference");
  assert.equal(r.connections.native, 0, "even an Anthropic upstream connection is unnecessary for these explicit Google requests");
  const restored = payload("claude-opus-new-native-fixture");
  assert.equal((await r.send(restored, false, headers)).status, 200);
  assert.equal(r.google.length, 2);
  assert.equal(r.native.length, 1);
  assert.equal(r.native[0]!.raw, JSON.stringify(restored), "switching back preserves the exact client-chosen native model");
  assert.equal(r.native[0]!.headers.authorization, MAIN_AUTH);
  assert.equal(r.native[0]!.headers.cookie, MAIN_COOKIE);
});

for (const failure of [401, 429, 503, "reset"] as const) {
  test(`personal Google Desktop: a native ${failure} failure does not create an automatic inference retry`, async t => {
    const r = await rig(t);
    r.failNative(failure);
    const body = payload(NATIVE_MODEL);
    const reply = await r.send(body);
    assert.equal(reply.status, failure === "reset" ? 502 : failure, reply.body);
    assert.equal(r.native.length, 1, "the client's single Messages POST is forwarded exactly once");
    assert.equal(r.native[0]!.raw, JSON.stringify(body));
    assert.equal(r.native[0]!.headers.authorization, MAIN_AUTH);
    assert.equal(r.google.length, 0, "native failures do not switch providers");
    assert.equal(r.connections.google, 0);
  });
}

test("personal Google Desktop: one mixed conversation can carry tools across Google and native switches", async t => {
  const r = await rig(t);
  const googleThought = "Synthetic Google thought summary";
  const googleSignature = "SYNTHETIC-GOOGLE-TOOL-THOUGHT-SIGNATURE";
  const nativeSignature = "U1lOVEhFVElDLU5BVElWRS1TSUdOQVRVUkU=";
  r.parts([
    { thought: true, text: googleThought },
    { text: GOOGLE_ANSWER },
    { functionCall: { name: "read_fixture", args: { name: "synthetic.txt" } }, thoughtSignature: googleSignature },
  ]);
  const initial = { ...payload(GOOGLE_MODEL), tools: [{ name: "read_fixture", input_schema: { type: "object", properties: { name: { type: "string" } } } }] };
  const first = await r.send(initial);
  assert.equal(first.status, 200, first.body);
  const googleReply = JSON.parse(first.body) as { content: Record<string, unknown>[]; stop_reason: string };
  assert.equal(googleReply.stop_reason, "tool_use");
  assert.ok(googleReply.content.some(block => block.type === "thinking"));
  const tool = googleReply.content.find(block => block.type === "tool_use")!;
  assert.equal(tool.name, "read_fixture");
  assert.ok(!first.body.includes(googleSignature), "Google opaque signatures stay internal to its adapter");

  const nativeThinking = { type: "thinking", thinking: "Synthetic original Claude summary", signature: nativeSignature };
  const nativeTurn = { ...initial, model: NATIVE_MODEL, messages: [
    { role: "user", content: RESEARCH },
    { role: "assistant", content: [nativeThinking, { type: "text", text: "Synthetic original Claude answer" }] },
    { role: "user", content: "Now use the Google fixture" },
    { role: "assistant", content: googleReply.content },
    { role: "user", content: [{ type: "tool_result", tool_use_id: tool.id, content: "Synthetic file text" }] },
  ] };
  const nativeResult = await r.send(nativeTurn);
  assert.equal(nativeResult.status, 200, nativeResult.body);
  const nativeWire = JSON.parse(r.native[0]!.raw);
  assert.deepEqual(nativeWire.messages[1].content[0], nativeThinking, "the native signature and summary are unchanged");
  assert.deepEqual(nativeWire.messages[3].content, googleReply.content.filter(block => block.type !== "thinking"));
  assert.deepEqual(nativeWire.messages[4], nativeTurn.messages[4], "tool results survive the switch");
  assert.ok(!r.native[0]!.raw.includes(googleThought));
  assert.ok(!r.native[0]!.raw.includes(googleSignature));
  assert.equal(r.native[0]!.headers.authorization, MAIN_AUTH);
  assert.equal(r.native[0]!.headers["x-goog-api-key"], undefined);

  // Return to Google with the same history. Only Google's own functionCall signature returns;
  // native Claude's opaque reasoning and account credentials are not sent to Google.
  r.parts([{ text: GOOGLE_ANSWER }]);
  const back = await r.send({ ...nativeTurn, model: GOOGLE_MODEL });
  assert.equal(back.status, 200, back.body);
  const googleWire = JSON.parse(r.google[1]!.raw);
  const parts = googleWire.contents.flatMap((message: { parts: Record<string, unknown>[] }) => message.parts);
  assert.equal(parts.find((part: Record<string, unknown>) => part.functionCall)?.thoughtSignature, googleSignature);
  assert.ok(parts.some((part: Record<string, unknown>) => part.functionResponse));
  assert.ok(!r.google[1]!.raw.includes(nativeSignature));
  assert.equal(r.google[1]!.headers["x-goog-api-key"], GOOGLE_KEY);
  assert.equal(r.google[1]!.headers.authorization, undefined);
  assert.equal(r.native.length, 1);
});

test("personal Google Desktop: revoking Google hides its extra, blocks egress, and leaves native Claude usable", async t => {
  const r = await rig(t);
  assert.equal((await r.send(payload(GOOGLE_MODEL))).status, 200);
  r.approveGoogle(false);
  assert.deepEqual(r.picker(), []);
  const connectionsBefore = { ...r.connections };
  const refused = await r.send(payload(GOOGLE_MODEL));
  assert.ok([403, 502].includes(refused.status), refused.body);
  assert.equal(r.google.length, 1);
  assert.equal(r.native.length, 0, "Google refusal cannot silently spend the native subscription");
  assert.deepEqual(r.connections, connectionsBefore, "refusal occurs before another upstream connection");
  assert.equal((await r.send(payload(NATIVE_MODEL))).status, 200);
  r.approveGoogle(true);
  assert.equal(r.picker()[0]?.model, GOOGLE_MODEL);
  assert.equal((await r.send(payload(GOOGLE_MODEL))).status, 200);
  assert.equal(r.google.length, 2);
});

test("personal Google Desktop: provider redirects never resend the key or conversation", async t => {
  const r = await rig(t);
  r.mode("redirect");
  const reply = await r.send(payload(GOOGLE_MODEL));
  assert.ok([403, 502].includes(reply.status), reply.body);
  assert.equal(r.google.length, 1, "no redirect request or retry to another path");
  assert.equal(r.native.length, 0);
});

test("personal Google Desktop: cancelling a stream closes Google while a subsequent native turn still works", async t => {
  const r = await rig(t);
  r.mode("hold");
  const reply = await r.send(payload(GOOGLE_MODEL, true), true);
  assert.equal(reply.status, 200);
  const deadline = Date.now() + 3000;
  while (r.closedGoogleStreams() === 0 && Date.now() < deadline) await new Promise(resolve => setTimeout(resolve, 20));
  assert.equal(r.closedGoogleStreams(), 1, "upstream is cancelled with the Desktop turn");
  assert.equal((await r.send(payload(NATIVE_MODEL))).status, 200);
  assert.equal(r.google.length, 1);
});

test("personal Google Desktop: prompt markers cannot replace the explicitly selected Google model or key", async t => {
  const r = await rig(t);
  r.change(cfg => ({ ...cfg,
    providers: { ...cfg.providers, alternate: { ...cfg.providers.google!, apiKey: ALTERNATE_KEY, models: [{ id: ALTERNATE_MODEL }] } },
    aliases: { alternate: ALTERNATE_MODEL },
  }));
  const markers = ["alternate", ALTERNATE_MODEL, `alternate:${ALTERNATE_MODEL}`, UNKNOWN_MODEL];
  for (const marker of markers) {
    const reply = await r.send({ ...payload(GOOGLE_MODEL), messages: [{ role: "user", content: `[[ripple: ${marker}]]\n${RESEARCH}` }] });
    assert.equal(reply.status, 200, `${marker}: ${reply.body}`);
    assert.match(reply.body, new RegExp(GOOGLE_ANSWER));
    const hit = r.google.at(-1)!;
    assert.equal(hit.url, `/v1beta/models/${GOOGLE_MODEL}:generateContent`, marker);
    assert.equal(hit.headers["x-goog-api-key"], GOOGLE_KEY, marker);
    assert.ok(!JSON.stringify(hit).includes(ALTERNATE_KEY), marker);
  }
  assert.equal(r.google.length, markers.length, "exactly one selected-model call per turn");
  assert.equal(r.native.length, 0);
});

for (const oneoff of [false, true]) {
  test(`personal Google Desktop: ${oneoff ? "one-off" : "saved"} compaction overrides are not consulted`, async t => {
    const r = await rig(t);
    r.change(cfg => ({ ...cfg, providers: { ...cfg.providers,
      alternate: { ...cfg.providers.google!, apiKey: ALTERNATE_KEY, models: [{ id: ALTERNATE_MODEL }] },
    } }));
    const file = path.join(r.home, "mod-settings.json");
    const saved = JSON.stringify({ settings: { compactModel: ALTERNATE_MODEL }, revision: 1, stored: true });
    fs.writeFileSync(file, saved);
    const session = `desktop-google-compact-${oneoff ? "oneoff" : "saved"}`;
    if (oneoff) r.proxy.compactPicks.set(session, ALTERNATE_MODEL);
    const read = fs.readFileSync;
    let settingsReads = 0;
    t.mock.method(fs, "readFileSync", (...args: Parameters<typeof fs.readFileSync>) => {
      if (args[0] === file) settingsReads++;
      return read(...args);
    });
    const take = t.mock.method(r.proxy.compactPicks, "take");
    const reply = await r.send({ ...payload(GOOGLE_MODEL), messages: [{ role: "user", content: `${RESEARCH}\nSummarize the synthetic conversation.` }] }, false, {
      "x-claude-code-session-id": session, "x-claude-code-request-class": "compaction",
    });
    assert.equal(reply.status, 200, reply.body);
    assert.equal(take.mock.callCount(), 0, "the legacy selection resolver is not called");
    assert.equal(settingsReads, 0, "saved mod settings are not read for this compaction");
    assert.equal(r.google.length, 1);
    assert.equal(r.google[0]!.url, `/v1beta/models/${GOOGLE_MODEL}:generateContent`);
    assert.equal(r.google[0]!.headers["x-goog-api-key"], GOOGLE_KEY);
    assert.equal(r.native.length, 0);
    await r.proxy.rows.settled();
    assert.equal(r.requests.list(1)[0]?.purpose, "compaction", "the fixture actually exercises the compaction path");
    take.mock.restore();
    assert.equal(r.proxy.compactPicks.take(session, false, () => undefined), undefined, "ignored queued picks cannot leak into a later turn");
    assert.equal(read(file, "utf8"), saved, "legacy settings are preserved, not deleted");
  });
}

test("personal Google Desktop: subagent turns bypass legacy worker ladders and their saved settings", async t => {
  const r = await rig(t);
  r.change(cfg => ({ ...cfg, providers: { ...cfg.providers,
    google: { ...cfg.providers.google!, models: [{ id: GOOGLE_MODEL }, { id: ALTERNATE_MODEL }] },
  }, aliases: { selected: GOOGLE_MODEL, alternate: ALTERNATE_MODEL } }));
  const file = path.join(r.home, "mod-settings.json");
  fs.writeFileSync(file, JSON.stringify({ revision: 1, settings: { rules: { general: { mode: "ladder", rungs: {
    standard: [{ target: { agent: "selected" }, effort: "high" }, { target: { agent: "alternate" }, effort: "high" }],
  } } } } }));
  const read = fs.readFileSync;
  let settingsReads = 0;
  t.mock.method(fs, "readFileSync", (...args: Parameters<typeof fs.readFileSync>) => {
    if (args[0] === file) settingsReads++;
    return read(...args);
  });
  const internals = r.proxy as unknown as { workerFallbacks(...args: unknown[]): unknown };
  const worker = t.mock.method(internals, "workerFallbacks");
  const ladder = workerLadderLine({ pick: "synthetic-worker-pick", model: GOOGLE_MODEL, fallbacks: [`${ALTERNATE_MODEL}@high`] });
  const reply = await r.send({ ...payload(GOOGLE_MODEL), messages: [{ role: "user", content: `${ladder}\n${RESEARCH}` }] }, false, {
    "x-claude-code-session-id": "synthetic-worker-session", "x-claude-code-agent-id": "synthetic-worker", "x-claude-code-request-class": "subagent",
  });
  assert.equal(reply.status, 200, reply.body);
  assert.equal(worker.mock.callCount(), 0, "the legacy worker ladder hook is not called");
  assert.equal(settingsReads, 0);
  assert.equal(r.google.length, 1);
  assert.equal(r.google[0]!.url, `/v1beta/models/${GOOGLE_MODEL}:generateContent`);
  assert.equal(r.google[0]!.headers["x-goog-api-key"], GOOGLE_KEY);
  assert.equal(r.native.length, 0);
  await r.proxy.rows.settled();
  assert.equal(r.requests.list(1)[0]?.subagent, true, "the fixture actually exercises a subagent turn");
});

for (const otherProvider of [false, true]) {
  for (const known of [false, true]) {
    test(`personal Google Desktop: ${known ? "a known" : "an undeclared"} ${otherProvider ? "cross-provider" : "same-provider"} fallback cannot replace a retired selection`, async t => {
      const r = await rig(t);
      r.change(cfg => ({ ...cfg,
        providers: { ...cfg.providers,
          google: { ...cfg.providers.google!, models: [{ id: GOOGLE_MODEL }, ...(!otherProvider ? [{ id: ALTERNATE_MODEL }] : [])] },
          ...(otherProvider ? { alternate: { ...cfg.providers.google!, apiKey: ALTERNATE_KEY, models: [{ id: ALTERNATE_MODEL }] } } : {}),
        },
        routes: { [GOOGLE_MODEL]: { provider: "google", model: GOOGLE_MODEL,
          fallbacks: [{ provider: otherProvider ? "alternate" : "google", model: known ? ALTERNATE_MODEL : UNKNOWN_MODEL }],
        } },
      }));
      // Only the selected primary returns a retirement. Any accidental fallback would succeed,
      // exposing both the silently changed model and, for a second provider, its different key.
      r.mode("retired");
      const first = await r.send(payload(GOOGLE_MODEL));
      assert.equal(first.status, 400, first.body); // Google's 404 maps to Anthropic invalid_request_error.
      assert.equal(r.google.length, 1);
      assert.equal(r.google[0]!.url, `/v1beta/models/${GOOGLE_MODEL}:generateContent`);
      assert.equal(r.google[0]!.headers["x-goog-api-key"], GOOGLE_KEY);
      assert.equal(r.proxy.modelHealth.get("google", GOOGLE_MODEL)?.reason, "model_deprecated");
      const next = await r.send(payload(GOOGLE_MODEL));
      assert.equal(next.status, 400, next.body);
      assert.equal(r.google.length, 2, "each explicit retry stays on the selected primary");
      for (const hit of r.google) {
        assert.equal(hit.url, `/v1beta/models/${GOOGLE_MODEL}:generateContent`);
        assert.equal(hit.headers["x-goog-api-key"], GOOGLE_KEY);
        assert.ok(!JSON.stringify(hit).includes(ALTERNATE_KEY));
      }
      assert.equal(r.native.length, 0, "no retry spends the native subscription");
      assert.equal(r.connections.native, 0);
      assert.ok(!next.body.includes(GOOGLE_ANSWER));
    });
  }
}

test("personal Google Desktop: an unknown selection cannot be rescued by a prompt marker or native passthrough", async t => {
  const r = await rig(t);
  r.change(cfg => ({ ...cfg, aliases: { alternate: GOOGLE_MODEL } }));
  for (const model of [UNKNOWN_MODEL, `google:${UNKNOWN_MODEL}`, `missing:${UNKNOWN_MODEL}`]) {
    const reply = await r.send({ ...payload(model), messages: [{ role: "user", content: `[[ripple: alternate]]\n${RESEARCH}` }] });
    assert.equal(reply.status, 400, `${model}: ${reply.body}`);
    assert.equal(r.google.length, 0);
    assert.equal(r.native.length, 0);
  }
  assert.deepEqual(r.connections, { native: 0, google: 0 });
});
