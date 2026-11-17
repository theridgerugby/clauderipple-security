// Exercise normal personal use through the actual CONNECT/TLS boundary. Every key, prompt,
// certificate and upstream below is synthetic; no account, external host or trust store is used.
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
import { Proxy } from "../src/proxy.ts";
import { RequestLog } from "../src/requestlog.ts";
import { createCa, createLeaf } from "../src/x509.ts";

const MAIN_BEARER = "Bearer sk-ant-oat01-SYNTHETIC-MAIN-ACCOUNT-ONLY";
const MAIN_KEY = "SYNTHETIC-CLIENT-PLACEHOLDER-KEY";
const MAIN_COOKIE = "sessionKey=SYNTHETIC-MAIN-ACCOUNT-COOKIE";
const PROXY_AUTH = "Basic SYNTHETIC-LOCAL-PROXY-CREDENTIAL";
const SCHOOL_KEY = "SYNTHETIC-SCHOOL-API-KEY";
const RESEARCH = "SYNTHETIC-UNPUBLISHED-RESEARCH-SENTINEL-7a42";
const SCHOOL_MODEL = "claude-school-fixture";
const NATIVE_MODEL = "claude-native-fixture";
const SCHOOL_ANSWER = "Synthetic school answer is complete.";
const NATIVE_ANSWER = "Synthetic native answer is complete.";

type Hit = { method: string | undefined; url: string | undefined; raw: string; headers: http.IncomingHttpHeaders };
type Reply = { status: number; headers: http.IncomingHttpHeaders; body: string };
type Mode = "ok" | "echo-error" | number;

function payload(model: string, stream = false) {
  return { model, max_tokens: 128, stream, messages: [{ role: "user", content: RESEARCH }] };
}

function event(name: string, data: unknown): string {
  return `event: ${name}\ndata: ${JSON.stringify(data)}\n\n`;
}

function nativeReply(res: http.ServerResponse, body: Record<string, unknown>): void {
  const message = { id: "msg_personal_fixture", type: "message", role: "assistant", model: body.model,
    content: [{ type: "text", text: NATIVE_ANSWER }], stop_reason: "end_turn", stop_sequence: null,
    usage: { input_tokens: 11, output_tokens: 6 } };
  if (!body.stream) { res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(message)); return; }
  res.writeHead(200, { "content-type": "text/event-stream" });
  res.write(event("message_start", { type: "message_start", message: { ...message, content: [], stop_reason: null, usage: { input_tokens: 11, output_tokens: 0 } } }));
  res.write(event("content_block_start", { type: "content_block_start", index: 0, content_block: { type: "text", text: "" } }));
  setImmediate(() => res.end(
    event("content_block_delta", { type: "content_block_delta", index: 0, delta: { type: "text_delta", text: NATIVE_ANSWER } }) +
    event("content_block_stop", { type: "content_block_stop", index: 0 }) +
    event("message_delta", { type: "message_delta", delta: { stop_reason: "end_turn", stop_sequence: null }, usage: { output_tokens: 6 } }) +
    event("message_stop", { type: "message_stop" }),
  ));
}

function schoolReply(res: http.ServerResponse): void {
  // The production adapter requests OpenAI SSE even when its caller wants one complete JSON reply.
  res.writeHead(200, { "content-type": "text/event-stream" });
  res.write(`data: ${JSON.stringify({ id: "chatcmpl_personal_fixture", choices: [{ index: 0, delta: { role: "assistant", content: SCHOOL_ANSWER }, finish_reason: null }] })}\n\n`);
  setImmediate(() => res.end(`data: ${JSON.stringify({ choices: [{ index: 0, delta: {}, finish_reason: "stop" }], usage: { prompt_tokens: 13, completion_tokens: 7, total_tokens: 20 } })}\n\ndata: [DONE]\n\n`));
}

async function rig(t: TestContext, options: { schoolWire?: "chat" | "anthropic"; schoolHeaders?: Record<string, string>; schoolReplyHeaders?: Record<string, string> } = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-smoke-"));
  const ca = createCa({ cn: "Synthetic personal smoke CA" });
  const nativeLeaf = createLeaf({ host: "api.anthropic.com", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
  const loopbackLeaf = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
  const native: Hit[] = [], school: Hit[] = [], sink: Hit[] = [];
  const connections = { native: 0, school: 0, sink: 0 };
  let schoolMode: Mode = "ok";
  let sinkOrigin = "";
  const servers: https.Server[] = [];
  const sockets = new Set<Duplex>();
  let proxy: Proxy | undefined;
  let nativeAgent: https.Agent | undefined;
  let dispatcher: Agent | undefined;
  let previousDispatcher: ReturnType<typeof getGlobalDispatcher> | undefined;
  const log = new Logger(path.join(home, "logs", "router.log"), 4096, 1, true, true);
  const requests = new RequestLog(path.join(home, "logs", "requests.jsonl"), 30, 4096, true);
  t.after(async () => {
    configurePersonalEgressPolicy(undefined);
    if (previousDispatcher) setGlobalDispatcher(previousDispatcher);
    proxy?.close();
    nativeAgent?.destroy();
    await dispatcher?.destroy();
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
    log.close();
    fs.rmSync(home, { recursive: true, force: true });
  });
  const makeServer = (kind: keyof typeof connections, seen: Hit[], leaf: ReturnType<typeof createLeaf>, reply: (res: http.ServerResponse, body: Record<string, unknown>) => void) => {
    const server = https.createServer({ key: leaf.keyPem, cert: leaf.certPem }, (req, res) => {
      const chunks: Buffer[] = [];
      req.on("data", (chunk: Buffer) => chunks.push(chunk));
      req.on("error", () => res.destroy());
      req.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        seen.push({ method: req.method, url: req.url, raw, headers: { ...req.headers } });
        try { reply(res, raw ? JSON.parse(raw) as Record<string, unknown> : {}); }
        catch { res.writeHead(400).end("fixture body error"); }
      });
    });
    server.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
    server.on("secureConnection", () => { connections[kind]++; });
    servers.push(server);
    return server;
  };
  const nativeServer = makeServer("native", native, nativeLeaf, nativeReply);
  const schoolServer = makeServer("school", school, loopbackLeaf, (res, body) => {
    for (const [name, value] of Object.entries(options.schoolReplyHeaders ?? {})) res.setHeader(name, value);
    if (typeof schoolMode === "number") { res.writeHead(schoolMode, { location: `${sinkOrigin}/never-send-research` }).end(); return; }
    if (schoolMode === "echo-error") { res.writeHead(400, { "content-type": "application/json" }).end(JSON.stringify({ error: { message: `Synthetic refusal reflecting ${RESEARCH} and ${SCHOOL_KEY}` } })); return; }
    if (options.schoolWire === "anthropic") nativeReply(res, body);
    else schoolReply(res);
  });
  const sinkServer = makeServer("sink", sink, loopbackLeaf, res => res.writeHead(200).end("unexpected redirect destination"));
  await Promise.all(servers.map(async server => { server.listen(0, "127.0.0.1"); await once(server, "listening"); }));
  const nativePort = (nativeServer.address() as net.AddressInfo).port;
  const schoolOrigin = `https://127.0.0.1:${(schoolServer.address() as net.AddressInfo).port}`;
  sinkOrigin = `https://127.0.0.1:${(sinkServer.address() as net.AddressInfo).port}`;
  let cfg: Config = normalizeConfig({
    upstream: "api.anthropic.com", listen: { host: "127.0.0.1", port: 0 }, autoUpdate: false,
    security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com", `https://api.anthropic.com:${nativePort}`, schoolOrigin, sinkOrigin] },
    providers: {
      school: options.schoolWire === "anthropic"
        ? { type: "anthropic-compatible", url: schoolOrigin, headers: { authorization: `Bearer ${SCHOOL_KEY}`, ...options.schoolHeaders }, models: [{ id: "school-fixture-model" }] }
        : { type: "openai-compatible", wire: "chat", url: `${schoolOrigin}/v1`, headers: { authorization: `Bearer ${SCHOOL_KEY}`, ...options.schoolHeaders }, models: [{ id: "school-fixture-model" }] },
      fallbackNative: { type: "anthropic", auth: "api-key", apiKey: "SYNTHETIC-UNUSED-FALLBACK-KEY", models: [{ id: "claude-fixture-fallback" }] },
    },
    routes: { [SCHOOL_MODEL]: { provider: "school", model: "school-fixture-model", fallbacks: [{ provider: "fallbackNative", model: "claude-fixture-fallback" }] } },
    aliases: {}, direct: [],
  });
  configurePersonalEgressPolicy(() => cfg.security);
  // Trust is explicit and remains verified at every real TLS hop. The lookup seam resolves only
  // the native fixture; all school/redirect fixture destinations are literal loopback addresses.
  nativeAgent = new https.Agent({ ca: ca.certPem, rejectUnauthorized: true,
    lookup: (host, _options, callback) => {
      assert.equal(host, "api.anthropic.com");
      callback(null, [{ address: "127.0.0.1", family: 4 }]);
    },
  });
  dispatcher = new Agent({ connect: { ca: ca.certPem, rejectUnauthorized: true } });
  previousDispatcher = getGlobalDispatcher();
  setGlobalDispatcher(dispatcher);
  const certs = new CertStore(home);
  certs.register("api.anthropic.com", Buffer.from(nativeLeaf.certPem), Buffer.from(nativeLeaf.keyPem));
  proxy = new Proxy({ config: () => cfg, home, certs, log, requests,
    health: new UpstreamHealth(() => 100, () => {}), agentDir: path.join(home, "fixture-agents"),
    upstreamPort: nativePort, upstreamAgent: nativeAgent,
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    claudeLoginKey: () => undefined,
    // Only account-display metadata uses a seam; inference itself always reaches real TLS servers.
    claudeProfileFetch: async () => new Response("{}", { status: 404 }),
  });
  // The compatible wire uses node:https rather than undici. Trust only this synthetic CA.
  if (options.schoolWire === "anthropic") (proxy as unknown as { providerAgents: Map<string, https.Agent> }).providerAgents
    .set("school|https:", new https.Agent({ ca: ca.certPem, rejectUnauthorized: true }));
  await proxy.listen();
  const proxyPort = ((proxy as unknown as { server: net.Server }).server.address() as net.AddressInfo).port;
  // Ephemeral allocation is the only reason the initial test-only listen value was zero.
  cfg = { ...cfg, listen: { host: "127.0.0.1", port: proxyPort } };
  assert.deepEqual(validate(cfg), []);

  async function send(body: Record<string, unknown>, options: { host?: string; method?: string; ca?: string; headers?: Record<string, string> } = {}): Promise<Reply> {
    const socket = net.connect(proxyPort, "127.0.0.1");
    let secure: tls.TLSSocket | undefined;
    let clientAgent: https.Agent | undefined;
    const deadline = setTimeout(() => { socket.destroy(new Error("personal smoke request deadline")); secure?.destroy(); }, 10_000);
    try {
      await once(socket, "connect");
      const connected = new Promise<string>((resolve, reject) => {
        let head = "";
        const data = (chunk: Buffer) => {
          head += chunk.toString("latin1");
          if (head.length > 8192) reject(new Error("oversized fixture CONNECT reply"));
          else if (head.includes("\r\n\r\n")) { socket.off("data", data); resolve(head); }
        };
        socket.on("data", data);
        socket.once("error", reject);
      });
      socket.write("CONNECT api.anthropic.com:443 HTTP/1.1\r\nHost: api.anthropic.com:443\r\n\r\n");
      assert.match(await connected, /^HTTP\/1\.1 200 /);
      secure = tls.connect({ socket, servername: "api.anthropic.com", ca: options.ca ?? ca.certPem, rejectUnauthorized: true });
      await once(secure, "secureConnect");
      assert.equal(secure.authorized, true);
      clientAgent = new https.Agent({ keepAlive: false });
      const verifiedSocket = secure;
      clientAgent.createConnection = () => verifiedSocket;
      const method = options.method ?? "POST";
      const raw = method === "GET" ? "" : JSON.stringify(body);
      return await new Promise<Reply>((resolve, reject) => {
        const request = https.request({ host: "api.anthropic.com", port: 443, method,
          path: method === "GET" ? `/v1/messages?research=${RESEARCH}` : "/v1/messages", agent: clientAgent,
          headers: { host: options.host ?? "api.anthropic.com", authorization: MAIN_BEARER, "x-api-key": MAIN_KEY,
            cookie: MAIN_COOKIE, "proxy-authorization": PROXY_AUTH,
            "x-custom-research-key": MAIN_KEY, "content-type": "application/json", "anthropic-version": "2023-06-01",
            "x-claude-code-session-id": "personal-fixture-session", "content-length": String(Buffer.byteLength(raw)), connection: "close", ...options.headers },
        }, response => {
          const chunks: Buffer[] = [];
          response.on("data", (chunk: Buffer) => chunks.push(chunk));
          response.once("error", reject);
          response.once("end", () => resolve({ status: response.statusCode!, headers: response.headers, body: Buffer.concat(chunks).toString("utf8") }));
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
  return { home, native, school, sink, connections, schoolOrigin, proxy, log, requests, send,
    mode: (mode: Mode) => { schoolMode = mode; },
    schoolApproved: (enabled: boolean) => {
      const origins = cfg.security!.approvedOrigins.filter(origin => origin !== schoolOrigin);
      cfg = { ...cfg, security: { mode: "personal", approvedOrigins: enabled ? [...origins, schoolOrigin] : origins } };
      assert.deepEqual(validate(cfg), []);
    },
  };
}

test("personal smoke: school API completes a real TLS-routed response without receiving the main account", async t => {
  const r = await rig(t);
  const reply = await r.send(payload(SCHOOL_MODEL));
  assert.equal(reply.status, 200, reply.body);
  const message = JSON.parse(reply.body) as { type: string; content: { text: string }[]; stop_reason: string };
  assert.equal(message.type, "message");
  assert.equal(message.content.map(block => block.text).join(""), SCHOOL_ANSWER);
  assert.equal(message.stop_reason, "end_turn");
  assert.equal(r.school.length, 1);
  assert.equal(r.school[0]!.url, "/v1/chat/completions");
  assert.match(r.school[0]!.raw, new RegExp(RESEARCH));
  assert.equal(r.school[0]!.headers.authorization, `Bearer ${SCHOOL_KEY}`);
  assert.equal(r.school[0]!.headers["x-api-key"], undefined);
  assert.ok(!JSON.stringify(r.school[0]).includes(MAIN_BEARER));
  assert.ok(!JSON.stringify(r.school[0]).includes(MAIN_KEY));
  assert.equal(r.native.length, 0);
  assert.equal(r.sink.length, 0);
});

test("personal smoke: native main-account JSON and SSE requests both finish through verified TLS", async t => {
  const r = await rig(t);
  const full = await r.send(payload(NATIVE_MODEL));
  assert.equal(full.status, 200, full.body);
  assert.equal((JSON.parse(full.body) as { content: { text: string }[] }).content[0]!.text, NATIVE_ANSWER);
  const streamed = await r.send(payload(NATIVE_MODEL, true));
  assert.equal(streamed.status, 200, streamed.body);
  assert.match(String(streamed.headers["content-type"]), /text\/event-stream/);
  for (const item of ["event: message_start", "event: content_block_delta", NATIVE_ANSWER, "event: message_stop"]) assert.ok(streamed.body.includes(item), item);
  assert.equal(r.native.length, 2);
  for (const [index, hit] of r.native.entries()) {
    assert.equal(hit.raw, JSON.stringify(payload(NATIVE_MODEL, index === 1)));
    assert.equal(hit.headers.authorization, MAIN_BEARER);
    assert.equal(hit.headers["x-api-key"], MAIN_KEY);
    assert.equal(hit.headers.cookie, MAIN_COOKIE);
    assert.equal(hit.headers["x-custom-research-key"], MAIN_KEY);
    assert.equal(hit.headers["proxy-authorization"], undefined, "proxy credentials never authenticate an origin");
    assert.ok(!JSON.stringify(hit).includes(SCHOOL_KEY));
  }
  assert.equal(r.school.length, 0);
  assert.equal(r.sink.length, 0);
  await r.proxy.rows.settled();
  assert.equal(r.proxy.stats.inFlight, 0);
});

test("personal smoke: an Anthropic-compatible origin receives only its own credentials and explicitly configured custom headers", async t => {
  const r = await rig(t, { schoolWire: "anthropic", schoolHeaders: { "x-school-session": "SYNTHETIC-SCHOOL-SESSION" } });
  const reply = await r.send(payload(SCHOOL_MODEL), { headers: { "x-client-secret": MAIN_KEY } });
  assert.equal(reply.status, 200, reply.body);
  assert.equal(r.school.length, 1);
  const hit = r.school[0]!;
  assert.equal(hit.headers.authorization, `Bearer ${SCHOOL_KEY}`);
  assert.equal(hit.headers["x-school-session"], "SYNTHETIC-SCHOOL-SESSION");
  assert.equal(hit.headers["anthropic-version"], "2023-06-01");
  assert.match(hit.raw, new RegExp(RESEARCH));
  for (const name of ["x-api-key", "cookie", "proxy-authorization", "x-client-secret", "x-custom-research-key", "x-claude-code-session-id"]) assert.equal(hit.headers[name], undefined, name);
  for (const value of [MAIN_BEARER, MAIN_KEY, MAIN_COOKIE, PROXY_AUTH]) assert.ok(!JSON.stringify(hit).includes(value), "no main-account credential travels to school");
  assert.equal(r.native.length, 0);
});

test("personal smoke: a compatible provider cannot set Claude-origin cookies or smuggle response hop-by-hop headers", async t => {
  const r = await rig(t, { schoolWire: "anthropic", schoolReplyHeaders: {
    "set-cookie": "sessionKey=SYNTHETIC-PROVIDER-COOKIE; HttpOnly; Secure",
    "clear-site-data": '"cookies"',
    "www-authenticate": "Basic realm=SYNTHETIC-PROVIDER",
    "connection": "close, X-Untrusted-State",
    "x-untrusted-state": "SYNTHETIC-PROVIDER-METADATA",
  } });
  const reply = await r.send(payload(SCHOOL_MODEL));
  assert.equal(reply.status, 200, reply.body);
  for (const name of ["set-cookie", "clear-site-data", "www-authenticate", "x-untrusted-state"]) {
    assert.equal(reply.headers[name], undefined, `${name} must not be sent as an Anthropic-origin response`);
  }
  assert.match(reply.body, new RegExp(NATIVE_ANSWER));
  assert.equal(r.school.length, 1);
});

test("personal smoke: native forwarding removes Connection-nominated headers while preserving native login", async t => {
  const r = await rig(t);
  const reply = await r.send(payload(NATIVE_MODEL), { headers: { connection: "close, X-Local-Only", "x-local-only": "SYNTHETIC-LOCAL-SECRET" } });
  assert.equal(reply.status, 200, reply.body);
  assert.equal(r.native.length, 1);
  assert.equal(r.native[0]!.headers["x-local-only"], undefined);
  assert.equal(r.native[0]!.headers.authorization, MAIN_BEARER);
  assert.equal(r.native[0]!.headers.cookie, MAIN_COOKIE);
});

test("personal smoke: revocation blocks the next school request without fallback, and explicit reapproval restores it", async t => {
  const r = await rig(t);
  assert.equal((await r.send(payload(SCHOOL_MODEL))).status, 200);
  const before = { ...r.connections };
  r.schoolApproved(false);
  const refused = await r.send(payload(SCHOOL_MODEL));
  assert.ok([403, 502].includes(refused.status), refused.body);
  assert.equal(r.school.length, 1);
  assert.equal(r.native.length, 0, "even an explicitly configured fallback cannot take the prompt");
  assert.equal(r.sink.length, 0);
  assert.deepEqual(r.connections, before, "refusal precedes any new upstream TLS connection");
  r.schoolApproved(true);
  assert.equal((await r.send(payload(SCHOOL_MODEL))).status, 200);
  assert.equal(r.school.length, 2);
  assert.equal(r.native.length, 0);
});

test("personal smoke: school redirects cannot resend a prompt even to another approved TLS origin", async t => {
  const r = await rig(t);
  for (const status of [302, 307, 308]) {
    r.mode(status);
    const before = r.school.length;
    const reply = await r.send(payload(SCHOOL_MODEL));
    assert.ok([403, 502].includes(reply.status), reply.body);
    assert.equal(r.school.length, before + 1, "one initial request, no same-account retry");
    assert.equal(r.native.length, 0, "no configured native-provider fallback");
    assert.equal(r.sink.length, 0, "redirect target receives no prompt or key");
    assert.equal(r.connections.sink, 0, "the redirect target receives no TLS connection");
  }
  r.mode("ok");
  assert.equal((await r.send(payload(SCHOOL_MODEL))).status, 200, "refusal must not poison ordinary later inference");
});

test("personal smoke: mismatched inner Host never opens a second connection, including bodyless custom-key requests", async t => {
  const r = await rig(t);
  for (const host of [new URL(r.schoolOrigin).host, "unapproved-fixture.invalid"]) {
    for (const method of ["GET", "POST"]) {
      const reply = await r.send(payload(SCHOOL_MODEL), { host, method });
      assert.ok([403, 421].includes(reply.status), reply.body);
      assert.deepEqual(r.connections, { native: 0, school: 0, sink: 0 });
      assert.equal(r.native.length + r.school.length + r.sink.length, 0);
    }
  }
});

test("personal smoke: reflected research diagnostics remain in memory and leave no disk dump", async t => {
  const r = await rig(t);
  r.mode("echo-error");
  const reply = await r.send(payload(SCHOOL_MODEL));
  assert.equal(reply.status, 400, reply.body);
  assert.match(r.log.memoryTail(30) ?? "", new RegExp(RESEARCH));
  assert.ok(!(r.log.memoryTail(30) ?? "").includes(SCHOOL_KEY));
  await r.proxy.rows.settled();
  assert.ok(r.requests.list(30).length > 0);
  for (const relative of ["logs/router.log", "logs/requests.jsonl", "logs/usage-hourly.jsonl", "requests.jsonl"]) assert.equal(fs.existsSync(path.join(r.home, relative)), false, relative);
  const visit = (directory: string): void => {
    for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
      const file = path.join(directory, entry.name);
      if (entry.isDirectory()) visit(file);
      else if (entry.isFile()) {
        const text = fs.readFileSync(file).toString("utf8");
        for (const secret of [RESEARCH, MAIN_BEARER, MAIN_KEY, SCHOOL_KEY]) assert.ok(!text.includes(secret), `${entry.name} contains fixture data`);
      } else assert.fail("unexpected nonregular entry in isolated fixture home");
    }
  };
  visit(r.home);
  assert.equal(r.native.length, 0);
});

test("personal smoke: an untrusted CA fails the TLS handshake before any research request", async t => {
  const r = await rig(t);
  const untrusted = createCa({ cn: "Untrusted synthetic CA" });
  await assert.rejects(r.send(payload(SCHOOL_MODEL), { ca: untrusted.certPem }), /certificate|issuer|verify/i);
  assert.equal(r.school.length + r.native.length + r.sink.length, 0);
  assert.deepEqual(r.connections, { native: 0, school: 0, sink: 0 });
});
