// Synthetic transport tests only. No real Desktop, account, key, OS trust store or internet.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import tls from "node:tls";
import { EventEmitter, once } from "node:events";
import type { Duplex } from "node:stream";
import { CertStore } from "../src/certs.ts";
import { normalizeConfig, type Config } from "../src/config.ts";
import { UpstreamHealth } from "../src/health.ts";
import { Logger } from "../src/log.ts";
import { Proxy } from "../src/proxy.ts";
import { RequestLog } from "../src/requestlog.ts";
import { requestKind } from "../src/routing.ts";
import { createCa, createLeaf } from "../src/x509.ts";

const ASSET = "assets.example.test";
const ORIGINS = ["https://api.anthropic.com", "https://claude.ai", `https://${ASSET}`];
const KEY = "dGhlIHNhbXBsZSBub25jZQ==";
type Internals = {
  onConnect(socket: net.Socket): void;
  terminate(socket: net.Socket, host: string): void;
  tunnel(socket: net.Socket, host: string, port: number): void;
  desktopStreams: Map<Duplex, unknown>;
  providerAgents: Map<string, https.Agent>;
  server: net.Server;
};

function base(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-desktop-transport-"));
  let cfg = normalizeConfig({
    security: { mode: "personal", approvedOrigins: [...ORIGINS] },
    listen: { host: "127.0.0.1", port: 0 }, picker: { enabled: true },
    providers: {}, aliases: {}, routes: {}, direct: [], cli: { extraModels: [] }, autoUpdate: false,
  });
  const log = new Logger(null, 4096, 1, true, true);
  const certs = new CertStore(home);
  const proxy = new Proxy({ config: () => cfg, home, log, certs,
    requests: new RequestLog(path.join(home, "requests.jsonl"), 10, 4096, true),
    health: new UpstreamHealth(() => 100, () => {}), agentDir: path.join(home, "agents"),
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    claudeLoginKey: () => undefined, claudeProfileFetch: async () => new Response("{}", { status: 404 }),
  });
  const internals = proxy as unknown as Internals;
  t.after(() => { proxy.close(); log.close(); fs.rmSync(home, { recursive: true, force: true }); });
  return { home, proxy, internals, certs, config: () => cfg,
    change: (update: (old: Config) => Config, reconcile = true) => { cfg = update(cfg); if (reconcile) proxy.reconcileConfig(cfg); },
  };
}

for (const [target, wanted, dispatch] of [
  ["claude.ai:443", 200, "terminate"], ["api.anthropic.com:443", 200, "terminate"],
  [`${ASSET}:443`, 200, "tunnel"], ["unknown.example.test:443", 403, "none"],
  [`${ASSET}:444`, 403, "none"], [`${ASSET}:0443`, 403, "none"],
  [`${ASSET}:0x1bb`, 403, "none"], [`${ASSET}.:443`, 403, "none"],
  [`${ASSET.toUpperCase()}:443`, 403, "none"], [`${ASSET}@claude.ai:443`, 403, "none"],
  ["claude%2eai:443", 403, "none"], ["claude.ai/path:443", 403, "none"],
] as const) {
  test(`Desktop CONNECT ${target}: ${wanted}, ${dispatch}`, t => {
    const r = base(t);
    const socket = new net.Socket();
    t.after(() => socket.destroy());
    const responses: string[] = [];
    t.mock.method(socket, "write", (data: string) => { responses.push(data); return true; });
    t.mock.method(socket, "end", (data: string) => { responses.push(data); return socket; });
    const terminate = t.mock.method(r.internals, "terminate", () => {});
    const tunnel = t.mock.method(r.internals, "tunnel", () => {});
    r.internals.onConnect(socket);
    socket.emit("data", Buffer.from(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    assert.match(responses.join(""), new RegExp(`^HTTP/1\\.1 ${wanted} `));
    assert.equal(terminate.mock.callCount(), dispatch === "terminate" ? 1 : 0);
    assert.equal(tunnel.mock.callCount(), dispatch === "tunnel" ? 1 : 0);
  });
}

test("an extra picker host is opaque; no new origin acquires interception privileges", t => {
  const r = base(t);
  r.change(cfg => ({ ...cfg, picker: { enabled: true, hosts: ["claude.ai", ASSET] } }));
  const socket = new net.Socket();
  t.after(() => socket.destroy());
  t.mock.method(socket, "write", () => true);
  const terminate = t.mock.method(r.internals, "terminate", () => {});
  const tunnel = t.mock.method(r.internals, "tunnel", () => {});
  r.internals.onConnect(socket);
  socket.emit("data", Buffer.from(`CONNECT ${ASSET}:443 HTTP/1.1\r\n\r\n`));
  assert.equal(terminate.mock.callCount(), 0);
  assert.equal(tunnel.mock.callCount(), 1);
});

test("picker off keeps personal CONNECT strict even for an otherwise approved origin", t => {
  const r = base(t);
  r.change(cfg => ({ ...cfg, picker: { enabled: false } }));
  const socket = new net.Socket();
  t.after(() => socket.destroy());
  const replies: string[] = [];
  t.mock.method(socket, "end", (data: string) => { replies.push(data); return socket; });
  const tunnel = t.mock.method(r.internals, "tunnel", () => {});
  r.internals.onConnect(socket);
  socket.emit("data", Buffer.from(`CONNECT ${ASSET}:443 HTTP/1.1\r\n\r\n`));
  assert.match(replies.join(""), /^HTTP\/1\.1 403 /);
  assert.equal(tunnel.mock.callCount(), 0);
});

test("blocked Desktop diagnostics are bounded canonical origins and do not grant access", t => {
  const r = base(t);
  const tunnel = t.mock.method(r.internals, "tunnel", () => {});
  for (let n = 0; n < 20; n++) {
    const socket = new net.Socket();
    t.mock.method(socket, "end", () => socket);
    r.internals.onConnect(socket);
    socket.emit("data", Buffer.from(`CONNECT denied-${n}.example.test:443 HTTP/1.1\r\nX-Secret: SECRET-NOT-DIAGNOSTIC\r\n\r\n`));
    socket.destroy();
  }
  assert.equal(r.proxy.blockedDesktopOrigins.length, 16);
  assert.ok(r.proxy.blockedDesktopOrigins.every(origin => /^https:\/\/denied-\d+\.example\.test$/.test(origin)));
  assert.deepEqual(r.config().security!.approvedOrigins, ORIGINS);
  assert.equal(tunnel.mock.callCount(), 0);
  const approved = r.proxy.blockedDesktopOrigins[0]!;
  r.change(cfg => ({ ...cfg, security: { mode: "personal", approvedOrigins: [...ORIGINS, approved] } }));
  assert.ok(!r.proxy.blockedDesktopOrigins.includes(approved), "explicit approval clears its stale warning");
});

for (const reason of ["revoke", "picker-off", "client-close", "upstream-error", "timeout", "shutdown"] as const) {
  test(`opaque Desktop tunnel closes both sides and clears its registry on ${reason}`, t => {
    const r = base(t);
    const client = new net.Socket(), upstream = new net.Socket();
    t.mock.method(net, "connect", () => upstream);
    if (reason === "timeout") t.mock.timers.enable({ apis: ["setTimeout"] });
    r.internals.tunnel(client, ASSET, 443);
    assert.equal(r.internals.desktopStreams.size, 1);
    if (reason === "revoke") r.change(cfg => ({ ...cfg, security: { mode: "personal", approvedOrigins: ["https://claude.ai"] } }));
    if (reason === "picker-off") r.change(cfg => ({ ...cfg, picker: { enabled: false } }));
    if (reason === "client-close") client.emit("close");
    if (reason === "upstream-error") upstream.emit("error", new Error("synthetic dial failure"));
    if (reason === "timeout") t.mock.timers.tick(10_001);
    if (reason === "shutdown") r.proxy.close();
    assert.equal(client.destroyed, true);
    assert.equal(upstream.destroyed, true);
    assert.equal(r.internals.desktopStreams.size, 0);
  });
}

test("opaque tunnels are capped and all pending connections are closed at shutdown", t => {
  const r = base(t);
  const upstreams: net.Socket[] = [];
  const dial = t.mock.method(net, "connect", () => { const sock = new net.Socket(); upstreams.push(sock); return sock; });
  for (let n = 0; n < 128; n++) r.internals.tunnel(new net.Socket(), ASSET, 443);
  const excess = new net.Socket();
  r.internals.tunnel(excess, ASSET, 443);
  assert.equal(excess.destroyed, true);
  assert.equal(r.internals.desktopStreams.size, 128);
  assert.equal(dial.mock.callCount(), 128);
  r.proxy.close();
  assert.equal(r.internals.desktopStreams.size, 0);
  assert.ok(upstreams.every(sock => sock.destroyed));
});

type Reply = { status: number; headers: http.IncomingHttpHeaders; body: string };
async function readHead(socket: net.Socket): Promise<{ header: string; tail: Buffer }> {
  return await new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const onError = (error: Error) => { cleanup(); reject(error); };
    const onClose = () => onError(new Error("closed before response headers"));
    const cleanup = () => { socket.off("data", onData); socket.off("error", onError); socket.off("close", onClose); };
    const onData = (chunk: Buffer) => {
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf("\r\n\r\n");
      if (end >= 0) { cleanup(); socket.pause(); resolve({ header: bytes.subarray(0, end + 4).toString("latin1"), tail: bytes.subarray(end + 4) }); }
      else if (bytes.length > 65536) onError(new Error("oversized synthetic header"));
    };
    socket.on("data", onData);
    socket.once("error", onError);
    socket.once("close", onClose);
    socket.resume();
  });
}

async function rig(t: TestContext) {
  const r = base(t);
  const ca = createCa({ cn: "Synthetic Desktop transport CA" });
  const leaves = Object.fromEntries(["api.anthropic.com", "claude.ai", ASSET].map(host => [host, createLeaf({ host, caCertPem: ca.certPem, caKeyPem: ca.keyPem })]));
  const sockets = new Set<Duplex>();
  const agents: https.Agent[] = [];
  const servers: https.Server[] = [];
  const hits: { host: string; path: string; headers: http.IncomingHttpHeaders; raw?: string }[] = [];
  const websocketUpstreams = new Set<Duplex>();
  const events = new EventEmitter();
  t.after(async () => {
    r.proxy.close();
    for (const agent of agents) agent.destroy();
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve()))));
  });
  for (const host of ["api.anthropic.com", "claude.ai", ASSET]) {
    if (host !== ASSET) r.certs.register(host, Buffer.from(leaves[host]!.certPem), Buffer.from(leaves[host]!.keyPem));
    const server = https.createServer({ cert: leaves[host]!.certPem, key: leaves[host]!.keyPem }, (req, res) => {
      const hit: typeof hits[number] = { host, path: req.url!, headers: req.headers };
      hits.push(hit);
      if (req.url === "/v1/messages") {
        const body: Buffer[] = [];
        req.on("data", bytes => body.push(bytes));
        req.on("end", () => {
          hit.raw = Buffer.concat(body).toString("utf8");
          res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ type: "message", id: "msg_native_fixture", role: "assistant", content: [{ type: "text", text: "Synthetic native answer" }], stop_reason: "end_turn", usage: { input_tokens: 5, output_tokens: 3 } }));
        });
        return;
      }
      if (req.url === "/cached") res.writeHead(304, { etag: '"fixture-version"' }).end();
      else if (req.url === "/redirect-same") res.writeHead(302, { location: "/landing" }).end();
      else if (req.url === "/redirect-approved") res.writeHead(307, { location: `https://${ASSET}/landing` }).end();
      else if (req.url === "/redirect-unapproved") res.writeHead(302, { location: "https://unapproved.example.test/landing" }).end();
      else if (req.url === "/redirect-http") res.writeHead(302, { location: "http://claude.ai/landing" }).end();
      else if (req.url === "/redirect-credentials") res.writeHead(302, { location: "https://name:secret@claude.ai/landing" }).end();
      else res.writeHead(200, { "content-type": "text/plain" }).end("synthetic native content");
    });
    server.on("connection", socket => { sockets.add(socket); socket.once("close", () => sockets.delete(socket)); });
    server.on("upgrade", (req, socket, head) => {
      hits.push({ host, path: req.url!, headers: req.headers });
      websocketUpstreams.add(socket);
      socket.once("close", () => websocketUpstreams.delete(socket));
      events.emit("websocket", req.url);
      const accept = req.url === "/ws-bad" ? "invalid" : crypto.createHash("sha1").update(`${req.headers["sec-websocket-key"]}258EAFA5-E914-47DA-95CA-C5AB0DC85B11`).digest("base64");
      if (req.url === "/ws-stall") return;
      socket.write(`HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: ${accept}\r\nSet-Cookie: fixture=unchanged; Secure\r\n\r\n`);
      if (head.length) socket.write(head);
      socket.on("data", bytes => socket.write(bytes));
      socket.on("error", () => {});
    });
    servers.push(server);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    const port = (server.address() as net.AddressInfo).port;
    const agent = new https.Agent({ keepAlive: false });
    agent.createConnection = options => {
      assert.equal(options.host, host);
      return tls.connect({ host: "127.0.0.1", port, servername: host, ca: ca.certPem, rejectUnauthorized: true, ALPNProtocols: ["http/1.1"] });
    };
    agents.push(agent);
    if (host === "api.anthropic.com") (r.proxy as unknown as { upstreamAgent: https.Agent }).upstreamAgent = agent;
    else r.internals.providerAgents.set(`host:${host}|https:`, agent);
    if (host === ASSET) {
      const connect = net.connect.bind(net);
      t.mock.method(net, "connect", (...args: unknown[]) => {
        const options = args[0] as { host?: string; port?: number };
        if (options && typeof options === "object" && options.host === ASSET) {
          assert.equal(options.port, 443);
          return connect({ host: "127.0.0.1", port });
        }
        return (connect as (...args: unknown[]) => net.Socket)(...args);
      });
    }
  }
  await r.proxy.listen();
  const port = (r.internals.server.address() as net.AddressInfo).port;
  async function secure(host = "claude.ai") {
    const socket = net.connect({ host: "127.0.0.1", port });
    sockets.add(socket);
    socket.on("error", () => {});
    await once(socket, "connect");
    const response = readHead(socket);
    socket.write(`CONNECT ${host}:443 HTTP/1.1\r\nHost: ${host}:443\r\n\r\n`);
    assert.match((await response).header, /^HTTP\/1\.1 200 /);
    const tlsSocket = tls.connect({ socket, servername: host, ca: ca.certPem, rejectUnauthorized: true });
    sockets.add(tlsSocket);
    tlsSocket.on("error", () => {});
    await once(tlsSocket, "secureConnect");
    assert.equal(tlsSocket.authorized, true);
    return tlsSocket;
  }
  async function send(requestPath: string, host = "claude.ai", options: { body?: Record<string, unknown>; headers?: Record<string, string> } = {}): Promise<Reply> {
    const socket = await secure(host);
    const agent = new https.Agent({ keepAlive: false });
    agents.push(agent);
    agent.createConnection = () => socket;
    return await new Promise((resolve, reject) => {
      const raw = options.body ? JSON.stringify(options.body) : undefined;
      const req = https.request({ host, port: 443, path: requestPath, agent, method: raw ? "POST" : "GET",
        headers: { cookie: "fixture=synthetic-native-session", connection: "close", ...(raw ? { "content-type": "application/json", "content-length": String(Buffer.byteLength(raw)), authorization: "Bearer SYNTHETIC-NATIVE-SUBSCRIPTION", "x-claude-code-session-id": "desktop-native-session" } : {}), ...options.headers } }, response => {
        const body: Buffer[] = [];
        response.on("data", chunk => body.push(chunk));
        response.once("error", reject);
        response.once("end", () => resolve({ status: response.statusCode!, headers: response.headers, body: Buffer.concat(body).toString("utf8") }));
      });
      req.once("error", reject);
      req.end(raw);
    });
  }
  async function upgrade(options: { target?: string; host?: string; path?: string; key?: string; method?: string; protocol?: string } = {}) {
    const socket = await secure(options.target);
    const response = readHead(socket);
    socket.write(`${options.method ?? "GET"} ${options.path ?? "/ws"} HTTP/1.1\r\nHost: ${options.host ?? options.target ?? "claude.ai"}\r\nConnection: Upgrade\r\nUpgrade: ${options.protocol ?? "websocket"}\r\nSec-WebSocket-Key: ${options.key ?? KEY}\r\nSec-WebSocket-Version: 13\r\nCookie: fixture=synthetic-native-session\r\nProxy-Authorization: SYNTHETIC-LOCAL-PROXY-SECRET\r\n\r\n`);
    return { socket, ...(await response) };
  }
  return { ...r, secure, send, upgrade, hits, leaves, websocketUpstreams, events };
}

test("approved asset CONNECT stays end-to-end TLS without minting a local interception leaf", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const socket = await r.secure(ASSET);
  assert.equal(socket.getPeerCertificate().fingerprint256, new crypto.X509Certificate(r.leaves[ASSET]!.certPem).fingerprint256);
  const response = readHead(socket);
  socket.write(`GET /asset HTTP/1.1\r\nHost: ${ASSET}\r\nConnection: keep-alive\r\n\r\n`);
  assert.match((await response).header, /^HTTP\/1\.1 200 /);
  assert.equal(r.hits.at(-1)!.host, ASSET);
  assert.equal(r.internals.desktopStreams.size, 1);
  const closed = once(socket, "close");
  socket.resume();
  r.change(cfg => ({ ...cfg, security: { mode: "personal", approvedOrigins: ["https://claude.ai"] } }));
  await closed;
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("Desktop cache validation and browser-owned approved redirects survive unchanged without server-follow", { timeout: 20_000 }, async t => {
  const r = await rig(t);
  const cached = await r.send("/cached");
  assert.equal(cached.status, 304);
  assert.equal(cached.headers.etag, '"fixture-version"');
  for (const [path, status, location] of [["/redirect-same", 302, "/landing"], ["/redirect-approved", 307, `https://${ASSET}/landing`]] as const) {
    const before = r.hits.length;
    const reply = await r.send(path);
    assert.equal(reply.status, status, reply.body);
    assert.equal(reply.headers.location, location);
    assert.equal(r.hits.length, before + 1, "the proxy must not follow a redirect");
  }
  for (const path of ["/redirect-unapproved", "/redirect-http", "/redirect-credentials"]) assert.equal((await r.send(path)).status, 502, path);
  assert.equal((await r.send("/redirect-same", "api.anthropic.com")).status, 502, "native inference API redirects stay forbidden");
  assert.equal((await r.send("/cached", "api.anthropic.com")).status, 304);
  assert.ok(r.hits.every(hit => hit.host !== ASSET), "no approved redirect destination was dialled");
});

test("native Desktop WebSocket preserves cookies and frames, drops local proxy auth, and closes on revocation", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const result = await r.upgrade();
  assert.match(result.header, /^HTTP\/1\.1 101 /);
  assert.match(result.header, /Set-Cookie: fixture=unchanged; Secure/i);
  assert.equal(r.hits.at(-1)!.headers.cookie, "fixture=synthetic-native-session");
  assert.equal(r.hits.at(-1)!.headers["proxy-authorization"], undefined);
  const frame = Buffer.from([0x89, 0x80, 0x01, 0x02, 0x03, 0x04]);
  const echoed = once(result.socket, "data");
  result.socket.resume();
  result.socket.write(frame);
  assert.deepEqual((await echoed)[0], frame);
  const closed = once(result.socket, "close");
  r.change(cfg => ({ ...cfg, security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com"] } }));
  await closed;
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("native Desktop WebSocket rejects another authority, API upgrades, malformed keys and generic protocols before dialing", { timeout: 20_000 }, async t => {
  const r = await rig(t);
  for (const options of [{ host: ASSET }, { target: "api.anthropic.com" }, { key: "not-a-websocket-key" }, { method: "POST" }, { protocol: "h2c" }]) {
    const reply = await r.upgrade(options);
    assert.match(reply.header, /^HTTP\/1\.1 426 /);
    reply.socket.destroy();
  }
  assert.deepEqual(r.hits, []);
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("native Desktop WebSocket validates upstream acceptance instead of blindly splicing", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const reply = await r.upgrade({ path: "/ws-bad" });
  assert.match(reply.header, /^HTTP\/1\.1 502 /);
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("picker disable closes already established Desktop WebSockets", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const reply = await r.upgrade();
  assert.match(reply.header, /^HTTP\/1\.1 101 /);
  const closed = once(reply.socket, "close");
  reply.socket.resume();
  r.change(cfg => ({ ...cfg, picker: { enabled: false } }));
  await closed;
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("native Desktop WebSocket has a bounded upstream handshake deadline", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const contacted = once(r.events, "websocket");
  const pending = r.upgrade({ path: "/ws-stall" });
  assert.equal((await contacted)[0], "/ws-stall");
  assert.equal(r.internals.desktopStreams.size, 1);
  t.mock.timers.tick(10_001);
  const response = await pending;
  assert.match(response.header, /^HTTP\/1\.1 502 /);
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("native Desktop WebSocket closes its upstream after the client exits", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const reply = await r.upgrade();
  assert.match(reply.header, /^HTTP\/1\.1 101 /);
  const upstream = r.websocketUpstreams.values().next().value!;
  const closed = once(upstream, "close");
  reply.socket.destroy();
  await closed;
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("revocation also closes a native Desktop WebSocket while its handshake is pending", { timeout: 15_000 }, async t => {
  const r = await rig(t);
  const contacted = once(r.events, "websocket");
  const pending = r.upgrade({ path: "/ws-stall" });
  await contacted;
  assert.equal(r.internals.desktopStreams.size, 1);
  r.change(cfg => ({ ...cfg, security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com"] } }));
  await assert.rejects(pending, /closed before response headers/);
  assert.equal(r.internals.desktopStreams.size, 0);
});

test("native Desktop subscription turns and auxiliary services ignore stale routing overrides", { timeout: 20_000 }, async t => {
  const r = await rig(t);
  r.change(cfg => ({ ...cfg,
    providers: { aux: { type: "anthropic-compatible", url: "https://claude.ai", headers: { "x-api-key": "SYNTHETIC-UNUSED-EXTERNAL-KEY" }, models: [{ id: "aux-model" }] } },
    routes: { "claude-haiku-5-5": { provider: "aux", model: "aux-model" } },
    aliases: { haiku: "aux-model" }, direct: [{ prefix: "claude-", provider: "aux" }],
    webSearch: { provider: "aux", model: "aux-model" }, autoModeClassifier: { provider: "aux", model: "aux-model" },
  }));
  // If a regression accidentally calls that old destination, it still reaches only a synthetic server.
  r.internals.providerAgents.set("aux|https:", r.internals.providerAgents.get("host:claude.ai|https:")!);
  fs.writeFileSync(path.join(r.home, "mod-settings.json"), JSON.stringify({ settings: { compactModel: "aux-model" }, revision: 1, stored: true }));
  r.proxy.compactPicks.set("desktop-native-session", "aux-model");
  const message = (text: string) => ({ model: "claude-haiku-5-5", max_tokens: 64, messages: [{ role: "user", content: text }] });
  const cases = [
    ["turn", message("[[ripple: aux-model]]\nSynthetic native task")],
    ["web-search", { ...message("Perform a web search for the query: synthetic search"), tools: [{ type: "web_search_20250305", name: "web_search" }], tool_choice: { type: "auto" } }],
    ["web-fetch", message("\nWeb page content:\n---\nSynthetic page.\n---\n\nSummarize this page.\n\nProvide a concise response based on the content above. Include relevant details, code examples, and documentation excerpts as needed.\n")],
    ["auto-mode-classifier", { ...message("Synthetic permission check"), system: "You are a security monitor for autonomous AI coding agents.\nEvaluate the action.", tools: [] }],
    ["compaction", message("Your task is to create a detailed summary of the conversation so far.")],
  ] as const;
  for (const [kind, body] of cases) {
    assert.equal(requestKind(body, "/v1/messages"), kind);
    const response = await r.send("/v1/messages", "api.anthropic.com", { body });
    assert.equal(response.status, 200, `${kind}: ${response.body}`);
    const seen = r.hits.at(-1)!;
    assert.equal(seen.host, "api.anthropic.com", kind);
    assert.equal(seen.raw, JSON.stringify(body), `${kind}: native body is unchanged`);
    assert.equal(seen.headers.authorization, "Bearer SYNTHETIC-NATIVE-SUBSCRIPTION");
    assert.equal(seen.headers.cookie, "fixture=synthetic-native-session");
    assert.equal(seen.headers["x-api-key"], undefined);
  }
  assert.equal(r.hits.length, cases.length, "no auxiliary provider was queried first");
  assert.equal(r.proxy.compactPicks.take("desktop-native-session", false, () => undefined), undefined, "ignored queued compaction is cleared");
});
