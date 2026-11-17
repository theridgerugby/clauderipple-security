import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import https from "node:https";
import http from "node:http";
import net from "node:net";
import * as crypto from "node:crypto";
import * as stream from "node:stream";
import * as tls from "node:tls";
import type { Socket } from "node:net";
import { once } from "node:events";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { adminTlsFetch, validateAdminPath, ADMIN_TLS_IDLE_TIMEOUT_MS, ADMIN_TLS_RESPONSE_LIMIT } from "../src/admin-transport-client.ts";
import { ADMIN_TOKEN_HEADER } from "../src/admin-auth.ts";
import { createCa, createLeaf } from "../src/x509.ts";
import { adminTlsFixture } from "./admin-tls-fixture.ts";

test("admin TLS validates path, authority, capability and request size before any connection", async t => {
  const f = await adminTlsFixture(t);
  for (const value of ["/", "https://evil.example/api/a", "//evil.example/api/a", "/api/../private", "/api/%2e%2e/private", "/api/\\evil", "/api/a#fragment", "/api/a\r\n", "/api/nested/../status", "/api/nested/%2e%2e/status", "/api/sta\ttus", " /api/status", "/api/status\u007f"])
    assert.throws(() => validateAdminPath(value), /invalid admin API path/);
  assert.equal(validateAdminPath("/api/requests?n=20&session=a%20b"), "/api/requests?n=20&session=a%20b");
  assert.equal(validateAdminPath("/readyz"), "/readyz");
  assert.throws(() => adminTlsFetch({ ...f.endpoint, tlsPort: 0 }, f.identity, f.token, "/api/status"), /endpoint/);
  assert.throws(() => adminTlsFetch(f.endpoint, f.identity, "", "/api/status"), /credential/);
  assert.throws(() => adminTlsFetch(f.endpoint, f.identity, f.token, "/api/status", { method: "CONNECT" }), /method/);
  assert.throws(() => adminTlsFetch(f.endpoint, f.identity, f.token, "/api/status", { body: "unexpected GET body" }), /body/);
});

test("pinned TLS sends credentials only to the private identity and strips caller authority/framing", async t => {
  let received: { headers: http.IncomingHttpHeaders; body: string; url: string | undefined } | undefined;
  const f = await adminTlsFixture(t, async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const value of req) chunks.push(Buffer.from(value));
    received = { headers: req.headers, body: Buffer.concat(chunks).toString(), url: req.url };
    res.writeHead(201, { "content-type": "application/json", "set-cookie": "not-forwarded=1", "x-clauderipple-admin": "never-forward" });
    res.end('{"saved":true}');
  });
  const response = await adminTlsFetch(f.endpoint, f.identity, f.token, "/api/config?revision=2", {
    method: "PUT", body: "test-private-body", headers: {
      host: "attacker.example", origin: "https://attacker.example", authorization: "Bearer unused",
      "proxy-authorization": "Basic unused", "content-length": "1", "transfer-encoding": "chunked",
      [ADMIN_TOKEN_HEADER]: "caller-supplied", "content-type": "application/json",
    },
  });
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), { saved: true });
  assert.equal(received?.headers[ADMIN_TOKEN_HEADER], f.token);
  assert.equal(received?.headers["x-clauderipple-instance-id"], f.endpoint.instanceId);
  assert.equal(received?.headers.host, `127.0.0.1:${f.endpoint.tlsPort}`);
  assert.equal(received?.headers["content-length"], String(Buffer.byteLength("test-private-body")));
  for (const name of ["origin", "authorization", "proxy-authorization", "transfer-encoding"]) assert.equal(received?.headers[name], undefined);
  assert.equal(received?.body, "test-private-body");
  assert.equal(received?.url, "/api/config?revision=2");
  assert.equal(response.headers.has("set-cookie"), false);
  assert.equal(response.headers.has(ADMIN_TOKEN_HEADER), false);
});

for (const kind of ["foreign CA", "same CA but different leaf", "wrong IP SAN"] as const) {
  test(`a port imposter with ${kind} receives no HTTP capability or request body`, async t => {
    const f = await adminTlsFixture(t);
    const ca = createCa();
    const expected = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
    const replacement = createLeaf({ host: kind === "wrong IP SAN" ? "localhost" : "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
    let calls = 0;
    const imposter = https.createServer({ key: replacement.keyPem, cert: replacement.certPem }, (_req, res) => { calls++; res.end("stolen"); });
    imposter.listen(0, "127.0.0.1");
    await once(imposter, "listening");
    t.after(async () => { imposter.closeAllConnections(); await new Promise<void>(resolve => imposter.close(() => resolve())); });
    const address = imposter.address();
    assert.ok(address && typeof address === "object");
    const identity = kind === "foreign CA" ? f.identity : { caCertPem: ca.certPem, certPem: kind === "wrong IP SAN" ? replacement.certPem : expected.certPem };
    await assert.rejects(adminTlsFetch({ ...f.endpoint, tlsPort: address.port }, identity, f.token, "/api/config", {
      method: "PUT", body: "private-provider-credential",
    }), /TLS connection or identity verification failed/);
    assert.equal(calls, 0, "verification fails before HTTP application data is written");
  });
}

test("a plaintext port imposter only sees a TLS handshake and never the capability/body", async t => {
  const f = await adminTlsFixture(t);
  const bytes: Buffer[] = [];
  const sockets = new Set<Socket>();
  const imposter = net.createServer(socket => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
    socket.on("data", data => { bytes.push(data); socket.end("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"); });
    socket.on("error", () => {});
  });
  imposter.listen(0, "127.0.0.1");
  await once(imposter, "listening");
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => imposter.close(() => resolve())); });
  const address = imposter.address();
  assert.ok(address && typeof address === "object");
  await assert.rejects(adminTlsFetch({ ...f.endpoint, tlsPort: address.port }, f.identity, f.token, "/api/config", {
    method: "PUT", body: "private-provider-credential",
  }), /TLS connection or identity verification failed/);
  const observed = Buffer.concat(bytes).toString("latin1");
  assert.ok(bytes.length > 0);
  assert.equal(observed.includes(f.token), false);
  assert.equal(observed.includes("private-provider-credential"), false);
  assert.equal(observed.includes("PUT /api/config"), false);
});

test("TLS redirects are rejected even to another endpoint on the same machine", async t => {
  const calls: string[] = [];
  const f = await adminTlsFixture(t, (req, res) => {
    calls.push(req.url ?? "");
    res.writeHead(302, { location: "/api/collect" }).end();
  });
  await assert.rejects(adminTlsFetch(f.endpoint, f.identity, f.token, "/api/redirect"), /redirects are forbidden/);
  assert.deepEqual(calls, ["/api/redirect"]);
});

test("TLS handshake deadline rejects a TCP listener that never authenticates", { timeout: 10_000 }, async t => {
  const f = await adminTlsFixture(t);
  const sockets = new Set<Socket>();
  const stalled = net.createServer(socket => { sockets.add(socket); socket.on("close", () => sockets.delete(socket)); });
  stalled.listen(0, "127.0.0.1");
  await once(stalled, "listening");
  t.after(async () => { for (const socket of sockets) socket.destroy(); await new Promise<void>(resolve => stalled.close(() => resolve())); });
  const address = stalled.address();
  assert.ok(address && typeof address === "object");
  await assert.rejects(adminTlsFetch({ ...f.endpoint, tlsPort: address.port }, f.identity, f.token, "/api/status"), /TLS connection timed out/);
});

test("authenticated requests can wait longer than four seconds for native approval", { timeout: 10_000 }, async t => {
  let delay: ReturnType<typeof setTimeout> | undefined;
  t.after(() => clearTimeout(delay));
  const f = await adminTlsFixture(t, (_req, res) => { delay = setTimeout(() => res.end('{"approved":true}'), 4200); });
  const response = await adminTlsFetch(f.endpoint, f.identity, f.token, "/api/picker", { method: "POST", body: "{}" });
  assert.deepEqual(await response.json(), { approved: true });
});

test("caller cancellation aborts both preflight and an authenticated response stream", async t => {
  const f = await adminTlsFixture(t, (_req, res) => { res.writeHead(200); res.write("start"); });
  await assert.rejects(adminTlsFetch(f.endpoint, f.identity, f.token, "/api/status", { signal: AbortSignal.abort() }), /aborted/);
  const controller = new AbortController();
  const response = await adminTlsFetch(f.endpoint, f.identity, f.token, "/api/status", { signal: controller.signal });
  controller.abort();
  await assert.rejects(response.text());
});

test("Electron and CLI use byte-identical TLS verification code", () => {
  assert.equal(fs.readFileSync(new URL("../../app/src/admin-transport-client.ts", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../src/admin-transport-client.ts", import.meta.url), "utf8"));
});

/** Only the idle socket deadline is shortened. HTTPS, CA/expiry/SAN and exact-leaf checks stay real. */
function acceleratedIdleTransport(onIdleTimeout: () => void): typeof adminTlsFetch {
  const source = fs.readFileSync(new URL("../src/admin-transport-client.ts", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
  const exports: { adminTlsFetch?: typeof adminTlsFetch } = {};
  const modules: Record<string, unknown> = {
    "node:crypto": crypto, "node:tls": tls, "node:stream": stream,
    "node:https": {
      ...https,
      request: (options: https.RequestOptions, callback: (response: http.IncomingMessage) => void) => {
        assert.equal(options.rejectUnauthorized, true);
        assert.equal(typeof options.checkServerIdentity, "function");
        assert.ok(options.ca, "the real fixture CA is still mandatory");
        const request = https.request(options, callback);
        const setTimeout = request.setTimeout.bind(request);
        request.setTimeout = (delay, listener) => {
          assert.equal(delay, ADMIN_TLS_IDLE_TIMEOUT_MS);
          return setTimeout(250, () => { onIdleTimeout(); listener?.(); });
        };
        return request;
      },
    },
  };
  runInNewContext(compiled, {
    exports, require: (id: string) => { assert.ok(id in modules, id); return modules[id]; },
    URL, Request, Response, Headers, ReadableStream, Buffer, Uint8Array, AbortController, AbortSignal, setTimeout, clearTimeout,
  });
  assert.ok(exports.adminTlsFetch);
  return exports.adminTlsFetch;
}

async function closesPromptly(closed: Promise<void>): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([closed, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error("client left its HTTPS response/socket open")), 1500);
    })]);
  } finally { clearTimeout(timer); }
}

test("a genuinely expired pinned certificate fails before receiving any HTTP request", async t => {
  const f = await adminTlsFixture(t);
  const ca = createCa({ cn: "Expired leaf fixture CA" });
  const expired = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem, days: -1 / 48 });
  assert.ok(Date.parse(new crypto.X509Certificate(expired.certPem).validTo) < Date.now());
  let requests = 0;
  const server = https.createServer({ cert: expired.certPem, key: expired.keyPem }, (_req, res) => { requests++; res.end("unexpected"); });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  t.after(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });
  const address = server.address(); assert.ok(address && typeof address === "object");
  await assert.rejects(adminTlsFetch({ ...f.endpoint, tlsPort: address.port }, { caCertPem: ca.certPem, certPem: expired.certPem }, f.token, "/api/status"), /identity verification failed/);
  assert.equal(requests, 0);
});

test("a declared response beyond 64 MiB is rejected before reading and closes its peer", async t => {
  let closePeer!: () => void;
  const closed = new Promise<void>(resolve => { closePeer = resolve; });
  const f = await adminTlsFixture(t, (_req, res) => {
    res.once("close", closePeer);
    res.writeHead(200, { "content-length": String(ADMIN_TLS_RESPONSE_LIMIT + 1) }); res.write("small");
  });
  await assert.rejects(adminTlsFetch(f.endpoint, f.identity, f.token, "/api/status"), /response exceeds the size limit/);
  await closesPromptly(closed);
});

test("chunked responses are bounded at 64 MiB while cancellation releases the sender", { timeout: 15_000 }, async t => {
  let closePeer!: () => void;
  const closed = new Promise<void>(resolve => { closePeer = resolve; });
  const chunk = Buffer.alloc(256 * 1024, 97);
  const f = await adminTlsFixture(t, async (_req, res) => {
    res.once("close", closePeer); res.writeHead(200, { "content-type": "application/octet-stream" });
    const writable = (): Promise<boolean> => new Promise(resolve => {
      const cleanup = () => { res.off("drain", drained); res.off("close", stopped); };
      const drained = () => { cleanup(); resolve(true); };
      const stopped = () => { cleanup(); resolve(false); };
      res.once("drain", drained); res.once("close", stopped);
    });
    for (let bytes = 0; bytes <= ADMIN_TLS_RESPONSE_LIMIT; bytes += chunk.length) {
      if (res.destroyed) return;
      if (!res.write(chunk) && !await writable()) return;
    }
    // Keep the peer open; reaching the client limit must close it, not wait for a server EOF.
  });
  const response = await adminTlsFetch(f.endpoint, f.identity, f.token, "/api/image");
  const reader = response.body!.getReader();
  let received = 0;
  await assert.rejects(async () => {
    for (;;) { const next = await reader.read(); if (next.done) break; received += next.value.byteLength; }
  }, /response exceeds the size limit/);
  assert.ok(received <= ADMIN_TLS_RESPONSE_LIMIT);
  await closesPromptly(closed);
});

for (const consume of [false, true]) test(`body cancellation ${consume ? "after one chunk" : "before the first read"} promptly closes the authenticated peer`, async t => {
  let closePeer!: () => void;
  const closed = new Promise<void>(resolve => { closePeer = resolve; });
  const f = await adminTlsFixture(t, (_req, res) => { res.once("close", closePeer); res.write("first"); });
  const response = await adminTlsFetch(f.endpoint, f.identity, f.token, "/api/status");
  if (consume) {
    const reader = response.body!.getReader(); assert.equal((await reader.read()).done, false); await reader.cancel();
  } else await response.body!.cancel();
  await closesPromptly(closed);
});

for (const bodyStarted of [false, true]) test(`native idle deadline closes an authenticated peer stalled ${bodyStarted ? "inside its body" : "before response headers"}`, async t => {
  let closePeer!: () => void;
  const closed = new Promise<void>(resolve => { closePeer = resolve; });
  let requests = 0;
  const f = await adminTlsFixture(t, (_req, res) => {
    requests++; res.once("close", closePeer);
    if (bodyStarted) res.write("first");
  });
  let idleTimeouts = 0;
  const fetch = acceleratedIdleTransport(() => { idleTimeouts++; });
  if (bodyStarted) {
    const response = await fetch(f.endpoint, f.identity, f.token, "/api/status");
    await assert.rejects(response.text(), /admin response interrupted/);
  } else await assert.rejects(fetch(f.endpoint, f.identity, f.token, "/api/status"), /admin response timed out/);
  assert.equal(requests, 1, "the request really authenticated and reached its HTTPS handler");
  assert.equal(idleTimeouts, 1, "the real native socket idle timer fired");
  await closesPromptly(closed);
});
