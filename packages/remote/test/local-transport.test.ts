import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import crypto from "node:crypto";
import { checkServerIdentity, connect as connectTls } from "node:tls";
import { once } from "node:events";
import { LocalControl, localSecret } from "../src/local-control.ts";
import { loadConfig, saveConfig } from "../src/config.ts";
import { localControlHome, localControlRequest, readLocalControlState } from "../src/local-transport.ts";
import { controlShutdown, hostStatus } from "../src/host-service.ts";
import { ensureAdminTlsIdentity, readAdminEndpoint, writeAdminEndpoint, type AdminEndpoint } from "../../router/src/admin-transport-state.ts";
import { ADMIN_TOKEN_HEADER } from "../../router/src/admin-auth.ts";
import { writePrivateFileAtomic } from "../../router/src/locked-file.ts";
import { posixModes } from "../../../test/capabilities.ts";

/** Test metadata only: never select the existing TLS listener as the replacement public port. */
function differentPublicPort(endpoint: Pick<AdminEndpoint, "publicPort" | "tlsPort">): number {
  // Two consecutive candidates suffice because only one can equal the TLS port. Wrapping
  // keeps boundary fixtures in the valid 1..65535 range without allocating another listener.
  for (let offset = 1; offset <= 2; offset++) {
    const candidate = ((endpoint.publicPort - 1 + offset) % 65_535) + 1;
    if (candidate !== endpoint.tlsPort) return candidate;
  }
  throw new Error("could not select a distinct fixture port");
}

test("replacement public-port fixtures exclude adjacent TLS ports and wrap the 65535 boundary", () => {
  for (const [publicPort, tlsPort, expected] of [
    [50_000, 50_001, 50_002],
    [65_534, 65_535, 1],
    [65_535, 1, 2],
    [65_535, 65_534, 1],
    [1, 2, 3],
  ] as const) {
    const actual = differentPublicPort({ publicPort, tlsPort });
    assert.equal(actual, expected);
    assert.ok(Number.isInteger(actual) && actual >= 1 && actual <= 65_535);
    assert.notEqual(actual, publicPort);
    assert.notEqual(actual, tlsPort);
  }
});

async function fixture(t: import("node:test").TestContext) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-host-tls-"));
  let publicServer: http.Server | undefined;
  let local: LocalControl | undefined;
  t.after(async () => {
    try { await local?.close(); }
    finally {
      try {
        if (publicServer) {
          publicServer.closeAllConnections();
          await new Promise<void>(resolve => publicServer!.close(() => resolve()));
        }
      } finally { fs.rmSync(dir, { recursive: true, force: true }); }
    }
  });
  let publicRequests = 0;
  publicServer = http.createServer((_request, response) => { publicRequests++; response.end("untrusted public port"); });
  await new Promise<void>(resolve => publicServer.listen(0, "127.0.0.1", resolve));
  const address = publicServer.address(); assert.ok(address && typeof address !== "string");
  const cfg = loadConfig(dir); cfg.port = address.port; saveConfig(cfg, dir);
  fs.writeFileSync(path.join(dir, "local.secret"), "legacy-fixture-capability", { mode: 0o600 });
  local = new LocalControl({ dir, config: cfg, version: "test", hostPublicKey: "public", phones: () => [], rotate() {} });
  await local.listen(cfg.port);
  return { dir, cfg, local, home: localControlHome(dir), publicRequests: () => publicRequests };
}

function raw(dir: string, headers: string[]): Promise<number> {
  const state = readLocalControlState(dir); assert.ok(state);
  const fingerprint = new crypto.X509Certificate(state.identity.certPem).fingerprint256;
  return new Promise((resolve, reject) => {
    const request = https.request({ host: "127.0.0.1", port: state.endpoint.tlsPort,
      path: "/api/local/status", method: "GET", headers, agent: false, ca: state.identity.caCertPem,
      rejectUnauthorized: true, servername: "", checkServerIdentity: (_name, cert) =>
        checkServerIdentity("127.0.0.1", cert) ?? (cert.fingerprint256 === fingerprint ? undefined : new Error("fixture TLS pin mismatch")),
    }, response => { response.resume(); response.on("end", () => resolve(response.statusCode!)); });
    request.on("error", reject); request.end();
  });
}

test("host local control uses a distinct private TLS identity and never reuses or sends the old capability", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir); assert.ok(state);
  assert.match(state.token, /^[a-f0-9]{64}$/);
  assert.notEqual(state.token, "legacy-fixture-capability");
  assert.equal(localSecret(f.dir), state.token);
  assert.equal(fs.readFileSync(path.join(f.dir, "local.secret"), "utf8"), "legacy-fixture-capability");
  if (posixModes) {
    assert.equal(fs.statSync(f.home).mode & 0o777, 0o700);
    for (const file of ["admin-tls-token", "admin-tls-identity.json", "admin-tls-endpoint.json"]) {
      assert.equal(fs.statSync(path.join(f.home, file)).mode & 0o777, 0o600);
    }
  }
  const response = await localControlRequest(f.dir, "/local/status");
  assert.equal(response.status, 200);
  const text = await response.text();
  assert.equal(text.includes(state.token), false);
  assert.equal(text.includes(state.identity.keyPem), false);
  assert.equal(f.publicRequests(), 0);
});

test("TLS local-control rejects duplicate authority, capability, origin and instance headers", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir)!;
  const normal = ["Host", `127.0.0.1:${state.endpoint.tlsPort}`, ADMIN_TOKEN_HEADER, state.token,
    "x-clauderipple-instance-id", state.endpoint.instanceId];
  assert.equal(await raw(f.dir, normal), 200);
  for (const extra of [["Host", `127.0.0.1:${state.endpoint.tlsPort}`],
    [ADMIN_TOKEN_HEADER, state.token], ["x-clauderipple-instance-id", state.endpoint.instanceId],
    ["Origin", "https://evil.example"], ["Sec-Fetch-Site", "cross-site"],
    ["Origin", "https://a.example", "origin", "https://b.example"]]) {
    assert.equal(await raw(f.dir, [...normal, ...extra]), 403, extra[0]);
  }
  assert.equal(await raw(f.dir, ["Host", `127.0.0.1:${state.endpoint.tlsPort}`, "x-ripple-local", "legacy-fixture-capability"]), 403);
});

test("unauthenticated TLS requests with an unsent body close immediately after rejection", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir)!;
  const fingerprint = new crypto.X509Certificate(state.identity.certPem).fingerprint256;
  const socket = connectTls({ host: "127.0.0.1", port: state.endpoint.tlsPort,
    ca: state.identity.caCertPem, rejectUnauthorized: true, servername: "",
    checkServerIdentity: (_name, cert) => checkServerIdentity("127.0.0.1", cert)
      ?? (cert.fingerprint256 === fingerprint ? undefined : new Error("fixture TLS pin mismatch")),
  });
  let received = "";
  socket.setEncoding("utf8"); socket.on("data", chunk => { received += chunk; });
  try {
    await once(socket, "secureConnect", { signal: AbortSignal.timeout(2_000) });
    const closed = once(socket, "close", { signal: AbortSignal.timeout(2_000) });
    socket.write(`POST /api/local/status HTTP/1.1\r\nHost: 127.0.0.1:${state.endpoint.tlsPort}\r\nContent-Length: 999999\r\nConnection: keep-alive\r\n\r\n`);
    await closed;
    assert.match(received, /^HTTP\/1\.1 403 /);
    assert.match(received, /\r\nconnection: close\r\n/i);
    assert.equal(socket.destroyed, true);
  } finally { socket.destroy(); }
});

test("local-control shutdown bounds even a raw TCP connection that never begins a TLS handshake", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir)!;
  const socket = net.connect({ host: "127.0.0.1", port: state.endpoint.tlsPort });
  try {
    await once(socket, "connect", { signal: AbortSignal.timeout(2_000) });
    const closed = once(socket, "close", { signal: AbortSignal.timeout(2_000) });
    const closing = f.local.close();
    await closed;
    await closing;
    assert.equal(socket.destroyed, true);
  } finally { socket.destroy(); }
});

test("a port-replacement server receives neither local capability nor request body before TLS rejection", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir)!;
  await f.local.close();
  // A crashed process can leave discovery behind. It remains a pin, never trust-on-first-use.
  writeAdminEndpoint(f.home, state.endpoint);
  const rogue = ensureAdminTlsIdentity(path.join(f.dir, "rogue"));
  let received = 0;
  const server = https.createServer({ cert: rogue.certPem, key: rogue.keyPem }, (_request, response) => { received++; response.end("untrusted"); });
  await new Promise<void>(resolve => server.listen(state.endpoint.tlsPort, "127.0.0.1", resolve));
  try {
    await assert.rejects(localControlRequest(f.dir, "/local/settings", { method: "POST", body: '{"private":"test-only"}' }), /TLS connection or identity verification failed/);
    assert.equal(await hostStatus(f.dir), null);
    await assert.rejects(controlShutdown(f.dir), /could not check the host/);
    assert.equal(received, 0);
    assert.equal(f.publicRequests(), 0);
  } finally {
    server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

test("missing, mismatched or permissive private discovery cannot fall back to the public HTTP listener", async t => {
  const f = await fixture(t);
  const endpoint = readAdminEndpoint(f.home)!;
  writeAdminEndpoint(f.home, { ...endpoint, publicPort: differentPublicPort(endpoint) });
  await assert.rejects(async () => localControlRequest(f.dir, "/local/status"), /mismatched/);
  writeAdminEndpoint(f.home, endpoint);
  if (posixModes) {
    fs.chmodSync(path.join(f.home, "admin-tls-endpoint.json"), 0o644);
    await assert.rejects(async () => localControlRequest(f.dir, "/local/status"), /owner-only/);
    fs.chmodSync(path.join(f.home, "admin-tls-endpoint.json"), 0o600);
  }
  fs.unlinkSync(path.join(f.home, "admin-tls-endpoint.json"));
  await assert.rejects(async () => localControlRequest(f.dir, "/local/status"), /private remote-host control is unavailable/);
  await assert.rejects(controlShutdown(f.dir), /stop the old host manually/);
  assert.equal(f.publicRequests(), 0);
});

test("host control path validation rejects destinations and traversal before opening a connection", async t => {
  const f = await fixture(t);
  for (const route of ["http://127.0.0.1/local/status", "//evil.example/local/status", "/local/../../api/config", "/local/%2e%2e/%2e%2e/config", "/local/status#fragment"]) {
    await assert.rejects(async () => localControlRequest(f.dir, route), /invalid|path/);
  }
  assert.equal(f.publicRequests(), 0);
});

test("failed local-control startup leaves the preceding authenticated discovery intact", async t => {
  const f = await fixture(t);
  const endpoint = readAdminEndpoint(f.home)!;
  const identityPath = path.join(f.home, "admin-tls-identity.json");
  const original = fs.readFileSync(identityPath);
  const competing = new LocalControl({ dir: f.dir, config: f.cfg, version: "new", hostPublicKey: "public", phones: () => [], rotate() {} });
  fs.writeFileSync(identityPath, '{"version":1,"invalid":true}', { mode: 0o600 });
  try { await assert.rejects(competing.listen(f.cfg.port), /invalid local admin TLS identity/); }
  finally { fs.writeFileSync(identityPath, original, { mode: 0o600 }); }
  await competing.close();
  assert.deepEqual(readAdminEndpoint(f.home), endpoint);
  assert.equal((await localControlRequest(f.dir, "/local/status")).status, 200);
});

test("shutdown never retargets a new instance published after the authenticated status response", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir)!;
  await f.local.close();
  // Prepare the fully owner-protected replacement before starting the network deadline.
  // A synchronous Windows ACL writer inside the handler would test PowerShell latency.
  const staged = path.join(f.home, "staged-next-endpoint.json");
  writePrivateFileAtomic(staged, JSON.stringify({ ...state.endpoint, instanceId: "c".repeat(32) }));
  const requests: string[] = [];
  const server = https.createServer({ cert: state.identity.certPem, key: state.identity.keyPem }, (request, response) => {
    requests.push(`${request.method} ${request.url}`);
    assert.equal(request.headers[ADMIN_TOKEN_HEADER], state.token);
    assert.equal(request.headers["x-clauderipple-instance-id"], state.endpoint.instanceId);
    fs.renameSync(staged, path.join(f.home, "admin-tls-endpoint.json"));
    response.setHeader("content-type", "application/json"); response.end('{"busy":false}');
  });
  await new Promise<void>(resolve => server.listen(state.endpoint.tlsPort, "127.0.0.1", resolve));
  try {
    await assert.rejects(controlShutdown(f.dir), /instance changed/);
    assert.deepEqual(requests, ["GET /api/local/status"]);
  } finally {
    server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve()));
  }
});

test("connection refusal from an old generation cannot confirm shutdown of a newly published instance", async t => {
  const f = await fixture(t);
  const state = readLocalControlState(f.dir)!;
  await f.local.close();
  const staged = path.join(f.home, "staged-next-endpoint.json");
  writePrivateFileAtomic(staged, JSON.stringify({ ...state.endpoint, instanceId: "d".repeat(32) }));
  const request = https.request;
  let dispatched = 0;
  const mocked = t.mock.method(https, "request", (...args: Parameters<typeof https.request>) => {
    const client = request(...args);
    // The original snapshot has already passed its complete ACL batch. Replace it before
    // the real loopback connection reports ECONNREFUSED, including on native Windows.
    dispatched++;
    fs.renameSync(staged, path.join(f.home, "admin-tls-endpoint.json"));
    return client;
  });
  try {
    await assert.rejects(controlShutdown(f.dir), /instance changed/);
    assert.equal(dispatched, 1);
  } finally { mocked.mock.restore(); }
});

test("an authenticated stop receipt survives a configured port change but rejects a newly published host", async t => {
  const f = await fixture(t);
  const endpoint = readAdminEndpoint(f.home)!;
  await f.local.close();
  const receipt = await controlShutdown(f.dir);
  const nextPort = differentPublicPort(endpoint);
  saveConfig({ ...f.cfg, port: nextPort }, f.dir);
  await assert.doesNotReject(() => receipt.assertStillStopped());
  assert.throws(() => readLocalControlState(f.dir), /mismatched/, "ordinary callers retain the config-port fence");
  writeAdminEndpoint(f.home, { ...endpoint, publicPort: nextPort, instanceId: "e".repeat(32) });
  await assert.rejects(() => receipt.assertStillStopped(), /instance changed/);
});
