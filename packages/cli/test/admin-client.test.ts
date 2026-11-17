// Temporary, authenticated native TLS fixtures only. No provider, browser or supervisor is run.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { promisify } from "node:util";
import { ADMIN_TOKEN_HEADER, ensureAdminToken } from "../../router/src/admin-auth.ts";
import { writeAdminEndpoint } from "../../router/src/admin-transport-state.ts";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";
import { adminFetch, adminRequestSync, localAdminBase, localAdminUrl, openAdminDashboard } from "../src/admin-client.ts";
import { adminBridgePath } from "../src/admin-runtime.ts";
import { fetchRouterStatus } from "../src/doctor.ts";
import { adminPowerCall } from "../src/power.ts";
import { remoteHosts } from "../src/remote.ts";

function emptyHome(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-cli-auth-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}
async function listener(t: TestContext, handler: http.RequestListener) {
  const server = http.createServer(handler);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  t.after(() => { server.closeAllConnections(); server.close(); });
  return { server, port: (server.address() as { port: number }).port };
}

test("admin discovery accepts literal loopback API URLs, including API query data", () => {
  for (const url of ["http://127.0.0.1:8792/api/status", "http://[::1]:8792/api/power", "http://127.0.0.1:8792/api/requests?session=test"]) assert.equal(localAdminUrl(url).href, url);
  for (const url of [
    "https://127.0.0.1:8792/api/status", "http://localhost:8792/api/status",
    "http://example.test/api/status", "http://127.0.0.1.example.test/api/status",
    "http://127.1:8792/api/status", "http://2130706433:8792/api/status",
    "http://user:pass@127.0.0.1/api/status", "http://127.0.0.1/api/status#secret",
    "http://127.0.0.1/assets/ui.js", "http://127.0.0.1/api/../other", "file:///api/status",
    "http://127.0.0.1/api/nested/../status", "http://127.0.0.1/api/nested/%2e%2e/status", "http://127.0.0.1/api/sta\ttus",
  ]) assert.throws(() => localAdminUrl(url), url);
  assert.equal(localAdminBase("http://127.0.0.1:8792/"), "http://127.0.0.1:8792");
  assert.throws(() => localAdminBase("http://127.0.0.1:8792/other"));
  assert.throws(() => localAdminBase("http://127.0.0.1:8792/?query=1"));
});

test("async requests use the supplied private TLS identity and preserve only ordinary headers", async (t) => {
  const received: { path: string; headers: http.IncomingHttpHeaders; method: string; body: string }[] = [];
  const fixture = await adminTlsFixture(t, (req, res) => {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => { received.push({ path: req.url!, headers: req.headers, method: req.method!, body }); res.end('{"ok":true}'); });
  });
  await (await adminFetch(fixture.base + "api/image?fixture=1", {
    method: "POST", headers: { "content-type": "application/json", [ADMIN_TOKEN_HEADER]: "wrong", host: "evil.test" },
    body: '{"prompt":"test"}', redirect: "follow",
  }, fixture.home)).text();
  assert.equal(received.length, 1);
  assert.equal(received[0]!.path, "/api/image?fixture=1");
  assert.equal(received[0]!.headers[ADMIN_TOKEN_HEADER], fixture.token);
  assert.equal(received[0]!.headers["content-type"], "application/json");
  assert.equal(received[0]!.headers.host, `127.0.0.1:${fixture.endpoint.tlsPort}`);
  assert.equal(received[0]!.body, '{"prompt":"test"}');
  assert.throws(() => adminFetch("https://outside.test/api/status", {}, fixture.home));
  assert.equal(received.length, 1);
});

test("missing TLS state fails closed and never probes an occupied plaintext admin port", async (t) => {
  const home = emptyHome(t);
  let received = 0;
  const plain = await listener(t, (_req, res) => { received++; res.end('{"version":"imposter"}'); });
  fs.writeFileSync(path.join(home, "admin-token"), "a".repeat(64), { mode: 0o600 });
  assert.throws(() => adminFetch(`http://127.0.0.1:${plain.port}/api/status`, { headers: { [ADMIN_TOKEN_HEADER]: "wrong" } }, home), /Secure admin state/);
  assert.equal(received, 0);
  assert.equal(fs.existsSync(path.join(home, "admin-tls-token")), false, "a diagnostic read does not create credentials");
});

test("a mismatched public port or a squatting TLS server receives no capability", async (t) => {
  let genuine = 0, impostor = 0;
  const fixture = await adminTlsFixture(t, (_req, res) => { genuine++; res.end("ok"); });
  const other = await adminTlsFixture(t, (_req, res) => { impostor++; res.end("unexpected"); });
  const wrongPort = fixture.endpoint.publicPort === 8792 ? 8793 : 8792;
  assert.throws(() => adminFetch(`http://127.0.0.1:${wrongPort}/api/status`, {}, fixture.home), /different configured port/);
  writeAdminEndpoint(fixture.home, { ...fixture.endpoint, tlsPort: other.endpoint.tlsPort });
  await assert.rejects(adminFetch(fixture.base + "api/status", {}, fixture.home), /identity verification/);
  assert.equal(genuine, 0);
  assert.equal(impostor, 0, "TLS rejection occurs before HTTP headers reach the wrong server");
});

test("an authenticated TLS redirect cannot forward credentials to a plaintext listener", async (t) => {
  let forwarded = 0;
  const target = await listener(t, (_req, res) => { forwarded++; res.end("unexpected"); });
  const source = await adminTlsFixture(t, (_req, res) => {
    res.writeHead(307, { location: `http://127.0.0.1:${target.port}/api/status` }); res.end();
  });
  await assert.rejects(adminFetch(source.base + "api/status", { redirect: "follow" }, source.home), /redirects are forbidden/);
  assert.equal(forwarded, 0);
});

test("synchronous probes send a fixed helper and request stdin, never a token", (t) => {
  const home = emptyHome(t), token = ensureAdminToken(home);
  let calls = 0;
  const result = adminRequestSync("http://127.0.0.1:8792/api/shutdown", home, {
    method: "POST", timeoutMs: 10_000, headers: { "x-clauderipple-install-id": "install-1", [ADMIN_TOKEN_HEADER]: token },
    run: (file, args, opts) => {
      calls++;
      assert.equal(path.isAbsolute(file), true);
      assert.deepEqual(args, [adminBridgePath()]);
      assert.equal(JSON.stringify({ args, input: opts.input }).includes(token), false);
      assert.deepEqual(opts.stdio, ["pipe", "pipe", "ignore"]);
      assert.equal(opts.env.CLAUDERIPPLE_HOME, home);
      assert.equal(opts.timeout, 11_000);
      const request = JSON.parse(opts.input);
      assert.equal(request.headers[ADMIN_TOKEN_HEADER], undefined);
      assert.equal(request.headers["x-clauderipple-install-id"], "install-1");
      assert.equal(request.method, "POST");
      return Buffer.from('{"ok":true,"status":200,"text":"{\\"ok\\":true}"}');
    },
  });
  assert.equal(result, '{"ok":true}');
  assert.equal(calls, 1);
  assert.equal(adminRequestSync("http://outside.test/api/status", home, { run: () => { throw new Error("external request must not run"); } }), null);
  assert.equal(adminRequestSync("http://127.0.0.1:8792/api/status", home, { run: () => { throw new Error("failed " + token); } }), null);
});

test("the real synchronous status helper authenticates the explicit home over TLS", async (t) => {
  const received: string[] = [];
  const fixture = await adminTlsFixture(t, (req, res) => { received.push(String(req.headers[ADMIN_TOKEN_HEADER] ?? "")); res.end('{"version":"test-auth","pid":42}'); });
  const moduleUrl = new URL("../src/router-state.ts", import.meta.url).href;
  const script = "import { probeStatus } from " + JSON.stringify(moduleUrl) +
    "; const [url, home] = process.argv.slice(1); process.stdout.write(JSON.stringify(probeStatus(url, 3000, home)));";
  const result = await promisify(execFile)(process.execPath, ["--input-type=module", "-e", script, fixture.base + "api/status", fixture.home], {
    timeout: 10_000, env: { ...process.env, CLAUDERIPPLE_HOME: path.join(fixture.home, "wrong-home") },
  });
  assert.deepEqual(JSON.parse(result.stdout), { version: "test-auth", pid: 42 });
  assert.deepEqual(received, [fixture.token]);
  assert.equal(result.stderr.includes(fixture.token), false);
});

test("doctor and power use their explicit installation home through native TLS", async (t) => {
  const calls: { pathname: string; headers: http.IncomingHttpHeaders; method: string }[] = [];
  const fixture = await adminTlsFixture(t, (req, res) => {
    calls.push({ pathname: req.url!, headers: req.headers, method: req.method! }); req.resume(); res.end('{"version":"test-auth","ok":true}');
  });
  // Match doctor's production budget. This assertion covers explicit-home routing and
  // authentication; dedicated transport tests retain their cancellation/deadline coverage.
  assert.deepEqual(await fetchRouterStatus(fixture.base.slice(0, -1), 4000, fixture.home), { version: "test-auth", runtimeVerified: false });
  assert.equal((await adminPowerCall(fixture.endpoint.publicPort, fixture.home)("PUT", { awake: { mode: "off" } }))?.status, 200);
  assert.deepEqual(calls.map(c => c.pathname), ["/api/status", "/api/power"]);
  for (const call of calls) assert.equal(call.headers[ADMIN_TOKEN_HEADER], fixture.token);
  assert.equal(calls[1]!.headers["content-type"], "application/json");
  assert.equal(calls[1]!.method, "PUT");
});

test("remote management uses the config file home, with no external admin override", async (t) => {
  let calls = 0;
  const received: string[] = [];
  const fixture = await adminTlsFixture(t, (req, res) => { calls++; received.push(String(req.headers[ADMIN_TOKEN_HEADER])); res.end('{"hosts":[]}'); });
  const configFile = path.join(fixture.home, "config.json");
  fs.writeFileSync(configFile, JSON.stringify({ remote: { hosts: [{ host: "me@box", port: 8791 }] } }));
  const assets = emptyHome(t), printed: string[] = [];
  await remoteHosts({ configFile, home: assets, adminUrl: fixture.base, print: s => printed.push(s) });
  assert.equal(calls, 1); assert.deepEqual(received, [fixture.token]);
  await remoteHosts({ configFile, home: assets, adminUrl: "https://outside.test", print: s => printed.push(s) });
  assert.equal(calls, 1);
  assert.equal(printed.join("\n").includes(fixture.token), false);
});

test("dashboard opens only native UI with a home and fixed view, never a capability URL", async (t) => {
  const home = emptyHome(t), token = ensureAdminToken(home), printed: string[] = [];
  for (const success of [true, false]) {
    assert.equal(await openAdminDashboard("http://127.0.0.1:8792/", home, {
      view: "mod", open: async (actualHome, view) => { assert.equal(actualHome, home); assert.equal(view, "mod"); return { ok: success, message: "Native UI fixture" }; },
      print: s => printed.push(s),
    }), success);
  }
  assert.equal(await openAdminDashboard("http://127.0.0.1:8792/", home, { open: async () => { throw new Error("failure " + token); }, print: s => printed.push(s) }), false);
  for (const line of printed) { assert.equal(line.includes(token), false); assert.doesNotMatch(line, /#admin-token=|https?:\/\//); }
  await assert.rejects(openAdminDashboard("http://outside.test/", home));
});

test("CLI image uses pinned TLS and keeps its credential out of output", async (t) => {
  const received: { token: string; pathname: string; body: string }[] = [];
  const fixture = await adminTlsFixture(t, (req, res) => {
    let body = ""; req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      received.push({ token: String(req.headers[ADMIN_TOKEN_HEADER] ?? ""), pathname: req.url ?? "", body });
      res.setHeader("content-type", "image/png"); res.end(Buffer.from([137, 80, 78, 71]));
    });
  });
  fs.writeFileSync(path.join(fixture.home, "config.json"), JSON.stringify({ admin: { port: fixture.endpoint.publicPort } }));
  const output = path.join(fixture.home, "fixture.png");
  const result = await promisify(execFile)(process.execPath, [path.resolve(import.meta.dirname, "../src/index.ts"), "image", "test prompt", "-o", output], {
    timeout: 10_000, env: { ...process.env, CLAUDERIPPLE_HOME: fixture.home },
  });
  assert.equal(received.length, 1); assert.equal(received[0]!.token, fixture.token);
  assert.equal(received[0]!.pathname, "/api/image"); assert.equal(JSON.parse(received[0]!.body).prompt, "test prompt");
  assert.deepEqual(fs.readFileSync(output), Buffer.from([137, 80, 78, 71]));
  assert.equal(result.stdout.trim(), output); assert.equal((result.stdout + result.stderr).includes(fixture.token), false);
});
