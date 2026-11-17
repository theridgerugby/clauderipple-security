import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { once } from "node:events";
import { ADMIN_TOKEN_HEADER, adminAuthHeaders, fetchAdmin, localAdminBaseUrl } from "../src/admin-auth.ts";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";
import { writeAdminEndpoint } from "../../router/src/admin-transport-state.ts";
import { writePrivateFileAtomic } from "../../router/src/locked-file.ts";

test("main-process credentials are read privately, never created, and invalid files fail closed", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-app-auth-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "admin-tls-token");
  assert.deepEqual(adminAuthHeaders(home), {});
  assert.equal(fs.existsSync(file), false);
  fs.writeFileSync(path.join(home, "admin-token"), "a".repeat(64), { mode: 0o600 });
  assert.deepEqual(adminAuthHeaders(home), {}, "an older HTTP client's capability is never read");
  const token = "b".repeat(64);
  writePrivateFileAtomic(file, token + "\n");
  assert.deepEqual(adminAuthHeaders(home), { [ADMIN_TOKEN_HEADER]: token });
  fs.writeFileSync(file, "invalid");
  assert.throws(() => adminAuthHeaders(home), /invalid admin credential/);
  fs.writeFileSync(file, token + "\n".repeat(2));
  assert.throws(() => adminAuthHeaders(home), /invalid private admin state/);
  fs.writeFileSync(file, token);
  if (process.platform !== "win32") {
    fs.chmodSync(file, 0o644);
    assert.throws(() => adminAuthHeaders(home), /owner-only/);
    fs.chmodSync(file, 0o600);
    const linked = path.join(home, "linked");
    fs.linkSync(file, linked);
    assert.throws(() => adminAuthHeaders(home), /regular private file/);
    fs.unlinkSync(linked);
    fs.renameSync(file, linked);
    fs.symlinkSync(linked, file);
    assert.throws(() => adminAuthHeaders(home), /regular private file/);
  }
});

test("main-process API destination is a loopback origin with no credentials, path, query, or fragment", () => {
  assert.equal(localAdminBaseUrl("http://127.0.0.1:8791/").href, "http://127.0.0.1:8791/");
  for (const value of [
    "https://collector.example/", "https://127.0.0.1/", "http://localhost:8791/", "http://[::1]:8791/",
    "http://127.0.0.1.evil.example/", "http://127.0.0.1@collector.example/", "http://user@127.0.0.1/",
    "http://127.0.0.1/api/", "http://127.0.0.1/?query=1", "http://127.0.0.1/#fragment", "invalid",
  ]) assert.throws(() => localAdminBaseUrl(value));
});

test("status, power, and update requests authenticate locally and cannot follow a redirect", async t => {
  const received: { url?: string; method?: string; auth?: string | string[] }[] = [];
  const { home, token, base } = await adminTlsFixture(t, (req, res) => {
    received.push({ url: req.url, method: req.method, auth: req.headers[ADMIN_TOKEN_HEADER] });
    if (req.url === "/api/redirect") { res.writeHead(302, { location: "/api/collected" }).end(); return; }
    res.setHeader("content-type", "application/json");
    res.end('{"ok":true}');
  });
  for (const [pathname, method] of [["/api/status", "GET"], ["/api/power", "GET"], ["/api/power", "PUT"], ["/api/update", "POST"]]) {
    const response = await fetchAdmin(base, pathname!, home, { method, headers: { [ADMIN_TOKEN_HEADER]: "renderer-supplied-value" } });
    assert.equal(response.status, 200);
    assert.ok(!(await response.text()).includes(token));
    assert.equal(received.at(-1)?.auth, token);
    assert.equal(received.at(-1)?.url, pathname);
    assert.equal(received.at(-1)?.method, method);
  }
  await assert.rejects(fetchAdmin(base, "/api/redirect", home, { redirect: "follow" }));
  assert.equal(received.some(request => request.url === "/api/collected"), false);
  for (const pathname of ["https://collector.example/api/status", "//collector.example/api/status", "/api/../../private", "/private"]) {
    assert.throws(() => fetchAdmin(base, pathname, home), /invalid admin API path/);
  }
  const count = received.length;
  fs.unlinkSync(path.join(home, "admin-tls-token"));
  assert.throws(() => fetchAdmin(base, "/api/status", home, { headers: { [ADMIN_TOKEN_HEADER]: "caller-value" } }), /credential is unavailable/);
  assert.equal(received.length, count, "missing credentials fail before network I/O");
});

test("a process squatting on the public HTTP port receives no main-process request", async t => {
  let stolen = 0, accepted = 0;
  const f = await adminTlsFixture(t, (req, res) => { accepted++; assert.equal(req.headers[ADMIN_TOKEN_HEADER], f.token); res.end("ok"); });
  const imposter = http.createServer((_req, res) => { stolen++; res.end("stolen"); });
  imposter.listen(0, "127.0.0.1");
  await once(imposter, "listening");
  t.after(async () => { imposter.closeAllConnections(); await new Promise<void>(resolve => imposter.close(() => resolve())); });
  const address = imposter.address();
  assert.ok(address && typeof address === "object");
  writeAdminEndpoint(f.home, { ...f.endpoint, publicPort: address.port });
  const response = await fetchAdmin(`http://127.0.0.1:${address.port}/`, "/api/status", f.home);
  assert.equal(await response.text(), "ok");
  assert.equal(stolen, 0);
  assert.equal(accepted, 1);
});

test("main process rejects missing, malformed, permissive, aliased or mismatched discovery state", async t => {
  const f = await adminTlsFixture(t);
  const file = path.join(f.home, "admin-tls-endpoint.json");
  const saved = fs.readFileSync(file);
  fs.writeFileSync(file, JSON.stringify({ ...f.endpoint, publicPort: f.endpoint.publicPort + 1 }));
  assert.throws(() => fetchAdmin(f.base, "/api/status", f.home), /mismatched/);
  fs.writeFileSync(file, '{"privateKey":"DO-NOT-PRINT');
  assert.throws(() => fetchAdmin(f.base, "/api/status", f.home), error => error instanceof Error && !error.message.includes("DO-NOT-PRINT"));
  fs.writeFileSync(file, saved);
  if (process.platform !== "win32") {
    fs.chmodSync(file, 0o644);
    assert.throws(() => fetchAdmin(f.base, "/api/status", f.home), /owner-only/);
    fs.chmodSync(file, 0o600);
    const alias = file + ".alias";
    fs.renameSync(file, alias);
    fs.symlinkSync(alias, file);
    assert.throws(() => fetchAdmin(f.base, "/api/status", f.home), /regular private file/);
    fs.unlinkSync(file);
    fs.renameSync(alias, file);
  }
  fs.unlinkSync(file);
  assert.throws(() => fetchAdmin(f.base, "/api/status", f.home), /unavailable/);
});
