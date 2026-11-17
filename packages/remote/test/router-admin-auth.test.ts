import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ensureAdminToken, ADMIN_TOKEN_HEADER } from "../../router/src/admin-auth.ts";
import { RouterClient, type Fetch } from "../src/router.ts";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";

test("the injected Remote transport receives ordinary request data without loading a capability", async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-remote-auth-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const token = ensureAdminToken(home);
  const calls: { url: string; init: Parameters<Fetch>[1] }[] = [];
  const mock: Fetch = async (url, init) => {
    calls.push({ url, init });
    return { ok: true, status: 200, json: async () => ({ settings: { effortAuto: true }, revision: 1 }) };
  };
  const client = new RouterClient("http://127.0.0.1:8792", mock, home);
  await client.modSettings();
  assert.equal(await client.setEffortAuto(true), true);
  assert.ok(calls.some(call => call.init?.method === "PUT"));
  for (const call of calls) {
    assert.equal(call.init?.headers?.[ADMIN_TOKEN_HEADER], undefined);
    assert.equal(call.init?.redirect, "error");
    assert.equal(call.url.includes(token), false);
  }
});

test("a rejected Remote-to-router response closes a stalled authenticated peer promptly", async t => {
  let peerClosed!: () => void;
  const closed = new Promise<void>(resolve => { peerClosed = resolve; });
  const f = await adminTlsFixture(t, (req, res) => {
    req.socket.once("close", peerClosed);
    res.writeHead(503, { "content-type": "application/json" });
    res.write("{"); // Deliberately leave the body unfinished after refusing the request.
  });
  const client = new RouterClient(f.base, undefined, f.home);
  await assert.rejects(client.modSettings(), /HTTP 503/);
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([closed, new Promise<never>((_resolve, reject) => {
      timer = setTimeout(() => reject(new Error("rejected response kept its socket open")), 1000);
    })]);
  } finally { if (timer) clearTimeout(timer); }
});
test("remote admin override cannot send a local capability to a foreign server", () => {
  for (const url of ["https://example.com", "http://127.0.0.1.example.com:8792", "http://127.0.0.1:8792@evil.example", "http://127.0.0.1:8792/base", "http://127.0.0.1:8792/?key=x", "http://localhost:8792", "http://127.0.0.1:8792/#x"])
    assert.throws(() => new RouterClient(url), /literal loopback HTTP origin/);
});

test("the real Remote host reads and writes only over the installation's pinned TLS", async t => {
  const calls: { method: string | undefined; token: string | string[] | undefined }[] = [];
  const f = await adminTlsFixture(t, (req, res) => {
    calls.push({ method: req.method, token: req.headers[ADMIN_TOKEN_HEADER] });
    res.end('{"settings":{"effortAuto":true},"revision":1}');
  });
  const client = new RouterClient(f.base, undefined, f.home);
  assert.deepEqual(await client.modSettings(), { settings: { effortAuto: true }, revision: 1 });
  assert.equal(await client.setEffortAuto(true), true);
  assert.ok(calls.some(call => call.method === "PUT"));
  assert.ok(calls.every(call => call.token === f.token));
  fs.unlinkSync(path.join(f.home, "admin-tls-endpoint.json"));
  await assert.rejects(client.modSettings(), /private admin transport state/);
  assert.equal(calls.length, 3, "no HTTP fallback when protected TLS state is unavailable");
});
