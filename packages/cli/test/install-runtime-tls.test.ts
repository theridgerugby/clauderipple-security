// Real loopback TLS/control traffic; all process restarts and model requests remain inert.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";
import { ADMIN_INSTANCE_HEADER, ADMIN_TOKEN_HEADER } from "../../router/src/admin-auth.ts";
import { adminFetch } from "../src/admin-client.ts";
import { captureRouterCodeIdentity, verifyAndApplyInstall, type InstallRuntimeTarget } from "../src/install-runtime.ts";
import { runtime } from "../src/runtime.ts";
import { fetchRouterStatus } from "../src/doctor.ts";
import { VERSION } from "../../router/src/version.ts";
import { ensureInstallationId } from "../../router/src/installation-id.ts";
import { writeSecretJsonAtomic } from "../../router/src/locked-file.ts";

const codeIdentity = Object.freeze({ schema: 1 as const, sha256: "b".repeat(64) });
function target(): InstallRuntimeTarget {
  const rt = runtime();
  return { version: "0.12.36", node: rt.node, router: rt.router, codeIdentity,
    listen: { host: "127.0.0.1", port: 8790 }, upstream: "api.anthropic.com" };
}

test("install refuses a working-looking legacy plaintext endpoint without sending it credentials", async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-install-legacy-"));
  const server = http.createServer((_req, res) => { received++; res.end('{"version":"0.12.36","pid":42}'); });
  let received = 0;
  t.after(async () => {
    server.closeAllConnections();
    await new Promise<void>(resolve => server.close(() => resolve()));
    fs.rmSync(home, { recursive: true, force: true });
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const port = (server.address() as { port: number }).port;
  await assert.rejects(verifyAndApplyInstall({
    started: "already-running", target: target(),
    deps: {
      status: async signal => (await adminFetch(`http://127.0.0.1:${port}/api/status`, { signal }, home)).json(),
      installationId: () => "a".repeat(32), captureIdentity: () => codeIdentity,
      restart: () => assert.fail("unverified old processes must not be restarted"),
    },
    probe: () => assert.fail("a good proxy response cannot rescue the missing identity"),
    apply: () => assert.fail("Claude settings must remain untouched"),
  }), /Secure router identity is unavailable/);
  assert.equal(received, 0);
  assert.equal(fs.existsSync(path.join(home, "admin-tls-token")), false);
});

test("same-version live-code verification and final settings gate use pinned authenticated TLS", async t => {
  const expected = target();
  const makeStatus = () => ({ version: expected.version, installId: "a".repeat(32), pid: 42,
    listen: expected.listen, upstream: expected.upstream,
    runtime: { node: expected.node, router: expected.router, startedAt: "2026-11-17T00:00:00.000Z", codeIdentity: { schema: 1, sha256: "a".repeat(64) } } });
  let current = makeStatus(), received = 0, restarted = 0, probed = 0, applied = 0;
  let token = "", instanceId = "";
  const fixture = await adminTlsFixture(t, (req, res) => {
    if (!token || req.headers[ADMIN_TOKEN_HEADER] !== token || req.headers[ADMIN_INSTANCE_HEADER] !== instanceId || req.url !== "/api/status") {
      res.writeHead(403, { connection: "close" }); res.end(); return;
    }
    received++; res.setHeader("content-type", "application/json"); res.end(JSON.stringify(current));
  });
  token = fixture.token; instanceId = fixture.endpoint.instanceId;
  const options = {
    started: "already-running" as const, target: expected,
    deps: {
      status: async (signal: AbortSignal) => (await adminFetch(fixture.base + "api/status", { signal }, fixture.home)).json(),
      installationId: () => "a".repeat(32), captureIdentity: () => codeIdentity,
      restart: () => { restarted++; current = { ...makeStatus(), pid: 43,
        runtime: { ...makeStatus().runtime, codeIdentity, startedAt: "2026-11-17T00:00:01.000Z" } }; return "drained" as const; },
    },
    probe: async () => { probed++; return { ok: true, detail: "no external model call", ms: 0 }; },
    apply: () => { applied++; },
  };
  await verifyAndApplyInstall(options);
  assert.deepEqual({ received, restarted, probed, applied }, { received: 3, restarted: 1, probed: 1, applied: 1 });

  // A legitimate replacement during the proxy check is still a changed installation attempt.
  options.probe = async () => { probed++; current = { ...current, pid: 44 }; return { ok: true, detail: "replacement fixture", ms: 0 }; };
  await assert.rejects(verifyAndApplyInstall(options), /instance changed/);
  assert.equal(applied, 1);
  assert.equal(restarted, 1);
});

test("recovery computes live-code proof over TLS and rejects a server-supplied verified flag", async t => {
  const rt = runtime(), captured = captureRouterCodeIdentity(rt);
  let status: Record<string, unknown>, received = 0;
  const fixture = await adminTlsFixture(t, (req, res) => {
    assert.equal(req.headers[ADMIN_TOKEN_HEADER], fixture.token);
    assert.equal(req.headers[ADMIN_INSTANCE_HEADER], fixture.endpoint.instanceId);
    received++; req.resume(); res.setHeader("content-type", "application/json"); res.end(JSON.stringify(status));
  });
  const listen = { host: "127.0.0.1", port: 18790 }, upstream = "api.anthropic.com";
  writeSecretJsonAtomic(path.join(fixture.home, "config.json"), { listen, upstream, admin: { port: fixture.endpoint.publicPort } });
  const installId = ensureInstallationId(fixture.home);
  const originalRuntime = { node: rt.node, router: rt.router, codeIdentity: captured, startedAt: "2026-11-17T00:00:00.000Z" };
  status = { version: VERSION, installId, pid: process.pid, listen, upstream, runtime: originalRuntime, runtimeVerified: true };
  assert.deepEqual(await fetchRouterStatus(fixture.base.slice(0, -1), 4000, fixture.home), { version: VERSION, runtimeVerified: true });
  status.runtime = { ...originalRuntime, codeIdentity: { schema: 1, sha256: "0".repeat(64) } };
  assert.deepEqual(await fetchRouterStatus(fixture.base.slice(0, -1), 4000, fixture.home), { version: VERSION, runtimeVerified: false });
  delete status.runtime;
  assert.deepEqual(await fetchRouterStatus(fixture.base.slice(0, -1), 4000, fixture.home), { version: VERSION, runtimeVerified: false });
  assert.equal(received, 3);
});
