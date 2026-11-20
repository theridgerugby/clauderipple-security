import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { fileURLToPath } from "node:url";
import { HostServer } from "../src/server.ts";
import type { ServerOptions } from "../src/server.ts";
import { LocalControl } from "../src/local-control.ts";
import { localControlHome, localControlRequest } from "../src/local-transport.ts";
import { loadConfig, saveConfig } from "../src/config.ts";
import { ensurePhonePairingSecurity } from "../src/phone-auth-migration.ts";
import { readAdminEndpoint } from "../../router/src/admin-transport-state.ts";

function temp(t: import("node:test").TestContext): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-owned-start-"));
  t.after(() => fs.rmSync(dir, { force: true, recursive: true }));
  return dir;
}

function options(): ServerOptions {
  return {
    listen: "127.0.0.1", port: 0, token: "legacy-fixture-token-01234567890123456789",
    webDir: fileURLToPath(new URL("../web", import.meta.url)),
    sessions: { list: () => [], groups: () => undefined, pollDesktop: async () => {}, pollQueued() {}, tailUnwatched() {}, watchAttached() {} } as never,
    router: { models: async () => [], status: async () => ({ ok: true, proxyEnv: {} }) },
    hostName: "test", version: "test", recentCli: async () => [],
  };
}

async function listen(server: http.Server, port = 0): Promise<number> {
  await new Promise<void>((resolve, reject) => { server.once("error", reject); server.listen(port, "127.0.0.1", resolve); });
  const address = server.address();
  assert.ok(address && typeof address !== "string");
  return address.port;
}

test("an occupied public port prevents pairing migration and private control publication", async t => {
  const dir = temp(t);
  const cfg = loadConfig(dir);
  const before = fs.readFileSync(path.join(dir, "host.json"));
  const occupied = http.createServer();
  const port = await listen(occupied);
  t.after(() => new Promise<void>(resolve => occupied.close(() => resolve())));
  let migrations = 0;
  let controls = 0;
  const host = new HostServer({ ...options(), port,
    beforeLocalControl: () => { migrations++; ensurePhonePairingSecurity(dir); },
    local: { listen: async () => { controls++; }, close: async () => {} },
  });
  t.after(() => host.close());
  await assert.rejects(host.listen(), { code: "EADDRINUSE" });
  assert.equal(migrations, 0);
  assert.equal(controls, 0);
  assert.deepEqual(fs.readFileSync(path.join(dir, "host.json")), before);
  assert.equal(loadConfig(dir, false).token, cfg.token);
  assert.equal(readAdminEndpoint(localControlHome(dir)), undefined);
});

test("owned startup migrates once before TLS control and refreshes its pairing snapshot", async t => {
  const dir = temp(t);
  const cfg = loadConfig(dir);
  cfg.relay = "https://relay.example";
  saveConfig(cfg, dir);
  const oldToken = cfg.token;
  const order: string[] = [];
  const local = new LocalControl({ dir, config: cfg, version: "test", hostPublicKey: "A".repeat(43), phones: () => [], rotate() {} });
  const host = new HostServer({ ...options(), token: cfg.token,
    beforeLocalControl: () => {
      order.push("migrate");
      assert.equal(readAdminEndpoint(localControlHome(dir)), undefined);
      assert.ok(host.address().port > 0);
      const migrated = ensurePhonePairingSecurity(dir);
      Object.assign(cfg, { token: migrated.token, pairingSecurityVersion: migrated.pairingSecurityVersion });
      host.rotateToken(cfg.token);
    },
    local: { listen: async port => { order.push("tls"); await local.listen(port); }, close: () => local.close() },
  });
  t.after(() => host.close());
  await host.listen();
  // The actual start callback is single-shot even if a caller mistakenly calls listen again.
  await assert.rejects(host.listen(), { code: "ERR_SERVER_ALREADY_LISTEN" });
  assert.deepEqual(order, ["migrate", "tls"]);
  assert.notEqual(cfg.token, oldToken);
  cfg.port = host.address().port;
  saveConfig(cfg, dir);
  const reply = await localControlRequest(dir, "/local/pairing");
  assert.equal(reply.status, 200, "TLS control sees the post-migration marker rather than its constructor snapshot");
  const body = await reply.json() as { url: string };
  assert.equal(new URLSearchParams(new URL(body.url).hash.slice(1)).get("pair"), cfg.token);
});

test("migration failure closes the owned listener and never publishes TLS control", async t => {
  let port = 0;
  let controls = 0;
  const host = new HostServer({ ...options(), beforeLocalControl: () => {
    port = host.address().port;
    throw new Error("fixture migration persistence failed");
  }, local: { listen: async () => { controls++; }, close: async () => {} } });
  t.after(() => host.close());
  await assert.rejects(host.listen(), /migration persistence failed/);
  assert.equal(controls, 0);
  assert.ok(port > 0);
  const replacement = http.createServer();
  await listen(replacement, port);
  t.after(() => new Promise<void>(resolve => replacement.close(() => resolve())));
});
