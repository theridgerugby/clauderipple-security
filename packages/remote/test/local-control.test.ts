import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import { checkServerIdentity } from "node:tls";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { fileURLToPath } from "node:url";
import { WebSocket } from "ws";
import { loadConfig, saveConfig } from "../src/config.ts";
import { LocalControl, isLoopback, localSecret } from "../src/local-control.ts";
import { ModInbox } from "../src/mod-inbox.ts";
import { SettingsJobs } from "../src/settings-jobs.ts";
import { HostServer } from "../src/server.ts";
import { ExpoNotifier } from "../src/expo-push.ts";
import { posixModes } from "../../../test/capabilities.ts";
import { localControlHome, localControlRequest, readLocalControlState } from "../src/local-transport.ts";
import { ADMIN_TOKEN_HEADER } from "../../router/src/admin-auth.ts";
import { peerFixtureUrl } from "./peer-fixture.ts";
import { ensurePhonePairingSecurity } from "../src/phone-auth-migration.ts";

async function rawControl(dir: string, route: string, headers: Record<string, string> = {}, method = "GET"): Promise<number> {
  const state = readLocalControlState(dir); assert.ok(state);
  return new Promise((resolve, reject) => {
    const request = https.request({ host: "127.0.0.1", port: state.endpoint.tlsPort, path: `/api/local/${route}`, method,
      ca: state.identity.caCertPem, rejectUnauthorized: true, servername: "", agent: false,
      checkServerIdentity: (_name, cert) => checkServerIdentity("127.0.0.1", cert), headers: {
        [ADMIN_TOKEN_HEADER]: state.token, "x-clauderipple-instance-id": state.endpoint.instanceId, ...headers,
      } }, response => { response.resume(); response.on("end", () => resolve(response.statusCode!)); });
    request.on("error", reject); request.end();
  });
}

async function fixture(t: import("node:test").TestContext, relay?: string, listen = "127.0.0.1", mod?: import("../src/local-control.ts").ModHost) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-local-"));
  const cfg = loadConfig(dir);
  if (relay) cfg.relay = relay;
  saveConfig(cfg, dir);
  const pairing = ensurePhonePairingSecurity(dir);
  cfg.token = pairing.token; cfg.pairingSecurityVersion = pairing.pairingSecurityVersion;
  const logs: string[] = [];
  const push = new ExpoNotifier({ dir, send: async () => "sent", seenRecently: () => false, log: line => logs.push(line) });
  push.subscribe("offline-phone", "ExpoPushToken[offline]", "en");
  let host: HostServer;
  const outcomes: string[] = [];
  const inbox = new ModInbox(() => true, (_offer, outcome) => outcomes.push(outcome));
  const settingsJobs = new SettingsJobs();
  t.after(() => { inbox.close(); settingsJobs.close(); });
  const local = new LocalControl({ dir, config: cfg, version: "test", hostPublicKey: "public-key", inbox, settingsJobs, phones: () => host.phones(), rotate: token => host.rotateToken(token), ...(mod ? { mod } : {}) });
  host = new HostServer({
    listen, port: 0, token: cfg.token, webDir: fileURLToPath(new URL("../web", import.meta.url)),
    sessions: { list: () => [], groups: () => undefined, pollDesktop: async () => {}, pollQueued: () => {}, tailUnwatched: () => {}, watchAttached: () => {} } as never,
    router: { status: async () => ({ ok: true, proxyEnv: {} }), models: async () => [] },
    hostName: "test", version: "test", recentCli: async () => [], log: line => logs.push(line), local,
    pushDevices: () => push.devices(), clearPush: () => { for (const id of push.devices()) push.unsubscribe(id); },
  });
  await host.listen();
  saveConfig(cfg, dir);
  t.after(async () => { await host.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const secret = localSecret(dir);
  const base = `http://127.0.0.1:${host.address().port}`;
  const call = (route: string, body?: unknown) => localControlRequest(dir, `/local/${route}`, body === undefined ? {} : { method: "POST", body: JSON.stringify(body) });
  return { dir, cfg, host, local, logs, push, call, base, secret, inbox, outcomes, settingsJobs };
}

async function hello(t: import("node:test").TestContext, host: HostServer, token: string, id = "online-phone") {
  const ws = new WebSocket(await peerFixtureUrl(t, host));
  ws.on("error", () => {});
  t.after(() => ws.terminate());
  await once(ws, "open");
  const message = once(ws, "message");
  ws.send(JSON.stringify({ t: "hello", token, clientId: id }));
  const [frame] = await message;
  return { ws, frame: JSON.parse(String(frame)) as { t: string } };
}

test("refresh is authenticated, refuses a busy host and only requests self-exit after idle reservation", async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-refresh-"));
  const cfg = loadConfig(dir); saveConfig(cfg, dir);
  let busy = true, reservations = 0, exits = 0;
  const local = new LocalControl({ dir, config: cfg, version: "old", hostPublicKey: "public", phones: () => [], rotate() {},
    prepareRefresh: () => { reservations++; return !busy; }, refresh: () => { exits++; } });
  await local.listen(cfg.port);
  t.after(async () => { await local.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  assert.equal(await rawControl(dir, "refresh", { [ADMIN_TOKEN_HEADER]: "wrong" }, "POST"), 403);
  assert.equal(reservations, 0);
  const refresh = () => localControlRequest(dir, "/local/refresh", { method: "POST" });
  assert.equal((await refresh()).status, 409); assert.equal(exits, 0);
  busy = false;
  assert.equal((await refresh()).status, 200); assert.equal(exits, 1);
});

test("local control requires authenticated TLS, loopback, and the new persistent private capability", async t => {
  const f = await fixture(t);
  assert.equal(localSecret(f.dir), f.secret);
  assert.equal(fs.existsSync(path.join(f.dir, "local.secret")), false);
  if (posixModes) assert.equal(fs.statSync(path.join(localControlHome(f.dir), "admin-tls-token")).mode & 0o777, 0o600);
  for (const address of ["127.0.0.1", "127.0.0.2", "::1", "::ffff:127.0.0.1"]) assert.equal(isLoopback(address), true);
  for (const address of [undefined, "10.0.0.1", "100.64.0.1", "::ffff:192.168.1.2"]) assert.equal(isLoopback(address), false);
  for (const headers of [{}, { "x-ripple-local": "wrong" }, { "x-forwarded-for": "127.0.0.1" }]) {
    assert.equal((await fetch(`${f.base}/local/status`, { headers })).status, 410);
  }
  assert.equal(await rawControl(f.dir, "status", { [ADMIN_TOKEN_HEADER]: "wrong" }), 403);
  assert.equal(await rawControl(f.dir, "status", { "x-clauderipple-instance-id": "b".repeat(32) }), 403);
  assert.equal(await rawControl(f.dir, "status", { origin: "https://evil.example" }), 403);
  assert.equal(await rawControl(f.dir, "status", { host: "evil.example" }), 403);
  assert.equal((await f.call("status")).status, 200);
  // A plaintext socket never becomes authenticated TLS through forwarded headers.
  const lan = http.createServer((req, res) => {
    Object.defineProperty(req.socket, "remoteAddress", { value: "192.168.1.23" });
    void f.local.handle(req, res);
  });
  await new Promise<void>(resolve => lan.listen(0, "127.0.0.1", resolve));
  t.after(() => new Promise<void>(resolve => lan.close(() => resolve())));
  const address = lan.address();
  assert.ok(address && typeof address !== "string");
  assert.equal((await fetch(`http://127.0.0.1:${address.port}/local/pairing`, { headers: { "x-ripple-local": f.secret, "x-forwarded-for": "127.0.0.1" } })).status, 403);
});

test("a specific interface bind adds only local control on IPv4 loopback", async t => {
  const f = await fixture(t, undefined, "::1");
  assert.equal((await f.call("status")).status, 200);
  assert.equal((await fetch(`${f.base}/healthz`)).status, 404);
  assert.equal((await fetch(`http://[::1]:${f.host.address().port}/healthz`)).status, 200);
  assert.equal((await fetch(`${f.base}/local/status`)).status, 410);
});

test("retired plaintext local-control routes close an unsent request body without exposing credentials", async t => {
  const f = await fixture(t);
  const socket = net.connect({ host: "127.0.0.1", port: f.host.address().port });
  let received = "";
  socket.setEncoding("utf8"); socket.on("data", chunk => { received += chunk; });
  try {
    await once(socket, "connect", { signal: AbortSignal.timeout(2_000) });
    const closed = once(socket, "close", { signal: AbortSignal.timeout(2_000) });
    socket.write(`POST /local/status HTTP/1.1\r\nHost: 127.0.0.1:${f.host.address().port}\r\nContent-Length: 999999\r\nConnection: keep-alive\r\n\r\n`);
    await closed;
    assert.match(received, /^HTTP\/1\.1 410 /);
    assert.match(received, /\r\nconnection: close\r\n/i);
    assert.equal(received.includes(f.secret), false);
    assert.equal(received.includes(f.cfg.token), false);
  } finally { socket.destroy(); }
});

test("pairing refuses plaintext direct mode and returns only secure relay URLs without credential logs", async t => {
  for (const relay of [undefined, "https://relay.example"]) {
    const f = await fixture(t, relay);
    const response = await f.call("pairing");
    assert.equal(response.headers.get("cache-control"), "no-store");
    if (!relay) {
      assert.equal(response.status, 409);
      const text = await response.text();
      assert.equal(text.includes(f.cfg.token), false);
      assert.equal(text.includes("#pair="), false);
      const status = await (await f.call("status")).json() as { mode: string; pushReady: boolean; reachableFromPhone: boolean };
      assert.equal(status.mode, "local-only");
      assert.equal(status.pushReady, false);
      assert.equal(status.reachableFromPhone, false);
      continue;
    }
    assert.equal(response.status, 200);
    const pairing = await response.json() as { url: string; svg: string };
    const url = new URL(pairing.url);
    assert.equal(url.origin, relay);
    assert.equal(new URLSearchParams(url.hash.slice(1)).get("pair"), f.cfg.token);
    if (relay) assert.equal(new URLSearchParams(url.hash.slice(1)).get("hpk"), "public-key");
    assert.match(pairing.svg, /^<svg\s/);
    assert.match(pairing.svg, /<path/);
    assert.equal(f.logs.join("\n").includes(f.cfg.token), false);
    assert.equal(f.logs.join("\n").includes(pairing.url), false);
    const status = await (await f.call("status")).json() as { mode: string; pushReady: boolean };
    assert.equal(status.mode, relay ? "relay" : "local-only");
    assert.equal(status.pushReady, !!relay);
    assert.equal(JSON.stringify(status).includes(f.cfg.token), false);
  }
});

test("rotate immediately drops authenticated sockets, clears push, and refuses the old token", async t => {
  const f = await fixture(t, "https://relay.example");
  const old = f.cfg.token;
  const online = await hello(t, f.host, old);
  assert.equal(online.frame.t, "ready");
  const status = await (await f.call("status")).json() as { phones: { clientId: string; connected: boolean; push: boolean }[] };
  assert.deepEqual(status.phones.map(p => [p.clientId, p.connected, p.push]), [["offline-phone", false, true], ["online-phone", true, false]]);
  const closed = once(online.ws, "close");
  assert.deepEqual(await (await f.call("rotate", {})).json(), { ok: true });
  await closed;
  assert.notEqual(loadConfig(f.dir, false).token, old);
  assert.deepEqual(f.push.devices(), []);
  assert.deepEqual(new ExpoNotifier({ dir: f.dir, send: async () => "sent", seenRecently: () => false, log: () => {} }).devices(), []);
  assert.equal((await hello(t, f.host, old)).frame.t, "denied");
  assert.equal((await hello(t, f.host, loadConfig(f.dir, false).token)).frame.t, "ready");
  const pairing = await (await f.call("pairing")).json() as { url: string };
  assert.equal(new URLSearchParams(new URL(pairing.url).hash.slice(1)).get("pair"), f.cfg.token);
});

test("a legacy unrotated host refuses even a relay pairing URL", async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-pairing-legacy-"));
  const cfg = loadConfig(dir); cfg.relay = "https://relay.example"; saveConfig(cfg, dir);
  const local = new LocalControl({ dir, config: cfg, version: "test", hostPublicKey: "public", phones: () => [], rotate() {} });
  await local.listen(cfg.port);
  t.after(async () => { await local.close(); fs.rmSync(dir, { recursive: true, force: true }); });
  const response = await localControlRequest(dir, "/local/pairing");
  assert.equal(response.status, 409);
  assert.equal((await response.text()).includes(cfg.token), false);
});

test("inbox routes authenticate, validate and enforce first-wins without logging text", async t => {
  const f = await fixture(t);
  const offered = f.inbox.offer({ sessionId: "cli-1", itemId: "item-1", text: "private inbox text", offeredAt: 123 }, 1000);
  assert.equal((await fetch(`${f.base}/local/inbox?session=cli-1`)).status, 410);
  assert.equal((await f.call("inbox")).status, 400);
  assert.deepEqual(await (await f.call("inbox?session=other")).json(), { offers: [] });
  assert.deepEqual(await (await f.call("inbox?session=cli-1")).json(), { offers: [{ sessionId: "cli-1", itemId: "item-1", text: "private inbox text", offeredAt: 123 }] });
  for (const bad of [null, [], {}, { itemId: "bad id" }, { itemId: "item-1", extra: true }]) assert.equal((await f.call("inbox/claim", bad)).status, 400);
  assert.equal((await f.call("inbox/result", { itemId: "item-1", outcome: "other" })).status, 400);
  assert.equal((await f.call("inbox/result", { itemId: "item-1", outcome: "submitted" })).status, 409);
  assert.deepEqual(await (await f.call("inbox/claim", { itemId: "item-1" })).json(), { ok: true });
  assert.equal(await offered, "claimed");
  assert.equal((await f.call("inbox/claim", { itemId: "item-1" })).status, 409);
  assert.equal((await f.call("inbox/result", { itemId: "item-1", outcome: "submitted" })).status, 200);
  assert.deepEqual(f.outcomes, ["submitted"]);
  assert.equal((await f.call("inbox/result", { itemId: "item-1", outcome: "submitted" })).status, 409);
  assert.equal((await localControlRequest(f.dir, "/local/inbox/claim", { method: "POST", body: "x".repeat(4097) })).status, 400);
  assert.equal(f.logs.join("\n").includes("private inbox text"), false);
});

test("the mod poll's send time reaches the host as a number, and a malformed one is refused before it does", async t => {
  const polls: unknown[][] = [];
  const mod = {
    modApprovalStart: async () => ({ state: "hold" as const }),
    modApprovalPoll: async (askId: string, waitMs?: number, sentAt?: number) => { polls.push([askId, waitMs, sentAt]); return { state: "pending" }; },
    modApprovalDone: () => ({}),
    reportMoved: () => true,
  };
  const f = await fixture(t, undefined, "127.0.0.1", mod);
  const poll = (query: string) => localControlRequest(f.dir, `/local/mod/approval?${query}`);
  assert.deepEqual(await (await poll("askId=ask-1&sentAt=1700000000000")).json(), { state: "pending" });
  assert.equal((await poll("askId=ask-1")).status, 200, "a mod that sends no send time is answered as before");
  for (const bad of ["sentAt=", "sentAt=-5", "sentAt=1.5", "sentAt=soon", "sentAt=1&sentAt=2", `sentAt=${"9".repeat(16)}`]) {
    assert.equal((await poll(`askId=ask-1&${bad}`)).status, 400, bad);
  }
  assert.deepEqual(polls, [["ask-1", undefined, 1700000000000], ["ask-1", undefined, undefined]]);
});

test("mod routes authenticate and validate, hand approvals and move reports to the host, and refuse what the host did not expect", async t => {
  const calls: unknown[][] = [];
  const mod = {
    modApprovalStart: async (req: unknown) => { calls.push(["start", req]); return { state: "hold" as const }; },
    modApprovalPoll: async (askId: string) => { calls.push(["poll", askId]); return { state: "pending" }; },
    modApprovalDone: (askId: string) => { calls.push(["done", askId]); return {}; },
    reportMoved: (itemId: string, from: string, to: string) => { calls.push(["moved", itemId, from, to]); return itemId === "claimed"; },
  };
  const f = await fixture(t, undefined, "127.0.0.1", mod);
  assert.equal((await fetch(`${f.base}/local/mod/approval`, { method: "POST", body: "{}" })).status, 410, "plaintext local control has been removed");
  const valid = { askId: "ask-1", session: "cli-1", tool: "Bash", input: { command: "ls" }, suggestions: [], title: "" };
  assert.deepEqual(await (await f.call("mod/approval", valid)).json(), { state: "hold" });
  for (const bad of [{ ...valid, askId: "bad id" }, { ...valid, input: [] }, { ...valid, session: "" }, { ...valid, tool: "" }, { ...valid, suggestions: "x" }, { ...valid, title: 7 }, null, []]) {
    assert.equal((await f.call("mod/approval", bad)).status, 400, JSON.stringify(bad));
  }
  assert.equal((await f.call("mod/approval", { ...valid, input: { command: "x".repeat(600 * 1024) } })).status, 400, "a request over the cap is refused, never started");
  assert.deepEqual(await (await f.call("mod/approval/poll")).status, 404, "an unknown mod route is not answered");
  assert.deepEqual(await (await f.call("mod/approval?askId=ask-1")).json(), { state: "pending" });
  assert.equal((await f.call("mod/approval?askId=bad%20id")).status, 400);
  assert.equal((await f.call("mod/approval?askId=a&askId=b")).status, 400);
  assert.equal((await f.call("mod/approval/done", { askId: "ask-1" })).status, 200);
  assert.equal((await f.call("mod/approval/done", {})).status, 400);
  assert.equal((await f.call("mod/moved", { itemId: "claimed", from: "cli-1", to: "cli-2" })).status, 200);
  assert.equal((await f.call("mod/moved", { itemId: "other", from: "cli-1", to: "cli-2" })).status, 409, "a move for an offer not claimed is refused");
  assert.equal((await f.call("mod/moved", { itemId: "claimed", from: "cli-1" })).status, 400);
  assert.deepEqual(calls.map(call => call[0]), ["start", "poll", "done", "moved", "moved"]);
  assert.deepEqual(calls[3], ["moved", "claimed", "cli-1", "cli-2"]);
});

test("the approval done route hands a phone answer back to the hook, and says nothing else", async t => {
  const mod = {
    modApprovalStart: async () => ({ state: "hold" as const }),
    modApprovalPoll: async () => ({ state: "pending" }),
    modApprovalDone: (askId: string) => askId === "answered-1" ? { answer: { behavior: "allow" as const } } : {},
    reportMoved: () => false,
  };
  const f = await fixture(t, undefined, "127.0.0.1", mod);
  assert.deepEqual(await (await f.call("mod/approval/done", { askId: "answered-1" })).json(), { ok: true, state: "answered", answer: { behavior: "allow" } });
  assert.deepEqual(await (await f.call("mod/approval/done", { askId: "other-1" })).json(), { ok: true });
});

test("settings job routes authenticate, validate and enforce one helper", async t => {
  const f = await fixture(t);
  f.settingsJobs.request({ jobId: "job-1", appSessionId: "local_target", cliSessionId: "cli-1", model: "private-model", createdAt: 1 });
  assert.equal((await fetch(`${f.base}/local/settings-jobs?exclude=local_helper`)).status, 410);
  for (const query of ["", "?exclude=bad%20id", "?exclude=a&exclude=b"]) assert.equal((await f.call(`settings-jobs${query}`)).status, 400);
  assert.deepEqual(await (await f.call("settings-jobs?exclude=local_target")).json(), { jobs: [] });
  assert.equal(((await (await f.call("settings-jobs?exclude=local_helper")).json()) as { jobs: unknown[] }).jobs.length, 1);
  for (const bad of [null, [], {}, { jobId: "bad id", helper: "a" }, { jobId: "job-1", helper: "a", extra: 1 }]) assert.equal((await f.call("settings-jobs/claim", bad)).status, 400);
  for (const bad of [{ jobId: "job-1", outcome: "other" }, { jobId: "job-1", outcome: "failed", detail: "x".repeat(1001) }]) assert.equal((await f.call("settings-jobs/result", bad)).status, 400);
  assert.equal((await f.call("settings-jobs/claim", { jobId: "job-1", helper: "local_target" })).status, 409);
  assert.equal((await f.call("settings-jobs/result", { jobId: "job-1", outcome: "applied" })).status, 409);
  assert.equal((await f.call("settings-jobs/claim", { jobId: "job-1", helper: "local_helper" })).status, 200);
  assert.equal((await f.call("settings-jobs/claim", { jobId: "job-1", helper: "local_helper" })).status, 409);
  assert.equal((await f.call("settings-jobs/result", { jobId: "job-1", outcome: "failed", detail: "refused" })).status, 200);
  assert.deepEqual(f.settingsJobs.status("local_target"), { jobId: "job-1", outcome: "failed", detail: "refused" });
  assert.equal((await localControlRequest(f.dir, "/local/settings-jobs/claim", { method: "POST", body: "x".repeat(4097) })).status, 400);
  assert.equal(f.logs.join("\n").includes("private-model"), false);
});

test("settings validates before saving, preserves secrets and distinguishes running from pending config", async t => {
  const f = await fixture(t);
  const original = fs.readFileSync(path.join(f.dir, "host.json"), "utf8");
  for (const bad of [null, [], { bind: "0.0.0.0" }, { bind: "127.0.0.1" }, { relay: "http://remote.example" }, { relay: false }, { token: "injected" }]) {
    assert.equal((await f.call("settings", bad)).status, 400);
    assert.equal(fs.readFileSync(path.join(f.dir, "host.json"), "utf8"), original);
  }
  assert.deepEqual(await (await f.call("settings", { relay: "https://relay.example", bind: "local" })).json(), { restartRequired: true });
  const saved = loadConfig(f.dir, false);
  assert.equal(saved.relay, "https://relay.example");
  assert.equal(saved.token, f.cfg.token);
  assert.equal(saved.relaySecret, f.cfg.relaySecret);
  const pending = await (await f.call("status")).json() as { mode: string; restartRequired: boolean; settings: { relay: string } };
  assert.equal(pending.mode, "local-only");
  assert.equal(pending.restartRequired, true);
  // No busy callback (an embedder that never runs turns) reads as idle, never as missing.
  assert.equal((pending as { busy?: unknown }).busy, false);
  assert.equal(pending.settings.relay, saved.relay);
  assert.deepEqual(await (await f.call("settings", { relay: "off", bind: "local" })).json(), { restartRequired: false });
  assert.equal(loadConfig(f.dir, false).relay, undefined);
});
