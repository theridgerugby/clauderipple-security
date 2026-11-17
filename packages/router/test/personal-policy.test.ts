import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import http from "node:http";
import tls from "node:tls";
import os from "node:os";
import path from "node:path";
import { approvedOrigin, assertApprovedDestination, configurePersonalEgressPolicy, PersonalPolicyError, personalFallbacks, personalPolicyProblems, type PersonalSecurityPolicy } from "../src/personal-policy.ts";
import { ConfigStore, normalizeConfig, validate, type Config } from "../src/config.ts";
import { egressFetch } from "../src/egress.ts";
import { writeSecretJsonAtomic } from "../src/locked-file.ts";
import { Logger } from "../src/log.ts";
import { RequestLog, type RequestRecord } from "../src/requestlog.ts";
import { Proxy } from "../src/proxy.ts";
import { CertStore } from "../src/certs.ts";
import { UpstreamHealth } from "../src/health.ts";

const policy = (...approvedOrigins: string[]): PersonalSecurityPolicy => ({ mode: "personal", approvedOrigins });
function temp(t: import("node:test").TestContext): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-policy-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

test("production normalization starts with zero approved destinations and cannot select a permissive mode", () => {
  assert.deepEqual(normalizeConfig({}).security, policy());
  assert.ok(personalPolicyProblems({ mode: "off", approvedOrigins: [] }).length);
  assert.ok(personalPolicyProblems({ mode: "personal", approvedOrigins: ["https://api.example.test/path"] }).length);
  assert.ok(personalPolicyProblems(policy("https://api.example.test", "https://api.example.test")).length);
});

test("approval parsing rejects ambiguous paths, query secrets, userinfo, wildcards and insecure origins", () => {
  assert.equal(approvedOrigin("https://API.example.test:443/"), "https://api.example.test");
  for (const value of ["http://api.example.test", "https://user:secret@api.example.test", "https://api.example.test/?key=secret", "https://api.example.test/#anything", "https://api.example.test/path", "https://*.example.test", "https://api.example.test\\other", " https://api.example.test"]) {
    assert.equal(approvedOrigin(value), null, value);
  }
});

test("a blocked request never reaches a transport, even with synthetic credentials and research body", async t => {
  configurePersonalEgressPolicy(() => policy("https://api.allowed.test"));
  t.after(() => configurePersonalEgressPolicy(undefined));
  let calls = 0;
  const transport = async () => { calls++; return Response.json({ ok: true }); };
  for (const url of ["https://other.test/v1", "https://api.allowed.test:444/v1", "http://api.allowed.test/v1", "https://api.allowed.test.attacker.test/v1", "https://user:pass@api.allowed.test/v1"]) {
    await assert.rejects(egressFetch(url, { method: "POST", headers: { authorization: "Bearer SYNTHETIC-KEY" }, body: "SYNTHETIC-UNPUBLISHED-RESEARCH" }, transport));
  }
  assert.equal(calls, 0);
});

test("exact approval permits normal traffic, revocation and unavailable configuration block the next attempt", async t => {
  let active: PersonalSecurityPolicy | undefined = policy("https://api.allowed.test");
  configurePersonalEgressPolicy(() => active);
  t.after(() => configurePersonalEgressPolicy(undefined));
  let calls = 0;
  const transport = async (url: string, init: RequestInit) => {
    calls++;
    assert.equal(url, "https://api.allowed.test/v1/chat/completions");
    assert.equal(init.redirect, "manual");
    assert.equal(init.body, "SYNTHETIC-CONTENT");
    return Response.json({ answer: "fixture answer" });
  };
  assert.equal((await egressFetch("https://api.allowed.test/v1/chat/completions", { method: "POST", body: "SYNTHETIC-CONTENT" }, transport)).status, 200);
  active = policy();
  await assert.rejects(egressFetch("https://api.allowed.test/v1", {}, transport), PersonalPolicyError);
  active = undefined;
  await assert.rejects(egressFetch("https://api.allowed.test/v1", {}, transport), PersonalPolicyError);
  assert.equal(calls, 1);
});

test("approved destinations still reject redirects and never trust a credential-bearing URL", async t => {
  const p = policy("https://one.test", "https://two.test");
  configurePersonalEgressPolicy(() => p);
  t.after(() => configurePersonalEgressPolicy(undefined));
  let calls = 0;
  await assert.rejects(egressFetch("https://one.test/v1", {}, async () => {
    calls++;
    return new Response(null, { status: 307, headers: { location: "https://two.test/receive" } });
  }), /redirect refused/i);
  assert.equal(calls, 1);
  assert.throws(() => assertApprovedDestination("https://name:secret@one.test", p), PersonalPolicyError);
});

test("missing or malformed configuration removes an already active destination grant", t => {
  const home = temp(t), file = path.join(home, "config.json");
  const valid = normalizeConfig({ security: policy("https://api.allowed.test") });
  writeSecretJsonAtomic(file, valid);
  const store = new ConfigStore(file);
  assert.deepEqual(store.get().security, valid.security);
  fs.unlinkSync(file);
  assert.deepEqual(store.get().security, policy(), "deleting a config cannot retain an old grant");
  writeSecretJsonAtomic(file, valid);
  assert.deepEqual(store.get().security, valid.security);
  writeSecretJsonAtomic(file, { ...valid, security: { mode: "off", approvedOrigins: ["https://api.allowed.test"] } });
  assert.deepEqual(store.get().security, policy(), "invalid mode cannot retain or activate grants");
});

test("personal mode disables high-risk integration features and credential cross-origin reassignment", () => {
  const cases: Partial<Config>[] = [
    { autoUpdate: true }, { listen: { host: "0.0.0.0", port: 8790 } },
    { upstream: "claude-lookalike.test" }, { remote: { hosts: [{ host: "other-host", port: 8790 }] } },
    { providers: { x: { type: "chatgpt", debugDump: "all" } } },
    { providers: { x: { type: "chatgpt", url: "https://other.test/backend-api" } } },
    { providers: { x: { type: "grok" } } },
    { providers: { x: { type: "google", auth: "antigravity" } } },
    { providers: { x: { type: "openai-compatible", url: "https://school.example/v1", models: [{ id: "model", url: "https://other.test/v1" }] } } },
  ];
  for (const change of cases) assert.ok(validate(normalizeConfig(change)).length > 0, JSON.stringify(change));
  assert.deepEqual(validate(normalizeConfig({ providers: {
    school: { type: "openai-compatible", url: "https://school.example/v1", models: [{ id: "model", url: "https://school.example/another-path" }] },
    google: { type: "google", auth: "api-key" }, claude: { type: "anthropic", auth: "claude-code" },
  } })), []);
});

test("fallbacks stay on the initially selected provider", () => {
  const candidates = [{ provider: "school", model: "alternate" }, { provider: "public", model: "same-name" }];
  assert.deepEqual(personalFallbacks({ security: policy() }, { provider: "school" }, candidates), [candidates[0]]);
});

test("personal CONNECT and absolute forwarding reject unapproved origins before TLS/TCP dispatch", t => {
  const home = temp(t);
  const cfg = normalizeConfig({ security: policy("https://api.anthropic.com", "https://opaque.example.test") });
  const proxy = new Proxy({ config: () => cfg, home, certs: new CertStore(home), health: new UpstreamHealth(() => 100, () => {}), log: new Logger(null, 1e6, 1, false, true), requests: new RequestLog(path.join(home, "requests.jsonl"), 10, 4096, true) });
  t.after(() => proxy.close());
  const internal = proxy as unknown as { onConnect: (socket: net.Socket) => void; terminate: () => void; tunnel: () => void };
  const terminate = t.mock.method(internal, "terminate", () => {});
  const tunnel = t.mock.method(internal, "tunnel", () => {});
  const rawTcp = t.mock.method(net, "connect", () => { throw new Error("must never dial"); });
  for (const request of ["CONNECT other.test:443 HTTP/1.1", "CONNECT api.anthropic.com:444 HTTP/1.1", "CONNECT opaque.example.test:443 HTTP/1.1", "GET http://api.anthropic.com/path HTTP/1.1", "GET https://api.anthropic.com/path HTTP/1.1", "GET https://other.test/path HTTP/1.1"]) {
    const socket = new net.Socket();
    const replies: string[] = [];
    t.mock.method(socket, "write", (data: string) => { replies.push(data); return true; });
    t.mock.method(socket, "end", (data: string) => { replies.push(data); return socket; });
    internal.onConnect(socket);
    socket.emit("data", Buffer.from(`${request}\r\nHost: other.test\r\n\r\n`));
    assert.match(replies.join(""), /^HTTP\/1\.1 403 Forbidden/);
    socket.destroy();
  }
  assert.equal(terminate.mock.callCount(), 0);
  assert.equal(tunnel.mock.callCount(), 0);
  assert.equal(rawTcp.mock.callCount(), 0);
});

test("personal diagnostics and usage stay in bounded memory without creating files or echoing content", t => {
  const home = temp(t), file = path.join(home, "requests.jsonl");
  const stdout = t.mock.method(process.stdout, "write", () => true);
  const log = new Logger(path.join(home, "router.log"), 1024, 1, true, true);
  log.warn("SYNTHETIC-RESEARCH echoed by a fixture provider error");
  assert.match(log.memoryTail(1)!, /SYNTHETIC-RESEARCH/);
  assert.equal(stdout.mock.callCount(), 0);
  stdout.mock.restore();
  const requests = new RequestLog(file, 2, 1024, true);
  for (let i = 0; i < 3; i++) requests.add({ id: String(i), at: new Date(1000 + i).toISOString(), ms: 5, status: 200, ok: true, kind: "messages", source: "fixture", target: "fixture", provider: "school", stream: false, note: "SYNTHETIC-RESEARCH" } satisfies RequestRecord);
  assert.equal(requests.list(10).length, 2);
  assert.equal(requests.usage(1000, 1003).total.count, 2);
  assert.equal(new RequestLog(file, 2, 1024, true).list(10).length, 0, "new process has no retained history");
  assert.deepEqual(fs.readdirSync(home), [], "no requests, hourly history, diagnostic file, or debug dump was written");
  log.close();
});

test("an inner WebSocket Host cannot bypass the approved CONNECT authority", t => {
  const home = temp(t);
  const cfg = normalizeConfig({ security: policy("https://api.anthropic.com") });
  const proxy = new Proxy({ config: () => cfg, home, certs: new CertStore(home), health: new UpstreamHealth(() => 100, () => {}), log: new Logger(null, 1e6, 1, false, true), requests: new RequestLog(path.join(home, "requests.jsonl"), 10, 4096, true) });
  t.after(() => proxy.close());
  const connect = t.mock.method(tls, "connect", () => { throw new Error("unapproved TLS dispatch"); });
  const socket = new net.Socket(), req = new http.IncomingMessage(socket);
  req.headers = { host: "unapproved.example.test", authorization: "Bearer SYNTHETIC-KEY" };
  req.rawHeaders = ["Host", "unapproved.example.test", "Authorization", "Bearer SYNTHETIC-KEY"];
  const replies: string[] = [];
  t.mock.method(socket, "end", (data: string) => { replies.push(data); return socket; });
  (proxy as unknown as { upgrade: (req: http.IncomingMessage, socket: net.Socket, head: Buffer) => void }).upgrade(req, socket, Buffer.from("SYNTHETIC-RESEARCH"));
  assert.match(replies.join(""), /^HTTP\/1\.1 426/);
  assert.equal(connect.mock.callCount(), 0);
  socket.destroy();
});

test("an inner HTTP Host cannot reassign caller credentials, including bodyless requests and another approved origin", async t => {
  const home = temp(t);
  const cfg = normalizeConfig({ security: policy("https://api.anthropic.com", "https://school.example.test") });
  const proxy = new Proxy({ config: () => cfg, home, certs: new CertStore(home), health: new UpstreamHealth(() => 100, () => {}), log: new Logger(null, 1e6, 1, false, true), requests: new RequestLog(path.join(home, "requests.jsonl"), 10, 4096, true) });
  t.after(() => proxy.close());
  const internals = proxy as unknown as { terminatedAuthorities: WeakMap<net.Socket, string>; handle: (req: http.IncomingMessage, res: http.ServerResponse) => Promise<void> };
  for (const target of ["unapproved.test", "school.example.test", "api.anthropic.com:444"]) {
    const socket = new net.Socket(), req = new http.IncomingMessage(socket), res = new http.ServerResponse(req);
    internals.terminatedAuthorities.set(socket, "https://api.anthropic.com");
    req.method = "GET";
    req.url = "/data?research=SYNTHETIC-CONTENT";
    req.headers = { host: target, "x-custom-secret": "SYNTHETIC-KEY" };
    req.rawHeaders = ["Host", target, "x-custom-secret", "SYNTHETIC-KEY"];
    await internals.handle(req, res);
    assert.equal(res.statusCode, 421);
    assert.equal(res.writableEnded, true);
    assert.equal(proxy.stats.started, 0, "refusal precedes dispatch and request processing");
    socket.destroy();
  }
});
