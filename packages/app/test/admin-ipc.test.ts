import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { EventEmitter } from "node:events";
import type http from "node:http";
import type { IpcMainInvokeEvent, WebContents } from "electron";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { ADMIN_TOKEN_HEADER, fetchAdmin } from "../src/admin-auth.ts";
import { ADMIN_IPC_CHANNEL, ADMIN_IPC_CONCURRENCY, ADMIN_IPC_REQUEST_LIMIT, ADMIN_IPC_RESPONSE_LIMIT, ADMIN_IPC_TIMEOUT_MS, createAdminRequestHandler, type AdminIpcResponse } from "../src/admin-ipc.ts";
import { ORIGIN, watchPrivilegedWindow } from "../src/security.ts";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";

const frame = { processId: 7, routingId: 11, origin: ORIGIN, url: `${ORIGIN}/`, frames: [] };
const owner = Object.assign(new EventEmitter(), { id: 17, mainFrame: frame }) as unknown as WebContents;
watchPrivilegedWindow(owner);
const event = { sender: owner, senderFrame: frame } as unknown as IpcMainInvokeEvent;
const text = (response: AdminIpcResponse): string => Buffer.from(response.body).toString();
function fixture(transport: typeof fetchAdmin) {
  return createAdminRequestHandler({ ownedContents: () => owner, admin: () => "http://127.0.0.1:1/", home: "/unused-ipc-home", transport });
}

test("production IPC uses pinned TLS and preserves API path, method, string body and representation headers", async t => {
  let received: { method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string } | undefined;
  const f = await adminTlsFixture(t, async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    received = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() };
    res.writeHead(201, { "content-type": "application/json", "cache-control": "no-store", "x-hidden-fixture": "must-not-cross" });
    res.end('{"approved":true}');
  });
  const handle = createAdminRequestHandler({ ownedContents: () => owner, admin: () => f.base, home: f.home });
  const response = await handle(event, { path: "/api/picker?enabled=1", method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, body: '{"on":true}' });
  assert.equal(response.status, 201);
  assert.deepEqual(JSON.parse(text(response)), { approved: true });
  assert.deepEqual(response.headers, { "content-type": "application/json", "cache-control": "no-store" });
  assert.equal(received?.method, "POST");
  assert.equal(received?.url, "/api/picker?enabled=1");
  assert.equal(received?.body, '{"on":true}');
  assert.equal(received?.headers.origin, undefined);
  assert.equal(received?.headers.host, `127.0.0.1:${f.endpoint.tlsPort}`);
  assert.equal(received?.headers[ADMIN_TOKEN_HEADER], f.token);
  assert.ok(!JSON.stringify(response).includes(f.token));
});

test("untrusted IPC frames are refused before payload inspection, endpoint lookup or transport", async () => {
  let calls = 0;
  const handle = createAdminRequestHandler({ ownedContents: () => owner,
    admin: () => { calls++; throw new Error("must not read configuration"); }, home: "/unused",
    transport: () => { calls++; throw new Error("must not send"); } });
  const payload = { get path(): never { throw new Error("payload must not be read"); } };
  for (const invalid of [
    { ...event, sender: { id: 18 } }, { ...event, senderFrame: null },
    { ...event, senderFrame: { ...frame, routingId: 12 } }, { ...event, senderFrame: { ...frame, processId: 8 } },
    { ...event, senderFrame: { ...frame, origin: "null" } },
    { ...event, senderFrame: { ...frame, url: "ripple://app/app.js" } },
    { ...event, senderFrame: { ...frame, origin: "https://untrusted.example", url: "https://untrusted.example/" } },
  ]) assert.equal((await handle(invalid as IpcMainInvokeEvent, payload)).status, 403);
  assert.equal(calls, 0);
});

test("borrowed parent IPC fails after child creation, detach and reload until a new window is owned", async () => {
  const make = () => Object.assign(new EventEmitter(), { id: 30, mainFrame: { ...frame, frames: [] as object[] } });
  let contents = make();
  watchPrivilegedWindow(contents as unknown as WebContents);
  const caller = () => ({ sender: contents, senderFrame: contents.mainFrame }) as unknown as IpcMainInvokeEvent;
  let calls = 0;
  const handle = createAdminRequestHandler({ ownedContents: () => contents as unknown as WebContents,
    admin: () => "http://127.0.0.1:1/", home: "/unused",
    transport: async () => { calls++; return new Response(null, { status: 204 }); } });
  assert.equal((await handle(caller(), { path: "/api/status" })).status, 204);
  const child = { ...frame, routingId: 99, parent: contents.mainFrame };
  contents.mainFrame.frames.push(child);
  contents.emit("frame-created", {}, { frame: child });
  // A borrowed parent bridge is attributed to the parent. The window-level latch still denies it.
  assert.equal((await handle(caller(), { path: "/api/status" })).status, 403);
  contents.mainFrame.frames.length = 0;
  assert.equal((await handle(caller(), { path: "/api/status" })).status, 403);
  contents.mainFrame = { ...frame, routingId: 100, frames: [] };
  watchPrivilegedWindow(contents as unknown as WebContents);
  assert.equal((await handle(caller(), { path: "/api/status" })).status, 403);
  assert.equal(calls, 1);
  contents = make();
  watchPrivilegedWindow(contents as unknown as WebContents);
  assert.equal((await handle(caller(), { path: "/api/status" })).status, 204);
  assert.equal(calls, 2);
});

test("live child presence fails closed even before a frame-created event and remains sticky", async () => {
  const contents = Object.assign(new EventEmitter(), { id: 31, mainFrame: { ...frame, frames: [] as object[] } });
  const owned = contents as unknown as WebContents;
  watchPrivilegedWindow(owned);
  let calls = 0;
  const handle = createAdminRequestHandler({ ownedContents: () => owned, admin: () => "http://127.0.0.1:1/", home: "/unused",
    transport: async () => { calls++; return new Response(null, { status: 204 }); } });
  const parent = { sender: owned, senderFrame: owned.mainFrame } as IpcMainInvokeEvent;
  contents.mainFrame.frames.push({ routingId: 44 });
  assert.equal((await handle(parent, { path: "/api/status" })).status, 403);
  contents.mainFrame.frames.length = 0;
  assert.equal((await handle(parent, { path: "/api/status" })).status, 403);
  assert.equal(calls, 0);
});

test("a window tainted while an authorized response is pending receives no response body", async () => {
  const contents = Object.assign(new EventEmitter(), { id: 32, mainFrame: { ...frame, frames: [] } });
  const owned = contents as unknown as WebContents;
  watchPrivilegedWindow(owned);
  let resolve!: (response: Response) => void;
  const handle = createAdminRequestHandler({ ownedContents: () => owned, admin: () => "http://127.0.0.1:1/", home: "/unused",
    transport: () => new Promise(done => { resolve = done; }) });
  const pending = handle({ sender: owned, senderFrame: owned.mainFrame } as IpcMainInvokeEvent, { path: "/api/status" });
  contents.emit("frame-created", {}, { frame: { ...frame, routingId: 33, parent: contents.mainFrame } });
  resolve(new Response("must not return private API data"));
  const response = await pending;
  assert.equal(response.status, 403);
  assert.ok(!text(response).includes("private API data"));
});

test("malformed IPC fields, URLs, methods, credentials and framing headers never reach transport", async () => {
  let calls = 0;
  const handle = fixture(() => { calls++; throw new Error("must not send"); });
  const base = { path: "/api/status" };
  const values: unknown[] = [null, [], "request", {}, new URL("https://example.com"),
    { ...base, unknown: true }, { ...base, signal: {} }, { ...base, credentials: "include" },
    { ...base, headers: [] }, { ...base, body: "" }, { ...base, method: "HEAD", body: "" },
    { ...base, method: "POST", body: {} }, { ...base, method: "POST", body: null },
    { ...base, method: "POST", body: new Uint8Array() }, { ...base, method: "TRACE" },
    { ...base, method: "OPTIONS" }, { ...base, method: 1 }, { ...base, method: " GET" },
    { ...base, headers: { accept: "x", Accept: "y" } },
    { ...base, headers: { accept: "x", "content-type": "y", extra: "z" } },
    { ...base, headers: { accept: "a".repeat(1025) } },
    { ...base, headers: { accept: "text/plain\r\nx-evil: yes" } },
    { ...base, headers: { accept: 42 } },
    { ...base, get body(): never { throw new Error("accessor must not execute"); } },
    { ...base, [Symbol("hidden")]: "x" },
  ];
  for (const path of ["/api", "/readyz", "api/status", "//untrusted.example/api/status", "https://untrusted.example/api/status", "/api/../private", "/api/%2e%2e/private", "/api/status#secret", "/api/evil\\path", "/api/status\n", "/api/" + "x".repeat(16_384)]) values.push({ path });
  for (const name of ["authorization", ADMIN_TOKEN_HEADER, "x-clauderipple-instance-id", "host", "origin", "cookie", "content-length", "transfer-encoding", "x-clauderipple-install-id"])
    values.push({ ...base, headers: { [name]: "forged" } });
  for (const value of values) assert.equal((await handle(event, value)).status, 400);
  assert.equal(calls, 0);
});

test("valid current and future API routes retain methods without granting an arbitrary URL proxy", async () => {
  const requests: { path: string; method?: string; body?: unknown }[] = [];
  const handle = fixture(async (_base, path, _home, init) => {
    requests.push({ path, method: init?.method, body: init?.body });
    return new Response(null, { status: 204 });
  });
  for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"])
    assert.equal((await handle(event, { path: "/api/future-endpoint?cursor=a%2Fb", method })).status, 204);
  assert.deepEqual(requests.map(request => request.method), ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
  assert.ok(requests.every(request => request.path === "/api/future-endpoint?cursor=a%2Fb" && request.body === undefined));
});

test("personal Desktop IPC refuses unrelated account, update and client operations before credential reads or transport", async () => {
  let lookups = 0, sends = 0;
  const handle = createAdminRequestHandler({ ownedContents: () => owner,
    admin: () => { lookups++; throw new Error("must not read transport configuration"); }, home: "/unused",
    transport: () => { sends++; throw new Error("must not send"); } });
  const paths = [
    "/api/update", "/api/update?force=1", "/api/power", "/api/power/setup",
    "/api/remote", "/api/remote/reload", "/api/phone/status", "/api/phone/pairing", "/api/phone-inbox/claim",
    "/api/mod/approval", "/api/mod-settings", "/api/mod-options", "/api/settings-jobs/result",
    "/api/codex", "/api/shutdown", "/api/compact-pick", "/api/agent-title", "/api/status-mod",
    ...["claude", "chatgpt", "google"].flatMap(provider => [
      `/api/${provider}-login`, `/api/${provider}-logout`, `/api/${provider}-oauth`,
      `/api/${provider}-oauth/code`, `/api/${provider}-accounts`, `/api/${provider}-accounts/current`,
    ]),
  ];
  for (const path of paths) for (const method of ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]) {
    const response = await handle(event, { path, method });
    assert.equal(response.status, 403, `${method} ${path}`);
    assert.match(text(response), /personal Desktop dashboard/);
  }
  assert.equal(lookups, 0);
  assert.equal(sends, 0);
});

test("personal Desktop status, provider keys, native picker and privacy approvals retain their IPC routes", async () => {
  const requests: string[] = [];
  const handle = fixture(async (_base, path) => { requests.push(path); return new Response(null, { status: 204 }); });
  const paths = [
    "/api/status", "/api/limits", "/api/config", "/api/presets", "/api/claude-models",
    "/api/context-windows", "/api/effort-levels", "/api/providers/probe", "/api/providers/measure",
    "/api/credentials/clear-cooldown", "/api/picker", "/api/security-policy",
    "/api/requests", "/api/requests/summary", "/api/logs",
  ];
  for (const path of paths) assert.equal((await handle(event, { path, method: "POST" })).status, 204, path);
  assert.deepEqual(requests, paths);
});

test("request strings are bounded by UTF-8 bytes before transport, including the exact boundary", async () => {
  let calls = 0;
  const handle = fixture(async () => { calls++; return new Response(null, { status: 204 }); });
  for (const body of ["x".repeat(ADMIN_IPC_REQUEST_LIMIT + 1), "界".repeat(Math.ceil(ADMIN_IPC_REQUEST_LIMIT / 3))])
    assert.equal((await handle(event, { path: "/api/config", method: "PUT", body })).status, 413);
  assert.equal(calls, 0);
  assert.equal((await handle(event, { path: "/api/config", method: "PUT", body: "x".repeat(ADMIN_IPC_REQUEST_LIMIT) })).status, 204);
  assert.equal(calls, 1);
});

test("response bodies are bounded for declared and chunked output and cancel overflow", async () => {
  let cancelled = 0;
  for (const declared of [true, false]) {
    const handle = fixture(async () => new Response(new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array(ADMIN_IPC_RESPONSE_LIMIT)); controller.enqueue(new Uint8Array(1)); },
      cancel() { cancelled++; },
    }), { headers: declared ? { "content-length": String(ADMIN_IPC_RESPONSE_LIMIT + 1) } : {} }));
    const response = await handle(event, { path: "/api/log" });
    assert.equal(response.status, 502);
    assert.deepEqual(JSON.parse(text(response)), { error: "admin response exceeds the size limit" });
  }
  assert.equal(cancelled, 2);
  const exact = await fixture(async () => new Response(new Uint8Array(ADMIN_IPC_RESPONSE_LIMIT)))(event, { path: "/api/log" });
  assert.equal(exact.status, 200);
  assert.equal(exact.body.byteLength, ADMIN_IPC_RESPONSE_LIMIT);
});

test("original error statuses and null-body statuses survive IPC without secret-bearing response headers", async t => {
  const f = await adminTlsFixture(t, (req, res) => {
    const status = Number(req.url?.split("/").pop());
    res.writeHead(status, { "content-type": "application/json", [ADMIN_TOKEN_HEADER]: "must-not-return", "set-cookie": "must-not-return" });
    res.end([204, 205, 304].includes(status) || req.method === "HEAD" ? undefined : '{"error":"conflict"}');
  });
  const handle = createAdminRequestHandler({ ownedContents: () => owner, admin: () => f.base, home: f.home });
  for (const status of [204, 205, 304, 409]) {
    const response = await handle(event, { path: `/api/status/${status}` });
    assert.equal(response.status, status);
    assert.deepEqual(response.headers, { "content-type": "application/json" });
    assert.equal(response.body.byteLength === 0, status !== 409);
  }
  const head = await handle(event, { path: "/api/status/200", method: "HEAD" });
  assert.equal(head.status, 200); assert.equal(head.body.byteLength, 0);
});

test("transport errors and forbidden redirects produce fixed diagnostics only", async t => {
  const failure = await fixture(() => { throw new Error("secret fixture key must never leak"); })(event, { path: "/api/status" });
  assert.equal(failure.status, 503);
  assert.deepEqual(JSON.parse(text(failure)), { error: "ClaudeRipple is not running", routerDown: true });
  const f = await adminTlsFixture(t, (_req, res) => { res.writeHead(302, { location: "https://untrusted.example/" }); res.end(); });
  const response = await createAdminRequestHandler({ ownedContents: () => owner, admin: () => f.base, home: f.home })(event, { path: "/api/status" });
  assert.equal(response.status, 503);
  assert.ok(!text(response).includes("untrusted.example"));
});

test("four active IPC requests share a concurrency limit, released only when work settles", async () => {
  const finish: ((value: Response) => void)[] = [];
  const handle = fixture(() => new Promise(resolve => { finish.push(resolve); }));
  const pending = Array.from({ length: ADMIN_IPC_CONCURRENCY }, () => handle(event, { path: "/api/status" }));
  assert.equal((await handle(event, { path: "/api/status" })).status, 429);
  assert.equal(finish.length, 4);
  finish[0]!(new Response(null, { status: 204 }));
  assert.equal((await pending[0]!).status, 204);
  const next = handle(event, { path: "/api/status" });
  assert.equal(finish.length, 5);
  for (const resolve of finish.slice(1)) resolve(new Response(null, { status: 204 }));
  assert.ok((await Promise.all([...pending, next])).every(response => response.status === 204));
});

test("deadline aborts stalled transport and stalled response reads without leaking details", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  let aborted = false;
  const handle = fixture((_base, _path, _home, init) => new Promise((_resolve, reject) => {
    init?.signal?.addEventListener("abort", () => { aborted = true; reject(new Error("private diagnostic")); }, { once: true });
  }));
  const pending = handle(event, { path: "/api/status" });
  t.mock.timers.tick(ADMIN_IPC_TIMEOUT_MS);
  assert.equal((await pending).status, 504);
  assert.equal(aborted, true);
  let cancelled = false;
  const read = fixture(async () => new Response(new ReadableStream({ cancel() { cancelled = true; } })));
  const body = read(event, { path: "/api/status" });
  await Promise.resolve(); await Promise.resolve();
  t.mock.timers.tick(ADMIN_IPC_TIMEOUT_MS);
  assert.equal((await body).status, 504);
  assert.equal(cancelled, true);
});

test("production preload exposes one fixed administrative method and never exposes raw IPC or credentials", async () => {
  const source = fs.readFileSync(new URL("../src/preload.ts", import.meta.url), "utf8");
  const compiled = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  let exposed: Record<string, Function> | undefined;
  const invoked: unknown[][] = [];
  runInNewContext(compiled, {
    require: (id: string) => { assert.equal(id, "electron"); return {
      contextBridge: { exposeInMainWorld: (name: string, value: Record<string, Function>) => { assert.equal(name, "rippleApp"); exposed = value; } },
      ipcRenderer: { invoke: (...args: unknown[]) => { invoked.push(args); return Promise.resolve({ status: 200 }); } },
    }; }, process: { platform: "fixture" },
  });
  assert.ok(exposed?.adminRequest);
  const request = { path: "/api/status" };
  await exposed.adminRequest(request);
  assert.deepEqual(invoked, [[ADMIN_IPC_CHANNEL, request]]);
  assert.ok(!("invoke" in exposed) && !("send" in exposed) && !("ipcRenderer" in exposed));
  assert.doesNotMatch(source, /admin-auth|admin-token|x-clauderipple-admin/);
});
