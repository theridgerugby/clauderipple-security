import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { nativeAdminBridge } from "./ui-native-fixture.ts";

// Execute the real dashboard boundary without a browser, live listener, or real credential.
const source = fs.readFileSync(new URL("../../ui/app.js", import.meta.url), "utf8");
const start = source.indexOf("const configSnapshots =");
const end = source.indexOf("// The router writes", start);
assert.ok(start >= 0 && end > start);
const boundary = source.slice(start, end);
const token = "a".repeat(64);
function fixture(hash = "", desktop = false, stored?: string, status = 200, beforeReply?: (index: number) => Promise<void>) {
  const storage = new Map(stored ? [["clauderipple-admin-token", stored]] : []);
  const history: string[] = [];
  const requests: { url: string; init: RequestInit }[] = [];
  const window = {
    location: { hash, pathname: "/", search: "" },
    history: { replaceState(_state: unknown, _title: string, url: string) { history.push(url); } },
    sessionStorage: { getItem() { throw new Error("renderer must not read credentials"); }, setItem() { throw new Error("renderer must not store credentials"); }, removeItem(key: string) { storage.delete(key); } },
  };
  const backend = async (url: string, init: RequestInit = {}) => {
    requests.push({ url, init });
    await beforeReply?.(requests.length - 1);
    return { ok: status === 200, status, text: async () => JSON.stringify(status === 200 ? { ok: true } : { error: "unauthorized" }) };
  };
  const browserFetch = () => { throw new Error("renderer must never use browser fetch for administration"); };
  const ui = new Function("window", "APP", "fetch", `${boundary}\nreturn { adminFetch, api };`)(window,
    desktop ? { adminRequest: nativeAdminBridge(backend) } : null, browserFetch) as {
    adminFetch(path: string, init?: RequestInit): Promise<unknown>;
    api(path: string, init?: RequestInit): Promise<unknown>;
  };
  return { ...ui, storage, history, requests };
}

test("obsolete browser capability is scrubbed and browser administration fails before network I/O", async () => {
  const f = fixture(`#admin-token=${token}&view=mod`, false, token);
  assert.deepEqual(f.history, ["/#mod"]);
  assert.equal(f.storage.has("clauderipple-admin-token"), false);
  await assert.rejects(f.api("/api/status"), /native dashboard/);
  assert.equal(f.requests.length, 0);
});

test("native renderer sends only typed IPC and discards all non-representation headers", async () => {
  const f = fixture("#health", true, token);
  await f.api("/api/power", { method: "PUT", headers: { "content-type": "application/json", "X-ClaudeRipple-Admin": "wrong", host: "untrusted", authorization: "wrong", cookie: "wrong" }, body: "{}" });
  const h = new Headers(f.requests[0]!.init.headers);
  assert.equal(h.has("x-clauderipple-admin"), false);
  assert.equal(h.get("content-type"), "application/json");
  assert.deepEqual([...h.keys()], ["content-type"]);
  assert.deepEqual(f.history, []);
});

test("malformed fragments are removed and cannot provide a credential", async () => {
  const f = fixture("#admin-token=invalid&view=%2F%2Fevil.example", true);
  assert.deepEqual(f.history, ["/"]);
  await f.api("/api/status");
  assert.equal(new Headers(f.requests[0]!.init.headers).has("x-clauderipple-admin"), false);
});

test("desktop renderer neither reads nor attaches the main-process capability", async () => {
  const f = fixture(`#admin-token=${token}`, true, token);
  await f.api("/api/status", { headers: { "x-clauderipple-admin": "wrong" } });
  assert.equal(new Headers(f.requests[0]!.init.headers).has("x-clauderipple-admin"), false);
  assert.deepEqual(f.history, ["/"]);
});

test("dashboard refuses external URLs and never follows authenticated redirects", async () => {
  const f = fixture("", true, token);
  for (const url of ["https://evil.example/api/status", "//evil.example/api/status", "/api/\\evil", "/api/\r\n"])
    assert.throws(() => f.adminFetch(url), /Invalid local admin path/);
  assert.equal(f.requests.length, 0);
  await f.adminFetch("/api/logs?n=200", { redirect: "follow", mode: "cors" });
  assert.equal(f.requests[0]!.init.redirect, undefined, "fetch-only options cannot enter IPC");
  assert.equal(f.requests[0]!.init.mode, undefined);
  assert.match(source, /await adminFetch\("\/api\/logs\?n=200"\)/);
});

test("renderer refuses unsupported and oversized IPC bodies before native dispatch", async () => {
  const f = fixture("", true);
  for (const init of [{ method: "CONNECT" }, { body: "a" }, { method: "HEAD", body: "a" },
    { method: "POST", body: new Uint8Array(2) }, { method: "POST", body: "界".repeat(1024 * 1024) }]) {
    assert.throws(() => f.adminFetch("/api/config", init), /Invalid local admin|too large/);
  }
  assert.equal(f.requests.length, 0);
  await f.api("/api/power", { method: "post", body: "{}" });
  assert.equal(f.requests[0]!.init.method, "POST");
});

test("native bodyless statuses reconstruct a valid bodyless renderer Response", async () => {
  for (const status of [204, 205, 304]) {
    const response = await fixture("", true, undefined, status).adminFetch("/api/status") as Response;
    assert.equal(response.status, status);
    assert.equal(response.body, null);
  }
});

test("dashboard queues concurrent startup reads within the four-call IPC budget in FIFO order", async () => {
  const releases: Array<() => void> = [];
  const gates = Array.from({ length: 10 }, () => new Promise<void>(resolve => releases.push(resolve)));
  const f = fixture("", true, undefined, 200, index => gates[index]!);
  const pending = Array.from({ length: 10 }, (_, index) => f.api(`/api/status?index=${index}`));
  await new Promise(setImmediate);
  assert.equal(f.requests.length, 4);
  for (let index = 0; index < 6; index++) {
    releases[index]!();
    await new Promise(setImmediate);
    assert.equal(f.requests.length, Math.min(10, index + 5));
  }
  for (const release of releases) release();
  await Promise.all(pending);
  assert.deepEqual(f.requests.map(request => request.url), Array.from({ length: 10 }, (_, index) => `/api/status?index=${index}`));
});

test("dashboard queue has bounded admission and releases slots after failed native requests", async () => {
  let release!: () => void;
  const gate = new Promise<void>(resolve => { release = resolve; });
  const f = fixture("", true, undefined, 200, async index => {
    await gate;
    if (index === 0) throw new Error("fixture native failure");
  });
  const pending = Promise.allSettled(Array.from({ length: 36 }, () => f.api("/api/status")));
  await new Promise(setImmediate);
  assert.equal(f.requests.length, 4);
  await assert.rejects(f.api("/api/status"), /queue is full/);
  assert.equal(f.requests.length, 4, "overflow is refused before dispatch");
  release();
  const settled = await pending;
  assert.equal(settled.filter(result => result.status === "fulfilled").length, 35);
  assert.equal(settled.filter(result => result.status === "rejected").length, 1);
  await f.api("/api/status");
  assert.equal(f.requests.length, 37, "a failed call does not poison the queue");
});

test("bulk provider refresh uses three workers without dropping providers beyond the queue bound", async () => {
  const start = source.indexOf("async function probeProviders(");
  const end = source.indexOf("async function loadProviders(", start);
  assert.ok(start >= 0 && end > start);
  const seen: string[] = [];
  let active = 0, peak = 0;
  const refresh = new Function("probeProvider", `${source.slice(start, end)}\nreturn probeProviders;`)(async (name: string) => {
    active++; peak = Math.max(peak, active); seen.push(name);
    await new Promise(setImmediate);
    active--;
  });
  const providers = Object.fromEntries(Array.from({ length: 80 }, (_, index) => [`provider-${index}`, {}]));
  await refresh(providers);
  assert.equal(peak, 3);
  assert.deepEqual(seen, Object.keys(providers));
});

test("unauthorized dashboard explains how to open an authenticated session", async () => {
  const f = fixture("", true, undefined, 401);
  await assert.rejects(f.api("/api/status"), /clauderipple ui/);
});

test("saved-provider probes name their credential scope and automatic updates are opt-in", () => {
  assert.match(source, /JSON\.stringify\(\{ \.\.\.body, name \}\)/);
  assert.match(source, /probeProvider\(options\.name \|\| temporary, draft\)/);
  assert.match(source, /name: options\.name, \.\.\.\(existing && existing\.url/);
  assert.match(source, /type: "grok", name: options\.name/);
  assert.doesNotMatch(source, /autoUpdate\?\.enabled !== false/);
});

test("removing the primary pooled key preserves the remaining key's credential identity", () => {
  const from = source.indexOf("function keyPool("), to = source.indexOf("/** A key left unnamed", from);
  assert.ok(from >= 0 && to > from);
  const { writeKeyPool } = new Function(`${source.slice(from, to)}\nreturn { writeKeyPool };`)();
  const marker = "__CLAUDERIPPLE_REDACTED_SECRET__";
  const a = { id: "a", headers: { authorization: `Bearer ${marker}` } };
  const b = { id: "b", headers: { authorization: `Bearer ${marker}` } };
  const provider = { headers: a.headers, credentials: [a, b] };
  writeKeyPool(provider, [b]);
  assert.deepEqual(provider.credentials, [b]);
  assert.deepEqual(provider.headers, b.headers);
  writeKeyPool(provider, []);
  assert.equal("credentials" in provider, false);
  assert.equal("headers" in provider, false);
});
