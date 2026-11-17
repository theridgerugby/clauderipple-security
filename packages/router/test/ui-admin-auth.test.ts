import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

// Execute the real dashboard boundary without a browser, live listener, or real credential.
const source = fs.readFileSync(new URL("../../ui/app.js", import.meta.url), "utf8");
const start = source.indexOf("const configSnapshots =");
const end = source.indexOf("// The router writes", start);
assert.ok(start >= 0 && end > start);
const boundary = source.slice(start, end);
const token = "a".repeat(64);
function fixture(hash = "", desktop = false, stored?: string, status = 200) {
  const storage = new Map(stored ? [["clauderipple-admin-token", stored]] : []);
  const history: string[] = [];
  const requests: { url: string; init: RequestInit }[] = [];
  const window = {
    location: { hash, pathname: "/", search: "" },
    history: { replaceState(_state: unknown, _title: string, url: string) { history.push(url); } },
    sessionStorage: { getItem() { throw new Error("renderer must not read credentials"); }, setItem() { throw new Error("renderer must not store credentials"); }, removeItem(key: string) { storage.delete(key); } },
  };
  const fetch = async (url: string, init: RequestInit) => {
    requests.push({ url, init });
    return { ok: status === 200, status, text: async () => JSON.stringify(status === 200 ? { ok: true } : { error: "unauthorized" }) };
  };
  const ui = new Function("window", "APP", "fetch", `${boundary}\nreturn { adminFetch, api };`)(window, desktop ? {} : null, fetch) as {
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

test("native renderer discards caller capabilities and retains only representation headers", async () => {
  const f = fixture("#health", true, token);
  await f.api("/api/power", { method: "PUT", headers: { "content-type": "application/json", "X-ClaudeRipple-Admin": "wrong" }, body: "{}" });
  const h = new Headers(f.requests[0]!.init.headers);
  assert.equal(h.has("x-clauderipple-admin"), false);
  assert.equal(h.get("content-type"), "application/json");
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
  assert.equal(f.requests[0]!.init.redirect, "error");
  assert.equal(f.requests[0]!.init.mode, "same-origin");
  assert.match(source, /await adminFetch\("\/api\/logs\?n=200"\)/);
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
