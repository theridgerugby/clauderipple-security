import { test } from "node:test";
import assert from "node:assert/strict";
import { Readable } from "node:stream";
import { ADMIN_BRIDGE_MAX_BYTES, executeBridgeRequest, parseBridgeRequest, runAdminBridge } from "../src/admin-bridge.ts";

const url = "http://127.0.0.1:8792/api/status?session=fixture";
test("bridge parses bounded local request metadata without accepting caller credentials", () => {
  assert.deepEqual(parseBridgeRequest({ kind: "request", url }), { kind: "request", url, method: "GET", headers: {}, timeoutMs: 15_000 });
  for (const change of [
    { url: "https://example.test/api/status" }, { url: "http://localhost:8792/api/status" },
    { headers: { "x-clauderipple-admin": "secret" } }, { headers: { authorization: "secret" } },
    { headers: { host: "evil.test" } }, { headers: { "content-type": "text/plain\nextra" } },
    { method: "CONNECT" }, { body: {} }, { timeoutMs: 30_001 }, { timeoutMs: 0 },
  ]) assert.throws(() => parseBridgeRequest({ kind: "request", url, ...change }));
  assert.throws(() => parseBridgeRequest({ kind: "ui", view: "https://evil.test" }));
});
test("bridge forwards requests through native transport with explicit home and timeout", async () => {
  const calls: unknown[] = [];
  const result = await executeBridgeRequest({ kind: "request", url, method: "POST", body: "{}", headers: { "content-type": "application/json" } }, "/fixture-home", {
    fetch: async (value, init, home) => {
      calls.push({ value, method: init?.method, body: init?.body, home });
      assert.ok(init?.signal instanceof AbortSignal);
      return new Response('{"fixture":true}', { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  assert.deepEqual(calls, [{ value: url, method: "POST", body: "{}", home: "/fixture-home" }]);
  assert.deepEqual(result, { status: 200, ok: true, headers: { "content-type": "application/json" }, text: '{"fixture":true}' });
});
test("UI bridge sends only a fixed view to native opener", async () => {
  const result = await executeBridgeRequest({ kind: "ui", view: "mod" }, "/fixture-home", {
    open: async (home, view) => { assert.equal(home, "/fixture-home"); assert.equal(view, "mod"); return { ok: true, message: "fixture" }; },
  });
  assert.deepEqual(result, { ok: true, message: "fixture" });
});
test("stdin and output bounds fail closed before unbounded allocation or a fallback", async () => {
  let calls = 0;
  const deps = { fetch: async () => { calls++; return new Response("x".repeat(ADMIN_BRIDGE_MAX_BYTES + 1)); } };
  await assert.rejects(runAdminBridge(Readable.from(["x".repeat(ADMIN_BRIDGE_MAX_BYTES + 1)]), "/fixture", deps));
  assert.equal(calls, 0);
  await assert.rejects(runAdminBridge(Readable.from([JSON.stringify({ kind: "request", url })]), "/fixture", deps));
  assert.equal(calls, 1);
  await assert.rejects(runAdminBridge(Readable.from(["not-json"]), "/fixture", deps));
  assert.equal(calls, 1);
});
