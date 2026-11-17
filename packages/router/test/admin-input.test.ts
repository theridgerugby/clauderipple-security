import { test } from "node:test";
import assert from "node:assert/strict";
import { MAX_PROBE_ERROR_BYTES, MAX_PROBE_JSON_BYTES, parseAdminJson, readProbeJson, readProbeText } from "../src/admin-input.ts";

test("admin JSON rejects malformed or excessive nesting/value counts without input excerpts", () => {
  assert.deepEqual(parseAdminJson('{"providers":{}}'), { providers: {} });
  assert.throws(() => parseAdminJson('{"apiKey":dummy-secret}'), /^Error: invalid JSON$/);
  assert.throws(() => parseAdminJson("[".repeat(65) + "0" + "]".repeat(65)), /nesting/);
  assert.throws(() => parseAdminJson(JSON.stringify(Array.from({ length: 50_001 }, () => 0))), /too many values/);
  assert.doesNotThrow(() => parseAdminJson("[".repeat(64) + "0" + "]".repeat(64)));
});

test("probe byte bounds include the exact boundary and decoded multibyte data", async () => {
  const text = "é".repeat(MAX_PROBE_ERROR_BYTES / 2);
  assert.equal(await readProbeText(new Response(text)), text);
  await assert.rejects(readProbeText(new Response(text + "é")), /size limit/);
  const json = JSON.stringify({ value: "x".repeat(MAX_PROBE_JSON_BYTES) });
  await assert.rejects(readProbeJson(new Response(json)), /size limit/);
});

test("oversized Content-Length cancels the body before consuming it", async () => {
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({ cancel() { cancelled = true; } });
  const response = new Response(body, { headers: { "content-length": String(MAX_PROBE_JSON_BYTES + 1) } });
  await assert.rejects(readProbeJson(response), /size limit/);
  assert.equal(cancelled, true);
});

test("probe reader joins UTF-8 split across chunks and masks JSON parser input", async () => {
  const bytes = new TextEncoder().encode('{"name":"你好"}');
  let at = 0;
  const response = new Response(new ReadableStream<Uint8Array>({
    pull(controller) {
      if (at >= bytes.length) { controller.close(); return; }
      controller.enqueue(bytes.slice(at, ++at));
    },
  }));
  assert.deepEqual(await readProbeJson(response), { name: "你好" });
  await assert.rejects(readProbeJson(new Response('{"name":dummy-secret}')), /^Error: invalid JSON$/);
});
