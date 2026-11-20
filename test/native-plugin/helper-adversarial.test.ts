// Pure synthetic inputs and mocked https.request only. No account, native configuration,
// operating-system trust store, real Google credential or external network is accessed.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import https from "node:https";
import tls from "node:tls";
import { PassThrough } from "node:stream";
import {
  ENDPOINT, MODEL, INPUT_LIMIT, UPSTREAM_LIMIT, REQUEST_TIMEOUT_MS,
  prepare, handle, sendGoogle, safeStartup, type GoogleCall, type GoogleReply,
} from "../../packages/gemini-native/src/request.ts";

const KEY = "synthetic_google_key_not_a_credential_123";
const SECRET = "PRIVATE_NATIVE_SENTINEL_MUST_NOT_BE_FORWARDED";
const tool = (name: string) => ({ name, description: "Synthetic fixture tool", input_schema: { type: "object", properties: {} } });
const raw = (request: Record<string, unknown> = {}, outer: Record<string, unknown> = {}) => JSON.stringify({
  protocol: 1, apiKey: KEY, request: { model: MODEL, messages: [{ role: "user", content: "Synthetic request." }], ...request }, ...outer,
});
const answer = (parts: unknown[] = [{ text: "Synthetic answer." }], extra: Record<string, unknown> = {}): GoogleReply => ({
  status: 200, body: JSON.stringify({ candidates: [{ finishReason: "STOP", content: { role: "model", parts } }], ...extra }),
});
function fixedCall(): GoogleCall { return prepare(raw()).call; }

test("prepare creates only Google headers and drops native authentication, metadata and reasoning", () => {
  const prepared = prepare(raw({
    metadata: { user_id: SECRET }, headers: { authorization: SECRET, cookie: SECRET },
    messages: [{ role: "assistant", content: [{ type: "thinking", thinking: SECRET, signature: SECRET }] },
      { role: "user", content: "Synthetic request." }],
  }));
  assert.equal(prepared.call.url, ENDPOINT);
  assert.deepEqual(prepared.call.headers, { "content-type": "application/json", accept: "application/json", "x-goog-api-key": KEY });
  assert.ok(!prepared.call.url.includes(KEY));
  assert.ok(!prepared.call.body.includes(SECRET));
  assert.ok(!prepared.call.body.includes(KEY));
});

test("unsupported model, external URLs, unknown blocks and oversized input never reach the sender", async () => {
  let calls = 0;
  const send = async () => { calls++; return answer(); };
  const inputs = [
    raw({ model: "claude-opus-native" }), raw({}, { url: "https://example.invalid" }),
    raw({ messages: [{ role: "user", content: [{ type: "image", source: { type: "url", url: "http://127.0.0.1/private" } }] }] }),
    raw({ messages: [{ role: "user", content: [{ type: "future_native_control", content: SECRET }] }] }),
    raw({ messages: [{ role: "user", content: "a".repeat(INPUT_LIMIT) }] }),
  ];
  for (const input of inputs) {
    const result = await handle(input, send);
    assert.equal(result.response.status, 400);
    assert.equal(result.response.ok, false);
    assert.ok(!JSON.stringify(result).includes(SECRET));
  }
  assert.equal(calls, 0);
});

test("shape validation does not coerce arrays into role, effort or source type strings", () => {
  assert.throws(() => prepare(raw({ messages: [{ role: ["user"], content: "Synthetic." }] })));
  assert.throws(() => prepare(raw({}, { effort: ["high"] })));
  assert.throws(() => prepare(raw({ messages: [{ role: "user", content: [{ type: "document", source: { type: ["text"], data: "Synthetic." } }] }] })));
  assert.throws(() => prepare(raw({ tools: [tool("ReadFile")], tool_choice: { type: ["none"] } })));
});

test("tool name collisions are refused before a Google call", async () => {
  let called = false;
  const result = await handle(raw({ tools: [tool("ReadFile"), tool("ReadFile")] }), async () => { called = true; return answer(); });
  assert.equal(called, false);
  assert.equal(result.response.status, 400);
});

test("Google cannot invent a tool absent from the request", async () => {
  const result = await handle(raw({ tools: [tool("ReadFile")] }), async () => answer([{ functionCall: { name: "RunCommand", args: {} } }]));
  assert.equal(result.response.status, 400);
  assert.ok(!result.response.text.includes("RunCommand"));
});

test("deferred tools are lifted but withdrawn tools cannot be called", async () => {
  const request = { messages: [{ role: "user", content: [
    { type: "text", text: "Synthetic task." }, { type: "tool_addition", tool: { definition: tool("ReadFile") } },
  ] }] };
  assert.ok(prepare(raw(request)).tools.has("ReadFile"));
  const removed = { messages: [{ role: "user", content: [...request.messages[0]!.content,
    { type: "tool_removal", tool: { type: "tool_reference", name: "ReadFile" } },
  ] }] };
  assert.ok(!prepare(raw(removed)).tools.has("ReadFile"));
  const result = await handle(raw(removed), async () => answer([{ functionCall: { name: "ReadFile", args: {} } }]));
  assert.equal(result.response.status, 400);
});

test("deferred tool declarations have the same count and shape limits as explicit tools", () => {
  const deferred = (definition: unknown) => ({ type: "tool_addition", tool: { definition } });
  for (const definition of [{ ...tool("a".repeat(257)) }, { ...tool("ReadFile"), description: { credential: SECRET } }]) {
    assert.throws(() => prepare(raw({ messages: [{ role: "user", content: [{ type: "text", text: "Synthetic task." }, deferred(definition)] }] })));
  }
  const additions = Array.from({ length: 513 }, (_, index) => deferred(tool(`Tool${index}`)));
  assert.throws(() => prepare(raw({ messages: [{ role: "user", content: [{ type: "text", text: "Synthetic task." }, ...additions] }] })));
});

test("mangled tool names and signatures round-trip without adding foreign thinking blocks", async () => {
  const name = "mcp__synthetic_server__read.file";
  const request = { tools: [tool(name)] };
  const wireName = [...prepare(raw(request)).tools][0]!;
  assert.notEqual(wireName, name);
  const output = await handle(raw(request), async () => answer([{ functionCall: { name: wireName, args: { path: "synthetic.txt" } }, thoughtSignature: "synthetic-signature" }]));
  assert.equal(output.response.status, 200);
  const message = JSON.parse(output.response.text);
  assert.equal(message.content[0].name, name);
  assert.deepEqual(message.content[0].input, { path: "synthetic.txt" });
  assert.deepEqual(output.thoughtSignatures, [[message.content[0].id, "synthetic-signature"]]);
  assert.equal(message.content[0].thoughtSignature, undefined);
});

test("tool_choice none refuses a function call even when its name was declared", async () => {
  const result = await handle(raw({ tools: [tool("WriteFile")], tool_choice: { type: "none" } }), async () => answer([{ functionCall: { name: "WriteFile", args: {} } }]));
  assert.equal(result.response.status, 400);
});

test("a forced tool choice cannot turn into a different declared function", async () => {
  const result = await handle(raw({ tools: [tool("ReadFile"), tool("WriteFile")], tool_choice: { type: "tool", name: "ReadFile" } }), async () => answer([{ functionCall: { name: "WriteFile", args: {} } }]));
  assert.equal(result.response.status, 400);
});

test("disable_parallel_tool_use refuses a multi-call response", async () => {
  const result = await handle(raw({ tools: [tool("ReadFile")], tool_choice: { type: "auto", disable_parallel_tool_use: true } }), async () => answer([
    { functionCall: { name: "ReadFile", args: { index: 1 } } }, { functionCall: { name: "ReadFile", args: { index: 2 } } },
  ]));
  assert.equal(result.response.status, 400);
});

test("undeclared, malformed and forged upstream structures produce only fixed errors", async () => {
  const variants: GoogleReply[] = [
    { status: 429, body: SECRET }, { status: 302, body: SECRET }, { status: 200, body: SECRET },
    { status: 200, body: "a".repeat(UPSTREAM_LIMIT + 1) },
    answer([{ functionCall: { name: "ReadFile", args: [] } }]),
    answer([{ functionCall: { name: "ReadFile", args: {} }, text: SECRET }]),
    answer([{ functionCall: { name: "ReadFile", args: {} }, thought: true }]),
    answer([{ text: "answer", executableCode: { code: SECRET } }]),
    answer([{ text: "answer" }], { error: { message: SECRET } }),
    answer([{ text: "answer" }], { promptFeedback: { blockReason: SECRET } }),
    answer([{ text: "answer" }], { usageMetadata: { promptTokenCount: -1 } }),
  ];
  for (const reply of variants) {
    const result = await handle(raw({ tools: [tool("ReadFile")] }), async () => reply);
    assert.equal(result.response.status, 400);
    assert.ok(!JSON.stringify(result).includes(SECRET));
    assert.deepEqual(result.thoughtSignatures, []);
  }
});

test("unsigned Gemini thinking does not contaminate a later native Claude transcript", async () => {
  const result = await handle(raw({ stream: true }), async () => answer([{ thought: true, text: SECRET }, { text: "Visible answer." }]));
  assert.equal(result.response.status, 200);
  assert.ok(result.response.text.includes("Visible answer."));
  assert.ok(!result.response.text.includes(SECRET));
  assert.ok(!result.response.text.includes('"thinking"'));
});

test("signature storage has a separate aggregate bound even under the upstream byte limit", async () => {
  const parts = Array.from({ length: 70 }, () => ({ functionCall: { name: "ReadFile", args: {} }, thoughtSignature: "s".repeat(16 * 1024) }));
  const reply = answer(parts);
  assert.ok(Buffer.byteLength(reply.body) < UPSTREAM_LIMIT);
  const result = await handle(raw({ tools: [tool("ReadFile")] }), async () => reply);
  assert.equal(result.response.status, 400);
  assert.deepEqual(result.thoughtSignatures, []);
});

test("an upstream exception cannot leak its message or native credentials", async () => {
  const result = await handle(raw(), async () => { throw new Error(SECRET); });
  assert.equal(result.response.status, 400);
  assert.ok(!JSON.stringify(result).includes(SECRET));
});

test("caller cancellation before send prevents any request", async () => {
  const abort = new AbortController(); abort.abort();
  let called = false;
  const result = await handle(raw(), async () => { called = true; return answer(); }, abort.signal);
  assert.equal(called, false);
  assert.equal(result.response.status, 400);
  assert.match(result.response.text, /cancelled/);
});

test("cancellation after a sender resolves discards its pending answer", async () => {
  const abort = new AbortController();
  const result = await handle(raw(), async () => { abort.abort(); return answer([{ text: SECRET }]); }, abort.signal);
  assert.equal(result.response.status, 400);
  assert.ok(!result.response.text.includes(SECRET));
});

type Capture = { url?: unknown; options?: https.RequestOptions; body?: string; destroyed: number; calls: number };
function transport(t: TestContext, response?: { status?: number; type?: string; encoding?: string; body?: Buffer | string; abort?: boolean }) {
  const capture: Capture = { destroyed: 0, calls: 0 };
  t.mock.method(https, "request", (url: unknown, options: https.RequestOptions, callback: (res: unknown) => void) => {
    capture.url = url; capture.options = options; capture.calls++;
    const request = new EventEmitter() as EventEmitter & { end(body: string): void; destroy(error?: Error): void };
    request.destroy = error => { capture.destroyed++; if (error) queueMicrotask(() => request.emit("error", error)); };
    request.end = body => {
      capture.body = body;
      if (!response) return;
      queueMicrotask(() => {
        const stream = new PassThrough() as PassThrough & { statusCode: number; headers: Record<string, string> };
        stream.statusCode = response.status ?? 200;
        stream.headers = { "content-type": response.type ?? "application/json", ...(response.encoding ? { "content-encoding": response.encoding } : {}) };
        callback(stream);
        if (response.abort) stream.emit("aborted");
        else stream.end(response.body ?? answer().body);
      });
    };
    options.signal?.addEventListener("abort", () => request.destroy(new Error("synthetic abort")), { once: true });
    return request;
  });
  return capture;
}

test("transport uses a private direct agent and bundled TLS roots at the fixed Google origin", async t => {
  const capture = transport(t, {}), call = fixedCall();
  const result = await sendGoogle(call, new AbortController().signal);
  assert.equal(capture.calls, 1);
  assert.equal(capture.url, ENDPOINT);
  assert.equal(capture.body, call.body);
  assert.equal(result.status, 200);
  assert.deepEqual(capture.options?.headers, call.headers);
  assert.ok(JSON.stringify(capture.options?.ca) === JSON.stringify(tls.rootCertificates), "request must use exactly the bundled root contents");
  assert.equal(capture.options?.rejectUnauthorized, true);
  assert.equal(capture.options?.minVersion, "TLSv1.2");
  assert.equal(capture.options?.checkServerIdentity, tls.checkServerIdentity);
  assert.ok(capture.options?.agent instanceof https.Agent);
  assert.notEqual(capture.options?.agent, https.globalAgent);
  const agent = capture.options!.agent as https.Agent;
  assert.deepEqual(agent.options.proxyEnv, {});
  assert.ok(JSON.stringify(agent.options.ca) === JSON.stringify(tls.rootCertificates), "agent must use exactly the bundled root contents");
  assert.equal(agent.options.keepAlive, false);
});

test("transport rejects another origin or native-auth header before constructing a request", async t => {
  const capture = transport(t, {}), call = fixedCall();
  await assert.rejects(sendGoogle({ ...call, url: "https://example.invalid/private" }, new AbortController().signal));
  await assert.rejects(sendGoogle({ ...call, headers: { ...call.headers, authorization: SECRET } }, new AbortController().signal));
  await assert.rejects(sendGoogle({ ...call, headers: { ...call.headers, cookie: SECRET } }, new AbortController().signal));
  assert.equal(capture.calls, 0);
});

test("transport refuses redirects without following them", async t => {
  const capture = transport(t, { status: 302, body: SECRET });
  await assert.rejects(sendGoogle(fixedCall(), new AbortController().signal));
  assert.equal(capture.calls, 1);
});

for (const [name, response] of [
  ["compressed body", { encoding: "gzip" }], ["wrong content type", { type: "text/html" }],
  ["oversized response", { body: Buffer.alloc(UPSTREAM_LIMIT + 1) }], ["aborted body", { abort: true }],
] as const) {
  test(`transport refuses ${name} without a retry`, async t => {
    const capture = transport(t, response);
    await assert.rejects(sendGoogle(fixedCall(), new AbortController().signal));
    assert.equal(capture.calls, 1);
  });
}

test("a synchronous request failure releases its private agent and deadline", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const destroy = t.mock.method(https.Agent.prototype, "destroy");
  t.mock.method(https, "request", () => { throw new Error(SECRET); });
  await assert.rejects(sendGoogle(fixedCall(), new AbortController().signal));
  assert.equal(destroy.mock.callCount(), 1);
  assert.doesNotThrow(() => t.mock.timers.tick(REQUEST_TIMEOUT_MS + 1));
});

test("the total transport deadline remains a timeout refusal", async t => {
  t.mock.timers.enable({ apis: ["setTimeout"] });
  const capture = transport(t);
  const settled = assert.rejects(sendGoogle(fixedCall(), new AbortController().signal), error => error instanceof Error && error.message === "timeout");
  t.mock.timers.tick(REQUEST_TIMEOUT_MS + 1);
  await settled;
  assert.equal(capture.destroyed, 1);
});

test("caller abort reaches the active transport and ends it without retry", async t => {
  const capture = transport(t), abort = new AbortController();
  const settled = assert.rejects(sendGoogle(fixedCall(), abort.signal), error => error instanceof Error && error.message === "timeout");
  abort.abort(); await settled;
  assert.equal(capture.destroyed, 1);
  assert.equal(capture.calls, 1);
});

test("startup rejects Node and TLS injection settings without trusting ordinary proxy env", () => {
  assert.equal(safeStartup({}, "24.22.3"), true);
  for (const version of ["22.0.0", "25.0.0", "garbage"]) assert.equal(safeStartup({}, version), false);
  for (const key of ["NODE_OPTIONS", "NODE_PATH", "NODE_EXTRA_CA_CERTS", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_USE_SYSTEM_CA", "NODE_USE_ENV_PROXY", "SSLKEYLOGFILE", "OPENSSL_CONF", "LD_PRELOAD", "DYLD_INSERT_LIBRARIES"]) {
    assert.equal(safeStartup({ [key]: SECRET }, "24.22.3"), false);
    assert.equal(safeStartup({ [key.toLowerCase()]: SECRET }, "24.22.3"), false);
  }
  assert.equal(safeStartup({ HTTPS_PROXY: "http://127.0.0.1:1234" }, "24.22.3"), true, "private transport explicitly ignores proxy environment");
});
