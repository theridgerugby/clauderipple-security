import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { ENDPOINT, MODEL, INPUT_LIMIT, OUTPUT_LIMIT, handle, prepare, refusal, safeStartup, type GoogleCall } from "../../packages/gemini-native/src/request.ts";

const key = "AIza-synthetic-not-a-real-key-0000000";
const raw = (request: Record<string, unknown> = {}, extra: Record<string, unknown> = {}): string => JSON.stringify({
  protocol: 1, apiKey: key, request: { model: MODEL, messages: [{ role: "user", content: "Check this fixture" }], ...request }, ...extra,
});
const answer = (parts: unknown[] = [{ text: "Fixture answer" }], finishReason = "STOP") => ({ status: 200, body: JSON.stringify({
  candidates: [{ content: { role: "model", parts }, finishReason }],
  usageMetadata: { promptTokenCount: 20, candidatesTokenCount: 6, thoughtsTokenCount: 4, cachedContentTokenCount: 5 },
}) });
const tool = { name: "mcp__files__read", description: "Read an approved file", input_schema: { type: "object", properties: { file: { type: "string" } }, required: ["file"] } };

test("native-plugin helper only creates the fixed Google request with fresh headers", () => {
  const prepared = prepare(raw({ metadata: { user_id: "native-account-must-not-travel" },
    headers: { authorization: "Bearer native-token-must-not-travel", cookie: "native-cookie" },
    system: [{ type: "text", text: "Harness fixture" }], tools: [tool] }, { effort: "high" }));
  assert.equal(prepared.call.url, ENDPOINT);
  assert.deepEqual(prepared.call.headers, { "content-type": "application/json", accept: "application/json", "x-goog-api-key": key });
  const body = JSON.parse(prepared.call.body);
  assert.equal(body.generationConfig.thinkingConfig.thinkingLevel, "high");
  assert.deepEqual(body.tools[0].functionDeclarations[0].parametersJsonSchema, tool.input_schema);
  assert.match(body.systemInstruction.parts[0].text, /Harness fixture/);
  assert.doesNotMatch(prepared.call.body, /native-account|native-token|native-cookie|x-goog-api-key|AIza-/);
});

test("native-plugin helper returns a complete bounded Anthropic reply without unsigned thinking", async () => {
  let requests = 0;
  const result = await handle(raw(), async () => { requests++; return answer([{ thought: true, text: "Private reasoning fixture" }, { text: "Public fixture" }]); });
  assert.equal(requests, 1);
  assert.equal(result.response.status, 200);
  const message = JSON.parse(result.response.text);
  assert.equal(message.role, "assistant");
  assert.equal(message.model, MODEL);
  assert.deepEqual(message.content, [{ type: "text", text: "Public fixture" }]);
  assert.equal(message.stop_reason, "end_turn");
  assert.deepEqual(message.usage, { input_tokens: 15, output_tokens: 10, cache_read_input_tokens: 5, cache_creation_input_tokens: 0 });
  assert.doesNotMatch(JSON.stringify(result), /Private reasoning|AIza-/);
  assert.ok(Buffer.byteLength(JSON.stringify(result)) < OUTPUT_LIMIT);
});

test("native-plugin helper's SSE is explicitly a complete buffered response", async () => {
  const result = await handle(raw({ stream: true }), async () => answer());
  assert.equal(result.response.headers["content-type"], "text/event-stream");
  const frames = result.response.text.trim().split("\n\n").map(frame => JSON.parse(frame.split("\ndata: ")[1]!));
  assert.equal(frames[0].type, "message_start");
  assert.equal(frames.at(-1).type, "message_stop");
  assert.ok(frames.some(frame => frame.type === "content_block_delta" && frame.delta.text === "Fixture answer"));
});

test("native-plugin helper preserves tool schema, tool name, args and next-step thought signature", async () => {
  let wire: GoogleCall | undefined;
  const first = await handle(raw({ tools: [tool] }), async call => {
    wire = call;
    const name = JSON.parse(call.body).tools[0].functionDeclarations[0].name;
    return answer([{ functionCall: { name, args: { file: "example.ts" } }, thoughtSignature: "synthetic-signature" }]);
  });
  assert.ok(wire);
  const firstMessage = JSON.parse(first.response.text);
  const use = firstMessage.content[0];
  assert.equal(use.type, "tool_use");
  assert.equal(use.name, tool.name);
  assert.deepEqual(use.input, { file: "example.ts" });
  assert.equal(firstMessage.stop_reason, "tool_use");
  assert.deepEqual(first.thoughtSignatures, [[use.id, "synthetic-signature"]]);
  assert.doesNotMatch(first.response.text, /synthetic-signature/);
  const second = prepare(raw({ tools: [tool], messages: [
    { role: "user", content: "Read example" }, { role: "assistant", content: [use] },
    { role: "user", content: [{ type: "tool_result", tool_use_id: use.id, content: "File contents fixture" }] },
  ] }, { thoughtSignatures: first.thoughtSignatures }));
  const contents = JSON.parse(second.call.body).contents;
  assert.equal(contents.find((item: any) => item.role === "model").parts[0].thoughtSignature, "synthetic-signature");
  assert.ok(contents.some((item: any) => item.parts.some((part: any) => part.functionResponse)));
});

test("native-plugin helper never uses Google when input is invalid, belongs to Claude, or has a foreign URL", async () => {
  let sent = 0;
  const send = async () => { sent++; return answer(); };
  for (const request of ["not-json", "", raw({ model: "claude-native-fixture" }), raw({}, { endpoint: "https://other.invalid" }),
    raw({}, { apiKey: "secret\r\ninjection" }), raw({ messages: [] }), raw({ stream: "yes" }), raw({ max_tokens: -1 }),
    raw({ messages: [{ role: "user", content: [{ type: "image", source: { type: "url", url: "http://127.0.0.1/private" } }] }] }),
    raw({ messages: [{ role: "user", content: [{ type: "unknown_future_block", text: "unsupported" }] }] }),
    raw({}, { thoughtSignatures: [["id", "s"], ["id", "duplicate"]] }), " ".repeat(INPUT_LIMIT + 1)]) {
    const result = await handle(request, send);
    assert.equal(result.response.ok, false);
    assert.equal(result.response.status, 400);
    assert.equal(result.thoughtSignatures.length, 0);
    assert.doesNotMatch(JSON.stringify(result), /AIza|secret|other.invalid|127\.0\.0\.1/);
  }
  assert.equal(sent, 0);
});

test("native-plugin helper rejects malformed or unsupported output rather than issuing tool calls", async () => {
  const toolName = [...prepare(raw({ tools: [tool] })).tools][0];
  const variants = [
    { status: 302, body: '{"location":"https://other.invalid?secret"}' },
    { status: 401, body: "upstream-key-or-account-error" },
    { status: 200, body: "invalid-response-secret" },
    answer([{ functionCall: { name: "not_declared", args: {} } }]),
    answer([{ functionCall: { name: toolName, args: "malformed" } }]),
    answer([{ inlineData: { data: "unsupported-image" } }]),
    answer([{ thought: true, text: "reasoning-only" }]),
    answer([], "STOP"), answer([{ text: "Incomplete" }], ""),
    { status: 200, body: JSON.stringify({ candidates: [JSON.parse(answer().body).candidates[0], JSON.parse(answer().body).candidates[0]] }) },
    { status: 200, body: JSON.stringify({ promptFeedback: { blockReason: "SAFETY", blockReasonMessage: "not-to-echo" } }) },
  ];
  for (const reply of variants) {
    let calls = 0;
    const result = await handle(raw({ tools: [tool] }), async () => { calls++; return reply; });
    assert.equal(calls, 1);
    assert.equal(result.response.ok, false);
    assert.deepEqual(result.thoughtSignatures, []);
    assert.doesNotMatch(result.response.text, /other.invalid|not-to-echo|upstream-key|response-secret|tool_use/);
  }
});

test("native-plugin helper does not retry errors or cancel into native Claude", async () => {
  let calls = 0;
  const result = await handle(raw(), async () => { calls++; throw new Error(`do-not-echo-${key}`); });
  assert.equal(calls, 1);
  assert.deepEqual(result, refusal("upstream"));
  const abort = new AbortController();
  abort.abort();
  const cancelled = await handle(raw(), async () => { calls++; return answer(); }, abort.signal);
  assert.equal(calls, 1);
  assert.deepEqual(cancelled, refusal("timeout"));
  const during = new AbortController();
  assert.deepEqual(await handle(raw(), async () => { during.abort(); return answer(); }, during.signal), refusal("timeout"));
});

test("native-plugin helper rejects a wide JSON tree before any outbound request", async () => {
  let calls = 0;
  const result = await handle(raw({ unused: new Array(200_001).fill(null) }), async () => { calls++; return answer(); });
  assert.equal(result.response.ok, false);
  assert.equal(calls, 0);
});

test("native-plugin helper enforces native forced/disabled/parallel tool policy on output", async () => {
  const name = [...prepare(raw({ tools: [tool] })).tools][0];
  const part = { functionCall: { name, args: {} } };
  assert.equal((await handle(raw({ tools: [tool], tool_choice: { type: "none" } }), async () => answer([part]))).response.ok, false);
  assert.equal((await handle(raw({ tools: [tool], tool_choice: { type: "any" } }), async () => answer())).response.ok, false);
  assert.equal((await handle(raw({ tools: [tool], tool_choice: { type: "auto", disable_parallel_tool_use: true } }), async () => answer([part, part]))).response.ok, false);
  const forced = await handle(raw({ tools: [tool], tool_choice: { type: "tool", name: tool.name } }), async () => answer([part]));
  assert.equal(forced.response.ok, true);
});

test("native-plugin helper handles lifted and removed deferred tool schemas", () => {
  const history = [{ role: "user", content: [{ type: "text", text: "Read" }, { type: "tool_addition", tool: { type: "tool_definition", definition: tool } }] }];
  assert.equal(prepare(raw({ messages: history })).tools.size, 1);
  const removed = prepare(raw({ messages: [...history, { role: "user", content: [{ type: "tool_removal", tool: { type: "tool_reference", name: tool.name } }, { type: "text", text: "Continue" }] }] }));
  assert.equal(removed.tools.size, 0);
  assert.equal(JSON.parse(removed.call.body).tools, undefined);
});

test("native-plugin helper startup check rejects alias-case preload and log settings", () => {
  assert.equal(safeStartup({}, "24.22.3"), true);
  assert.equal(safeStartup({ NODE_OPTIONS: "", NODE_EXTRA_CA_CERTS: "" }, "24.22.3"), true);
  assert.equal(safeStartup({}, "22.0.0"), false);
  for (const name of ["NODE_OPTIONS", "Node_Options", "node_extra_ca_certs", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_V8_COVERAGE", "NODE_REDIRECT_WARNINGS", "SSLKEYLOGFILE", "OPENSSL_CONF", "LD_PRELOAD"]) {
    assert.equal(safeStartup({ [name]: "fixture" }, "24.22.3"), false, name);
  }
});

test("native-plugin helper entrypoint rejects input and exits without writing local account/config state", t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-proof-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  const env: NodeJS.ProcessEnv = { PATH: process.env.PATH ?? "", HOME: temp, USERPROFILE: temp, APPDATA: temp, LOCALAPPDATA: temp };
  for (const name of ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]) if (process.env[name]) env[name] = process.env[name];
  const result = spawnSync(process.execPath, [fileURLToPath(new URL("../../packages/gemini-native/src/request.ts", import.meta.url))], {
    cwd: temp, env, input: raw({ model: "native-claude-fixture" }), encoding: "utf8", timeout: 10_000, maxBuffer: OUTPUT_LIMIT,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).response.ok, false);
  assert.doesNotMatch(result.stdout, /AIza|native-claude-fixture/);
  assert.deepEqual(fs.readdirSync(temp), []);
});
