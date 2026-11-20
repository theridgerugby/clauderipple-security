// Experimental official-mod transport. One invocation, one fixed-origin API request, then exit.
// No port, proxy, certificate installation, account discovery, filesystem write or retry.
import https from "node:https";
import tls from "node:tls";
import { type Readable, type Writable } from "node:stream";
import { GoogleStreamMapper, formatSse, toGeminiRequest, type GeminiPart } from "../../router/src/providers/google/translate.ts";
import { toolNameForResponses, toolNameRestoreMap, type AnthropicRequest } from "../../router/src/providers/chatgpt/translate.ts";

export const MODEL = "gemini-4-carbon";
export const ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/${MODEL}:generateContent`;
export const INPUT_LIMIT = 8 * 1024 * 1024;
export const UPSTREAM_LIMIT = 2 * 1024 * 1024;
export const OUTPUT_LIMIT = 3 * 1024 * 1024;
export const SIGNATURE_COUNT = 128;
export const SIGNATURE_BYTES = 512 * 1024;
export const REQUEST_TIMEOUT_MS = 110_000;

type RecordValue = Record<string, unknown>;
type Signature = [string, string];
export type Input = {
  protocol: 1;
  apiKey: string;
  request: AnthropicRequest;
  effort?: "low" | "medium" | "high";
  thoughtSignatures?: Signature[];
};
export type Output = {
  protocol: 1;
  response: { status: number; ok: boolean; headers: Record<string, string>; text: string };
  thoughtSignatures: Signature[];
};
export type GoogleCall = { url: string; headers: Record<string, string>; body: string };
export type GoogleReply = { status: number; body: string };
export type Sender = (call: GoogleCall, signal: AbortSignal) => Promise<GoogleReply>;

const MESSAGES = {
  input: "Gemini extension rejected an unsupported or oversized request. Native Claude was not invoked by this transport.",
  upstream: "Google AI Studio did not return a supported complete response. Check the Gemini API key, quota and model access.",
  timeout: "The Gemini request was cancelled or exceeded its time limit. No native Claude fallback was attempted by this transport.",
  startup: "Gemini helper startup requirements were not met. Use the validated Node 24 runtime and a clean child environment.",
  blocked: "Google AI Studio declined this generation. No native Claude fallback was attempted by this transport.",
} as const;
type ErrorCode = keyof typeof MESSAGES;
class Refusal extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode) { super(code); this.code = code; }
}
const record = (value: unknown): value is RecordValue => typeof value === "object" && value !== null && !Array.isArray(value);
const integer = (value: unknown, limit: number): value is number => typeof value === "number" && Number.isSafeInteger(value) && value >= 0 && value <= limit;
const validTool = (tool: unknown): boolean => record(tool) && typeof tool.name === "string" && !!tool.name && tool.name.length <= 256 &&
  (tool.description === undefined || typeof tool.description === "string") && (tool.input_schema === undefined || record(tool.input_schema));

export function refusal(code: ErrorCode): Output {
  // A terminal client error avoids an automatic retry loop through Claude's transport. Never
  // forward upstream error text, arbitrary headers, request ids or exceptions into the transcript.
  return { protocol: 1, response: { status: 400, ok: false, headers: { "content-type": "application/json" },
    text: JSON.stringify({ type: "error", error: { type: "invalid_request_error", message: MESSAGES[code] } }) }, thoughtSignatures: [] };
}

function validateDepth(value: unknown): void {
  const pending: [unknown, number][] = [[value, 0]];
  let nodes = 0;
  while (pending.length) {
    const [item, depth] = pending.pop()!;
    if (++nodes > 200_000 || depth > 64) throw new Refusal("input");
    const queue = (child: unknown): void => {
      if (nodes + pending.length >= 200_000) throw new Refusal("input");
      pending.push([child, depth + 1]);
    };
    if (Array.isArray(item)) for (const child of item) queue(child);
    else if (record(item)) for (const key in item) if (Object.hasOwn(item, key)) queue(item[key]);
  }
}

function validateBlocks(value: unknown, level = 0): void {
  if (typeof value === "string") return;
  if (!Array.isArray(value) || level > 8) throw new Refusal("input");
  for (const block of value) {
    if (!record(block) || typeof block.type !== "string") throw new Refusal("input");
    switch (block.type) {
      case "text": if (typeof block.text !== "string") throw new Refusal("input"); break;
      case "thinking": case "redacted_thinking": break; // Native reasoning is not replayed to Google.
      case "tool_use":
        if (typeof block.id !== "string" || !block.id || typeof block.name !== "string" || !block.name || !record(block.input)) throw new Refusal("input");
        break;
      case "tool_result":
        if (typeof block.tool_use_id !== "string" || !block.tool_use_id) throw new Refusal("input");
        if (block.content !== undefined) validateBlocks(block.content, level + 1);
        break;
      case "image":
        if (!record(block.source) || block.source.type !== "base64" || typeof block.source.data !== "string" || typeof block.source.media_type !== "string") throw new Refusal("input");
        break;
      case "document":
        if (!record(block.source) || typeof block.source.type !== "string" || !["base64", "text"].includes(block.source.type) || typeof block.source.data !== "string") throw new Refusal("input");
        if (block.source.type === "base64" && block.source.media_type !== "application/pdf") throw new Refusal("input");
        break;
      case "tool_addition":
        if (!record(block.tool) || !validTool(block.tool.definition)) throw new Refusal("input");
        break;
      case "tool_removal":
        if (!record(block.tool) || block.tool.type !== "tool_reference" || typeof block.tool.name !== "string" || !block.tool.name) throw new Refusal("input");
        break;
      case "tool_reference":
        if (typeof block.tool_name !== "string" || !block.tool_name) throw new Refusal("input");
        break;
      default: throw new Refusal("input"); // Never silently ignore a newly introduced native block.
    }
  }
}

function signatures(value: unknown): Map<string, string> {
  if (value === undefined) return new Map();
  if (!Array.isArray(value) || value.length > SIGNATURE_COUNT) throw new Refusal("input");
  const result = new Map<string, string>();
  let bytes = 0;
  for (const entry of value) {
    if (!Array.isArray(entry) || entry.length !== 2 || typeof entry[0] !== "string" || !entry[0] || entry[0].length > 256 ||
        typeof entry[1] !== "string" || !entry[1] || entry[1].length > 16 * 1024 || result.has(entry[0])) throw new Refusal("input");
    bytes += Buffer.byteLength(entry[0]) + Buffer.byteLength(entry[1]);
    if (bytes > SIGNATURE_BYTES) throw new Refusal("input");
    result.set(entry[0], entry[1]);
  }
  return result;
}

function input(raw: string): { value: Input; signatures: Map<string, string> } {
  if (Buffer.byteLength(raw) > INPUT_LIMIT) throw new Refusal("input");
  let value: unknown;
  try { value = JSON.parse(raw); } catch { throw new Refusal("input"); }
  validateDepth(value);
  if (!record(value) || value.protocol !== 1 || Object.keys(value).some(key => !["protocol", "apiKey", "request", "effort", "thoughtSignatures"].includes(key)) ||
      typeof value.apiKey !== "string" || !/^[A-Za-z0-9_-]{16,256}$/.test(value.apiKey) ||
      value.effort !== undefined && (typeof value.effort !== "string" || !["low", "medium", "high"].includes(value.effort))) throw new Refusal("input");
  const request = value.request;
  if (!record(request) || request.model !== MODEL || !Array.isArray(request.messages) || request.messages.length === 0 || request.messages.length > 4096 ||
      request.stream !== undefined && typeof request.stream !== "boolean" ||
      request.max_tokens !== undefined && (!integer(request.max_tokens, 2 ** 31 - 1) || request.max_tokens === 0)) throw new Refusal("input");
  for (const message of request.messages) {
    if (!record(message) || typeof message.role !== "string" || !["user", "assistant"].includes(message.role)) throw new Refusal("input");
    validateBlocks(message.content);
  }
  if (request.system !== undefined && typeof request.system !== "string") {
    if (!Array.isArray(request.system) || request.system.some(block => !record(block) || typeof block.text !== "string" || block.type !== undefined && block.type !== "text")) throw new Refusal("input");
  }
  if (request.tools !== undefined && (!Array.isArray(request.tools) || request.tools.length > 512 || request.tools.some(tool => !validTool(tool)))) throw new Refusal("input");
  if (request.tool_choice !== undefined && (!record(request.tool_choice) || typeof request.tool_choice.type !== "string" || !["auto", "any", "none", "tool"].includes(request.tool_choice.type) ||
      request.tool_choice.type === "tool" && (typeof request.tool_choice.name !== "string" || !request.tool_choice.name) ||
      request.tool_choice.disable_parallel_tool_use !== undefined && typeof request.tool_choice.disable_parallel_tool_use !== "boolean")) throw new Refusal("input");
  return { value: value as Input, signatures: signatures(value.thoughtSignatures) };
}

/** Fresh headers and a hard-coded endpoint. No host URL, Claude credentials or metadata are reused. */
export function prepare(raw: string): { value: Input; call: GoogleCall; tools: Set<string>; minCalls: number; maxCalls: number } {
  const parsed = input(raw);
  const { value } = parsed;
  const body = toGeminiRequest(value.request, { model: MODEL, effort: value.effort ?? "medium", thoughtSignatures: parsed.signatures, signatureSentinel: false });
  if (body.contents.length === 0) throw new Refusal("input");
  const removed = new Set<string>();
  for (const message of value.request.messages) if (Array.isArray(message.content)) for (const block of message.content) {
    if (block.type === "tool_removal") removed.add(toolNameForResponses((block.tool as RecordValue).name as string));
    if (block.type === "tool_addition") removed.delete(toolNameForResponses(((block.tool as RecordValue).definition as RecordValue).name as string));
  }
  for (const tool of value.request.tools ?? []) removed.delete(toolNameForResponses(tool.name));
  if (body.tools) body.tools = body.tools.map(tool => ({ functionDeclarations: tool.functionDeclarations.filter(declaration => !removed.has(declaration.name)) }));
  const declarations = body.tools?.flatMap(tool => tool.functionDeclarations) ?? [];
  const names = declarations.map(tool => tool.name);
  if (names.length > 512 || new Set(names).size !== names.length) throw new Refusal("input");
  if (names.length === 0) { delete body.tools; delete body.toolConfig; }
  const choice = value.request.tool_choice;
  const forced = choice?.type === "tool" ? toolNameForResponses(choice.name!) : undefined;
  if (forced && !names.includes(forced) || choice?.type === "any" && names.length === 0) throw new Refusal("input");
  const tools = new Set(choice?.type === "none" ? [] : forced ? [forced] : names);
  const minCalls = choice?.type === "any" || forced ? 1 : 0;
  const maxCalls = choice?.type === "none" ? 0 : choice?.disable_parallel_tool_use ? 1 : SIGNATURE_COUNT;
  const text = JSON.stringify(body);
  if (Buffer.byteLength(text) > INPUT_LIMIT) throw new Refusal("input");
  return { value, tools, minCalls, maxCalls, call: { url: ENDPOINT, body: text,
    headers: { "content-type": "application/json", accept: "application/json", "x-goog-api-key": value.apiKey } } };
}

function validateReply(reply: GoogleReply, tools: Set<string>, minCalls: number, maxCalls: number): { candidates: { content: { parts: GeminiPart[] }; finishReason: string }[]; usageMetadata?: RecordValue } {
  if (reply.status !== 200 || Buffer.byteLength(reply.body) > UPSTREAM_LIMIT) throw new Refusal("upstream");
  const value: unknown = JSON.parse(reply.body);
  validateDepth(value);
  if (!record(value)) throw new Refusal("upstream");
  if (record(value.promptFeedback) && value.promptFeedback.blockReason) throw new Refusal("blocked");
  if (value.error || !Array.isArray(value.candidates) || value.candidates.length !== 1) throw new Refusal("upstream");
  const candidate: unknown = value.candidates[0];
  if (!record(candidate) || typeof candidate.finishReason !== "string" || !["STOP", "MAX_TOKENS"].includes(candidate.finishReason) || !record(candidate.content) || !Array.isArray(candidate.content.parts) ||
      candidate.content.role !== undefined && candidate.content.role !== "model") throw new Refusal("upstream");
  const parts: GeminiPart[] = [];
  let calls = 0;
  for (const part of candidate.content.parts) {
    if (!record(part) || Object.keys(part).some(key => !["text", "thought", "thoughtSignature", "functionCall"].includes(key))) throw new Refusal("upstream");
    if (part.thought !== undefined && typeof part.thought !== "boolean") throw new Refusal("upstream");
    if (part.thoughtSignature !== undefined && (typeof part.thoughtSignature !== "string" || part.thoughtSignature.length > 16 * 1024)) throw new Refusal("upstream");
    if (part.functionCall !== undefined) {
      const call = part.functionCall;
      if (++calls > maxCalls || part.text !== undefined || part.thought === true || !record(call) || typeof call.name !== "string" || !tools.has(call.name) || call.args !== undefined && !record(call.args)) throw new Refusal("upstream");
      parts.push({ functionCall: { name: call.name, args: (call.args ?? {}) as RecordValue },
        ...(typeof part.thoughtSignature === "string" && part.thoughtSignature ? { thoughtSignature: part.thoughtSignature } : {}) });
    } else if (typeof part.text === "string") {
      // Do not add unsigned Gemini thinking blocks to history that native Claude may later read.
      if (part.thought !== true && part.text) parts.push({ text: part.text });
    } else throw new Refusal("upstream");
  }
  if (!parts.length || calls < minCalls) throw new Refusal("upstream");
  if (value.usageMetadata !== undefined && (!record(value.usageMetadata) || ["promptTokenCount", "candidatesTokenCount", "cachedContentTokenCount", "thoughtsTokenCount"].some(key =>
    (value.usageMetadata as RecordValue)[key] !== undefined && !integer((value.usageMetadata as RecordValue)[key], 10 ** 12)))) throw new Refusal("upstream");
  return { candidates: [{ content: { parts }, finishReason: candidate.finishReason }],
    ...(record(value.usageMetadata) ? { usageMetadata: value.usageMetadata } : {}) };
}

/** Fully buffered proof. It intentionally does not claim incremental rendering or host acceptance. */
export async function handle(raw: string, send: Sender = sendGoogle, signal: AbortSignal = AbortSignal.timeout(REQUEST_TIMEOUT_MS)): Promise<Output> {
  try {
    const prepared = prepare(raw);
    if (signal.aborted) throw new Refusal("timeout");
    const reply = await send(prepared.call, signal);
    if (signal.aborted) throw new Refusal("timeout");
    const chunk = validateReply(reply, prepared.tools, prepared.minCalls, prepared.maxCalls);
    const fresh: Signature[] = [];
    const mapper = new GoogleStreamMapper(MODEL, 0, toolNameRestoreMap(prepared.value.request), call => { if (call.signature) fresh.push([call.id, call.signature]); });
    mapper.redactError = () => MESSAGES.upstream;
    const events = [...mapper.feed(chunk), ...mapper.finish()];
    if (!mapper.completed || mapper.failure) throw new Refusal("upstream");
    signatures(fresh);
    const stream = prepared.value.request.stream === true;
    const output: Output = { protocol: 1, response: { status: 200, ok: true,
      headers: { "content-type": stream ? "text/event-stream" : "application/json" },
      text: stream ? events.map(formatSse).join("") : JSON.stringify(mapper.message()) }, thoughtSignatures: fresh };
    if (Buffer.byteLength(JSON.stringify(output)) >= OUTPUT_LIMIT) throw new Refusal("upstream");
    return output;
  } catch (error) {
    return refusal(signal.aborted ? "timeout" : error instanceof Refusal ? error.code : "upstream");
  }
}

export function sendGoogle(call: GoogleCall, signal: AbortSignal): Promise<GoogleReply> {
  // A new built-in Agent ignores a potentially proxy-configured globalAgent. Explicit bundled
  // roots exclude the legacy local interception CA and NODE_EXTRA_CA_CERTS from this connection.
  if (call.url !== ENDPOINT || Object.keys(call.headers).sort().join() !== "accept,content-type,x-goog-api-key") return Promise.reject(new Refusal("input"));
  const roots = [...tls.rootCertificates];
  const agent = new https.Agent({ keepAlive: false, maxSockets: 1, proxyEnv: {}, ca: roots, rejectUnauthorized: true });
  return new Promise((resolve, reject) => {
    let complete = false;
    const done = (error?: Error, reply?: GoogleReply): void => {
      if (complete) return;
      complete = true;
      clearTimeout(timer);
      agent.destroy();
      if (error) reject(error); else resolve(reply!);
    };
    // This total deadline covers DNS, connection, headers and a peer dripping an incomplete body.
    let request: ReturnType<typeof https.request> | undefined;
    const timer = setTimeout(() => { done(new Refusal("timeout")); request?.destroy(); }, REQUEST_TIMEOUT_MS);
    try {
    request = https.request(ENDPOINT, { method: "POST", headers: call.headers, agent, signal,
      ca: roots, rejectUnauthorized: true, minVersion: "TLSv1.2", checkServerIdentity: tls.checkServerIdentity }, response => {
      if (response.statusCode !== 200 || response.headers["content-encoding"] && response.headers["content-encoding"] !== "identity" ||
          !/^application\/json(?:\s*;|$)/i.test(response.headers["content-type"] ?? "")) {
        response.destroy(); done(new Refusal("upstream")); return;
      }
      const chunks: Buffer[] = [];
      let bytes = 0;
      response.on("data", (chunk: Buffer) => {
        bytes += chunk.length;
        if (bytes > UPSTREAM_LIMIT || chunks.length >= 8192) { response.destroy(); done(new Refusal("upstream")); }
        else chunks.push(chunk);
      });
      response.on("error", () => done(new Refusal("upstream")));
      response.on("aborted", () => done(new Refusal("upstream")));
      response.on("end", () => done(undefined, { status: 200, body: Buffer.concat(chunks).toString("utf8") }));
    });
    request.on("error", () => done(new Refusal(signal.aborted ? "timeout" : "upstream")));
    request.end(call.body);
    } catch { request?.destroy(); done(new Refusal(signal.aborted ? "timeout" : "upstream")); }
  });
}

export function safeStartup(env: NodeJS.ProcessEnv, nodeVersion: string): boolean {
  if (!/^24\./.test(nodeVersion)) return false;
  const sensitive = /^(?:NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|NODE_USE_SYSTEM_CA|NODE_USE_ENV_PROXY|NODE_DEBUG|NODE_DEBUG_NATIVE|NODE_V8_COVERAGE|NODE_REDIRECT_WARNINGS|SSLKEYLOGFILE|SSL_CERT_FILE|SSL_CERT_DIR|OPENSSL_CONF|OPENSSL_MODULES|LD_PRELOAD|LD_LIBRARY_PATH|DYLD_INSERT_LIBRARIES|DYLD_LIBRARY_PATH)$/i;
  return !Object.entries(env).some(([key, value]) => sensitive.test(key) && value);
}

async function readInput(source: Readable): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  const timer = setTimeout(() => source.destroy(new Refusal("input")), 10_000);
  try {
    for await (const value of source) {
      const chunk = Buffer.isBuffer(value) ? value : Buffer.from(value);
      size += chunk.length;
      if (size > INPUT_LIMIT || chunks.length >= 8192) { source.destroy(); throw new Refusal("input"); }
      chunks.push(chunk);
    }
    return Buffer.concat(chunks).toString("utf8");
  } finally { clearTimeout(timer); }
}

export async function main(source: Readable = process.stdin, destination: Writable = process.stdout): Promise<void> {
  const abort = new AbortController();
  const stop = (): void => { abort.abort(); source.destroy(); };
  process.once("SIGTERM", stop);
  process.once("SIGINT", stop);
  let output: Output;
  try {
    if (!safeStartup(process.env, process.versions.node)) { source.destroy(); output = refusal("startup"); }
    else output = await handle(await readInput(source), sendGoogle, abort.signal);
  } catch { output = refusal(abort.signal.aborted ? "timeout" : "input"); }
  finally { process.off("SIGTERM", stop); process.off("SIGINT", stop); }
  // stdout is a bounded machine-only result. No diagnostics or credentials go to stderr.
  await new Promise<void>(resolve => { destination.once("error", () => resolve()); destination.write(JSON.stringify(output) + "\n", () => resolve()); });
}

if (import.meta.main) await main();
