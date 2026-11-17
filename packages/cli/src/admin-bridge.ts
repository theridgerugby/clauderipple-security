// One bounded native process per request from the Claude mods engine. Request data is stdin;
// the credential and pinned certificate are read natively, never handed to the mod or its argv.
import { homeDir } from "../../router/src/config.ts";
import { adminFetch, localAdminUrl } from "./admin-client.ts";
import { openNativeDashboard, type AdminView } from "./native-ui.ts";

export const ADMIN_BRIDGE_MAX_BYTES = 3 * 1024 * 1024;
const ERROR_MESSAGE = "Secure ClaudeRipple admin bridge failed. Start or upgrade ClaudeRipple and run `clauderipple mod on`; no HTTP fallback was used.";
type BridgeRequest = { kind: "request"; url: string; method: string; headers: Record<string, string>; body?: string; timeoutMs: number };
type BridgeUi = { kind: "ui"; view: AdminView };

export function parseBridgeRequest(value: unknown): BridgeRequest | BridgeUi {
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error(ERROR_MESSAGE);
  const row = value as Record<string, unknown>;
  if (row.kind === "ui" && (row.view === "dashboard" || row.view === "mod")) return { kind: "ui", view: row.view };
  if (row.kind !== "request" || typeof row.url !== "string" || row.url.length > 16_384 ||
      (row.method !== undefined && !["GET", "POST", "PUT", "DELETE", "PATCH"].includes(String(row.method))) ||
      (row.body !== undefined && typeof row.body !== "string")) throw new Error(ERROR_MESSAGE);
  localAdminUrl(row.url);
  const timeoutMs = row.timeoutMs ?? 15_000;
  if (!Number.isSafeInteger(timeoutMs) || Number(timeoutMs) < 1 || Number(timeoutMs) > 30_000) throw new Error(ERROR_MESSAGE);
  const headers = row.headers ?? {};
  if (!headers || typeof headers !== "object" || Array.isArray(headers)) throw new Error(ERROR_MESSAGE);
  const safe: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    // Only request metadata used by this bridge. A mod cannot replace Host, authorization or
    // connection semantics, and it never supplies the installation capability.
    const key = name.toLowerCase();
    if (!["content-type", "accept", "x-clauderipple-install-id"].includes(key) ||
        typeof value !== "string" || value.length > 4096 || /[\r\n\0]/.test(value)) throw new Error(ERROR_MESSAGE);
    safe[key] = value;
  }
  return { kind: "request", url: row.url, method: String(row.method ?? "GET"), headers: safe,
    ...(typeof row.body === "string" ? { body: row.body } : {}), timeoutMs: Number(timeoutMs) };
}

export async function executeBridgeRequest(value: unknown, home: string, deps: {
  fetch?: typeof adminFetch;
  open?: typeof openNativeDashboard;
} = {}): Promise<unknown> {
  const request = parseBridgeRequest(value);
  if (request.kind === "ui") return (deps.open ?? openNativeDashboard)(home, request.view);
  const response = await (deps.fetch ?? adminFetch)(request.url, {
    method: request.method, headers: request.headers,
    ...(request.body !== undefined ? { body: request.body } : {}),
    signal: AbortSignal.timeout(request.timeoutMs),
  }, home);
  const chunks: Buffer[] = [];
  let bytes = 0;
  const reader = response.body?.getReader();
  if (reader) {
    try {
      for (;;) {
        const chunk = await reader.read();
        if (chunk.done) break;
        bytes += chunk.value.byteLength;
        if (bytes > ADMIN_BRIDGE_MAX_BYTES) { await reader.cancel(); throw new Error(ERROR_MESSAGE); }
        chunks.push(Buffer.from(chunk.value));
      }
    } finally { reader.releaseLock(); }
  }
  const text = Buffer.concat(chunks).toString("utf8");
  return { status: response.status, ok: response.ok, headers: Object.fromEntries(response.headers), text };
}

export async function runAdminBridge(input: AsyncIterable<Uint8Array | string>, home: string, deps: Parameters<typeof executeBridgeRequest>[2] = {}): Promise<string> {
  const chunks: Buffer[] = [];
  let bytes = 0;
  for await (const chunk of input) {
    const value = Buffer.from(chunk);
    bytes += value.length;
    if (bytes > ADMIN_BRIDGE_MAX_BYTES) throw new Error(ERROR_MESSAGE);
    chunks.push(value);
  }
  const result = await executeBridgeRequest(JSON.parse(Buffer.concat(chunks).toString("utf8")), home, deps);
  const output = JSON.stringify(result);
  if (Buffer.byteLength(output) > ADMIN_BRIDGE_MAX_BYTES) throw new Error(ERROR_MESSAGE);
  return output;
}

if (import.meta.main) {
  const timer = setTimeout(() => process.exit(1), 35_000);
  timer.unref();
  try { process.stdout.write(await runAdminBridge(process.stdin, homeDir())); }
  catch { process.stderr.write(ERROR_MESSAGE + "\n"); process.exitCode = 1; }
  finally { clearTimeout(timer); }
}
