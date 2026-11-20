// The renderer never receives a local capability or a network proxy. Only this narrow IPC
// handler can read private transport state, after Electron identifies the actual sender frame.
import type { IpcMainInvokeEvent, WebContents } from "electron";
import { fetchAdmin } from "./admin-auth.ts";
import { validateAdminPath } from "./admin-transport-client.ts";
import { trustedIpcSender } from "./security.ts";
import { personalDesktopAdminRequestAllowed } from "./personal-admin-policy.ts";

export const ADMIN_IPC_CHANNEL = "ripple-app:admin-request";
export const ADMIN_IPC_REQUEST_LIMIT = 2 * 1024 * 1024;
export const ADMIN_IPC_RESPONSE_LIMIT = 8 * 1024 * 1024;
export const ADMIN_IPC_CONCURRENCY = 4;
export const ADMIN_IPC_TIMEOUT_MS = 60_000;
const METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
const REQUEST_FIELDS = new Set(["path", "method", "headers", "body"]);
const REPRESENTATION_HEADERS = new Set(["accept", "content-type"]);

export interface AdminIpcRequest {
  path: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}
export interface AdminIpcResponse {
  status: number;
  headers: Record<string, string>;
  body: Uint8Array;
}
type Sender = Pick<IpcMainInvokeEvent, "sender" | "senderFrame">;
type Owner = Pick<WebContents, "id" | "mainFrame">;
interface Options {
  ownedContents: () => Owner | null;
  admin: () => string;
  home: string;
  /** Dependency replacement for isolated tests; production uses the pinned TLS reader. */
  transport?: typeof fetchAdmin;
}

function failure(status: number, error: string, routerDown = false): AdminIpcResponse {
  return { status, headers: { "content-type": "application/json", "cache-control": "no-store" },
    body: new Uint8Array(Buffer.from(JSON.stringify(routerDown ? { error, routerDown: true } : { error }))) };
}

/** Only plain data fields are accepted, with no accessors, symbols or extra IPC options. */
function record(value: unknown, maxKeys: number): value is Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== null && prototype !== Object.prototype) return false;
  const keys = Reflect.ownKeys(value);
  return keys.length <= maxKeys && keys.every(key => {
    if (typeof key !== "string") return false;
    const descriptor = Object.getOwnPropertyDescriptor(value, key);
    return !!descriptor?.enumerable && Object.prototype.hasOwnProperty.call(descriptor, "value");
  });
}

function validate(value: unknown): AdminIpcRequest & { method: string; headers: Record<string, string> } {
  if (!record(value, 4) || Object.keys(value).some(key => !REQUEST_FIELDS.has(key)) ||
      typeof value.path !== "string" || !value.path.startsWith("/api/")) throw new Error("invalid request");
  const pathname = validateAdminPath(value.path);
  if (value.method !== undefined && (typeof value.method !== "string" || value.method.length > 8)) throw new Error("invalid method");
  const method = ((value.method as string | undefined) ?? "GET").toUpperCase();
  if (!METHODS.has(method)) throw new Error("invalid method");
  const bodyPresent = Object.prototype.hasOwnProperty.call(value, "body");
  if (bodyPresent && (typeof value.body !== "string" || method === "GET" || method === "HEAD")) throw new Error("invalid body");
  if (typeof value.body === "string" && (value.body.length > ADMIN_IPC_REQUEST_LIMIT ||
      Buffer.byteLength(value.body, "utf8") > ADMIN_IPC_REQUEST_LIMIT)) throw new RangeError("request too large");
  const headers: Record<string, string> = {};
  if (value.headers !== undefined) {
    if (!record(value.headers, 2)) throw new Error("invalid headers");
    for (const [key, field] of Object.entries(value.headers)) {
      if (key.length > 32 || typeof field !== "string" || field.length > 1024 || /[^\t\x20-\x7e]/.test(field)) throw new Error("invalid header");
      const name = key.toLowerCase();
      if (!REPRESENTATION_HEADERS.has(name) || Object.prototype.hasOwnProperty.call(headers, name)) throw new Error("invalid header");
      headers[name] = field;
    }
  }
  return { path: pathname, method, headers, ...(bodyPresent ? { body: value.body as string } : {}) };
}

/** One handler per installation/window, with one shared budget across all its IPC callers. */
export function createAdminRequestHandler(options: Options): (event: Sender, value: unknown) => Promise<AdminIpcResponse> {
  let active = 0;
  const transport = options.transport ?? fetchAdmin;
  return async (event, value) => {
    // webRequest.frame is not an authority: Chromium can attribute a child fetch to the top
    // frame. IPC's senderFrame belongs to this invocation and must pass before any state read.
    if (!trustedIpcSender(event, options.ownedContents())) return failure(403, "untrusted admin caller");
    let request: ReturnType<typeof validate>;
    try { request = validate(value); }
    catch (error) { return error instanceof RangeError ? failure(413, "admin request body too large") : failure(400, "invalid admin request"); }
    if (!personalDesktopAdminRequestAllowed(request.path)) return failure(403, "This operation is unavailable in the personal Desktop dashboard");
    if (active >= ADMIN_IPC_CONCURRENCY) return failure(429, "too many admin requests");
    active++;
    const abort = new AbortController();
    let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
    let expired = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const deadline = performance.now() + ADMIN_IPC_TIMEOUT_MS;
    const timeout = new Promise<AdminIpcResponse>(resolve => {
      timer = setTimeout(() => {
        expired = true;
        abort.abort();
        void reader?.cancel().catch(() => {});
        resolve(failure(504, "admin request timed out"));
      }, ADMIN_IPC_TIMEOUT_MS);
    });
    const work = (async (): Promise<AdminIpcResponse> => {
      try {
        const response = await transport(options.admin(), request.path, options.home, {
          method: request.method, headers: request.headers,
          ...(request.body === undefined ? {} : { body: request.body }), signal: abort.signal,
        });
        if (expired || performance.now() >= deadline) {
          expired = true; abort.abort(); void response.body?.cancel().catch(() => {});
          return failure(504, "admin request timed out");
        }
        if (!trustedIpcSender(event, options.ownedContents())) {
          abort.abort(); void response.body?.cancel().catch(() => {});
          return failure(403, "untrusted admin caller");
        }
        const headers: Record<string, string> = {};
        for (const name of ["content-type", "cache-control"]) {
          const field = response.headers.get(name);
          if (field !== null) headers[name] = field;
        }
        if (request.method === "HEAD" || [204, 205, 304].includes(response.status) || !response.body) {
          await response.body?.cancel();
          return { status: response.status, headers, body: new Uint8Array() };
        }
        const claimedLength = response.headers.get("content-length");
        if (claimedLength !== null && (!/^\d+$/.test(claimedLength) || Number(claimedLength) > ADMIN_IPC_RESPONSE_LIMIT)) {
          abort.abort(); void response.body.cancel().catch(() => {});
          return failure(502, "admin response exceeds the size limit");
        }
        reader = response.body.getReader();
        const chunks: Uint8Array[] = [];
        let length = 0;
        for (;;) {
          const { done, value: chunk } = await reader.read();
          if (expired || performance.now() >= deadline) {
            expired = true; abort.abort(); void reader.cancel().catch(() => {});
            return failure(504, "admin request timed out");
          }
          if (done) break;
          length += chunk.byteLength;
          if (length > ADMIN_IPC_RESPONSE_LIMIT) {
            abort.abort(); void reader.cancel().catch(() => {});
            return failure(502, "admin response exceeds the size limit");
          }
          chunks.push(chunk);
        }
        if (!trustedIpcSender(event, options.ownedContents())) return failure(403, "untrusted admin caller");
        const body = new Uint8Array(length);
        let offset = 0;
        for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
        return { status: response.status, headers, body };
      } catch {
        return expired ? failure(504, "admin request timed out") : failure(503, "ClaudeRipple is not running", true);
      } finally {
        try { reader?.releaseLock(); } catch { /* A cancelled stream may already be detached. */ }
        // A timed-out request keeps its slot until cancellation actually settles its work.
        active--;
      }
    })();
    try { return await Promise.race([work, timeout]); }
    finally { if (timer !== undefined) clearTimeout(timer); }
  };
}
