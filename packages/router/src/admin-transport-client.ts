// Canonical authenticated admin transport. The Electron CommonJS build carries an exact copy;
// scripts/sync-admin-transport.mjs checks parity. No filesystem access or ambient HTTP proxy here.
import { X509Certificate, timingSafeEqual } from "node:crypto";
import https from "node:https";
import { Readable } from "node:stream";
import { checkServerIdentity } from "node:tls";

export interface AdminEndpoint {
  version: 1;
  instanceId: string;
  publicPort: number;
  tlsPort: number;
}
export interface AdminPublicIdentity { caCertPem: string; certPem: string }
export interface AdminRequestInit {
  method?: string | undefined;
  headers?: RequestInit["headers"];
  body?: string | Uint8Array | undefined;
  signal?: AbortSignal | undefined;
}

export const ADMIN_TLS_REQUEST_LIMIT = 32 * 1024 * 1024;
export const ADMIN_TLS_RESPONSE_LIMIT = 64 * 1024 * 1024;
export const ADMIN_TLS_CONNECT_TIMEOUT_MS = 4_000;
export const ADMIN_TLS_IDLE_TIMEOUT_MS = 180_000;
const TOKEN_HEADER = "x-clauderipple-admin";
const ALLOWED_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);

/** Validate an API path before reading credentials or opening a socket. Query strings are data. */
export function validateAdminPath(value: string): string {
  if (typeof value !== "string" || value.length > 16_384 || /[\u0000-\u0020\u007f\\#]/.test(value)) {
    throw new Error("invalid admin API path");
  }
  const url = new URL(value, "https://127.0.0.1/");
  if (url.origin !== "https://127.0.0.1" || url.pathname !== value.split("?", 1)[0] ||
      (!url.pathname.startsWith("/api/") && url.pathname !== "/readyz")) {
    throw new Error("invalid admin API path");
  }
  return url.pathname + url.search;
}

/**
 * Authenticate the server BEFORE sending a capability or request body. Normal CA, expiry and IP-SAN
 * checks stay enabled, then the exact per-install leaf is pinned. A process squatting on either
 * loopback port cannot receive HTTP headers by presenting a different certificate. No redirects,
 * no insecure fallback, no pooled TLS sessions and no system/interception CA trust are used.
 */
export function adminTlsFetch(endpoint: AdminEndpoint, identity: AdminPublicIdentity, token: string, pathname: string, init: AdminRequestInit = {}): Promise<Response> {
  const apiPath = validateAdminPath(pathname);
  if (endpoint.version !== 1 || !Number.isInteger(endpoint.publicPort) || endpoint.publicPort < 1 || endpoint.publicPort > 65_535 ||
      !Number.isInteger(endpoint.tlsPort) || endpoint.tlsPort < 1 || endpoint.tlsPort > 65_535 ||
      endpoint.publicPort === endpoint.tlsPort || typeof endpoint.instanceId !== "string" || endpoint.instanceId.length !== 32 || !/^[a-f0-9]{32}$/.test(endpoint.instanceId)) {
    throw new Error("invalid private admin endpoint");
  }
  if (typeof token !== "string" || token.length !== 64 || !/^[a-f0-9]{64}$/.test(token)) throw new Error("private admin credential is unavailable");
  if (typeof identity.caCertPem !== "string" || identity.caCertPem.length > 65_536 ||
      typeof identity.certPem !== "string" || identity.certPem.length > 65_536) throw new Error("invalid private admin identity");
  let pinned: Buffer;
  try { pinned = new X509Certificate(identity.certPem).raw; }
  catch { throw new Error("invalid private admin identity"); }
  const method = (init.method ?? "GET").toUpperCase();
  if (!ALLOWED_METHODS.has(method)) throw new Error("invalid admin HTTP method");
  const body = init.body === undefined ? undefined : typeof init.body === "string" ? Buffer.from(init.body) : Buffer.from(init.body);
  if (body && (body.length > ADMIN_TLS_REQUEST_LIMIT || method === "GET" || method === "HEAD")) throw new Error("invalid admin request body");
  const supplied = new Headers(init.headers);
  // Only ordinary representation headers cross this boundary. Callers cannot replace authority,
  // framing, browser origin, proxy authorization or the local capability.
  const headers: Record<string, string> = {
    [TOKEN_HEADER]: token, "x-clauderipple-instance-id": endpoint.instanceId, accept: supplied.get("accept") ?? "*/*",
  };
  const contentType = supplied.get("content-type");
  if (contentType) headers["content-type"] = contentType;
  const installId = supplied.get("x-clauderipple-install-id");
  if (installId) {
    if (installId.length > 256 || /[^\x21-\x7e]/.test(installId)) throw new Error("invalid admin installation identity header");
    headers["x-clauderipple-install-id"] = installId;
  }
  if (body !== undefined) headers["content-length"] = String(body.length);
  if (init.signal?.aborted) {
    const error = new Error("admin request aborted");
    error.name = "AbortError";
    return Promise.reject(error);
  }
  return new Promise((resolve, reject) => {
    let settled = false;
    const fail = (error: Error) => {
      if (settled) return;
      settled = true;
      reject(error);
    };
    const request = https.request({
      hostname: "127.0.0.1", port: endpoint.tlsPort, method, path: apiPath, headers,
      agent: false, ca: identity.caCertPem, rejectUnauthorized: true, minVersion: "TLSv1.2",
      maxHeaderSize: 16_384,
      checkServerIdentity: (_hostname, cert) => {
        if (checkServerIdentity("127.0.0.1", cert)) return new Error("admin TLS identity verification failed");
        if (!cert.raw || cert.raw.length !== pinned.length || !timingSafeEqual(cert.raw, pinned)) {
          return new Error("admin TLS certificate pin mismatch");
        }
        return undefined;
      },
    }, response => {
      const status = response.statusCode ?? 502;
      if (status >= 300 && status < 400 && status !== 304) {
        response.destroy();
        request.destroy(new Error("admin redirects are forbidden"));
        fail(new Error("admin redirects are forbidden"));
        return;
      }
      const out = new Headers();
      for (const name of ["content-type", "cache-control", "content-disposition", "content-length", "retry-after", "x-revised-prompt"]) {
        const value = response.headers[name];
        if (typeof value === "string") out.set(name, value);
      }
      const nullBody = status === 204 || status === 205 || status === 304 || method === "HEAD";
      if (nullBody) response.resume();
      try {
        const claimedLength = response.headers["content-length"];
        if (!nullBody && claimedLength !== undefined && (!/^\d+$/.test(claimedLength) || Number(claimedLength) > ADMIN_TLS_RESPONSE_LIMIT)) {
          response.destroy();
          fail(new Error("admin response exceeds the size limit"));
          return;
        }
        // Bound decoded allocation even for chunked responses. Streaming and binary images remain
        // supported; consumers cannot accidentally buffer unlimited authenticated output.
        let body: ReadableStream<Uint8Array> | null = null;
        if (!nullBody) {
          const reader = (Readable.toWeb(response) as ReadableStream<Uint8Array>).getReader();
          let bytes = 0;
          let cancelled = false;
          body = new ReadableStream<Uint8Array>({
            async pull(controller) {
              try {
                const { done, value } = await reader.read();
                if (cancelled) return;
                if (done) { controller.close(); reader.releaseLock(); return; }
                bytes += value.byteLength;
                if (bytes > ADMIN_TLS_RESPONSE_LIMIT) {
                  response.destroy();
                  request.destroy();
                  controller.error(new Error("admin response exceeds the size limit"));
                  await reader.cancel().catch(() => {});
                  return;
                }
                controller.enqueue(value);
              } catch {
                if (!cancelled) controller.error(new Error("admin response interrupted"));
              }
            },
            async cancel() {
              // Returning from an async generator does not interrupt a pending socket read.
              // Close the underlying connection explicitly even before the first consumer read.
              cancelled = true;
              response.destroy();
              request.destroy();
              await reader.cancel().catch(() => {});
            },
          });
        }
        const result = new Response(body, { status, headers: out });
        settled = true;
        resolve(result);
      } catch {
        response.destroy();
        fail(new Error("invalid admin response"));
      }
    });
    // Include the TLS handshake in this deadline; TCP connect alone is not authentication.
    const connectTimer = setTimeout(() => request.destroy(new Error("admin TLS connection timed out")), ADMIN_TLS_CONNECT_TIMEOUT_MS);
    request.once("socket", socket => socket.once("secureConnect", () => clearTimeout(connectTimer)));
    request.setTimeout(ADMIN_TLS_IDLE_TIMEOUT_MS, () => request.destroy(new Error("admin response timed out")));
    const aborted = () => request.destroy(new Error("admin request aborted"));
    init.signal?.addEventListener("abort", aborted, { once: true });
    request.once("close", () => {
      clearTimeout(connectTimer);
      init.signal?.removeEventListener("abort", aborted);
    });
    request.once("error", error => {
      clearTimeout(connectTimer);
      // The underlying error contains no token/body, but expose only a bounded fixed vocabulary.
      const safe = /^(admin TLS connection timed out|admin response timed out|admin request aborted|admin redirects are forbidden)$/.test(error.message)
        ? error.message : "admin TLS connection or identity verification failed";
      const code = (error as NodeJS.ErrnoException).code;
      const failure = new Error(safe, code === "ECONNREFUSED" ? { cause: { code: "ECONNREFUSED" } } : undefined);
      if (safe === "admin request aborted") failure.name = "AbortError";
      else if (safe === "admin TLS connection timed out" || safe === "admin response timed out") failure.name = "TimeoutError";
      fail(failure);
    });
    request.end(body);
  });
}
