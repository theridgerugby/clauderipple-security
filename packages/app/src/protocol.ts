// ripple://app/ — the dashboard drawn from this app's own copy of packages/ui, with /api/* passed
// on to the router's admin port. The router used to serve the page too, so when it died the
// dashboard died with it, exactly when it was needed (2026-10-20). Now only the data needs the
// router; a router that does not answer gives a 503 the dashboard reads as "Ripple is down".

import { protocol, session, type OnBeforeRequestListenerDetails, type WebContents } from "electron";
import fs from "node:fs";
import path from "node:path";

import { routeRequest } from "./status-model";
import { fetchAdmin, localAdminBaseUrl } from "./admin-auth";
import { ADMIN_TLS_REQUEST_LIMIT } from "./admin-transport-client";
import { DASHBOARD_CSP, isAppUrl, ORIGIN, SCHEME, trustedTopFrame } from "./security";

export { SCHEME, ORIGIN } from "./security";

/** Before app ready: a standard, secure scheme gets an origin, localStorage, fetch and the page's CSP 'self'. */
export function registerScheme(): void {
  protocol.registerSchemesAsPrivileged([{ scheme: SCHEME, privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true } }]);
}

/**
 * Only the dashboard's own top-level frame may use the main-process capability. A referrer alone is not
 * an authority: an absent/detached frame, another window, and iframe requests all fail closed.
 */
export function trustedAdminRequester(details: Pick<OnBeforeRequestListenerDetails, "webContentsId" | "frame" | "resourceType">, owned: Pick<WebContents, "id" | "mainFrame"> | null): boolean {
  try {
    return details.resourceType === "xhr" && trustedTopFrame(details.webContentsId, details.frame, owned);
  } catch { return false; }
}

const MIME: Record<string, string> = {
  ".html": "text/html; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".svg": "image/svg+xml",
  ".png": "image/png",
  ".json": "application/json",
  ".ico": "image/x-icon",
};

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", "cache-control": "no-store" } });
}

export function routerDownResponse(): Response {
  return json(503, { error: "ClaudeRipple is not running", routerDown: true });
}

/**
 * The admin API, asked as the CLI and the tray ask it: no Origin header (the router turns away a
 * cross-site Origin on writes, and a custom scheme's would be one) and a Host it accepts.
 */
async function forward(request: Request, admin: URL, home: string): Promise<Response> {
  const url = new URL(request.url);
  let body: Buffer | undefined;
  if (request.body && request.method !== "GET" && request.method !== "HEAD") {
    const reader = request.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > ADMIN_TLS_REQUEST_LIMIT) {
          await reader.cancel().catch(() => {});
          return json(413, { error: "admin request body too large" });
        }
        chunks.push(value);
      }
    } finally { reader.releaseLock(); }
    body = Buffer.concat(chunks, size);
  }
  const headers: Record<string, string> = {
    accept: request.headers.get("accept") ?? "*/*",
  };
  const type = request.headers.get("content-type");
  if (type) headers["content-type"] = type;
  try {
    return await fetchAdmin(admin.origin, `${url.pathname}${url.search}`, home, {
      method: request.method, headers, body, signal: request.signal,
    });
  } catch { return routerDownResponse(); }
}

async function serveFile(root: string, rel: string): Promise<Response> {
  const full = path.resolve(root, rel);
  if (full !== root && !full.startsWith(root.endsWith(path.sep) ? root : root + path.sep)) return json(400, { error: "invalid path" });
  try {
    const data = await fs.promises.readFile(full);
    return new Response(data, { status: 200, headers: {
      "content-type": MIME[path.extname(full).toLowerCase()] ?? "application/octet-stream", "cache-control": "no-cache",
      "content-security-policy": DASHBOARD_CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
    } });
  } catch {
    return json(404, { error: "not found" });
  }
}

/** After app ready. `admin` is read per request, so a port changed in config.json is followed. */
export function handleScheme(uiRoot: string, admin: () => string, home: string, ownedContents: () => WebContents | null): void {
  // This session belongs to the dashboard; there are no other onBeforeRequest listeners.
  // Frame identity prevents same-origin iframes and other windows from borrowing this capability.
  session.defaultSession.webRequest.onBeforeRequest({ urls: [`${SCHEME}://*/*`] }, (details, callback) => {
    let allowed = isAppUrl(details.url);
    if (allowed) {
      const route = routeRequest(new URL(details.url).pathname);
      allowed = !!route && (route.kind !== "api" || trustedAdminRequester(details, ownedContents()));
    }
    callback({ cancel: !allowed });
  });
  protocol.handle(SCHEME, async (request) => {
    const url = new URL(request.url);
    if (!isAppUrl(request.url)) return json(404, { error: "not found" });
    const route = routeRequest(url.pathname);
    if (!route) return json(400, { error: "invalid path" });
    if (route.kind === "api") {
      // The pinned patched runtime supplies this browser-owned property. Missing/opaque or
      // foreign initiators fail closed even if a request bypasses webRequest dispatch.
      if ((request as Request & { initiatorOrigin?: string }).initiatorOrigin !== ORIGIN) {
        return json(403, { error: "untrusted initiator" });
      }
      const origin = request.headers.get("origin");
      if (origin !== null && origin !== ORIGIN) return json(403, { error: "untrusted origin" });
      try { return await forward(request, localAdminBaseUrl(admin()), home); }
      catch { return json(503, { error: "local admin credentials or endpoint are unavailable" }); }
    }
    if (request.method !== "GET" && request.method !== "HEAD") return json(405, { error: "method not allowed" });
    return serveFile(uiRoot, route.rel);
  });
}
