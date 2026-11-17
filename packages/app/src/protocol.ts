// ripple://app serves bundled static assets only. Administrative requests use the separate
// senderFrame-checked preload IPC; no browser request can cause a credential read or TLS call.

import { protocol, session } from "electron";
import fs from "node:fs";
import path from "node:path";

import { routeRequest } from "./status-model";
import { DASHBOARD_CSP, isAppUrl, SCHEME } from "./security";

export { SCHEME, ORIGIN } from "./security";

/** Before app ready: a standard, secure scheme gets an origin, localStorage, fetch and the page's CSP 'self'. */
export function registerScheme(): void {
  protocol.registerSchemesAsPrivileged([{ scheme: SCHEME, privileges: { standard: true, secure: true, supportFetchAPI: true, corsEnabled: true, stream: true } }]);
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

async function serveFile(root: string, rel: string, head: boolean): Promise<Response> {
  const full = path.resolve(root, rel);
  if (full !== root && !full.startsWith(root.endsWith(path.sep) ? root : root + path.sep)) return json(400, { error: "invalid path" });
  try {
    const data = await fs.promises.readFile(full);
    return new Response(head ? null : data, { status: 200, headers: {
      "content-type": MIME[path.extname(full).toLowerCase()] ?? "application/octet-stream", "cache-control": "no-cache",
      "content-security-policy": DASHBOARD_CSP, "x-content-type-options": "nosniff", "referrer-policy": "no-referrer",
    } });
  } catch {
    return json(404, { error: "not found" });
  }
}

/** After app ready. This module deliberately has no installation, admin endpoint or capability. */
export function handleScheme(uiRoot: string): void {
  session.defaultSession.webRequest.onBeforeRequest({ urls: [`${SCHEME}://*/*`] }, (details, callback) => {
    const route = isAppUrl(details.url) ? routeRequest(new URL(details.url).pathname) : null;
    callback({ cancel: route?.kind !== "file" });
  });
  protocol.handle(SCHEME, async (request) => {
    const url = new URL(request.url);
    if (!isAppUrl(request.url)) return json(404, { error: "not found" });
    // Keep the same refusal even when invoked without Chromium's webRequest dispatch.
    if (url.pathname === "/api" || url.pathname.startsWith("/api/")) return json(403, { error: "admin API requires the native IPC bridge" });
    const route = routeRequest(url.pathname);
    if (!route || route.kind !== "file") return json(400, { error: "invalid path" });
    if (request.method !== "GET" && request.method !== "HEAD") return json(405, { error: "method not allowed" });
    return serveFile(uiRoot, route.rel, request.method === "HEAD");
  });
}
