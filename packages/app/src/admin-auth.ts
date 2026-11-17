// The Electron main process reads the same installation capability as the CLI. Keep this
// module out of preload/renderer code: the page only asks the authenticated protocol bridge.
// The app has a separate CommonJS rootDir, so it cannot import the router's TypeScript module.

import fs from "node:fs";
import path from "node:path";
import { verifyWindowsPrivateAcl } from "./windows-private-acl.ts";
import { adminTlsFetch, validateAdminPath, type AdminEndpoint, type AdminPublicIdentity } from "./admin-transport-client.ts";

export const ADMIN_TOKEN_HEADER = "x-clauderipple-admin";

/** Never creates or repairs transport state. Exposed credentials must be rotated. */
function privateAdminText(home: string, name: string, limit: number): string | undefined {
  const file = path.join(home, name);
  let fd: number;
  let before: fs.Stats;
  try {
    before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) throw new Error("admin credential must be a regular private file");
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) throw new Error("admin credential must be a regular private file");
    if (stat.dev !== before.dev || stat.ino !== before.ino) throw new Error("admin credential changed while opening it");
    if (stat.size > limit) throw new Error("invalid private admin state file");
    if (process.platform !== "win32") {
      if (typeof process.getuid === "function" && stat.uid !== process.getuid()) throw new Error("admin credential must belong to the current user");
      if ((stat.mode & 0o077) !== 0) throw new Error("admin credential permissions must be owner-only (0600)");
    } else {
      // Do not assume Node's file timestamps track every native Windows DACL change.
      // Check existing permissions on every new-namespace read without silently repairing them.
      verifyWindowsPrivateAcl(file, false);
      const after = fs.lstatSync(file);
      if (after.isSymbolicLink() || after.nlink !== 1 || after.dev !== stat.dev || after.ino !== stat.ino) {
        throw new Error("admin credential changed while verifying its permissions");
      }
    }
    // A writer growing the file after fstat cannot turn credential reading into an unbounded allocation.
    const bytes = Buffer.alloc(limit + 1);
    let total = 0;
    while (total < bytes.length) {
      const count = fs.readSync(fd, bytes, total, bytes.length - total, null);
      if (!count) break;
      total += count;
    }
    if (total > limit) throw new Error("invalid private admin state file");
    return bytes.subarray(0, total).toString("utf8");
  } finally {
    fs.closeSync(fd);
  }
}

/** The old HTTP-only client's token is deliberately a different file and is never accepted. */
export function adminAuthHeaders(home: string): Record<string, string> {
  const text = privateAdminText(home, "admin-tls-token", 65);
  if (text === undefined) return {};
  const token = text.trim();
  if (!/^[a-f0-9]{64}$/.test(token)) throw new Error("invalid admin credential file");
  return { [ADMIN_TOKEN_HEADER]: token };
}

/** A config origin identifies an installation; it is never an HTTP credential destination. */
export function localAdminBaseUrl(value: string): URL {
  const url = new URL(value);
  if (url.protocol !== "http:" || url.hostname !== "127.0.0.1" || url.username || url.password ||
      url.pathname !== "/" || url.search || url.hash) {
    throw new Error("admin URL must be an http://127.0.0.1:<port>/ origin");
  }
  return url;
}

function privateAdminJson(home: string, name: string): Record<string, unknown> {
  const text = privateAdminText(home, name, 64 * 1024);
  if (text === undefined) throw new Error("private admin transport state is unavailable; start the updated router");
  try {
    const value: unknown = JSON.parse(text);
    if (value && typeof value === "object" && !Array.isArray(value)) return value as Record<string, unknown>;
  } catch { /* Parsing diagnostics must not include a private key or a credential. */ }
  throw new Error("invalid private admin transport state");
}

/** Main-process API requests, including tray polling, power changes, and updates, all use pinned TLS. */
export function fetchAdmin(base: string, pathname: string, home: string, init: Omit<RequestInit, "body"> & { body?: string | Uint8Array | null } = {}): Promise<Response> {
  const origin = localAdminBaseUrl(base);
  validateAdminPath(pathname);
  const endpoint = privateAdminJson(home, "admin-tls-endpoint.json");
  const identity = privateAdminJson(home, "admin-tls-identity.json");
  if (endpoint.version !== 1 || endpoint.publicPort !== Number(origin.port || 80) ||
      typeof endpoint.instanceId !== "string" || endpoint.instanceId.length !== 32 || !/^[a-f0-9]{32}$/.test(endpoint.instanceId) ||
      endpoint.publicPort === endpoint.tlsPort || identity.version !== 1 ||
      typeof identity.caCertPem !== "string" || typeof identity.certPem !== "string") {
    throw new Error("invalid or mismatched private admin transport state");
  }
  const token = adminAuthHeaders(home)[ADMIN_TOKEN_HEADER];
  if (!token) throw new Error("private admin credential is unavailable");
  if (init.body != null && typeof init.body !== "string" && !(init.body instanceof Uint8Array)) {
    throw new Error("unsupported admin request body");
  }
  return adminTlsFetch(endpoint as unknown as AdminEndpoint, identity as unknown as AdminPublicIdentity, token, pathname, {
    method: init.method, headers: init.headers, body: (init.body ?? undefined) as string | Uint8Array | undefined,
    signal: init.signal ?? undefined,
  });
}
