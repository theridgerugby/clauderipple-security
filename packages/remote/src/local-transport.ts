// A separate installation capability for the remote host's local administration. Phone/relay
// pairing secrets and the legacy plaintext local.secret are never used on this transport.
import path from "node:path";
import fs from "node:fs";
import { readAdminToken, adminTokenPath, parseAdminToken } from "../../router/src/admin-auth.ts";
import { readAdminEndpoint, readAdminTlsIdentity, adminTransportPaths, parseAdminEndpoint,
  parseAdminStateJson, parseAdminTlsIdentity } from "../../router/src/admin-transport-state.ts";
import { adminTlsFetch, validateAdminPath, type AdminRequestInit } from "../../router/src/admin-transport-client.ts";
import { readPrivateFilesStrict } from "../../router/src/private-file.ts";
import { loadConfig, remoteHome, DEFAULT_PORT, parseStoredHostConfig } from "./config.ts";

export function localControlHome(dir = remoteHome()): string { return path.join(dir, "local-control-tls"); }

/** Missing discovery means no authenticated endpoint is available; never learn identity from HTTP. */
export function readLocalControlState(dir = remoteHome()) {
  const home = localControlHome(dir);
  const endpoint = readAdminEndpoint(home);
  if (!endpoint) return undefined;
  const identity = readAdminTlsIdentity(home);
  const token = readAdminToken(home);
  const port = loadConfig(dir, false).port;
  if (!identity || !token || !Number.isSafeInteger(port) || port < 1 || port > 65_535 || endpoint.publicPort !== port) {
    throw new Error("private remote-host control state is unavailable or mismatched; restart the updated host");
  }
  return { endpoint, identity, token };
}

export type LocalControlState = NonNullable<ReturnType<typeof readLocalControlState>>;

/** Fresh four-file snapshot. Only the legacy synchronous provisioning path uses loadConfig. */
export async function readLocalControlStateAsync(dir = remoteHome(), options: { signal?: AbortSignal } = {}): Promise<LocalControlState | undefined> {
  const home = localControlHome(dir), files = adminTransportPaths(home);
  let bytes: Buffer[];
  try {
    bytes = await readPrivateFilesStrict([
      { file: files.endpoint, maxBytes: 64 * 1024 },
      { file: files.identity, maxBytes: 64 * 1024 },
      { file: adminTokenPath(home), maxBytes: 65 },
      { file: path.join(dir, "host.json"), maxBytes: 1024 * 1024 },
    ], options);
  } catch (error) {
    if (options.signal?.aborted) throw Object.assign(new Error("Private storage read aborted"), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      // Only missing discovery means no endpoint. A partial identity/config remains an error.
      try { fs.lstatSync(files.endpoint); }
      catch (missing) { if ((missing as NodeJS.ErrnoException).code === "ENOENT") return undefined; }
      throw new Error("private remote-host control state is unavailable or mismatched; restart the updated host");
    }
    throw error;
  }
  const endpoint = parseAdminEndpoint(parseAdminStateJson(bytes[0]!.toString("utf8")));
  const identity = parseAdminTlsIdentity(parseAdminStateJson(bytes[1]!.toString("utf8")));
  const token = parseAdminToken(bytes[2]!.toString("utf8"));
  let record: unknown;
  try { record = JSON.parse(bytes[3]!.toString("utf8")) as unknown; }
  catch { throw new Error("Invalid phone host configuration JSON"); }
  const stored = parseStoredHostConfig(record);
  const port = typeof stored.port === "number" ? stored.port : DEFAULT_PORT;
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535 || endpoint.publicPort !== port) {
    throw new Error("private remote-host control state is unavailable or mismatched; restart the updated host");
  }
  return { endpoint, identity, token };
}

function localPath(route: string): string {
  if (!route.startsWith("/local/")) throw new Error("invalid remote-host control path");
  const pathname = validateAdminPath(`/api${route}`);
  if (!pathname.startsWith("/api/local/")) throw new Error("invalid remote-host control path");
  return pathname;
}

export interface LocalControlRequestLimits { networkTimeoutMs?: number }

/**
 * For a snapshot just verified in this attempt, with no intervening await. Callers must obtain
 * a fresh snapshot after every network operation, never reuse this as a trusted-state cache.
 */
export function requestVerifiedLocalControl(state: LocalControlState, route: string, init: AdminRequestInit = {}, limits: LocalControlRequestLimits = {}): Promise<Response> {
  const pathname = localPath(route);
  let signal = init.signal;
  if (limits.networkTimeoutMs !== undefined) {
    if (!Number.isSafeInteger(limits.networkTimeoutMs) || limits.networkTimeoutMs < 1 || limits.networkTimeoutMs > 60_000) {
      throw new Error("invalid local-control network deadline");
    }
    const network = AbortSignal.timeout(limits.networkTimeoutMs);
    signal = signal ? AbortSignal.any([signal, network]) : network;
  }
  return adminTlsFetch(state.endpoint, state.identity, state.token, pathname, { ...init, ...(signal ? { signal } : {}) });
}

/** Route validation happens before files/network. Caller signal covers both verification and TLS. */
export async function localControlRequest(dir: string, route: string, init: AdminRequestInit = {}, expectedInstanceId?: string, limits: LocalControlRequestLimits = {}): Promise<Response> {
  localPath(route);
  const state = await readLocalControlStateAsync(dir, init.signal ? { signal: init.signal } : {});
  if (!state) throw Object.assign(new Error("private remote-host control is unavailable; start the updated host"), { code: "LOCAL_CONTROL_UNAVAILABLE" });
  if (expectedInstanceId !== undefined && state.endpoint.instanceId !== expectedInstanceId) throw new Error("remote-host control instance changed before request");
  return requestVerifiedLocalControl(state, route, init, limits);
}
