// A separate installation capability for the remote host's local administration. Phone/relay
// pairing secrets and the legacy plaintext local.secret are never used on this transport.
import path from "node:path";
import { readAdminToken } from "../../router/src/admin-auth.ts";
import { readAdminEndpoint, readAdminTlsIdentity } from "../../router/src/admin-transport-state.ts";
import { adminTlsFetch, validateAdminPath, type AdminRequestInit } from "../../router/src/admin-transport-client.ts";
import { loadConfig, remoteHome } from "./config.ts";

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

/** Route strings are fixed caller vocabulary, not a destination URL. Headers cannot change authority. */
export function localControlRequest(dir: string, route: string, init: AdminRequestInit = {}, expectedInstanceId?: string): Promise<Response> {
  if (!route.startsWith("/local/")) throw new Error("invalid remote-host control path");
  const pathname = validateAdminPath(`/api${route}`);
  if (!pathname.startsWith("/api/local/")) throw new Error("invalid remote-host control path");
  const state = readLocalControlState(dir);
  if (!state) throw Object.assign(new Error("private remote-host control is unavailable; start the updated host"), { code: "LOCAL_CONTROL_UNAVAILABLE" });
  if (expectedInstanceId !== undefined && state.endpoint.instanceId !== expectedInstanceId) throw new Error("remote-host control instance changed before request");
  return adminTlsFetch(state.endpoint, state.identity, state.token, pathname, init);
}
