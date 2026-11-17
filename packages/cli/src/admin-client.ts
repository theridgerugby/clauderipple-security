// The configured loopback HTTP address is a discovery identifier only. Admin traffic uses the
// separately recorded TLS endpoint and the pinned identity belonging to this installation.
import { execFileSync } from "node:child_process";
import { ADMIN_TOKEN_HEADER, readAdminToken } from "../../router/src/admin-auth.ts";
import { readAdminEndpoint, readAdminTlsIdentity } from "../../router/src/admin-transport-state.ts";
import { adminTlsFetch, validateAdminPath } from "../../router/src/admin-transport-client.ts";
import { homeDir } from "../../router/src/config.ts";
import { adminBridgePath } from "./admin-runtime.ts";
import { NATIVE_UI_REMEDIATION, openNativeDashboard, type AdminView, type NativeUiResult } from "./native-ui.ts";
import { runtime } from "./runtime.ts";

function localUrl(value: string): URL {
  const url = new URL(value);
  if (!/^http:\/\/(?:127\.0\.0\.1|\[::1\])(?::\d+)?(?:\/|$)/.test(value) ||
      /[\\\r\n\0]/.test(value) || url.protocol !== "http:" ||
      !["127.0.0.1", "[::1]"].includes(url.hostname) || url.username || url.password || url.hash) {
    throw new Error("admin requests require a literal loopback discovery URL without credentials or fragment");
  }
  return url;
}

export function localAdminUrl(value: string): URL {
  const url = localUrl(value);
  // Validate the spelling before URL normalization can erase traversal or whitespace.
  validateAdminPath(value.slice(value.indexOf("/", "http://".length)));
  if (!url.pathname.startsWith("/api/")) throw new Error("admin requests require an /api/ path");
  return url;
}

export function localAdminBase(value: string): string {
  const url = localUrl(value);
  if (url.pathname !== "/" || url.search) throw new Error("admin base URL must not include a path or query");
  return url.origin;
}

function ordinaryHeaders(input?: RequestInit["headers"]): Headers {
  const headers = new Headers(input);
  headers.delete(ADMIN_TOKEN_HEADER);
  return headers;
}

export function adminFetch(value: string, init: RequestInit = {}, home: string = homeDir()): Promise<Response> {
  const url = localAdminUrl(value);
  const endpoint = readAdminEndpoint(home);
  const identity = readAdminTlsIdentity(home);
  const token = readAdminToken(home);
  if (!endpoint || !identity || !token) {
    throw new Error("Secure admin state is unavailable; start or upgrade ClaudeRipple before using administrative commands");
  }
  if (endpoint.publicPort !== Number(url.port || "80")) throw new Error("Admin endpoint belongs to a different configured port");
  if (init.body !== undefined && init.body !== null && typeof init.body !== "string" && !(init.body instanceof Uint8Array)) {
    throw new Error("Admin requests require a text or byte body");
  }
  return adminTlsFetch(endpoint, identity, token, url.pathname + url.search, {
    headers: ordinaryHeaders(init.headers),
    ...(init.method ? { method: init.method } : {}),
    ...(init.body !== undefined && init.body !== null ? { body: init.body } : {}),
    ...(init.signal ? { signal: init.signal } : {}),
  });
}

export type AdminSyncRunner = (file: string, args: string[], opts: {
  input: string;
  env: NodeJS.ProcessEnv;
  stdio: ["pipe", "pipe", "ignore"];
  windowsHide: boolean;
  timeout: number;
  maxBuffer: number;
}) => Buffer | string;

/** The trusted child reads private credentials itself. Neither argv nor stdin includes a token. */
export function adminRequestSync(value: string, home: string, opts: {
  method?: "GET" | "POST";
  headers?: RequestInit["headers"];
  timeoutMs?: number;
  run?: AdminSyncRunner;
} = {}): string | null {
  try {
    const url = localAdminUrl(value);
    const rt = runtime();
    const timeoutMs = opts.timeoutMs ?? 3_000;
    const out = (opts.run ?? execFileSync)(rt.node, [adminBridgePath(rt)], {
      input: JSON.stringify({ kind: "request", url: url.href, method: opts.method ?? "GET", headers: Object.fromEntries(ordinaryHeaders(opts.headers)), timeoutMs }),
      env: { ...process.env, ...rt.env, CLAUDERIPPLE_HOME: home },
      stdio: ["pipe", "pipe", "ignore"], windowsHide: true,
      timeout: timeoutMs + 1_000, maxBuffer: 4 * 1024 * 1024,
    }).toString();
    const response = JSON.parse(out) as { ok?: unknown; text?: unknown };
    return response.ok === true && typeof response.text === "string" ? response.text || "{}" : null;
  } catch { return null; }
}

/** No browser fallback: an HTTP page cannot authenticate itself before reading a capability. */
export async function openAdminDashboard(base: string, home: string, opts: {
  view?: "mod";
  open?: (home: string, view: AdminView) => Promise<NativeUiResult>;
  print?: (line: string) => void;
} = {}): Promise<boolean> {
  localAdminBase(base);
  let result: NativeUiResult;
  try { result = await (opts.open ?? openNativeDashboard)(home, opts.view ?? "dashboard"); }
  catch { result = { ok: false, message: NATIVE_UI_REMEDIATION }; }
  (opts.print ?? console.log)(result.message);
  return result.ok;
}
