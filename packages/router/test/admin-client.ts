// Fixtures use the production TLS listener, a private CA and an exact leaf pin. Existing test
// URLs use the configured public port as a logical instance address, like installed clients.
// Security tests select unauthenticatedFetch so TLS verification never adds an admin capability.
import crypto from "node:crypto";
import path from "node:path";
import tls from "node:tls";
import type https from "node:https";
import { Agent } from "undici";
import { startAdmin as startServer, type AdminDeps } from "../src/admin.ts";
import { adminAuthHeaders, ADMIN_INSTANCE_HEADER, ADMIN_TOKEN_HEADER } from "../src/admin-auth.ts";
import { readAdminTlsIdentity, readAdminEndpoint, type AdminTlsIdentity, type AdminEndpoint } from "../src/admin-transport-state.ts";
import { adminTlsFetch } from "../src/admin-transport-client.ts";

interface FixtureTransport {
  headers: Record<string, string>;
  tlsPort: number;
  ca: string;
  checkServerIdentity: typeof tls.checkServerIdentity;
  agent: Agent;
  endpoint: AdminEndpoint;
  identity: AdminTlsIdentity;
}
const transports = new Map<string, FixtureTransport>();

export async function startAdmin(deps: AdminDeps): ReturnType<typeof startServer> {
  const server = await startServer({ modelScoresFetch: async () => new Response("offline fixture", { status: 503 }), ...deps });
  try {
    const home = path.dirname(path.resolve(deps.configFile));
    const identity = readAdminTlsIdentity(home)!;
    const endpoint = readAdminEndpoint(home)!;
    const fingerprint = new crypto.X509Certificate(identity.certPem).fingerprint256;
    // The socket destination is always literal loopback. A hostile HTTP Host supplied by a
    // server-side guard test must not replace the address whose TLS identity we authenticate.
    const checkServerIdentity: typeof tls.checkServerIdentity = (_host, certificate) =>
      tls.checkServerIdentity("127.0.0.1", certificate) ?? (certificate.fingerprint256 === fingerprint ? undefined : new Error("test admin TLS pin mismatch"));
    const transport: FixtureTransport = {
      headers: { ...adminAuthHeaders(home), [ADMIN_INSTANCE_HEADER]: endpoint.instanceId },
      tlsPort: server.tlsPort, ca: identity.caCertPem, checkServerIdentity,
      // Windows DPAPI/ACL assertions can block this test process for seconds between requests.
      // Reusing an idle TLS socket across those synchronous OS calls races the server's idle
      // timeout and produces an unrelated `fetch failed` (ECONNRESET) under hosted CI load.
      // Every fixture request still performs certificate verification and the same API checks.
      agent: new Agent({ connect: { ca: identity.caCertPem, rejectUnauthorized: true, checkServerIdentity }, pipelining: 0 }),
      endpoint, identity,
    };
    const origins = ["127.0.0.1", "localhost", "[::1]"].flatMap(host => [
      `http://${host}:${server.port}`, `https://${host}:${server.tlsPort}`,
    ]);
    for (const origin of origins) transports.set(origin, transport);
    return {
      port: server.port,
      tlsPort: server.tlsPort,
      close() {
        for (const origin of origins) if (transports.get(origin) === transport) transports.delete(origin);
        void transport.agent.destroy();
        server.close();
      },
    };
  } catch (error) {
    server.close();
    throw error;
  }
}

export function adminTestAuthHeaders(base: string): Record<string, string> {
  const transport = transports.get(new URL(base).origin);
  if (!transport) throw new Error("unknown test admin TLS instance");
  return { ...transport.headers };
}

/** Exact request target/duplicate-header tests need node:https rather than URL normalization. */
export function adminTestTlsOptions(base: string): https.RequestOptions & { ca: string; checkServerIdentity: typeof tls.checkServerIdentity } {
  const transport = transports.get(new URL(base).origin);
  if (!transport) throw new Error("unknown test admin TLS instance");
  return { host: "127.0.0.1", port: transport.tlsPort, ca: transport.ca, rejectUnauthorized: true,
    checkServerIdentity: transport.checkServerIdentity, agent: false };
}

async function fixtureFetch(input: Parameters<typeof globalThis.fetch>[0], init: RequestInit | undefined, authenticated: boolean): Promise<Response> {
  const url = new URL(input instanceof Request ? input.url : input);
  const transport = transports.get(url.origin);
  if (!transport) return globalThis.fetch(input, init);
  const headers = new Headers(init?.headers ?? (input instanceof Request ? input.headers : undefined));
  // Attack-shaped headers must reach the real listener unchanged instead of being stripped or
  // replaced by the production client's safe header policy. Ordinary requests use that client.
  const explicitBoundaryHeaders = ["origin", "host", "sec-fetch-site", ADMIN_TOKEN_HEADER, ADMIN_INSTANCE_HEADER].some(name => headers.has(name));
  if (authenticated) {
    for (const [name, value] of Object.entries(transport.headers)) if (!headers.has(name)) headers.set(name, value);
    // Positive legacy fixtures express their own origin using the logical public address.
    // Security tests use the unauthenticated wrapper, which preserves their supplied Origin.
    const origin = headers.get("origin");
    if (origin && transports.get(origin) === transport) headers.set("origin", `https://127.0.0.1:${transport.tlsPort}`);
  }
  if (authenticated && !explicitBoundaryHeaders && (url.pathname.startsWith("/api/") || url.pathname === "/readyz")) {
    const body = init?.body ?? (input instanceof Request && input.body ? new Uint8Array(await input.arrayBuffer()) : undefined);
    const method = init?.method ?? (input instanceof Request ? input.method : undefined);
    if (body !== undefined && body !== null && typeof body !== "string" && !(body instanceof Uint8Array)) throw new Error("unsupported fixture request body");
    return adminTlsFetch(transport.endpoint, transport.identity, transport.headers["x-clauderipple-admin"]!, url.pathname + url.search, {
      ...(method === undefined ? {} : { method }), headers,
      ...(body == null ? {} : { body }), ...(init?.signal ? { signal: init.signal } : {}),
    });
  }
  url.protocol = "https:";
  url.hostname = "127.0.0.1";
  url.port = String(transport.tlsPort);
  // Node's bundled undici-types and the installed undici package expose different optional
  // interceptor overloads; the Agent still implements the fetch dispatcher wire contract.
  const options: RequestInit = { ...init, headers, dispatcher: transport.agent as unknown as NonNullable<RequestInit["dispatcher"]> };
  return globalThis.fetch(input instanceof Request ? new Request(url, input) : url, options);
}

export const fetch: typeof globalThis.fetch = (input, init) => fixtureFetch(input, init, true);
export const unauthenticatedFetch: typeof globalThis.fetch = (input, init) => fixtureFetch(input, init, false);
