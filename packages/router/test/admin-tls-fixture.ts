// Test-only native TLS endpoint. Uses the same private state, CA, leaf and token as production.
import type { TestContext } from "node:test";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import https from "node:https";
import type { RequestListener } from "node:http";
import { once } from "node:events";
import { ensureAdminToken } from "../src/admin-auth.ts";
import { ensureAdminTlsIdentity, writeAdminEndpoint, type AdminEndpoint } from "../src/admin-transport-state.ts";

export async function adminTlsFixture(t: TestContext, handler: RequestListener = (_req, res) => res.end('{"ok":true}')) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-tls-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const token = ensureAdminToken(home);
  const identity = ensureAdminTlsIdentity(home);
  const server = https.createServer({ key: identity.keyPem, cert: identity.certPem, minVersion: "TLSv1.2" }, handler);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });
  const address = server.address();
  if (!address || typeof address !== "object") throw new Error("fixture listener unavailable");
  const endpoint: AdminEndpoint = { version: 1, instanceId: "a".repeat(32), publicPort: address.port === 8791 ? 8792 : 8791, tlsPort: address.port };
  writeAdminEndpoint(home, endpoint);
  return { home, token, identity, endpoint, server, base: `http://127.0.0.1:${endpoint.publicPort}/` };
}
