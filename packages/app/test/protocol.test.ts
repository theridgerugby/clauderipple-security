import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import type http from "node:http";
import path from "node:path";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { routeRequest } from "../src/status-model.ts";
import { ADMIN_TOKEN_HEADER, fetchAdmin, localAdminBaseUrl } from "../src/admin-auth.ts";
import { ADMIN_TLS_REQUEST_LIMIT } from "../src/admin-transport-client.ts";
import * as security from "../src/security.ts";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";

// Run the actual protocol module with Electron frame dispatch replaced. Real I/O tests use the
// production private-state reader and TLS transport; handshake/timeout attacks live in router tests.
const source = fs.readFileSync(new URL("../src/protocol.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
type Handler = (request: Request) => Promise<Response>;
type GuardDetails = { url: string; webContentsId?: number; resourceType: string; frame?: { origin: string; url: string; processId: number; routingId: number } | null };
type Guard = (details: GuardDetails, callback: (response: { cancel: boolean }) => void) => void;
const frame = { origin: "ripple://app", url: "ripple://app/", processId: 11, routingId: 17 };
type Harness = Handler & { guard: Guard; raw: Handler };
function harness(admin: string, home = "/tmp/unused-ripple-home", transport: typeof fetchAdmin = fetchAdmin): Harness {
  let handler: Handler | undefined;
  let guard: Guard | undefined;
  const exports: { registerScheme?: () => void; handleScheme?: (root: string, admin: () => string, home: string, owned: () => object) => void } = {};
  const modules: Record<string, object> = {
    electron: {
      protocol: {
        handle: (_scheme: string, callback: Handler) => { handler = callback; },
        registerSchemesAsPrivileged: (schemes: { privileges: { corsEnabled?: boolean } }[]) => assert.equal(schemes[0]?.privileges.corsEnabled, true),
      },
      session: { defaultSession: { webRequest: { onBeforeRequest: (_filter: object, callback: Guard) => { guard = callback; } } } },
    },
    "node:fs": { promises: { readFile: () => Buffer.from("fixture bundled UI") } },
    "node:path": path, "./status-model": { routeRequest },
    "./admin-auth": { fetchAdmin: transport, localAdminBaseUrl },
    "./admin-transport-client": { ADMIN_TLS_REQUEST_LIMIT },
    "./security": security,
  };
  runInNewContext(compiled, {
    exports, require: (id: string) => { assert.ok(id in modules, id); return modules[id]; },
    URL, Request, Response, Headers, Buffer,
  });
  assert.ok(exports.handleScheme && exports.registerScheme);
  exports.registerScheme();
  exports.handleScheme("/tmp/unused-ripple-ui", () => admin, home, () => ({ id: 5, mainFrame: frame }));
  assert.ok(handler);
  assert.ok(guard);
  const raw = handler;
  const installedGuard = guard;
  const handle = async (request: Request) => {
    let denied = true;
    installedGuard({ url: request.url, webContentsId: 5, resourceType: "xhr", frame }, response => { denied = response.cancel; });
    Object.defineProperty(request, "initiatorOrigin", { value: security.ORIGIN });
    return denied ? new Response(null, { status: 403 }) : raw(request);
  };
  return Object.assign(handle, { guard: installedGuard, raw });
}

test("the real protocol bridge uses pinned TLS and preserves method, body and response", async t => {
  let received: { method?: string; url?: string; headers: http.IncomingHttpHeaders; body: string } | undefined;
  const f = await adminTlsFixture(t, async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    received = { method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks).toString() };
    res.writeHead(201, { "content-type": "application/json", "cache-control": "no-store" });
    res.end(JSON.stringify({ approved: true }));
  });
  const handle = harness(f.base, f.home);
  const response = await handle(new Request("ripple://app/api/picker?enabled=1", {
    method: "POST", headers: { "content-type": "application/json", origin: "ripple://app", [ADMIN_TOKEN_HEADER]: "forged" }, body: '{"on":true}',
  }));
  assert.equal(response.status, 201);
  assert.deepEqual(await response.json(), { approved: true });
  assert.equal(response.headers.get("content-type"), "application/json");
  assert.equal(response.headers.get("cache-control"), "no-store");
  assert.equal(received?.method, "POST");
  assert.equal(received?.url, "/api/picker?enabled=1");
  assert.equal(received?.body, '{"on":true}');
  assert.equal(received?.headers.origin, undefined);
  assert.equal(received?.headers.host, `127.0.0.1:${f.endpoint.tlsPort}`);
  assert.equal(received?.headers[ADMIN_TOKEN_HEADER], f.token);
  assert.ok(!JSON.stringify([...response.headers]).includes(f.token));
});

test("TLS or private state errors return routerDown with no credentials in diagnostics", async () => {
  const response = await harness("http://127.0.0.1:1/")(new Request("ripple://app/api/status"));
  assert.equal(response.status, 503);
  assert.deepEqual(await response.json(), { error: "ClaudeRipple is not running", routerDown: true });
});

test("TLS HTTP errors and bodyless responses keep their original status", async t => {
  const f = await adminTlsFixture(t, (req, res) => {
    if (req.url === "/api/empty") { res.writeHead(204); res.end(); return; }
    res.writeHead(409, { "content-type": "application/json" });
    res.end('{"error":"conflict"}');
  });
  const handle = harness(f.base, f.home);
  const conflict = await handle(new Request("ripple://app/api/conflict"));
  assert.equal(conflict.status, 409);
  assert.deepEqual(await conflict.json(), { error: "conflict" });
  const empty = await handle(new Request("ripple://app/api/empty"));
  assert.equal(empty.status, 204);
  assert.equal(empty.body, null);
});

test("oversized renderer bodies are rejected before transport", async () => {
  let calls = 0;
  const handle = harness("http://127.0.0.1:8791/", undefined, () => { calls++; throw new Error("must not send"); });
  const request = new Request("ripple://app/api/image", { method: "POST", body: new Uint8Array(ADMIN_TLS_REQUEST_LIMIT + 1) });
  assert.equal((await handle(request)).status, 413);
  assert.equal(calls, 0);
});

test("the API bridge accepts only the dashboard main frame, not other windows, frames, navigation or absent origin", () => {
  const handle = harness("http://127.0.0.1:1/");
  const base: GuardDetails = { url: "ripple://app/api/config", webContentsId: 5, resourceType: "xhr", frame };
  const allowed = (details: GuardDetails) => {
    let result = false;
    handle.guard(details, response => { result = !response.cancel; });
    return result;
  };
  assert.equal(allowed(base), true);
  for (const details of [
    { ...base, frame: null }, { ...base, frame: undefined }, { ...base, webContentsId: 6 },
    { ...base, resourceType: "mainFrame" }, { ...base, resourceType: "subFrame" },
    { ...base, frame: { ...frame, routingId: 18 } }, { ...base, frame: { ...frame, processId: 12 } },
    { ...base, frame: { ...frame, origin: "null" } },
    { ...base, frame: { ...frame, origin: "https://untrusted.example", url: "https://untrusted.example/" } },
    { ...base, url: "ripple://untrusted/api/config" }, { ...base, url: "ripple://app:8080/api/config" },
    { ...base, url: "ripple://user@app/api/config" },
  ]) assert.equal(allowed(details), false, JSON.stringify(details));
});

test("foreign Origin headers and non-loopback admin overrides are rejected before attaching credentials", async () => {
  let calls = 0;
  const transport: typeof fetchAdmin = () => { calls++; throw new Error("unexpected request"); };
  const handle = harness("http://127.0.0.1:1/", undefined, transport);
  for (const origin of ["null", "https://untrusted.example", "ripple://app.evil", "ripple://app:80"]) {
    const response = await handle(new Request("ripple://app/api/config", { headers: { origin } }));
    assert.equal(response.status, 403);
  }
  for (const base of ["https://collector.example/", "http://localhost:1/", "http://127.0.0.1:1/elsewhere/", "http://user@127.0.0.1:1/", "http://127.0.0.1:1/?extra=1"]) {
    const response = await harness(base, undefined, transport)(new Request("ripple://app/api/config"));
    assert.equal(response.status, 503);
  }
  assert.equal(calls, 0);
});

test("the static page and script never receive the main-process capability", async () => {
  const handle = harness("http://127.0.0.1:1/");
  for (const pathname of ["/", "/app.js"]) {
    const response = await handle(new Request(`ripple://app${pathname}`));
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "fixture bundled UI");
    assert.equal(response.headers.has(ADMIN_TOKEN_HEADER), false);
    assert.equal(response.headers.get("content-security-policy"), security.DASHBOARD_CSP);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  }
});

test("browser-owned initiator metadata is required even with a forged Origin or referrer", async () => {
  let calls = 0;
  const handle = harness("http://127.0.0.1:1/", undefined, () => { calls++; throw new Error("unexpected request"); });
  for (const initiatorOrigin of [undefined, "null", "https://untrusted.example", "ripple://app.evil", "ripple://app:80"]) {
    const request = new Request("ripple://app/api/config", { headers: { origin: security.ORIGIN, referer: `${security.ORIGIN}/` } });
    if (initiatorOrigin !== undefined) Object.defineProperty(request, "initiatorOrigin", { value: initiatorOrigin });
    assert.equal((await handle.raw(request)).status, 403);
  }
  assert.equal(calls, 0);
});
