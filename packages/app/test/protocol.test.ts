import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { routeRequest } from "../src/status-model.ts";
import * as security from "../src/security.ts";

// Load the production protocol with no auth/transport module available at all. Even a request
// attributed to an owned top frame cannot ask this module to read a key or open a socket.
const source = fs.readFileSync(new URL("../src/protocol.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true } }).outputText;
type Handler = (request: Request) => Promise<Response>;
type GuardDetails = { url: string; webContentsId?: number; resourceType?: string; frame?: object | null };
type Guard = (details: GuardDetails, callback: (response: { cancel: boolean }) => void) => void;
function harness(): { raw: Handler; guard: Guard } {
  let raw: Handler | undefined;
  let guard: Guard | undefined;
  const exports: { registerScheme?: () => void; handleScheme?: (root: string) => void } = {};
  const modules: Record<string, object> = {
    electron: {
      protocol: {
        handle: (_scheme: string, callback: Handler) => { raw = callback; },
        registerSchemesAsPrivileged: (schemes: { privileges: { corsEnabled?: boolean } }[]) => assert.equal(schemes[0]?.privileges.corsEnabled, true),
      },
      session: { defaultSession: { webRequest: { onBeforeRequest: (_filter: object, callback: Guard) => { guard = callback; } } } },
    },
    "node:fs": { promises: { readFile: () => Buffer.from("fixture bundled UI") } },
    "node:path": path, "./status-model": { routeRequest }, "./security": security,
  };
  runInNewContext(compiled, {
    exports, require: (id: string) => { assert.ok(id in modules, `static protocol must not import ${id}`); return modules[id]; },
    URL, Request, Response, Headers, Buffer,
  });
  assert.ok(exports.handleScheme && exports.registerScheme);
  exports.registerScheme();
  exports.handleScheme(path.resolve("/tmp/unused-ripple-ui"));
  assert.ok(raw && guard);
  return { raw, guard };
}

test("browser API requests are always refused, including top-frame misattribution and forged metadata", async () => {
  const { guard, raw } = harness();
  const top = { origin: security.ORIGIN, url: `${security.ORIGIN}/`, processId: 11, routingId: 17 };
  for (const pathname of ["/api", "/api/", "/api/status", "/api/config?next=https://untrusted.example", "/api/future-endpoint"]) {
    for (const metadata of [{}, { webContentsId: 5, resourceType: "xhr", frame: top },
      { webContentsId: 5, resourceType: "xhr", frame: { ...top, routingId: 18 } },
      { webContentsId: 6, frame: top }, { frame: null }, { resourceType: "mainFrame", frame: top }]) {
      let cancelled = false;
      guard({ url: `${security.ORIGIN}${pathname}`, ...metadata }, response => { cancelled = response.cancel; });
      assert.equal(cancelled, true);
    }
    for (const initiatorOrigin of [undefined, security.ORIGIN, "null", "https://untrusted.example"]) {
      const request = new Request(`${security.ORIGIN}${pathname}`, { headers: { origin: security.ORIGIN, referer: `${security.ORIGIN}/` } });
      if (initiatorOrigin !== undefined) Object.defineProperty(request, "initiatorOrigin", { value: initiatorOrigin });
      assert.equal((await raw(request)).status, 403, "raw protocol dispatch has no administrative fallback");
    }
  }
});

test("static pages and scripts retain CSP and never require a router or credentials", async () => {
  const { guard, raw } = harness();
  for (const pathname of ["/", "/index.html", "/app.js", "/style.css"]) {
    let cancelled = true;
    guard({ url: `${security.ORIGIN}${pathname}` }, response => { cancelled = response.cancel; });
    assert.equal(cancelled, false);
    const response = await raw(new Request(`${security.ORIGIN}${pathname}`));
    assert.equal(response.status, 200);
    assert.equal(await response.text(), "fixture bundled UI");
    assert.equal(response.headers.has("x-clauderipple-admin"), false);
    assert.equal(response.headers.get("content-security-policy"), security.DASHBOARD_CSP);
    assert.equal(response.headers.get("x-content-type-options"), "nosniff");
    assert.equal(response.headers.get("referrer-policy"), "no-referrer");
  }
  const head = await raw(new Request(`${security.ORIGIN}/`, { method: "HEAD" }));
  assert.equal(head.status, 200);
  assert.equal(head.body, null);
  assert.equal((await raw(new Request(`${security.ORIGIN}/`, { method: "POST" }))).status, 405);
});

test("static scheme routing rejects foreign authority and path escapes", async () => {
  const { guard, raw } = harness();
  for (const url of ["ripple://untrusted/app.js", "ripple://app:8080/app.js", "ripple://user@app/app.js", "ripple://app/%00.js", "ripple://app/%2e%2e%2fsecret.js"]) {
    let cancelled = false;
    guard({ url }, response => { cancelled = response.cancel; });
    assert.equal(cancelled, true, url);
    // Exercise protocol validation even for URLs that Node's Request constructor rejects.
    assert.ok((await raw({ url, method: "GET" } as Request)).status >= 400, url);
  }
});
