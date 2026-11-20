import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import ts from "typescript";
import { ADMIN_TOKEN_HEADER, fetchAdmin } from "../src/admin-auth.ts";
import { adminTlsFixture } from "../../router/test/admin-tls-fixture.ts";

// Exercise the real tray entry points without creating an Electron window, importing a CA,
// or running a CLI installer. Only platform and presentation boundaries are replaced.
const main = fs.readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
const syntax = ts.createSourceFile("main.ts", main, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
const names = new Set(["poll", "readPower", "changePower", "installUpdate"]);
const selected = syntax.statements.filter(statement => ts.isFunctionDeclaration(statement) && statement.name && names.has(statement.name.text));
assert.equal(selected.length, names.size);
const functions = ts.transpileModule(selected.map(statement => statement.getText(syntax)).join("\n"), {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
}).outputText;

test("dashboard status and isolated legacy helpers use the main-process credential", async t => {
  const requests: { path?: string; method?: string; token?: string | string[] }[] = [];
  const { home, token, base } = await adminTlsFixture(t, (req, res) => {
    requests.push({ path: req.url, method: req.method, token: req.headers[ADMIN_TOKEN_HEADER] });
    res.setHeader("content-type", "application/json");
    res.end(JSON.stringify(req.url === "/api/status" ? { version: "fixture", autoUpdate: {} } : { awake: { setup: "ok" } }));
  });
  const create = new Function("deps", `
    const { fetchAdmin, home, base } = deps;
    const adminUrl = () => base;
    let answered = null, last = null, lastError = null, downSince = null, downNotified = false, power = null;
    let updating = false, routerUpdateUntil = 0, rec = { restartClaude: false };
    const handleRouterUpdate = async () => {}, reconcileRouter = () => {}, render = () => {};
    const refreshDoctor = async () => {}, Notification = { isSupported: () => false };
    const showFailure = async () => { throw new Error('unexpected failure dialog'); };
    ${functions}
    return { poll, readPower, changePower, installUpdate, status: () => last };
  `);
  const tray = create({ fetchAdmin, home, base });
  await tray.poll();
  assert.deepEqual(requests.map(({ path: route, method }) => [route, method]), [["/api/status", "GET"]], "personal status refresh must not perform power/update/reconciliation work");
  // Legacy helpers are tested only in isolation; the production personal dashboard never
  // wires them into boot, timers, tray menus or renderer actions.
  await tray.readPower();
  await tray.changePower({ tether: { enabled: false } });
  await tray.installUpdate("fixture-version");
  assert.deepEqual(requests.map(({ path: route, method }) => [route, method]), [
    ["/api/status", "GET"], ["/api/power", "GET"], ["/api/power", "PUT"], ["/api/update", "POST"],
  ]);
  assert.ok(requests.every(request => request.token === token));
  assert.ok(!JSON.stringify(tray.status()).includes(token));
  const preload = fs.readFileSync(new URL("../src/preload.ts", import.meta.url), "utf8");
  assert.doesNotMatch(preload, /admin-auth|admin-token|x-clauderipple-admin/);
});
