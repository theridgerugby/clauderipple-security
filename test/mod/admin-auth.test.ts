import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { ADMIN_BRIDGE_LIMIT, adminRequest, adminResponse, nativeCommand, nativeResult, parseAdminRuntime } from "../../packages/mod/hooks/admin.ts";
import { parseAdminRuntime as nativeRuntime } from "../../packages/cli/src/admin-runtime.ts";

const home = path.resolve(os.tmpdir(), "ripple-mod-native");
const runtime = { version: 1 as const, home, node: process.execPath, bridge: path.join(home, "admin-bridge.js"), env: {} };
test("mod and native descriptor parsers agree on current installation runtime", () => {
  assert.deepEqual(parseAdminRuntime(runtime, home), nativeRuntime(runtime, home));
  const windows = { version: 1, home: "C:\\Users\\Ethan\\.clauderipple", node: "C:\\Runtime\\node.exe", bridge: "C:\\Runtime\\admin-bridge.js", env: { ELECTRON_RUN_AS_NODE: "1" } };
  assert.equal(parseAdminRuntime(windows, windows.home).node, windows.node);
  for (const change of [
    { version: 2 }, { home: path.join(home, "other") }, { node: "node" }, { bridge: "admin-bridge.js" },
    { node: "\\\\remote\\node.exe" }, { bridge: path.join(home, "evil.js") },
    { env: { NODE_OPTIONS: "--require=evil" } }, { env: { ELECTRON_RUN_AS_NODE: "0" } },
  ]) assert.throws(() => parseAdminRuntime({ ...runtime, ...change }, home));
});
test("mod admin bridge sends only allowed local request metadata over stdin", () => {
  const request = adminRequest("http://127.0.0.1:8792/api/requests?session=fixture", { method: "POST", headers: { "Content-Type": "application/json" }, body: "{}" });
  const command = nativeCommand(runtime, request);
  assert.deepEqual(command.argv, [runtime.node, runtime.bridge]);
  assert.deepEqual(command.init.env, { CLAUDERIPPLE_HOME: home });
  assert.equal(command.init.timeoutMs, 35_000);
  assert.deepEqual(JSON.parse(command.init.stdin), request);
  assert.doesNotMatch(JSON.stringify(command), /admin-token|x-clauderipple-admin|#admin-/);
  assert.deepEqual(JSON.parse(nativeCommand(runtime, { kind: "ui", view: "mod" }).init.stdin), { kind: "ui", view: "mod" });
});
test("external URLs and caller-supplied auth cannot reach the native bridge", () => {
  for (const url of ["https://evil.example/api/status", "http://127.0.0.1.evil.example:8792/api/status", "http://127.0.0.1:8792@evil.example/api/status", "http://127.0.0.1:65536/api/status", "http://127.0.0.1:8792/api/\\evil", "http://127.0.0.1:8792/api/status#fragment", "http://127.0.0.1:8792/"]) assert.throws(() => adminRequest(url));
  for (const name of ["Authorization", "x-clauderipple-admin", "Host", "Cookie"]) assert.throws(() => adminRequest("http://127.0.0.1:8792/api/status", { headers: { [name]: "secret" } }));
});
test("failed, malformed and truncated native replies fail closed without echoing stderr", () => {
  const ok = { exitCode: 0, stdout: JSON.stringify({ ok: true, status: 200, headers: {}, text: "{}" }), stderr: "", isStdoutTruncated: false, isStderrTruncated: false };
  assert.deepEqual(adminResponse(ok), { ok: true, status: 200, headers: {}, text: "{}" });
  for (const change of [
    { exitCode: 1, stderr: "private diagnostic" }, { isStdoutTruncated: true }, { isStderrTruncated: true },
    { stdout: "not-json" }, { stdout: "[]" }, { stdout: "x".repeat(ADMIN_BRIDGE_LIMIT + 1) },
    { stdout: '{"ok":true,"status":401,"headers":{},"text":""}' },
    { stdout: '{"ok":true,"status":200,"headers":{"x":4},"text":""}' },
  ]) assert.throws(() => adminResponse({ ...ok, ...change }), error => error instanceof Error && !error.message.includes("private diagnostic"));
  assert.deepEqual(nativeResult({ ...ok, stdout: '{"ok":true}' }), { ok: true });
});
test("engine wiring never reads credentials or fetches plaintext admin HTTP; provider fetch stays separate", () => {
  const source = fs.readFileSync(new URL("../../packages/mod/hooks/register.tsx", import.meta.url), "utf8");
  assert.doesNotMatch(source, /admin-token|admin-tls-token|dashboardLink|adminHeaders/);
  assert.doesNotMatch(source, /return \$\.http\.fetch\(url/);
  assert.match(source, /\$\.http\.fetch\(source === 'zen'/);
  assert.match(source, /\$\.process\.run\(command\.argv, command\.init\)/);
  assert.match(source, /\$\.fs\.stat\(file, \{ resolve: false \}\)/);
});
