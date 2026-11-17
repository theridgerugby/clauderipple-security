import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ADMIN_RUNTIME_FILE, adminBridgePath, parseAdminRuntime, readAdminRuntime, recordAdminRuntime } from "../src/admin-runtime.ts";
import { runtime } from "../src/runtime.ts";

test("native execution descriptor records installed absolute files with no secrets", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-runtime-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const row = recordAdminRuntime(home);
  assert.equal(row.node, fs.realpathSync(process.execPath));
  assert.equal(row.bridge, fs.realpathSync(adminBridgePath()));
  assert.deepEqual(readAdminRuntime(home), row);
  assert.deepEqual(Object.keys(row).sort(), ["bridge", "env", "home", "node", "version"]);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(home).mode & 0o777, 0o700);
    assert.equal(fs.statSync(path.join(home, ADMIN_RUNTIME_FILE)).mode & 0o777, 0o600);
  }
  assert.equal(fs.existsSync(path.join(home, "admin-tls-token")), false);
});
test("descriptor parser rejects foreign homes, PATH commands and executable environment injection", () => {
  const home = path.resolve(os.tmpdir(), "native-admin");
  const valid = { version: 1, home, node: process.execPath, bridge: adminBridgePath(), env: {} };
  assert.equal(parseAdminRuntime(valid, home).home, home);
  for (const change of [
    { version: 2 }, { home: path.join(home, "other") }, { node: "node" }, { node: "\\\\server\\node.exe" },
    { bridge: path.join(home, "arbitrary.js") }, { bridge: "admin-bridge.ts" },
    { env: { NODE_OPTIONS: "--require=evil" } }, { env: { ELECTRON_RUN_AS_NODE: "0" } },
  ]) assert.throws(() => parseAdminRuntime({ ...valid, ...change }, home), /Invalid native admin runtime/);
});
test("recording fails before publishing when the bundled helper is absent", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-missing-runtime-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  assert.throws(() => recordAdminRuntime(home, { ...runtime(), cli: path.join(home, "index.js") }));
  assert.equal(fs.existsSync(path.join(home, ADMIN_RUNTIME_FILE)), false);
});
