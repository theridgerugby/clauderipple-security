import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { PERSONAL_ENTRYPOINTS, REQUIRED_PERSONAL_OUTPUTS, verifyBuiltPersonalRuntime } from "../../scripts/build-personal.mjs";

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-build-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  for (const relative of REQUIRED_PERSONAL_OUTPUTS) {
    fs.mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
    fs.writeFileSync(path.join(root, relative), relative.endsWith(".json") ? "{}" : "");
  }
  return root;
}

test("personal build explicitly includes executable helpers outside static imports", () => {
  for (const entry of ["packages/cli/src/admin-bridge.ts", "packages/cli/src/watchdog-port.ts"]) assert.ok(PERSONAL_ENTRYPOINTS.includes(entry));
});

test("compiled personal inventory accepts built-ins and the two reviewed runtime packages", t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), 'import fs from "node:fs"; import lockfile from "proper-lockfile"; await import("undici");');
  const report = verifyBuiltPersonalRuntime(root);
  assert.equal(report.files, REQUIRED_PERSONAL_OUTPUTS.length);
  assert.ok(report.bytes > 0);
});

test("compiled personal inventory rejects missing helper or relative dynamic imports", t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), 'await import("./missing.js");');
  assert.throws(() => verifyBuiltPersonalRuntime(root), /Missing or escaping emitted import/);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), "");
  fs.unlinkSync(path.join(root, "cli/src/watchdog-port.js"));
  assert.throws(() => verifyBuiltPersonalRuntime(root), /ENOENT|Missing personal runtime output/);
});

test("compiled personal inventory rejects external SDK imports and non-personal output", t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), 'import sdk from "@anthropic-ai/claude-agent-sdk";');
  assert.throws(() => verifyBuiltPersonalRuntime(root), /Unexpected personal runtime package/);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), 'const sdk = require("@anthropic-ai/claude-agent-sdk");');
  assert.throws(() => verifyBuiltPersonalRuntime(root), /Unexpected personal runtime package/);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), "");
  fs.mkdirSync(path.join(root, "remote/src"), { recursive: true });
  fs.writeFileSync(path.join(root, "remote/src/main.js"), "");
  assert.throws(() => verifyBuiltPersonalRuntime(root), /Non-personal output leaked/);
});

test("compiled runtime cannot depend on a file outside the emitted tree", t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "cli/src/index.js"), 'export * from "../../../../elsewhere.js";');
  assert.throws(() => verifyBuiltPersonalRuntime(root), /Missing or escaping emitted import/);
});

test("build asset inspection rejects linked trees", t => {
  const root = fixture(t);
  const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-build-outside-"));
  t.after(() => fs.rmSync(elsewhere, { recursive: true, force: true }));
  fs.symlinkSync(elsewhere, path.join(root, "ui/linked-assets"), process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => verifyBuiltPersonalRuntime(root), /symbolic link/);
});
