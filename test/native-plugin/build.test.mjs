import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { buildNativePlugin, checkNativePlugin, runtimeClosure } from "../../scripts/build-native-plugin.mjs";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-build-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  fs.mkdirSync(path.join(root, "gemini-native/src"), { recursive: true });
  fs.writeFileSync(path.join(root, "gemini-native/src/request.js"), 'import crypto from "node:crypto";\n');
  return root;
}

test("native proof manifest keeps explicit consent, exact-build gate and sensitive optional key", () => {
  const { manifest } = checkNativePlugin(checkout);
  assert.equal(manifest.userConfig.consent.default, false);
  assert.equal(manifest.userConfig.validated_engine_version.default, "");
  assert.equal(manifest.userConfig.api_key.sensitive, true);
  assert.equal(manifest.userConfig.api_key.required, undefined);
});

test("native helper closure follows only local JS and reviewed builtins", t => {
  const root = fixture(t);
  fs.writeFileSync(path.join(root, "gemini-native/src/request.js"), 'import "./pure.js"; import https from "node:https";');
  fs.writeFileSync(path.join(root, "gemini-native/src/pure.js"), 'import "./request.js";');
  assert.deepEqual(runtimeClosure(root), ["gemini-native/src/pure.js", "gemini-native/src/request.js"]);
});

test("native helper closure refuses SDKs, filesystem/process imports, dynamic modules and traversal", t => {
  const root = fixture(t);
  for (const source of ['import "undici";', 'import "node:fs";', 'import "node:child_process";',
    'await import("node:https");', 'require("node:crypto");', 'export * from "../../../escape.js";', 'import "./missing.js";']) {
    fs.writeFileSync(path.join(root, "gemini-native/src/request.js"), source);
    assert.throws(() => runtimeClosure(root));
  }
});

test("native helper closure refuses linked source parents and files", t => {
  const root = fixture(t);
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-outside-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  fs.writeFileSync(path.join(outside, "other.js"), "");
  fs.symlinkSync(outside, path.join(root, "linked"), process.platform === "win32" ? "junction" : "dir");
  fs.writeFileSync(path.join(root, "gemini-native/src/request.js"), 'import "../../linked/other.js";');
  assert.throws(() => runtimeClosure(root), /symbolic link/);
  fs.writeFileSync(path.join(root, "gemini-native/src/request.js"), 'import "./hard.js";');
  fs.linkSync(path.join(outside, "other.js"), path.join(root, "gemini-native/src/hard.js"));
  assert.throws(() => runtimeClosure(root), /independent regular file/);
});

test("native proof build is inert, self-contained, hashed, and executable without node_modules", { timeout: 60_000 }, t => {
  const report = buildNativePlugin(checkout);
  const stage = path.dirname(report.directory);
  assert.equal(path.dirname(stage), checkout);
  assert.match(path.basename(stage), /^native-plugin-build-/);
  t.after(() => fs.rmSync(stage, { recursive: true, force: true }));
  assert.equal(report.runtimePackages, 0);
  assert.ok(report.bytes < 400 * 1024, `proof grew to ${report.bytes} bytes`);
  const inventory = JSON.parse(fs.readFileSync(path.join(report.directory, "inventory.json"), "utf8"));
  assert.equal(inventory.runtimePackages, 0);
  assert.equal(inventory.experimental, true);
  for (const item of inventory.files) {
    const bytes = fs.readFileSync(path.join(report.directory, item.path));
    assert.equal(bytes.length, item.bytes);
    assert.equal(crypto.createHash("sha256").update(bytes).digest("hex"), item.sha256);
  }
  assert.ok(inventory.files.some(item => item.path === "runtime/request.mjs"));
  assert.ok(inventory.files.every(item => !/node_modules|\.key$|\.pem$|credentials|electron|watchdog|config\.json/.test(item.path)));
  assert.equal(fs.existsSync(path.join(stage, "compiled")), false);
  const empty = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-empty-"));
  t.after(() => fs.rmSync(empty, { recursive: true, force: true }));
  const env = { PATH: process.env.PATH ?? "", HOME: empty, USERPROFILE: empty, APPDATA: empty, LOCALAPPDATA: empty };
  for (const key of ["SystemRoot", "SYSTEMROOT", "WINDIR", "TEMP", "TMP"]) if (process.env[key]) env[key] = process.env[key];
  const result = spawnSync(process.execPath, [path.join(report.directory, "runtime/request.mjs")], {
    cwd: empty, env, input: '{"protocol":0}', encoding: "utf8", timeout: 10_000,
  });
  assert.equal(result.status, 0, result.stderr);
  assert.equal(result.stderr, "");
  assert.equal(JSON.parse(result.stdout).response.status, 400);
  assert.deepEqual(fs.readdirSync(empty), []);
});
