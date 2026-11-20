import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { dependencyClosure, verifyPersonalInstall, verifyPersonalManifests } from "../../scripts/check-personal-install.mjs";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const saveJson = (filename, value) => { fs.mkdirSync(path.dirname(filename), { recursive: true }); fs.writeFileSync(filename, JSON.stringify(value)); };

function fixture(t) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-inventory-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const manifest = { name: "clauderipple", dependencies: { "proper-lockfile": "1.0.0", undici: "1.0.0" },
    devDependencies: { "@electron/fuses": "1.0.0", "@types/node": "1.0.0", "@types/proper-lockfile": "1.0.0", typescript: "1.0.0" } };
  const app = { name: "@clauderipple/app", devDependencies: { electron: "1.0.0" } };
  const lock = { lockfileVersion: 3, packages: { "": manifest, "packages/app": app } };
  for (const name of [...Object.keys(manifest.dependencies), ...Object.keys(manifest.devDependencies), "electron"]) {
    lock.packages[`node_modules/${name}`] = { version: "1.0.0" };
    saveJson(path.join(root, "node_modules", name, "package.json"), { name, version: "1.0.0" });
  }
  saveJson(path.join(root, "package.json"), manifest);
  saveJson(path.join(root, "package-lock.json"), lock);
  saveJson(path.join(root, "packages/app/package.json"), app);
  fs.mkdirSync(path.join(root, "node_modules/@clauderipple"), { recursive: true });
  fs.symlinkSync(path.join(root, "packages/app"), path.join(root, "node_modules/@clauderipple/app"), process.platform === "win32" ? "junction" : "dir");
  return { root, lock, manifest, app };
}

test("personal manifest keeps only Desktop runtime dependencies; full Remote workspace stays locked", () => {
  const { manifest, lock } = verifyPersonalManifests(checkout);
  assert.deepEqual(Object.keys(manifest.dependencies).sort(), ["proper-lockfile", "undici"]);
  const remote = JSON.parse(fs.readFileSync(path.join(checkout, "packages/remote/package.json"), "utf8"));
  for (const name of ["@anthropic-ai/claude-agent-sdk", "qrcode-generator", "tweetnacl", "web-push", "ws", "zod"]) {
    assert.ok(remote.dependencies[name]);
    assert.equal(lock.packages["packages/remote"].dependencies[name], remote.dependencies[name]);
  }
});

test("personal package inventory accepts only the locked owner-build closure", t => {
  const { root } = fixture(t);
  const report = verifyPersonalInstall(root);
  assert.equal(report.packages, 7);
  assert.deepEqual(report.coreRuntimePackages, ["proper-lockfile", "undici"]);
  assert.ok(report.bytes > 0);
  assert.equal(report.electronBinaryInstalled, false);
});

test("heavy dependencies are rejected even when hidden under another package", t => {
  const { root } = fixture(t);
  saveJson(path.join(root, "node_modules/electron/node_modules/@anthropic-ai/claude-agent-sdk/package.json"), { name: "@anthropic-ai/claude-agent-sdk", version: "1.0.0" });
  assert.throws(() => verifyPersonalInstall(root), /Remote or release-tool dependency present/);
});

test("unexpected packages, changed versions and missing core dependencies are failures", t => {
  const { root } = fixture(t);
  const extra = path.join(root, "node_modules/extra");
  saveJson(path.join(extra, "package.json"), { name: "extra", version: "1.0.0" });
  assert.throws(() => verifyPersonalInstall(root), /unexpected package/);
  fs.rmSync(extra, { recursive: true });
  saveJson(path.join(root, "node_modules/undici/package.json"), { name: "undici", version: "2.0.0" });
  assert.throws(() => verifyPersonalInstall(root), /version differs/);
  fs.rmSync(path.join(root, "node_modules/undici"), { recursive: true });
  assert.throws(() => verifyPersonalInstall(root), /missing required personal dependency/);
});

test("a workspace link cannot turn a personal checkout into a Remote host installation", t => {
  const { root } = fixture(t);
  const remote = path.join(root, "packages/remote");
  fs.mkdirSync(remote, { recursive: true });
  fs.symlinkSync(remote, path.join(root, "node_modules/@clauderipple/remote"), process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => verifyPersonalInstall(root), /unexpected linked dependency|Remote or release-tool dependency/);
});

test("required transitive peers and nested versions resolve through the lockfile", () => {
  const lock = { packages: {
    "node_modules/parent": { dependencies: { child: "1" }, peerDependencies: { peer: "1", optionalPeer: "1" }, peerDependenciesMeta: { optionalPeer: { optional: true } } },
    "node_modules/parent/node_modules/child": { version: "1" }, "node_modules/child": { version: "2" }, "node_modules/peer": { version: "1" },
  } };
  const closure = dependencyClosure(lock, [{ importer: "", name: "parent" }]);
  assert.deepEqual([...closure.keys()].sort(), ["node_modules/parent", "node_modules/parent/node_modules/child", "node_modules/peer"]);
});

test("a changed or newly added root dependency requires an explicit boundary review", t => {
  const { root, manifest } = fixture(t);
  manifest.dependencies.ws = "1.0.0";
  saveJson(path.join(root, "package.json"), manifest);
  assert.throws(() => verifyPersonalInstall(root), /root runtime dependencies changed/);
});
