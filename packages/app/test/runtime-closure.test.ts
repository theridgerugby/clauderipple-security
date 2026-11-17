import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { execFileSync } from "node:child_process";
// @ts-ignore The build hook is executable ESM, with its exported pure staging/validation seams.
import { copyRuntimeTree, reserveRuntimeStage, stageNativeRuntime, verifyRuntimeClosure } from "../scripts/stage-runtime.mjs";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-closure-"));
const runtime = path.join(temporary, "resources", "clauderipple");
const copiedRuntime = path.join(temporary, "actual-builder-resources", "clauderipple");
test.after(() => fs.rmSync(temporary, { recursive: true, force: true }));

test("dormant native release configuration reserves distinct Windows target staging paths", () => {
  const app = JSON.parse(fs.readFileSync(path.join(checkout, "packages/app/package.json"), "utf8"));
  assert.equal(app.build.beforePack, "scripts/stage-runtime.mjs");
  assert.equal(app.build.npmRebuild, false);
  assert.equal(app.build.nodeGypRebuild, false);
  assert.deepEqual(app.build.extraResources, [
    { from: "release-native/runtime/${os}/${arch}", to: "clauderipple" },
    { from: "release-native/runtime/${os}/${arch}/node_modules", to: "clauderipple/node_modules" },
  ]);
  assert.equal(app.scripts["release:win"], "node scripts/block-personal-release.mjs");
  const destinations = new Set<string>();
  for (const arch of ["x64", "arm64"]) {
    const from = app.build.extraResources[0].from.replace("${os}", "win").replace("${arch}", arch);
    assert.equal(from, `release-native/runtime/win/${arch}`);
    destinations.add(from);
  }
  assert.equal(destinations.size, 2);
});

test("owned runtime copying preserves selected dependencies and hidden mod manifests", () => {
  const project = path.join(temporary, "source-copy");
  const staged = path.join(project, "release-native/runtime/win/x64");
  const resources = path.join(temporary, "source-copied-resources");
  const files = ["node_modules/ws/package.json", "packages/remote/src/main.ts", "packages/mod/.claude-plugin/plugin.json", "packages/installers/install.ps1"];
  for (const file of files) { fs.mkdirSync(path.dirname(path.join(staged, file)), { recursive: true }); fs.writeFileSync(path.join(staged, file), "copy-fixture"); }
  const destination = path.join(resources, "clauderipple");
  copyRuntimeTree(staged, destination);
  copyRuntimeTree(path.join(staged, "node_modules/ws"), path.join(destination, "node_modules/ws"), true);
  for (const file of files) assert.equal(fs.readFileSync(path.join(resources, "clauderipple", file), "utf8"), "copy-fixture");
});

test("isolated native resources include complete sources, web assets, production peers and target SDK payload", () => {
  const result = stageNativeRuntime({ sourceRoot: checkout, output: runtime });
  assert.equal(result.platform, process.platform);
  assert.equal(result.arch, process.arch);
  const names = new Set(result.dependencies.map((item: { name: string }) => item.name));
  for (const name of ["@anthropic-ai/claude-agent-sdk", "@anthropic-ai/sdk", "@modelcontextprotocol/sdk", "qrcode-generator", "tweetnacl", "web-push", "ws", "zod", "proper-lockfile", "undici"]) assert.ok(names.has(name), name);
  assert.ok(names.has(`@anthropic-ai/claude-agent-sdk-${process.platform}-${process.arch}`));
  for (const name of ["electron", "electron-builder", "typescript", "wrangler", "@types/node"]) assert.equal(fs.existsSync(path.join(runtime, "node_modules", name)), false, name);
  for (const tree of ["router/src", "cli/src", "remote/src", "remote/web", "ui"]) {
    const from = path.join(checkout, "packages", tree);
    for (const relative of fs.readdirSync(from, { recursive: true, withFileTypes: true }).filter(entry => entry.isFile()).map(entry => path.relative(from, path.join(entry.parentPath, entry.name)))) {
      assert.deepEqual(fs.readFileSync(path.join(runtime, "packages", tree, relative)), fs.readFileSync(path.join(from, relative)), `${tree}/${relative}`);
    }
  }
  for (const file of ["install.sh", "install.ps1"]) assert.deepEqual(fs.readFileSync(path.join(runtime, "packages/installers", file)), fs.readFileSync(path.join(checkout, "scripts", file)));
  const pkg = JSON.parse(fs.readFileSync(path.join(runtime, "package.json"), "utf8"));
  assert.equal(pkg.type, "module"); assert.equal(pkg.private, true); assert.equal(pkg.devDependencies, undefined); assert.equal(pkg.scripts, undefined);
  for (const denied of ["packages/mod/tests", "packages/mod/preview", "packages/mod/.claude-plugin/types", ".env", "host.json", "admin-tls-token"]) assert.equal(fs.existsSync(path.join(runtime, denied)), false, denied);
  assert.equal(verifyRuntimeClosure(runtime).dependencies.length, result.dependencies.length);
});

test("an independently copied source-only runtime retains complete dependency closure", () => {
  fs.cpSync(runtime, copiedRuntime, { recursive: true, errorOnExist: true, force: false });
  assert.equal(verifyRuntimeClosure(copiedRuntime).dependencies.length, verifyRuntimeClosure(runtime).dependencies.length);
});

test("trusted parent aliases use canonical containment without accepting links within the runtime", () => {
  const alias = path.join(temporary, "aliased-resource-parent");
  fs.symlinkSync(path.dirname(runtime), alias, process.platform === "win32" ? "junction" : "dir");
  const aliasedRoot = path.join(alias, path.basename(runtime));
  assert.equal(verifyRuntimeClosure(aliasedRoot).dependencies.length, verifyRuntimeClosure(runtime).dependencies.length);
  const linkedRoot = path.join(temporary, "linked-runtime-root");
  fs.symlinkSync(runtime, linkedRoot, process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => verifyRuntimeClosure(linkedRoot), /not an independent directory/);
  const outside = path.join(temporary, "outside-runtime-tree");
  fs.mkdirSync(outside);
  const link = path.join(runtime, "packages/remote/src/untrusted-link");
  fs.symlinkSync(outside, link, process.platform === "win32" ? "junction" : "dir");
  try { assert.throws(() => verifyRuntimeClosure(aliasedRoot), /symbolic link/); }
  finally { fs.unlinkSync(link); }
});

test("isolated CLI and Remote help run with no checkout ancestor, NODE_PATH or user state", () => {
  assert.equal(fs.existsSync(path.join(temporary, "node_modules")), false);
  const state = path.join(temporary, "empty-home");
  fs.mkdirSync(state);
  const env: NodeJS.ProcessEnv = { PATH: path.dirname(process.execPath), HOME: state, USERPROFILE: state,
    CLAUDERIPPLE_HOME: path.join(state, "router"), RIPPLE_REMOTE_HOME: path.join(state, "remote"), NODE_PATH: "", NODE_OPTIONS: "",
    ...(process.env.SystemRoot ? { SystemRoot: process.env.SystemRoot } : {}) };
  for (const [entry, expected] of [["cli/src/index.ts", /clauderipple/], ["remote/src/main.ts", /Usage: clauderipple remote/]] as const) {
    const output = execFileSync(process.execPath, [path.join(copiedRuntime, "packages", entry), "--help"], { cwd: temporary, env, encoding: "utf8", timeout: 20_000 });
    assert.match(output, expected);
  }
  assert.deepEqual(fs.readdirSync(state), [], "help must not start the router, host, installer, provider, or trust-store work");
});

test("missing staged imports or dependencies fail instead of resolving from the checkout", () => {
  for (const relative of ["packages/remote/src/local-transport.ts", "node_modules/proper-lockfile"]) {
    const file = path.join(runtime, relative);
    const saved = `${file}.closure-fixture`;
    fs.renameSync(file, saved);
    try { assert.throws(() => verifyRuntimeClosure(runtime), /ENOENT|MODULE_NOT_FOUND|missing/); }
    finally { fs.renameSync(saved, file); }
  }
});

test("target SDK payload is mandatory and failure neither downloads nor creates partial resources", () => {
  const root = path.join(temporary, "missing-target");
  fs.mkdirSync(root);
  for (const name of ["package.json", "package-lock.json"]) fs.copyFileSync(path.join(checkout, name), path.join(root, name));
  const output = path.join(temporary, "must-stay-absent");
  assert.throws(() => stageNativeRuntime({ sourceRoot: root, output, platform: "win32", arch: "arm64" }), /matching locked @anthropic-ai\/claude-agent-sdk-win32-arm64/);
  assert.equal(fs.existsSync(output), false);
  assert.deepEqual(fs.readdirSync(root).sort(), ["package-lock.json", "package.json"]);
});

test("native resource inspection rejects injected install credentials and backup variants", () => {
  for (const relative of ["packages/router/src/admin-tls-token", "packages/remote/src/host-key.json", "packages/remote/web/local-control-tls/admin-tls-identity.json", "node_modules/ws/credentials.json.bak", ".npmrc"]) {
    const file = path.join(runtime, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, "synthetic-capability");
    try { assert.throws(() => verifyRuntimeClosure(runtime), /credential or repository metadata in release/); }
    finally {
      fs.rmSync(file);
      if (relative.includes("/local-control-tls/")) fs.rmdirSync(path.dirname(file));
    }
  }
});

test("dependency copying preserves legitimate package assets and rejects install credential paths", () => {
  const source = path.join(temporary, "dependency-assets");
  const destination = path.join(temporary, "dependency-assets-copied");
  fs.mkdirSync(source);
  for (const file of ["package.json", "config.json", "public.pem"]) fs.writeFileSync(path.join(source, file), "fixture-asset");
  copyRuntimeTree(source, destination, true);
  assert.deepEqual(fs.readdirSync(destination).sort(), ["config.json", "package.json", "public.pem"]);
  fs.writeFileSync(path.join(source, "admin-tls-token"), "synthetic-capability");
  assert.throws(() => copyRuntimeTree(source, path.join(temporary, "dependency-assets-rejected"), true), /credential or repository metadata/);
});

test("native ABI addons require a new reviewed target policy and cannot silently ship unbuilt", () => {
  const file = path.join(runtime, "node_modules/ws/unreviewed.node");
  fs.writeFileSync(file, "synthetic-native-addon");
  try { assert.throws(() => verifyRuntimeClosure(runtime), /unreviewed ABI addon/); }
  finally { fs.rmSync(file); }
});

test("a target reservation survives staging return and rejects concurrent or crashed-build reuse", () => {
  const root = path.join(temporary, "stage-lock");
  fs.mkdirSync(root);
  const first = reserveRuntimeStage(root, "darwin", "x64");
  fs.mkdirSync(first.output);
  fs.writeFileSync(path.join(first.output, "native-runtime.json"), JSON.stringify({ version: 1, platform: "darwin", arch: "x64" }));
  fs.writeFileSync(path.join(first.output, "keep-during-copy"), "fixture");
  assert.throws(() => reserveRuntimeStage(root, "darwin", "x64"), /staging is reserved/);
  assert.equal(fs.readFileSync(path.join(first.output, "keep-during-copy"), "utf8"), "fixture");
  first.release();
  const second = reserveRuntimeStage(root, "darwin", "x64");
  assert.equal(fs.existsSync(second.output), false, "only the recognized completed target may be replaced after release");
  second.release();
  const lock = path.join(root, "packages/app/release-native/runtime/mac/x64.stage-lock");
  fs.writeFileSync(lock, JSON.stringify({ pid: 999999999, nonce: "crashed-fixture" }));
  assert.throws(() => reserveRuntimeStage(root, "darwin", "x64"), /After verifying that no build is running/);
  assert.equal(fs.existsSync(lock), true, "an unrecognized stale lock must not be automatically removed");
});

test("staging cleanup refuses mismatched markers and redirected parents without deleting their data", () => {
  const root = path.join(temporary, "stage-marker");
  const output = path.join(root, "packages/app/release-native/runtime/mac/x64");
  fs.mkdirSync(output, { recursive: true });
  const marker = path.join(output, "native-runtime.json");
  fs.writeFileSync(marker, JSON.stringify({ version: 1, platform: "win32", arch: "x64" }));
  assert.throws(() => reserveRuntimeStage(root, "darwin", "x64"), /another target/);
  assert.equal(JSON.parse(fs.readFileSync(marker, "utf8")).platform, "win32");
  const redirectedRoot = path.join(temporary, "redirected-stage");
  const outside = path.join(temporary, "outside-stage");
  fs.mkdirSync(redirectedRoot); fs.mkdirSync(outside);
  fs.writeFileSync(path.join(outside, "keep"), "fixture");
  fs.symlinkSync(outside, path.join(redirectedRoot, "packages"), process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => reserveRuntimeStage(redirectedRoot, "darwin", "x64"), /not an independent directory/);
  assert.deepEqual(fs.readdirSync(outside), ["keep"]);
});
