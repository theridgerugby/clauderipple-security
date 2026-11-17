import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);

test("Electron runtime and packaging pin the same patched version and the intentional fuse policy", () => {
  const app = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  const electron = require("electron/package.json");
  assert.equal(app.devDependencies.electron, "45.3.3");
  assert.equal(app.build.electronVersion, app.devDependencies.electron);
  assert.equal(electron.version, app.devDependencies.electron);
  assert.equal(app.build.asar, true);
  assert.deepEqual(app.build.electronFuses, {
    // Packaged CLI/router use ELECTRON_RUN_AS_NODE; custom upstream CAs use NODE_EXTRA_CA_CERTS.
    runAsNode: true, enableNodeOptionsEnvironmentVariable: true,
    enableNodeCliInspectArguments: false, enableEmbeddedAsarIntegrityValidation: true,
    onlyLoadAppFromAsar: true, grantFileProtocolExtraPrivileges: false,
  });
});

test("the app and router use a byte-identical canonical Windows ACL implementation", () => {
  assert.equal(fs.readFileSync(new URL("../src/windows-private-acl.ts", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../../router/src/windows-private-acl.ts", import.meta.url), "utf8"));
});

test("the app and router use a byte-identical pinned TLS admin transport", () => {
  assert.equal(fs.readFileSync(new URL("../src/admin-transport-client.ts", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../../router/src/admin-transport-client.ts", import.meta.url), "utf8"));
});

test("the two modern builder glob consumers resolve patched minimatch without changing legacy glob APIs", () => {
  for (const consumer of ["app-builder-lib", "@electron/universal"]) {
    const from = createRequire(require.resolve(consumer));
    assert.equal(from("minimatch/package.json").version, "11.0.9", consumer);
    const { minimatch, Minimatch } = from("minimatch");
    const matcher = new Minimatch("dist/**", { dot: true });
    assert.equal(matcher.match("dist/main.js"), true);
    assert.equal(matcher.match("dist", true), true);
    assert.ok(Array.isArray(matcher.set));
    assert.equal(new Minimatch("!**/*.map").negate, true);
    assert.equal(minimatch("path/tool.node", "*.node", { matchBase: true }), true);
  }
  const fromGlob = createRequire(require.resolve("glob"));
  assert.equal(typeof fromGlob("minimatch"), "function", "glob7 still receives its compatible minimatch3 API");
});

test("real electron-builder file filters preserve includes, excludes, partial directories and dotfiles", () => {
  const { FileMatcher } = require("app-builder-lib/out/fileMatcher.js");
  const root = path.resolve("fixture-app");
  const filter = new FileMatcher(root, path.resolve("fixture-output"), (value: string) => value,
    ["dist/**", "assets/**", "package.json", "!**/*.map"]).createFilter();
  const matches = (relative: string, directory = false) => filter(path.join(root, relative), { isDirectory: () => directory });
  assert.equal(matches("dist", true), true);
  assert.equal(matches("dist/main.js"), true);
  assert.equal(matches("dist/.hidden.js"), true);
  assert.equal(matches("dist/main.js.map"), false);
  assert.equal(matches("assets/icon.png"), true);
  assert.equal(matches("package.json"), true);
  assert.equal(matches("src/main.ts"), false);
  assert.equal(matches("node_modules", true), false);
  // Directory shorthand is used by builder for extra resources and needs its .set inspection.
  const extra = new FileMatcher(root, path.resolve("fixture-output"), (value: string) => value, ["assets"]).createFilter();
  assert.equal(extra(path.join(root, "assets", "tray.png"), { isDirectory: () => false }), true);
});
