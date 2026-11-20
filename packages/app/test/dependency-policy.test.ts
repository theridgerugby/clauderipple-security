import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
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

test("the app and router use a byte-identical canonical secret-storage implementation", () => {
  assert.equal(fs.readFileSync(new URL("../src/secret-storage.ts", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../../router/src/secret-storage.ts", import.meta.url), "utf8"));
});

test("the app and router use a byte-identical pinned TLS admin transport", () => {
  assert.equal(fs.readFileSync(new URL("../src/admin-transport-client.ts", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../../router/src/admin-transport-client.ts", import.meta.url), "utf8"));
});

test("source-only Windows installation excludes the vulnerable native packager dependency tree", () => {
  const root = new URL("../../../", import.meta.url);
  const project = JSON.parse(fs.readFileSync(new URL("package.json", root), "utf8"));
  const lock = JSON.parse(fs.readFileSync(new URL("package-lock.json", root), "utf8"));
  assert.equal(project.devDependencies["electron-builder"], undefined);
  for (const name of ["electron-builder", "app-builder-lib", "@electron/universal", "builder-util", "node-gyp", "tinyglobby", "fdir", "picomatch"]) {
    assert.equal(lock.packages[`node_modules/${name}`], undefined, `source-only lock must exclude ${name}`);
  }
});

test("every native distribution entry point is disabled in the source-only app", () => {
  const app = JSON.parse(fs.readFileSync(new URL("../package.json", import.meta.url), "utf8"));
  for (const name of ["dist", "dist:win", "release", "release:win"]) {
    assert.equal(app.scripts[name], "node scripts/block-personal-release.mjs");
  }
  const blocker = fs.readFileSync(new URL("../scripts/block-personal-release.mjs", import.meta.url), "utf8");
  assert.match(blocker, /source-only/);
  assert.match(blocker, /process\.exitCode = 1/);
  assert.doesNotMatch(blocker, /fetch\(|exec\(|spawn\(|require\(|writeFile|electron-builder/);
});
