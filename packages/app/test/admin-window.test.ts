import test from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import os from "node:os";
import fs from "node:fs";
import { adminViewFromArgs, adminUserDataPath, prepareAdminUserDataPath } from "../src/admin-window.ts";

test("native UI launch carries only an allowlisted view", () => {
  assert.equal(adminViewFromArgs(["electron", "--ripple-admin-view=mod"]), "mod");
  assert.equal(adminViewFromArgs(["app", "--ripple-admin-view=dashboard"]), "health");
  for (const args of [[], ["--ripple-admin-view=https://attacker.example"], ["--ripple-admin-view=mod#script"], ["--admin-token=secret"]]) {
    assert.equal(adminViewFromArgs(args), undefined);
  }
});

test("a private Electron profile exists before setPath and refuses alias or world-readable profiles", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-profile-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const profile = path.join(root, "new", "profile");
  assert.equal(prepareAdminUserDataPath(profile), profile);
  assert.equal(fs.statSync(profile).isDirectory(), true);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(profile).mode & 0o777, 0o700);
    fs.chmodSync(profile, 0o755);
    assert.throws(() => prepareAdminUserDataPath(profile), /owner-only/);
    fs.chmodSync(profile, 0o700);
    const alias = path.join(root, "alias");
    fs.symlinkSync(profile, alias);
    assert.throws(() => prepareAdminUserDataPath(alias), /alias/);
  }
});

test("Electron single-instance identity follows installation home without revealing its path", () => {
  const base = path.resolve("fixture-app-data");
  const first = adminUserDataPath(base, "installation-one");
  assert.notEqual(first, adminUserDataPath(base, "installation-two"));
  assert.notEqual(first, adminUserDataPath(base, "INSTALLATION-ONE"));
  assert.equal(first, adminUserDataPath(base, path.resolve("installation-one")));
  assert.ok(first.startsWith(path.join(base, "ClaudeRipple") + path.sep));
  assert.equal(path.basename(first).includes("installation-one"), false);
});
