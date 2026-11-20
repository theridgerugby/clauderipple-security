import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

test("personal fork bootstrap refuses before any install or download effects", t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-bootstrap-denial-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const windows = process.platform === "win32";
  const installer = path.resolve(import.meta.dirname, "../../../scripts", windows ? "install.ps1" : "install.sh");
  const source = fs.readFileSync(installer, "utf8");
  const marker = "# LEGACY_INSTALLER_BODY:";
  assert.ok(source.indexOf(marker) > 0);
  assert.match(source.slice(0, source.indexOf(marker)), /^exit 1$/m);
  const env = { ...process.env, CLAUDERIPPLE_PREFIX: root, CLAUDERIPPLE_HOME: root,
    CLAUDERIPPLE_PACKAGE: "this-must-not-be-downloaded", CLAUDERIPPLE_NO_SETUP: "1", CLAUDERIPPLE_NO_TRAY: "1" };
  const result = spawnSync(windows ? "powershell.exe" : "/bin/sh",
    windows ? ["-NoProfile", "-NonInteractive", "-File", installer] : [installer],
    { env, encoding: "utf8", timeout: 30_000 });
  assert.equal(result.status, 1, result.stdout + result.stderr);
  assert.match(result.stderr, /personal security fork disables bootstrap installation/);
  assert.match(result.stderr, /docs\/personal-windows-install\.md/);
  assert.deepEqual(fs.readdirSync(root), [], "no runtime, credentials, settings or bootstrap output is created");
});
