// Real CLI entry point, isolated config/settings paths, no provider or OS-service invocation.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readPrivateFile } from "../../router/src/private-file.ts";

function fixture(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-personal-cli-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const env: NodeJS.ProcessEnv = { ...process.env, CLAUDERIPPLE_HOME: home, CLAUDE_SETTINGS_PATH: path.join(home, "claude-settings.json") };
  delete env.NODE_OPTIONS;
  const run = (...args: string[]) => spawnSync(process.execPath, [path.resolve(import.meta.dirname, "../src/index.ts"), ...args], {
    env, encoding: "utf8", timeout: 20_000, windowsHide: true,
  });
  return { home, run, config: path.join(home, "config.json") };
}

test("all help paths bypass policy storage and command mutations", t => {
  const f = fixture(t);
  for (const args of [["help"], ["install", "--help"], ["remote", "install", "--help"], ["security", "approve-origin", "https://example.test", "--help"]]) {
    const result = f.run(...args);
    assert.equal(result.status, 0, result.stdout + result.stderr);
    assert.deepEqual(fs.readdirSync(f.home), [], args.join(" "));
  }
});

test("the CLI refuses unacknowledged approval then persists only the explicitly named origin", t => {
  const f = fixture(t);
  const refused = f.run("security", "approve-origin", "https://example.test");
  assert.equal(refused.status, 1);
  assert.match(refused.stderr, /acknowledge-data-sharing/);
  assert.equal(fs.existsSync(f.config), false);
  const approved = f.run("security", "approve-origin", "https://example.test", "--acknowledge-data-sharing");
  assert.equal(approved.status, 0, approved.stdout + approved.stderr);
  assert.deepEqual(JSON.parse(readPrivateFile(f.config).toString("utf8")).security, { mode: "personal", approvedOrigins: ["https://example.test"] });
  const revoked = f.run("security", "revoke-origin", "https://example.test");
  assert.equal(revoked.status, 0, revoked.stdout + revoked.stderr);
  assert.deepEqual(JSON.parse(readPrivateFile(f.config).toString("utf8")).security.approvedOrigins, []);
  assert.equal(fs.existsSync(path.join(f.home, "claude-settings.json")), false);
});

test("personal activation/update denial happens before supervisor or downloader work", t => {
  const f = fixture(t);
  for (const args of [["remote", "install", "--print"], ["remote", "pair"], ["remote", "refresh"], ["remote", "add", "example.invalid"], ["update", "--force"], ["google-login"], ["google-login", "--manual"]]) {
    const result = f.run(...args);
    assert.equal(result.status, 1, result.stdout + result.stderr);
    assert.match(result.stderr, /disabled in personal mode/);
    assert.deepEqual(fs.readdirSync(f.home), [], args.join(" "));
  }
});
