import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { ADMIN_TOKEN_HEADER, adminAuthHeaders, ensureAdminToken, readAdminToken, validAdminToken } from "../src/admin-auth.ts";
import { writePrivateFileAtomic } from "../src/locked-file.ts";

test("admin capability is random, persistent, private, and matched exactly", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-auth-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  assert.equal(readAdminToken(home), undefined);
  assert.deepEqual(adminAuthHeaders(home), {});
  const token = ensureAdminToken(home);
  assert.match(token, /^[a-f0-9]{64}$/);
  assert.equal(ensureAdminToken(home), token);
  assert.equal(readAdminToken(home), token);
  assert.deepEqual(adminAuthHeaders(home), { [ADMIN_TOKEN_HEADER]: token });
  assert.equal(validAdminToken(token, token), true);
  for (const bad of [undefined, "", "0".repeat(64), token + " ", token + "\n", [token, token]]) {
    assert.equal(validAdminToken(bad, token), false);
  }
  if (process.platform !== "win32") assert.equal(fs.statSync(path.join(home, "admin-tls-token")).mode & 0o777, 0o600);
});

test("admin capability fails closed on malformed, readable-by-others, or linked files", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-auth-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "admin-tls-token");
  writePrivateFileAtomic(file, "bad");
  assert.throws(() => ensureAdminToken(home), /invalid admin credential/);
  fs.writeFileSync(file, "a".repeat(64), { mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(file, 0o644);
    assert.throws(() => readAdminToken(home), /owner-only/);
    fs.chmodSync(file, 0o600);
    const alias = path.join(home, "alias");
    fs.linkSync(file, alias);
    assert.throws(() => readAdminToken(home), /private file/);
    fs.unlinkSync(alias);
    fs.renameSync(file, alias);
    fs.symlinkSync(alias, file);
    assert.throws(() => ensureAdminToken(home), /private file/);
    assert.equal(fs.readFileSync(alias, "utf8"), "a".repeat(64), "refusal leaves the target untouched");
  }
});

test("concurrent startup creates one complete admin capability", async t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-auth-race-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const source = new URL("../src/admin-auth.ts", import.meta.url).href;
  const run = () => new Promise<string>((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", `import {ensureAdminToken} from ${JSON.stringify(source)}; process.stdout.write(ensureAdminToken(${JSON.stringify(home)}));`], { stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.setEncoding("utf8").on("data", data => { stdout += data; });
    child.stderr.setEncoding("utf8").on("data", data => { stderr += data; });
    child.once("error", reject);
    child.once("exit", code => code === 0 ? resolve(stdout) : reject(new Error(`token worker failed: ${stderr}`)));
  });
  const tokens = await Promise.all(Array.from({ length: 6 }, run));
  assert.equal(new Set(tokens).size, 1);
  assert.equal(readAdminToken(home), tokens[0]);
});

test("the TLS capability never reuses or accepts the legacy HTTP token", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-auth-migration-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const legacy = "a".repeat(64);
  fs.writeFileSync(path.join(home, "admin-token"), legacy, { mode: 0o600 });
  assert.equal(readAdminToken(home), undefined);
  const current = ensureAdminToken(home);
  assert.notEqual(current, legacy);
  assert.equal(validAdminToken(legacy, current), false);
  assert.equal(fs.readFileSync(path.join(home, "admin-token"), "utf8"), legacy);
});
