import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { certsExist, generateCerts } from "../src/certs.ts";
import { CertStore } from "../../router/src/certs.ts";

test("certificate generation and cached leaf issuance keep private files restricted", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-certificate-test-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const certs = generateCerts(home);
  assert.equal(certsExist(home), true);
  assert.ok(new CertStore(home).contextFor("claude.ai"));
  assert.ok(new CertStore(home).contextFor("claude.ai"), "reuse the protected cached key");
  if (process.platform !== "win32") {
    for (const file of [...Object.values(certs), path.join(home, "certs", "claude.ai.key")]) {
      assert.equal(fs.statSync(file).mode & 0o777, 0o600);
    }
  }
});

test("certificate generation refuses a private-key symlink before changing any certificate", { skip: process.platform === "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-certificate-test-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const external = path.join(home, "unrelated");
  fs.writeFileSync(external, "unchanged", { mode: 0o600 });
  fs.symlinkSync(external, path.join(home, "ca.key"));
  assert.throws(() => generateCerts(home), /regular/);
  assert.equal(fs.readFileSync(external, "utf8"), "unchanged");
  assert.equal(fs.existsSync(path.join(home, "ca.pem")), false);
});

test("cached leaf keys cannot alias an unrelated file", { skip: process.platform === "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-certificate-test-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  generateCerts(home);
  const certs = new CertStore(home);
  certs.contextFor("claude.ai");
  const cachedKey = path.join(home, "certs", "claude.ai.key");
  fs.renameSync(cachedKey, path.join(home, "unrelated"));
  fs.symlinkSync(path.join(home, "unrelated"), cachedKey);
  assert.throws(() => new CertStore(home).contextFor("claude.ai"), /regular/);
});
