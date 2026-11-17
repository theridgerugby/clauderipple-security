import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeConfig } from "../../router/src/config.ts";
import { writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { readPrivateFile } from "../../router/src/private-file.ts";
import { assertPersonalCliCommandAllowed, updateApprovedOrigin } from "../src/security-config.ts";

test("origin approval requires an explicit acknowledgement before creating configuration", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-origin-ack-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  assert.throws(() => updateApprovedOrigin({ file, action: "approve-origin", origin: "https://example.test" }), /acknowledge-data-sharing/);
  assert.equal(fs.existsSync(file), false);
  for (const origin of ["http://example.test", "https://*.example.test", "https://user:password@example.test", "https://example.test/v1", "https://example.test?key=dummy", "https://example.test/#fragment"]) {
    assert.throws(() => updateApprovedOrigin({ file, action: "approve-origin", origin, acknowledgeDataSharing: true }), /exact HTTPS origin/);
    assert.equal(fs.existsSync(file), false);
  }
});

test("a pre-install explicit approval uses the private config writer and revocation is exact", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-origin-config-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  const approve = (origin: string) => updateApprovedOrigin({ file, action: "approve-origin", origin, acknowledgeDataSharing: true });
  assert.deepEqual(approve("https://EXAMPLE.test:443/"), { origin: "https://example.test", changed: true, approvedOrigins: ["https://example.test"] });
  assert.equal(approve("https://example.test").changed, false);
  approve("https://other.example.test:8443");
  const stored = JSON.parse(readPrivateFile(file).toString("utf8"));
  assert.deepEqual(stored.security, { mode: "personal", approvedOrigins: ["https://example.test", "https://other.example.test:8443"] });
  assert.notEqual(stored.autoUpdate, true);
  if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(updateApprovedOrigin({ file, action: "revoke-origin", origin: "https://example.test" }), {
    origin: "https://example.test", changed: true, approvedOrigins: ["https://other.example.test:8443"],
  });
});

test("approval preserves existing provider credentials without returning or logging them", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-origin-preserve-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  const config = normalizeConfig({ providers: { fixture: { type: "google", auth: "api-key", apiKey: "dummy-never-used-key" } } });
  writeSecretJsonAtomic(file, config);
  const result = updateApprovedOrigin({ file, action: "approve-origin", origin: "https://generativelanguage.googleapis.com", acknowledgeDataSharing: true });
  assert.equal(JSON.stringify(result).includes("dummy-never-used-key"), false);
  assert.deepEqual(JSON.parse(readPrivateFile(file).toString("utf8")).providers, config.providers);
});

test("invalid existing configuration is preserved instead of silently replaced by defaults", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-origin-invalid-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  for (const config of [[], { security: { mode: "personal", approvedOrigins: ["https://example.test/path"] } }, { autoUpdate: true }]) {
    writeSecretJsonAtomic(file, config);
    const before = fs.readFileSync(file);
    assert.throws(() => updateApprovedOrigin({ file, action: "approve-origin", origin: "https://example.test", acknowledgeDataSharing: true }), /existing configuration/);
    assert.deepEqual(fs.readFileSync(file), before);
  }
});

test("the 32-origin bound does not evict an earlier approval", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "cr-origin-bound-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  const security = { mode: "personal" as const, approvedOrigins: Array.from({ length: 32 }, (_, index) => `https://origin${index}.test`) };
  writeSecretJsonAtomic(file, normalizeConfig({ security }));
  const before = fs.readFileSync(file);
  assert.throws(() => updateApprovedOrigin({ file, action: "approve-origin", origin: "https://extra.test", acknowledgeDataSharing: true }), /At most 32/);
  assert.deepEqual(fs.readFileSync(file), before);
});

test("personal command gate blocks activation and executable updates, retaining status and cleanup", () => {
  const config = normalizeConfig({});
  for (const argv of [["remote"], ["remote", "install"], ["remote", "add", "host"], ["remote", "pair"], ["remote", "refresh"], ["update"], ["update", "--force"], ["google-login"], ["google-login", "--manual"]]) {
    assert.throws(() => assertPersonalCliCommandAllowed(config, argv), /disabled in personal mode/);
  }
  for (const argv of [["remote", "status"], ["remote", "hosts"], ["remote", "uninstall"], ["remote", "remove", "host"], ["update", "--check"], ["uninstall"], ["google-logout"], ["security", "revoke-origin", "https://example.test"]]) {
    assert.doesNotThrow(() => assertPersonalCliCommandAllowed(config, argv));
  }
});
