import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { readPrivateConfigPorts } from "../src/admin-auth.ts";
import { type SecretProtector } from "../src/secret-storage.ts";
import { writePrivateFileAtomic, writeSecretJsonAtomic } from "../../router/src/locked-file.ts";

// Tests inject an ephemeral RAM-only protector; native Windows tests use real CurrentUser DPAPI.
function fakeProtector(): SecretProtector {
  const key = crypto.randomBytes(32);
  return {
    kind: "app-test-ephemeral-aes-gcm",
    protect(bytes, entropy) {
      const nonce = crypto.randomBytes(12), cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
      cipher.setAAD(entropy);
      return Buffer.concat([nonce, cipher.update(bytes), cipher.final(), cipher.getAuthTag()]);
    },
    unprotect(bytes, entropy) {
      const cipher = crypto.createDecipheriv("aes-256-gcm", key, bytes.subarray(0, 12));
      cipher.setAAD(entropy); cipher.setAuthTag(bytes.subarray(-16));
      return Buffer.concat([cipher.update(bytes.subarray(12, -16)), cipher.final()]);
    },
  };
}

test("main's verified config reader extracts only ports from the router's encrypted file", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-app-config-secret-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json"), protector = fakeProtector();
  assert.deepEqual(readPrivateConfigPorts(home, { protector }), { proxy: 8790, admin: 8791 });
  writeSecretJsonAtomic(file, { listen: { port: 12990 }, admin: { port: 12992 }, providers: { school: { apiKey: "synthetic-school-key" } } }, { protector });
  const result = readPrivateConfigPorts(home, { protector });
  assert.deepEqual(result, { proxy: 12990, admin: 12992 });
  assert.equal(JSON.stringify(result).includes("synthetic-school-key"), false);
  assert.equal(fs.readFileSync(file).includes("synthetic-school-key"), false);
  const ciphertext = fs.readFileSync(file);
  writePrivateFileAtomic(file, ciphertext.subarray(0, ciphertext.length - 6));
  assert.throws(() => readPrivateConfigPorts(home, { protector }), error => error instanceof Error && /protection failed/.test(error.message) && !error.message.includes("synthetic-school-key"));
});

test("app config decoding keeps owner/link checks ahead of the decrypt/cache boundary", { skip: process.platform === "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-app-config-permission-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json"), protector = fakeProtector();
  writeSecretJsonAtomic(file, { listen: { port: 12990 } }, { protector });
  assert.deepEqual(readPrivateConfigPorts(home, { protector }), { proxy: 12990, admin: 12991 });
  fs.chmodSync(file, 0o644);
  assert.throws(() => readPrivateConfigPorts(home, { protector }), /owner-only/);
  fs.chmodSync(file, 0o600);
  fs.linkSync(file, file + ".alias");
  assert.throws(() => readPrivateConfigPorts(home, { protector }), /regular private file/);
});

test("app config parsing and invalid ports never expose credential-bearing JSON excerpts", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-app-config-invalid-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  for (const text of ['{"apiKey":"synthetic-secret-do-not-print', '{"listen":{"port":"synthetic-secret-do-not-print"}}', '{"admin":{"port":65536}}']) {
    writePrivateFileAtomic(file, text);
    assert.throws(() => readPrivateConfigPorts(home), error => error instanceof Error && error.message === "invalid private application config");
  }
});

test("native Windows app reads a real DPAPI config written by router storage", { skip: process.platform !== "win32", timeout: 30_000 }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-native-app-dpapi-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  writeSecretJsonAtomic(file, { listen: { port: 22990 }, admin: { port: 22991 }, apiKey: "synthetic-native-config-secret" });
  assert.deepEqual(readPrivateConfigPorts(home), { proxy: 22990, admin: 22991 });
  assert.equal(fs.readFileSync(file).includes("synthetic-native-config-secret"), false);
});
