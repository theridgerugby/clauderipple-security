import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { ensureAdminTlsIdentity, readAdminTlsIdentity, readAdminEndpoint, writeAdminEndpoint, removeAdminEndpoint, type AdminEndpoint } from "../src/admin-transport-state.ts";
import { createCa, createLeaf } from "../src/x509.ts";
import { writePrivateFileAtomic } from "../src/locked-file.ts";

function homeFor(t: TestContext): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-transport-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

test("admin TLS identity is persistent, private, IP-bound and independent of the proxy CA", t => {
  const home = homeFor(t);
  assert.equal(readAdminTlsIdentity(home), undefined);
  assert.equal(readAdminEndpoint(home), undefined);
  const identity = ensureAdminTlsIdentity(home);
  assert.deepEqual(ensureAdminTlsIdentity(home), identity);
  assert.deepEqual(readAdminTlsIdentity(home), identity);
  const cert = new crypto.X509Certificate(identity.certPem), ca = new crypto.X509Certificate(identity.caCertPem);
  assert.ok(cert.checkIP("127.0.0.1"));
  assert.equal(cert.checkHost("api.anthropic.com"), undefined);
  assert.ok(cert.verify(ca.publicKey));
  assert.equal(ca.subject, "CN=ClaudeRipple local admin CA");
  assert.deepEqual(fs.readdirSync(home), ["admin-tls-identity.json"]);
  assert.deepEqual(Object.keys(identity).sort(), ["caCertPem", "certPem", "keyPem", "version"]);
  if (process.platform !== "win32") assert.equal(fs.statSync(path.join(home, "admin-tls-identity.json")).mode & 0o777, 0o600);
});

test("malformed or incoherent identities fail closed without replacing the stored bytes", t => {
  const home = homeFor(t), other = homeFor(t);
  const identity = ensureAdminTlsIdentity(home), foreign = ensureAdminTlsIdentity(other);
  const file = path.join(home, "admin-tls-identity.json");
  for (const value of ["{dummy-private-fragment", JSON.stringify({ ...identity, keyPem: foreign.keyPem }), JSON.stringify({ ...identity, caCertPem: foreign.caCertPem })]) {
    fs.writeFileSync(file, value, { mode: 0o600 });
    assert.throws(() => ensureAdminTlsIdentity(home), error => error instanceof Error && /admin.*(?:state|identity)/.test(error.message) && !error.message.includes("dummy-private"));
    assert.equal(fs.readFileSync(file, "utf8"), value);
  }
});

test("exposed POSIX transport identity or endpoint permissions fail closed without repair", { skip: process.platform === "win32" }, t => {
  const home = homeFor(t);
  const identity = ensureAdminTlsIdentity(home);
  const identityFile = path.join(home, "admin-tls-identity.json");
  fs.chmodSync(identityFile, 0o644);
  assert.throws(() => readAdminTlsIdentity(home), /owner-only/);
  assert.throws(() => ensureAdminTlsIdentity(home), /owner-only/);
  assert.equal(fs.statSync(identityFile).mode & 0o777, 0o644, "a potentially copied private key is not silently trusted again");
  assert.deepEqual(JSON.parse(fs.readFileSync(identityFile, "utf8")), identity);
  const endpoint: AdminEndpoint = { version: 1, instanceId: "a".repeat(32), publicPort: 8792, tlsPort: 49100 };
  writeAdminEndpoint(home, endpoint);
  const endpointFile = path.join(home, "admin-tls-endpoint.json");
  fs.chmodSync(endpointFile, 0o666);
  assert.throws(() => readAdminEndpoint(home), /owner-only/);
  assert.throws(() => removeAdminEndpoint(home, endpoint.instanceId), /owner-only/);
  assert.equal(fs.statSync(endpointFile).mode & 0o777, 0o666);
  assert.deepEqual(JSON.parse(fs.readFileSync(endpointFile, "utf8")), endpoint);
});

test("endpoint metadata validates ports and cleanup is scoped to the publishing instance", t => {
  const home = homeFor(t);
  const first: AdminEndpoint = { version: 1, instanceId: "a".repeat(32), publicPort: 8792, tlsPort: 49100 };
  writeAdminEndpoint(home, first);
  assert.deepEqual(readAdminEndpoint(home), first);
  removeAdminEndpoint(home, "b".repeat(32));
  assert.deepEqual(readAdminEndpoint(home), first);
  const second = { ...first, instanceId: "b".repeat(32), tlsPort: 49101 };
  writeAdminEndpoint(home, second);
  removeAdminEndpoint(home, first.instanceId);
  assert.deepEqual(readAdminEndpoint(home), second);
  for (const bad of [{ ...first, publicPort: 0 }, { ...first, tlsPort: 65536 }, { ...first, tlsPort: 8792 }, { ...first, instanceId: "unsafe" }, { ...first, instanceId: first.instanceId + "\n" }]) {
    assert.throws(() => writeAdminEndpoint(home, bad), /invalid/);
  }
  removeAdminEndpoint(home, second.instanceId);
  assert.equal(readAdminEndpoint(home), undefined);
});

test("only server initialization renews a coherent expired identity atomically", t => {
  const home = homeFor(t);
  const ca = createCa({ cn: "expired admin test CA" });
  const leaf = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem, days: -1 / 48 });
  const previous = { version: 1, caCertPem: ca.certPem, certPem: leaf.certPem, keyPem: leaf.keyPem };
  const file = path.join(home, "admin-tls-identity.json");
  writePrivateFileAtomic(file, JSON.stringify(previous));
  assert.throws(() => readAdminTlsIdentity(home), /expired/);
  assert.deepEqual(JSON.parse(fs.readFileSync(file, "utf8")), previous, "client read never writes a replacement identity");
  const renewed = ensureAdminTlsIdentity(home);
  assert.notEqual(renewed.certPem, previous.certPem);
  assert.notEqual(renewed.caCertPem, previous.caCertPem);
  assert.deepEqual(readAdminTlsIdentity(home), renewed);
});

test("linked transport state is never followed or overwritten", { skip: process.platform === "win32" }, t => {
  const home = homeFor(t);
  const target = path.join(home, "untouched");
  fs.writeFileSync(target, "original", { mode: 0o600 });
  fs.symlinkSync(target, path.join(home, "admin-tls-identity.json"));
  assert.throws(() => ensureAdminTlsIdentity(home), /regular/);
  fs.symlinkSync(target, path.join(home, "admin-tls-endpoint.json"));
  assert.throws(() => readAdminEndpoint(home), /regular/);
  assert.throws(() => removeAdminEndpoint(home, "a".repeat(32)), /regular/);
  assert.equal(fs.readFileSync(target, "utf8"), "original");
});

test("concurrent identity initialization produces one coherent certificate and key bundle", async t => {
  const home = homeFor(t);
  const source = new URL("../src/admin-transport-state.ts", import.meta.url).href;
  const run = () => new Promise<string>((resolve, reject) => {
    const child = spawn(process.execPath, ["--input-type=module", "-e", `
      import crypto from "node:crypto";
      import {ensureAdminTlsIdentity} from ${JSON.stringify(source)};
      process.stdout.write(new crypto.X509Certificate(ensureAdminTlsIdentity(${JSON.stringify(home)}).certPem).fingerprint256);
    `], { stdio: ["ignore", "pipe", "pipe"] });
    let output = "", diagnostic = "";
    child.stdout.setEncoding("utf8").on("data", value => { output += value; });
    child.stderr.setEncoding("utf8").on("data", value => { diagnostic += value; });
    child.once("error", reject);
    child.once("exit", code => code === 0 ? resolve(output) : reject(new Error(diagnostic)));
  });
  const results = await Promise.all(Array.from({ length: 4 }, run));
  assert.equal(new Set(results).size, 1);
  assert.equal(new crypto.X509Certificate(readAdminTlsIdentity(home)!.certPem).fingerprint256, results[0]);
});
