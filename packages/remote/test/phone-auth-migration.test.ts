import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { EventEmitter } from "node:events";
import { execFile, spawnSync } from "node:child_process";
import { promisify } from "node:util";
import nacl from "tweetnacl";
import { ensurePhonePairingSecurity, rotatePhonePairingToken } from "../src/phone-auth-migration.ts";
import { loadConfig, saveConfig } from "../src/config.ts";
import { RelayHost, type WsLike } from "../src/relay.ts";
import { phoneHello, phoneFinish } from "../src/e2ee.ts";
import { HostServer } from "../src/server.ts";
import { posixModes } from "../../../test/capabilities.ts";

function legacy(t: import("node:test").TestContext) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-phone-migrate-"));
  const cfg = loadConfig(dir);
  cfg.relay = "https://relay.example";
  saveConfig(cfg, dir);
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  return { dir, cfg, file: path.join(dir, "host.json") };
}

test("old phone capability rotates once with its marker, preserves host fields, and remains private", t => {
  const f = legacy(t);
  const before = JSON.parse(fs.readFileSync(f.file, "utf8"));
  const first = ensurePhonePairingSecurity(f.dir);
  assert.equal(first.rotated, true);
  assert.notEqual(first.token, before.token);
  assert.match(first.token, /^[A-Za-z0-9_-]{43}$/);
  const stored = JSON.parse(fs.readFileSync(f.file, "utf8"));
  assert.deepEqual(stored, { ...before, token: first.token, pairingSecurityVersion: 2 });
  if (posixModes) assert.equal(fs.statSync(f.file).mode & 0o777, 0o600);
  const original = fs.readFileSync(f.file, "utf8");
  assert.deepEqual(ensurePhonePairingSecurity(f.dir), { ...first, rotated: false });
  assert.equal(fs.readFileSync(f.file, "utf8"), original);
});

test("read-only host configuration does not trigger a pairing rotation", t => {
  const f = legacy(t);
  const before = fs.readFileSync(f.file, "utf8");
  assert.equal(loadConfig(f.dir, false).token, f.cfg.token);
  assert.equal(fs.readFileSync(f.file, "utf8"), before);
});

test("malformed and future pairing generations fail closed without modifying stored credentials", t => {
  const f = legacy(t);
  for (const value of ["{", "[]", "null", JSON.stringify({ ...f.cfg, token: "short" }),
    JSON.stringify({ ...f.cfg, pairingSecurityVersion: "2" }), JSON.stringify({ ...f.cfg, pairingSecurityVersion: 3 }),
    JSON.stringify({ ...f.cfg, token: "x".repeat(64), pairingSecurityVersion: 2 })]) {
    fs.writeFileSync(f.file, value, { mode: 0o600 });
    assert.throws(() => ensurePhonePairingSecurity(f.dir), /startup was refused/);
    assert.equal(fs.readFileSync(f.file, "utf8"), value);
  }
});

test("a failed atomic replacement never commits only the marker or reports migration success", t => {
  const f = legacy(t);
  const before = fs.readFileSync(f.file, "utf8");
  const replace = t.mock.method(fs, "renameSync", () => { throw Object.assign(new Error("fixture write failure"), { code: "EIO" }); });
  assert.throws(() => ensurePhonePairingSecurity(f.dir), /could not be committed/);
  replace.mock.restore();
  assert.equal(fs.readFileSync(f.file, "utf8"), before);
  assert.equal(fs.readdirSync(f.dir).some(name => name.includes(".tmp-")), false);
});

test("migrated invalid tokens are rejected by loadConfig before any automatic repair can overwrite them", t => {
  const f = legacy(t);
  for (const token of [undefined, "short", "x".repeat(64), "!".repeat(43)]) {
    const original = JSON.stringify({ ...f.cfg, token, pairingSecurityVersion: 2 });
    fs.writeFileSync(f.file, original, { mode: 0o600 });
    assert.throws(() => loadConfig(f.dir), /invalid migrated phone pairing token/);
    assert.equal(fs.readFileSync(f.file, "utf8"), original);
  }
});

test("stale legacy and v2 settings saves cannot restore an older phone capability", t => {
  const f = legacy(t);
  const legacySnapshot = { ...f.cfg };
  const migrated = ensurePhonePairingSecurity(f.dir);
  const v2Snapshot = loadConfig(f.dir, false);
  const rotated = rotatePhonePairingToken(f.dir, migrated.token);
  assert.notEqual(rotated.token, migrated.token);
  for (const snapshot of [legacySnapshot, v2Snapshot]) {
    saveConfig({ ...snapshot, bind: "::1" }, f.dir);
    const saved = loadConfig(f.dir, false);
    assert.equal(saved.token, rotated.token);
    assert.equal(saved.pairingSecurityVersion, 2);
    assert.equal(saved.bind, "::1");
  }
  assert.throws(() => rotatePhonePairingToken(f.dir, migrated.token), /changed; reload/);
  assert.equal(loadConfig(f.dir, false).token, rotated.token);
});

test("an exposed migrated token is refused without repairing its mode or restoring trust", { skip: !posixModes }, t => {
  const f = legacy(t);
  const migrated = ensurePhonePairingSecurity(f.dir);
  const snapshot = loadConfig(f.dir, false);
  const original = fs.readFileSync(f.file);
  fs.chmodSync(f.file, 0o644);
  assert.throws(() => loadConfig(f.dir, false), /must already be owner-only/);
  assert.throws(() => saveConfig(snapshot, f.dir), /must already be owner-only/);
  assert.throws(() => ensurePhonePairingSecurity(f.dir), /startup was refused/);
  assert.throws(() => rotatePhonePairingToken(f.dir, migrated.token), /startup was refused/);
  assert.equal(fs.statSync(f.file).mode & 0o777, 0o644);
  assert.deepEqual(fs.readFileSync(f.file), original);
});

test("a readable legacy token rotates into new private state without a read-only permission mutation", { skip: !posixModes }, t => {
  const f = legacy(t);
  fs.chmodSync(f.file, 0o644);
  assert.equal(loadConfig(f.dir, false).token, f.cfg.token);
  assert.equal(fs.statSync(f.file).mode & 0o777, 0o644);
  const migrated = ensurePhonePairingSecurity(f.dir);
  assert.equal(migrated.rotated, true);
  assert.notEqual(migrated.token, f.cfg.token);
  assert.equal(fs.statSync(f.file).mode & 0o777, 0o600);
});

test("native Windows migrated phone state rejects an exposed ACL without repairing it", { skip: process.platform !== "win32" }, t => {
  const f = legacy(t);
  const migrated = ensurePhonePairingSecurity(f.dir);
  const snapshot = loadConfig(f.dir, false);
  const original = fs.readFileSync(f.file);
  const executable = path.win32.join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const source = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$item = Get-Item -LiteralPath ([string]$request.path) -Force
if ($request.widen) {
  $acl = $item.GetAccessControl()
  $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($everyone, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow))
  $item.SetAccessControl($acl)
}
[Console]::Out.Write($item.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]'Access, Owner, Group'))
`;
  const descriptor = (widen: boolean) => {
    const result = spawnSync(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", source], {
      input: JSON.stringify({ path: f.file, widen }), encoding: "utf8", timeout: 10_000, windowsHide: true,
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  const exposed = descriptor(true);
  assert.throws(() => loadConfig(f.dir, false), /Cannot verify owner-only Windows/);
  assert.throws(() => saveConfig(snapshot, f.dir), /Cannot verify owner-only Windows/);
  assert.throws(() => ensurePhonePairingSecurity(f.dir), /startup was refused/);
  assert.throws(() => rotatePhonePairingToken(f.dir, migrated.token), /startup was refused/);
  assert.equal(descriptor(false), exposed);
  assert.deepEqual(fs.readFileSync(f.file), original);
});

test("host configuration rejects aliased, oversized and malformed records without reflecting credentials", t => {
  const f = legacy(t);
  for (const content of ["x".repeat(1024 * 1024 + 1), '{"privateToken":"fixture-only-secret", INVALID}']) {
    fs.writeFileSync(f.file, content, { mode: 0o600 });
    assert.throws(() => loadConfig(f.dir, false), error => {
      assert.ok(error instanceof Error);
      assert.match(error.message, /size bound|Invalid phone host configuration JSON/);
      assert.equal(error.message.includes("fixture-only-secret"), false);
      return true;
    });
    assert.equal(fs.readFileSync(f.file, "utf8"), content);
  }
  const alias = path.join(f.dir, "host-alias.json");
  fs.linkSync(f.file, alias);
  assert.throws(() => loadConfig(f.dir, false), /regular unlinked/);
});

test("independent concurrent startup processes commit exactly one phone security migration", async t => {
  const f = legacy(t);
  const helper = new URL("../src/phone-auth-migration.ts", import.meta.url).href;
  const run = promisify(execFile);
  const source = `import { ensurePhonePairingSecurity } from ${JSON.stringify(helper)}; console.log(JSON.stringify(ensurePhonePairingSecurity(process.argv[1])));`;
  const results = await Promise.all(Array.from({ length: 3 }, async () => {
    const result = await run(process.execPath, ["--input-type=module", "-e", source, f.dir], { timeout: 25_000 });
    return JSON.parse(result.stdout) as { token: string; rotated: boolean };
  }));
  assert.equal(results.filter(result => result.rotated).length, 1);
  assert.equal(new Set(results.map(result => result.token)).size, 1);
  assert.notEqual(results[0]!.token, f.cfg.token);
});

class RelayWire extends EventEmitter implements WsLike {
  readyState = 0;
  bufferedAmount = 0;
  sent: (string | Uint8Array)[] = [];
  closedWith: number | null = null;
  open() { this.readyState = 1; this.emit("open"); }
  text(text: string) { this.emit("message", Buffer.from(text), false); }
  send(data: string | Uint8Array) { this.sent.push(data); }
  close(code = 1000) { if (this.readyState !== 3) { this.readyState = 3; this.closedWith = code; this.emit("close", code); } }
  terminate() { this.close(1006); }
}

test("real RelayHost encryption plus host authorization refuses the old direct token and accepts only the new token", async t => {
  const f = legacy(t);
  const migrated = ensurePhonePairingSecurity(f.dir);
  const sessions = { list: () => [], groups: () => undefined, watchAttached() {} };
  const host = new HostServer({ listen: "127.0.0.1", port: 0, token: migrated.token, webDir: f.dir,
    sessions: sessions as never, router: { models: async () => [], status: async () => ({ ok: true, proxyEnv: {} }) },
    hostName: "test", version: "test", recentCli: async () => [] });
  const hostKey = nacl.box.keyPair();
  const sockets: RelayWire[] = [];
  const relay = new RelayHost({ relay: "https://relay.example", serverId: f.cfg.serverId, secret: f.cfg.relaySecret, hostKey, nacl,
    makeSocket: () => { const socket = new RelayWire(); sockets.push(socket); return socket; }, onPeer: peer => host.connected(peer) });
  t.after(async () => { relay.stop(); await host.close(); });
  relay.start(); const control = sockets[0]!; control.open(); control.text('{"relay":"hello"}');
  for (const [index, token] of [f.cfg.token, migrated.token].entries()) {
    control.text(JSON.stringify({ relay: "connect", conn: `fixture-conn-${index}` }));
    const wire = sockets.at(-1)!; assert.notEqual(wire, control); wire.open();
    const hello = phoneHello(nacl); wire.text(hello.text);
    assert.equal(typeof wire.sent[0], "string");
    const phone = phoneFinish(nacl, hello.eph, hostKey.publicKey, wire.sent[0] as string);
    wire.emit("message", Buffer.from(phone.seal(JSON.stringify({ t: "hello", token, clientId: "fixture-phone" }))), true);
    assert.ok(wire.sent[1] instanceof Uint8Array);
    const response = JSON.parse(phone.open(wire.sent[1]));
    assert.equal(response.t, index === 0 ? "denied" : "ready");
    assert.equal(wire.closedWith, index === 0 ? 4003 : null);
    assert.equal(wire.sent.some(frame => typeof frame === "string" && (frame.includes(f.cfg.token) || frame.includes(migrated.token))), false);
  }
});
