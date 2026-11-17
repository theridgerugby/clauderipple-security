import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import http from "node:http";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";
import { EventLog } from "../src/eventlog.ts";
import { PermissionQueue } from "../src/permissions.ts";
import { Sessions } from "../src/sessions.ts";

const exec = promisify(execFile);
const main = fileURLToPath(new URL("../src/main.ts", import.meta.url));
const cli = fileURLToPath(new URL("../../cli/src/index.ts", import.meta.url));

function isolatedEnv(dir: string): NodeJS.ProcessEnv {
  return { ...process.env, HOME: dir, USERPROFILE: dir, CLAUDERIPPLE_HOME: path.join(dir, "router"),
    RIPPLE_REMOTE_HOME: path.join(dir, "remote"), NODE_OPTIONS: "" };
}

for (const script of [cli, main]) for (const flag of ["--help", "-h"]) {
  test(`${path.basename(path.dirname(script))}/${path.basename(script)} ${flag} prints usage without opening host state`, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-help-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const args = script === cli ? ["remote", flag] : [flag];
    const result = await exec(process.execPath, [script, ...args], { env: isolatedEnv(dir), timeout: 10_000 });
    assert.match(result.stdout, /Usage: clauderipple remote/);
    assert.match(result.stdout, /--bind/);
    assert.doesNotMatch(result.stdout + result.stderr, /listening on|EADDRINUSE|Invalid event/);
    assert.deepEqual(fs.readdirSync(dir), [], "help creates no configuration or session files");
  });
}

for (const stored of [false, true]) {
  test(`--new-token is refused before any configuration or service mutation (${stored ? "existing" : "new"} state)`, async t => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-refused-rotation-"));
    t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
    const home = path.join(dir, "remote");
    const file = path.join(home, "host.json");
    const original = JSON.stringify({ bind: "127.0.0.1", port: 8797, token: "x".repeat(43), pairingSecurityVersion: 2,
      serverId: "test-server-id-000", relaySecret: "y".repeat(43), adminUrl: "http://127.0.0.1:1" });
    if (stored) { fs.mkdirSync(home); fs.writeFileSync(file, original, { mode: 0o600 }); }
    const invocations = [
      [main, "--new-token", "--port", "54321"],
      [main, "pair", "--new-token"],
      [main, "install", "--new-token", "--port", "54321"],
      [main, "status", "--new-token"],
      [cli, "remote", "pair", "--new-token"],
    ];
    for (const args of invocations) {
      await assert.rejects(exec(process.execPath, args, { env: isolatedEnv(dir), timeout: 10_000 }), error => {
        assert.ok(error instanceof Error && "stderr" in error);
        assert.match(String(error.stderr), /--new-token is disabled|activation is disabled in personal mode/);
        if (args[0] === main) assert.match(String(error.stderr), /authenticated Phone settings/);
        assert.doesNotMatch(String(error.stderr), /EADDRINUSE|legacy host control|service.*unsupported/);
        return true;
      });
      assert.deepEqual(fs.readdirSync(dir), stored ? ["remote"] : []);
      if (stored) {
        assert.deepEqual(fs.readdirSync(home), ["host.json"]);
        assert.equal(fs.readFileSync(file, "utf8"), original);
      }
    }
  });
}

test("personal-mode host activation leaves pending permissions untouched for explicit cleanup or recovery", async t => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-startup-"));
  const occupied = http.createServer((_req, res) => res.end("occupied"));
  await new Promise<void>(resolve => occupied.listen(0, "127.0.0.1", resolve));
  t.after(async () => {
    await new Promise<void>(resolve => occupied.close(() => resolve()));
    fs.rmSync(dir, { recursive: true, force: true });
  });
  const address = occupied.address();
  assert.ok(address && typeof address !== "string");
  const home = path.join(dir, "remote");
  const id = "test-session";
  const sessionDir = path.join(home, "sessions", id);
  const permissionsFile = path.join(home, "permissions.json");
  const permissions = PermissionQueue.open(permissionsFile);
  const pending = permissions.request({ session: id, tool: "Bash", title: "", summary: "fixture", input: {} }).record;
  const permissionBytes = fs.readFileSync(permissionsFile);
  const log = EventLog.open({ dir: sessionDir });
  log.append({ kind: "state", state: "running" });
  log.append({ kind: "permission", id: pending.id, tool: "Bash", title: "", summary: "fixture", input: "fixture", canAlways: false });
  log.close();
  const records = JSON.stringify([{ id, state: "running", cwd: dir, title: "test", model: "test", effort: null, createdAt: 1, updatedAt: 1 }]);
  fs.writeFileSync(path.join(home, "sessions.json"), records);
  // These are dummy fixture values, not credentials for a service.
  fs.writeFileSync(path.join(home, "host.json"), JSON.stringify({ bind: "127.0.0.1", port: address.port,
    token: "x".repeat(32), serverId: "test-server-id-000", relaySecret: "y".repeat(32), adminUrl: "http://127.0.0.1:1" }));
  const hostBytes = fs.readFileSync(path.join(home, "host.json"));
  const before = new Map(fs.readdirSync(sessionDir).map(name => [name, fs.readFileSync(path.join(sessionDir, name))]));
  await assert.rejects(exec(process.execPath, [main], { env: isolatedEnv(dir), timeout: 10_000 }), error => {
    assert.ok(error instanceof Error && "stderr" in error);
    assert.match(String(error.stderr), /Remote activation is disabled/);
    return true;
  });
  assert.equal(fs.readFileSync(path.join(home, "sessions.json"), "utf8"), records);
  assert.deepEqual(fs.readFileSync(path.join(home, "host.json")), hostBytes, "the losing process did not rotate the running host's phone token");
  assert.deepEqual(fs.readdirSync(sessionDir).sort(), [...before.keys()].sort());
  for (const [name, bytes] of before) assert.deepEqual(fs.readFileSync(path.join(sessionDir, name)), bytes, name);
  assert.deepEqual(fs.readFileSync(permissionsFile), permissionBytes, "the losing process did not expire the live host's approval");
  const reopened = PermissionQueue.open(permissionsFile);
  assert.deepEqual(reopened.expiredOnOpen.map(p => p.id), [pending.id]);
  const restarted = new Sessions({ dir: home, permissions: reopened,
    router: { status: async () => ({ ok: true, proxyEnv: {} }), figures: async () => { throw new Error("unused"); } },
    queryFn: () => { throw new Error("recovery never starts a query"); }, onEvent() {}, onSessions() {},
  });
  try {
    restarted.recover();
    const expired = restarted.log(id).tail().events.find(e => e.kind === "permission_decided");
    assert.ok(expired?.kind === "permission_decided");
    assert.deepEqual([expired.id, expired.decision, expired.reason], [pending.id, "expired", "host_restarted"]);
  } finally { restarted.shutdown(); }
});
