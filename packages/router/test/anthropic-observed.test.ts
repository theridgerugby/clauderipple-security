// All identities below are disposable synthetic strings. Normal traffic must never persist them.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ObservedClaudeCodeAuth, OBSERVED_CLAUDE_CODE_TTL_MS } from "../src/providers/anthropic-observed.ts";
import { authorizeClaudeLocalAuth, claudeLocalAuthRevokedPath, isClaudeLocalAuthRevoked, revokeClaudeLocalAuth } from "../src/providers/anthropic-local-auth.ts";

const MINUTE = 60_000;
function storage(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-observed-"));
  const file = path.join(home, "claude-auth-observed.json");
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return { home, file };
}

for (const activity of ["observe", "noteUsed"] as const) {
  test(`continuous ${activity} stays fresh in RAM and never writes a credential`, t => {
    const { home, file } = storage(t);
    const auth = new ObservedClaudeCodeAuth(file);
    t.mock.method(fs, "writeFileSync", () => { throw new Error("normal observed traffic must not write any file"); });
    const headers = ["Authorization", "Bearer synthetic-observed-secret", "anthropic-beta", "mock-beta"];
    auth.observe(headers, 0);
    for (let minute = 1; minute <= 13 * 60; minute++) {
      if (activity === "observe") auth.observe(headers, minute * MINUTE);
      else auth.noteUsed("bearer synthetic-observed-secret", minute * MINUTE);
    }
    const now = 13 * 60 * MINUTE;
    assert.equal(auth.getFresh(now)?.observedAt, now);
    assert.deepEqual(auth.getFresh(now)?.headers, { Authorization: "Bearer synthetic-observed-secret", "anthropic-beta": "mock-beta" });
    assert.deepEqual(fs.readdirSync(home), []);
    assert.equal(new ObservedClaudeCodeAuth(file).getFresh(now), null, "restart has no saved token to restore");
    assert.equal(auth.getFresh(now + OBSERVED_CLAUDE_CODE_TTL_MS), null);
  });
}

test("startup deletes the legacy credential copy without importing it", t => {
  const { home, file } = storage(t);
  fs.writeFileSync(file, JSON.stringify({ authorization: "Bearer synthetic-legacy-secret", headers: { authorization: "Bearer synthetic-legacy-secret" }, observedAt: Date.now() }), { mode: 0o600 });
  const auth = new ObservedClaudeCodeAuth(file);
  assert.equal(auth.getFresh(), null);
  assert.deepEqual(fs.readdirSync(home), []);
});

test("token replacement and exact-token invalidation retain their generation guards in RAM", t => {
  const { file } = storage(t);
  const auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer old-token"], 0);
  auth.observe(["authorization", "Bearer new-token"], 1);
  auth.noteUsed("Bearer old-token", 10 * MINUTE);
  auth.forget("Bearer old-token");
  auth.noteUsed("Bearer new-token", 0);
  assert.equal(auth.getFresh(1)?.observedAt, 1);
  auth.forget("bearer new-token");
  auth.observe(["authorization", "Bearer new-token"], 2);
  auth.noteUsed("Bearer new-token", 10 * MINUTE);
  assert.equal(auth.getFresh(10 * MINUTE), null);
  auth.observe(["authorization", "Bearer replacement-token"], 10 * MINUTE);
  assert.equal(auth.getFresh(10 * MINUTE)?.authorization, "Bearer replacement-token");
  assert.equal(fs.existsSync(file), false);
});

test("explicit logout clears RAM and persists suppression across restart until explicit consent", t => {
  const { home, file } = storage(t);
  const auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer original-synthetic-secret", "user-agent", "claude-cli/2.0.1 (external, cli)"], 1);
  assert.ok(auth.getFresh(1));
  auth.revoke();
  assert.equal(isClaudeLocalAuthRevoked(home), true);
  assert.equal(auth.getFresh(1), null);
  assert.equal(auth.cliVersion(1), null);
  auth.observe(["authorization", "Bearer completely-new-synthetic-secret"], 2);
  auth.noteUsed("Bearer original-synthetic-secret", 2);
  assert.equal(auth.getFresh(2), null, "even a rotated token cannot undo local logout");
  const restarted = new ObservedClaudeCodeAuth(file);
  restarted.observe(["authorization", "Bearer completely-new-synthetic-secret"], 3);
  assert.equal(restarted.getFresh(3), null);
  const marker = fs.readFileSync(claudeLocalAuthRevokedPath(home), "utf8");
  const state = JSON.parse(marker);
  assert.equal(state.allowed, false);
  assert.match(state.generation, /^[a-f0-9]{32}$/);
  assert.doesNotMatch(marker, /synthetic-secret|Bearer|authorization/);
  assert.deepEqual(fs.readdirSync(home), ["claude-local-auth-state.json"]);
  auth.authorize();
  assert.equal(auth.getFresh(4), null, "explicit consent does not resurrect a prior snapshot");
  auth.observe(["authorization", "Bearer freshly-presented-synthetic-secret"], 4);
  assert.equal(auth.getFresh(4)?.authorization, "Bearer freshly-presented-synthetic-secret");
  assert.deepEqual(fs.readdirSync(home), ["claude-local-auth-state.json"]);
  const reauthorized = JSON.parse(fs.readFileSync(claudeLocalAuthRevokedPath(home), "utf8"));
  assert.equal(reauthorized.allowed, true);
  assert.notEqual(reauthorized.generation, state.generation);
});

test("an out-of-process logout is observed before returning or recapturing RAM auth", t => {
  const { home, file } = storage(t);
  const auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer synthetic-observed-secret"], 0);
  revokeClaudeLocalAuth(home);
  assert.equal(auth.getFresh(0), null);
  auth.observe(["authorization", "Bearer another-synthetic-secret"], 1);
  assert.equal(auth.getFresh(1), null);
  authorizeClaudeLocalAuth(home);
  assert.equal(auth.getFresh(2), null);
  auth.observe(["authorization", "Bearer freshly-authorized-secret"], 2);
  assert.ok(auth.getFresh(2));
});

test("failed persistent logout still clears and blocks the running process", t => {
  const { file } = storage(t);
  const auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer synthetic-observed-secret"], 0);
  t.mock.method(fs, "renameSync", () => { throw new Error("synthetic write failure"); });
  assert.throws(() => auth.revoke(), /synthetic write failure/);
  auth.observe(["authorization", "Bearer another-synthetic-secret"], 1);
  assert.equal(auth.getFresh(1), null);
});

test("an in-memory-only instance also honors explicit logout and reauthorization", () => {
  const auth = new ObservedClaudeCodeAuth();
  auth.observe(["authorization", "Bearer old-synthetic-secret"], 0);
  auth.revoke();
  auth.observe(["authorization", "Bearer new-synthetic-secret"], 1);
  assert.equal(auth.getFresh(1), null);
  auth.authorize();
  assert.equal(auth.getFresh(1), null);
  auth.observe(["authorization", "Bearer new-synthetic-secret"], 2);
  assert.ok(auth.getFresh(2));
});

test("a full external logout/reconnect between reads does not resurrect an old RAM snapshot", t => {
  const { home, file } = storage(t);
  const auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer old-synthetic-secret"], 0);
  revokeClaudeLocalAuth(home);
  authorizeClaudeLocalAuth(home);
  assert.equal(auth.getFresh(1), null, "the persistent consent generation exposes the intervening logout");
  auth.observe(["authorization", "Bearer newly-presented-secret"], 2);
  assert.equal(auth.getFresh(2)?.authorization, "Bearer newly-presented-secret");
});

test("an explicit CLI reauthorization can resume a router that previously revoked its live instance", t => {
  const { home, file } = storage(t), auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer old-synthetic-secret"], 0);
  auth.revoke();
  authorizeClaudeLocalAuth(home);
  assert.equal(auth.getFresh(1), null);
  auth.observe(["authorization", "Bearer newly-authorized-secret"], 2);
  assert.ok(auth.getFresh(2));
});
