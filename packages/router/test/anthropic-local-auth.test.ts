import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ClaudeCodeAuthStore, ClaudeCodeCredentialStore } from "../src/providers/anthropic.ts";
import { ObservedClaudeCodeAuth } from "../src/providers/anthropic-observed.ts";
import { authorizeClaudeLocalAuth, isClaudeLocalAuthRevoked, revokeClaudeLocalAuth } from "../src/providers/anthropic-local-auth.ts";
import { readClaudeAuthFile, removeClaudeAuthFile, saveClaudeOAuthFile } from "../src/providers/anthropic-token-file.ts";

function fixture(t: TestContext): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-local-consent-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

test("local logout clears a cached borrowed login and blocks every automatic source until explicit authorization", async t => {
  const home = fixture(t), observed = new ObservedClaudeCodeAuth(path.join(home, "claude-auth-observed.json"));
  let reads = 0, refreshes = 0;
  const credentials = new ClaudeCodeCredentialStore(() => { reads++; return JSON.stringify({ claudeAiOauth: { accessToken: "synthetic-borrowed-token", expiresAt: 1_000_000 } }); }, () => 1);
  const store = new ClaudeCodeAuthStore(credentials, { home, observed, env: {}, now: () => 1,
    fetch: async () => { refreshes++; throw new Error("local logout must not touch upstream OAuth"); } });
  assert.ok(!(store.get() instanceof Error));
  assert.equal(reads, 1);
  observed.observe(["authorization", "Bearer synthetic-observed-token"], 1);
  const captured = store.get();
  assert.ok(!(captured instanceof Error));
  assert.equal(captured.source, "observed");
  store.revoke();
  assert.equal(isClaudeLocalAuthRevoked(home), true);
  assert.ok(store.get() instanceof Error);
  assert.equal(store.describeSource(), null);
  observed.observe(["authorization", "Bearer different-synthetic-token"], 2);
  assert.equal(observed.getFresh(2), null);
  await store.refreshIfNeeded();
  assert.equal(reads, 1, "logout never immediately reads the original client's token again");
  assert.equal(refreshes, 0, "no upstream revocation or OAuth refresh occurs");
  const envStore = new ClaudeCodeAuthStore(credentials, { home, env: { CLAUDE_CODE_OAUTH_TOKEN: "synthetic-env-token" }, now: () => 1 });
  assert.ok(envStore.get() instanceof Error, "an inherited environment variable does not silently undo local logout");
  store.authorize();
  assert.ok(!(store.get() instanceof Error));
  assert.equal(reads, 2, "explicit authorization rechecks the OS source rather than reviving the old cache");
});

test("persistent refusal is checked again after a synchronous credential reader returns", t => {
  const home = fixture(t);
  const credentials = new ClaudeCodeCredentialStore(() => {
    // Models another process publishing a logout while a credential-store subprocess was running.
    revokeClaudeLocalAuth(home);
    return JSON.stringify({ claudeAiOauth: { accessToken: "synthetic-raced-token", expiresAt: 1_000_000 } });
  }, () => 1);
  const store = new ClaudeCodeAuthStore(credentials, { home, env: {}, now: () => 1 });
  assert.ok(store.get() instanceof Error);
});

for (const reconnect of [false, true]) {
  test(`an old in-flight refresh cannot restore credentials after logout${reconnect ? " and an explicit new login" : ""}`, async t => {
    const home = fixture(t), now = 1_000_000;
    saveClaudeOAuthFile(home, { accessToken: "synthetic-old-access", refreshToken: "synthetic-old-refresh", expiresAt: now + 1 });
    const response = Promise.withResolvers<Response>();
    let calls = 0;
    const store = new ClaudeCodeAuthStore(new ClaudeCodeCredentialStore(() => null, () => now), {
      home, env: {}, now: () => now, fetch: async () => { calls++; return response.promise; },
    });
    const pending = store.refreshIfNeeded();
    assert.equal(calls, 1);
    store.revoke();
    removeClaudeAuthFile(home);
    if (reconnect) {
      store.authorize();
      saveClaudeOAuthFile(home, { accessToken: "synthetic-new-login", refreshToken: "synthetic-new-login-refresh", expiresAt: now + 3_600_000 });
    }
    response.resolve(Response.json({ access_token: "synthetic-obsolete-refresh-answer", refresh_token: "synthetic-obsolete-refresh-token", expires_in: 3600 }));
    await pending;
    const current = readClaudeAuthFile(home);
    if (reconnect) assert.equal(current?.token, "synthetic-new-login");
    else { assert.equal(current, null); assert.ok(store.get() instanceof Error); }
    assert.equal(calls, 1);
  });
}

test("an external logout suppresses a running store without clearing any real client-owned file", t => {
  const home = fixture(t), client = path.join(home, "synthetic-client-owned-login");
  fs.writeFileSync(client, "synthetic-client-secret", { mode: 0o600 });
  let reads = 0;
  const credentials = new ClaudeCodeCredentialStore(() => { reads++; return JSON.stringify({ claudeAiOauth: { accessToken: "synthetic-token", expiresAt: 1000 } }); }, () => 1);
  const store = new ClaudeCodeAuthStore(credentials, { home, env: {}, now: () => 1 });
  assert.ok(!(store.get() instanceof Error));
  revokeClaudeLocalAuth(home);
  assert.ok(store.get() instanceof Error);
  assert.equal(reads, 1);
  assert.equal(fs.readFileSync(client, "utf8"), "synthetic-client-secret");
  authorizeClaudeLocalAuth(home);
  assert.ok(!(store.get() instanceof Error));
  assert.equal(reads, 2);
});

test("a complete external logout/reconnect invalidates a pending refresh even if the same old file remains", async t => {
  const home = fixture(t), now = 1_000_000;
  saveClaudeOAuthFile(home, { accessToken: "synthetic-old-access", refreshToken: "synthetic-old-refresh", expiresAt: now + 1 });
  const response = Promise.withResolvers<Response>();
  const store = new ClaudeCodeAuthStore(new ClaudeCodeCredentialStore(() => null, () => now), {
    home, env: {}, now: () => now, fetch: async () => response.promise,
  });
  const pending = store.refreshIfNeeded();
  revokeClaudeLocalAuth(home);
  authorizeClaudeLocalAuth(home);
  response.resolve(Response.json({ access_token: "synthetic-obsolete-answer", refresh_token: "synthetic-obsolete-refresh", expires_in: 3600 }));
  await pending;
  assert.equal(readClaudeAuthFile(home)?.token, "synthetic-old-access", "old refresh never checkpoints into a new consent generation");
});

test("a failed logout-state write still blocks a live auth store with no observed helper", async t => {
  const home = fixture(t);
  let reads = 0;
  const store = new ClaudeCodeAuthStore(new ClaudeCodeCredentialStore(() => { reads++; return JSON.stringify({ claudeAiOauth: { accessToken: "synthetic-borrowed-token", expiresAt: 1000 } }); }, () => 1), { home, env: {}, now: () => 1 });
  assert.ok(!(store.get() instanceof Error));
  t.mock.method(fs, "renameSync", () => { throw new Error("synthetic consent write failure"); });
  assert.throws(() => store.revoke(), /synthetic consent write failure/);
  assert.ok(store.get() instanceof Error);
  assert.equal(store.describeSource(), null);
  await store.refreshIfNeeded();
  assert.equal(reads, 1);
});
