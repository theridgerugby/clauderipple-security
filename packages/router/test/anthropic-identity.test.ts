// The current Claude login's identity: what `/api/oauth/profile` reduces to, and how rarely it asks.
import { test } from "node:test";
import assert from "node:assert/strict";

import { ClaudeCurrentIdentity, claudeIdentityFromBody } from "../src/providers/anthropic-identity.ts";
import { subjectHash } from "../src/providers/anthropic-accounts.ts";
import type { Credential } from "../src/pool.ts";

const PROFILE = {
  account: { uuid: "upstream-account-uuid", email: "Person@example.test" },
  organization: { uuid: "org-uuid", name: "Personal" },
};

function currentLogin(getToken: () => string): { credentials(): Promise<Credential[]> } {
  return {
    credentials: async () => [{ id: "current:abcdef", ownerId: "current", headers: { authorization: `Bearer ${getToken()}` } }],
  };
}

test("disabled identity access does not inspect credentials, contact upstream or return a previously cached identity", async () => {
  let enabled = true, credentials = 0, calls = 0;
  const identity = new ClaudeCurrentIdentity({ credentials: async () => {
    credentials++;
    return [{ id: "current:synthetic", ownerId: "current", headers: { authorization: "Bearer synthetic-identity-token" } }];
  } }, {
    upstream: () => "api.example.test", enabled: () => enabled,
    fetch: async () => { calls++; return Response.json(PROFILE); },
  });
  assert.equal((await identity.identify())?.email, PROFILE.account.email);
  enabled = false;
  assert.equal(await identity.identify(), null);
  assert.equal(await identity.identifyWith({ authorization: "Bearer synthetic-identity-token" }), null);
  assert.equal(credentials, 1);
  assert.equal(calls, 1);
  enabled = true;
  assert.equal((await identity.identify())?.email, PROFILE.account.email);
  assert.equal(calls, 2, "the old cache was discarded, not merely hidden");
});

test("discard cancels a pending profile and a late response cannot repopulate the identity cache", async () => {
  let calls = 0, release!: (response: Response) => void;
  let pendingSignal: AbortSignal | null | undefined;
  const identity = new ClaudeCurrentIdentity(currentLogin(() => "synthetic-token"), {
    upstream: () => "api.example.test",
    fetch: async (_url, init) => {
      calls++;
      if (calls > 1) return Response.json(PROFILE);
      pendingSignal = init.signal;
      return await new Promise<Response>(resolve => { release = resolve; });
    },
  });
  const lookup = identity.identifyWith({ authorization: "Bearer synthetic-token" });
  assert.ok(pendingSignal);
  identity.discard();
  assert.equal(pendingSignal.aborted, true);
  // This synthetic transport deliberately ignores the abort to exercise the publication guard.
  release(Response.json(PROFILE));
  assert.equal(await lookup, null);
  assert.equal((await identity.identifyWith({ authorization: "Bearer synthetic-token" }))?.email, PROFILE.account.email);
  assert.equal(calls, 2);
});

test("a mode change while credentials are pending prevents the later profile request", async () => {
  let enabled = true, calls = 0, release!: (value: Credential[]) => void;
  const identity = new ClaudeCurrentIdentity({ credentials: () => new Promise(resolve => { release = resolve; }) }, {
    upstream: () => "api.example.test", enabled: () => enabled,
    fetch: async () => { calls++; return Response.json(PROFILE); },
  });
  const lookup = identity.identify();
  enabled = false;
  identity.discard();
  release([{ id: "current:synthetic", ownerId: "current", headers: { authorization: "Bearer synthetic-late-token" } }]);
  assert.equal(await lookup, null);
  assert.equal(calls, 0);
});

test("the profile body reduces to the email and the pool's own subject hash", () => {
  assert.deepEqual(claudeIdentityFromBody(PROFILE), {
    email: "Person@example.test",
    subjectHash: subjectHash("upstream-account-uuid"),
  });
  // Only those two fields leave the parser; the body itself is never returned.
  assert.deepEqual(Object.keys(claudeIdentityFromBody(PROFILE) ?? {}).sort(), ["email", "subjectHash"]);
  assert.equal(claudeIdentityFromBody({ account: { email: "no-uuid@example.test" } }), null);
  assert.equal(claudeIdentityFromBody({ account: { uuid: "u" } }), null);
  assert.equal(claudeIdentityFromBody({ organization: {} }), null);
  assert.equal(claudeIdentityFromBody(null), null);
});

test("the lookup asks once per token, keeps a success for the token's life, and asks again for a new token", async () => {
  let token = "token-one";
  let calls = 0;
  const urls: string[] = [];
  let now = 1_000_000;
  const identity = new ClaudeCurrentIdentity(currentLogin(() => token), {
    upstream: () => "api.example.test",
    now: () => now,
    fetch: async (url) => {
      calls += 1;
      urls.push(url);
      return new Response(JSON.stringify(PROFILE), { status: 200 });
    },
  });

  const expected = { email: "Person@example.test", subjectHash: subjectHash("upstream-account-uuid") };
  assert.deepEqual(await identity.identify(), expected);
  assert.deepEqual(await identity.identify(), expected);
  assert.equal(calls, 1, "a second poll inside the cache window does not call upstream");
  assert.equal(urls[0], "https://api.example.test/api/oauth/profile");

  now += 9 * 60_000;
  assert.deepEqual(await identity.identify(), expected);
  assert.equal(calls, 1, "still inside ten minutes");

  token = "token-two";
  assert.deepEqual(await identity.identify(), expected);
  assert.equal(calls, 2, "a new login token asks again immediately");

  // An identity does not change with time: a success outlives the ten-minute failure window.
  now += 10 * 60_000;
  assert.deepEqual(await identity.identify(), expected);
  assert.equal(calls, 2, "a success is still kept after ten minutes");

  now += 24 * 60 * 60_000;
  assert.deepEqual(await identity.identify(), expected);
  assert.equal(calls, 3, "the same token re-asks once a day has passed");
});

test("a failed profile returns null, is cached, and is retried after the cache time", async () => {
  let fail = true;
  let calls = 0;
  let now = 5_000_000;
  const warnings: string[] = [];
  const identity = new ClaudeCurrentIdentity(currentLogin(() => "secret-token"), {
    upstream: () => "api.example.test",
    now: () => now,
    warn: (message) => warnings.push(message),
    fetch: async () => {
      calls += 1;
      if (fail) throw new Error("connection refused");
      return new Response(JSON.stringify(PROFILE), { status: 200 });
    },
  });

  assert.equal(await identity.identify(), null);
  assert.equal(await identity.identify(), null);
  assert.equal(calls, 1, "a failure is not retried on every poll");
  assert.ok(!warnings.join("\n").includes("secret-token"), "the token never reaches a log line");

  fail = false;
  now += 10 * 60_000;
  assert.deepEqual(await identity.identify(), { email: "Person@example.test", subjectHash: subjectHash("upstream-account-uuid") });
  assert.equal(calls, 2);
});

test("a non-200 answer and a body without an account are both unknown, never a wrong identity", async () => {
  let calls = 0;
  const identity = new ClaudeCurrentIdentity(currentLogin(() => "token"), {
    upstream: () => "api.example.test",
    fetch: async () => {
      calls += 1;
      return new Response(JSON.stringify({ account: { uuid: "u", email: "person@example.test" } }), { status: 401 });
    },
  });
  assert.equal(await identity.identify(), null);
  assert.equal(calls, 1);

  // A 200 whose body carries no account is null too, and does not keep the last good answer alive.
  const empty = new ClaudeCurrentIdentity(currentLogin(() => "token"), {
    upstream: () => "api.example.test",
    fetch: async () => new Response(JSON.stringify({ organization: {} }), { status: 200 }),
  });
  assert.equal(await empty.identify(), null);
});

test("no current login means no request at all", async () => {
  let called = false;
  const identity = new ClaudeCurrentIdentity({
    // Only a stored account: the current login is absent.
    credentials: async () => [{ id: "stored", ownerId: "stored-id", headers: { authorization: "Bearer stored" } }],
  }, {
    upstream: () => "api.example.test",
    fetch: async () => {
      called = true;
      return new Response(JSON.stringify(PROFILE), { status: 200 });
    },
  });
  assert.equal(await identity.identify(), null);
  assert.equal(called, false);

  const broken = new ClaudeCurrentIdentity({ credentials: async () => { throw new Error("unreadable"); } }, { upstream: () => "api.example.test" });
  assert.equal(await broken.identify(), null);
});

test("a request's own login and the pool's copy each stay cached, so alternating between them asks once each", async () => {
  let calls = 0;
  const identity = new ClaudeCurrentIdentity(currentLogin(() => "pool-token"), {
    upstream: () => "api.example.test",
    now: () => 1_000_000,
    fetch: async () => {
      calls += 1;
      return new Response(JSON.stringify(PROFILE), { status: 200 });
    },
  });
  for (let turn = 0; turn < 4; turn += 1) {
    assert.equal((await identity.identifyWith({ authorization: "Bearer client-token" }))?.email, "Person@example.test");
    assert.equal((await identity.identify())?.email, "Person@example.test");
  }
  assert.equal(calls, 2, "one lookup per token, not one per turn");
});
