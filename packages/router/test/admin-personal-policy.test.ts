import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ConfigStore, normalizeConfig } from "../src/config.ts";
import { writeSecretJsonAtomic } from "../src/locked-file.ts";
import { readPrivateFile } from "../src/private-file.ts";
import { configurePersonalEgressPolicy } from "../src/personal-policy.ts";
import { egressFetch } from "../src/egress.ts";
import { Logger } from "../src/log.ts";
import { RequestLog } from "../src/requestlog.ts";
import { startAdmin, fetch as adminFetch, unauthenticatedFetch } from "./admin-client.ts";

const ORIGIN = "https://school.example.test";
const SECRET = "SYNTHETIC-KEY-ADMIN-PERSONAL-NOT-REAL";

async function fixture(t: TestContext) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-personal-admin-"));
  const previous = { home: process.env.CLAUDERIPPLE_HOME, settings: process.env.CLAUDE_SETTINGS_PATH };
  process.env.CLAUDERIPPLE_HOME = home;
  process.env.CLAUDE_SETTINGS_PATH = path.join(home, "synthetic-claude-settings.json");
  const file = path.join(home, "config.json");
  writeSecretJsonAtomic(file, normalizeConfig({ admin: { port: 0 }, providers: {
    school: { type: "openai-compatible", url: ORIGIN + "/v1", headers: { authorization: `Bearer ${SECRET}` }, models: [{ id: "synthetic-model" }] },
  } }));
  const store = new ConfigStore(file);
  configurePersonalEgressPolicy(() => store.get().security);
  let server: Awaited<ReturnType<typeof startAdmin>> | undefined;
  t.after(() => {
    configurePersonalEgressPolicy(undefined);
    server?.close();
    if (previous.home === undefined) delete process.env.CLAUDERIPPLE_HOME; else process.env.CLAUDERIPPLE_HOME = previous.home;
    if (previous.settings === undefined) delete process.env.CLAUDE_SETTINGS_PATH; else process.env.CLAUDE_SETTINGS_PATH = previous.settings;
    fs.rmSync(home, { recursive: true, force: true });
  });
  server = await startAdmin({
    config: () => store.get(), configFile: file, agentDir: path.join(home, "agents"),
    log: new Logger(null, 1_000_000, 1, false, true),
    requests: new RequestLog(path.join(home, "requests.jsonl"), undefined, undefined, true),
    stats: () => ({ inFlight: 0, messagesInFlight: 0, started: 0, completed: 0, failed: 0 }),
    health: () => 0, version: "synthetic-personal-policy",
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
  });
  const base = `https://127.0.0.1:${server.tlsPort}`;
  const send = (resource: string, body: unknown, method = "POST") => adminFetch(base + resource, {
    method, headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { base, file, store, send };
}

test("native admin approval is explicit, exact, credential-preserving and immediately revocable", async t => {
  const f = await fixture(t);
  const unauthorized = await unauthenticatedFetch(f.base + "/api/security-policy");
  assert.equal(unauthorized.status, 401);
  await unauthorized.text();
  const initial = await (await adminFetch(f.base + "/api/security-policy")).json() as Record<string, unknown>;
  assert.deepEqual(initial.approvedOrigins, []);
  assert.ok((initial.candidates as string[]).includes(ORIGIN));
  assert.equal(initial.persistentDiagnostics, false);
  assert.equal(initial.crossProviderFallback, false);
  const before = fs.readFileSync(f.file);
  for (const request of [
    { action: "approve", origin: ORIGIN },
    { action: "approve", origin: ORIGIN, acknowledgeDataSharing: "true" },
    { action: "approve", origin: `${ORIGIN}/v1?key=${SECRET}`, acknowledgeDataSharing: true },
    { action: "approve", origin: `https://${SECRET}@school.example.test`, acknowledgeDataSharing: true },
    { action: "approve", origin: "http://school.example.test", acknowledgeDataSharing: true },
  ]) {
    const response = await f.send("/api/security-policy", request);
    assert.equal(response.status, 400);
    assert.ok(!(await response.text()).includes(SECRET));
    assert.deepEqual(fs.readFileSync(f.file), before);
  }

  let networkCalls = 0;
  const transport = async (_url: string, init: RequestInit) => {
    networkCalls++;
    assert.equal(init.redirect, "manual");
    assert.equal(new Headers(init.headers).get("authorization"), `Bearer ${SECRET}`);
    return new Response("synthetic answer");
  };
  const sendSynthetic = () => egressFetch(ORIGIN + "/v1/chat/completions", {
    method: "POST", headers: { authorization: `Bearer ${SECRET}` }, body: "synthetic unpublished-text sentinel",
  }, transport);
  await assert.rejects(sendSynthetic, /not approved|destination|personal/i);
  assert.equal(networkCalls, 0);

  const approved = await f.send("/api/security-policy", { action: "approve", origin: ORIGIN, acknowledgeDataSharing: true });
  assert.equal(approved.status, 200, await approved.text());
  assert.deepEqual(f.store.get().security?.approvedOrigins, [ORIGIN]);
  assert.equal(await (await sendSynthetic()).text(), "synthetic answer");
  assert.equal(networkCalls, 1);
  assert.equal(JSON.parse(readPrivateFile(f.file).toString("utf8")).providers.school.headers.authorization, `Bearer ${SECRET}`);
  if (process.platform === "win32") assert.ok(!fs.readFileSync(f.file).includes(SECRET), "DPAPI configuration contains no plaintext provider key");

  const revoked = await f.send("/api/security-policy", { action: "revoke", origin: ORIGIN });
  assert.equal(revoked.status, 200, await revoked.text());
  assert.deepEqual(f.store.get().security?.approvedOrigins, []);
  await assert.rejects(sendSynthetic, /not approved|destination|personal/i);
  assert.equal(networkCalls, 1, "revocation prevents the next transport call");
});

test("ordinary config saving cannot silently approve an external destination", async t => {
  const f = await fixture(t);
  const response = await adminFetch(f.base + "/api/config");
  const snapshot = await response.json() as Record<string, unknown>;
  assert.ok(!JSON.stringify(snapshot).includes(SECRET));
  const before = fs.readFileSync(f.file);
  const refused = await f.send("/api/config", { ...snapshot, security: { mode: "personal", approvedOrigins: [ORIGIN] } }, "PUT");
  assert.equal(refused.status, 403, await refused.text());
  assert.deepEqual(fs.readFileSync(f.file), before);
  assert.deepEqual(f.store.get().security?.approvedOrigins, []);
});
