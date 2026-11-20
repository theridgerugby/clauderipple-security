import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { ConfigStore, normalizeConfig } from "../src/config.ts";
import { writeJsonAtomic, writeSecretJsonAtomic } from "../src/locked-file.ts";
import { readPrivateFile } from "../src/private-file.ts";
import { configurePersonalEgressPolicy } from "../src/personal-policy.ts";
import { egressFetch } from "../src/egress.ts";
import { Logger } from "../src/log.ts";
import { RequestLog } from "../src/requestlog.ts";
import { startAdmin, fetch as adminFetch, unauthenticatedFetch } from "./admin-client.ts";
import type { AdminDeps } from "../src/admin.ts";

const ORIGIN = "https://school.example.test";
const SECRET = "SYNTHETIC-KEY-ADMIN-PERSONAL-NOT-REAL";

async function fixture(t: TestContext, controls: Pick<AdminDeps, "runCli" | "picker" | "startCliDetached" | "claudeCodeCredentialReaders" | "claudeIdentity" | "chatgpt" | "google" | "power" | "remote" | "agentsChanged"> = {}, beforeStart?: (home: string) => void) {
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
  beforeStart?.(home);
  server = await startAdmin({
    config: () => store.get(), configFile: file, agentDir: path.join(home, "agents"),
    log: new Logger(null, 1_000_000, 1, false, true),
    requests: new RequestLog(path.join(home, "requests.jsonl"), undefined, undefined, true),
    stats: () => ({ inFlight: 0, messagesInFlight: 0, started: 0, completed: 0, failed: 0 }),
    health: () => 0, version: "synthetic-personal-policy",
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    ...controls,
  });
  const base = `https://127.0.0.1:${server.tlsPort}`;
  const send = (resource: string, body: unknown, method = "POST") => adminFetch(base + resource, {
    method, headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  return { base, file, store, send, settings: process.env.CLAUDE_SETTINGS_PATH! };
}

test("personal admin leaves legacy update state untouched and reports the coordinator disabled", async t => {
  let journal = "", original = Buffer.alloc(0);
  const f = await fixture(t, {}, home => {
    journal = path.join(home, "auto-update.json");
    // The old constructor reconciles a completed version immediately, even without start().
    writeJsonAtomic(journal, { failures: {}, pending: { from: "0.0.1", to: "synthetic-personal-policy", at: 1 } });
    original = fs.readFileSync(journal);
  });
  const response = await adminFetch(f.base + "/api/status");
  assert.equal(response.status, 200);
  const status = await response.json() as { autoUpdate: { enabled: boolean; running: boolean } };
  assert.deepEqual(status.autoUpdate, { enabled: false, running: false });
  assert.deepEqual(fs.readFileSync(journal), original);
});

test("personal admin refuses hidden account, updater and integration capabilities before side effects", async t => {
  const calls: string[] = [];
  const forbidden = (label: string): never => { calls.push(label); throw new Error(`forbidden fixture capability: ${label}`); };
  const f = await fixture(t, {
    runCli: async () => forbidden("cli"), startCliDetached: () => forbidden("spawn"),
    claudeCodeCredentialReaders: { keychain: () => forbidden("keychain"), credentialsFile: () => forbidden("credentialsFile") },
    claudeIdentity: async () => forbidden("claudeIdentity"),
    chatgpt: () => forbidden("chatgptAccounts"), google: () => forbidden("googleAccounts"),
    agentsChanged: () => forbidden("agents"),
    power: { status: () => forbidden("power.status"), pin: () => forbidden("power.pin"), poke: async () => forbidden("power.poke") },
    remote: { status: () => forbidden("remote.status"), reload: () => forbidden("remote.reload") },
  });
  const home = path.dirname(f.file);
  const beforeNames = fs.readdirSync(home).sort();
  const beforeConfig = fs.readFileSync(f.file);
  const cases: [string, string][] = [
    ["/api/update", "GET"], ["/api/update", "POST"], ["/api/power", "GET"], ["/api/power", "PUT"], ["/api/power/setup", "POST"],
    ["/api/remote", "GET"], ["/api/remote/reload", "POST"], ["/api/phone-inbox", "GET"], ["/api/phone/settings", "POST"],
    ["/api/mod-options", "GET"], ["/api/mod-settings", "PUT"], ["/api/mod/approval", "POST"],
    ["/api/codex", "GET"], ["/api/codex", "POST"], ["/api/settings-jobs", "GET"], ["/api/settings-jobs/result", "POST"],
    ["/api/compact-pick", "POST"], ["/api/agent-title", "POST"], ["/api/status-mod", "POST"],
    ...["claude", "chatgpt", "google"].flatMap(name => [
      [`/api/${name}-accounts`, "GET"], [`/api/${name}-accounts`, "PUT"],
      [`/api/${name}-accounts/synthetic`, "PATCH"], [`/api/${name}-accounts/synthetic`, "DELETE"],
      [`/api/${name}-login`, "GET"], [`/api/${name}-login`, "POST"], [`/api/${name}-logout`, "POST"],
      [`/api/${name}-oauth`, "GET"], [`/api/${name}-oauth/code`, "POST"],
    ] as [string, string][]),
  ];
  for (const [resource, method] of cases) {
    const response = await adminFetch(f.base + resource, {
      method,
      ...(method === "GET" ? {} : { headers: { "content-type": "application/json" }, body: "{deliberately-invalid-json" }),
    });
    assert.equal(response.status, 403, `${method} ${resource}`);
    assert.match(await response.text(), /disabled in the personal Desktop profile/);
  }
  assert.deepEqual(calls, []);
  assert.deepEqual(fs.readdirSync(home).sort(), beforeNames, "no account, worker, updater or remote state created");
  assert.deepEqual(fs.readFileSync(f.file), beforeConfig);
  assert.equal(fs.existsSync(f.settings), false);

  // Necessary key management and native-picker catalogue surfaces remain authenticated and live.
  for (const resource of ["/api/security-policy", "/api/config", "/api/claude-models", "/api/presets"]) {
    const response = await adminFetch(f.base + resource);
    assert.equal(response.status, 200, resource);
    await response.text();
  }
  assert.deepEqual(calls, []);
});

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

test("picker activation errors are bounded and redacted without hiding a refusal", async t => {
  const calls: string[][] = [];
  const f = await fixture(t, { runCli: async args => {
    calls.push(args);
    return { ok: false, output: "Desktop activation refused: apiKey=PRIVATE-TEST-KEY " + "x".repeat(9000) };
  } });
  const invalid = await f.send("/api/picker", { enabled: "yes" });
  assert.equal(invalid.status, 400);
  assert.deepEqual(calls, []);
  const response = await f.send("/api/picker", { enabled: true });
  assert.equal(response.status, 500);
  const result = await response.json() as { ok: boolean; error: string; output: string };
  assert.equal(result.ok, false);
  assert.equal(result.error, result.output);
  assert.ok(result.output.startsWith("Desktop activation refused:"));
  assert.ok(result.output.length <= 8192);
  assert.ok(!result.output.includes("PRIVATE-TEST-KEY"));
  assert.deepEqual(calls, [["picker", "on"]]);
});

test("picker status exposes bounded destination diagnostics and unapproved native origin", async t => {
  const f = await fixture(t, { picker: () => ({ enabled: true, hosts: ["claude.ai"], last: null,
    blockedOrigins: ["https://example.test"] }) });
  const status = await (await adminFetch(f.base + "/api/status")).json() as {
    picker: { blockedOrigins: string[] }; readiness: { ready: boolean; problems: string[] };
  };
  assert.deepEqual(status.picker.blockedOrigins, ["https://example.test"]);
  assert.equal(status.readiness.ready, false);
  assert.ok(status.readiness.problems.includes("picker-origin"));
});

test("personal provider and checklist saves leave existing Claude settings byte-for-byte unchanged", async t => {
  const f = await fixture(t);
  const original = '{\n  "env": {"EXISTING_SETTING": "keep", "ANTHROPIC_MODEL": "sonnet"},\n  "theme": "dark"\n}\n';
  fs.writeFileSync(f.settings, original);
  const snapshot = await (await adminFetch(f.base + "/api/config")).json() as Record<string, any>;
  snapshot.cli.extraModels = [{ model: "synthetic-model", name: "Synthetic extra" }];
  const response = await f.send("/api/config", snapshot, "PUT");
  assert.equal(response.status, 200, await response.text());
  assert.equal(fs.readFileSync(f.settings, "utf8"), original);
});

test("personal config saving cannot bypass explicit Desktop activation or recovery", async t => {
  const f = await fixture(t);
  const snapshot = await (await adminFetch(f.base + "/api/config")).json() as Record<string, any>;
  const before = fs.readFileSync(f.file);
  const response = await f.send("/api/config", { ...snapshot, picker: { enabled: true } }, "PUT");
  assert.equal(response.status, 403, await response.text());
  assert.deepEqual(fs.readFileSync(f.file), before);
  assert.equal(fs.existsSync(f.settings), false);
});

test("active personal Desktop rejects later native-slot and safety-service overrides", async t => {
  const f = await fixture(t);
  const initial = JSON.parse(readPrivateFile(f.file).toString("utf8"));
  writeSecretJsonAtomic(f.file, { ...initial, picker: { enabled: true } });
  const snapshot = await (await adminFetch(f.base + "/api/config")).json() as Record<string, any>;
  const before = fs.readFileSync(f.file);
  for (const change of [
    { cli: { ...snapshot.cli, models: { main: "synthetic-model" } } },
    { routes: { opus: { provider: "school", model: "synthetic-model" } } },
    { webSearch: { provider: "school", model: "synthetic-model" } },
    { autoModeClassifier: { provider: "school", model: "synthetic-model" } },
  ]) {
    const response = await f.send("/api/config", { ...snapshot, ...change }, "PUT");
    const message = await response.text();
    assert.equal(response.status, 400, message);
    assert.match(message, /personal Desktop mode/);
    assert.deepEqual(fs.readFileSync(f.file), before);
    assert.equal(fs.existsSync(f.settings), false);
  }
  const deactivate = await f.send("/api/config", { ...snapshot, picker: { enabled: false } }, "PUT");
  assert.equal(deactivate.status, 403, await deactivate.text());
  assert.deepEqual(fs.readFileSync(f.file), before);
});
