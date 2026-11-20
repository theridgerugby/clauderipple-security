import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeConfig, validate, type Config, type Provider } from "../src/config.ts";
import type { AdminDeps } from "../src/admin.ts";
import { REDACTED_SECRET } from "../src/admin-config-secrets.ts";
import { configurePersonalEgressPolicy } from "../src/personal-policy.ts";
import { writeSecretJsonAtomic } from "../src/locked-file.ts";
import { readPrivateFile } from "../src/private-file.ts";
import { Logger } from "../src/log.ts";
import { RequestLog } from "../src/requestlog.ts";
import { startAdmin, fetch as adminFetch } from "./admin-client.ts";

const SCHOOL = "https://school.example.test";
const VENDOR = "https://opencode.ai";
const SECRET = "synthetic-school-credential-never-a-real-key";
type Transport = NonNullable<AdminDeps["measureFetch"]>;
type Job = { state: string; done: number; results: unknown[]; error?: string };

function config(provider?: Provider, origins = [SCHOOL, VENDOR]): Config {
  return normalizeConfig({
    admin: { port: 0 },
    security: { mode: "personal", approvedOrigins: origins },
    providers: provider ? { school: provider } : {},
  });
}

async function admin(t: TestContext, cfg: Config, transport: Transport) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-credential-origin-"));
  const previousHome = process.env.CLAUDERIPPLE_HOME;
  const previousSettings = process.env.CLAUDE_SETTINGS_PATH;
  process.env.CLAUDERIPPLE_HOME = home;
  process.env.CLAUDE_SETTINGS_PATH = path.join(home, "fixture-settings.json");
  configurePersonalEgressPolicy(() => cfg.security);
  let server: Awaited<ReturnType<typeof startAdmin>> | undefined;
  t.after(() => {
    server?.close();
    configurePersonalEgressPolicy(undefined);
    if (previousHome === undefined) delete process.env.CLAUDERIPPLE_HOME;
    else process.env.CLAUDERIPPLE_HOME = previousHome;
    if (previousSettings === undefined) delete process.env.CLAUDE_SETTINGS_PATH;
    else process.env.CLAUDE_SETTINGS_PATH = previousSettings;
    fs.rmSync(home, { recursive: true, force: true });
  });
  const configFile = path.join(home, "config.json");
  writeSecretJsonAtomic(configFile, cfg);
  server = await startAdmin({
    config: () => cfg, configFile,
    log: new Logger(null, 1_000_000, 1, false),
    stats: () => ({ inFlight: 0, messagesInFlight: 0, started: 0, completed: 0, failed: 0 }),
    health: () => 0, version: "0.0.0-credential-origin-test",
    requests: new RequestLog(path.join(home, "requests.jsonl")),
    claudeCodeCredentialReaders: { keychain: () => null, credentialsFile: () => null },
    probeFetch: transport, probeModelFetch: transport, measureFetch: transport,
    modelCatalog: async () => undefined,
  });
  const origin = `http://127.0.0.1:${server.port}`;
  const post = (resource: string, body: unknown) => adminFetch(origin + resource, {
    method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body),
  });
  const measure = async (models: string[]): Promise<Job> => {
    const response = await post("/api/providers/measure", { provider: "school", models });
    assert.equal(response.status, 202);
    const { jobId } = await response.json() as { jobId: string };
    // Synthetic transports finish immediately; this also bounds a broken detached-job fixture.
    for (let n = 0; n < 80; n++) {
      const job = await (await adminFetch(`${origin}/api/providers/measure/${jobId}`)).json() as Job;
      if (job.state !== "running") return job;
      await new Promise<void>(resolve => setTimeout(resolve, 25));
    }
    throw new Error("synthetic measurement did not settle");
  };
  return { configFile, post, measure };
}

test("personal measurement refuses preset-derived origins before sending the provider key, even when both origins are approved", async t => {
  const models = ["minimax-m3", "minimax-m2.7", "qwen3.8-max", "qwen3.8-flash", "queued-model"];
  const cfg = config({
    type: "openai-compatible", url: `${SCHOOL}/v1`, preset: "opencode-go",
    headers: { authorization: `Bearer ${SECRET}` }, models: models.map(id => ({ id })),
  });
  // A custom compatible URL is valid. A preset must not silently broaden its credential scope.
  assert.deepEqual(validate(cfg), []);
  let calls = 0;
  const server = await admin(t, cfg, async () => { calls++; return Response.json({}); });
  const before = fs.readFileSync(server.configFile);
  const job = await server.measure(models);
  assert.equal(job.state, "failed");
  assert.match(job.error ?? "", /destination refused/i);
  assert.doesNotMatch(JSON.stringify(job), /synthetic-school-credential|opencode\.ai/);
  assert.equal(calls, 0, "no preset endpoint or queued model receives the credential");
  assert.equal(job.done, 0);
  assert.deepEqual(fs.readFileSync(server.configFile), before);
});

test("personal measurement stops when a fallback wire changes credential origin after safe same-origin attempts", async t => {
  const cfg = config({
    type: "openai-compatible", wire: "responses", url: `${SCHOOL}/v1`, preset: "opencode-go",
    caps: { reasoning: "effort", effortLevels: [] },
    headers: { authorization: `Bearer ${SECRET}` }, models: [{ id: "unknown-school-model" }],
  });
  const attempts: { url: string; signal: AbortSignal | null | undefined }[] = [];
  const server = await admin(t, cfg, async (url, init) => {
    attempts.push({ url, signal: init.signal });
    assert.equal(new Headers(init.headers).get("authorization"), `Bearer ${SECRET}`);
    return new Response("wrong wire", { status: 404 });
  });
  const before = fs.readFileSync(server.configFile);
  const job = await server.measure(["unknown-school-model"]);
  assert.equal(job.state, "failed");
  assert.match(job.error ?? "", /destination refused/i);
  assert.deepEqual(attempts.map(attempt => attempt.url), [`${SCHOOL}/v1/responses`, `${SCHOOL}/v1/chat/completions`]);
  assert.ok(attempts.every(attempt => attempt.signal?.aborted), "policy failure aborts the whole measurement transport scope");
  assert.deepEqual(fs.readFileSync(server.configFile), before);
});

for (const catalogue of [`${VENDOR}/zen/go/v1/models`, `${SCHOOL}:8443/v1/models`]) {
  test(`personal draft probe refuses another approved catalogue origin (${new URL(catalogue).host})`, async t => {
    let calls = 0;
    const cfg = config(undefined, [SCHOOL, new URL(catalogue).origin]);
    const server = await admin(t, cfg, async () => { calls++; return Response.json({ data: [] }); });
    const response = await server.post("/api/providers/probe", {
      type: "openai-compatible", url: `${SCHOOL}/v1`, modelsUrl: catalogue,
      headers: { authorization: `Bearer ${SECRET}` }, preset: "opencode-go",
    });
    assert.equal(response.status, 403);
    const body = await response.text();
    assert.match(body, /destination refused/i);
    assert.doesNotMatch(body, /synthetic-school-credential/);
    assert.equal(calls, 0, "the catalogue and subsequent inference probe are both fenced");
  });
}

test("personal saved-key probe cannot use a preset catalogue exception to change credential origin", async t => {
  const provider: Provider = {
    type: "openai-compatible", url: `${SCHOOL}/v1`, preset: "opencode-go",
    headers: { authorization: `Bearer ${SECRET}` }, models: [{ id: "school-model" }],
  };
  let calls = 0;
  const server = await admin(t, config(provider), async () => { calls++; return Response.json({ data: [] }); });
  const response = await server.post("/api/providers/probe", {
    name: "school", type: "openai-compatible", url: provider.url, preset: provider.preset,
    modelsUrl: `${VENDOR}/zen/go/v1/models`, headers: { authorization: `Bearer ${REDACTED_SECRET}` },
  });
  assert.equal(response.status, 403);
  assert.match(await response.text(), /destination refused/i);
  assert.equal(calls, 0);
});

test("a custom school-compatible API can probe and measure its own approved HTTPS origin", async t => {
  const cfg = config({
    type: "openai-compatible", wire: "responses", url: `${SCHOOL}/gateway/v1`,
    caps: { reasoning: "effort", effortLevels: [] },
    headers: { authorization: `Bearer ${SECRET}` }, models: [{ id: "school-model" }],
  }, [SCHOOL]);
  assert.deepEqual(validate(cfg), []);
  const attempts: string[] = [];
  const server = await admin(t, cfg, async (url, init) => {
    attempts.push(url);
    assert.equal(new URL(url).origin, SCHOOL);
    assert.equal(new Headers(init.headers).get("authorization"), `Bearer ${SECRET}`);
    assert.equal(init.redirect, "manual");
    return Response.json(url.endsWith("/models") ? { data: [{ id: "school-model" }] } : {});
  });
  const response = await server.post("/api/providers/probe", {
    type: "openai-compatible", wire: "responses", url: `${SCHOOL}/gateway/v1`,
    modelsUrl: `${SCHOOL}/gateway/v1/models`, headers: { authorization: `Bearer ${SECRET}` },
    probeModel: "school-model",
  });
  assert.equal(response.status, 200);
  assert.equal((await response.json() as { ok: boolean }).ok, true);
  const job = await server.measure(["school-model"]);
  assert.equal(job.state, "done");
  assert.deepEqual(attempts, [`${SCHOOL}/gateway/v1/models`, `${SCHOOL}/gateway/v1/responses`, `${SCHOOL}/gateway/v1/responses`]);
  const saved = JSON.parse(readPrivateFile(server.configFile)!.toString("utf8")) as Config;
  assert.equal(saved.providers.school!.models?.[0]?.wire, "responses");
});

test("a preset may change wire, path and auth header within its original approved credential origin", async t => {
  const cfg = config({
    type: "openai-compatible", wire: "responses", url: `${VENDOR}/zen/go/v1`, preset: "opencode-go",
    caps: { reasoning: "effort", effortLevels: [] },
    headers: { authorization: `Bearer ${SECRET}` }, models: [{ id: "minimax-m3" }],
  }, [VENDOR]);
  assert.deepEqual(validate(cfg), []);
  let calls = 0;
  const server = await admin(t, cfg, async (url, init) => {
    calls++;
    assert.equal(url, `${VENDOR}/zen/go/v1/messages`);
    assert.equal(new Headers(init.headers).get("x-api-key"), SECRET);
    assert.equal(new Headers(init.headers).has("authorization"), false);
    return Response.json({});
  });
  const job = await server.measure(["minimax-m3"]);
  assert.equal(job.state, "done");
  assert.equal(calls, 1);
});

test("same-origin probe attempts still recheck a live origin revocation before inference", async t => {
  const cfg = config(undefined, [SCHOOL]);
  let calls = 0;
  const server = await admin(t, cfg, async (_url, _init) => {
    calls++;
    cfg.security!.approvedOrigins = [];
    return Response.json({ data: [{ id: "school-model" }] });
  });
  const response = await server.post("/api/providers/probe", {
    type: "openai-compatible", url: `${SCHOOL}/v1`, modelsUrl: `${SCHOOL}/v1/models`,
    headers: { authorization: `Bearer ${SECRET}` },
  });
  assert.equal(response.status, 403);
  assert.match(await response.text(), /destination not approved/i);
  assert.equal(calls, 1, "revocation prevents the next same-origin request");
});
