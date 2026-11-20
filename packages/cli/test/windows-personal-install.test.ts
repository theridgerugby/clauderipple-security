// Explicit hosted-Windows acceptance, not part of an ordinary developer test run.
// This registers a uniquely named disposable task and launches the actual router. Its config
// approves no outbound origins, has only a synthetic key, disables generated workers, and points
// Claude settings at a disposable file. No OS trust store, real account, installed Claude app or
// default ClaudeRipple task is changed. A refused cleanup is a failure, never a forced PID kill.
import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { setTimeout as delay } from "node:timers/promises";
import { adminFetch } from "../src/admin-client.ts";
import { recordAdminRuntime } from "../src/admin-runtime.ts";
import { generateCerts } from "../src/certs.ts";
import { captureRouterCodeIdentity, sameRouterCodeIdentity, statusMatchesRuntime, verifyAndApplyInstall, type InstallRuntimeTarget } from "../src/install-runtime.ts";
import { probe } from "../src/probe.ts";
import { launcherProgram, writePaths } from "../src/registration.ts";
import { runtime } from "../src/runtime.ts";
import * as sourceTasks from "../src/schtasks.ts";
import * as sourceSupervisor from "../src/supervisor.ts";
import { normalizeConfig, validate } from "../../router/src/config.ts";
import { readInstallationId } from "../../router/src/installation-id.ts";
import { writePrivateFileAtomic, writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { readPrivateFileStrict } from "../../router/src/private-file.ts";
import { SECRET_FILE_PREFIX } from "../../router/src/secret-storage.ts";
import { VERSION } from "../../router/src/version.ts";

const enabled = process.platform === "win32" && process.env.GITHUB_ACTIONS === "true" &&
  process.env.CLAUDERIPPLE_WINDOWS_SERVICE_ACCEPTANCE === "1";

async function reservePorts(count: number): Promise<{ ports: number[]; release(): Promise<void> }> {
  const servers = Array.from({ length: count }, () => net.createServer());
  try {
    for (const server of servers) { server.listen(0, "127.0.0.1"); await once(server, "listening"); }
    return {
      ports: servers.map(server => (server.address() as net.AddressInfo).port),
      release: () => Promise.all(servers.map(server => new Promise<void>(resolve => server.close(() => resolve())))).then(() => {}),
    };
  } catch (error) {
    for (const server of servers) server.close();
    throw error;
  }
}

test("hosted Windows installs, verifies, restarts and removes an isolated personal router task", {
  skip: !enabled, timeout: 9 * 60_000,
}, async t => {
  // Select the task renderer and lifecycle together with the runtime. A source renderer would
  // otherwise launch the compiled router with a source-only watchdog helper, masking omissions
  // in the filtered distribution. Keep these imports inside the enabled fixture.
  const compiledAcceptance = process.env.CLAUDERIPPLE_ACCEPTANCE_COMPILED === "1";
  const rt = compiledAcceptance
    ? (await import(new URL("../../../dist/cli/src/runtime.js", import.meta.url).href)).runtime() as ReturnType<typeof runtime>
    : runtime();
  const tasks = compiledAcceptance
    ? await import(new URL("../../../dist/cli/src/schtasks.js", import.meta.url).href) as typeof sourceTasks
    : sourceTasks;
  const { restartAgent, stopAgent } = compiledAcceptance
    ? await import(new URL("../../../dist/cli/src/supervisor.js", import.meta.url).href) as typeof sourceSupervisor
    : sourceSupervisor;
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-native-personal-"));
  const home = path.join(root, "owner's 学生 data");
  const otherHome = path.join(root, "other installation");
  const settings = path.join(root, "disposable client", "settings.json");
  const task = `ClaudeRippleAcceptance-${crypto.randomUUID()}`;
  const oldEnv = new Map<string, string | undefined>();
  const setEnv = (key: string, value: string) => { oldEnv.set(key, process.env[key]); process.env[key] = value; };
  setEnv("CLAUDERIPPLE_TASK_NAME", task);
  setEnv("CLAUDERIPPLE_HOME", home);
  setEnv("CLAUDE_SETTINGS_PATH", settings);
  let registered = false;
  const reservations = await reservePorts(3);
  let reserved = true;
  t.after(async () => {
    try {
      if (reserved) { await reservations.release(); reserved = false; }
      if (registered) {
        const stopped = stopAgent(home);
        assert.ok(stopped === "stopped" || stopped === "not-loaded", `fixture cleanup could not prove a safe stop: ${stopped}`);
        const removed = tasks.removeAgent(task, { home });
        assert.ok(removed === "removed" || removed === "absent", `fixture cleanup refused task removal: ${removed}`);
        registered = false;
        assert.equal(tasks.readTaskDefinition(task).state, "absent");
      }
      fs.rmSync(root, { recursive: true, force: true });
    } finally {
      for (const [key, value] of oldEnv) {
        if (value === undefined) delete process.env[key]; else process.env[key] = value;
      }
    }
  });

  assert.equal(tasks.readTaskDefinition(task).state, "absent", "a collision never permits overwriting a task");
  const [proxyPort, adminPort, ingressPort] = reservations.ports as [number, number, number];
  const syntheticKey = `SYNTHETIC-NATIVE-SCHOOL-KEY-${crypto.randomUUID()}`;
  const cfg = normalizeConfig({
    listen: { host: "127.0.0.1", port: proxyPort, openaiPort: ingressPort }, admin: { port: adminPort },
    upstream: "api.anthropic.com", security: { mode: "personal", approvedOrigins: [] },
    autoUpdate: false, cli: { extraModels: [], agentFiles: false },
    providers: { school: { type: "openai-compatible", url: "https://school-fixture.invalid/v1",
      headers: { authorization: `Bearer ${syntheticKey}` }, models: [] } },
  });
  assert.deepEqual(validate(cfg), []);
  generateCerts(home);
  for (const name of ["ca.key", "leaf.key"]) assert.ok(fs.readFileSync(path.join(home, name)).toString().startsWith(SECRET_FILE_PREFIX), `${name} must be DPAPI-sealed on disk`);
  writeSecretJsonAtomic(path.join(home, "config.json"), cfg);
  const stored = fs.readFileSync(path.join(home, "config.json"));
  assert.ok(stored.toString().startsWith(SECRET_FILE_PREFIX));
  assert.equal(stored.includes(syntheticKey), false);
  assert.equal(JSON.parse(readPrivateFileStrict(path.join(home, "config.json")).toString()).providers.school.headers.authorization, `Bearer ${syntheticKey}`);
  const settingsBytes = Buffer.from('{"fixture":"client settings remain unchanged"}\n');
  writePrivateFileAtomic(settings, settingsBytes, false);

  // The filtered-build job uses exactly the compiled distribution described in the owner guide.
  // This override is test-only and fixed to this checkout, never an arbitrary executable path.
  if (compiledAcceptance) {
    assert.ok(rt.cli.endsWith(`${path.sep}dist${path.sep}cli${path.sep}src${path.sep}index.js`));
    assert.ok(rt.router.endsWith(`${path.sep}dist${path.sep}router${path.sep}src${path.sep}index.js`));
    assert.ok(fs.existsSync(path.join(path.dirname(rt.cli), "watchdog-port.js")), "compiled watchdog helper must be present");
  }
  writePaths(rt, home);
  recordAdminRuntime(home, rt);
  const expected: InstallRuntimeTarget = { version: VERSION, node: rt.node, router: rt.router,
    codeIdentity: captureRouterCodeIdentity(rt), listen: { host: cfg.listen.host, port: cfg.listen.port }, upstream: cfg.upstream };
  const launchOptions = { program: rt.node, args: [rt.router], home,
    env: { ...rt.env, CLAUDE_SETTINGS_PATH: settings, CLAUDERIPPLE_TASK_NAME: task } };
  const launcher = tasks.installAgent(launchOptions);
  registered = true;
  assert.equal(launcher, tasks.launcherScriptPath(home));
  const launcherText = fs.readFileSync(launcher, "utf8");
  assert.deepEqual(launcherProgram(launcherText), [rt.node, rt.router]);
  const watchdogPath = path.join(path.dirname(rt.cli), `watchdog-port${path.extname(rt.cli)}`);
  const watchdogLine = launcherText.split(/\r?\n/).find(line => line.trimStart().startsWith("$info.Arguments = "));
  assert.equal(watchdogLine?.trim(), `$info.Arguments = '\"${watchdogPath.replace(/'/g, "''")}\"'`,
    "the registered task must execute the selected runtime's exact watchdog helper");
  if (compiledAcceptance) t.diagnostic("registered the filtered build's compiled router, watchdog and lifecycle modules");
  const definition = tasks.existingTaskDefinition(task) as { runLevel: number; logonType: number; arguments: string };
  assert.equal(definition.runLevel, 0, "task requests limited privileges");
  assert.equal(definition.logonType, 3, "task runs as the interactive user");
  assert.ok(definition.arguments.includes(launcher), "the task names this exact quoted Unicode data home");
  assert.equal(tasks.taskOwnership(home).state, "ours");
  assert.equal(tasks.taskOwnership(otherHome).state, "other");
  assert.throws(() => tasks.installAgent({ ...launchOptions, home: otherHome }), /another ClaudeRipple installation/);
  assert.equal(fs.existsSync(tasks.launcherScriptPath(otherHome)), false);
  assert.deepEqual(tasks.existingTaskDefinition(task), definition, "refused takeover preserves the real task definition");
  assert.equal(tasks.installAgent(launchOptions), launcher, "same-definition installation is idempotent");
  await reservations.release(); reserved = false;

  const started = tasks.startAgent(task, { home, waitMs: 30_000 });
  assert.equal(started, "started", "acceptance requires the registered task, with no direct-process fallback");
  const base = `http://127.0.0.1:${adminPort}`;
  const status = async (signal: AbortSignal): Promise<Record<string, unknown>> => {
    const response = await adminFetch(`${base}/api/status`, { signal }, home);
    assert.equal(response.status, 200);
    return await response.json() as Record<string, unknown>;
  };
  const waitStatus = async (): Promise<Record<string, unknown>> => {
    const deadline = performance.now() + 60_000;
    while (performance.now() < deadline) {
      try {
        const value = await status(AbortSignal.timeout(10_000));
        if (statusMatchesRuntime(value, expected, readInstallationId(home))) return value;
      } catch { /* startup has not yet published complete private TLS state */ }
      await delay(250);
    }
    assert.fail("scheduled router did not expose the expected pinned runtime identity within 60 seconds");
  };
  const before = await waitStatus();
  assert.equal(tasks.taskRouterPid(task, { home }), before.pid, "authenticated responder is a descendant of this task's launcher");
  assert.ok(sameRouterCodeIdentity(captureRouterCodeIdentity(rt), expected.codeIdentity));
  t.diagnostic("actual scheduled router passed pinned TLS, DPAPI config, exact runtime source and owned-process checks");

  const options = {
    started, target: expected,
    deps: { status, installationId: () => readInstallationId(home),
      captureIdentity: () => captureRouterCodeIdentity(rt),
      restart: () => restartAgent({ home, waitMs: 30_000 }) },
    probe: () => probe({ host: "127.0.0.1", port: proxyPort, caPem: path.join(home, "ca.pem"), upstream: cfg.upstream, timeoutMs: 2_000 }),
    apply: () => assert.fail("a refused data-path probe must never authorize client settings"),
  };
  await assert.rejects(verifyAndApplyInstall(options), /proxy probe failed/);
  assert.deepEqual(fs.readFileSync(settings), settingsBytes);

  assert.equal(tasks.removeAgent(task, { home: otherHome }), "other-installation");
  assert.equal(tasks.readTaskDefinition(task).state, "found");
  assert.equal(restartAgent({ home, waitMs: 30_000 }), "drained");
  const after = await waitStatus();
  assert.notEqual(after.pid, before.pid, "restart creates a new verified scheduled process");
  assert.equal(after.installId, before.installId);
  assert.equal(tasks.taskRouterPid(task, { home }), after.pid);
  assert.deepEqual(fs.readFileSync(settings), settingsBytes);
  assert.equal(fs.readFileSync(path.join(home, "config.json")).includes(syntheticKey), false);
  for (const name of ["launcher.log", "launcher.err.log"]) {
    assert.equal(fs.existsSync(path.join(home, "logs", name)), false, `${name} must not persist unhandled process output`);
  }
  for (const name of ["router.log", "requests.jsonl", "launcher.log", "launcher.err.log", "launcher-watchdog.log"]) {
    const file = path.join(home, "logs", name);
    if (fs.existsSync(file)) assert.equal(fs.readFileSync(file).includes(syntheticKey), false, `${name} must not contain the synthetic credential`);
  }
  assert.equal(stopAgent(home), "stopped");
  assert.equal(tasks.removeAgent(task, { home }), "removed");
  registered = false;
  assert.equal(tasks.readTaskDefinition(task).state, "absent");
  t.diagnostic("owned scheduled restart and removal passed; no client settings, external credentials or OS certificate trust were changed");
});
