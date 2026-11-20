// Behavioral orchestration test: execute the complete router entry body, with only imports and
// external OS/network/timer boundaries replaced. Integration writers modify synthetic temp files
// when called, so a missing guard changes real fixture bytes. This does not run a real listener,
// certificate trust change, provider request, controller subprocess, or installed Claude Desktop.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import vm from "node:vm";
import { stripTypeScriptTypes } from "node:module";
import ts from "typescript";
import { DEFAULTS, type Config } from "../src/config.ts";
import { personalMode } from "../src/personal-policy.ts";
import type { AdminDeps } from "../src/admin.ts";

const source = fs.readFileSync(new URL("../src/index.ts", import.meta.url), "utf8");
const parsed = ts.createSourceFile("index.ts", source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS);
// Strip import statements by syntax-tree ranges, not a line/string approximation. Everything
// following them, including startup, configuration callbacks, admin callbacks and timer bodies,
// executes unchanged. New unprovided dependencies fail rather than reaching the host runtime.
let body = source;
for (const statement of [...parsed.statements].reverse()) {
  if (!ts.isImportDeclaration(statement)) continue;
  const start = statement.getStart(parsed);
  body = body.slice(0, start) + body.slice(start, statement.end).replace(/[^\r\n]/g, " ") + body.slice(statement.end);
}
const script = new vm.Script(stripTypeScriptTypes(body), {filename: "synthetic-router-entry.js"});

type Timer = { kind: "interval" | "timeout" | "immediate"; ms: number; fn(): unknown; active: boolean; unref(): Timer };
const flush = () => new Promise<void>(resolve => setImmediate(resolve));

function runtimeConfig(personal: boolean): Config {
  return {
    ...structuredClone(DEFAULTS),
    // Legacy knobs deliberately remain present, so the test cannot pass merely because the
    // settings that once triggered generation/power work happen to be absent.
    cli: {extraModels:[{model:"gemini-fixture",name:"Synthetic Gemini"}], agentFiles:true, autoCompactWindow:258400},
    awake: {mode:"on"}, tether: {enabled:true,hotspotSsid:"Synthetic network"},
    providers: {google:{type:"google",auth:"api-key",apiKey:"SYNTHETIC-NOT-A-KEY",models:[{id:"gemini-fixture"}]}},
    autoUpdate:false,
    ...(personal ? {security:{mode:"personal" as const,approvedOrigins:[]}} : {}),
  };
}

async function runtime(t: TestContext, personal = true) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "cr-desktop-runtime-")));
  t.after(() => fs.rmSync(root, {recursive:true,force:true}));
  const home = path.join(root, "ripple");
  const files = {
    settings: path.join(root, "claude", "settings.json"),
    worker: path.join(root, "claude", "agents", "existing-worker.md"),
    userWorker: path.join(root, "claude", "agents", "user-authored.md"),
    codexConfig: path.join(root, "codex", "config.toml"),
    catalog: path.join(root, "codex", "clauderipple-models.json"),
  };
  for (const [name, file] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(file), {recursive:true});
    fs.writeFileSync(file, `synthetic original ${name}\n`, "utf8");
  }
  const snapshot = () => Object.fromEntries(Object.entries(files).map(([name,file]) => [name,fs.readFileSync(file,"utf8")]));
  const before = snapshot(), calls: string[] = [], logs: string[] = [], timers: Timer[] = [];
  const record = (name: string) => { calls.push(name); };
  const write = (name: string, file: string) => { record(name); fs.writeFileSync(file, `${name}: ${calls.length}\n`, "utf8"); };
  const timer = (kind: Timer["kind"], fn: () => unknown, ms = 0): Timer => {
    const handle: Timer = {kind,fn,ms,active:true,unref() { return this; }};
    timers.push(handle); return handle;
  };
  const events = new Map<string, (() => void)[]>();
  const on = (event: string, callback: () => void) => { events.set(event,[...(events.get(event) || []),callback]); };
  let current = runtimeConfig(personal), onConfig!: (config: Config, errors: string[]) => void;
  let admin: AdminDeps | undefined;
  let cacheWatch: {active: boolean; tick(): void} | undefined;
  let backfillGate: Promise<void> | undefined;
  const codexWrite = () => write("codex.write", files.catalog);
  const statistics = () => ({started:0,completed:0,failed:0,inFlight:0,messagesInFlight:0});
  class SyntheticStore {
    constructor(_file: unknown, changed: typeof onConfig) { onConfig = changed; changed(current,[]); }
    get(): Config { return current; }
  }
  class SyntheticAgents {
    constructor(_options: unknown) { record("agents.construct"); }
    regenerate(): void { write("agents.regenerate", files.worker); }
    changed(): boolean { record("agents.changed"); return true; }
  }
  class SyntheticProxy {
    stats = statistics();
    blockedDesktopOrigins: string[] = [];
    lastPickerInjection = null;
    rows = {settled:async () => {}};
    claudeUsage = {snapshot:async () => {record("claude.usage"); return {};}};
    claudeModels = {list:async () => {record("claude.models"); return null;}};
    claudeIdentity = {identify:async () => {record("claude.identity"); return null;}};
    constructor(options: {observedClaudeCodeAuth?: unknown}) { if (options.observedClaudeCodeAuth) record("proxy.receivedObservedAuth"); }
    async listen(): Promise<void> { record("proxy.listen"); }
    async drain(): Promise<void> { record("proxy.drain"); }
    reconcileConfig(): void { record("proxy.reconcile"); }
    resetDesktopSelection(): void { record("proxy.clearSelection"); }
    chatgptRefreshAll(): void { record("chatgpt.quota"); }
    chatgptRefreshCatalog(): void { record("chatgpt.catalogue"); }
    setClaudeLocalAuthorization(): void { record("claude.authorization"); }
  }
  class SyntheticIngress {
    stats = statistics();
    rows = {settled:async () => {}};
    constructor(_options: unknown) { record("ingress.construct"); }
    async listen(): Promise<number> { record("ingress.listen"); return 18793; }
    async drain(): Promise<void> { record("ingress.drain"); }
    setClaudeLocalAuthorization(): void { record("ingress.authorization"); }
  }
  class SyntheticTunnels {
    constructor(_options: unknown) { record("remote.construct"); }
    cleanupStale(): void { record("remote.cleanup"); }
    reconcile(): void { record("remote.reconcile"); }
    assetsChanged(): void { record("remote.assetsChanged"); }
    stopAll(): void { record("remote.stop"); }
    status(): unknown[] { return []; }
  }
  class SyntheticUpdater {
    constructor(_options: unknown) { record("updater.construct"); }
    start(): void { record("updater.start"); }
    stop(): void { record("updater.stop"); }
  }
  class SyntheticAwake {
    constructor(_options: unknown) { record("awake.construct"); }
    async start(): Promise<void> { record("awake.start"); }
    stop(): void { record("awake.stop"); }
    beforeExit(): void { record("awake.beforeExit"); }
    async refresh(): Promise<void> { record("awake.refresh"); }
    status(): unknown { return {}; }
  }
  class SyntheticTether {
    constructor(_options: unknown) { record("tether.construct"); }
    start(): void { record("tether.start"); }
    stop(): void { record("tether.stop"); }
    kick(): void { record("tether.kick"); }
    setPin(): void { record("tether.pin"); }
    status(): unknown { return {}; }
  }
  const logger = {info:(message:string) => {logs.push(message);}, warn:(message:string) => {logs.push(message);}, error:(message:string) => {logs.push(message);}};
  const context = vm.createContext({
    // No real process, file, child-process, fetch, TLS, listener or controller capability is
    // available to this entry body. Only the three explicit synthetic writer spies touch disk.
    fs: new Proxy({}, {get:(_object,key) => {throw new Error(`Unexpected direct fs access: ${String(key)}`);}}),
    path, Buffer, Date, performance:{timeOrigin:Date.now()}, console:logger,
    process:{platform:"win32",pid:4242,env:{},on,exit:(code:number) => {throw new Error(`unexpected exit ${code}: ${logs.join("; ")}`);}},
    setTimeout:(fn:()=>unknown,ms:number) => timer("timeout",fn,ms),
    setInterval:(fn:()=>unknown,ms:number) => timer("interval",fn,ms),
    setImmediate:(fn:()=>unknown) => timer("immediate",fn),
    clearTimeout:(handle:Timer) => {if (handle) handle.active=false;},
    clearInterval:(handle:Timer) => {if (handle) handle.active=false;},
    assertPersonalWindowsNodeEnv:() => record("windows.environmentCheck"),
    captureRouterCodeIdentity:() => ({packageVersion:"fixture",sourceHash:"synthetic"}),
    homeDir:() => home, configPath:() => path.join(home,"config.json"),
    ConfigStore:SyntheticStore, personalMode,
    configurePersonalEgressPolicy:() => {},
    applyProcessPriority:() => {}, targetWarnings:() => [],
    PinnedAgentSync:SyntheticAgents, defaultAgentDir:() => path.dirname(files.worker),
    codexEnabled:() => {record("codex.enabled"); return true;},
    writeCodexCatalog:codexWrite, ingressModels:() => [],
    followCodexCache:(models:()=>unknown) => {
      record("codex.follow");
      cacheWatch={active:true,tick:() => {if (cacheWatch?.active) {models(); codexWrite();}}};
      return () => {record("codex.unfollow"); cacheWatch!.active=false;};
    },
    syncContextWindows:() => write("compact.sync",files.settings),
    Logger:class { info=logger.info; warn=logger.warn; error=logger.error; },
    CertStore:class { register() {} has() {return true;} contextFor() {throw new Error("unexpected certificate mint");} },
    readPrivateFile:(file:string) => {assert.ok(file.startsWith(home + path.sep)); return Buffer.from("synthetic certificate bytes");},
    migrateSecretFile:(file:string) => {assert.ok(file.startsWith(home + path.sep));},
    openRequestLog:() => ({}), terminateHosts:() => ["api.anthropic.com"],
    HoldGate:class {close() {}}, execRunner:() => (() => {throw new Error("unexpected process execution");}),
    UpstreamHealth:class {consecutiveFailures=0;}, EXIT_UPSTREAM_UNREACHABLE:75, checkConnectivity:() => {throw new Error("unexpected network check");},
    ObservedClaudeCodeAuth:class {constructor() {record("authObserver.construct");}}, allowLongSilences:() => {},
    Proxy:SyntheticProxy, OpenAiIngress:SyntheticIngress,
    AutoUpdater:SyntheticUpdater, autoUpdateEnabled:(config:Config) => config.autoUpdate === true,
    AwakeController:SyntheticAwake, TetherController:SyntheticTether,
    awakeSettings:(config:Config) => config.awake, tetherSettings:(config:Config) => config.tether,
    powerPlatform:() => "win32",
    runCli:() => {throw new Error("unexpected CLI execution");}, startCliDetached:() => {throw new Error("unexpected detached CLI");},
    RemoteTunnels:SyntheticTunnels, proxyConnectHost:(host:string) => host,
    readLocalAssets:() => {record("remote.assetsRead"); return {};},
    assetsFingerprint:() => "fixture", spawnSsh:() => {throw new Error("unexpected SSH");}, syncRemoteAssets:() => record("remote.sync"),
    ensureInstallationId:() => "synthetic-installation", VERSION:"fixture",
    startAdmin:async (deps:AdminDeps) => {record("admin.start"); admin=deps; return {port:18792};},
    loadModelCatalog:async () => {record("catalogue.load"); return {};},
    backfillContextWindows:async () => {record("catalogue.backfill"); await backfillGate; return [];},
    measureUnsettledModels:() => {record("models.measure"); return 0;},
    adoptNewClaudeModels:async () => {record("claude.adopt"); return [];},
  });
  await script.runInContext(context, {timeout:3000});
  await flush();
  assert.ok(admin, `admin startup did not finish: ${logs.join("; ")}`);
  return {
    calls, logs, before, snapshot, admin, timers,
    config:() => current,
    reload:(next:Config, errors:string[] = []) => {current=next; onConfig(current,errors);},
    cacheActive:() => Boolean(cacheWatch?.active),
    tickCache:() => cacheWatch?.tick(),
    holdBackfill() {
      let release!: () => void;
      backfillGate=new Promise<void>(resolve => {release=resolve;});
      return () => {backfillGate=undefined; release();};
    },
    async maintenance() {
      for (const entry of [...timers]) if (entry.active) {
        if (entry.kind !== "interval") entry.active=false;
        await entry.fn();
      }
      await flush();
    },
  };
}

const unrelatedWork = new Set([
  "authObserver.construct","proxy.receivedObservedAuth",
  "claude.usage","claude.models","claude.identity","claude.authorization","ingress.authorization",
  "agents.construct","ingress.construct","updater.construct","awake.construct","tether.construct",
  "agents.regenerate","agents.changed","compact.sync","codex.enabled","codex.write","codex.follow",
  "ingress.listen","remote.construct","remote.cleanup","remote.reconcile","remote.assetsRead","remote.sync",
  "chatgpt.quota","chatgpt.catalogue","awake.start","awake.refresh","tether.start","tether.kick","tether.pin",
  "updater.start","catalogue.load","catalogue.backfill","models.measure","claude.adopt",
]);

test("personal router startup preserves global Claude settings/workers and Codex files despite legacy knobs", async t => {
  const run = await runtime(t);
  assert.deepEqual(run.calls.filter(call => unrelatedWork.has(call)), []);
  assert.deepEqual(run.snapshot(), run.before);
  assert.equal(run.cacheActive(),false);
  assert.ok(run.calls.includes("proxy.listen"));
  assert.ok(run.calls.includes("admin.start"));
  assert.ok(run.calls.includes("windows.environmentCheck"));
  assert.equal(run.admin.observedClaudeCodeAuth, undefined, "personal startup exposes no observed-account authority to admin");
  assert.deepEqual(run.timers.filter(timer => timer.kind !== "immediate").map(timer => timer.ms), [5*60_000],
    "only the existing own-router statistics timer remains");
});

test("personal config reload, account callback and maintenance cannot generate workers, rewrite context or touch Codex", async t => {
  const run = await runtime(t);
  const next=structuredClone(run.config());
  next.cli.extraModels.push({model:"gemini-fixture-two",name:"Synthetic second choice"});
  run.reload(next);
  run.admin.agentsChanged?.();
  run.tickCache();
  await run.maintenance();
  await run.maintenance();
  assert.deepEqual(run.calls.filter(call => unrelatedWork.has(call)), []);
  assert.deepEqual(run.snapshot(), run.before);
  assert.ok(run.calls.includes("proxy.reconcile"), "connection policy still reconciles on reload");
  assert.ok(run.calls.includes("proxy.clearSelection"));
});

test("personal administrative power/remote callbacks do not start hidden services", async t => {
  const run=await runtime(t);
  assert.equal(run.admin.remote?.status().length,0);
  assert.equal(run.admin.remote?.reload().length,0);
  run.admin.power?.pin(true);
  await run.admin.power?.poke();
  assert.deepEqual(run.calls.filter(call => unrelatedWork.has(call)), []);
  assert.deepEqual(run.snapshot(),run.before);
});

test("personal native-account callbacks neither inspect nor alter the native login", async t => {
  const run = await runtime(t);
  assert.equal(Object.keys(await run.admin.claudeUsage!()).length, 0);
  assert.equal(await run.admin.claudeModels!(), null);
  assert.equal(await run.admin.claudeIdentity!(), null);
  run.admin.claudeLocalAuthorization!(true);
  run.admin.claudeLocalAuthorization!(false);
  assert.deepEqual(run.calls.filter(call => unrelatedWork.has(call)), []);
  assert.deepEqual(run.snapshot(), run.before);
});

test("personal shutdown drains the proxy without constructing or running unrelated cleanup controllers", async t => {
  const run = await runtime(t);
  assert.equal(run.admin.power, undefined);
  assert.equal(run.admin.autoUpdater, undefined);
  run.admin.shutdown?.();
  await flush();
  assert.ok(run.calls.includes("proxy.drain"));
  assert.deepEqual(run.calls.filter(call => unrelatedWork.has(call)), []);
  for (const name of ["ingress.drain", "updater.stop", "awake.stop", "awake.beforeExit", "tether.stop"])
    assert.equal(run.calls.includes(name), false, name);
  assert.deepEqual(run.snapshot(), run.before);
});

test("an empty fail-closed personal configuration does not remove or rewrite existing client state", async t => {
  const run=await runtime(t);
  run.reload({...structuredClone(DEFAULTS),security:{mode:"personal",approvedOrigins:[]}},["synthetic config validation failure"]);
  run.admin.agentsChanged?.(); await run.maintenance();
  assert.deepEqual(run.calls.filter(call => unrelatedWork.has(call)),[]);
  assert.deepEqual(run.snapshot(),run.before);
  assert.ok(run.logs.some(line => line.includes("synthetic config validation failure")));
});

test("generic mode positive control retains integration writers, worker/context maintenance and optional services", async t => {
  const run=await runtime(t,false);
  for (const call of ["authObserver.construct","proxy.receivedObservedAuth","agents.construct","ingress.construct","updater.construct","awake.construct","tether.construct",
    "agents.regenerate","compact.sync","codex.enabled","codex.write","codex.follow","ingress.listen",
    "remote.cleanup","chatgpt.quota","chatgpt.catalogue","awake.start","tether.start","updater.start"])
    assert.ok(run.calls.includes(call),call);
  assert.ok(run.admin.observedClaudeCodeAuth, "generic account-pool support remains available");
  await run.admin.claudeUsage!();
  await run.admin.claudeModels!();
  await run.admin.claudeIdentity!();
  run.admin.claudeLocalAuthorization!(true);
  for (const call of ["claude.usage", "claude.models", "claude.identity", "claude.authorization", "ingress.authorization"])
    assert.ok(run.calls.includes(call), call);
  assert.notDeepEqual(run.snapshot(),run.before,"the instrumented writers must actually change fixture bytes when invoked");
  assert.equal(run.snapshot().userWorker,run.before.userWorker);
  assert.equal(run.snapshot().codexConfig,run.before.codexConfig);
  const count=run.calls.length;
  run.tickCache(); run.admin.agentsChanged?.(); await run.maintenance();
  for (const call of ["codex.write","agents.changed","agents.regenerate","compact.sync","catalogue.backfill","models.measure","claude.adopt"])
    assert.ok(run.calls.slice(count).includes(call),call);
});

test("a generic-to-personal reload stops the Codex watcher and queued entry-point maintenance rechecks live mode", async t => {
  const run=await runtime(t,false);
  assert.equal(run.cacheActive(),true);
  const before=run.snapshot(), at=run.calls.length;
  run.reload(runtimeConfig(true));
  assert.equal(run.cacheActive(),false);
  assert.ok(run.calls.slice(at).includes("codex.unfollow"));
  run.tickCache(); run.admin.agentsChanged?.();
  assert.equal(Object.keys(await run.admin.claudeUsage!()).length, 0);
  assert.equal(await run.admin.claudeModels!(), null);
  assert.equal(await run.admin.claudeIdentity!(), null);
  run.admin.claudeLocalAuthorization!(true);
  await run.maintenance();
  // A pre-existing generic tunnel manager may reconcile an empty host list to stop its old
  // tunnels. This is cleanup, not a new connection. The real controllers' private timers are
  // outside this orchestration fixture; their own stop/reload behavior has separate tests.
  const unwanted=run.calls.slice(at).filter(call => unrelatedWork.has(call) && call !== "remote.reconcile");
  assert.deepEqual(unwanted,[]);
  assert.deepEqual(run.snapshot(),before);
});

test("an in-flight generic catalogue backfill cannot start effort probes after personal mode activates", async t => {
  const run=await runtime(t,false), release=run.holdBackfill();
  await run.maintenance();
  assert.ok(run.calls.includes("catalogue.backfill"));
  assert.equal(run.calls.includes("models.measure"),false);
  const before=run.snapshot(), at=run.calls.length;
  run.reload(runtimeConfig(true));
  release(); await flush();
  assert.equal(run.calls.slice(at).includes("models.measure"),false);
  assert.deepEqual(run.snapshot(),before);
});
