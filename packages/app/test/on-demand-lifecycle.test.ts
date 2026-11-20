import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import * as adminAuth from "../src/admin-auth.ts";
import * as adminWindow from "../src/admin-window.ts";
import * as failureModel from "../src/failure-model.ts";
import * as statusModel from "../src/status-model.ts";
import * as updateModel from "../src/update-model.ts";

// Execute the complete production entry point, including app.whenReady and app event wiring.
// Only native/CLI/network boundaries are replaced. No source substring or reimplemented boot
// function can conceal a timer, tray, login-item write, updater or hidden client mutation.
const source = fs.readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source + "\nexports.readState = bridgeState;", {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
}).outputText;

type Options = { config?: "personal" | "invalid" | "missing" | "unknown"; offline?: boolean; doctorFails?: boolean; pendingDoctor?: boolean; argv?: string[]; env?: Record<string, string> };

async function boot(t: TestContext, options: Options = {}) {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-app-boot-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "config.json");
  if (options.config !== "missing") {
    fs.writeFileSync(file, options.config === "invalid" ? "{invalid" : JSON.stringify({
      security: { mode: options.config === "unknown" ? "generic" : "personal", approvedOrigins: [] },
      listen: { port: 19990 }, admin: { port: 19991 },
    }), { mode: 0o600 });
  }
  const originalConfig = fs.existsSync(file) ? fs.readFileSync(file) : null;
  const calls = {
    trays: 0, loginReads: 0, loginWrites: 0, windows: 0, quits: 0, setupDialogs: 0, doctorAborts: 0,
    cli: [] as { args: string[]; timeout: number }[], admin: [] as string[],
    timers: [] as { type: string; ms?: number }[], writes: [] as string[], logs: [] as unknown[][],
  };
  const events = new Map<string, (...args: unknown[]) => unknown>();
  const ipc = new Map<string, (...args: unknown[]) => unknown>();
  let currentWindow: { webContents: object } | null = null;
  let ready: Promise<unknown> = Promise.resolve();
  const forbidden = (): never => { throw new Error("Unexpected external operation during dashboard boot"); };
  const io = {
    existsSync: () => false,
    readFileSync: (filename: string) => {
      if (filename === path.join(home, "app.json")) return "{}";
      if (filename.endsWith("package.json")) return '{"version":"fixture"}';
      throw Object.assign(new Error("fixture file absent"), { code: "ENOENT" });
    },
    mkdirSync: (filename: string) => { calls.writes.push(filename); forbidden(); },
    writeFileSync: (filename: string) => { calls.writes.push(filename); forbidden(); },
  };
  const modules: Record<string, object> = {
    electron: {
      app: {
        enableSandbox() {}, getPath: () => home, setPath() {}, requestSingleInstanceLock: () => true,
        on: (name: string, callback: (...args: unknown[]) => unknown) => { events.set(name, callback); },
        whenReady: () => ({ then: (callback: () => unknown) => { ready = Promise.resolve().then(callback); return ready; } }),
        isReady: () => true, isPackaged: false, getVersion: () => "fixture", setAppUserModelId() {},
        getPreferredSystemLanguages: () => ["en"], getSystemLocale: () => "en", getLocale: () => "en",
        getLoginItemSettings: () => { calls.loginReads++; return { openAtLogin: false }; },
        setLoginItemSettings: () => { calls.loginWrites++; },
        quit: () => { calls.quits++; events.get("before-quit")?.(); }, exit: forbidden,
      },
      Menu: { setApplicationMenu() {}, buildFromTemplate: (items: object[]) => items },
      Tray: class { constructor() { calls.trays++; forbidden(); } },
      Notification: class { constructor() { forbidden(); } static isSupported() { return false; } },
      nativeImage: { createFromPath: forbidden }, shell: { openExternal: forbidden, openPath: forbidden },
      dialog: { showMessageBox: () => { calls.setupDialogs++; forbidden(); } }, clipboard: {}, session: { defaultSession: {} },
      ipcMain: { handle: (name: string, callback: (...args: unknown[]) => unknown) => { ipc.set(name, callback); } },
    },
    "node:child_process": { execFile: forbidden },
    "./bounded-exec": {
      execBounded: (_node: string, args: string[], opts: { timeoutMs: number; maxBuffer: number; signal?: AbortSignal }) => {
        calls.cli.push({ args: Array.from(args).slice(1), timeout: opts.timeoutMs });
        assert.equal(opts.maxBuffer, 1024 * 1024, "diagnostic output stays bounded and separate from stderr");
        assert.deepEqual(Array.from(args).slice(1), ["doctor", "--json"], "opening/closing a dashboard must never mutate a client or install/restart/update a service");
        if (options.pendingDoctor) {
          return new Promise((_resolve, reject) => {
            opts.signal?.addEventListener("abort", () => {
              calls.doctorAborts++;
              reject(new Error("diagnostic aborted"));
            }, { once: true });
          });
        }
        if (options.doctorFails) return Promise.reject(Object.assign(new Error("synthetic-diagnostic-secret"), { stdout: "private-json", stderr: "private-stderr" }));
        return Promise.resolve(JSON.stringify({ mode: "ripple", router: { responding: !options.offline }, problems: [] }));
      },
    },
    "node:fs": io, "node:os": { homedir: forbidden }, "node:path": path,
    "./admin-auth": {
      readPrivateConfigPorts: adminAuth.readPrivateConfigPorts,
      fetchAdmin: async (_base: string, route: string) => {
        calls.admin.push(route);
        if (options.offline) throw new Error("fixture router unavailable");
        return { ok: true, json: async () => ({ version: "fixture", settings: {}, listen: { port: 19990 }, providers: {}, readiness: { ready: true, problems: [] } }) };
      },
    },
    "./admin-ipc": { ADMIN_IPC_CHANNEL: "ripple-app:admin-request", createAdminRequestHandler: () => forbidden },
    "./admin-window": { ...adminWindow, prepareAdminUserDataPath: (directory: string) => directory },
    "./security": { configurePermissions() {}, trustedIpcSender: (event: { trusted?: boolean }) => event.trusted === true },
    "./claude-desktop": { claudeStartedAt: forbidden, reopenClaude: forbidden },
    "./failure-model": failureModel, "./status-model": statusModel, "./update-model": updateModel,
    "./protocol": { registerScheme() {}, handleScheme() {}, ORIGIN: "ripple://app" },
    "./window": {
      mainWindow: () => currentWindow, windowVisible: () => currentWindow !== null, sendToWindow() {},
      openWindow: (deps: { shown: () => void }) => { calls.windows++; currentWindow = { webContents: {} }; deps.shown(); },
    },
  };
  const exported: { readState?: () => statusModel.AppState } = {};
  runInNewContext(compiled, {
    exports: exported, require: (id: string) => { assert.ok(id in modules, id); return modules[id]; },
    process: { env: { CLAUDERIPPLE_HOME: home, CLAUDERIPPLE_APP_CLI: path.join(home, "fake-cli"), ...options.env }, argv: ["electron", "main.js", ...(options.argv ?? [])], platform: "win32", execPath: "electron.exe" },
    __dirname: path.join(home, "app/dist"), console: Object.fromEntries(["log", "warn", "error"].map(method => [method, (...args: unknown[]) => calls.logs.push(args)])), fetch: forbidden, AbortSignal, AbortController,
    setTimeout: (_fn: unknown, ms?: number) => { calls.timers.push({ type: "timeout", ms }); return 1; },
    setInterval: (_fn: unknown, ms?: number) => { calls.timers.push({ type: "interval", ms }); return 2; },
  });
  const settle = async () => { await ready; await new Promise<void>(resolve => setImmediate(resolve)); };
  await settle();
  return {
    calls, events, ipc, settle,
    state: () => JSON.parse(JSON.stringify(exported.readState!())) as statusModel.AppState,
    unchangedConfig: () => assert.deepEqual(fs.existsSync(file) ? fs.readFileSync(file) : null, originalConfig),
  };
}

test("actual Windows boot opens one on-demand window with one bounded doctor and no resident tray, timers, login item or updater", async t => {
  const app = await boot(t);
  assert.equal(app.calls.windows, 1);
  assert.deepEqual(app.calls.cli, [{ args: ["doctor", "--json"], timeout: 15_000 }]);
  assert.deepEqual(app.calls.admin, ["/api/status"]);
  assert.deepEqual(app.calls.timers, []);
  assert.equal(app.calls.trays, 0);
  assert.equal(app.calls.loginReads, 0);
  assert.equal(app.calls.loginWrites, 0);
  assert.equal(app.calls.setupDialogs, 0);
  assert.deepEqual(app.calls.writes, []);
  assert.equal(app.state().loginItem, null);
  app.unchangedConfig();
  app.events.get("window-all-closed")!();
  await app.settle();
  assert.equal(app.calls.quits, 1);
  assert.equal(app.calls.cli.length, 1, "close must not stop/reconfigure the router or Claude Desktop");
});

for (const config of ["missing", "invalid", "unknown"] as const) {
  test(`${config} configuration still opens offline recovery without background behavior or config repairs`, async t => {
    const app = await boot(t, { config, offline: true, doctorFails: true, env: { CLAUDERIPPLE_SECURITY_MODE: "generic", CLAUDERIPPLE_PERSONAL_MODE: "0" } });
    assert.equal(app.calls.windows, 1);
    assert.equal(app.state().doctorFailed, true);
    assert.equal(app.state().loginItem, null);
    assert.deepEqual(app.calls.timers, []);
    assert.equal(app.calls.loginWrites, 0);
    assert.equal(app.calls.trays, 0);
    assert.deepEqual(app.calls.logs, [], "CLI errors and output may contain secrets and must not be echoed");
    app.unchangedConfig();
  });
}

test("a trusted renderer cannot re-enable an app login item, while explicit recovery refresh remains available", async t => {
  const app = await boot(t);
  const act = app.ipc.get("ripple-app:act")!;
  assert.equal(await act({ trusted: true }, "login-item"), null);
  assert.equal(app.calls.loginWrites, 0);
  assert.equal(app.calls.cli.length, 1);
  await act({ trusted: true }, "refresh");
  assert.equal(app.calls.cli.length, 2);
  assert.deepEqual(app.calls.admin, ["/api/status", "/api/status"]);
  assert.deepEqual(app.calls.timers, []);
  assert.equal(await act({ trusted: false }, "refresh"), null);
  assert.equal(app.calls.cli.length, 2);
});

test("closing during a stalled diagnostic aborts only its owned subprocess signal", async t => {
  const app = await boot(t, { pendingDoctor: true });
  assert.equal(app.calls.cli.length, 1);
  assert.equal(app.calls.doctorAborts, 0);
  app.events.get("window-all-closed")!();
  await app.settle();
  assert.equal(app.calls.quits, 1);
  assert.equal(app.calls.doctorAborts, 1);
  assert.deepEqual(app.calls.cli.map(call => call.args), [["doctor", "--json"]]);
  assert.equal(app.calls.loginWrites, 0);
});

test("a marked old background launch exits without altering its registration or starting recovery", async t => {
  const app = await boot(t, { argv: ["--at-login"] });
  assert.equal(app.calls.quits, 1);
  assert.equal(app.calls.windows, 0);
  assert.equal(app.calls.trays, 0);
  assert.equal(app.calls.loginWrites, 0);
  assert.deepEqual(app.calls.cli, []);
  assert.deepEqual(app.calls.admin, []);
  assert.deepEqual(app.calls.timers, []);
  assert.deepEqual(app.calls.writes, []);
});

test("explicit dashboard launch wins over a legacy marker and an unmarked old launch remains closeable", async t => {
  const explicit = await boot(t, { argv: ["--at-login", "--ripple-admin-view=dashboard"] });
  assert.equal(explicit.calls.windows, 1);
  assert.equal(explicit.calls.quits, 0);
  explicit.events.get("window-all-closed")!();
  assert.equal(explicit.calls.quits, 1);
  const legacy = await boot(t);
  legacy.events.get("window-all-closed")!();
  assert.equal(legacy.calls.quits, 1);
  assert.equal(legacy.calls.loginWrites, 0, "legacy registry ownership is not guessed from app state");
});
