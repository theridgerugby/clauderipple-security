// Boot the actual built app and close its real sandboxed BrowserWindow. Only the external CLI
// boundary is replaced: this fixture must not inspect/mutate a user's real supervisor or clients.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const childProcess = require("node:child_process");
const { app, BrowserWindow } = require("electron");
const bounded = require("../dist/bounded-exec.js");
const { diagnosticTreeScript, processIsRunning } = require("./diagnostic-tree.cjs");
const realExecBounded = bounded.execBounded;

const home = process.env.RIPPLE_NATIVE_FIXTURE;
const scenario = process.env.RIPPLE_NATIVE_LIFECYCLE_CASE;
assert.ok(home && path.isAbsolute(home));
assert.ok(["missing", "invalid", "personal", "pending"].includes(scenario));
assert.ok(!app.commandLine.hasSwitch("no-sandbox"));
assert.ok(!app.commandLine.hasSwitch("disable-setuid-sandbox"));
assert.ok(!process.env.ELECTRON_DISABLE_SANDBOX);
process.env.CLAUDERIPPLE_HOME = home;
process.env.CLAUDERIPPLE_APP_USER_DATA = path.join(home, "app-data");
process.env.CLAUDERIPPLE_APP_CLI = path.join(home, "synthetic-cli-not-executed");
delete process.env.CLAUDERIPPLE_APP_ADMIN_URL;
delete process.env.CLAUDERIPPLE_APP_SHOW;

let doctors = 0, windows = 0, closed = false, refusalChecked = false, failed = false;
let diagnosticAborted = false, ownedRoot = 0, diagnosticOutput = "";
let readyResolve;
const pendingReady = new Promise(resolve => { readyResolve = resolve; });
const fail = error => { failed = true; console.error(error); app.exit(1); };
// Fail on any attempt to install/update/restart a service, reconnect an account, alter a login
// item, open a browser, or stop Claude. No such operation is necessary to view/close setup.
childProcess.execFile = () => { throw new Error("Dashboard boot must not run an unbounded CLI worker"); };
bounded.execBounded = (_executable, args, options) => {
  assert.deepEqual(args.slice(1), ["doctor", "--json"]);
  assert.equal(options.timeoutMs, 15_000);
  assert.equal(options.maxBuffer, 1024 * 1024);
  doctors++;
  if (scenario === "pending") {
    assert.ok(options.signal && !options.signal.aborted);
    options.signal.addEventListener("abort", () => { diagnosticAborted = true; }, { once: true });
    // Substitute only the external CLI payload with an inert self-expiring process tree. The
    // real production helper, cancellation signal, timeout and cleanup still execute unchanged.
    return realExecBounded(process.execPath, ["-e", diagnosticTreeScript], {
      ...options, env: { ...process.env, ELECTRON_RUN_AS_NODE: "1" },
      spawn: (file, argv, spawnOptions) => {
        if (file === process.execPath) {
          assert.deepEqual(argv, ["-e", diagnosticTreeScript]);
        } else {
          assert.equal(process.platform, "win32");
          assert.equal(file, "taskkill");
          assert.deepEqual(argv, ["/PID", String(ownedRoot), "/T", "/F"]);
        }
        const child = childProcess.spawn(file, argv, spawnOptions);
        if (file === process.execPath) {
          ownedRoot = child.pid;
          child.stdout.on("data", chunk => {
            diagnosticOutput += String(chunk);
            if (diagnosticOutput.includes("\n")) readyResolve(JSON.parse(diagnosticOutput.split("\n")[0]));
          });
        }
        return child;
      },
    });
  }
  return Promise.resolve(JSON.stringify({
    mode: "direct", router: { responding: false },
    supervisor: { registered: false }, desktop: { proxy: "none" }, cli: { proxy: "none" }, problems: [],
  }));
};
app.setLoginItemSettings = () => { throw new Error("Dashboard must not change login items"); };
app.getLoginItemSettings = () => { throw new Error("Dashboard must not inspect unrelated login items"); };
global.fetch = async () => { throw new Error("Dashboard boot must not initiate an external fetch"); };

app.on("browser-window-created", (_event, window) => {
  windows++;
  window.webContents.once("did-fail-load", (_event, code, message) => fail(new Error(`Dashboard did not load: ${code} ${message}`)));
  window.webContents.once("did-finish-load", () => {
    void (async () => {
      const preferences = window.webContents.getLastWebPreferences();
      assert.equal(preferences.sandbox, true);
      assert.equal(preferences.contextIsolation, true);
      assert.equal(preferences.nodeIntegration, false);
      const result = await window.webContents.executeJavaScript(`(async () => ({
        state: await rippleApp.state(),
        loginAttempt: await rippleApp.enableLoginItem(),
        unrelatedRoutes: await Promise.all(["/api/update", "/api/claude-login", "/api/power", "/api/codex"]
          .map(path => rippleApp.adminRequest({path, method: "POST"}).then(reply => reply.status))),
        requireType: typeof require,
        hasRecovery: typeof rippleApp.repair === "function" && typeof rippleApp.directOn === "function"
      }))()`);
      assert.equal(result.state.loginItem, null);
      assert.equal(result.loginAttempt, null);
      assert.deepEqual(result.unrelatedRoutes, [403, 403, 403, 403]);
      assert.equal(result.requireType, "undefined");
      assert.equal(result.hasRecovery, true);
      assert.equal(doctors, 1, "one bounded diagnostic on opening; none on the rejected login-item action");
      refusalChecked = true;
      if (scenario === "pending") {
        let timer;
        const pids = await Promise.race([pendingReady, new Promise((_resolve, reject) => {
          timer = setTimeout(() => reject(new Error("Native diagnostic fixture did not become ready")), 10000);
        })]).finally(() => clearTimeout(timer));
        assert.equal(pids.root, ownedRoot);
        assert.notEqual(pids.root, pids.descendant);
        assert.equal(processIsRunning(pids.root), true);
        assert.equal(processIsRunning(pids.descendant), true);
        fs.writeFileSync(path.join(home, "diagnostic-processes.json"), JSON.stringify(pids), { mode: 0o600 });
      }
      window.once("closed", () => { closed = true; });
      window.close();
    })().catch(fail);
  });
});
app.on("will-quit", () => {
  if (failed) return;
  try {
    assert.equal(windows, 1);
    assert.equal(closed, true);
    assert.equal(refusalChecked, true);
    assert.equal(doctors, 1);
    assert.equal(BrowserWindow.getAllWindows().length, 0);
    if (scenario === "pending") assert.equal(diagnosticAborted, true, "actual before-quit must cancel its owned diagnostic tree");
    console.log(`PASS native personal dashboard (${scenario}): real boot, login-item IPC refusal, close-to-quit`);
  } catch (error) { fail(error); }
});
process.on("unhandledRejection", fail);
process.on("uncaughtException", fail);
require("../dist/main.js");
