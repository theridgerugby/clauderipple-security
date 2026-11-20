// Exercise the actual launcher body with OS boundaries replaced. No Electron, user files,
// service registrations or old log contents are touched by these fixtures.
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import fs from "node:fs";
import ts from "typescript";
import { earlyExit, trayEnv } from "../src/tray.ts";

const source = fs.readFileSync(new URL("../src/tray.ts", import.meta.url), "utf8");
const syntax = ts.createSourceFile("tray.ts", source, ts.ScriptTarget.ES2022, true);
const entry = syntax.statements.find(statement => ts.isFunctionDeclaration(statement) && statement.name?.text === "startTray");
assert.ok(entry);
const compiled = ts.transpileModule(entry.getText(syntax), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 },
}).outputText;

function fixture(packaged = false) {
  const launches: { executable: string; args: string[]; options: Record<string, unknown> }[] = [];
  let lookups = 0, exitChecks = 0, unrefs = 0;
  const start = new Function("deps", `
    const exports = {};
    const { runtime, trayEnv, spawn, electronPath, ensureTrayBundle, earlyExit, fs } = deps;
    ${compiled}
    return exports.startTray;
  `)({
    runtime: () => { lookups++; return { node: "fixture-electron", packaged, trayMain: "fixture-main.js" }; },
    trayEnv: () => ({ KEEP: "fixture" }),
    spawn: (executable: string, args: string[], options: Record<string, unknown>) => {
      launches.push({ executable, args, options }); return { unref: () => { unrefs++; } };
    },
    electronPath: () => "fixture-electron",
    ensureTrayBundle: () => null,
    earlyExit: async (_child: unknown, log: string | null) => {
      assert.equal(log, null, "no historical log may be read or quoted"); exitChecks++;
      return { ok: true, message: "fixture started" };
    },
    fs: new Proxy({}, { get: (_target, key) => {
      if (key === "existsSync") return () => true;
      throw new Error(`unexpected filesystem operation: ${String(key)}`);
    } }),
  });
  return { start, launches, counts: () => ({ lookups, exitChecks, unrefs }) };
}

test("personal dashboard launches without a persistent stdout/stderr sink or log read", async () => {
  const f = fixture();
  assert.equal((await f.start()).ok, true);
  assert.deepEqual(f.launches, [{ executable: "fixture-electron", args: ["fixture-main.js"],
    options: { detached: true, stdio: "ignore", env: { KEEP: "fixture", CLAUDERIPPLE_APP_SHOW: "1" } } }]);
  assert.deepEqual(f.counts(), { lookups: 1, exitChecks: 1, unrefs: 1 });
});

test("legacy login launch requests do not locate, download or spawn a setup window", async () => {
  for (const packaged of [false, true]) {
    const f = fixture(packaged);
    assert.equal((await f.start({ atLogin: true })).ok, true);
    assert.deepEqual(f.launches, []);
    assert.deepEqual(f.counts(), { lookups: 0, exitChecks: 0, unrefs: 0 });
  }
});

test("personal dashboard drops inherited Electron output/key logs without changing the caller", () => {
  const original = { KEEP: "fixture", ELECTRON_RUN_AS_NODE: "1", Electron_Log_File: "sensitive.log",
    ELECTRON_ENABLE_LOGGING: "1", SSLKEYLOGFILE: "tls-keys.log" };
  assert.deepEqual(trayEnv(original), { KEEP: "fixture" });
  assert.equal(original.Electron_Log_File, "sensitive.log");
});

test("an early dashboard failure reports only its status when output capture is disabled", async () => {
  const child = spawn(process.execPath, ["-e", "console.error('SYNTHETIC_PRIVATE_CONTENT');process.exit(3)"], { stdio: "ignore" });
  const result = await earlyExit(child, null, 5_000);
  assert.equal(result.ok, false);
  assert.match(result.message, /exit code 3/);
  assert.match(result.message, /Raw output was not saved/);
  assert.doesNotMatch(result.message, /SYNTHETIC_PRIVATE_CONTENT|tray\.log/);
});
