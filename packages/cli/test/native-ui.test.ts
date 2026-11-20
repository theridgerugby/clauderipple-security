import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import type { ChildProcess, SpawnOptions } from "node:child_process";
import path from "node:path";
import os from "node:os";
import { NATIVE_UI_REMEDIATION, openNativeDashboard } from "../src/native-ui.ts";
import { runtime } from "../src/runtime.ts";

const home = path.resolve(os.tmpdir(), "native-ui-home");
const installedElectron = path.join(home, "runtime", process.platform === "win32" ? "electron.exe" : "electron");
const main = path.join(home, "app", "main.js");
function spawnFixture(calls: { file: string; args: string[]; options: SpawnOptions }[], outcome: "spawn" | "error" = "spawn") {
  return (file: string, args: string[], options: SpawnOptions): ChildProcess => {
    calls.push({ file, args, options });
    const child = Object.assign(new EventEmitter(), { unref() {} });
    queueMicrotask(() => child.emit(outcome, outcome === "error" ? new Error("private process diagnostics") : undefined));
    return child as ChildProcess;
  };
}
test("native dashboard starts only an existing absolute runtime with non-secret view argv", async () => {
  const calls: { file: string; args: string[]; options: SpawnOptions }[] = [];
  const result = await openNativeDashboard(home, "mod", {
    rt: { ...runtime(), trayMain: main, packaged: false }, electron: requested => { assert.equal(requested, home); return installedElectron; },
    exists: file => [installedElectron, main].includes(file), spawn: spawnFixture(calls),
  });
  assert.equal(result.ok, true); assert.equal(calls.length, 1);
  assert.equal(calls[0]!.file, installedElectron); assert.deepEqual(calls[0]!.args, [main, "--ripple-admin-view=mod"]);
  assert.equal(calls[0]!.options.env?.CLAUDERIPPLE_HOME, home);
  assert.equal(calls[0]!.options.env?.ELECTRON_RUN_AS_NODE, undefined);
  assert.equal(calls[0]!.options.detached, true);
  assert.doesNotMatch(JSON.stringify(calls[0]!.args), /https?:|admin-token/);
});
test("packaged native app launch does not execute a source script", async () => {
  const calls: { file: string; args: string[]; options: SpawnOptions }[] = [];
  const result = await openNativeDashboard(home, "dashboard", {
    rt: { ...runtime(), node: installedElectron, packaged: true }, exists: () => true, spawn: spawnFixture(calls),
    electron: () => { throw new Error("packaged launch must not resolve an npm runtime"); },
  });
  assert.equal(result.ok, true); assert.deepEqual(calls[0]!.args, ["--ripple-admin-view=dashboard"]);
});
test("missing runtime, relative executable, and launch failure never fall back to a browser or install", async () => {
  let spawned = 0;
  for (const file of [null, "electron", installedElectron]) {
    const result = await openNativeDashboard(home, "dashboard", {
      rt: { ...runtime(), packaged: false, trayMain: main }, electron: () => file, exists: () => false,
      spawn: () => { spawned++; throw new Error("must not run"); },
    });
    assert.equal(result.ok, false); assert.equal(result.message, NATIVE_UI_REMEDIATION);
  }
  assert.equal(spawned, 0);
  const failure = await openNativeDashboard(home, "mod", { rt: { ...runtime(), packaged: true }, exists: () => true, spawn: spawnFixture([], "error") });
  assert.equal(failure.ok, false); assert.equal(failure.message, NATIVE_UI_REMEDIATION);
  assert.doesNotMatch(failure.message, /private process diagnostics/);
});
