import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import { selectWindowsDesktop, windowsDesktopRestartScript, type WindowsDesktopSelection } from "../src/claude-desktop.ts";

const LOCAL = String.raw`C:\Users\Fixture\AppData\Local`;
const PROGRAMS = String.raw`C:\Program Files`;
const DESKTOP = LOCAL + String.raw`\AnthropicClaude\app-1.2.3\claude.exe`;
const STARTED = "2026-11-19T21:00:00.0000000Z";
const visible = (overrides: Record<string, unknown> = {}) => ({
  id: 1001, visible: true, path: DESKTOP, startedAt: STARTED,
  productName: "Claude", fileDescription: "Claude", signatureStatus: "Valid", signer: "Anthropic, PBC",
  ...overrides,
});
const snapshot = (processes: unknown[], overrides: Record<string, unknown> = {}) => ({ localAppData: LOCAL, programFiles: PROGRAMS, processes, ...overrides });

test("Windows selection identifies one signed Desktop image and leaves headless CLI processes outside the close plan", () => {
  const selected = selectWindowsDesktop(snapshot([
    visible(),
    { id: 2002, visible: false, path: String.raw`C:\Users\Fixture\.local\bin\claude.exe` },
    { id: 2003, visible: false, path: DESKTOP.replace("claude.exe", String.raw`resources\claude-code\claude.exe`) },
  ]));
  assert.deepEqual(selected, { exe: DESKTOP, processes: [{ id: 1001, startedAt: STARTED }] });
});

test("Windows selection accepts conservative classic and package Desktop layouts", () => {
  for (const exe of [
    LOCAL + String.raw`\AnthropicClaude\claude.exe`,
    PROGRAMS + String.raw`\WindowsApps\Claude_1.2.3.4_x64__pzs8sxrjxfjjc\app\Claude.exe`,
    PROGRAMS + String.raw`\WindowsApps\Claude_1.2.3.4_arm64__pzs8sxrjxfjjc\app\Claude.exe`,
  ]) assert.equal(selectWindowsDesktop(snapshot([visible({ path: exe })]))?.exe, exe);
});

test("Windows selection refuses multiple visible executable paths or an incompletely identified window owner", () => {
  for (const other of [
    visible({ id: 1002, path: DESKTOP.replace("app-1.2.3", "app-1.2.4") }),
    visible({ id: 1002, path: String.raw`C:\Users\Fixture\.local\bin\claude.exe`, productName: "Claude Code" }),
    visible({ id: 1002, path: null }),
    { id: 1002, visible: null },
  ]) assert.equal(selectWindowsDesktop(snapshot([visible(), other])), undefined);
  const same = selectWindowsDesktop(snapshot([visible(), visible({ id: 1002, path: DESKTOP.toUpperCase() })]));
  assert.equal(same?.processes.length, 2, "every visible owner must belong to the same validated executable");
});

test("a process name, a window, and copied metadata alone never authorize a Windows restart", () => {
  for (const change of [
    { productName: "Claude Code" }, { fileDescription: "" }, { signatureStatus: "NotSigned" },
    { signatureStatus: "UnknownError" }, { signer: "Unrelated publisher" }, { signer: null }, { signer: ["Anthropic, PBC"] },
    { id: -1 }, { id: 1.5 }, { startedAt: "not a date" }, { startedAt: "" },
    { path: String.raw`C:\Tools\claude.exe` },
    { path: LOCAL + String.raw`\AnthropicClaude\resources\claude-code\claude.exe` },
    { path: LOCAL + String.raw`\AnthropicClaude\..\cli\claude.exe` },
    { path: String.raw`\\server\share\AnthropicClaude\claude.exe` },
    { path: DESKTOP + ":alternate-stream" },
  ]) assert.equal(selectWindowsDesktop(snapshot([visible(change)])), undefined, JSON.stringify(change));
});

test("absent, headless, duplicate and malformed Windows snapshots fail without choosing a guessed executable", () => {
  assert.equal(selectWindowsDesktop(snapshot([])), null);
  for (const value of [undefined, {}, snapshot([{ id: 1001, visible: false }]), snapshot([visible(), visible()]), snapshot(new Array(257).fill(visible()))])
    assert.equal(selectWindowsDesktop(value), undefined);
});

test("restart script validates exact PIDs, birth times, image metadata and all visible paths before a graceful close", () => {
  const selected = selectWindowsDesktop(snapshot([visible()]))!;
  const script = windowsDesktopRestartScript(selected)!;
  assert.match(script, /\$expected = @\{ 1001 = '2026-11-19T21:00:00\.0000000Z' \}/);
  assert.match(script, /\$windows\.Count -ne \$expected\.Count/);
  assert.match(script, /\$expected\.ContainsKey\(\$p\.Id\)/);
  assert.match(script, /\$p\.Path -ine \$exe/);
  assert.match(script, /\$p\.StartTime\.ToUniversalTime\(\)\.ToString\('o'\) -cne \$expected\[\$p\.Id\]/);
  assert.ok(script.indexOf("Get-AuthenticodeSignature") < script.indexOf("CloseMainWindow"));
  assert.ok(script.indexOf("$expected.ContainsKey") < script.indexOf("CloseMainWindow"));
  assert.match(script, /if \(-not \$p\.CloseMainWindow\(\)\) \{ exit 1 \}/);
  assert.match(script, /AddMilliseconds\(20000\)/);
  assert.match(script, /if \(\(Get-Date\) -ge \$deadline\) \{ exit 1 \}/);
  assert.ok(script.indexOf("$remaining.Count -eq 0") < script.indexOf("Start-Process -FilePath $exe"));
  assert.doesNotMatch(script, /Stop-Process|taskkill|TerminateProcess|\.Kill\(|-Force\b|ExecutionPolicy|Invoke-Expression/);
  assert.doesNotMatch(script, /Select-Object -First|Join-Path.*LOCALAPPDATA/);
});

test("PowerShell generation safely quotes an apostrophe in a Desktop path and refuses malformed process plans", () => {
  const root = LOCAL.replace("Fixture", "O'Neil");
  const selected = selectWindowsDesktop(snapshot([visible({ path: DESKTOP.replace("Fixture", "O'Neil") })], { localAppData: root }))!;
  assert.ok(windowsDesktopRestartScript(selected)!.includes(String.raw`C:\Users\O''Neil\AppData\Local`));
  for (const plan of [
    { exe: DESKTOP, processes: [] },
    { exe: DESKTOP, processes: [{ id: 0, startedAt: STARTED }] },
    { exe: DESKTOP, processes: [{ id: 1001, startedAt: "'; invalid" }] },
    { exe: "not an absolute path", processes: [{ id: 1001, startedAt: STARTED }] },
  ]) assert.equal(windowsDesktopRestartScript(plan as WindowsDesktopSelection), null);
});

// Execute the production orchestration with a fake child-process boundary. The tests never run
// PowerShell, close an application, discover the host's real processes, or launch an executable.
const compiled = ts.transpileModule(fs.readFileSync(new URL("../src/claude-desktop.ts", import.meta.url), "utf8"), {
  compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022, esModuleInterop: true },
}).outputText;

function runtime(value: unknown, restartOk = true) {
  const calls: { file: string; args: string[]; timeout: number }[] = [];
  const exports: Record<string, () => Promise<unknown>> = {};
  runInNewContext(compiled, {
    exports, process: { platform: "win32" }, setTimeout,
    require: (name: string) => {
      if (name === "node:path") return path;
      assert.equal(name, "node:child_process");
      return { execFile(file: string, args: string[], options: { timeout: number }, done: (error: Error | null, stdout: string) => void) {
        calls.push({ file, args, timeout: options.timeout });
        if (calls.length === 1) done(null, JSON.stringify(value));
        else done(restartOk ? null : new Error("synthetic user cancellation or deadline"), "");
      } };
    },
  });
  return { calls, reopen: exports.reopenClaude!, startedAt: exports.claudeStartedAt! };
}

test("ambiguous or absent Windows Desktop snapshots never issue a close or launch command", async () => {
  for (const value of [snapshot([]), snapshot([visible({ signatureStatus: "NotSigned" })]), snapshot([visible(), visible({ id: 1002, path: DESKTOP.replace("1.2.3", "1.2.4") })])]) {
    const r = runtime(value);
    assert.equal(await r.reopen(), false);
    assert.equal(r.calls.length, 1);
    assert.doesNotMatch(r.calls[0]!.args.join(" "), /CloseMainWindow|Start-Process|Stop-Process|taskkill/);
  }
});

test("a cancelled or timed-out graceful Windows close returns failure without forced retries or fallback launches", async () => {
  const r = runtime(snapshot([visible()]), false);
  assert.equal(await r.reopen(), false);
  assert.equal(r.calls.length, 2);
  assert.equal(r.calls[1]!.timeout, 40_000);
  for (const call of r.calls) assert.doesNotMatch(call.args.join(" "), /Stop-Process|taskkill|-Force\b|-ExecutionPolicy/);
});

test("successful Windows restart only runs the validated script; start-time discovery uses the same identity checks", async () => {
  const r = runtime(snapshot([visible()]));
  assert.equal(await r.reopen(), true);
  assert.equal(r.calls.length, 2);
  assert.equal(r.calls[1]!.args.at(-1), windowsDesktopRestartScript(selectWindowsDesktop(snapshot([visible()]))!));
  assert.equal(await runtime(snapshot([visible()])).startedAt(), Date.parse(STARTED));
  assert.equal(await runtime(snapshot([visible({ productName: "Claude Code" })])).startedAt(), undefined);
  assert.equal(await runtime(snapshot([])).startedAt(), null);
});
