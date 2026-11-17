import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const installer = path.resolve(import.meta.dirname, "../../../scripts/install.ps1");

function powershell(source: string, env: NodeJS.ProcessEnv) {
  // Keep the launcher constant and pass fixture code on stdin. No execution-policy override or
  // machine configuration is needed to run this isolated in-memory test harness.
  return spawnSync("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", "$ErrorActionPreference='Stop'; & ([scriptblock]::Create([Console]::In.ReadToEnd()))"], {
    input: source, env, encoding: "utf8", timeout: 30_000,
  });
}

// These tests execute only selected installer functions against temporary fixtures. Every
// downloader is replaced with a local stub; no npm install, certificate or user PATH is touched.
const runtimeHarness = String.raw`
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$Prefix = Join-Path $env:FIXTURE_ROOT 'prefix'
$Runtime = Join-Path $Prefix 'runtime'
$NodeMajor = 24
$NodeFallback = 'v24.0.0'
$NodeBackup = $null
$NodeStaging = $null
New-Item -ItemType Directory -Path $Runtime -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $Runtime 'identity'), 'old')
$tokens = $null
$errors = $null
$tree = [Management.Automation.Language.Parser]::ParseFile($env:INSTALLER_SOURCE, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
foreach ($name in @('Install-Node', 'Restore-NodeRuntime')) {
  $definition = $tree.Find({ param($ast) $ast -is [Management.Automation.Language.FunctionDefinitionAst] -and $ast.Name -eq $name }, $true)
  if (-not $definition) { throw "missing installer function: $name" }
  Set-Item -LiteralPath "Function:\$name" -Value $definition.Body.GetScriptBlock()
}
function Get-NodeMajor([string]$exe) { if ($env:FAIL_POINT -eq 'bad-node') { return 0 }; return 24 }
function Invoke-RestMethod { return [pscustomobject]@{version='v24.0.0'} }
function Invoke-WebRequest {
  param($Uri, $OutFile, [switch]$UseBasicParsing)
  if ($OutFile) { [IO.File]::WriteAllText($OutFile, 'inert archive'); return }
  return [pscustomobject]@{Content=(('a' * 64) + '  node-v24.0.0-win-x64.zip')}
}
function Get-FileHash { return [pscustomobject]@{Hash=('a' * 64)} }
function Expand-Archive {
  param($Path, $DestinationPath, [switch]$Force)
  if ($env:FAIL_POINT -eq 'extract') { throw 'simulated extraction failure' }
  $unpacked = Join-Path $DestinationPath 'node-v24.0.0-win-x64'
  New-Item -ItemType Directory -Path $unpacked -Force | Out-Null
  [IO.File]::WriteAllText((Join-Path $unpacked 'node.exe'), 'inert node fixture')
  [IO.File]::WriteAllText((Join-Path $unpacked 'identity'), 'new')
}
function Move-Item {
  param($LiteralPath, $Destination)
  if ($env:FAIL_POINT -eq 'second-rename' -and $LiteralPath -like '*.new.*' -and $Destination -eq $Runtime) { throw 'simulated second rename failure' }
  Microsoft.PowerShell.Management\Move-Item -LiteralPath $LiteralPath -Destination $Destination
  if ($env:FAIL_POINT -eq 'first-rename' -and $Destination -like '*.old.*') { throw 'simulated first rename failure' }
}
$env:PROCESSOR_ARCHITECTURE = 'AMD64'
$failed = $false
try {
  Install-Node
  if ($env:FAIL_POINT -eq 'npm') { throw 'simulated later npm failure' }
  if ($env:FAIL_POINT -eq 'none') {
    $committed = $NodeBackup
    $NodeBackup = $null
    if ($committed) { Remove-Item -LiteralPath $committed -Recurse -Force }
  }
} catch { $failed = $true }
finally { Restore-NodeRuntime }
if ($env:FAIL_POINT -eq 'none' -and $failed) { throw 'successful fixture unexpectedly failed' }
if ($env:FAIL_POINT -ne 'none' -and -not $failed) { throw 'fixture failed to exercise the failure branch' }
$expected = if ($env:FAIL_POINT -eq 'none') { 'new' } else { 'old' }
if ([IO.File]::ReadAllText((Join-Path $Runtime 'identity')) -ne $expected) { throw 'runtime recovery kept the wrong version' }
if (@(Get-ChildItem -LiteralPath $Prefix -Directory | Where-Object { $_.Name -like 'runtime.*' }).Count) { throw 'runtime staging or backup was leaked' }
Write-Host 'fixture passed'
`;

test("Windows installer restores old runtime on extraction, validation, rename and npm failures", { skip: process.platform !== "win32" }, t => {
  for (const point of ["extract", "bad-node", "first-rename", "second-rename", "npm", "none"]) {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-win-install-"));
    t.after(() => fs.rmSync(root, { recursive: true, force: true }));
    const result = powershell(runtimeHarness, { ...process.env, FIXTURE_ROOT: root, INSTALLER_SOURCE: installer, FAIL_POINT: point });
    assert.equal(result.status, 0, `${point}: ${result.stdout}\n${result.stderr}`);
    assert.match(result.stdout, /fixture passed/);
  }
});

test("Windows cmd shim preserves percent and exclamation characters even with delayed expansion enabled", { skip: process.platform !== "win32" }, t => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-win-shim-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const prefix = path.join(root, "prefix %SHIM_INJECTION% !SHIM_INJECTION!");
  const runtime = path.join(prefix, "runtime");
  fs.mkdirSync(runtime, { recursive: true });
  const executable = path.join(runtime, "node.exe");
  fs.copyFileSync(process.execPath, executable);
  const entry = path.join(prefix, "node_modules/clauderipple/bin/clauderipple.js");
  fs.mkdirSync(path.dirname(entry), { recursive: true });
  fs.writeFileSync(entry, 'require("node:fs").writeFileSync(process.env.FIXTURE_RESULT, "literal paths passed");');
  const source = fs.readFileSync(installer, "utf8");
  const start = source.indexOf("if ($node.StartsWith");
  const end = source.indexOf("# After npm and the shim succeed", start);
  assert.ok(start > 0 && end > start);
  const script = `$ErrorActionPreference = 'Stop'\n$Prefix = $env:FIXTURE_PREFIX\n$Runtime = Join-Path $Prefix 'runtime'\n$node = Join-Path $Runtime 'node.exe'\n$cmd = Join-Path $Prefix 'clauderipple.cmd'\n${source.slice(start, end)}`;
  const env = { ...process.env, FIXTURE_PREFIX: prefix, FIXTURE_RESULT: path.join(root, "result"), SHIM_INJECTION: "unexpected-expansion" };
  const generated = powershell(script, env);
  assert.equal(generated.status, 0, generated.stdout + generated.stderr);
  // Enter the path as a literal PowerShell string, then let cmd read the wrapper with /V:ON.
  // The wrapper's own setlocal must prevent delayed expansion while reading its runtime paths.
  const invoked = powershell('$ErrorActionPreference = "Stop"\nPush-Location -LiteralPath $env:FIXTURE_PREFIX\ntry { & cmd.exe /D /V:ON /C clauderipple.cmd; exit $LASTEXITCODE } finally { Pop-Location }\n', env);
  assert.equal(invoked.status, 0, invoked.stdout + invoked.stderr);
  assert.equal(fs.readFileSync(env.FIXTURE_RESULT, "utf8"), "literal paths passed");
});
