import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import childProcess from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import {
  applyWindowsPrivateAcl, ensurePrivateDirectory, readPrivateFile, WINDOWS_PRIVATE_ACL_SCRIPT,
} from "../src/private-file.ts";
import { withFileLock, writeJsonAtomic, writePrivateFileAtomic } from "../src/locked-file.ts";
import { readClaudeAuthFile, saveClaudeAuthFile } from "../src/providers/anthropic-token-file.ts";
import { ObservedClaudeCodeAuth } from "../src/providers/anthropic-observed.ts";
import { ConfigStore } from "../src/config.ts";
import { ensureAdminToken } from "../src/admin-auth.ts";

function fixture(t: TestContext): string {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-private-test-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return home;
}

test("private storage writes complete owner-only data and leaves no temporary files", t => {
  const home = fixture(t);
  const file = path.join(home, "credential.json");
  writeJsonAtomic(file, { token: "dummy-old" });
  writeJsonAtomic(file, { token: "dummy-new" });
  assert.deepEqual(JSON.parse(readPrivateFile(file).toString("utf8")), { token: "dummy-new" });
  assert.deepEqual(fs.readdirSync(home), ["credential.json"]);
  if (process.platform !== "win32") {
    assert.equal(fs.statSync(home).mode & 0o777, 0o700);
    assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  }
});

test("private reads tighten owner-created legacy files before reading", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "credential");
  fs.writeFileSync(file, "dummy-credential", { mode: 0o644 });
  fs.chmodSync(file, 0o644);
  assert.equal(readPrivateFile(file).toString(), "dummy-credential");
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test("generic locks and JSON writes preserve an existing workspace's directory permissions", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "settings.json");
  fs.chmodSync(home, 0o755);
  withFileLock(file, () => writeJsonAtomic(file, { local: true }));
  assert.equal(fs.statSync(home).mode & 0o777, 0o755);
  assert.equal(fs.statSync(file).mode & 0o777, 0o600);
  assert.deepEqual(JSON.parse(readPrivateFile(file).toString()), { local: true });
});

test("a failed permission repair never reads the credential bytes", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "credential");
  fs.writeFileSync(file, "dummy-credential");
  fs.chmodSync(file, 0o644);
  let reads = 0;
  t.mock.method(fs, "fchmodSync", () => { throw Object.assign(new Error("denied"), { code: "EACCES" }); });
  t.mock.method(fs, "readSync", () => { reads++; throw new Error("must never read"); });
  assert.throws(() => readPrivateFile(file), { code: "EACCES" });
  assert.equal(reads, 0);
});

test("linked and hard-linked secrets cannot be read or replaced", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), original = path.join(home, "original"), alias = path.join(home, "alias");
  fs.writeFileSync(original, "dummy-original", { mode: 0o600 });
  fs.symlinkSync(original, alias);
  assert.throws(() => readPrivateFile(alias), /regular/);
  assert.throws(() => writePrivateFileAtomic(alias, "dummy-replacement"), /regular/);
  fs.unlinkSync(alias);
  fs.linkSync(original, alias);
  assert.throws(() => readPrivateFile(original), /regular/);
  assert.throws(() => writePrivateFileAtomic(original, "dummy-replacement"), /regular/);
  assert.equal(fs.readFileSync(original, "utf8"), "dummy-original");
});

test("private directory symlinks or junctions are refused without changing their targets", t => {
  const home = fixture(t), original = path.join(home, "original"), alias = path.join(home, "alias");
  fs.mkdirSync(original, { mode: 0o755 });
  fs.symlinkSync(original, alias, process.platform === "win32" ? "junction" : "dir");
  assert.throws(() => ensurePrivateDirectory(alias), /real directory/);
  assert.deepEqual(fs.readdirSync(original), []);
});

test("private read rejects ownership and identity changes before consuming data", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "credential");
  fs.writeFileSync(file, "dummy-credential", { mode: 0o600 });
  const original = fs.lstatSync;
  t.mock.method(fs, "lstatSync", (target: fs.PathLike) => {
    const stat = original(target);
    stat.uid = (process.getuid!() + 1) % 65536;
    return stat;
  });
  assert.throws(() => readPrivateFile(file), /current user/);
  assert.throws(() => writePrivateFileAtomic(file, "dummy-replacement"), /current user/);
  assert.equal(fs.readFileSync(file, "utf8"), "dummy-credential");
});

test("a file swapped between lstat and open is rejected", t => {
  const home = fixture(t), file = path.join(home, "credential"), replacement = path.join(home, "replacement");
  fs.writeFileSync(file, "dummy-first", { mode: 0o600 });
  fs.writeFileSync(replacement, "dummy-second", { mode: 0o600 });
  const open = fs.openSync;
  let swapped = false;
  t.mock.method(fs, "openSync", (...args: Parameters<typeof fs.openSync>) => {
    if (args[0] === file && !swapped) { swapped = true; fs.renameSync(replacement, file); }
    return open(...args);
  });
  assert.throws(() => readPrivateFile(file), /changed while opening/);
});

test("private reads have explicit size/type bounds", t => {
  const home = fixture(t), file = path.join(home, "credential");
  fs.writeFileSync(file, "x".repeat(129), { mode: 0o600 });
  assert.throws(() => readPrivateFile(file, 128), /size bound/);
  assert.throws(() => readPrivateFile(file, -1), /size bound/);
  assert.throws(() => readPrivateFile(home), /regular/);
  writePrivateFileAtomic(file, "");
  assert.equal(readPrivateFile(file, 0).length, 0);
});

test("Windows ACL invocation keeps arbitrary paths out of executable source and argv", () => {
  const file = "C:\\private space\\'; $(Write-Output injected); %TEMP%!x\\凭据.json";
  let called = false;
  applyWindowsPrivateAcl(file, false, (executable, args, options) => {
    called = true;
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_SCRIPT]);
    assert.ok(args.every(argument => !argument.includes(file)));
    assert.deepEqual(JSON.parse(options.input), { path: file, directory: false });
    assert.equal(options.windowsHide, true);
    assert.ok(options.timeout <= 10_000);
    return { status: 0, stdout: "private-acl-ok" };
  }, "C:\\Windows");
  assert.equal(called, true);
  for (const result of [{ status: 1, stdout: "private-acl-ok" }, { status: 0, stdout: "not-applied" }, { status: null, error: new Error("dummy-sensitive-output") }]) {
    assert.throws(() => applyWindowsPrivateAcl(file, false, () => result, "C:\\Windows"), error =>
      error instanceof Error && /Cannot enforce/.test(error.message) && !error.message.includes("dummy-sensitive-output"));
  }
  assert.throws(() => applyWindowsPrivateAcl(file, false, () => { throw new Error("must not run"); }, "relative"), /system directory/);
});

test("Windows atomic replacement checks the existing file's ACL ownership before writing", t => {
  const home = fixture(t), file = path.join(home, "credential");
  fs.writeFileSync(file, "dummy-original", { mode: 0o600 });
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const systemRoot = process.env.SystemRoot;
  const checked: string[] = [];
  const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
    const request = JSON.parse(options.input);
    checked.push(request.path);
    return request.directory ? { status: 0, stdout: "private-acl-ok" } : { status: 1, stdout: "" };
  });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    assert.throws(() => writePrivateFileAtomic(file, "dummy-replacement"), /Cannot enforce/);
    assert.ok(checked.includes(file));
    assert.equal(fs.readFileSync(file, "utf8"), "dummy-original");
    assert.deepEqual(fs.readdirSync(home), ["credential"]);
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
    mocked.mock.restore();
    syncBuiltinESMExports();
  }
});

test("Windows generic JSON writes apply a private ACL before writing any secret bytes", t => {
  const home = fixture(t), file = path.join(home, "settings.json");
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const systemRoot = process.env.SystemRoot;
  let checkedEmptyTemp = false;
  const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
    const request = JSON.parse(options.input);
    assert.equal(request.directory, false, "existing user directory ACLs are preserved");
    assert.equal(fs.statSync(request.path).size, 0, "temporary file must still be empty");
    checkedEmptyTemp = true;
    return { status: 1, stdout: "" };
  });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    assert.throws(() => writeJsonAtomic(file, { apiKey: "dummy-secret" }), /Cannot enforce/);
    assert.equal(checkedEmptyTemp, true);
    assert.deepEqual(fs.readdirSync(home), []);
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
    mocked.mock.restore();
    syncBuiltinESMExports();
  }
});

for (const mutation of ["replace", "hard-link"] as const) {
  test(`Windows atomic writes reject a temporary-file ${mutation} during the ACL operation before writing bytes`, t => {
    const home = fixture(t), file = path.join(home, "credential"), moved = path.join(home, "unprotected-original");
    fs.writeFileSync(file, "dummy-original", { mode: 0o600 });
    const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
    const systemRoot = process.env.SystemRoot;
    let changed = false;
    const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
      const request = JSON.parse(options.input);
      if (!request.directory && request.path.startsWith(`${file}.tmp-`)) {
        assert.equal(fs.statSync(request.path).size, 0);
        if (mutation === "replace") {
          fs.renameSync(request.path, moved);
          fs.writeFileSync(request.path, "", { mode: 0o600 });
        } else {
          fs.linkSync(request.path, moved);
        }
        changed = true;
      }
      return { status: 0, stdout: "private-acl-ok" };
    });
    syncBuiltinESMExports();
    try {
      Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
      process.env.SystemRoot = "C:\\Windows";
      assert.throws(() => writePrivateFileAtomic(file, "dummy-secret", false), /changed|regular, unlinked/);
      assert.equal(changed, true);
      assert.equal(fs.statSync(moved).size, 0, "the unchecked or newly aliased descriptor must receive no secret bytes");
      assert.equal(fs.readFileSync(file, "utf8"), "dummy-original", "the previous destination remains intact");
      assert.deepEqual(fs.readdirSync(home).sort(), ["credential", "unprotected-original"]);
    } finally {
      Object.defineProperty(process, "platform", descriptor);
      if (systemRoot === undefined) delete process.env.SystemRoot;
      else process.env.SystemRoot = systemRoot;
      mocked.mock.restore();
      syncBuiltinESMExports();
    }
  });
}

test("atomic writes refuse a foreign-owned temporary descriptor before writing bytes", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "credential");
  const fstat = fs.fstatSync;
  const write = fs.writeFileSync;
  let writes = 0;
  t.mock.method(fs, "fstatSync", (fd: number) => {
    const stat = fstat(fd);
    stat.uid = (process.getuid!() + 1) % 65536;
    return stat;
  });
  t.mock.method(fs, "writeFileSync", (...args: Parameters<typeof fs.writeFileSync>) => { writes++; return write(...args); });
  assert.throws(() => writePrivateFileAtomic(file, "dummy-secret"), /current user/);
  assert.equal(writes, 0);
  assert.deepEqual(fs.readdirSync(home), []);
});

test("atomic writes recheck the temporary pathname after closing its descriptor and before publication", t => {
  const home = fixture(t), file = path.join(home, "credential"), moved = path.join(home, "protected-original");
  fs.writeFileSync(file, "dummy-original", { mode: 0o600 });
  const open = fs.openSync, close = fs.closeSync;
  let tempFd: number | undefined, tempPath: string | undefined;
  let changed = false;
  t.mock.method(fs, "openSync", (...args: Parameters<typeof fs.openSync>) => {
    const fd = open(...args);
    if (typeof args[0] === "string" && args[0].startsWith(`${file}.tmp-`)) { tempFd = fd; tempPath = args[0]; }
    return fd;
  });
  t.mock.method(fs, "closeSync", (fd: number) => {
    close(fd);
    if (fd === tempFd && tempPath && !changed) {
      changed = true;
      fs.renameSync(tempPath, moved);
      fs.writeFileSync(tempPath, "", { mode: 0o600 });
    }
  });
  assert.throws(() => writePrivateFileAtomic(file, "dummy-secret"), /changed while writing/);
  assert.equal(changed, true);
  assert.equal(fs.readFileSync(moved, "utf8"), "dummy-secret", "only the originally protected file was written");
  assert.equal(fs.readFileSync(file, "utf8"), "dummy-original", "an unrelated replacement must not be published");
  assert.deepEqual(fs.readdirSync(home).sort(), ["credential", "protected-original"]);
});

test("Windows rename retries retain the original temporary-file identity", t => {
  const home = fixture(t), file = path.join(home, "credential"), moved = path.join(home, "protected-original");
  fs.writeFileSync(file, "dummy-original", { mode: 0o600 });
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const systemRoot = process.env.SystemRoot;
  const spawn = t.mock.method(childProcess, "spawnSync", () => ({ status: 0, stdout: "private-acl-ok" }));
  const rename = fs.renameSync;
  let publishAttempts = 0;
  const mockedRename = t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
    if (typeof from === "string" && from.startsWith(`${file}.tmp-`) && to === file) {
      publishAttempts++;
      rename(from, moved);
      fs.writeFileSync(from, "", { mode: 0o600 });
      throw Object.assign(new Error("temporary Windows sharing conflict"), { code: "EPERM" });
    }
    return rename(from, to);
  });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    assert.throws(() => writePrivateFileAtomic(file, "dummy-secret", false), /changed while writing/);
    assert.equal(publishAttempts, 1, "the next retry must refuse the exchanged path before calling rename");
    assert.equal(fs.readFileSync(moved, "utf8"), "dummy-secret");
    assert.equal(fs.readFileSync(file, "utf8"), "dummy-original");
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    if (systemRoot === undefined) delete process.env.SystemRoot;
    else process.env.SystemRoot = systemRoot;
    mockedRename.mock.restore();
    spawn.mock.restore();
    syncBuiltinESMExports();
  }
});

for (const kind of ["private bytes", "admin capability"] as const) {
  test(`Windows ${kind} creation checks the empty file ACL even inside a private directory`, t => {
    const home = fixture(t);
    const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
    const systemRoot = process.env.SystemRoot;
    let checkedEmptyTemp = false;
    const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
      const request = JSON.parse(options.input);
      if (request.directory) return { status: 0, stdout: "private-acl-ok" };
      assert.match(request.path, /\.tmp-\d+-[0-9a-f]+$/);
      assert.equal(fs.statSync(request.path).size, 0, "refuse before any capability or secret is written");
      checkedEmptyTemp = true;
      return { status: 1, stdout: "" };
    });
    syncBuiltinESMExports();
    try {
      Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
      process.env.SystemRoot = "C:\\Windows";
      assert.throws(() => kind === "admin capability"
        ? ensureAdminToken(home)
        : writePrivateFileAtomic(path.join(home, "credential"), "dummy-secret"), /Cannot enforce/);
      assert.equal(checkedEmptyTemp, true);
      assert.deepEqual(fs.readdirSync(home), [], "no empty token or abandoned temporary file remains");
    } finally {
      Object.defineProperty(process, "platform", descriptor);
      if (systemRoot === undefined) delete process.env.SystemRoot;
      else process.env.SystemRoot = systemRoot;
      mocked.mock.restore();
      syncBuiltinESMExports();
    }
  });
}

test("native Windows private DACL contains only the current user and SYSTEM", { skip: process.platform !== "win32" }, t => {
  const home = fixture(t), file = path.join(home, "credential");
  writePrivateFileAtomic(file, "dummy-credential");
  const script = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$item = Get-Item -LiteralPath ([Console]::In.ReadToEnd() | ConvertFrom-Json).path -Force
$acl = $item.GetAccessControl()
@{ protected = $acl.AreAccessRulesProtected; owner = $acl.GetOwner([System.Security.Principal.SecurityIdentifier]).Value; current = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value; identities = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) } | ConvertTo-Json -Compress
`;
  const result = spawnSync(path.win32.join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], { input: JSON.stringify({ path: file }), encoding: "utf8", timeout: 10_000, windowsHide: true });
  assert.equal(result.status, 0, result.stderr);
  const acl = JSON.parse(result.stdout);
  assert.equal(acl.protected, true);
  assert.equal(acl.owner, acl.current);
  assert.ok(acl.identities.includes(acl.current));
  assert.ok(acl.identities.every((identity: string) => identity === acl.current || identity === "S-1-5-18"));
});

test("native Windows storage rechecks cached file and directory permissions after a DACL change", { skip: process.platform !== "win32" }, t => {
  const home = fixture(t), file = path.join(home, "credential");
  writePrivateFileAtomic(file, "dummy-credential");
  readPrivateFile(file);
  ensurePrivateDirectory(home);
  const executable = path.win32.join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const widen = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$item = Get-Item -LiteralPath ([Console]::In.ReadToEnd() | ConvertFrom-Json).path -Force
$acl = $item.GetAccessControl()
$everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
$acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($everyone, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow))
$item.SetAccessControl($acl)
`;
  const check = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$item = Get-Item -LiteralPath ([Console]::In.ReadToEnd() | ConvertFrom-Json).path -Force
@($item.GetAccessControl().GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object { $_.IdentityReference.Value }) | ConvertTo-Json -Compress
`;
  for (const target of [file, home]) {
    const run = (script: string) => spawnSync(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
      input: JSON.stringify({ path: target }), encoding: "utf8", timeout: 10_000, windowsHide: true,
    });
    const changed = run(widen);
    assert.equal(changed.status, 0, changed.stderr);
    if (target === file) assert.equal(readPrivateFile(file).toString(), "dummy-credential");
    else ensurePrivateDirectory(home);
    const actual = run(check);
    assert.equal(actual.status, 0, actual.stderr);
    assert.ok(!JSON.parse(actual.stdout).includes("S-1-1-0"), "cached permissions must not retain Everyone access");
  }
});

test("owned login storage refuses aliasing without modifying the unrelated target", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), external = path.join(home, "unrelated"), target = path.join(home, "claude-auth.json");
  fs.writeFileSync(external, "unchanged", { mode: 0o600 });
  fs.symlinkSync(external, target);
  assert.equal(readClaudeAuthFile(home), null);
  assert.throws(() => saveClaudeAuthFile(home, "dummy-token"), /regular/);
  assert.equal(fs.readFileSync(external, "utf8"), "unchanged");
});

test("observed login persistence ignores the predictable legacy temp-file trap", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "observed.json"), target = path.join(home, "unrelated");
  fs.writeFileSync(target, "unchanged", { mode: 0o600 });
  fs.symlinkSync(target, `${file}.tmp-${process.pid}`);
  const auth = new ObservedClaudeCodeAuth(file);
  auth.observe(["authorization", "Bearer dummy-token"], 123);
  assert.equal(fs.readFileSync(target, "utf8"), "unchanged");
  assert.equal(new ObservedClaudeCodeAuth(file).getFresh(124)?.authorization, "Bearer dummy-token");
});

test("config diagnostics do not contain JSON parser excerpts or follow symlinks", { skip: process.platform === "win32" }, t => {
  const home = fixture(t), file = path.join(home, "config.json"), external = path.join(home, "external");
  const messages: string[] = [];
  fs.writeFileSync(file, '{"apiKey":"dummy-do-not-log" oops}', { mode: 0o600 });
  new ConfigStore(file, (_config, errors) => messages.push(...errors));
  assert.ok(messages.length > 0);
  assert.ok(messages.every(message => !message.includes("dummy-do-not-log")));
  fs.unlinkSync(file);
  fs.writeFileSync(external, '{"listen":{"port":4567}}', { mode: 0o600 });
  fs.symlinkSync(external, file);
  const store = new ConfigStore(file);
  assert.notEqual(store.get().listen.port, 4567);
});
