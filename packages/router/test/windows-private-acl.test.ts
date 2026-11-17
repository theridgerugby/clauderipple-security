import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import childProcess, { spawnSync } from "node:child_process";
import { syncBuiltinESMExports } from "node:module";
import { applyWindowsPrivateAcl, verifyWindowsPrivateAcl, WINDOWS_PRIVATE_ACL_SCRIPT } from "../src/windows-private-acl.ts";
import { ensurePrivateDirectory, readPrivateFileStrict } from "../src/private-file.ts";
import { ensureAdminTlsIdentity, readAdminTlsIdentity, readAdminEndpoint, writeAdminEndpoint } from "../src/admin-transport-state.ts";
import { ensureAdminToken, readAdminToken } from "../src/admin-auth.ts";

test("Windows verify-only ACL checks use fixed code, data-only paths, and a distinct acknowledgement", () => {
  const file = "C:\\private\\quote'; $(not-code)\\identity.json";
  verifyWindowsPrivateAcl(file, false, (executable, args, options) => {
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_SCRIPT]);
    assert.deepEqual(JSON.parse(options.input), { path: file, directory: false, verifyOnly: true });
    assert.ok(args.every(argument => !argument.includes(file)));
    return { status: 0, stdout: "private-acl-verified" };
  }, "C:\\Windows");
  for (const result of [{ status: 0, stdout: "private-acl-ok" }, { status: 1, stdout: "private-acl-verified" }, { status: 0, stdout: "private-acl-verified\n" }]) {
    assert.throws(() => verifyWindowsPrivateAcl(file, false, () => result, "C:\\Windows"), /Cannot verify/);
  }
  const branch = WINDOWS_PRIVATE_ACL_SCRIPT.indexOf("if ($request.verifyOnly -eq $true)");
  const exit = WINDOWS_PRIVATE_ACL_SCRIPT.indexOf("exit 0", branch);
  const mutation = WINDOWS_PRIVATE_ACL_SCRIPT.indexOf("$item.SetAccessControl");
  assert.ok(branch >= 0 && exit > branch && mutation > exit);
  assert.match(WINDOWS_PRIVATE_ACL_SCRIPT, /GetAccessRules\(\$true, \$true/);
  assert.match(WINDOWS_PRIVATE_ACL_SCRIPT, /PropagationFlags\]::InheritOnly/);
});

test("admin trust-state readers refuse failed Windows verification before consuming credential bytes", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-acl-read-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  ensureAdminTlsIdentity(home);
  ensureAdminToken(home);
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const previousRoot = process.env.SystemRoot;
  let checks = 0, reads = 0;
  const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
    assert.equal(JSON.parse(options.input).verifyOnly, true);
    checks++;
    return { status: 1, stdout: "" };
  });
  const read = t.mock.method(fs, "readSync", () => { reads++; throw new Error("private bytes must not be read"); });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    assert.throws(() => readAdminTlsIdentity(home), /Cannot verify/);
    assert.throws(() => readAdminToken(home), /Cannot verify/);
    assert.equal(checks, 2);
    assert.equal(reads, 0);
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    if (previousRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = previousRoot;
    mocked.mock.restore(); read.mock.restore(); syncBuiltinESMExports();
  }
});

test("every Windows transport-state read verifies once and never invokes legacy ACL repair", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-acl-once-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const identity = ensureAdminTlsIdentity(home), token = ensureAdminToken(home);
  const endpoint = { version: 1 as const, instanceId: "a".repeat(32), publicPort: 8792, tlsPort: 12345 };
  writeAdminEndpoint(home, endpoint);
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const previousRoot = process.env.SystemRoot;
  const checked: string[] = [];
  const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
    const request = JSON.parse(options.input);
    assert.equal(request.verifyOnly, true, "new trust-state reads must never reapply ACLs after verifying them");
    checked.push(path.basename(request.path));
    return { status: 0, stdout: "private-acl-verified" };
  });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    for (let repeat = 0; repeat < 2; repeat++) {
      assert.equal(readAdminToken(home), token);
      assert.deepEqual(readAdminTlsIdentity(home), identity);
      assert.deepEqual(readAdminEndpoint(home), endpoint);
    }
    assert.deepEqual(checked, ["admin-tls-token", "admin-tls-identity.json", "admin-tls-endpoint.json",
      "admin-tls-token", "admin-tls-identity.json", "admin-tls-endpoint.json"]);
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    if (previousRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = previousRoot;
    mocked.mock.restore(); syncBuiltinESMExports();
  }
});

test("Windows strict reader rejects an exposed replacement after ACL verification without reading or repairing it", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-admin-acl-swap-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const token = ensureAdminToken(home), file = path.join(home, "admin-tls-token"), moved = path.join(home, "checked-original");
  const descriptor = Object.getOwnPropertyDescriptor(process, "platform")!;
  const previousRoot = process.env.SystemRoot;
  let checks = 0, reads = 0;
  const mocked = t.mock.method(childProcess, "spawnSync", (_executable: unknown, _args: unknown, options: { input: string }) => {
    assert.deepEqual(JSON.parse(options.input), { path: file, directory: false, verifyOnly: true });
    checks++;
    fs.renameSync(file, moved);
    fs.writeFileSync(file, token, { mode: 0o644 });
    return { status: 0, stdout: "private-acl-verified" };
  });
  const read = t.mock.method(fs, "readSync", () => { reads++; throw new Error("no exchanged bytes may be read"); });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...descriptor, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    assert.throws(() => readAdminToken(home), /changed while reading or verifying/);
    assert.equal(checks, 1, "there is no legacy apply or second permission check on the replacement");
    assert.equal(reads, 0);
  } finally {
    Object.defineProperty(process, "platform", descriptor);
    if (previousRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = previousRoot;
    mocked.mock.restore(); read.mock.restore(); syncBuiltinESMExports();
  }
  if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o644);
});

test("native Windows verify-only accepts private inheritance and refuses exposed ACLs without repairing them", { skip: process.platform !== "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-verify-acl-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  ensurePrivateDirectory(home);
  const file = path.join(home, "new-trust-state");
  // Exercise genuinely inherited grants. Elevated accounts may create Administrators-owned
  // files, so set only the fixture owner before verifying; keep its inherited DACL intact.
  fs.writeFileSync(file, "dummy-secret", { flag: "wx", mode: 0o600 });
  const executable = path.win32.join(process.env.SystemRoot!, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const script = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$item = Get-Item -LiteralPath ([string]$request.path) -Force
if ($request.initialize) {
  $acl = $item.GetAccessControl()
  $acl.SetOwner([System.Security.Principal.WindowsIdentity]::GetCurrent().User)
  $item.SetAccessControl($acl)
  if ($item.GetAccessControl().AreAccessRulesProtected) { throw 'Fixture must retain inheritance' }
}
if ($request.widen) {
  $acl = $item.GetAccessControl()
  $everyone = [System.Security.Principal.SecurityIdentifier]::new('S-1-1-0')
  $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new($everyone, [System.Security.AccessControl.FileSystemRights]::Read, [System.Security.AccessControl.AccessControlType]::Allow))
  $item.SetAccessControl($acl)
}
[Console]::Out.Write($item.GetAccessControl().GetSecurityDescriptorSddlForm([System.Security.AccessControl.AccessControlSections]'Access, Owner, Group'))
`;
  const invoke = (widen: boolean, initialize = false) => {
    const result = spawnSync(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", script], {
      input: JSON.stringify({ path: file, widen, initialize }), encoding: "utf8", timeout: 10_000, windowsHide: true,
    });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout;
  };
  invoke(false, true);
  verifyWindowsPrivateAcl(file, false);
  assert.equal(readPrivateFileStrict(file).toString(), "dummy-secret");
  const exposed = invoke(true);
  assert.throws(() => verifyWindowsPrivateAcl(file, false), /Cannot verify/);
  assert.throws(() => readPrivateFileStrict(file), /Cannot verify/);
  assert.equal(invoke(false), exposed, "verification must never repair a potentially exposed trust anchor");
  applyWindowsPrivateAcl(file, false);
  verifyWindowsPrivateAcl(file, false);
});
