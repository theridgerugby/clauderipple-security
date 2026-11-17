// Canonical Windows private-storage ACL boundary. The Electron copy is generated and parity-tested.
import path from "node:path";
import { spawnSync } from "node:child_process";

// Both the legacy migration and fresh async batch use this exact allowlist. A verify-only
// caller never reaches a SetAccessControl operation and cannot repair an exposed capability.
const ASSERT_PRIVATE_ACL = String.raw`
function Assert-PrivateAcl($candidate, [bool]$requireProtected) {
  if (($requireProtected -and -not $candidate.AreAccessRulesProtected) -or -not $candidate.GetOwner([System.Security.Principal.SecurityIdentifier]).Equals($sid)) { throw 'Private storage ACL is not private' }
  $selfAllowed = $false
  foreach ($rule in $candidate.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier])) {
    if ($rule.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { throw 'Unexpected private storage deny rule' }
    if (-not $rule.IdentityReference.Equals($sid) -and -not $rule.IdentityReference.Equals($system)) { throw 'Private storage grants another identity access' }
    if ($rule.IdentityReference.Equals($sid) -and ($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq [System.Security.AccessControl.FileSystemRights]::FullControl -and ($rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) -eq 0) { $selfAllowed = $true }
  }
  if (-not $selfAllowed) { throw 'Private storage owner has insufficient access' }
}
`;

// The program is fixed. Paths are JSON on stdin, never PowerShell source or command arguments.
// Use SID identities rather than localized account names. Refuse reparse points and foreign
// owners before replacing the DACL; inherited/explicit grants to other users are both removed.
export const WINDOWS_PRIVATE_ACL_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$item = Get-Item -LiteralPath ([string]$request.path) -Force -ErrorAction Stop
if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Reparse points are not private storage' }
if ([bool]$item.PSIsContainer -ne [bool]$request.directory) { throw 'Unexpected private storage type' }
$identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$sid = $identity.User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
$admins = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
$old = $item.GetAccessControl()
$owner = $old.GetOwner([System.Security.Principal.SecurityIdentifier])
$principal = [System.Security.Principal.WindowsPrincipal]::new($identity)
$adminOwned = $owner.Equals($admins) -and $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $owner.Equals($sid) -and -not $adminOwned) { throw 'Private storage belongs to another user' }
${ASSERT_PRIVATE_ACL}
if ($request.verifyOnly -eq $true) {
  # A newly created file can inherit a private parent DACL. Check every effective/inherited
  # grant without changing it; widening the parent later must cause the next check to fail.
  Assert-PrivateAcl $old $false
  [Console]::Out.Write('private-acl-verified')
  exit 0
}
if ($request.directory) {
  $acl = [System.Security.AccessControl.DirectorySecurity]::new()
  $inherit = [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
} else {
  $acl = [System.Security.AccessControl.FileSecurity]::new()
  $inherit = [System.Security.AccessControl.InheritanceFlags]::None
}
$acl.SetOwner($sid)
$acl.SetAccessRuleProtection($true, $false)
foreach ($account in @($sid, $system)) {
  $rule = [System.Security.AccessControl.FileSystemAccessRule]::new($account, [System.Security.AccessControl.FileSystemRights]::FullControl, $inherit, [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow)
  $acl.AddAccessRule($rule)
}
$item.SetAccessControl($acl)
$check = $item.GetAccessControl()
Assert-PrivateAcl $check $true
[Console]::Out.Write('private-acl-ok')
`;

/** One process verifies every file of a bounded fresh snapshot. Paths are data-only stdin. */
export const WINDOWS_PRIVATE_ACL_BATCH_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
$files = @($request.files)
if ($files.Count -lt 1 -or $files.Count -gt 16) { throw 'Invalid private storage batch' }
$sid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
$system = [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
${ASSERT_PRIVATE_ACL}
foreach ($file in $files) {
  $item = Get-Item -LiteralPath ([string]$file) -Force -ErrorAction Stop
  if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or $item.PSIsContainer) { throw 'Unexpected private storage type' }
  Assert-PrivateAcl ($item.GetAccessControl()) $false
}
[Console]::Out.Write('private-acl-batch-verified')
`;

export interface AsyncPrivateAclOptions { signal?: AbortSignal }
/** Inject the project's bounded runner; the generated Electron policy has no cross-root import. */
export type AsyncPrivateAclRunner = (executable: string, args: string[], options: {
  input: string; timeoutMs: number; maxBuffer: number; windowsHide: boolean; signal?: AbortSignal;
}) => Promise<string>;

export async function verifyWindowsPrivateFiles(
  files: readonly string[],
  run: AsyncPrivateAclRunner,
  options: AsyncPrivateAclOptions = {},
  systemRoot = process.env.SystemRoot,
): Promise<void> {
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) throw new Error("Windows system directory is unavailable for private storage");
  if (files.length < 1 || files.length > 16 || files.some(file => typeof file !== "string" || file.length === 0 || file.length > 32_768 || file.includes("\0"))) {
    throw new Error("Invalid private storage batch");
  }
  if (options.signal?.aborted) throw Object.assign(new Error("Private storage verification aborted"), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
  const executable = path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  let output: string;
  try {
    output = await run(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_BATCH_SCRIPT], {
      input: JSON.stringify({ files }), timeoutMs: 10_000, maxBuffer: 16 * 1024, windowsHide: true,
      ...(options.signal ? { signal: options.signal } : {}),
    });
  } catch (error) {
    if (options.signal?.aborted || (error as { name?: string }).name === "AbortError") {
      throw Object.assign(new Error("Private storage verification aborted"), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
    }
    if ((error as { timedOut?: boolean }).timedOut) {
      throw Object.assign(new Error("Private storage verification timed out"), { name: "TimeoutError", code: "PRIVATE_STORAGE_TIMEOUT" });
    }
    // Never include subprocess output or a supplied path in a diagnostic.
    throw new Error("Cannot verify owner-only Windows private storage permissions");
  }
  if (options.signal?.aborted) throw Object.assign(new Error("Private storage verification aborted"), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
  if (output !== "private-acl-batch-verified") throw new Error("Cannot verify owner-only Windows private storage permissions");
}

type AclRunner = (executable: string, args: string[], options: {
  input: string; encoding: "utf8"; timeout: number; maxBuffer: number; windowsHide: boolean;
}) => { status: number | null; stdout?: string | Buffer | null; error?: Error };

/** Exported for hermetic command-boundary tests; no credential bytes ever enter this process. */
export function applyWindowsPrivateAcl(
  file: string,
  directory: boolean,
  run: AclRunner = spawnSync,
  systemRoot = process.env.SystemRoot,
): void {
  windowsPrivateAcl(file, directory, false, run, systemRoot);
}

/** New trust anchors/capabilities have no migration case: previously exposed ACLs fail closed. */
export function verifyWindowsPrivateAcl(
  file: string,
  directory: boolean,
  run: AclRunner = spawnSync,
  systemRoot = process.env.SystemRoot,
): void {
  windowsPrivateAcl(file, directory, true, run, systemRoot);
}

function windowsPrivateAcl(file: string, directory: boolean, verifyOnly: boolean, run: AclRunner, systemRoot: string | undefined): void {
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) throw new Error("Windows system directory is unavailable for private storage");
  const executable = path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = run(executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_SCRIPT], {
    input: JSON.stringify({ path: file, directory, ...(verifyOnly ? { verifyOnly: true } : {}) }), encoding: "utf8", timeout: 10_000,
    maxBuffer: 16 * 1024, windowsHide: true,
  });
  // Do not surface subprocess output: it may reflect paths and cannot establish successful ACLs.
  if (result.error || result.status !== 0 || String(result.stdout) !== (verifyOnly ? "private-acl-verified" : "private-acl-ok")) {
    throw new Error(verifyOnly ? "Cannot verify owner-only Windows private storage permissions" : "Cannot enforce owner-only Windows private storage permissions");
  }
}
