// Requesting an orderly quit and reopen so Claude Desktop picks up a changed connection. The
// caller asks first; cancellation or a still-running app never triggers forced termination.

import { execFile } from "node:child_process";
import path from "node:path";

const MAC_BUNDLE_ID = "com.anthropic.claudefordesktop";
const QUIT_WAIT_MS = 20_000;

function run(file: string, args: string[], timeoutMs = 30_000): Promise<{ ok: boolean; stdout: string }> {
  return new Promise((resolve) => {
    execFile(file, args, { timeout: timeoutMs, windowsHide: true }, (err, stdout) => resolve({ ok: !err, stdout: String(stdout) }));
  });
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

/** True once Claude Desktop is running again. */
export async function reopenClaude(): Promise<boolean> {
  if (process.platform === "darwin") return reopenMac();
  if (process.platform === "win32") return reopenWindows();
  return false;
}

async function macRunning(): Promise<boolean> {
  // `is running` asks without launching the app.
  const r = await run("osascript", ["-e", `application id "${MAC_BUNDLE_ID}" is running`], 10_000);
  return r.ok && r.stdout.trim() === "true";
}

/**
 * When the running Claude Desktop started (epoch ms), `null` when it is not running, `undefined`
 * when that cannot be told here. Reopening it by hand applies a changed connection just as the
 * window's button does, and this is how the window notices.
 */
export async function claudeStartedAt(): Promise<number | null | undefined> {
  if (process.platform === "darwin") {
    // `lstart` is the local start time ("Tue Oct 20 22:13:48 2026"), which Date.parse reads as local.
    const r = await run("ps", ["-axo", "lstart=,comm="], 10_000);
    if (!r.ok) return undefined;
    const line = r.stdout.split("\n").find((l) => l.trimEnd().endsWith(".app/Contents/MacOS/Claude"));
    if (!line) return null;
    const at = Date.parse(line.trim().split(/\s+/).slice(0, 5).join(" "));
    return Number.isFinite(at) ? at : undefined;
  }
  if (process.platform === "win32") {
    const selected = await windowsDesktop();
    if (selected === null || selected === undefined) return selected;
    return Math.min(...selected.processes.map(p => Date.parse(p.startedAt)));
  }
  return undefined;
}

async function reopenMac(): Promise<boolean> {
  if (await macRunning()) {
    await run("osascript", ["-e", `tell application id "${MAC_BUNDLE_ID}" to quit`]);
    const deadline = Date.now() + QUIT_WAIT_MS;
    while (Date.now() < deadline && (await macRunning())) await sleep(500);
    // Opening it while the old one is still on its way out would only bring that one forward.
    if (await macRunning()) return false;
  }
  const opened = await run("open", ["-b", MAC_BUNDLE_ID]);
  return opened.ok || (await run("open", ["-a", "Claude"])).ok;
}

type WindowsDesktopProcess = { id: number; startedAt: string };
export type WindowsDesktopSelection = { exe: string; processes: WindowsDesktopProcess[] };

function object(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function windowsPath(value: unknown): value is string {
  return typeof value === "string" && value.length < 4096 && /^[A-Za-z]:\\/.test(value) &&
    !/[\x00-\x1f<>"|?*]/.test(value) && !value.slice(2).includes(":") &&
    !value.split(/[\\/]/).some(part => part === "." || part === "..");
}

function desktopImage(exe: string, localAppData: unknown, programFiles: unknown): boolean {
  const relativeTo = (root: unknown): string | undefined => windowsPath(root) ? path.win32.relative(root, exe).toLowerCase() : undefined;
  // Deliberately narrow: an unfamiliar installer layout requires a manual restart. Cached Code
  // binaries under resources/claude-code and independent CLI installs never match these paths.
  const local = relativeTo(localAppData);
  if (local && /^anthropicclaude\\(?:app-\d+(?:\.\d+){1,3}\\)?claude\.exe$/.test(local)) return true;
  const packaged = relativeTo(programFiles);
  return !!packaged && /^windowsapps\\claude_[\d.]+_(?:x64|arm64|x86)__pzs8sxrjxfjjc\\app\\claude\.exe$/.test(packaged);
}

function processIdentity(value: unknown): value is WindowsDesktopProcess & Record<string, unknown> {
  return object(value) && Number.isSafeInteger(value.id) && (value.id as number) > 0 && (value.id as number) <= 0x7fffffff &&
    typeof value.startedAt === "string" && /^\d{4}-\d{2}-\d{2}T[\d:.]+Z$/.test(value.startedAt) && Number.isFinite(Date.parse(value.startedAt));
}

/** Pure read-only snapshot selection. `null` means no named process, `undefined` means manual
 * restart is required. A window or a process name alone does not identify Desktop. */
export function selectWindowsDesktop(snapshot: unknown): WindowsDesktopSelection | null | undefined {
  if (!object(snapshot) || !Array.isArray(snapshot.processes) || snapshot.processes.length > 256) return undefined;
  if (snapshot.processes.length === 0) return null;
  if (!snapshot.processes.every(p => object(p) && typeof p.visible === "boolean")) return undefined;
  const visible = snapshot.processes.filter(p => p.visible) as Record<string, unknown>[];
  if (visible.length === 0) return undefined;
  const ids = new Set<number>();
  for (const process of visible) {
    if (!processIdentity(process) || ids.has(process.id) || !windowsPath(process.path) ||
        !desktopImage(process.path, snapshot.localAppData, snapshot.programFiles) ||
        process.productName !== "Claude" || process.fileDescription !== "Claude" ||
        process.signatureStatus !== "Valid" || typeof process.signer !== "string" || !["Anthropic, PBC", "Anthropic"].includes(process.signer)) return undefined;
    ids.add(process.id);
  }
  const paths = new Set(visible.map(p => path.win32.normalize(p.path as string).toLowerCase()));
  if (paths.size !== 1) return undefined;
  return { exe: visible[0]!.path as string, processes: visible.map(p => ({ id: p.id as number, startedAt: p.startedAt as string })) };
}

const WINDOWS_SNAPSHOT_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
try {
  $rows = @(Get-Process -Name claude -ErrorAction SilentlyContinue | ForEach-Object {
    $p = $_
    $row = @{ id = $p.Id; visible = $null; path = $null; startedAt = $null }
    try {
      $row.visible = $p.MainWindowHandle -ne 0
      if ($row.visible) {
        $row.path = $p.Path
        $row.startedAt = $p.StartTime.ToUniversalTime().ToString('o')
        $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($row.path)
        $row.productName = $info.ProductName
        $row.fileDescription = $info.FileDescription
        $sig = Get-AuthenticodeSignature -LiteralPath $row.path
        $row.signatureStatus = $sig.Status.ToString()
        if ($sig.SignerCertificate) { $row.signer = $sig.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false) }
      }
    } catch { }
    $row
  })
  @{ localAppData = [Environment]::GetFolderPath('LocalApplicationData'); programFiles = [Environment]::GetFolderPath('ProgramFiles'); processes = $rows } | ConvertTo-Json -Depth 4 -Compress
} catch { exit 1 }
`;

async function windowsDesktop(): Promise<WindowsDesktopSelection | null | undefined> {
  const result = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", WINDOWS_SNAPSHOT_SCRIPT], 15_000);
  if (!result.ok || result.stdout.length > 128 * 1024) return undefined;
  try { return selectWindowsDesktop(JSON.parse(result.stdout.replace(/^\uFEFF/, ""))); }
  catch { return undefined; }
}

const powershellLiteral = (value: string): string => `'${value.replaceAll("'", "''")}'`;

/** Revalidate exactly the selected window owners before asking them to close. A cancelled save
 * prompt, a tray-only process, a changed image or a new window leaves restart to the user. */
export function windowsDesktopRestartScript(selection: WindowsDesktopSelection): string | null {
  if (!selection || !windowsPath(selection.exe) || !Array.isArray(selection.processes) || !selection.processes.length ||
      selection.processes.length > 256 || !selection.processes.every(processIdentity) ||
      new Set(selection.processes.map(p => p.id)).size !== selection.processes.length) return null;
  const expected = selection.processes.map(p => `${p.id} = ${powershellLiteral(p.startedAt)}`).join("; ");
  return String.raw`
$ErrorActionPreference = 'Stop'
try {
  $exe = ${powershellLiteral(selection.exe)}
  $expected = @{ ${expected} }
  $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
  $sig = Get-AuthenticodeSignature -LiteralPath $exe
  if ($info.ProductName -cne 'Claude' -or $info.FileDescription -cne 'Claude' -or $sig.Status -ne 'Valid' -or -not $sig.SignerCertificate) { exit 1 }
  $signer = $sig.SignerCertificate.GetNameInfo([System.Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
  if ($signer -cne 'Anthropic, PBC' -and $signer -cne 'Anthropic') { exit 1 }
  $windows = @(Get-Process -Name claude -ErrorAction SilentlyContinue | Where-Object { $_.MainWindowHandle -ne 0 })
  if ($windows.Count -ne $expected.Count) { exit 1 }
  foreach ($p in $windows) {
    if (-not $expected.ContainsKey($p.Id) -or $p.Path -ine $exe -or $p.StartTime.ToUniversalTime().ToString('o') -cne $expected[$p.Id]) { exit 1 }
  }
  foreach ($p in $windows) { if (-not $p.CloseMainWindow()) { exit 1 } }
  $deadline = (Get-Date).AddMilliseconds(${QUIT_WAIT_MS})
  do {
    $named = @(Get-Process -Name claude -ErrorAction SilentlyContinue)
    foreach ($p in $named) { if (-not $p.Path) { exit 1 } }
    $remaining = @($named | Where-Object { $_.Path -ieq $exe })
    if ($remaining.Count -eq 0) {
      if (@($named | Where-Object { $_.MainWindowHandle -ne 0 }).Count -ne 0) { exit 1 }
      break
    }
    if ((Get-Date) -ge $deadline) { exit 1 }
    Start-Sleep -Milliseconds 250
  } while ($true)
  # A replacement window or unrelated CLI is never closed as part of this restart.
  Start-Process -FilePath $exe -ErrorAction Stop | Out-Null
} catch { exit 1 }
`;
}

async function reopenWindows(): Promise<boolean> {
  const selected = await windowsDesktop();
  if (!selected) return false;
  const script = windowsDesktopRestartScript(selected);
  if (!script) return false;
  const r = await run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], 40_000);
  return r.ok;
}
