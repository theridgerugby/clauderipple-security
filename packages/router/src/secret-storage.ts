// OS-bound encryption for ClaudeRipple-owned secret files. ACL/descriptor validation belongs
// to private-file.ts and MUST finish before calling these byte-only helpers. No master key is
// created or persisted. Windows DPAPI CurrentUser also requires the user's OS profile to decrypt.
import crypto from "node:crypto";
import path from "node:path";
import { spawnSync } from "node:child_process";

export const SECRET_FILE_PREFIX = "CLAUDERIPPLE-SECRET-V1\n";
const SECRET_NAMESPACE = "CLAUDERIPPLE-SECRET-";
const DPAPI_KIND = "windows-dpapi-current-user";
const MAX_SECRET_BYTES = 8 * 1024 * 1024;
const DPAPI_OVERHEAD = 16 * 1024;

// Fixed source; neither credentials nor filenames are command-line arguments. .NET Framework's
// ProtectedData is the native DPAPI wrapper available in Windows PowerShell 5.1. All failures
// produce a fixed message, never the request/secret or the exception returned by the OS.
export const WINDOWS_DPAPI_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
try {
  Add-Type -AssemblyName System.Security
  $request = [Console]::In.ReadToEnd() | ConvertFrom-Json
  if ($request.operation -ne 'protect' -and $request.operation -ne 'unprotect') { throw 'operation' }
  $bytes = [Convert]::FromBase64String([string]$request.data)
  $entropy = [Convert]::FromBase64String([string]$request.entropy)
  if ($bytes.Length -gt 8404992 -or $entropy.Length -gt 1024) { throw 'bound' }
  $scope = [System.Security.Cryptography.DataProtectionScope]::CurrentUser
  if ($request.operation -eq 'protect') {
    $result = [System.Security.Cryptography.ProtectedData]::Protect($bytes, $entropy, $scope)
  } else {
    $result = [System.Security.Cryptography.ProtectedData]::Unprotect($bytes, $entropy, $scope)
  }
  [Console]::Out.Write([Convert]::ToBase64String($result))
  [Array]::Clear($bytes, 0, $bytes.Length)
  [Array]::Clear($result, 0, $result.Length)
} catch {
  [Console]::Error.Write('Private secret protection failed')
  exit 1
}
`;

export type SecretRunner = (executable: string, args: string[], options: {
  input: string; encoding: "utf8"; timeout: number; maxBuffer: number; windowsHide: boolean; env: NodeJS.ProcessEnv;
}) => { status: number | null; stdout?: string | Buffer | null; error?: Error };
export type AsyncSecretRunner = (executable: string, args: string[], options: {
  input: string; timeoutMs: number; maxBuffer: number; windowsHide: boolean; env: NodeJS.ProcessEnv; signal?: AbortSignal;
}) => Promise<string>;
export interface AsyncSecretOptions { signal?: AbortSignal; run: AsyncSecretRunner }
export interface SecretProtector {
  readonly kind: string;
  protect(bytes: Buffer, entropy: Buffer): Buffer;
  unprotect(bytes: Buffer, entropy: Buffer): Buffer;
  unprotectAsync?(bytes: Buffer, entropy: Buffer, options: AsyncSecretOptions): Promise<Buffer>;
}

function protectionError(): Error {
  return new Error("Private secret protection failed; use the original Windows user profile or reconnect the account");
}
function checkActive(signal?: AbortSignal): void {
  if (signal?.aborted) throw Object.assign(new Error("Private secret read aborted"), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
}
function dpapiCommand(systemRoot: string | undefined): { executable: string; args: string[] } {
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) throw new Error("Windows system directory is unavailable for secret protection");
  return {
    executable: path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    args: ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_DPAPI_SCRIPT],
  };
}
/** Match the CLI's Windows PowerShell environment without coupling the app's generated copy to
 * another package. A pwsh -> Node -> 5.1 launch must rebuild the 5.1 module path, not inherit 7's. */
function dpapiEnvironment(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => key.toLowerCase() !== "psmodulepath"));
}
function canonicalBase64(value: unknown, bound: number): Buffer {
  if (typeof value !== "string" || value.length > Math.ceil(bound / 3) * 4 || value.length % 4 !== 0 || /[^A-Za-z0-9+/=]/.test(value)) throw protectionError();
  const bytes = Buffer.from(value, "base64");
  if (bytes.length > bound || bytes.toString("base64") !== value) throw protectionError();
  return bytes;
}
function dpapiInput(operation: "protect" | "unprotect", bytes: Buffer, entropy: Buffer): string {
  if (bytes.length > MAX_SECRET_BYTES + DPAPI_OVERHEAD || entropy.length > 1024) throw protectionError();
  return JSON.stringify({ operation, data: bytes.toString("base64"), entropy: entropy.toString("base64") });
}

/** Injectable only as a function argument for isolated tests, never a config/env bypass. */
export function createWindowsDpapiProtector(run?: SecretRunner, systemRoot = process.env.SystemRoot): SecretProtector {
  function transform(operation: "protect" | "unprotect", bytes: Buffer, entropy: Buffer): Buffer {
    const { executable, args } = dpapiCommand(systemRoot);
    try {
      const result = (run ?? spawnSync)(executable, args, {
        input: dpapiInput(operation, bytes, entropy), encoding: "utf8", timeout: 10_000,
        maxBuffer: Math.ceil((MAX_SECRET_BYTES + DPAPI_OVERHEAD) / 3) * 4, windowsHide: true, env: dpapiEnvironment(),
      });
      if (result.error || result.status !== 0) throw protectionError();
      return canonicalBase64(String(result.stdout ?? ""), MAX_SECRET_BYTES + DPAPI_OVERHEAD);
    } catch { throw protectionError(); }
  }
  return {
    kind: DPAPI_KIND,
    protect: (bytes, entropy) => transform("protect", bytes, entropy),
    unprotect: (bytes, entropy) => transform("unprotect", bytes, entropy),
    async unprotectAsync(bytes, entropy, options) {
      checkActive(options.signal);
      const { executable, args } = dpapiCommand(systemRoot);
      try {
        const output = await options.run(executable, args, {
          input: dpapiInput("unprotect", bytes, entropy), timeoutMs: 10_000,
          maxBuffer: Math.ceil((MAX_SECRET_BYTES + DPAPI_OVERHEAD) / 3) * 4, windowsHide: true, env: dpapiEnvironment(),
          ...(options.signal ? { signal: options.signal } : {}),
        });
        checkActive(options.signal);
        return canonicalBase64(output, MAX_SECRET_BYTES);
      } catch (error) {
        checkActive(options.signal);
        if ((error as { timedOut?: boolean }).timedOut) throw Object.assign(new Error("Private secret read timed out"), { name: "TimeoutError", code: "PRIVATE_STORAGE_TIMEOUT" });
        throw protectionError();
      }
    },
  };
}

let nativeProtector: SecretProtector | undefined;
function defaultProtector(): SecretProtector | undefined {
  if (process.platform !== "win32") return undefined;
  return nativeProtector ??= createWindowsDpapiProtector();
}
export function hasNativeSecretProtection(): boolean { return process.platform === "win32"; }

/** Size limit for encoded bytes, separate from the caller's unchanged plaintext size bound. */
export function secretStoredBytesLimit(plainLimit: number): number {
  return Math.ceil((plainLimit + DPAPI_OVERHEAD) / 3) * 4 + 2048;
}
function purpose(file: string): string {
  const name = path.basename(file);
  if (!name || name.includes("\0") || Buffer.byteLength(name) > 512) throw protectionError();
  return name;
}
function entropyFor(name: string): Buffer { return Buffer.from(`ClaudeRipple private secret v1\0${name}`, "utf8"); }
export function isSealedSecret(bytes: Buffer): boolean { return bytes.subarray(0, SECRET_NAMESPACE.length).toString("utf8") === SECRET_NAMESPACE; }

/** Only explicit secret writers call this. PEMs and third-party settings remain interoperable. */
export function sealSecretBytes(file: string, bytes: Buffer, protector = defaultProtector()): Buffer {
  if (bytes.length > MAX_SECRET_BYTES) throw new Error("Private secret exceeds its size bound");
  if (!protector) return Buffer.from(bytes); // Other platforms retain their existing owner-only storage.
  const name = purpose(file);
  let ciphertext: Buffer;
  try { ciphertext = protector.protect(bytes, entropyFor(name)); }
  catch { throw protectionError(); }
  if (!Buffer.isBuffer(ciphertext) || ciphertext.length < 1 || ciphertext.length > MAX_SECRET_BYTES + DPAPI_OVERHEAD) throw protectionError();
  return Buffer.from(SECRET_FILE_PREFIX + JSON.stringify({ version: 1, protector: protector.kind, purpose: name, ciphertext: ciphertext.toString("base64") }) + "\n", "utf8");
}

interface ParsedSecret { protector: SecretProtector; ciphertext: Buffer; entropy: Buffer; key: string }
function parseSealed(file: string, bytes: Buffer, protector: SecretProtector | undefined): ParsedSecret {
  if (!bytes.subarray(0, SECRET_FILE_PREFIX.length).equals(Buffer.from(SECRET_FILE_PREFIX))) throw protectionError();
  let value: unknown;
  try { value = JSON.parse(bytes.subarray(SECRET_FILE_PREFIX.length).toString("utf8")); } catch { throw protectionError(); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw protectionError();
  const item = value as Record<string, unknown>;
  const name = purpose(file);
  if (Object.keys(item).sort().join(",") !== "ciphertext,protector,purpose,version" || item.version !== 1 || !protector || item.protector !== protector.kind || item.purpose !== name) throw protectionError();
  return { protector, ciphertext: canonicalBase64(item.ciphertext, MAX_SECRET_BYTES + DPAPI_OVERHEAD), entropy: entropyFor(name), key: crypto.createHash("sha256").update(bytes).digest("hex") };
}

// A small, bounded RAM cache avoids launching PowerShell for every forwarded request. It is keyed
// by exact sealed bytes and protector identity, never pathname or timestamps. Every filesystem
// reader still performs its descriptor/owner/ACL checks before this cache is considered.
const clearCaches = new WeakMap<SecretProtector, Map<string, { value: Buffer; expiresAt: number }>>();
const CACHE_TTL_MS = 60_000;
const CACHE_MAX_BYTES = 8 * 1024 * 1024;
function cached(item: ParsedSecret): Buffer | null {
  const cache = clearCaches.get(item.protector), hit = cache?.get(item.key);
  if (!hit) return null;
  if (hit.expiresAt <= Date.now()) { hit.value.fill(0); cache!.delete(item.key); return null; }
  return Buffer.from(hit.value);
}
function cacheValue(item: ParsedSecret, value: Buffer): void {
  if (value.length > CACHE_MAX_BYTES) return;
  let cache = clearCaches.get(item.protector);
  if (!cache) { cache = new Map(); clearCaches.set(item.protector, cache); }
  let used = 0;
  for (const entry of cache.values()) used += entry.value.length;
  if (cache.size >= 32 || used + value.length > CACHE_MAX_BYTES) {
    for (const entry of cache.values()) entry.value.fill(0);
    cache.clear();
  }
  cache.set(item.key, { value: Buffer.from(value), expiresAt: Date.now() + CACHE_TTL_MS });
}
function boundedPlain(bytes: Buffer, maxBytes: number): Buffer {
  if (!Buffer.isBuffer(bytes) || bytes.length > maxBytes) throw new Error("Private storage exceeds its size bound");
  return bytes;
}

export function unsealSecretBytes(file: string, bytes: Buffer, maxBytes: number, protector = defaultProtector()): Buffer {
  if (!isSealedSecret(bytes)) return boundedPlain(bytes, maxBytes);
  const item = parseSealed(file, bytes, protector);
  const hit = cached(item);
  if (hit) return boundedPlain(hit, maxBytes);
  let clear: Buffer;
  try { clear = item.protector.unprotect(item.ciphertext, item.entropy); } catch { throw protectionError(); }
  boundedPlain(clear, maxBytes);
  cacheValue(item, clear);
  return clear;
}

export async function unsealSecretBytesAsync(file: string, bytes: Buffer, maxBytes: number, options: AsyncSecretOptions & { protector?: SecretProtector }): Promise<Buffer> {
  checkActive(options.signal);
  if (!isSealedSecret(bytes)) return boundedPlain(bytes, maxBytes);
  const item = parseSealed(file, bytes, options.protector ?? defaultProtector());
  const hit = cached(item);
  if (hit) return boundedPlain(hit, maxBytes);
  let clear: Buffer;
  try { clear = item.protector.unprotectAsync ? await item.protector.unprotectAsync(item.ciphertext, item.entropy, options) : item.protector.unprotect(item.ciphertext, item.entropy); }
  catch (error) { checkActive(options.signal); if ((error as { code?: string }).code === "PRIVATE_STORAGE_TIMEOUT") throw error; throw protectionError(); }
  checkActive(options.signal);
  boundedPlain(clear, maxBytes);
  cacheValue(item, clear);
  return clear;
}
