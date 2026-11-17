// Files owned by ClaudeRipple that contain credentials or private keys. This is an OS-user
// boundary, not protection against malware or administrators acting as the same user.
import fs from "node:fs";
import path from "node:path";
import { applyWindowsPrivateAcl, verifyWindowsPrivateAcl, verifyWindowsPrivateFiles } from "./windows-private-acl.ts";
import { execBounded } from "../../cli/src/bounded-exec.ts";
export { applyWindowsPrivateAcl, WINDOWS_PRIVATE_ACL_SCRIPT } from "./windows-private-acl.ts";

const DEFAULT_MAX_BYTES = 8 * 1024 * 1024;
const windowsChecked = new Map<string, string>();

function identity(stat: fs.Stats): string {
  return [stat.dev, stat.ino, stat.ctimeMs, stat.mtimeMs, stat.size, stat.mode].join(":");
}

function rememberWindows(file: string, stat: fs.Stats): void {
  // Bounds memory even if a caller creates many transient files.
  if (windowsChecked.size >= 512) windowsChecked.clear();
  windowsChecked.set(path.resolve(file), identity(stat));
}

function protectWindows(file: string, directory: boolean, stat: fs.Stats): void {
  if (windowsChecked.get(path.resolve(file)) === identity(stat)) return;
  applyWindowsPrivateAcl(file, directory);
  const after = fs.lstatSync(file);
  if (after.dev !== stat.dev || after.ino !== stat.ino || after.isSymbolicLink()) {
    throw new Error("Private storage changed while protecting its permissions");
  }
  rememberWindows(file, after);
}

function assertOwner(stat: fs.Stats): void {
  if (process.platform !== "win32" && typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error("Private storage must belong to the current user");
  }
}

function assertRegular(stat: fs.Stats): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error("Private storage must be a regular, unlinked file");
  }
  assertOwner(stat);
}

/** Only call for an application-owned state directory, never a workspace or shared directory. */
export function ensurePrivateDirectory(directory: string): void {
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Private storage directory must be a real directory");
  assertOwner(stat);
  if (process.platform === "win32") protectWindows(directory, true, stat);
  else if ((stat.mode & 0o077) !== 0) fs.chmodSync(directory, 0o700);
}

/** Existing shared/configuration directories belong to the user: do not change their access. */
export function ensureStorageDirectory(directory: string): void {
  let existed = false;
  try {
    fs.lstatSync(directory);
    existed = true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
  }
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Storage directory must be a real directory");
  assertOwner(stat);
  if (!existed && process.platform === "win32") protectWindows(directory, true, stat);
}

/** Reject aliased/foreign targets before an atomic replacement. Missing destinations are valid. */
export function assertPrivateTarget(file: string): void {
  try {
    const stat = fs.lstatSync(file);
    assertRegular(stat);
    // Windows ownership lives in the security descriptor, not stat.uid. Check it on writes
    // as well as reads so replacement cannot overwrite a foreign-owned regular file.
    if (process.platform === "win32") protectWindows(file, false, stat);
  }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
}

/** Caller must close the returned descriptor. No credential bytes are read before checks pass. */
export function openPrivateRead(file: string): number {
  const before = fs.lstatSync(file);
  assertRegular(before);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const stat = fs.fstatSync(fd);
    assertRegular(stat);
    if (stat.dev !== before.dev || stat.ino !== before.ino) throw new Error("Private storage changed while opening it");
    if (process.platform === "win32") protectWindows(file, false, stat);
    else if ((stat.mode & 0o077) !== 0) fs.fchmodSync(fd, 0o600);
    return fd;
  } catch (error) { fs.closeSync(fd); throw error; }
}

function assertReadLimit(maxBytes: number): void {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 64 * 1024 * 1024) throw new Error("Invalid private storage size bound");
}

function readBoundedDescriptor(fd: number, maxBytes: number): Buffer {
  if (fs.fstatSync(fd).size > maxBytes) throw new Error("Private storage exceeds its size bound");
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, maxBytes + 1 - total));
    const count = fs.readSync(fd, chunk, 0, chunk.length, null);
    if (!count) break;
    total += count;
    if (total > maxBytes) throw new Error("Private storage exceeds its size bound");
    chunks.push(chunk.subarray(0, count));
  }
  return Buffer.concat(chunks, total);
}

/**
 * Read from a checked descriptor, without following symlinks or opening a FIFO indefinitely.
 * Existing owner-created legacy files are tightened before reading, never read after chmod fails.
 */
export function readPrivateFile(file: string, maxBytes = DEFAULT_MAX_BYTES): Buffer {
  assertReadLimit(maxBytes);
  const fd = openPrivateRead(file);
  try { return readBoundedDescriptor(fd, maxBytes); }
  finally { fs.closeSync(fd); }
}

function assertStrictPermissions(stat: fs.Stats): void {
  assertRegular(stat);
  if (process.platform !== "win32" && (stat.mode & 0o077) !== 0) {
    throw new Error("Private storage permissions must already be owner-only (0600)");
  }
}

function assertStrictSnapshot(file: string, expected: fs.Stats, fd: number): void {
  const current = fs.lstatSync(file);
  const opened = fs.fstatSync(fd);
  assertStrictPermissions(current);
  assertStrictPermissions(opened);
  if (identity(current) !== identity(expected) || identity(opened) !== identity(expected)) {
    throw new Error("Private storage changed while reading or verifying it");
  }
}

/**
 * New capabilities/trust anchors must already be private. Never repair permissions or reuse an
 * ACL cache. Verify Windows ownership/DACLs once per read, with the descriptor opened first and
 * its pathname identity checked before/after verification and reading. Trusted ancestors remain
 * required, as for the private writers; pathname checks alone do not secure a hostile parent.
 */
export function readPrivateFileStrict(file: string, maxBytes = DEFAULT_MAX_BYTES): Buffer {
  assertReadLimit(maxBytes);
  const before = fs.lstatSync(file);
  assertStrictPermissions(before);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    assertStrictSnapshot(file, before, fd);
    if (before.size > maxBytes) throw new Error("Private storage exceeds its size bound");
    if (process.platform === "win32") verifyWindowsPrivateAcl(file, false);
    assertStrictSnapshot(file, before, fd);
    const bytes = readBoundedDescriptor(fd, maxBytes);
    assertStrictSnapshot(file, before, fd);
    return bytes;
  } finally { fs.closeSync(fd); }
}

export interface PrivateFileRead { file: string; maxBytes: number }

function assertReadActive(signal?: AbortSignal): void {
  if (signal?.aborted) throw Object.assign(new Error("Private storage read aborted"), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
}

/**
 * One fresh snapshot, with at most one uncached Windows ACL process. All descriptors stay open
 * across verification and every pathname/descriptor is checked again before any bytes are read
 * and after the entire batch. A failed/aborted batch closes all descriptors and returns nothing.
 * As with the single-file reader, the caller must use trusted ancestor directories.
 */
export async function readPrivateFilesStrict(files: readonly PrivateFileRead[], options: { signal?: AbortSignal } = {}): Promise<Buffer[]> {
  assertReadActive(options.signal);
  if (files.length < 1 || files.length > 16) throw new Error("Invalid private storage batch");
  let maximum = 0;
  const names = new Set<string>();
  for (const item of files) {
    assertReadLimit(item.maxBytes);
    maximum += item.maxBytes;
    if (typeof item.file !== "string" || item.file.length === 0 || item.file.includes("\0") || names.has(path.resolve(item.file))) {
      throw new Error("Invalid private storage batch");
    }
    names.add(path.resolve(item.file));
  }
  if (maximum > DEFAULT_MAX_BYTES) throw new Error("Private storage batch exceeds its size bound");
  const opened: { file: string; maxBytes: number; fd: number; before: fs.Stats }[] = [];
  try {
    for (const item of files) {
      assertReadActive(options.signal);
      const before = fs.lstatSync(item.file);
      assertStrictPermissions(before);
      if (before.size > item.maxBytes) throw new Error("Private storage exceeds its size bound");
      const fd = fs.openSync(item.file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
      opened.push({ ...item, fd, before });
      assertStrictSnapshot(item.file, before, fd);
    }
    if (process.platform === "win32") await verifyWindowsPrivateFiles(opened.map(item => item.file), execBounded, options);
    assertReadActive(options.signal);
    for (const item of opened) assertStrictSnapshot(item.file, item.before, item.fd);
    const results = opened.map(item => {
      assertReadActive(options.signal);
      return readBoundedDescriptor(item.fd, item.maxBytes);
    });
    for (const item of opened) assertStrictSnapshot(item.file, item.before, item.fd);
    assertReadActive(options.signal);
    return results;
  } catch (error) {
    const code = (error as NodeJS.ErrnoException).code;
    if (typeof code === "string" && /^E[A-Z0-9_]{1,40}$/.test(code)) {
      // Keep machine-readable absence/permission classification without reflecting a pathname.
      throw Object.assign(new Error("Private storage could not be read"), { code });
    }
    throw error;
  } finally {
    // Close every descriptor even if a previous close itself failed. No batch can leak a
    // descriptor because an early open, ACL check, JSON reader or cancellation rejected it.
    for (const item of opened) { try { fs.closeSync(item.fd); } catch { /* already closed */ } }
  }
}

/** Cache metadata only after the caller has explicitly protected this newly written file. */
export function rememberPrivateFileCreated(file: string): void {
  if (process.platform !== "win32") return;
  const stat = fs.lstatSync(file);
  assertRegular(stat);
  rememberWindows(file, stat);
}

/** Refresh metadata only after our own entry mutation in an already protected directory. */
export function notePrivateDirectoryMutation(directory: string): void {
  if (process.platform !== "win32") return;
  const previous = windowsChecked.get(path.resolve(directory));
  if (!previous) return;
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || !previous.startsWith(`${stat.dev}:${stat.ino}:`)) return;
  rememberWindows(directory, stat);
}

/** Open a private append-only log without following a link or loosening an existing file. */
export function openPrivateAppend(file: string): number {
  ensureStorageDirectory(path.dirname(file));
  let before: fs.Stats | undefined;
  try { before = fs.lstatSync(file); assertRegular(before); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  const fd = fs.openSync(file, fs.constants.O_WRONLY | fs.constants.O_APPEND | fs.constants.O_CREAT |
    (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0), 0o600);
  try {
    const stat = fs.fstatSync(fd);
    assertRegular(stat);
    if (before && (before.dev !== stat.dev || before.ino !== stat.ino)) throw new Error("Private log changed while opening it");
    if (process.platform === "win32") protectWindows(file, false, stat);
    else if ((stat.mode & 0o077) !== 0) fs.fchmodSync(fd, 0o600);
    return fd;
  } catch (error) { fs.closeSync(fd); throw error; }
}

export function appendPrivateFile(file: string, data: string): void {
  const fd = openPrivateAppend(file);
  try {
    fs.writeFileSync(fd, data, "utf8");
    rememberPrivateFileCreated(file);
    notePrivateDirectoryMutation(path.dirname(file));
  }
  finally { fs.closeSync(fd); }
}
