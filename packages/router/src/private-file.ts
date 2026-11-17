// Files owned by ClaudeRipple that contain credentials or private keys. This is an OS-user
// boundary, not protection against malware or administrators acting as the same user.
import fs from "node:fs";
import path from "node:path";
import { applyWindowsPrivateAcl } from "./windows-private-acl.ts";
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

/**
 * Read from a checked descriptor, without following symlinks or opening a FIFO indefinitely.
 * Existing owner-created legacy files are tightened before reading, never read after chmod fails.
 */
export function readPrivateFile(file: string, maxBytes = DEFAULT_MAX_BYTES): Buffer {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0 || maxBytes > 64 * 1024 * 1024) throw new Error("Invalid private storage size bound");
  const fd = openPrivateRead(file);
  try {
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
  } finally { fs.closeSync(fd); }
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
