// Secret-bearing JSON files that more than one process writes: the router refreshes tokens while a
// `clauderipple login` in another terminal adds an account. Every mutation holds a cross-process
// lock and replaces the file atomically, so a reader sees the old file or the new one, never half.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { lockSync } from "proper-lockfile";
import { applyWindowsPrivateAcl, assertPrivateTarget, ensurePrivateDirectory, ensureStorageDirectory, notePrivateDirectoryMutation, readPrivateFileStored, rememberPrivateFileCreated } from "./private-file.ts";
import { hasNativeSecretProtection, isSealedSecret, sealSecretBytes, secretStoredBytesLimit, unsealSecretBytes, type SecretProtector } from "./secret-storage.ts";

const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 100;
// Windows private-file checks use the OS security descriptor and can take longer than chmod.
// Keep waiting bounded while allowing queued account writers to complete those checks.
const LOCK_TIMEOUT_MS = process.platform === "win32" ? 10_000 : 2_000;

/**
 * Whether taking the lock failed only because another writer holds it or is letting it go. On
 * Windows a lock directory another process is removing refuses a new `mkdir` with EPERM (or EACCES,
 * EBUSY) until the removal completes, so eight processes adding accounts at once lost one to EPERM
 * on Windows CI (2026-11-12). There it is waited out like ELOCKED; elsewhere it is a real refusal.
 */
export function lockBusy(code: string | undefined, platform: NodeJS.Platform = process.platform): boolean {
  return code === "ELOCKED" || (platform === "win32" && (code === "EPERM" || code === "EACCES" || code === "EBUSY"));
}
/** Wait for another writer for at most two seconds (ten on Windows), then run `mutate`. */
export function withFileLock<T>(file: string, mutate: () => T): T {
  ensureStorageDirectory(path.dirname(file));
  const deadline = Date.now() + LOCK_TIMEOUT_MS;
  let release: () => void;
  for (;;) {
    try {
      release = lockSync(file, { realpath: false, stale: LOCK_STALE_MS, update: 10_000 });
      break;
    } catch (error) {
      if (!lockBusy((error as NodeJS.ErrnoException).code) || Date.now() >= deadline) throw error;
      Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, LOCK_WAIT_MS);
    }
  }
  try {
    return mutate();
  } finally {
    release!();
    notePrivateDirectoryMutation(path.dirname(file));
  }
}

const RENAME_RETRY_BUDGET_MS = 2_000;
const RENAME_RETRY_WAIT_MS = 10;
const RENAME_RETRY_WAIT_MAX_MS = 200;

function sleepSync(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * Windows refuses a rename while another process has the target open (the old router reading its
 * state) or a virus scanner is inspecting it — EPERM/EACCES/EBUSY — and one refusal aborted a whole
 * GUI update (issue #125). Wait briefly and retry, about two seconds in total, then rethrow. Every
 * other platform and error is a single call with no retry. `now` is injectable so a test can run the
 * budget without sleeping.
 */
export function renameWithRetry(
  from: string,
  to: string,
  platform: NodeJS.Platform = process.platform,
  rename: (from: string, to: string) => void = fs.renameSync,
  sleep: (ms: number) => void = sleepSync,
  now: () => number = Date.now,
): void {
  if (platform !== "win32") return rename(from, to);
  const deadline = now() + RENAME_RETRY_BUDGET_MS;
  let wait = RENAME_RETRY_WAIT_MS;
  for (;;) {
    try {
      return rename(from, to);
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if ((code !== "EPERM" && code !== "EACCES" && code !== "EBUSY") || now() + wait > deadline) throw error;
      sleep(wait);
      wait = Math.min(wait * 2, RENAME_RETRY_WAIT_MAX_MS);
    }
  }
}

/**
 * Replace `file` with `value` as JSON (mode 0600): flushed temp file, then rename. Returns whether
 * the directory entry was also made durable — POSIX can fsync a directory, Windows cannot, and a
 * caller retiring an older copy of the same secret needs to know which it got.
 */
export function writeJsonAtomic(file: string, value: unknown): { directoryDurable: boolean } {
  // Also used for user-selected Claude/Codex settings paths. Protect the file without taking
  // ownership of the surrounding workspace's directory permissions.
  return writePrivateFileAtomic(file, JSON.stringify(value, null, 2) + "\n", false);
}

/** Opt-in for project-owned secrets only, never third-party settings or externally read PEMs. */
export function writeSecretJsonAtomic(file: string, value: unknown, options: { protector?: SecretProtector } = {}): { directoryDurable: boolean } {
  return writeSecretFileAtomic(file, JSON.stringify(value, null, 2) + "\n", options);
}

/** Encrypt before creating the temporary file: even incomplete atomic writes contain ciphertext. */
export function writeSecretFileAtomic(file: string, value: string | Buffer, options: { protector?: SecretProtector } = {}): { directoryDurable: boolean } {
  const bytes = typeof value === "string" ? Buffer.from(value, "utf8") : value;
  return writePrivateFileAtomic(file, sealSecretBytes(file, bytes, options.protector));
}

/**
 * Idempotent upgrade of a specifically identified, project-owned legacy secret. Call at startup
 * before using that store. A failure is fatal to migration, never a reason to write plaintext or
 * reset the account. No backup copy is created; only the encrypted temporary file reaches disk.
 */
export function migrateSecretFile(file: string, options: { protector?: SecretProtector } = {}): boolean {
  if (!options.protector && !hasNativeSecretProtection()) return false;
  let existing: Buffer;
  try { existing = readPrivateFileStored(file, secretStoredBytesLimit(8 * 1024 * 1024)); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return false; throw error; }
  // The normal already-migrated path remains read-only and does not contend with account refresh.
  if (isSealedSecret(existing)) { unsealSecretBytes(file, existing, 8 * 1024 * 1024, options.protector); return false; }
  return withFileLock(file, () => {
    const bytes = readPrivateFileStored(file, secretStoredBytesLimit(8 * 1024 * 1024));
    if (isSealedSecret(bytes)) { unsealSecretBytes(file, bytes, 8 * 1024 * 1024, options.protector); return false; }
    writeSecretFileAtomic(file, bytes, options);
    return true;
  });
}

function assertPrivateTemporary(stat: fs.Stats): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) {
    throw new Error("Private temporary storage must be a regular, unlinked file");
  }
  if (process.platform !== "win32") {
    if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
      throw new Error("Private temporary storage must belong to the current user");
    }
    if ((stat.mode & 0o077) !== 0) throw new Error("Private temporary storage permissions must be owner-only");
  }
}

/** Bind pathname-based ACL operations and publication to the descriptor opened exclusively. */
function assertTemporaryBinding(file: string, expected: fs.Stats, fd?: number): void {
  const current = fs.lstatSync(file);
  const opened = fd === undefined ? expected : fs.fstatSync(fd);
  assertPrivateTemporary(current);
  assertPrivateTemporary(opened);
  if (current.dev !== expected.dev || current.ino !== expected.ino ||
      opened.dev !== expected.dev || opened.ino !== expected.ino) {
    throw new Error("Private temporary storage changed while writing it");
  }
}

/**
 * Atomic private bytes, shared by JSON credential stores and PEM private keys. Storage paths
 * still require trusted ancestors. In particular, preserving a generic parent's permissions
 * does not make an attacker-writable directory safe: pathname checks cannot prevent every race
 * between a check and a filesystem operation, or an attacker moving the same entry away/back.
 */
export function writePrivateFileAtomic(file: string, value: string | Buffer, privateDirectory = true): { directoryDurable: boolean } {
  const dirName = path.dirname(file);
  if (privateDirectory) ensurePrivateDirectory(dirName);
  else ensureStorageDirectory(dirName);
  assertPrivateTarget(file);
  const tmp = `${file}.tmp-${process.pid}-${crypto.randomBytes(6).toString("hex")}`;
  try {
    const fd = fs.openSync(tmp, "wx", 0o600);
    let created: fs.Stats;
    try {
      created = fs.fstatSync(fd);
      assertTemporaryBinding(tmp, created, fd);
      // An elevated Windows process can create Administrators-owned files even inside a private
      // parent. Set the actual file owner and DACL while it is still empty; inherited grants
      // alone cannot establish the identity required by verify-only credential readers. The ACL
      // helper checks Windows ownership; bind its path to this descriptor again before writing.
      if (process.platform === "win32") applyWindowsPrivateAcl(tmp, false);
      assertTemporaryBinding(tmp, created, fd);
      fs.writeFileSync(fd, value, "utf8");
      fs.fsyncSync(fd);
      assertTemporaryBinding(tmp, created, fd);
    } finally {
      fs.closeSync(fd);
    }
    // Close before rename for Windows compatibility, but check the original identity on every
    // retry too: waiting for another process to release the destination must not accept a swap.
    renameWithRetry(tmp, file, process.platform, (from, to) => {
      assertPrivateTarget(to);
      assertTemporaryBinding(from, created);
      fs.renameSync(from, to);
    });
    assertTemporaryBinding(file, created);
    rememberPrivateFileCreated(file);
    let directoryDurable = false;
    try {
      const dir = fs.openSync(dirName, "r");
      try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); }
      directoryDurable = true;
    } catch (error) {
      const code = (error as NodeJS.ErrnoException).code;
      if (process.platform !== "win32" && code !== "EINVAL" && code !== "ENOTSUP" && code !== "EBADF") throw error;
    }
    return { directoryDurable };
  } finally {
    try { fs.unlinkSync(tmp); } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error;
    }
    notePrivateDirectoryMutation(dirName);
  }
}
