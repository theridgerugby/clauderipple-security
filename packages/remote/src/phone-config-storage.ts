// Host configuration can contain a legacy phone token that must be rotated. Reads do not
// repair permissions: an already-migrated capability exposed by a broad ACL is never reused.
import fs from "node:fs";
import { verifyWindowsPrivateAcl } from "../../router/src/windows-private-acl.ts";

const MAX_BYTES = 1024 * 1024;

function assertFile(stat: fs.Stats): void {
  if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("Phone host state must be a regular unlinked file");
  if (process.platform !== "win32" && typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error("Phone host state must belong to the current user");
  }
}

/** Missing is distinct from malformed. No raw JSON, credential, or path is reflected in errors. */
export function readPhoneHostRecord(file: string): Record<string, unknown> | undefined {
  let before: fs.Stats;
  try { before = fs.lstatSync(file); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw new Error("Phone host state could not be read");
  }
  assertFile(before);
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const opened = fs.fstatSync(fd);
    assertFile(opened);
    if (opened.dev !== before.dev || opened.ino !== before.ino) throw new Error("Phone host state changed while opening it");
    if (opened.size > MAX_BYTES) throw new Error("Phone host state exceeds its size bound");
    const bytes = Buffer.alloc(MAX_BYTES + 1);
    let total = 0;
    while (total <= MAX_BYTES) {
      const count = fs.readSync(fd, bytes, total, bytes.length - total, null);
      if (!count) break;
      total += count;
    }
    if (total > MAX_BYTES) throw new Error("Phone host state exceeds its size bound");
    let parsed: unknown;
    try { parsed = JSON.parse(bytes.subarray(0, total).toString("utf8")) as unknown; }
    catch { throw new Error("Invalid phone host configuration JSON"); }
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("Invalid phone host configuration record");
    const record = parsed as Record<string, unknown>;
    if (record.pairingSecurityVersion === 2) {
      if (process.platform === "win32") verifyWindowsPrivateAcl(file, false);
      else if ((opened.mode & 0o077) !== 0) throw new Error("Migrated phone pairing permissions must already be owner-only (0600); re-pairing is required");
    }
    // An atomic writer may legitimately replace this file during the read. Fail closed and
    // let the caller retry; never validate one path's ACL and return another inode's token.
    const after = fs.lstatSync(file);
    assertFile(after);
    if (after.dev !== opened.dev || after.ino !== opened.ino || after.size !== opened.size ||
        after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs || after.mode !== opened.mode) {
      throw new Error("Phone host state changed while reading it");
    }
    return record;
  } finally { fs.closeSync(fd); }
}
