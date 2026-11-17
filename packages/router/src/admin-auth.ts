// A local TCP port is reachable by other users and untrusted local programs. Administrative
// requests therefore need a per-installation capability in addition to the Host/Origin guards.
// This does not isolate an application from malware already running as that same OS user.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { homeDir } from "./config.ts";
import { withFileLock, writePrivateFileAtomic } from "./locked-file.ts";
import { ensurePrivateDirectory, readPrivateFile } from "./private-file.ts";
import { verifyWindowsPrivateAcl } from "./windows-private-acl.ts";

export const ADMIN_TOKEN_HEADER = "x-clauderipple-admin";
export const ADMIN_INSTANCE_HEADER = "x-clauderipple-instance-id";
// A new namespace is part of the transport migration: an older HTTP-only client must never
// discover the credential accepted by the TLS listener by reading its legacy token filename.
const TOKEN_FILE = "admin-tls-token";
const TOKEN_PATTERN = /^[a-f0-9]{64}$/;

function assertOwner(stat: fs.Stats): void {
  if (process.platform !== "win32" && typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new Error("admin credential must belong to the current user");
  }
}

/** Read a private, regular file without following a credential-file symlink. Never creates one. */
export function readAdminToken(home = homeDir()): string | undefined {
  const file = path.join(home, TOKEN_FILE);
  if (process.platform === "win32") {
    try {
      const stat = fs.lstatSync(file);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("admin credential must be a regular private file");
      verifyWindowsPrivateAcl(file, false);
      const token = readPrivateFile(file, 65).toString("utf8").trim();
      if (!TOKEN_PATTERN.test(token)) throw new Error("invalid admin credential file");
      return token;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw error;
    }
  }
  let fd: number;
  let before: fs.Stats;
  try {
    before = fs.lstatSync(file);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) throw new Error("admin credential must be a regular private file");
    assertOwner(before);
    fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1) throw new Error("admin credential must be a regular private file");
    if (stat.dev !== before.dev || stat.ino !== before.ino) throw new Error("admin credential changed while opening it");
    assertOwner(stat);
    if ((stat.mode & 0o077) !== 0) {
      throw new Error("admin credential permissions must be owner-only (0600)");
    }
    if (stat.size > 65) throw new Error("invalid admin credential file");
    const bytes = Buffer.alloc(66);
    const count = fs.readSync(fd, bytes, 0, bytes.length, 0);
    if (count > 65) throw new Error("invalid admin credential file");
    const token = bytes.subarray(0, count).toString("utf8").trim();
    if (!TOKEN_PATTERN.test(token)) throw new Error("invalid admin credential file");
    return token;
  } finally {
    fs.closeSync(fd);
  }
}

/** Create once under the installation's lock. Never repairs an insecure existing token silently. */
export function ensureAdminToken(home = homeDir()): string {
  ensurePrivateDirectory(home);
  const file = path.join(home, TOKEN_FILE);
  return withFileLock(file, () => {
    const current = readAdminToken(home);
    if (current !== undefined) return current;
    const token = crypto.randomBytes(32).toString("hex");
    // The writer establishes Windows ownership/DACLs before writing any bytes and publishes
    // the complete capability atomically. A refused ACL leaves no unusable empty token behind.
    writePrivateFileAtomic(file, token + "\n");
    return token;
  });
}

/** Missing credentials produce no header; the server refuses the request instead of bypassing auth. */
export function adminAuthHeaders(home = homeDir()): Record<string, string> {
  const token = readAdminToken(home);
  return token === undefined ? {} : { [ADMIN_TOKEN_HEADER]: token };
}

export function validAdminToken(value: string | string[] | undefined, expected: string): boolean {
  return typeof value === "string" && value.length === 64 && expected.length === 64 && TOKEN_PATTERN.test(value) && TOKEN_PATTERN.test(expected) &&
    crypto.timingSafeEqual(Buffer.from(value, "hex"), Buffer.from(expected, "hex"));
}
