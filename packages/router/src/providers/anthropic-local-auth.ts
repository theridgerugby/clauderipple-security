// A local consent state, not an upstream logout/revocation. It contains no credential and is
// checked before borrowing Claude Code's login or retaining a pass-through Authorization header.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { withFileLock, writePrivateFileAtomic } from "../locked-file.ts";
import { notePrivateDirectoryMutation, readPrivateFile } from "../private-file.ts";

export function claudeLocalAuthRevokedPath(home: string): string { return path.join(home, "claude-local-auth-state.json"); }
export function observedClaudeAuthPath(home: string): string { return path.join(home, "claude-auth-observed.json"); }

export type ClaudeLocalAuthState = { allowed: boolean; generation: string };
export function readClaudeLocalAuthState(home: string): ClaudeLocalAuthState {
  try {
    const item = JSON.parse(readPrivateFile(claudeLocalAuthRevokedPath(home), 256).toString("utf8")) as Record<string, unknown>;
    if (!item || typeof item !== "object" || Array.isArray(item) || item.version !== 1 || typeof item.allowed !== "boolean" ||
        typeof item.generation !== "string" || !/^[a-f0-9]{32}$/.test(item.generation)) throw new Error();
    return { allowed: item.allowed, generation: item.generation };
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { allowed: true, generation: "initial" };
    throw new Error("Local Claude authorization state is unreadable; explicitly reconnect to authorize it");
  }
}

function writeAuthorizationState(home: string, allowed: boolean): void {
  // One atomic record binds consent and generation. A fast logout/reconnect cannot hide the
  // intervening revocation from an older process that still has a pending OAuth response.
  writePrivateFileAtomic(claudeLocalAuthRevokedPath(home), JSON.stringify({ version: 1, allowed, generation: crypto.randomBytes(16).toString("hex") }) + "\n");
}

/** Unknown permissions/types also fail closed. No token file or OS credential reader is touched. */
export function isClaudeLocalAuthRevoked(home: string): boolean {
  try { return !readClaudeLocalAuthState(home).allowed; }
  catch { return true; }
}

/** Only our historical extra snapshot is removed; Claude Code's actual login is untouched. */
export function removeLegacyObservedClaudeAuth(home: string, file = observedClaudeAuthPath(home)): void {
  try { fs.unlinkSync(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw error; }
  notePrivateDirectoryMutation(path.dirname(file));
}

export function revokeClaudeLocalAuth(home: string): void {
  withFileLock(claudeLocalAuthRevokedPath(home), () => {
    // Publish refusal first. Another process can no longer re-observe while cleanup runs.
    writeAuthorizationState(home, false);
    removeLegacyObservedClaudeAuth(home);
  });
}

/** Call only after an explicit local sign-in/use-current-login action, never on observed traffic. */
export function authorizeClaudeLocalAuth(home: string): void {
  withFileLock(claudeLocalAuthRevokedPath(home), () => {
    removeLegacyObservedClaudeAuth(home);
    writeAuthorizationState(home, true);
  });
}

/** Serialize a background credential checkpoint with explicit local logout, across processes. */
export function withClaudeLocalAuthAuthorization<T>(home: string, action: () => T, expectedGeneration?: string): T | undefined {
  return withFileLock(claudeLocalAuthRevokedPath(home), () => {
    const state = readClaudeLocalAuthState(home);
    return !state.allowed || expectedGeneration !== undefined && state.generation !== expectedGeneration ? undefined : action();
  });
}

/** An explicitly requested sign-in may start while revoked, but any later consent change wins. */
export function withClaudeLocalAuthGeneration<T>(home: string, expectedGeneration: string, action: () => T): T | undefined {
  return withFileLock(claudeLocalAuthRevokedPath(home), () => readClaudeLocalAuthState(home).generation === expectedGeneration ? action() : undefined);
}
