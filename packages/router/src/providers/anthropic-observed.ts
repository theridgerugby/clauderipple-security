// Claude Code OAuth observed while transparently passing a real CLI request. RAM only: normal
// traffic never creates another persistent token copy. An explicit local logout prevents even
// RAM re-capture until the user explicitly authorizes reuse. No diagnostics/listing surface exists.

import path from "node:path";
import { authorizeClaudeLocalAuth, readClaudeLocalAuthState, removeLegacyObservedClaudeAuth, revokeClaudeLocalAuth } from "./anthropic-local-auth.ts";
import { parseClaudeCliVersion } from "./claude-cli-version.ts";

export const OBSERVED_CLAUDE_CODE_TTL_MS = 12 * 60 * 60 * 1_000;

export type ObservedClaudeCodeAuthSnapshot = {
  /** Validated Bearer value. It is only used to make an upstream request. */
  authorization: string;
  /** Exact allowlisted CLI header values, including authorization. */
  headers: Readonly<Record<string, string>>;
  observedAt: number;
};

/** The token part of a validated Bearer value; tokens are compared without their scheme. */
function bearerToken(value: string): string | null {
  const match = /^Bearer\s+(\S+)$/i.exec(value);
  return match ? match[1]! : null;
}

function isObservedHeader(name: string): boolean {
  const lower = name.toLowerCase();
  return lower === "authorization"
    || lower === "anthropic-beta"
    || lower === "anthropic-version"
    || lower === "user-agent"
    || lower === "x-app"
    || lower.startsWith("x-stainless-")
    || lower.startsWith("anthropic-client-");
}

/**
 * Stores the latest valid CLI Authorization plus its protocol-identifying headers in RAM.
 * Callers receive no inspection or listing API: getFresh() exists solely for direct forwarding.
 * noteUsed() and forget() exist only to keep the 12 h idle guard honest about a login that is
 * still being used; they read no token back.
 */
export class ObservedClaudeCodeAuth {
  private snapshot: ObservedClaudeCodeAuthSnapshot | null = null;
  /**
   * The token the upstream answered 401 for. An access token that was rejected does not become
   * valid again, so re-presenting it must not resurrect the login; a different token is a new
   * sign-in and is adopted normally.
   */
  private rejected: string | null = null;
  private readonly home: string | null;
  private readonly legacyFile: string | null;
  /** A failed attempt to publish the refusal still blocks this running process. */
  private locallyRevoked = false;
  private consentGeneration: string | undefined;
  private cliVersionSeen: string | null = null;
  private cliVersionAt = 0;

  constructor(file?: string) {
    this.home = file ? path.dirname(file) : null;
    this.legacyFile = file ?? null;
    // Never deserialize or re-import the old extra copy. Failed cleanup is visible to the caller.
    if (this.home && this.legacyFile) removeLegacyObservedClaudeAuth(this.home, this.legacyFile);
  }

  /** Keeps only the version token from `user-agent`, never the rest of the header set. */
  private recordCliVersion(headers: Readonly<Record<string, string>>, observedAt: number): void {
    for (const [name, value] of Object.entries(headers)) {
      if (name.toLowerCase() !== "user-agent") continue;
      const version = parseClaudeCliVersion(value);
      if (version) {
        this.cliVersionSeen = version;
        this.cliVersionAt = observedAt;
      }
      return;
    }
  }

  isRevoked(): boolean {
    let revoked = this.locallyRevoked;
    if (this.home) {
      try {
        const state = readClaudeLocalAuthState(this.home);
        if (this.consentGeneration !== undefined && this.consentGeneration !== state.generation) this.clear();
        this.consentGeneration = state.generation;
        revoked ||= !state.allowed;
      } catch { revoked = true; }
    }
    if (revoked) this.clear();
    return revoked;
  }

  private clear(): void {
    this.snapshot = null;
    this.rejected = null;
    this.cliVersionSeen = null;
    this.cliVersionAt = 0;
  }

  /** Drop borrowed in-memory authority when entering a mode that does not use it. No logout,
   * consent change, native credential access or persistent write is performed. */
  discard(): void { this.clear(); }

  /** Drop in-memory authority immediately, persist refusal, and retire only our legacy copy. */
  revoke(): void {
    this.locallyRevoked = true;
    this.clear();
    if (this.home) revokeClaudeLocalAuth(this.home);
    if (this.home && this.legacyFile) removeLegacyObservedClaudeAuth(this.home, this.legacyFile);
    // Once durable, the shared consent generation is authoritative. A later explicit CLI
    // authorization can resume a running router too; failed publication keeps the RAM latch set.
    if (this.home) this.locallyRevoked = false;
  }

  /** Explicit local consent. Old in-memory credentials are never revived by authorization. */
  authorize(): void {
    this.clear();
    if (this.home) authorizeClaudeLocalAuth(this.home);
    this.locallyRevoked = false;
  }

  observe(rawHeaders: readonly string[], observedAt = Date.now()): void {
    if (this.isRevoked() || !Number.isFinite(observedAt)) return;
    const headers: Record<string, string> = {};
    let authorization: string | null = null;
    for (let index = 0; index + 1 < rawHeaders.length; index += 2) {
      const name = rawHeaders[index]!;
      const value = rawHeaders[index + 1]!;
      if (!isObservedHeader(name) || /[\r\n\0]/.test(value)) continue;
      if (name.toLowerCase() === "authorization") {
        if (!/^Bearer\s+\S+$/i.test(value)) continue;
        authorization = value;
      }
      headers[name] = value;
    }
    if (!authorization) return;
    // A 401 already proved this token dead (see forget); the client may keep sending it until it
    // signs in again, which must not make the accounts list flap in and out per request.
    if (this.rejected !== null && bearerToken(authorization) === this.rejected) return;
    this.snapshot = {
      authorization,
      headers: Object.freeze({ ...headers }),
      observedAt,
    };
    // A different token is a sign-in or account switch; the previous token's refusal no longer applies.
    this.rejected = null;
    this.recordCliVersion(headers, observedAt);
  }

  /**
   * Counts the login being presented again — a routed request carried it, or the pool answered on
   * it — as still current. Only the login already held moves; a different token belongs to
   * observe(), which also replaces the header set (issue #123, 2026-11-05: 12 h of routed traffic
   * left the login forgotten because only an un-routed request used to refresh it).
   */
  noteUsed(authorization: string, at = Date.now()): void {
    if (this.isRevoked() || !Number.isFinite(at)) return;
    const snapshot = this.snapshot;
    const token = bearerToken(authorization);
    if (!snapshot || !token || bearerToken(snapshot.authorization) !== token || at < snapshot.observedAt) return;
    this.snapshot = { ...snapshot, observedAt: at };
  }

  /**
   * Drops the login after the upstream rejected this exact token with 401 (signed out or revoked).
   * A different token observed since then is left alone: the refusal belongs to that generation.
   */
  forget(authorization: string): void {
    const snapshot = this.snapshot;
    const token = bearerToken(authorization);
    if (!snapshot || !token || bearerToken(snapshot.authorization) !== token) return;
    this.rejected = token;
    this.snapshot = null;
  }

  /**
   * The CLI version seen on the last observation that is still inside the snapshot's TTL, for the
   * fallback headers' `user-agent`. A bare version only: the header set itself is never exposed.
   */
  cliVersion(now = Date.now()): string | null {
    if (this.isRevoked()) return null;
    if (!this.cliVersionSeen || now < this.cliVersionAt || now - this.cliVersionAt >= OBSERVED_CLAUDE_CODE_TTL_MS) return null;
    return this.cliVersionSeen;
  }

  getFresh(now = Date.now()): ObservedClaudeCodeAuthSnapshot | null {
    if (this.isRevoked()) return null;
    const snapshot = this.snapshot;
    if (!snapshot) return null;
    if (now < snapshot.observedAt || now - snapshot.observedAt >= OBSERVED_CLAUDE_CODE_TTL_MS) {
      this.snapshot = null;
      return null;
    }
    return snapshot;
  }
}
