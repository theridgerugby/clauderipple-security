// A token previously sent over direct HTTP/WebSocket cannot become trustworthy by moving it
// into an encrypted channel. Rotate it once, atomically with its security-generation marker.
import path from "node:path";
import { newToken } from "./config.ts";
import { withFileLock, writePrivateFileAtomic } from "../../router/src/locked-file.ts";
import { readPhoneHostRecord } from "./phone-config-storage.ts";

export interface PhonePairingSecurity {
  token: string;
  pairingSecurityVersion: 2;
  rotated: boolean;
}

function pairingRecord(file: string): Record<string, unknown> & { token: string } {
  let value: unknown;
  try { value = readPhoneHostRecord(file); }
  catch { throw new Error("Phone pairing state could not be read; host startup was refused"); }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid phone pairing state; host startup was refused");
  const stored = value as Record<string, unknown>;
  if (typeof stored.token !== "string" || stored.token.length < 32 || stored.token.length > 256 || /[\0-\x20\x7f]/.test(stored.token)) {
    throw new Error("Invalid phone pairing credential; host startup was refused");
  }
  if (stored.pairingSecurityVersion !== undefined && stored.pairingSecurityVersion !== 1 && stored.pairingSecurityVersion !== 2) {
    throw new Error("Unsupported phone pairing security version; host startup was refused");
  }
  if (stored.pairingSecurityVersion === 2 && !/^[A-Za-z0-9_-]{43}$/.test(stored.token)) throw new Error("Invalid migrated phone pairing credential; host startup was refused");
  return stored as Record<string, unknown> & { token: string };
}

function commitRotation(file: string, stored: Record<string, unknown>): PhonePairingSecurity {
  const token = newToken();
  try { writePrivateFileAtomic(file, JSON.stringify({ ...stored, token, pairingSecurityVersion: 2 }, null, 2) + "\n"); }
  catch { throw new Error("Phone pairing security migration could not be committed; host startup was refused"); }
  return { token, pairingSecurityVersion: 2, rotated: true };
}

/** Called only by an actual updated host startup after a valid host.json has been created. */
export function ensurePhonePairingSecurity(dir: string): PhonePairingSecurity {
  const file = path.join(dir, "host.json");
  return withFileLock(file, () => {
    const stored = pairingRecord(file);
    if (stored.pairingSecurityVersion === 2) return { token: stored.token, pairingSecurityVersion: 2, rotated: false };
    return commitRotation(file, stored);
  });
}

/** An explicit operator action. A stale caller cannot rotate over another writer's token. */
export function rotatePhonePairingToken(dir: string, expectedToken: string): PhonePairingSecurity {
  const file = path.join(dir, "host.json");
  return withFileLock(file, () => {
    const stored = pairingRecord(file);
    if (stored.token !== expectedToken) throw new Error("Phone pairing changed; reload before rotating it again");
    return commitRotation(file, stored);
  });
}
