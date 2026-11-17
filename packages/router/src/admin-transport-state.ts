// Local admin server identity and discovery. TLS authenticates the server before clients send
// their capability; neither a guessed port nor a plaintext /api/ping answer is an identity.
// This CA is admin-only and is never imported into an OS/browser trust store by this module.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { withFileLock, writeJsonAtomic } from "./locked-file.ts";
import { ensurePrivateDirectory, readPrivateFileStrict, readPrivateFilesStrict } from "./private-file.ts";
import { createCa, createLeaf } from "./x509.ts";

export interface AdminTlsIdentity {
  version: 1;
  caCertPem: string;
  certPem: string;
  keyPem: string;
}

export interface AdminEndpoint {
  version: 1;
  instanceId: string;
  publicPort: number;
  tlsPort: number;
}

const IDENTITY_FILE = "admin-tls-identity.json";
const ENDPOINT_FILE = "admin-tls-endpoint.json";

export function adminTransportPaths(home: string): { identity: string; endpoint: string } {
  return { identity: path.join(home, IDENTITY_FILE), endpoint: path.join(home, ENDPOINT_FILE) };
}

export function parseAdminStateJson(text: string): unknown {
  try { return JSON.parse(text) as unknown; }
  catch { throw new Error("invalid local admin transport state"); }
}

function readState(file: string): unknown | undefined {
  let text: string;
  try {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1) throw new Error("admin transport state must be a regular private file");
    // These are new trust anchors, not legacy provider storage. An exposed signing key may
    // already have been copied; chmod/ACL repair must never make it trusted again silently.
    text = readPrivateFileStrict(file, 64 * 1024).toString("utf8");
  }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  return parseAdminStateJson(text);
}

function record(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : undefined;
}

function validIdentity(value: unknown, checkExpiration = true): value is AdminTlsIdentity {
  const item = record(value);
  if (!item || item.version !== 1 || typeof item.caCertPem !== "string" || typeof item.certPem !== "string" || typeof item.keyPem !== "string") return false;
  try {
    const ca = new crypto.X509Certificate(item.caCertPem);
    const cert = new crypto.X509Certificate(item.certPem);
    const key = crypto.createPrivateKey(item.keyPem);
    const publicKey = crypto.createPublicKey(key).export({ type: "spki", format: "der" });
    const now = Date.now();
    return ca.ca && !cert.ca && !!cert.checkIP("127.0.0.1") && cert.checkIssued(ca) &&
      cert.verify(ca.publicKey) && ca.verify(ca.publicKey) &&
      cert.publicKey.export({ type: "spki", format: "der" }).equals(publicKey) &&
      Date.parse(ca.validFrom) <= now && Date.parse(cert.validFrom) <= now &&
      (!checkExpiration || (Date.parse(ca.validTo) > now && Date.parse(cert.validTo) > now));
  } catch { return false; }
}

/** No creation or TOFU from the network: only owner-protected installation state is trusted. */
export function readAdminTlsIdentity(home: string): AdminTlsIdentity | undefined {
  const value = readState(path.join(home, IDENTITY_FILE));
  if (value === undefined) return undefined;
  return parseAdminTlsIdentity(value);
}

export function parseAdminTlsIdentity(value: unknown): AdminTlsIdentity {
  if (!validIdentity(value)) throw new Error("invalid or expired local admin TLS identity");
  return value;
}

/** A single atomic bundle keeps the leaf, private key and dedicated trust anchor coherent. */
export function ensureAdminTlsIdentity(home: string): AdminTlsIdentity {
  ensurePrivateDirectory(home);
  const file = path.join(home, IDENTITY_FILE);
  return withFileLock(file, () => {
    const existing = readState(file);
    if (existing !== undefined) {
      // Only the server startup path can renew an expired, otherwise coherent identity.
      // Client reads stay fail-closed; malformed or mismatched keys are never repaired silently.
      if (!validIdentity(existing, false)) throw new Error("invalid local admin TLS identity");
      if (validIdentity(existing)) return existing;
    }
    const ca = createCa({ cn: "ClaudeRipple local admin CA", days: 3650 });
    const leaf = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
    const identity: AdminTlsIdentity = { version: 1, caCertPem: ca.certPem, certPem: leaf.certPem, keyPem: leaf.keyPem };
    // The CA signing key is not persisted. This identity can serve only its issued loopback leaf.
    writeJsonAtomic(file, identity);
    return identity;
  });
}

function validPort(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 1 && value <= 65535;
}

function validEndpoint(value: unknown): value is AdminEndpoint {
  const item = record(value);
  return !!item && item.version === 1 && typeof item.instanceId === "string" && item.instanceId.length === 32 && /^[a-f0-9]{32}$/.test(item.instanceId) &&
    validPort(item.publicPort) && validPort(item.tlsPort) && item.publicPort !== item.tlsPort;
}

export function readAdminEndpoint(home: string): AdminEndpoint | undefined {
  const value = readState(path.join(home, ENDPOINT_FILE));
  if (value === undefined) return undefined;
  return parseAdminEndpoint(value);
}

export function parseAdminEndpoint(value: unknown): AdminEndpoint {
  if (!validEndpoint(value)) throw new Error("invalid local admin endpoint state");
  return value;
}

/** A stop receipt needs only fresh protected discovery, not the current configured port. */
export async function readAdminEndpointAsync(home: string, options: { signal?: AbortSignal } = {}): Promise<AdminEndpoint | undefined> {
  let files: Buffer[];
  try { files = await readPrivateFilesStrict([{ file: adminTransportPaths(home).endpoint, maxBytes: 64 * 1024 }], options); }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
    throw error;
  }
  return parseAdminEndpoint(parseAdminStateJson(files[0]!.toString("utf8")));
}

export function writeAdminEndpoint(home: string, endpoint: AdminEndpoint): void {
  if (!validEndpoint(endpoint)) throw new Error("invalid local admin endpoint state");
  const file = path.join(home, ENDPOINT_FILE);
  withFileLock(file, () => writeJsonAtomic(file, endpoint));
}

/** An older listener's close must not erase a newer instance's discovery record. */
export function removeAdminEndpoint(home: string, instanceId: string): void {
  const file = path.join(home, ENDPOINT_FILE);
  withFileLock(file, () => {
    if (readAdminEndpoint(home)?.instanceId === instanceId) fs.unlinkSync(file);
  });
}
