// Installation is complete only when the authenticated live router is running these files.
// A version string cannot distinguish a security fork from its same-version upstream, and
// hashing files on every status read would let an old process describe a newer on-disk tree.
// The router captures this fingerprint once, before it listens; install independently captures
// its expected tree and compares it again before changing any client settings.
//
// This is a stale-process/coherent-installation check, not attestation against malicious code
// already running as the same OS user. It covers bundled runtime files and dependency manifests;
// it does not certify arbitrary node_modules contents or replace locked dependency installation.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import type { AgentRestart } from "./ownership.ts";
import type { ProbeResult } from "./probe.ts";
import { runtime, type Runtime } from "./runtime.ts";
import type { StartResult } from "./supervisor.ts";

export type RouterCodeIdentity = Readonly<{ schema: 1; sha256: string }>;
type RuntimeLocation = Pick<Runtime, "repo" | "router" | "cli">;
type Snapshot = { file: string; stat: fs.BigIntStats };
const MAX_FILES = 8192;
const MAX_FILE_BYTES = 8 * 1024 * 1024;
const MAX_TREE_BYTES = 64 * 1024 * 1024;
const CODE_EXTENSIONS = new Set([".ts", ".tsx", ".js", ".mjs", ".cjs", ".json", ".html", ".css", ".svg"]);
const SHA256 = /^[a-f0-9]{64}$/;
const INSTALL_ID = /^[a-f0-9]{32}$/;

function unchanged(a: fs.BigIntStats, b: fs.BigIntStats): boolean {
  return a.dev === b.dev && a.ino === b.ino && a.mode === b.mode && a.nlink === b.nlink &&
    a.uid === b.uid && a.gid === b.gid && a.size === b.size && a.mtimeNs === b.mtimeNs && a.ctimeNs === b.ctimeNs;
}

function samePath(a: string, b: string): boolean {
  if (!path.isAbsolute(a) || !path.isAbsolute(b) || /[\0\r\n]/.test(a + b)) return false;
  // realpath also handles a Node executable reached through its legitimate installation alias.
  // Neither path is executed here, and a nonexistent claimed runtime cannot be accepted.
  try {
    const realA = fs.realpathSync.native(a), realB = fs.realpathSync.native(b);
    return process.platform === "win32" ? realA.toLowerCase() === realB.toLowerCase() : realA === realB;
  } catch { return false; }
}

/** Bounded, descriptor-bound, deterministic runtime fingerprint. No shell, Git or credential read. */
export function captureRouterCodeIdentity(rt: RuntimeLocation = runtime()): RouterCodeIdentity {
  const root = fs.realpathSync.native(rt.repo);
  const source = path.extname(rt.cli) === ".ts";
  const layout = source ? "packages" : "dist";
  const extension = source ? ".ts" : ".js";
  if (!samePath(rt.cli, path.join(root, layout, "cli", "src", `index${extension}`)) ||
      !samePath(rt.router, path.join(root, layout, "router", "src", `index${extension}`))) {
    throw new Error("The router runtime layout could not be verified");
  }
  const hash = crypto.createHash("sha256");
  hash.update(`clauderipple-runtime-v1\0${process.versions.node}\0${process.platform}\0${process.arch}\0`);
  const snapshots: Snapshot[] = [];
  let files = 0, bytes = 0;
  const record = (file: string): fs.BigIntStats => {
    const stat = fs.lstatSync(file, { bigint: true });
    if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile())) throw new Error("The router runtime contains an unsupported file alias");
    if (snapshots.length >= MAX_FILES * 2) throw new Error("The router runtime exceeds the fingerprint entry limit");
    snapshots.push({ file, stat });
    return stat;
  };
  const readFile = (file: string, relative: string, stat: fs.BigIntStats): void => {
    if (!stat.isFile() || stat.nlink !== 1n || stat.size > BigInt(MAX_FILE_BYTES) || ++files > MAX_FILES) {
      throw new Error("The router runtime contains an aliased or oversized file");
    }
    bytes += Number(stat.size);
    if (bytes > MAX_TREE_BYTES) throw new Error("The router runtime exceeds the fingerprint size limit");
    const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
    try {
      if (!unchanged(stat, fs.fstatSync(fd, { bigint: true }))) throw new Error("The router runtime changed while it was being verified");
      hash.update(`file\0${relative}\0${stat.size}\0`);
      const buffer = Buffer.allocUnsafe(64 * 1024);
      let read = 0;
      while (true) {
        const count = fs.readSync(fd, buffer, 0, buffer.length, null);
        if (!count) break;
        read += count;
        if (read > Number(stat.size)) throw new Error("The router runtime changed while it was being verified");
        hash.update(buffer.subarray(0, count));
      }
      if (read !== Number(stat.size) || !unchanged(stat, fs.fstatSync(fd, { bigint: true })) ||
          !unchanged(stat, fs.lstatSync(file, { bigint: true }))) throw new Error("The router runtime changed while it was being verified");
    } finally { fs.closeSync(fd); }
  };
  const walk = (relative: string, required = false): void => {
    const file = path.join(root, ...relative.split("/"));
    let stat: fs.BigIntStats;
    try { stat = record(file); } catch (error) {
      if (!required && (error as NodeJS.ErrnoException).code === "ENOENT") {
        hash.update(`absent\0${relative}\0`);
        return;
      }
      throw error;
    }
    if (stat.isDirectory()) {
      hash.update(`directory\0${relative}\0`);
      for (const name of fs.readdirSync(file).sort()) {
        if (name === "node_modules" || name === ".git") continue;
        const child = path.join(file, name);
        const childStat = fs.lstatSync(child, { bigint: true });
        if (childStat.isDirectory() || childStat.isSymbolicLink() || CODE_EXTENSIONS.has(path.extname(name))) walk(`${relative}/${name}`, true);
      }
    } else readFile(file, relative, stat);
  };
  // The module tree imports CLI and Remote helpers and the mod's pure settings logic. Include
  // the native dashboard's source/built files as well, so a later rebuild changes the expected
  // fingerprint. The build command still owns checking/rebuilding generated artifacts.
  record(root);
  walk("package.json", true);
  walk("package-lock.json");
  for (const name of ["router", "cli", "remote", "app", "mod", "ui"]) walk(`${layout}/${name}/package.json`);
  for (const relative of ["router/src", "cli/src", "remote/src", "remote/web", "mod/hooks", "ui", "app/src", "app/dist"]) {
    walk(`${layout}/${relative}`, relative === "router/src" || relative === "cli/src");
  }
  for (const snapshot of snapshots) {
    if (!unchanged(snapshot.stat, fs.lstatSync(snapshot.file, { bigint: true }))) throw new Error("The router runtime changed while it was being verified");
  }
  return Object.freeze({ schema: 1, sha256: hash.digest("hex") });
}

export function isRouterCodeIdentity(value: unknown): value is RouterCodeIdentity {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  const row = value as Partial<RouterCodeIdentity>;
  return row.schema === 1 && typeof row.sha256 === "string" && SHA256.test(row.sha256);
}

export function sameRouterCodeIdentity(a: unknown, b: unknown): boolean {
  return isRouterCodeIdentity(a) && isRouterCodeIdentity(b) && a.sha256 === b.sha256;
}

export type InstallRuntimeTarget = {
  version: string;
  node: string;
  router: string;
  codeIdentity: RouterCodeIdentity;
  listen: { host: string; port: number };
  upstream: string;
};
type RuntimeProof = {
  installId: string;
  pid: number;
  startedAt: string;
  version: string;
  node: string;
  router: string;
  codeIdentity: unknown;
  listen: unknown;
  upstream: unknown;
};
export type InstallRuntimeDeps = {
  /** Must use the pinned authenticated transport, with no plaintext or browser fallback. */
  status(signal: AbortSignal): Promise<unknown>;
  installationId(): string | null;
  /** Existing ownership-checked supervisor drain/restart; never a PID kill fallback. */
  restart(): AgentRestart | Promise<AgentRestart>;
  /** Re-read the local tree immediately before applying client settings. */
  captureIdentity(): RouterCodeIdentity;
  onRestart?(result: AgentRestart): void;
  now?(): number;
  sleep?(ms: number): Promise<void>;
};

function ownedStatus(value: unknown, installId: string | null): RuntimeProof {
  const row = value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
  const rt = row.runtime && typeof row.runtime === "object" && !Array.isArray(row.runtime) ? row.runtime as Record<string, unknown> : {};
  if (!installId || !INSTALL_ID.test(installId) || row.installId !== installId ||
      !Number.isSafeInteger(row.pid) || Number(row.pid) <= 0 || typeof row.version !== "string" ||
      typeof rt.node !== "string" || !path.isAbsolute(rt.node) || typeof rt.router !== "string" || !path.isAbsolute(rt.router) ||
      typeof rt.startedAt !== "string" || !Number.isFinite(Date.parse(rt.startedAt))) {
    throw new Error("The authenticated router could not be verified as this installation; client settings were left unchanged");
  }
  return { installId, pid: Number(row.pid), startedAt: rt.startedAt, version: row.version,
    node: rt.node, router: rt.router, codeIdentity: rt.codeIdentity, listen: row.listen, upstream: row.upstream };
}

function matchesTarget(proof: RuntimeProof, target: InstallRuntimeTarget): boolean {
  const listen = proof.listen && typeof proof.listen === "object" ? proof.listen as Record<string, unknown> : {};
  return proof.version === target.version && samePath(proof.node, target.node) && samePath(proof.router, target.router) &&
    sameRouterCodeIdentity(proof.codeIdentity, target.codeIdentity) && listen.host === target.listen.host &&
    listen.port === target.listen.port && proof.upstream === target.upstream;
}

/** Reused by recovery. The input must come from the pinned, authenticated admin transport. */
export function statusMatchesRuntime(value: unknown, target: InstallRuntimeTarget, installId: string | null): boolean {
  try { return matchesTarget(ownedStatus(value, installId), target); }
  catch { return false; }
}

/**
 * One completion boundary for install: prove the live code, probe data traffic, prove the same
 * live process/tree once more, then perform the synchronous settings edit. A failed start,
 * legacy HTTP-only process, unknown owner, failed restart or a racing replacement never reaches
 * `apply`. Setup may have generated private state/registered a task; it has not redirected Claude.
 */
export async function verifyAndApplyInstall<T>(options: {
  started: StartResult;
  target: InstallRuntimeTarget;
  deps: InstallRuntimeDeps;
  probe(): Promise<ProbeResult>;
  onProbe?(result: ProbeResult): void;
  apply(): T;
  readinessMs?: number;
}): Promise<T> {
  const { target, deps } = options;
  if (!["already-running", "started", "started-directly"].includes(options.started)) {
    throw new Error(`The router did not start (${options.started}); client settings were left unchanged`);
  }
  if (!isRouterCodeIdentity(target.codeIdentity)) throw new Error("The expected router code identity is invalid");
  const now = deps.now ?? (() => performance.now());
  const sleep = deps.sleep ?? (ms => delay(ms));
  const readinessMs = options.readinessMs ?? 15_000;
  if (!Number.isSafeInteger(readinessMs) || readinessMs <= 0 || readinessMs > 60_000) throw new Error("Invalid installation readiness budget");
  const read = async (waitForStartup: boolean, requireTarget = false): Promise<RuntimeProof> => {
    const deadline = now() + readinessMs;
    while (true) {
      const remaining = Math.max(1, Math.ceil(deadline - now()));
      let raw: unknown;
      try { raw = await deps.status(AbortSignal.timeout(Math.min(10_000, remaining))); }
      catch { raw = null; }
      if (raw !== null && raw !== undefined) {
        const proof = ownedStatus(raw, deps.installationId());
        if (now() <= deadline && (!requireTarget || matchesTarget(proof, target))) return proof;
      }
      if (!waitForStartup || now() >= deadline) {
        throw new Error(requireTarget
          ? "The restarted router is not running the expected code; client settings were left unchanged"
          : "Secure router identity is unavailable. Exit a known older installation using its own controls, then retry; client settings were left unchanged");
      }
      await sleep(Math.min(250, Math.max(1, deadline - now())));
    }
  };
  let proof = await read(options.started !== "already-running");
  if (!matchesTarget(proof, target)) {
    const beforeRestart = proof;
    const result = await deps.restart();
    deps.onRestart?.(result);
    if (!["drained", "kickstarted", "direct"].includes(result)) {
      throw new Error(`The verified router could not be switched to this code (${result}); client settings were left unchanged`);
    }
    proof = await read(true, true);
    if (proof.installId !== beforeRestart.installId ||
        (proof.pid === beforeRestart.pid && proof.startedAt === beforeRestart.startedAt)) {
      throw new Error("The restart did not produce a newly verified instance of this installation; client settings were left unchanged");
    }
  }
  const probe = await options.probe();
  options.onProbe?.(probe);
  if (!probe.ok) throw new Error("The end-to-end proxy probe failed; client settings were left unchanged");
  const finalProof = await read(false, true);
  if (finalProof.installId !== proof.installId || finalProof.pid !== proof.pid || finalProof.startedAt !== proof.startedAt) {
    throw new Error("The router instance changed during installation; client settings were left unchanged");
  }
  // Last synchronous operation before the settings edit. In particular, a source update while
  // the final authenticated status was awaited must not inherit an earlier disk check.
  if (!sameRouterCodeIdentity(deps.captureIdentity(), target.codeIdentity)) {
    throw new Error("The source or runtime files changed during installation; rebuild/retry before changing client settings");
  }
  return options.apply();
}
