// `clauderipple update`: bring this installation to the latest published version, the way it
// was installed.
//
// Until now an update meant running the install command again by hand, and the tray could not
// offer it (#39). What "again" means depends on how ClaudeRipple arrived:
//   * The install scripts put it under their own prefix (~/.clauderipple by default) with their own
//     command shims — a wrapper naming the Node they downloaded, and on Windows no .ps1. A plain
//     `npm install -g` would put npm's default shims back, which find no Node on a machine where
//     the script's Node is the only one. So a script install is updated by running the installer
//     bundled with the already-installed package. It is never fetched from a moving Git branch.
//   * An `npm install -g` is updated by npm, into the same prefix.
//   * A packaged app or a source checkout is not updated from here.
// Either way `install` runs afterwards from the new files; it restarts a router still running
// the old version, which re-running the installer never did before.

import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { windowsPowerShellEnv } from "./windows-powershell.ts";
import type { Runtime } from "./runtime.ts";

export const PACKAGE = "clauderipple";
const VERSION_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;

function isVersion(value: unknown): value is string {
  if (typeof value !== "string" || value !== value.trim() || value.length > 200) return false;
  const match = VERSION_PATTERN.exec(value);
  if (!match || match.slice(1, 4).some((part) => !Number.isSafeInteger(Number(part)))) return false;
  // npm can interpret a malformed version as a mutable dist-tag. Numeric prerelease identifiers
  // with leading zeroes and empty identifiers therefore must not pass as version pins.
  return !match[4] || match[4].split(".").every((part) => !/^\d+$/.test(part) || part === "0" || !part.startsWith("0"));
}

export type InstallKind =
  | { kind: "script"; prefix: string }
  | { kind: "npm"; prefix: string }
  | { kind: "packaged" }
  | { kind: "checkout" }
  | { kind: "unknown"; root: string };

/** Numeric x.y.z comparison; a pre-release suffix is ignored. */
export function isNewer(latest: string, current: string): boolean {
  const parse = (v: string) => v.replace(/^v/, "").split("-")[0]!.split(".").map((n) => Number(n) || 0);
  const a = parse(latest);
  const b = parse(current);
  for (let i = 0; i < 3; i++) {
    if ((a[i] ?? 0) !== (b[i] ?? 0)) return (a[i] ?? 0) > (b[i] ?? 0);
  }
  return false;
}

/** The default prefix of both install scripts, or the one they were told to use. */
export function scriptPrefix(env: NodeJS.ProcessEnv = process.env, home = os.homedir()): string {
  return env.CLAUDERIPPLE_PREFIX || path.join(home, ".clauderipple");
}

/**
 * How the running copy was installed, read from where its files are. A global npm package lives
 * at <prefix>/lib/node_modules/<name> on macOS and Linux and <prefix>\node_modules\<name> on Windows.
 */
export function installKind(rt: Pick<Runtime, "packaged" | "cli" | "repo">, opts: { platform?: NodeJS.Platform; env?: NodeJS.ProcessEnv; home?: string; stateHome?: string } = {}): InstallKind {
  if (rt.packaged) return { kind: "packaged" };
  if (rt.cli.endsWith(".ts")) return { kind: "checkout" };
  const p = (opts.platform ?? process.platform) === "win32" ? path.win32 : path.posix;
  const root = rt.repo;
  const modules = p.dirname(root);
  if (p.basename(modules) !== "node_modules") return { kind: "unknown", root };
  const parent = p.dirname(modules);
  const prefix = (opts.platform ?? process.platform) === "win32" ? parent : p.basename(parent) === "lib" ? p.dirname(parent) : null;
  if (!prefix) return { kind: "unknown", root };
  const same = (a: string, b: string) => (opts.platform ?? process.platform) === "win32" ? p.resolve(a).toLowerCase() === p.resolve(b).toLowerCase() : p.resolve(a) === p.resolve(b);
  const record = p.join(prefix, "clauderipple-install.json");
  if (fs.existsSync(record)) {
    const installed = JSON.parse(fs.readFileSync(record, "utf8")) as { kind?: string; prefix?: string };
    if ((installed.kind === "script" || installed.kind === "npm") && installed.prefix && same(installed.prefix, prefix)) {
      return { kind: installed.kind, prefix };
    }
  }
  const stateHome = opts.stateHome ?? (opts.env ?? process.env).CLAUDERIPPLE_HOME ?? p.join(opts.home ?? os.homedir(), ".clauderipple");
  const pathsFile = p.join(stateHome, "paths.json");
  if (fs.existsSync(pathsFile)) {
    const saved = JSON.parse(fs.readFileSync(pathsFile, "utf8")) as { repo?: string; install?: { kind?: string; prefix?: string } };
    if (saved.repo && same(saved.repo, root) && saved.install?.prefix && same(saved.install.prefix, prefix) && (saved.install.kind === "script" || saved.install.kind === "npm")) {
      return { kind: saved.install.kind, prefix };
    }
  }
  return same(prefix, scriptPrefix(opts.env, opts.home)) ? { kind: "script", prefix } : { kind: "npm", prefix };
}

/**
 * npm puts a clauderipple.ps1 next to clauderipple.cmd, and PowerShell picks it first — but the
 * default execution policy runs no .ps1, so `clauderipple` failed with PSSecurityException (#38 for
 * a script install, #62 for `npm install -g`). Without it PowerShell falls through to the .cmd,
 * which runs under any policy. Every npm install writes it again, so `install`, which every update
 * ends with, removes it. Returns the file removed.
 */
export function dropPowerShellShim(kind: InstallKind, platform: NodeJS.Platform = process.platform): string | null {
  if (platform !== "win32" || (kind.kind !== "npm" && kind.kind !== "script")) return null;
  const ps1 = path.join(kind.prefix, `${PACKAGE}.ps1`);
  if (!fs.existsSync(path.join(kind.prefix, `${PACKAGE}.cmd`)) || !fs.existsSync(ps1)) return null;
  try {
    fs.rmSync(ps1);
    return ps1;
  } catch {
    return null;
  }
}

/** The version npm would install now. */
export async function latestVersion(fetchImpl: typeof fetch = fetch): Promise<string> {
  const res = await fetchImpl(`https://registry.npmjs.org/${PACKAGE}/latest`, { redirect: "error", signal: AbortSignal.timeout(10_000), headers: { accept: "application/json" } });
  if (!res.ok) throw new Error(`npm registry answered HTTP ${res.status}`);
  const version = ((await res.json()) as { version?: unknown }).version;
  if (!isVersion(version)) throw new Error("npm registry answered without a valid, pinned version");
  return version;
}

/** The npm that came with the Node running us, as a script that same Node can run. */
function npmCli(node: string = process.execPath): string | null {
  const candidates = [
    path.resolve(path.dirname(node), "../lib/node_modules/npm/bin/npm-cli.js"),
    path.resolve(path.dirname(node), "node_modules/npm/bin/npm-cli.js"),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

/**
 * Installs `spec` over this installation and runs `install` from the new files. Output goes to
 * our stdout as it happens, so the tray's dialog and a terminal show the installer's own lines.
 */
type UpdateRunner = (program: string, args: string[], opts: { env: NodeJS.ProcessEnv; stdio: "inherit"; windowsHide?: boolean }) => { status: number | null; signal?: NodeJS.Signals | null };

/** The build puts both reviewed installers alongside dist/cli, inside the published package. */
export function bundledInstaller(cli: string, platform: NodeJS.Platform = process.platform): string {
  return path.resolve(path.dirname(cli), "../../installers", platform === "win32" ? "install.ps1" : "install.sh");
}

export function runUpdate(target: InstallKind & { kind: "script" | "npm" }, rt: Pick<Runtime, "node" | "env" | "cli">, spec: string, opts: { run?: UpdateRunner; platform?: NodeJS.Platform; tempDir?: string; npmCli?: string } = {}): { ok: boolean; message: string } {
  const run = opts.run ?? spawnSync;
  // Only the exact package/version observed by the check can be installed. Tags, alternate
  // packages, URLs and tarballs would create a second update trust path.
  if (!spec.startsWith(`${PACKAGE}@`) || !isVersion(spec.slice(PACKAGE.length + 1))) {
    return { ok: false, message: "resolve a specific ClaudeRipple version before updating" };
  }
  const env = { ...process.env, ...rt.env, CLAUDERIPPLE_PREFIX: target.prefix, CLAUDERIPPLE_PACKAGE: spec };
  if (target.kind === "script") {
    const platform = opts.platform ?? process.platform;
    const source = bundledInstaller(rt.cli, platform);
    let script: Buffer;
    try {
      const before = fs.lstatSync(source);
      if (!before.isFile() || before.nlink !== 1) throw new Error("installer is not a singly linked regular file");
      const fd = fs.openSync(source, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
      try {
        const opened = fs.fstatSync(fd);
        if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino || opened.size > 1024 * 1024) throw new Error("installer changed or is not a bounded regular file");
        script = fs.readFileSync(fd);
      } finally { fs.closeSync(fd); }
      if (script.length === 0) throw new Error("installer is empty");
    } catch (error) {
      // Fail closed. Falling back to a remote installer would restore the original trust gap.
      return { ok: false, message: `the installed package has no usable bundled installer: ${(error as Error).message}; reinstall a verified release manually` };
    }
    // npm replaces the current package while the shell is reading the installer. A private copy
    // keeps that exact, already-installed script intact throughout the update.
    const temp = fs.mkdtempSync(path.join(opts.tempDir ?? os.tmpdir(), "clauderipple-update-"));
    const installer = path.join(temp, path.basename(source));
    try {
      fs.writeFileSync(installer, script, { flag: "wx", mode: 0o600 });
      const result = platform === "win32"
        ? run("powershell.exe", ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", installer], { env: windowsPowerShellEnv(env), stdio: "inherit", windowsHide: true })
        : run("sh", [installer], { env, stdio: "inherit" });
      // The bundled script reinstates the pinned-Node wrappers and runs `install` afterwards.
      return result.status === 0 ? { ok: true, message: "✓ updated" } : { ok: false, message: `the installer exited with ${result.status ?? result.signal}` };
    } finally {
      fs.rmSync(temp, { recursive: true, force: true });
    }
  }
  const npm = opts.npmCli ?? npmCli(rt.node);
  if (!npm) return { ok: false, message: `found no npm next to ${rt.node}; install a verified ClaudeRipple release manually` };
  // The shipped package and its production dependencies need no install lifecycle hooks. Run
  // only our explicit setup step, after npm has checked the registry's package integrity.
  const installed = run(rt.node, [npm, "install", "--global", "--prefix", target.prefix, "--registry", "https://registry.npmjs.org", "--ignore-scripts", "--loglevel", "error", spec], { env, stdio: "inherit" });
  if (installed.status !== 0) return { ok: false, message: `npm could not install ${spec}` };
  const setup = run(rt.node, [rt.cli, "install"], { env: { ...process.env, ...rt.env }, stdio: "inherit" });
  return setup.status === 0 ? { ok: true, message: "✓ updated" } : { ok: false, message: "the new version is installed, but `clauderipple install` did not finish" };
}
