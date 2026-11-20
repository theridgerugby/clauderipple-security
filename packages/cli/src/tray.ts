// The menu-bar / tray app, started from the CLI.
//
// Installed from npm there is no application bundle to double-click. Electron supplies the tray,
// and npm fetches the binary already built for this platform — but it is 270MB, which is not
// something to hand every person who only wants the router. So it is not a dependency: the tray
// command fetches it on request, once. Inside a packaged app the bundle is the Electron binary,
// so the same command simply relaunches it.

import { createRequire } from "node:module";
import { execFileSync, spawn, spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

import { homeDir } from "../../router/src/config.ts";
import { bundleIdOf, findIcon } from "./launcher.ts";
import { runtime } from "./runtime.ts";

/** Electron version to fetch on request. Kept in step with the one the app is developed against. */
export const ELECTRON_VERSION = "45.3.3";

/**
 * Where Electron is fetched to: ClaudeRipple's home, not the package. Until 0.6 it went into the
 * installed package's own node_modules, and every update replaced that folder — measured
 * 2026-09-28, `npm install -g` of another version left no trace of it, so the tray was gone after
 * each update, and on Windows a running tray held electron.exe inside the folder being replaced.
 */
export function trayRuntimeDir(): string {
  return path.join(homeDir(), "tray-runtime");
}

/** The electron package exports the path to its binary as its module value. */
function resolveElectron(from: string): string | null {
  try {
    const value = createRequire(from)("electron") as unknown;
    return typeof value === "string" && fs.existsSync(value) ? value : null;
  } catch {
    return null;
  }
}

/** The Electron executable to run the tray with, or null when none has been fetched. */
export function electronPath(home: string = homeDir()): string | null {
  // A checkout or an install from before 0.6 resolves it next to us.
  return resolveElectron(path.join(home, "tray-runtime", "package.json")) ?? resolveElectron(import.meta.url);
}

/** Our own name, identifier and icon for the tray's bundle. */
export const TRAY_BUNDLE_ID = "com.clauderipple.tray";
const TRAY_BUNDLE_NAME = "ClaudeRipple";
const TRAY_ICON = "icon.icns";

/**
 * macOS shows a bundle's own name and icon while its app is not running, and the Dock keeps a
 * pinned item by bundle path. npm's Electron.app is named Electron and carries the atom, so a
 * ClaudeRipple pinned while the tray was stopped showed Electron's icon; the running app could only
 * paint ours over the atom (2026-10-20, reported again 2026-10-26). The tray therefore runs a
 * renamed copy of it, as electron-packager makes one: our name and identifier in Info.plist, our
 * icon.icns, ad-hoc signed.
 *
 * The copy lives at the top of the fetched runtime (`tray-runtime/ClaudeRipple.app`), not inside
 * npm's `node_modules`, so no package manager sees it. It is built in the staging folder before the
 * B15 swap, which recreates it on every refresh — a hand-made bundle would otherwise disappear with
 * the old runtime, which is why the icon came back as Electron before.
 */

/** The app bundle that encloses an executable such as `…/Electron.app/Contents/MacOS/Electron`. */
export function enclosingApp(executable: string): string | null {
  const macos = path.dirname(executable);
  const contents = path.dirname(macos);
  const app = path.dirname(contents);
  if (path.basename(macos) !== "MacOS" || path.basename(contents) !== "Contents") return null;
  return app.endsWith(".app") ? app : null;
}

/** Where our bundle sits in a tray runtime folder. */
export function trayBundleApp(runtimeDir = trayRuntimeDir()): string {
  return path.join(runtimeDir, `${TRAY_BUNDLE_NAME}.app`);
}

function plistValue(plist: string, key: string): string | null {
  return new RegExp(`<key>${key}</key>\\s*<string>([^<]*)</string>`).exec(plist)?.[1] ?? null;
}

function setPlistValue(plist: string, key: string, value: string): string {
  const pattern = new RegExp(`(<key>${key}</key>\\s*<string>)[^<]*(</string>)`);
  return pattern.test(plist) ? plist.replace(pattern, `$1${value}$2`) : plist;
}

/** Electron's Info.plist under our name. Everything else (executable name, minimum system) stays. */
export function trayBundlePlist(plist: string, icon: boolean): string {
  let out = plist;
  for (const key of ["CFBundleName", "CFBundleDisplayName"]) out = setPlistValue(out, key, TRAY_BUNDLE_NAME);
  out = setPlistValue(out, "CFBundleIdentifier", TRAY_BUNDLE_ID);
  if (icon) out = setPlistValue(out, "CFBundleIconFile", TRAY_ICON);
  return out;
}

/** A clone when the file system can make one (instant for Electron's 250MB), a copy otherwise. */
function copyApp(from: string, to: string): void {
  try {
    execFileSync("/bin/cp", ["-cR", from, to], { stdio: "ignore" });
  } catch {
    fs.rmSync(to, { recursive: true, force: true });
    fs.cpSync(from, to, { recursive: true });
  }
}

/**
 * Re-signs the copy ad-hoc. Changing Info.plist and adding our icon invalidates Electron's own
 * signature, and macOS refuses to start an app whose nested code no longer matches, so the whole
 * bundle is signed again (`--deep` reaches the helpers and frameworks).
 */
function signApp(app: string): void {
  execFileSync("/usr/bin/codesign", ["--force", "--deep", "--sign", "-", app], { stdio: "ignore" });
}

export type TrayBundleBuilt = { ok: true; executable: string } | { ok: false; message: string };

type BundleOps = {
  /** Copies the source bundle; injected in tests so they need no real Electron. */
  copy?: (from: string, to: string) => void;
  /** Signs the finished bundle; injected in tests so no real signature is made. */
  sign?: (app: string) => void;
};

/**
 * Builds the tray's bundle from the Electron at `electron` into `app`. A bundle left half made is
 * removed, so the tray falls back to the plain Electron instead of starting a broken copy.
 */
export function buildTrayBundle(
  opts: { electron: string; app: string; icon: string | null },
  ops: BundleOps = {},
): TrayBundleBuilt {
  const source = enclosingApp(opts.electron);
  if (!source) return { ok: false, message: `${opts.electron} is not inside a macOS app bundle` };
  try {
    fs.rmSync(opts.app, { recursive: true, force: true });
    (ops.copy ?? copyApp)(source, opts.app);
    const contents = path.join(opts.app, "Contents");
    const plistPath = path.join(contents, "Info.plist");
    const plist = fs.readFileSync(plistPath, "utf8");
    const executable = plistValue(plist, "CFBundleExecutable");
    if (!executable) throw new Error(`${plistPath} names no CFBundleExecutable`);
    const named = trayBundlePlist(plist, opts.icon !== null);
    if (plistValue(named, "CFBundleIdentifier") !== TRAY_BUNDLE_ID) throw new Error(`${plistPath} has no CFBundleIdentifier to change`);
    fs.writeFileSync(plistPath, named);
    if (opts.icon) {
      fs.mkdirSync(path.join(contents, "Resources"), { recursive: true });
      fs.copyFileSync(opts.icon, path.join(contents, "Resources", TRAY_ICON));
    }
    (ops.sign ?? signApp)(opts.app);
    return { ok: true, executable: path.join(contents, "MacOS", executable) };
  } catch (error) {
    try { fs.rmSync(opts.app, { recursive: true, force: true }); } catch { /* the next start rebuilds it */ }
    return { ok: false, message: (error as Error).message };
  }
}

/** The executable a bundle names in its Info.plist, or null when it cannot be read. */
function bundleExecutable(app: string): string | null {
  try {
    const name = plistValue(fs.readFileSync(path.join(app, "Contents", "Info.plist"), "utf8"), "CFBundleExecutable");
    return name ? path.join(app, "Contents", "MacOS", name) : null;
  } catch {
    return null;
  }
}

export type TrayBundleState = { ok: true; executable: string } | { ok: false; message: string } | null;

/**
 * The executable the tray should run: our bundle once there is one, built now if the runtime came
 * from a version that did not make one. Null when this platform has no Dock to name (Windows,
 * Linux) or the Electron is not the fetched runtime's (a checkout runs its own).
 */
export function ensureTrayBundle(
  electron: string,
  opts: { platform?: NodeJS.Platform; runtimeDir?: string; icon?: string | null; build?: typeof buildTrayBundle } = {},
): TrayBundleState {
  if ((opts.platform ?? process.platform) !== "darwin") return null;
  const dir = opts.runtimeDir ?? trayRuntimeDir();
  if (!path.resolve(electron).startsWith(`${path.resolve(dir)}${path.sep}`)) return null;
  const app = trayBundleApp(dir);
  const built = bundleExecutable(app);
  if (built && bundleIdOf(app) === TRAY_BUNDLE_ID && fs.existsSync(built)) return { ok: true, executable: built };
  const icon = opts.icon === undefined ? findIcon(runtime(), TRAY_ICON) : opts.icon;
  return (opts.build ?? buildTrayBundle)({ electron, app, icon });
}

export type TrayStart = { ok: boolean; message: string };

/**
 * Our environment without ELECTRON_RUN_AS_NODE, so Electron starts as the tray rather than as a
 * plain Node process. The variable has to be removed, not emptied: macOS Electron reads an empty
 * value as unset, but Windows Electron only asks whether it exists, so an empty one ran the tray
 * as Node — it exited at once and no icon ever appeared (measured 2026-09-24, Electron 38,
 * Windows 11; issue #8).
 */
export function trayEnv(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const out = { ...env };
  // Neither inherited Electron logging nor Chromium's SSL-key log belongs in a personal
  // dashboard. Clearing the child's copy leaves the caller's environment unchanged.
  const removed = new Set(["ELECTRON_RUN_AS_NODE", "ELECTRON_ENABLE_LOGGING", "ELECTRON_LOG_FILE", "SSLKEYLOGFILE"]);
  for (const name of Object.keys(out)) if (removed.has(name.toUpperCase())) delete out[name];
  return out;
}

/**
 * Starts the tray and returns once it has stayed up for a moment. `detached` outlives this
 * process, which is what a command typed in a terminal wants; the supervisor uses the foreground
 * form instead.
 */
export async function startTray(options: { detached?: boolean; atLogin?: boolean } = {}): Promise<TrayStart> {
  // Compatibility callers can still request the old login launch. This personal setup window
  // is strictly on demand; do not even locate or spawn Electron for a background login request.
  if (options.atLogin) return { ok: true, message: "✓ personal setup opens on demand; no login window started" };
  const current = runtime();
  const env = { ...trayEnv(), CLAUDERIPPLE_APP_SHOW: "1" };
  if (current.packaged) {
    // The packaged app IS the tray: relaunching its own binary with no script is what opens it.
    // Our own CLI runs under ELECTRON_RUN_AS_NODE here, and inheriting it would relaunch Node.
    const child = spawn(current.node, [], { detached: true, stdio: "ignore", env });
    child.unref();
    return { ok: true, message: "✓ tray started" };
  }
  const electron = electronPath();
  if (!electron) {
    return {
      ok: false,
      message: "the tray needs Electron, which is about 270MB and is not installed by default.\nFetch it once with: clauderipple tray --install",
    };
  }
  const main = current.trayMain;
  if (!fs.existsSync(main)) {
    return { ok: false, message: `the tray is not built: ${main} is missing (run: npm run build)` };
  }
  // macOS runs our own named bundle so the Dock shows ClaudeRipple, not Electron, even before the
  // tray has started (see the bundle block above). Everywhere else, and for a checkout's Electron,
  // this is null and the fetched binary runs as it always has.
  const bundle = ensureTrayBundle(electron);
  const executable = bundle?.ok ? bundle.executable : electron;
  // Native/renderer errors may reflect private content. Do not persist raw Electron output or
  // read historical logs back into a launch failure. Exit status remains an explicit signal.
  const child = spawn(executable, [main], {
    detached: options.detached ?? true,
    stdio: "ignore",
    // Electron would otherwise re-enter as a plain Node process, since that is how the CLI runs.
    env,
  });
  if (options.detached ?? true) child.unref();
  return earlyExit(child, null);
}

export function trayLogPath(): string {
  return path.join(homeDir(), "logs", "tray.log");
}

/** A tray that is still running after a moment has started; one that exits before then has not. */
export function earlyExit(child: ChildProcess, log: string | null, waitMs = 2_000): Promise<TrayStart> {
  return new Promise((resolve) => {
    // Not unref'd: the command has to stay up long enough to see the exit it is waiting for.
    const timer = setTimeout(() => resolve({ ok: true, message: "✓ tray started" }), waitMs);
    const failed = (detail: string) => {
      clearTimeout(timer);
      let tail = "";
      if (log !== null) {
        try { tail = fs.readFileSync(log, "utf8").trim().split(/\r?\n/).slice(-8).join("\n"); } catch { /* nothing logged */ }
      }
      resolve({ ok: false, message: log === null
        ? `the setup window exited at once (${detail}). Raw output was not saved. Run doctor --json from the reviewed checkout for recovery status.`
        : `the tray exited at once (${detail}). Its output is in ${log}${tail ? `:\n${tail}` : ""}` });
    };
    child.once("error", (error) => failed(error.message));
    child.once("exit", (code, signal) => {
      // A clean exit at once is a tray that found another one running (main.ts's single-instance lock).
      if (code === 0 && !signal) {
        clearTimeout(timer);
        resolve({ ok: true, message: "✓ tray is already running" });
      } else failed(signal ? `signal ${signal}` : `exit code ${code}`);
    });
  });
}

/** The npm that came with the Node running us, as a script we can hand to that same Node. */
function npmCli(): string | null {
  const candidates = [
    path.resolve(path.dirname(process.execPath), "../lib/node_modules/npm/bin/npm-cli.js"),
    path.resolve(path.dirname(process.execPath), "node_modules/npm/bin/npm-cli.js"),
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? null;
}

/**
 * The environment for npm children that fetch Electron. npm runs package lifecycle scripts through
 * a shell, and Electron's `node install.js` needs a bare `node` on PATH — the machines the tray is
 * for are exactly the ones where ClaudeRipple's own Node is the only Node, so the fetch failed with
 * "'node' is not recognized" (#80). The Node running us goes first; Windows spells the variable
 * `Path` or `PATH`, so either spelling is the one fixed.
 */
export function npmEnv(base: NodeJS.ProcessEnv = process.env, nodeDir = path.dirname(process.execPath)): NodeJS.ProcessEnv {
  const out = { ...base };
  const names = Object.keys(out).filter((name) => name.toUpperCase() === "PATH");
  const name = names[0] ?? "PATH";
  // Both spellings would be two variables in the child's environment block; keep the one and drop.
  for (const other of names.slice(1)) delete out[other];
  const current = out[name];
  out[name] = current ? `${nodeDir}${path.delimiter}${current}` : nodeDir;
  return out;
}

/** The Electron range the fetched tray runtime records, or null when there is no readable copy. */
export function trayRuntimeRange(dir = trayRuntimeDir()): string | null {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(dir, "package.json"), "utf8")) as { dependencies?: Record<string, string> };
    return pkg.dependencies?.electron ?? null;
  } catch {
    return null;
  }
}

/**
 * Whether the fetched Electron is the one this CLI asks for. An install from an older version is
 * never updated by `npm install` of ClaudeRipple itself: the runtime lives in the home folder, not
 * in the package (B15). A copy without the record cannot be proved current, so it is replaced.
 */
export function trayRuntimeMatches(range = ELECTRON_VERSION, dir = trayRuntimeDir()): boolean {
  return trayRuntimeRange(dir) === range;
}

export type RuntimeSwap = { ok: true } | { ok: false; message: string };

/**
 * Put a fully installed staging copy at `target`, keeping the working copy until the move works.
 * On Windows a running electron.exe holds its files: the rename then fails, and the old copy is
 * left exactly as it was rather than half-replaced (B15).
 */
export function swapTrayRuntime(target: string, staging: string, backup = `${target}.old-${process.pid}`): RuntimeSwap {
  if (!fs.existsSync(target)) {
    try { fs.renameSync(staging, target); return { ok: true }; }
    catch (error) { return { ok: false, message: `could not move the new Electron into ${target} (${(error as Error).message})` }; }
  }
  try {
    if (fs.existsSync(backup)) throw new Error(`backup path already exists: ${backup}`);
    fs.renameSync(target, backup);
  } catch (error) {
    return { ok: false, message: `the running tray still holds ${target}; quit it and run the update again (${(error as Error).message})` };
  }
  try { fs.renameSync(staging, target); }
  catch (error) {
    try { fs.renameSync(backup, target); } catch { /* the old copy is where it was */ }
    return { ok: false, message: `could not move the new Electron into ${target} (${(error as Error).message})` };
  }
  try { fs.rmSync(backup, { recursive: true, force: true }); } catch { /* left for the next refresh */ }
  return { ok: true };
}

/** Staging and backup folders an interrupted refresh left behind; a live tray's copy is untouched. */
function pruneTrayRuntimes(target = trayRuntimeDir()): void {
  const dir = path.dirname(target);
  const name = path.basename(target);
  let entries: string[];
  try { entries = fs.readdirSync(dir); } catch { return; }
  for (const entry of entries) {
    if (entry === name) continue;
    if (!entry.startsWith(`${name}.new-`) && !entry.startsWith(`${name}.old-`)) continue;
    try { fs.rmSync(path.join(dir, entry), { recursive: true, force: true }); } catch { /* in use: the next run */ }
  }
}

export type TrayInstallDeps = {
  /** The runtime folder to fill; tests use one of their own. */
  target?: string;
  /** The Electron this installation already has; tests pass null so the user's own is not seen. */
  existing?: string | null;
  /** Installs Electron into the staging folder and returns npm's exit status. */
  install?: (staging: string) => number | null;
  /** Builds the tray's bundle inside the staging folder. */
  bundle?: (electron: string, app: string) => TrayBundleBuilt;
  platform?: NodeJS.Platform;
};

type ElectronInstaller = (program: string, args: string[], options: { cwd: string; env: NodeJS.ProcessEnv; stdio: "inherit" }) => { status: number | null };

/** Fetch a version pin without dependency lifecycle hooks, then run only Electron's downloader. */
export function installElectronPackage(staging: string, npm: string, run: ElectronInstaller = spawnSync): number | null {
  const options = { cwd: staging, env: npmEnv(), stdio: "inherit" as const };
  const installed = run(process.execPath, [npm, "install", "--prefix", staging, "--no-package-lock", "--save-exact", "--registry", "https://registry.npmjs.org", "--ignore-scripts", "--loglevel", "error", `electron@${ELECTRON_VERSION}`], options);
  if (installed.status !== 0) return installed.status;
  // install.js is the explicitly reviewed entry point from this exact Electron package. npm's
  // other hooks, including transitive postinstall scripts, are never enabled for this fetch.
  return run(process.execPath, [path.join(staging, "node_modules", "electron", "install.js")], options).status;
}

/** Fetches Electron into this installation so the tray can run. Prints npm's own progress. */
export function installTrayRuntime(options: { refresh?: boolean } & TrayInstallDeps = {}): TrayStart {
  const target = options.target ?? trayRuntimeDir();
  // A refresh replaces a runtime an older ClaudeRipple fetched; without one, an existing copy is
  // what the tray runs and is left alone.
  const existing = options.existing === undefined ? electronPath() : options.existing;
  if (existing && (!options.refresh || trayRuntimeMatches(ELECTRON_VERSION, target))) return { ok: true, message: "✓ Electron is already installed" };
  const cli = npmCli();
  if (!cli && !options.install) return { ok: false, message: `found no npm next to ${process.execPath}; install Electron yourself: npm install electron` };
  // Into a copy of its own first: npm failing (offline, a locked file) must leave the tray runnable.
  const staging = `${target}.new-${process.pid}`;
  pruneTrayRuntimes(target);
  try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* nothing to clear */ }
  fs.mkdirSync(staging, { recursive: true });
  const status = options.install
    ? options.install(staging)
    : installElectronPackage(staging, cli!);
  if (status !== 0) {
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* left for the next run */ }
    return { ok: false, message: `npm could not install Electron into ${staging}` };
  }
  // Resolve the binary inside the staging tree before trusting the copy over the working one.
  const electron = resolveElectron(path.join(staging, "package.json"));
  if (!electron) {
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* left for the next run */ }
    return { ok: false, message: `npm reported success but Electron is not resolvable from ${staging}` };
  }
  // Built here, before the swap, so the next refresh makes a fresh one instead of losing it with
  // the old runtime. A failure is not fatal: the tray runs the plain Electron, as it always did.
  if ((options.platform ?? process.platform) === "darwin") {
    const app = trayBundleApp(staging);
    const built = (options.bundle ?? ((from: string, to: string) => buildTrayBundle({ electron: from, app: to, icon: findIcon(runtime(), TRAY_ICON) })))(electron, app);
    if (!built.ok) console.warn(`the tray will start as plain Electron: ${built.message}`);
  }
  const swapped = swapTrayRuntime(target, staging);
  if (!swapped.ok) {
    try { fs.rmSync(staging, { recursive: true, force: true }); } catch { /* left for the next run */ }
    return { ok: false, message: swapped.message };
  }
  return resolveElectron(path.join(target, "package.json"))
    ? { ok: true, message: "✓ Electron installed — start the tray with: clauderipple tray" }
    : { ok: false, message: `Electron is still not resolvable from ${target}` };
}
