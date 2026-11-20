// A read-only inventory of this installation's native-Claude coupling. Router health and
// original-client independence are different claims. No probe sends an inference request,
// reads account credentials, trusts a certificate, changes settings, or controls a service.
import fs from "node:fs";
import path from "node:path";
import { X509Certificate } from "node:crypto";
import { execBounded } from "./bounded-exec.ts";
import { certPaths } from "./certs.ts";
import { sameHome } from "./ownership.ts";
import { caTrustedAsync, configLibraryDir } from "./picker.ts";
import type { SupervisorView } from "./registration.ts";
import { settingsPath } from "./settings.ts";
import { windowsPowerShellEnv } from "./windows-powershell.ts";

type JsonObject = Record<string, unknown>;
type State = "present" | "absent" | "unknown";
type Ownership = "this-installation" | "unverified-or-external" | "none";
export type IndependenceFinding = {
  state: State;
  effect: "traffic-dependency" | "trust-scope" | "saved-reactivation" | "background-resource";
  ownership: Ownership;
  detail: string;
};
export type NativeIndependenceReport = {
  schemaVersion: 1;
  scope: "installation-local-persisted-state";
  /** False with an observed traffic coupling; a file audit cannot prove live independence. */
  originalIndependent: false | null;
  /** Includes remaining trust, saved restoration and background resources, not just routing. */
  knownCouplingsAbsent: boolean | null;
  findings: Record<"sharedProxy" | "sharedCa" | "desktopProxy" | "desktopPac" | "trustedCa" | "savedRestoration" | "backgroundService" | "windowsWatchdog", IndependenceFinding>;
  limitations: string[];
};
export type DesktopAuditState = { meta: JsonObject; entry: JsonObject };
export type NativeIndependenceOptions = {
  home: string;
  proxyUrl: string;
  supervisor: SupervisorView;
  platform?: NodeJS.Platform;
  /** Dependency injection keeps tests away from real settings and certificate stores. */
  readSettings?: () => unknown;
  readDesktop?: () => DesktopAuditState;
  readRestoration?: () => unknown;
  readWatchdog?: () => string | undefined;
  trustedCa?: () => Promise<boolean | null>;
};

const MAX_FILE_BYTES = 1024 * 1024;
const PROXY_KEYS = ["https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"] as const;
const isObject = (value: unknown): value is JsonObject => !!value && typeof value === "object" && !Array.isArray(value);

/** Reject final-component symlinks and non-regular files; bound reads and redact parse errors. */
function readText(file: string): string | undefined {
  let before: fs.Stats;
  try { before = fs.lstatSync(file); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined; throw error; }
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1 || before.size > MAX_FILE_BYTES) throw new Error("uninspectable audit file");
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0));
  const unchanged = (stat: fs.Stats): boolean => stat.isFile() && stat.dev === before.dev && stat.ino === before.ino &&
    stat.nlink === 1 && stat.size === before.size && stat.mtimeMs === before.mtimeMs && stat.ctimeMs === before.ctimeMs;
  try {
    if (!unchanged(fs.fstatSync(fd))) throw new Error("audit file changed");
    const data = Buffer.alloc(before.size + 1);
    let size = 0;
    while (size < data.length) {
      const count = fs.readSync(fd, data, size, data.length - size, size);
      if (!count) break;
      size += count;
    }
    if (size !== before.size || !unchanged(fs.fstatSync(fd)) || !unchanged(fs.lstatSync(file))) throw new Error("audit file changed");
    return data.subarray(0, size).toString("utf8");
  } finally { fs.closeSync(fd); }
}

function readJson(file: string, emptyIsObject = false): unknown {
  const text = readText(file);
  if (text === undefined) return undefined;
  if (emptyIsObject && !text.trim()) return {};
  return JSON.parse(text);
}

function readDesktop(): DesktopAuditState {
  const dir = configLibraryDir();
  const meta = readJson(path.join(dir, "_meta.json"));
  if (meta === undefined) return { meta: {}, entry: {} };
  if (!isObject(meta)) throw new Error("uninspectable Desktop metadata");
  if (meta.appliedId === undefined || meta.appliedId === null) return { meta, entry: {} };
  if (typeof meta.appliedId !== "string" || !/^[a-zA-Z0-9][a-zA-Z0-9_-]{0,127}$/.test(meta.appliedId)) throw new Error("uninspectable Desktop entry");
  const entry = readJson(path.join(dir, `${meta.appliedId}.json`));
  if (!isObject(entry)) throw new Error("uninspectable Desktop entry");
  if (JSON.stringify(readJson(path.join(dir, "_meta.json"))) !== JSON.stringify(meta)) throw new Error("Desktop metadata changed");
  return { meta, entry };
}

/** Existing helper is read-only; make its swallowed errors and malformed counts explicit unknowns. */
async function inspectCa(caPem: string, platform: NodeJS.Platform): Promise<boolean | null> {
  let certificate: string;
  try {
    const pem = readText(caPem);
    if (!pem || !new X509Certificate(pem).ca) return null;
    certificate = pem;
  } catch { return null; }
  if (!["win32", "darwin", "linux"].includes(platform)) return null;
  let failed = false;
  const deadline = performance.now() + 3_000;
  const result = await caTrustedAsync(caPem, {
    platform,
    run: async (command, args) => {
      try {
        const timeoutMs = Math.ceil(deadline - performance.now());
        if (timeoutMs <= 0) throw new Error("audit deadline");
        const safeArgs = [...args];
        const commandIndex = safeArgs.indexOf("-Command");
        if (platform === "win32" && commandIndex >= 0) safeArgs[commandIndex + 1] = `$ErrorActionPreference = 'Stop'; ${safeArgs[commandIndex + 1]}`;
        const output = await execBounded(command, safeArgs, { timeoutMs, maxBuffer: 128 * 1024, env: windowsPowerShellEnv(), windowsHide: true });
        if (platform === "win32" && !/^\d+$/.test(output.trim())) throw new Error("unrecognized certificate count");
        return output;
      } catch { failed = true; throw new Error("certificate inspection unavailable"); }
    },
  });
  try { return failed || readText(caPem) !== certificate ? null : result; }
  catch { return null; }
}

function finding(state: State, effect: IndependenceFinding["effect"], ownership: Ownership, detail: string): IndependenceFinding {
  return { state, effect, ownership, detail };
}
function safePathMatch(value: unknown, wanted: string): boolean {
  return typeof value === "string" && path.isAbsolute(value) && path.resolve(value) === path.resolve(wanted);
}
function proxyMatch(value: unknown, wanted: string): boolean {
  if (typeof value !== "string") return false;
  try { return new URL(value).href === new URL(wanted).href; } catch { return false; }
}

export function nativeIndependenceSummary(report: NativeIndependenceReport): string {
  if (report.originalIndependent === false) return "Native Claude is still coupled to local proxy settings; a healthy router does not establish independence.";
  if (report.knownCouplingsAbsent === true) return "No known persisted coupling found; live Claude Desktop and CLI independence has not been verified.";
  if (report.knownCouplingsAbsent === false) return "No active owned traffic coupling was established, but trust, restoration or background effects remain; live independence is unverified.";
  return "Native independence is unknown because one or more local coupling checks could not be completed.";
}

export async function auditNativeIndependence(options: NativeIndependenceOptions): Promise<NativeIndependenceReport> {
  const platform = options.platform ?? process.platform;
  const caPem = certPaths(options.home).caPem;
  const absent = (effect: IndependenceFinding["effect"], detail: string): IndependenceFinding => finding("absent", effect, "none", detail);
  const unknown = (effect: IndependenceFinding["effect"], detail: string): IndependenceFinding => finding("unknown", effect, "unverified-or-external", detail);
  let sharedProxy = unknown("traffic-dependency", "Shared proxy settings could not be inspected.");
  let sharedCa = unknown("trust-scope", "Shared CA settings could not be inspected.");
  try {
    const settings = (options.readSettings ?? (() => readJson(settingsPath(), true)))() ?? {};
    if (!isObject(settings) || settings.env !== undefined && !isObject(settings.env)) throw new Error("settings shape");
    const env = (settings.env as JsonObject | undefined) ?? {};
    const caMatches = safePathMatch(env.NODE_EXTRA_CA_CERTS, caPem);
    const proxyValues = PROXY_KEYS.map(key => env[key]);
    const ownedTarget = proxyValues.some(value => proxyMatch(value, options.proxyUrl));
    const staleOwnedTarget = caMatches && proxyValues.some(value => typeof value === "string" && /^http:\/\/(127\.0\.0\.1|localhost|\[::1\]):\d+\/?$/.test(value));
    sharedProxy = ownedTarget
      ? finding("present", "traffic-dependency", caMatches ? "this-installation" : "unverified-or-external", "A shared Claude proxy setting targets this router; standalone CLI and IDE sessions can inherit it.")
      : staleOwnedTarget
        ? unknown("traffic-dependency", "A different loopback proxy is paired with this installation's CA; its target ownership was not inferred.")
      : proxyValues.some(value => value !== undefined && value !== "")
        ? unknown("traffic-dependency", "An external or unrecognized shared proxy setting exists; its ownership and effect were not inferred.")
        : absent("traffic-dependency", "No shared proxy value was found in the inspected settings file.");
    sharedCa = caMatches
      ? finding("present", "trust-scope", "this-installation", "The shared Claude settings reference this installation's CA.")
      : env.NODE_EXTRA_CA_CERTS !== undefined && env.NODE_EXTRA_CA_CERTS !== ""
        ? unknown("trust-scope", "A different or malformed shared CA setting exists; its contents were not inspected.")
        : absent("trust-scope", "No shared extra-CA value was found in the inspected settings file.");
  } catch { /* Fixed diagnostics never include malformed JSON, paths, provider keys or error text. */ }

  let desktopProxy = unknown("traffic-dependency", "Desktop's active proxy configuration could not be inspected.");
  let desktopPac = unknown("traffic-dependency", "Desktop's active PAC configuration could not be inspected.");
  try {
    const { meta, entry } = (options.readDesktop ?? readDesktop)();
    if (!isObject(meta) || !isObject(entry)) throw new Error("Desktop shape");
    const mark = isObject(meta.clauderipple) ? meta.clauderipple : {};
    const owned = typeof meta.appliedId === "string" && mark.ourId === meta.appliedId && typeof mark.installationHome === "string" && sameHome(mark.installationHome, options.home);
    const target = entry.egressProxyUrl;
    desktopProxy = proxyMatch(target, options.proxyUrl)
      ? finding("present", "traffic-dependency", owned ? "this-installation" : "unverified-or-external", "Desktop's active configuration names this installation's proxy; already-running clients can retain it until restart.")
      : target !== undefined
        ? unknown("traffic-dependency", "An external or unrecognized Desktop proxy exists; it was not claimed as this installation's.")
        : absent("traffic-dependency", "No fixed proxy was found in Desktop's active configuration.");
    desktopPac = entry.egressProxyPacUrl !== undefined
      ? unknown("traffic-dependency", "Desktop has a PAC configuration; the script was not fetched or evaluated.")
      : absent("traffic-dependency", "No PAC value was found in Desktop's active configuration.");
  } catch { /* Inspection failure is not absence. */ }

  let trustedCa = unknown("trust-scope", "This installation's exact CA identity or its current-user trust could not be verified.");
  try {
    const trusted = await (options.trustedCa ?? (() => inspectCa(caPem, platform)))();
    if (trusted === true) trustedCa = finding("present", "trust-scope", "this-installation", "This installation's CA is trusted for the current user; this is a trust-scope effect even when clients are direct.");
    else if (trusted === false) trustedCa = absent("trust-scope", "This installation's exact CA was not found trusted by the inspected current-user store.");
  } catch { /* Read failure or denial stays unknown. */ }

  let savedRestoration = unknown("saved-reactivation", "The saved direct-connection restoration state could not be inspected.");
  try {
    const saved = (options.readRestoration ?? (() => readJson(path.join(options.home, "direct.json"))))();
    if (saved === undefined) savedRestoration = absent("saved-reactivation", "No saved direct-connection restoration file was found.");
    else {
      if (!isObject(saved) || typeof saved.at !== "string" || !isObject(saved.cli) || !Object.values(saved.cli).every(value => typeof value === "string") ||
          saved.desktop !== null && (!isObject(saved.desktop) || typeof saved.desktop.egressProxyUrl !== "string" || saved.desktop.appliedAfter !== null && typeof saved.desktop.appliedAfter !== "string")) throw new Error("restoration shape");
      savedRestoration = Object.keys(saved.cli).length || saved.desktop !== null
        ? finding("present", "saved-reactivation", "this-installation", "A saved restoration snapshot can reapply proxy or other client settings through direct off; it does not by itself route current traffic.")
        : absent("saved-reactivation", "The saved restoration snapshot contains no client settings to reapply.");
    }
  } catch { /* Do not print snapshots, which can contain unexpected user-owned values. */ }

  const view = options.supervisor;
  const ownedService = typeof view.installedHome === "string" && sameHome(view.installedHome, options.home);
  const backgroundService = view.lookupError || view.state === "unknown"
    ? unknown("background-resource", "The service or its running state could not be inspected.")
    : view.registered || view.state === "running" || view.state === "loaded" || view.pid !== null
      ? finding(ownedService ? "present" : "unknown", "background-resource", ownedService ? "this-installation" : "unverified-or-external", ownedService
        ? "This installation has a registered or running background service; service presence alone does not prove native traffic uses it."
        : "A service is registered or running, but this installation's ownership was not established.")
      : absent("background-resource", "No registered or running service was reported by the inspected supervisor.");
  let windowsWatchdog = platform === "win32"
    ? unknown("background-resource", "Windows watchdog deployment could not be established.")
    : absent("background-resource", "The Windows watchdog does not apply on this platform.");
  if (platform === "win32" && backgroundService.state === "absent") {
    windowsWatchdog = absent("background-resource", "No Windows watchdog is registered through the inspected service; detached processes were not enumerated.");
  } else if (platform === "win32" && ownedService && view.registered && !view.lookupError) {
    try {
      const script = (options.readWatchdog ?? (() => readText(path.join(options.home, "clauderipple-router.ps1"))))();
      if (script?.includes("function Get-AdminPort") && script.includes("/api/ping") && script.includes("$watchdogLog")) {
        windowsWatchdog = finding("present", "background-resource", "this-installation", "The owned Windows service launcher contains watchdog logic; the watchdog's live execution was not observed.");
      }
    } catch { /* A missing or unfamiliar launcher is unknown, never an absent watchdog claim. */ }
  }
  const findings = { sharedProxy, sharedCa, desktopProxy, desktopPac, trustedCa, savedRestoration, backgroundService, windowsWatchdog };
  const values = Object.values(findings);
  return {
    schemaVersion: 1,
    scope: "installation-local-persisted-state",
    originalIndependent: values.some(value => value.state === "present" && value.effect === "traffic-dependency") ? false : null,
    knownCouplingsAbsent: values.some(value => value.state === "present") ? false : values.some(value => value.state === "unknown") ? null : true,
    findings,
    limitations: [
      "A local file audit cannot prove that already-running Desktop or CLI sessions have dropped cached settings; live client acceptance is still required.",
      "Project and managed settings, saved Desktop environments, OS proxy configuration, other installations and detached processes were not inventoried.",
      "This report contains no inference or billing test and does not certify arbitrary future Desktop updates.",
    ],
  };
}
