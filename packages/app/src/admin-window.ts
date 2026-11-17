import { createHash } from "node:crypto";
import path from "node:path";
import fs from "node:fs";
import { applyWindowsPrivateAcl } from "./windows-private-acl.ts";

/** The CLI passes only a view enum, never a capability or arbitrary renderer URL. */
export function adminViewFromArgs(args: readonly string[]): "mod" | "health" | undefined {
  if (args.includes("--ripple-admin-view=mod")) return "mod";
  if (args.includes("--ripple-admin-view=dashboard")) return "health";
  return undefined;
}

/** Separate installations must not reuse another home's Electron lock, renderer or capability. */
export function adminUserDataPath(appData: string, home: string): string {
  const canonicalHome = path.resolve(home);
  // Windows can enable case-sensitive directories. Keep spelling distinct rather than merging
  // two genuinely different homes into one privileged window; aliases may safely get two profiles.
  const digest = createHash("sha256").update(canonicalHome).digest("hex").slice(0, 32);
  return path.join(appData, "ClaudeRipple", `installation-${digest}`);
}

/** Electron setPath requires an existing directory. A profile may contain sensitive rendered data. */
export function prepareAdminUserDataPath(directory: string): string {
  if (!path.isAbsolute(directory)) throw new Error("Electron profile must be an absolute private directory");
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error("Electron profile must be a private directory without an alias");
  if (process.platform === "win32") applyWindowsPrivateAcl(directory, true);
  else if ((typeof process.getuid === "function" && stat.uid !== process.getuid()) || (stat.mode & 0o077) !== 0) {
    throw new Error("Electron profile must belong to the current user with owner-only permissions");
  }
  return directory;
}
