// An ordinary browser cannot pin a private local TLS identity. Open an already installed native
// dashboard instead, with no token URL and no automatic download, build, or ad-hoc signing.
import fs from "node:fs";
import path from "node:path";
import { spawn, type ChildProcess, type SpawnOptions } from "node:child_process";
import { electronPath, trayEnv } from "./tray.ts";
import { runtime, type Runtime } from "./runtime.ts";

export type AdminView = "dashboard" | "mod";
export const NATIVE_UI_REMEDIATION = "The native ClaudeRipple dashboard is unavailable. Install the ClaudeRipple desktop app, or explicitly run `clauderipple tray --install`, then run `clauderipple ui`. No browser capability was opened.";
export type NativeUiResult = { ok: boolean; message: string };
type NativeUiDeps = {
  rt?: Runtime;
  electron?: (home: string) => string | null;
  exists?: (file: string) => boolean;
  spawn?: (file: string, args: string[], options: SpawnOptions) => ChildProcess;
};

export async function openNativeDashboard(home: string, view: AdminView = "dashboard", deps: NativeUiDeps = {}): Promise<NativeUiResult> {
  if (!path.isAbsolute(home) || /[\0\r\n]/.test(home) || !["dashboard", "mod"].includes(view)) {
    return { ok: false, message: "Invalid native dashboard launch request" };
  }
  const rt = deps.rt ?? runtime();
  const exists = deps.exists ?? ((file: string) => {
    try { return fs.statSync(file).isFile(); } catch { return false; }
  });
  const executable = rt.packaged ? rt.node : (deps.electron ?? electronPath)(home);
  const args = rt.packaged ? [] : [rt.trayMain];
  if (!executable || !path.isAbsolute(executable) || !exists(executable) ||
      args.some((file) => !path.isAbsolute(file) || !exists(file))) {
    return { ok: false, message: NATIVE_UI_REMEDIATION };
  }
  args.push(`--ripple-admin-view=${view}`);
  const env = { ...trayEnv(), CLAUDERIPPLE_HOME: path.resolve(home), CLAUDERIPPLE_APP_SHOW: "1" };
  try {
    return await new Promise<NativeUiResult>((resolve) => {
      const child = (deps.spawn ?? spawn)(executable, args, {
        detached: true, stdio: "ignore", env, windowsHide: true,
      });
      child.once("error", () => resolve({ ok: false, message: NATIVE_UI_REMEDIATION }));
      child.once("spawn", () => {
        child.unref();
        resolve({ ok: true, message: "Opening the native ClaudeRipple dashboard" });
      });
    });
  } catch {
    return { ok: false, message: NATIVE_UI_REMEDIATION };
  }
}
