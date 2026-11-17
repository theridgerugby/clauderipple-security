// The scheduled-task launcher needs one public liveness port, never the provider config itself.
// Read through the canonical private/DPAPI decoder in the installation's pinned Node runtime.
// The helper is deliberately read-only and emits at most five digits; no credential or parse
// error is returned to PowerShell or its launcher logs.
import path from "node:path";
import { adminPort, homeDir, normalizeConfig, validate, type Config } from "../../router/src/config.ts";
import { readPrivateFile } from "../../router/src/private-file.ts";
import type { SecretProtector } from "../../router/src/secret-storage.ts";

export function readWatchdogAdminPort(home: string = homeDir(), options: { protector?: SecretProtector } = {}): number {
  if (!path.isAbsolute(home) || /[\0\r\n]/.test(home) || /^(?:\\\\|\/\/)/.test(home)) return 0;
  try {
    let raw: unknown;
    try { raw = JSON.parse(readPrivateFile(path.join(home, "config.json"), undefined, options).toString("utf8")); }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") return 0;
      // The router itself uses the built-in defaults before a config exists.
      raw = {};
    }
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) return 0;
    const config = normalizeConfig(raw as Partial<Config>);
    if (validate(config).length !== 0) return 0;
    const port = adminPort(config);
    return Number.isSafeInteger(port) && port > 0 && port < 65536 ? port : 0;
  } catch { return 0; }
}

if (import.meta.main) process.stdout.write(String(readWatchdogAdminPort()));
