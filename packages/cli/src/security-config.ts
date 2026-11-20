// Explicit, local-only approval bootstrap. It works before the router is installed, so an
// empty outbound allowlist never creates a dependency on an unauthenticated browser dashboard.
import { normalizeConfig, validate, type Config } from "../../router/src/config.ts";
import { withFileLock, writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { approvedOrigin, personalMode, personalPolicyProblems } from "../../router/src/personal-policy.ts";
import { readPrivateFile } from "../../router/src/private-file.ts";

export const SECURITY_USAGE = "usage: clauderipple security approve-origin <https-origin> --acknowledge-data-sharing\n       clauderipple security revoke-origin <https-origin>";

export function updateApprovedOrigin(options: {
  file: string;
  action: "approve-origin" | "revoke-origin";
  origin: string;
  acknowledgeDataSharing?: boolean;
}): { origin: string; changed: boolean; approvedOrigins: string[] } {
  const origin = approvedOrigin(options.origin);
  if (!origin) throw new Error("Use one exact HTTPS origin, with no path, credentials, query, fragment or wildcard");
  if (options.action !== "approve-origin" && options.action !== "revoke-origin") throw new Error(SECURITY_USAGE);
  if (options.action === "approve-origin" && options.acknowledgeDataSharing !== true) {
    throw new Error("Approval permits sensitive request data and credentials to be sent to this origin. Add --acknowledge-data-sharing only after checking its owner and privacy terms");
  }
  return withFileLock(options.file, () => {
    let parsed: Partial<Config> = {};
    try {
      const value: unknown = JSON.parse(readPrivateFile(options.file).toString("utf8"));
      if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Invalid configuration");
      parsed = value as Partial<Config>;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== "ENOENT") throw new Error("The existing configuration is unreadable or invalid; no approvals were changed");
    }
    const current = normalizeConfig(parsed);
    if (!current.security || personalPolicyProblems(current.security).length || validate(current).length) {
      throw new Error("The existing configuration has validation errors; no approvals were changed");
    }
    const before = current.security.approvedOrigins;
    const next = options.action === "approve-origin" ? [...new Set([...before, origin])] : before.filter(item => item !== origin);
    const security = { mode: "personal" as const, approvedOrigins: next };
    if (personalPolicyProblems(security).length) throw new Error("At most 32 exact origins may be approved");
    const changed = next.length !== before.length;
    if (changed || parsed.security === undefined) writeSecretJsonAtomic(options.file, { ...current, security });
    return { origin, changed, approvedOrigins: [...next] };
  });
}

/** Cleanup stays available. Data-sharing activation and replacement executable downloads do not. */
export function assertPersonalCliCommandAllowed(config: Pick<Config, "security">, argv: string[]): void {
  if (!personalMode(config)) return;
  if (argv[0] === "login" || argv[0] === "claude-login") {
    throw new Error("Separate subscription sign-in is disabled in personal mode; keep the existing Claude Desktop login and configure a Google AI Studio API key in Providers");
  }
  if (["codex", "mod", "agent-title"].includes(argv[0] ?? "") && argv[1] === "on") {
    throw new Error("Non-Desktop integration activation is disabled in personal mode; explicit cleanup remains available");
  }
  if (argv[0] === "tray" && argv.some((arg, index) =>
    arg === "--login=on" || arg === "--login=init" ||
    ((arg === "--login" || arg === "-login") && (argv[index + 1] === "on" || argv[index + 1] === "init")))) {
    throw new Error("Setup-window autostart is disabled in personal mode; open it on demand");
  }
  if (argv[0] === "google-login") {
    throw new Error("Google subscription sign-in is disabled in personal mode; use a Google API-key provider or your approved university API endpoint");
  }
  if (argv[0] === "remote" && !["status", "hosts", "uninstall", "remove"].includes(argv[1] ?? "")) {
    throw new Error("Remote/SSH/phone activation is disabled in personal mode. Local status and explicit removal remain available");
  }
  if (argv[0] === "update" && !argv.includes("--check")) {
    throw new Error("Executable updates are disabled in personal mode. Keep the reviewed source commit; explicitly review and install a new pinned checkout when needed");
  }
}
