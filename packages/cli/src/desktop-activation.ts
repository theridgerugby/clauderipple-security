// The optional Desktop integration redirects the whole app. Verify before trusting a CA or
// changing its configuration, then compare the exact state again after each asynchronous step.
import fs from "node:fs";
import path from "node:path";
import { createHash, X509Certificate } from "node:crypto";
import { normalizeConfig, validate, type Config } from "../../router/src/config.ts";
import { assertApprovedDestination, personalMode } from "../../router/src/personal-policy.ts";
import { personalDesktopProblems } from "../../router/src/desktop-policy.ts";
import { personalPickerModelProblem } from "../../router/src/picker.ts";
import { readPrivateFile } from "../../router/src/private-file.ts";
import { withFileLock, writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { verifyAndApplyInstall, type InstallRuntimeDeps, type InstallRuntimeTarget } from "./install-runtime.ts";
import { appProxyFingerprint, checkAppProxyActivation, currentAppProxy, type CaRemoval } from "./picker.ts";
import { isNativeClaudeModel, MODEL_SLOT_ENV, settingsEnv } from "./settings.ts";
import type { ProbeResult } from "./probe.ts";

export type DesktopActivationState = {
  config: Config;
  env: Record<string, string>;
  desktop: ReturnType<typeof currentAppProxy>;
  desktopFingerprint: string;
  caFingerprint: string;
  direct: boolean;
};

function readConfig(file: string): { raw: Record<string, unknown>; config: Config } {
  try {
    const raw: unknown = JSON.parse(readPrivateFile(file).toString("utf8"));
    if (!raw || typeof raw !== "object" || Array.isArray(raw)) throw new Error("shape");
    const config = normalizeConfig(raw as Partial<Config>);
    if (validate(config).length) throw new Error("validation");
    return { raw: raw as Record<string, unknown>, config };
  } catch {
    // JSON errors can quote credential values. Keep the failure message independent of input.
    throw new Error("Desktop activation requires a readable, valid private configuration; no client settings were changed");
  }
}

export function readDesktopActivationState(file: string, home: string, caPem: string): DesktopActivationState {
  const caBytes = fs.readFileSync(caPem);
  const pem = caBytes.toString("utf8");
  if (!/^\s*-----BEGIN CERTIFICATE-----[\r\nA-Za-z0-9+/=]+-----END CERTIFICATE-----\s*$/.test(pem) || !new X509Certificate(caBytes).ca) {
    throw new Error("Desktop activation requires exactly this installation's single CA certificate");
  }
  return {
    config: readConfig(file).config, env: settingsEnv(), desktop: currentAppProxy(),
    desktopFingerprint: appProxyFingerprint(), caFingerprint: createHash("sha256").update(caBytes).digest("hex"),
    direct: fs.existsSync(path.join(home, "direct.json")),
  };
}

export function checkDesktopActivation(state: DesktopActivationState, proxyUrl: string, caPem: string): void {
  if (state.direct) throw new Error("Direct connection is enabled. Restore the verified integration before enabling the Desktop picker");
  if (state.env.HTTPS_PROXY !== proxyUrl || state.env.NODE_EXTRA_CA_CERTS !== caPem) {
    throw new Error("Claude Code's Desktop engine is not configured for this router and CA. Run the verified install/repair before enabling the picker");
  }
  if (!personalMode(state.config)) return;
  const cfg = state.config;
  for (const origin of ["https://api.anthropic.com", "https://claude.ai"]) assertApprovedDestination(origin, cfg.security!);
  const problems = personalDesktopProblems({ ...cfg, picker: { ...cfg.picker, enabled: true } });
  if (problems.length) throw new Error(problems.join("; "));
  if (!cfg.cli.extraModels.length) throw new Error("Select at least one separate Google/API model for the Desktop picker before enabling it");
  for (const entry of cfg.cli.extraModels) {
    const problem = personalPickerModelProblem(cfg, entry.model);
    if (problem) throw new Error(`Desktop model cannot be enabled: ${problem}`);
  }
  for (const name of ["ANTHROPIC_BASE_URL", "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"]) {
    if (state.env[name]) throw new Error(`${name} overrides native Claude subscription access; review that existing setting before enabling the Desktop picker`);
  }
  for (const name of [...Object.values(MODEL_SLOT_ENV), "ANTHROPIC_DEFAULT_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_FABLE_MODEL"]) {
    if (state.env[name] && !isNativeClaudeModel(state.env[name])) {
      throw new Error(`${name} replaces a native Claude slot; keep the extra API model in its own picker entry`);
    }
  }
  if (["CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX", "CLAUDE_CODE_USE_FOUNDRY"].some(name => state.env[name] === "1") ||
      state.env.NODE_TLS_REJECT_UNAUTHORIZED === "0" || state.env.NODE_OPTIONS) {
    throw new Error("Claude Code has a provider or TLS startup override; review the existing setting before enabling the Desktop picker");
  }
  const bypasses = [state.env.NO_PROXY ?? "", state.env.no_proxy ?? ""].join(",").toLowerCase().split(",").map(value => value.trim().replace(/^\./, "").replace(/:443$/, ""));
  if (bypasses.some(value => value === "*" || ["api.anthropic.com", "claude.ai"].some(host => value && (host === value || host.endsWith(`.${value}`))))) {
    throw new Error("NO_PROXY bypasses an intercepted Claude endpoint; review the existing setting before enabling the Desktop picker");
  }
}

/** Synchronous last step under the config lock. A failed Desktop write restores only our flag. */
export function commitDesktopPicker<T>(file: string, expected: Config, apply: () => T): T {
  return withFileLock(file, () => {
    const before = readConfig(file);
    if (JSON.stringify(before.config) !== JSON.stringify(expected)) throw new Error("Router configuration changed during Desktop activation; left untouched");
    const next = { ...before.raw, picker: { ...(before.raw.picker as Record<string, unknown> | undefined), enabled: true } };
    const nextConfig = normalizeConfig(next as Partial<Config>);
    if (validate(nextConfig).length) throw new Error("Desktop configuration no longer meets the personal policy; left untouched");
    try {
      if (!before.config.picker?.enabled) writeSecretJsonAtomic(file, next);
      return apply();
    } catch (error) {
      if (!before.config.picker?.enabled) {
        try {
          const current = readConfig(file).raw;
          if (JSON.stringify(current) === JSON.stringify(next)) writeSecretJsonAtomic(file, before.raw);
          else if (JSON.stringify(current) !== JSON.stringify(before.raw)) {
            throw new Error("concurrent edit");
          }
        } catch {
          throw new Error("Desktop activation failed; configuration changed or rollback failed. Existing edits were preserved. Review the owned direct-connection recovery", { cause: error });
        }
      }
      throw error;
    }
  });
}

export type DesktopActivationOptions<T> = {
  target: InstallRuntimeTarget;
  runtime: InstallRuntimeDeps;
  proxyUrl: string;
  caPem: string;
  readState(): DesktopActivationState;
  checkDesktop(): void;
  probe(): Promise<ProbeResult>;
  trusted(): boolean;
  trust(): void;
  untrust(): CaRemoval;
  apply(state: DesktopActivationState): T;
};

export async function activateDesktopPicker<T>(options: DesktopActivationOptions<T>): Promise<T> {
  const before = options.readState();
  checkDesktopActivation(before, options.proxyUrl, options.caPem);
  options.checkDesktop();
  const stable = (): void => {
    if (JSON.stringify(options.readState()) !== JSON.stringify(before)) throw new Error("Desktop, router, CA or Code settings changed during activation; left untouched");
    options.checkDesktop();
  };
  const trustedBefore = options.trusted();
  let trustAttempted = false;
  try {
    return await verifyAndApplyInstall({
      started: "already-running", target: options.target, deps: options.runtime,
      probe: async () => {
        const result = await options.probe();
        if (!result.ok) return result;
        stable();
        if (!trustedBefore) { trustAttempted = true; options.trust(); }
        if (!options.trusted()) throw new Error("The local CA was not trusted; Desktop picker activation stopped");
        stable();
        return result;
      },
      apply: () => { stable(); return options.apply(before); },
    });
  } catch (error) {
    if (trustAttempted && !trustedBefore && !before.config.picker?.enabled && !before.desktop.ours) {
      try {
        const current = options.readState();
        if (current.caFingerprint !== before.caFingerprint || current.desktopFingerprint !== before.desktopFingerprint || current.config.picker?.enabled) {
          throw new Error("state changed");
        }
        const removal = options.untrust();
        if (removal !== "removed" && removal !== "absent") throw new Error("trust removal not confirmed");
      } catch {
        throw new Error("Desktop activation did not complete. The newly requested CA trust could not be safely removed; review this installation's exact certificate before retrying", { cause: error });
      }
    }
    throw error;
  }
}

export { checkAppProxyActivation };
