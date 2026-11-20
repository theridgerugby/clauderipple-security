// Personal Desktop mode adds explicit extra models. Its native subscription slots and safety
// services must keep their original destinations, including after a later dashboard edit.
import type { Config } from "./config.ts";

export const isNativeDesktopModel = (value: string): boolean => /^(?:claude-[a-z0-9._-]+|opus|sonnet|haiku|fable|best|default|opusplan)(?:\[1m\])?$/i.test(value.split("@")[0]!);

/** Native Desktop slots stay on the subscription even if an old config contains overrides. */
export function preserveNativeDesktopModel(config: Config, model: unknown): boolean {
  return config.security?.mode === "personal" && config.picker?.enabled === true &&
    typeof model === "string" && isNativeDesktopModel(model);
}

export function personalDesktopProblems(config: Config): string[] {
  if (config.security?.mode !== "personal" || !config.picker?.enabled) return [];
  const problems: string[] = [];
  const hosts = config.picker.hosts ?? ["claude.ai"];
  if (hosts.length !== 1 || hosts[0] !== "claude.ai") problems.push("personal Desktop mode intercepts only claude.ai and api.anthropic.com");
  if (Object.keys(config.routes).some(isNativeDesktopModel) || Object.keys(config.aliases).some(isNativeDesktopModel) ||
      config.direct.some(rule => "claude-".startsWith(rule.prefix.toLowerCase()) || isNativeDesktopModel(rule.prefix) || rule.prefix.toLowerCase().startsWith("claude-"))) {
    problems.push("personal Desktop mode preserves native Claude model routes; add a distinct extra model instead");
  }
  if (Object.values(config.providers).some(provider => provider.models?.some(model => isNativeDesktopModel(model.id)))) {
    problems.push("personal Desktop mode keeps native Claude model IDs out of external provider catalogues");
  }
  if (Object.values(config.cli.models ?? {}).some(model => model !== undefined && model !== "" && !isNativeDesktopModel(model))) {
    problems.push("personal Desktop mode preserves native default, small-fast and subagent slots");
  }
  if (config.autoModeClassifier || (config.webSearch !== undefined && config.webSearch !== "native")) {
    problems.push("personal Desktop mode preserves Claude's native safety classifier and web-search configuration");
  }
  return problems;
}
