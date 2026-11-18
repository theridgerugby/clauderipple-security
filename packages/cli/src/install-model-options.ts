// Desktop's additional picker entry does not need global native-model or context overrides.
// Keep the legacy options only for callers explicitly outside the personal profile.
import type { Config } from "../../router/src/config.ts";
import { CLI_WINDOW_MAX } from "../../router/src/bootstrap.ts";
import { personalMode } from "../../router/src/personal-policy.ts";
import type { ModelSlots } from "./settings.ts";

export function installModelOptions(config: Config, requestedCap?: string): { models?: ModelSlots; maxContextTokens?: number } {
  if (personalMode(config)) {
    if (requestedCap !== undefined) {
      throw new Error("Personal Desktop setup preserves native context limits; omit --max-context-tokens");
    }
    return {};
  }
  return { models: config.cli.models ?? {}, maxContextTokens: requestedCap ? Number(requestedCap) : CLI_WINDOW_MAX };
}
