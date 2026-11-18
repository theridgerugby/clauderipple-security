// Picker mode: put real model names into the Claude Desktop model picker.
//
// The picker list comes from claude.ai's bootstrap response (`model_selector_config`, an
// array of surfaces, each with `models[]`). The renderer forwards the chosen id to the app,
// which passes it to the CLI unchecked (docs/ARCHITECTURE.md §3). So when the app's own
// traffic goes through ClaudeRipple, we add our entries to the Code surface here.
//
// We do not know every field of a model entry, so we clone an existing enabled Claude
// entry as a template and override the identifying fields. Only explicitly recognised
// surfaces are edited. Personal Desktop use is restricted further to Code surfaces;
// Chat, Cowork and any new/unknown surface retain the server's own model list.

import { providerFor, type CliModel, type Config } from "./config.ts";
import { resolve } from "./routing.ts";
import { clampEffort } from "./compat.ts";
import { isJudgeOnlyModel } from "./model-policy.ts";
import { chatgptModelWindow } from "./providers/chatgpt/windows.ts";
import { assertApprovedDestination, personalMode } from "./personal-policy.ts";
import { isNativeDesktopModel } from "./desktop-policy.ts";

export const BOOTSTRAP_PATHS = ["/edge-api/bootstrap", "/api/bootstrap"];

export function isBootstrapPath(path: string): boolean {
  return BOOTSTRAP_PATHS.some((p) => path === p || path.startsWith(p + "/") || path.startsWith(p + "?"));
}

type ModelEntry = Record<string, unknown> & { id?: string };
type Surface = Record<string, unknown> & { id?: string; models?: ModelEntry[] };

function isModelEntry(value: unknown): value is ModelEntry {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

// Generic mode keeps its existing CLI-backed surfaces. The author's 2026-09-13 Desktop
// capture identifies ccd as the menu and code as its available IDs, effort and saved state;
// ccr belongs to web Code. Personal Desktop mode changes only those two measured surfaces.
const CLI_SURFACES = new Set(["code", "ccd", "ccr", "cowork"]);
const CODE_SURFACES = new Set(["code", "ccd"]);

export type DesktopCodeSurface = "code" | "ccd";
export function isDesktopCodeSurface(value: unknown): value is DesktopCodeSurface {
  return value === "code" || value === "ccd";
}

function isClaudeEntry(m: ModelEntry): boolean {
  return typeof m.id === "string" && m.id.startsWith("claude-");
}

function pickTemplate(models: ModelEntry[]): ModelEntry | null {
  return models.find((m) => isClaudeEntry(m) && !m.disabled && m.section !== "deprecated" && m.section !== "legacy") ?? models.find(isClaudeEntry) ?? null;
}

/**
 * The effort menu for one routed model: the template's own options, narrowed to the levels the
 * model takes.
 *
 * The app builds the menu per entry from `thinking.effort_options` (`effortOptionsFor: e =>
 * …effort_options ?? []` in the Code tab bundle, read 2026-10-02), so a cloned Claude entry offered
 * Claude's whole ladder for a model that takes three of it. The template's option objects are kept
 * as they are — they carry the app's localised labels, and an id the app does not know (its list is
 * low/medium/high/xhigh/max) is not invented here. `recommended` moves to high, or the level nearest
 * it: when the selected level is not on the list, the app switches to the recommended one (`uw`).
 * A model that takes none of them gets no `thinking` at all, which the app reads as "no effort".
 */
function narrowThinking(entry: ModelEntry, levels: string[]): void {
  const thinking = entry.thinking as { effort_options?: { id?: unknown; recommended?: unknown }[] } | undefined;
  if (!thinking || !Array.isArray(thinking.effort_options)) return;
  const kept = thinking.effort_options.filter((option) => option !== null && typeof option === "object" && typeof option.id === "string" && levels.includes(option.id));
  if (kept.length === 0) {
    delete entry.thinking;
    return;
  }
  const preferred = clampEffort("high", kept.map((option) => option.id as string));
  entry.thinking = { ...thinking, effort_options: kept.map(({ recommended: _recommended, ...option }) => (option.id === preferred ? { ...option, recommended: true } : option)) };
}

/**
 * A config-only eligibility check shared by picker activation and list injection. No network,
 * filesystem or credential-store reads occur here. It proves a selected extra has one explicit
 * usable route and an approved destination, not that its key, paid tier or remote model is live.
 * Native Claude IDs always retain their server-provided picker entry in personal mode.
 */
export function personalPickerModelProblem(cfg: Config, model: string): string | null {
  if (!personalMode(cfg)) return null;
  if (isNativeDesktopModel(model)) return "Native Claude picker entries must remain unchanged";
  const target = resolve(model, {}, cfg);
  if (!target) return "The extra model has no unique routable provider";
  if (isJudgeOnlyModel(model) || isJudgeOnlyModel(target.model)) return "Judge-only models cannot be added to the Code picker";
  const configured = cfg.providers[target.provider];
  if (!configured) return "The extra model's provider is missing";
  const provider = providerFor(configured, target.model);
  if (provider.type === "grok" || (provider.type === "google" && provider.auth !== "api-key")) {
    return "This provider's sign-in mode is unavailable in personal mode";
  }
  if ("credentials" in provider && provider.credentials?.length && provider.credentials.every(credential => credential.paused)) {
    return "All configured provider credentials are paused";
  }
  const endpoint = provider.type === "google" ? provider.url?.trim() || "https://generativelanguage.googleapis.com"
    : provider.type === "chatgpt" ? provider.url || "https://chatgpt.com"
    : provider.type === "anthropic" ? "https://api.anthropic.com"
    : provider.url;
  try { assertApprovedDestination(endpoint, cfg.security!); }
  catch { return "The extra model's HTTPS destination is not approved"; }
  return null;
}

/** Resolve aliases/routes before advertising an entry; a chat-looking alias can target a judge. */
export function chatPickerModels(cfg: Config): CliModel[] {
  return cfg.cli.extraModels
    .filter(entry => !isJudgeOnlyModel(entry.model) && !isJudgeOnlyModel(resolve(entry.model, {}, cfg)?.model ?? cfg.aliases[entry.model.split("@")[0]!] ?? ""))
    .filter(entry => personalPickerModelProblem(cfg, entry.model) === null)
    .map(entry => {
      // A window the operator set on this entry is the one the router advertises, catalogue or not
      // (`pickerWindowOverride`, §4 2026-10-30).
      if (pickerWindowOverride(cfg, entry.model) !== undefined) return entry;
      // Otherwise a ChatGPT-subscription model follows the live catalogue: config carried 272000
      // for 6.1 Sol while Codex runs 475000 (§4, 2026-10-23).
      const live = chatgptModelWindow(cfg, entry.model);
      if (live) return { ...entry, contextWindow: live };
      if (entry.contextWindow) return entry;
      const window = providerModelWindow(cfg, entry.model);
      return window ? { ...entry, contextWindow: window } : entry;
    });
}

/** The window a provider itself declares for `model`: its `/models` context length, or one set by hand. */
function declaredModelWindow(cfg: Config, model: string): number | undefined {
  const base = model.split("@")[0]!;
  const target = resolve(base, {}, cfg) ?? resolve(cfg.aliases[base] ?? base, {}, cfg);
  if (!target) return undefined;
  const undated = target.model.replace(/-\d{8}$/, "");
  const entry = cfg.providers[target.provider]?.models?.find(m => m.id === target.model || m.id.replace(/-\d{8}$/, "") === undated);
  return entry?.contextWindow;
}

/**
 * The window the operator set on a picker entry (`cli.extraModels[].contextWindow`), or undefined
 * when the entry says nothing of its own. Ticking a model in the dashboard copies the provider's
 * declared window onto its entry (`applyPickerSelections`), so an entry equal to that declaration is
 * the copy and not a choice — today's configs carry 6.1 Sol's stale 272000 exactly that way and
 * must keep following the live catalogue. An explicit `route.contextWindow` still wins over this
 * (docs/ARCHITECTURE.md §4, 2026-10-30).
 */
export function pickerWindowOverride(cfg: Config, model: string): number | undefined {
  const base = model.split("@")[0]!;
  const saved = cfg.cli.extraModels.find(m => m.model.split("@")[0] === base)?.contextWindow;
  if (!(typeof saved === "number" && Number.isFinite(saved) && saved > 0)) return undefined;
  return saved === declaredModelWindow(cfg, model) ? undefined : saved;
}

/**
 * The window a provider declared for `model` (its `/models` context length, or one set by hand),
 * by id without an `@effort` suffix or through an alias. A picker entry saved without a window of
 * its own used to fall to `cli.autoCompactWindow` although its provider knew better: a 1M MiniMax
 * subagent compacted twice at ~240K (2026-10-21). A ChatGPT-subscription model answers from the
 * live catalogue first, ahead of the provider's own stored figure (`chatgptModelWindow`, §4
 * 2026-10-23); an operator's override is handled by the callers above and wins over both.
 */
export function providerModelWindow(cfg: Config, model: string): number | undefined {
  const live = chatgptModelWindow(cfg, model);
  if (live) return live;
  return declaredModelWindow(cfg, model);
}

/** Provider-bound capacity, shared by bootstrap's keys and the context-window API. */
export function resolvedModelWindow(cfg: Config, id: string, nativeWindow?: number): { model: string; provider: string | null; contextWindow: number | null } {
  const base = id.split("@")[0]!;
  const route = cfg.routes[base] ?? cfg.routes[base.replace(/-\d{8}$/, "")];
  const target = resolve(id, {}, cfg) ?? (cfg.aliases[base] ? resolve(cfg.aliases[base], {}, cfg) : null);
  const model = target?.model.split("@")[0] ?? base;
  const provider = target ? cfg.providers[target.provider] : undefined;
  const explicit = target && !cfg.direct.some(d => base.startsWith(d.prefix)) ? route?.contextWindow : undefined;
  // The window the operator set on the picker entry, then the live catalogue, then whatever the
  // provider declares (the entry holds a copy of that same figure when nothing was chosen).
  const chosen = pickerWindowOverride(cfg, base) ?? pickerWindowOverride(cfg, model);
  const declared = provider?.models?.find(m => m.id === model || m.id.replace(/-\d{8}$/, "") === model.replace(/-\d{8}$/, ""))?.contextWindow;
  const known = target ? explicit ?? chosen ?? chatgptModelWindow(cfg, id) ?? declared : nativeWindow;
  return { model, provider: target?.provider ?? null, contextWindow: typeof known === "number" && Number.isFinite(known) && known > 0 ? Math.floor(known) : null };
}

export type PickerModelEntry = { id: string; name: string };
/** `injected` names the ids this call added: an id the app already lists (a Claude model ticked for the picker) is not one. */
export type InjectResult = { injected: number; surfaces: { id: string; models: string[]; entries: PickerModelEntry[]; injected: string[] }[] };

/**
 * Mutates `json` in place; returns what was done for logging. `effortFor` names the levels a model
 * takes (by its id without an `@effort` suffix); undefined leaves the template's menu as it is.
 */
export function injectPickerModels(json: Record<string, unknown>, extra: CliModel[], contextWindow?: number, effortFor?: (model: string) => string[] | undefined, options: { codeOnly?: boolean } = {}): InjectResult {
  const result: InjectResult = { injected: 0, surfaces: [] };
  extra = extra.filter(e => !isJudgeOnlyModel(e.model));
  const msc = json.model_selector_config;
  if (!Array.isArray(msc) || extra.length === 0) return result;
  for (const surface of msc as Surface[]) {
    // A changed/malformed native schema must remain a passthrough, not break Desktop's boot.
    if (!surface || typeof surface !== "object" || !Array.isArray(surface.models) || !surface.models.every(isModelEntry)) continue;
    const id = String(surface.id ?? "");
    result.surfaces.push({
      id,
      models: surface.models.map((m) => String(m.id ?? "?")),
      entries: surface.models.map((m) => ({ id: String(m.id ?? "?"), name: typeof m.name === "string" ? m.name : String(m.id ?? "?") })),
      injected: [],
    });
    if (!(options.codeOnly ? CODE_SURFACES : CLI_SURFACES).has(id)) continue;
    const template = pickTemplate(surface.models);
    if (!template) continue;
    const existing = new Set(surface.models.map((m) => m.id));
    const added: CliModel[] = [];
    for (const e of extra) {
      if (existing.has(e.model)) continue;
      const entry: ModelEntry = { ...structuredClone(template), id: e.model, name: e.name };
      const w = e.contextWindow ?? contextWindow;
      if (w) entry.context_window = w;
      else delete entry.context_window;
      if (e.description) entry.description = e.description;
      else delete entry.description;
      for (const k of ["disabled", "disabled_reason", "notice", "selection_notice", "badge", "badge_tooltip", "tooltip", "minimum_tier", "is_default"]) delete entry[k];
      entry.section = "main";
      const levels = effortFor?.(e.model.split("@")[0]!);
      if (options.codeOnly && (!levels || levels.length === 0)) delete entry.thinking;
      else if (levels) narrowThinking(entry, levels);
      surface.models.push(entry);
      // The dashboard writes each id once, but a hand-edited list can repeat one: it is still one row.
      existing.add(e.model);
      added.push(e);
      result.surfaces[result.surfaces.length - 1]!.injected.push(e.model);
      result.injected++;
    }
    // Per-entry window first: routed models do not share one, and `contextWindow` is only the fallback.
    for (const key of ["context_window_by_model", "contextWindowByModel"]) {
      const map = surface[key];
      if (!map || typeof map !== "object" || Array.isArray(map)) continue;
      // Never rewrite capacity metadata for a server-provided/native entry, even when a
      // hand-edited extraModels list names that id with a different window. Repeated calls
      // likewise retain the first entry and its matching metadata together.
      for (const e of added) {
        const w = e.contextWindow ?? contextWindow;
        if (w) (map as Record<string, number>)[e.model] = w;
      }
    }
    const recorded = result.surfaces[result.surfaces.length - 1]!;
    recorded.models = surface.models.map((m) => String(m.id ?? "?"));
    recorded.entries = surface.models.map((m) => ({ id: String(m.id ?? "?"), name: typeof m.name === "string" ? m.name : String(m.id ?? "?") }));
  }
  return result;
}
