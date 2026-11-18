/**
 * A small, process-local overlay for the Desktop Code picker. Native Claude selection writes
 * still go to claude.ai unchanged. Only an authenticated upstream 400 model_not_selectable for
 * an explicitly configured, currently approved extra can receive the known state response.
 *
 * Shape evidence: patrickjaja/claude-desktop-extra, commit
 * 5f9c7a9730b8159598849fea7b0251396e46b67a, scripts/tests/community/test-custom-models-main.mjs,
 * "remembered selection" fixtures captured 2026-09-13; baseline/CUSTOM_MODELS_ANCHORS.md.
 * This implements that observed subset, not a claim about every/current Desktop build. No app
 * patching, signed catalog changes, disk persistence, raw account IDs, cookies or logging.
 */
import { createHash, createHmac, randomBytes } from "node:crypto";
import { providerFor, type Config } from "./config.ts";
import { isNativeDesktopModel } from "./desktop-policy.ts";
import { isDesktopCodeSurface, personalPickerModelProblem, type DesktopCodeSurface } from "./picker.ts";
import { personalMode } from "./personal-policy.ts";
import { resolve } from "./routing.ts";
import { effortLevels } from "./targets.ts";

export type DesktopSelectionContext = {
  authority: string;
  path: string;
  rawHeaders: readonly string[];
};
declare const selectionTokenBrand: unique symbol;
/** Opaque and single-use. Only the cache instance which created it can complete it. */
export type DesktopSelectionToken = Readonly<{ [selectionTokenBrand]: true }>;

type Thinking = { type: "effort"; effort: string };
type SelectorState = {
  id: DesktopCodeSurface;
  model: string;
  thinking?: Thinking;
  thinking_by_model?: { id: string; thinking: Thinking }[];
};
type Choice = { model: string; thinking?: Thinking; fingerprint: string };
type Slot = { native: SelectorState; serialized: string; version: number; touched: number; choice?: Choice };
type Pending = { key: string; version: number; expires: number; choice?: Choice };
const EFFORTS = new Set(["low", "medium", "high", "xhigh", "max"]);
const MODEL_LIMIT = 256;
const ROW_LIMIT = 128;
const ORG_SEGMENT = "([A-Za-z0-9][A-Za-z0-9_-]{0,127})";
const BOOTSTRAP = new RegExp(`^/(?:edge-api|api)/bootstrap/${ORG_SEGMENT}/app_start$`);
const SELECTION = new RegExp(`^/api/organizations/${ORG_SEGMENT}/model_selector_state/(code|ccd)$`);

function record(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
function onlyKeys(value: Record<string, unknown>, keys: readonly string[]): boolean {
  return Object.keys(value).every(key => keys.includes(key));
}
function modelId(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= MODEL_LIMIT && !/[\s\x00-\x1f\x7f]/.test(value);
}
function thinking(value: unknown): value is Thinking {
  return record(value) && onlyKeys(value, ["type", "effort"]) && value.type === "effort"
    && typeof value.effort === "string" && EFFORTS.has(value.effort);
}
function selectorState(value: unknown): value is SelectorState {
  if (!record(value) || !onlyKeys(value, ["id", "model", "thinking", "thinking_by_model"])
    || !isDesktopCodeSurface(value.id) || !modelId(value.model)) return false;
  if (Object.hasOwn(value, "thinking") && !thinking(value.thinking)) return false;
  if (!Object.hasOwn(value, "thinking_by_model")) return true;
  if (!Array.isArray(value.thinking_by_model) || value.thinking_by_model.length > ROW_LIMIT) return false;
  const ids = new Set<string>();
  for (const row of value.thinking_by_model) {
    if (!record(row) || !onlyKeys(row, ["id", "thinking"]) || !modelId(row.id) || !thinking(row.thinking) || ids.has(row.id)) return false;
    ids.add(row.id);
  }
  return true;
}
function surfaceModels(json: Record<string, unknown>, surface: DesktopCodeSurface): Record<string, unknown>[] | null {
  const config = json.model_selector_config;
  if (!Array.isArray(config) || config.length > ROW_LIMIT) return null;
  const matching = config.filter(row => record(row) && row.id === surface);
  if (matching.length !== 1) return null;
  const models = matching[0]!.models;
  if (!Array.isArray(models) || models.length > ROW_LIMIT || !models.every(row => record(row) && modelId(row.id))) return null;
  const ids = models.map(row => row.id);
  if (new Set(ids).size !== ids.length) return null;
  return models;
}
function enabled(cfg: Config): boolean {
  return personalMode(cfg) && cfg.picker?.enabled === true;
}
function routeFingerprint(cfg: Config, id: string): string | null {
  if (!modelId(id) || cfg.cli.extraModels.filter(entry => entry.model === id).length !== 1 || personalPickerModelProblem(cfg, id) !== null) return null;
  const target = resolve(id, {}, cfg);
  if (!target) return null;
  const configured = cfg.providers[target.provider];
  if (!configured) return null;
  const provider = providerFor(configured, target.model);
  const endpoint = provider.type === "google" ? provider.url?.trim() || "https://generativelanguage.googleapis.com"
    : provider.type === "chatgpt" ? provider.url || "https://chatgpt.com"
    : provider.type === "anthropic" ? "https://api.anthropic.com" : provider.url;
  return createHash("sha256").update(JSON.stringify([target.provider, target.model, provider.type, "auth" in provider ? provider.auth : null, endpoint])).digest("hex");
}
function supportedThinking(cfg: Config, id: string, value: Thinking): boolean {
  const target = resolve(id, {}, cfg);
  if (!target) return false;
  const owner = cfg.providers[target.provider];
  const declared = owner?.models?.find(model => model.id === target.model || model.id.replace(/-\d{8}$/, "") === target.model.replace(/-\d{8}$/, ""));
  // A Google model without a measured/declared ladder must not borrow another Gemini model's.
  const levels = owner?.type === "google" ? declared?.effortLevels
    : declared?.effortLevels ?? effortLevels(cfg).providers[target.provider]?.default;
  return levels?.includes(value.effort) === true;
}
function stateReply(native: SelectorState, choice: Choice): SelectorState {
  const rows = structuredClone(native.thinking_by_model ?? []);
  if (choice.thinking) {
    const existing = rows.find(row => row.id === choice.model);
    if (existing) existing.thinking = structuredClone(choice.thinking);
    else rows.push({ id: choice.model, thinking: structuredClone(choice.thinking) });
  }
  return { id: native.id, model: choice.model, thinking_by_model: rows,
    ...(choice.thinking ? { thinking: structuredClone(choice.thinking) } : {}) };
}
function modelNotSelectable(value: unknown): boolean {
  return record(value) && record(value.error) && record(value.error.details) && value.error.details.error_code === "model_not_selectable";
}
function bounded(value: number | undefined, fallback: number, maximum: number): number {
  return Math.max(1, Math.min(maximum, value !== undefined && Number.isFinite(value) ? Math.floor(value) : fallback));
}

export class DesktopSelectionCache {
  #salt = randomBytes(32);
  #slots = new Map<string, Slot>();
  #pending = new Map<DesktopSelectionToken, Pending>();
  #configuration: WeakRef<Config> | undefined;
  #version = 0;
  #now: () => number;
  #ttl: number;
  #maxSlots: number;
  #maxPending: number;

  constructor(options: { now?: () => number; ttlMs?: number; maxScopes?: number; maxPending?: number } = {}) {
    this.#now = options.now ?? Date.now;
    this.#ttl = bounded(options.ttlMs, 30 * 60_000, 30 * 60_000);
    this.#maxSlots = bounded(options.maxScopes, 8, 32) * 2;
    this.#maxPending = bounded(options.maxPending, 32, 128);
  }

  /** Call on EVERY accepted configuration change, including in-place revocation/reapproval. */
  clear(): void {
    this.#slots.clear();
    this.#pending.clear();
    this.#salt = randomBytes(32);
  }

  #active(cfg: Config): boolean {
    if (enabled(cfg)) {
      if (this.#configuration?.deref() !== cfg) {
        this.clear();
        this.#configuration = new WeakRef(cfg);
      }
      return true;
    }
    this.clear();
    return false;
  }
  #prune(): void {
    const now = this.#now();
    for (const [key, slot] of this.#slots) if (now - slot.touched >= this.#ttl) this.#slots.delete(key);
    for (const [token, pending] of this.#pending) if (pending.expires <= now || !this.#slots.has(pending.key)) this.#pending.delete(token);
  }
  #trim<T, V>(map: Map<T, V>, maximum: number): void {
    while (map.size > maximum) map.delete(map.keys().next().value!);
  }
  #scope(ctx: DesktopSelectionContext, kind: "bootstrap" | "selection"): { key: string; surface?: DesktopCodeSurface } | null {
    if (ctx.authority !== "claude.ai" && ctx.authority !== "claude.ai:443") return null;
    if (ctx.path.length > 4096 || ctx.path.includes("#") || ctx.rawHeaders.length > 256 || ctx.rawHeaders.length % 2 !== 0) return null;
    const path = ctx.path.split("?")[0]!;
    const match = (kind === "bootstrap" ? BOOTSTRAP : SELECTION).exec(path);
    if (!match) return null;
    // Hash the native authentication and organization together under a per-process random salt.
    // Retain neither raw value; absent or duplicate ambiguous native authentication is unscoped.
    const auth = new Map<string, string>();
    let bytes = 0;
    for (let i = 0; i < ctx.rawHeaders.length; i += 2) {
      const name = ctx.rawHeaders[i]!.toLowerCase();
      if (name !== "cookie" && name !== "authorization") continue;
      const value = ctx.rawHeaders[i + 1]!;
      bytes += value.length;
      if (auth.has(name) || !value.trim() || bytes > 32_768 || /[\r\n\x00]/.test(value)) return null;
      auth.set(name, value);
    }
    if (auth.size === 0) return null;
    const key = createHmac("sha256", this.#salt).update(JSON.stringify([match[1], auth.get("cookie") ?? "", auth.get("authorization") ?? ""])).digest("hex");
    return kind === "selection" ? { key, surface: match[2] as DesktopCodeSurface } : { key };
  }
  #choiceValid(cfg: Config, choice: Choice): boolean {
    return routeFingerprint(cfg, choice.model) === choice.fingerprint && (!choice.thinking || supportedThinking(cfg, choice.model, choice.thinking));
  }
  #advanceScope(key: string, clearChoices: boolean): number {
    // code and ccd are two parts of the same Desktop picker, not independent accounts.
    // A later native write on either surface must invalidate an earlier extra on the other.
    const prefix = key.slice(0, key.lastIndexOf(":") + 1);
    const version = ++this.#version;
    for (const [related, slot] of this.#slots) if (related.startsWith(prefix)) {
      slot.version = version;
      if (clearChoices) delete slot.choice;
    }
    return version;
  }

  /** Call only for a successful parsed native bootstrap, BEFORE adding picker models. */
  observeBootstrap(ctx: DesktopSelectionContext, json: Record<string, unknown>, cfg: Config): void {
    if (!this.#active(cfg)) return;
    this.#prune();
    const scope = this.#scope(ctx, "bootstrap");
    if (!scope) return;
    const states = json.model_selector_state;
    for (const surface of ["code", "ccd"] as const) {
      const key = `${scope.key}:${surface}`;
      const matches = Array.isArray(states) && states.length <= ROW_LIMIT ? states.filter(state => record(state) && state.id === surface) : [];
      const native = matches[0];
      const models = surfaceModels(json, surface);
      if (matches.length !== 1 || !selectorState(native) || !isNativeDesktopModel(native.model)
        || !models?.some(model => typeof model.id === "string" && isNativeDesktopModel(model.id))) {
        if (this.#slots.has(key)) this.#advanceScope(key, true);
        this.#slots.delete(key);
        continue;
      }
      const serialized = JSON.stringify(native);
      const previous = this.#slots.get(key);
      if (previous && previous.serialized !== serialized) this.#advanceScope(key, true);
      const choice = previous?.serialized === serialized && previous.choice && this.#choiceValid(cfg, previous.choice) ? previous.choice : undefined;
      this.#slots.delete(key);
      this.#slots.set(key, { native: structuredClone(native), serialized,
        version: previous?.serialized === serialized ? previous.version : ++this.#version,
        touched: this.#now(), ...(choice ? { choice } : {}) });
    }
    this.#trim(this.#slots, this.#maxSlots);
  }

  /** Call AFTER adding picker models. Returns how many known state rows were changed. */
  overlayBootstrap(ctx: DesktopSelectionContext, json: Record<string, unknown>, cfg: Config): number {
    if (!this.#active(cfg)) return 0;
    this.#prune();
    const scope = this.#scope(ctx, "bootstrap");
    const states = json.model_selector_state;
    if (!scope || !Array.isArray(states) || states.length > ROW_LIMIT) return 0;
    let changed = 0;
    for (const [index, state] of states.entries()) {
      if (!selectorState(state) || states.filter(row => record(row) && row.id === state.id).length !== 1) continue;
      const slot = this.#slots.get(`${scope.key}:${state.id}`);
      if (!slot?.choice) continue;
      if (!this.#choiceValid(cfg, slot.choice)) { delete slot.choice; continue; }
      if (JSON.stringify(state) !== slot.serialized || !surfaceModels(json, state.id)?.some(model => model.id === slot.choice!.model)) continue;
      const reply = stateReply(state, slot.choice);
      if (!selectorState(reply)) { delete slot.choice; continue; }
      states[index] = reply;
      slot.touched = this.#now();
      changed++;
    }
    return changed;
  }

  /** Prepare before forwarding the exact native request. No upstream request is replaced here. */
  prepareSelection(ctx: DesktopSelectionContext, method: string, body: unknown, cfg: Config): DesktopSelectionToken | null {
    if (!this.#active(cfg) || method !== "PATCH") return null;
    this.#prune();
    const scope = this.#scope(ctx, "selection");
    if (!scope?.surface) return null;
    const key = `${scope.key}:${scope.surface}`;
    const slot = this.#slots.get(key);
    if (!slot) return null;
    const version = this.#advanceScope(key, false);
    slot.touched = this.#now();
    let choice: Choice | undefined;
    if (record(body) && onlyKeys(body, ["model", "thinking"]) && modelId(body.model)) {
      const fingerprint = routeFingerprint(cfg, body.model);
      if (fingerprint && (!Object.hasOwn(body, "thinking") || thinking(body.thinking) && supportedThinking(cfg, body.model, body.thinking))) {
        choice = { model: body.model, fingerprint, ...(thinking(body.thinking) ? { thinking: structuredClone(body.thinking) } : {}) };
      }
    }
    const token = Object.freeze({}) as DesktopSelectionToken;
    this.#pending.set(token, { key, version, expires: this.#now() + Math.min(this.#ttl, 30_000), ...(choice ? { choice } : {}) });
    this.#trim(this.#pending, this.#maxPending);
    return token;
  }

  /**
   * Return a replacement JSON body ONLY for the exact known refusal. The caller may then send
   * 200 with regenerated body headers. null means original status/body/headers pass unchanged.
   * Effort-only, fast-mode and unknown writes never get synthetic success. A native success
   * clears the overlay, including an effort-only success, and requires no request-body changes.
   */
  completeSelection(token: DesktopSelectionToken | null, status: number, body: unknown, cfg: Config): Record<string, unknown> | null {
    if (!token || !this.#active(cfg)) return null;
    this.#prune();
    const pending = this.#pending.get(token);
    this.#pending.delete(token);
    if (!pending) return null;
    const slot = this.#slots.get(pending.key);
    if (!slot || slot.version !== pending.version) return null;
    if (status >= 200 && status < 300) {
      this.#advanceScope(pending.key, true);
      if (selectorState(body) && body.id === slot.native.id && isNativeDesktopModel(body.model)) {
        slot.native = structuredClone(body);
        slot.serialized = JSON.stringify(body);
        slot.touched = this.#now();
      } else this.#slots.delete(pending.key);
      return null;
    }
    if (status !== 400 || !modelNotSelectable(body) || !pending.choice || !this.#choiceValid(cfg, pending.choice)) return null;
    const reply = stateReply(slot.native, pending.choice);
    if (!selectorState(reply)) return null;
    slot.choice = pending.choice;
    slot.touched = this.#now();
    return reply;
  }
}
