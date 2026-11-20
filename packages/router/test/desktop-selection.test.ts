import assert from "node:assert/strict";
import { test } from "node:test";
import { DEFAULTS, type Config } from "../src/config.ts";
import { DesktopSelectionCache, type DesktopSelectionContext, type DesktopSelectionToken } from "../src/desktop-selection.ts";
import { chatPickerModels, DESKTOP_PICKER_ROW_LIMIT, injectPickerModels } from "../src/picker.ts";

// Synthetic, non-secret fixtures following the author's 2026-09-13 captured state shape:
// https://github.com/patrickjaja/claude-desktop-extra/blob/5f9c7a9730b8159598849fea7b0251396e46b67a/scripts/tests/community/test-custom-models-main.mjs
// These are protocol regressions, not a live Windows/account/current Desktop compatibility test.
const EXTRA = "gemini-test-extra";
const REFUSAL = { error: { details: { error_code: "model_not_selectable" } } };
const nativeState = (id = "code", model = "claude-opus-5") => ({
  id, model, thinking: { type: "effort", effort: "high" },
  thinking_by_model: [{ id: model, thinking: { type: "effort", effort: "high" } }],
});
const bootstrap = (): Record<string, unknown> => ({
  account: { uuid: "synthetic-account", plan: "unchanged" },
  model_selector_config: ["chat", "code", "ccd", "ccr", "cc", "cowork"].map(id => ({
    id, models: [{ id: "claude-opus-5", name: "Native Opus", thinking: { type: "effort", effort_options: [{ id: "high" }] } }],
  })),
  model_selector_state: ["chat", "code", "ccd", "ccr", "cc", "cowork"].map(id => nativeState(id)),
});
const config = (): Config => ({
  ...structuredClone(DEFAULTS),
  security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com", "https://generativelanguage.googleapis.com"] },
  picker: { enabled: true },
  providers: { google: { type: "google", auth: "api-key", apiKey: "synthetic-not-a-real-key",
    models: [{ id: EXTRA, effortLevels: ["low", "high"], contextWindow: 1_000_000 }] } },
  routes: {}, direct: [], aliases: {},
  cli: { ...DEFAULTS.cli, extraModels: [{ model: EXTRA, name: "Synthetic Gemini" }] },
});
const context = (kind: "bootstrap" | "selection" = "bootstrap", org = "org-one", user = "synthetic-session-one", surface = "code"): DesktopSelectionContext => ({
  authority: "claude.ai", path: kind === "bootstrap" ? `/edge-api/bootstrap/${org}/app_start` : `/api/organizations/${org}/model_selector_state/${surface}`,
  rawHeaders: ["Cookie", `sessionKey=${user}`, "Accept", "application/json"],
});
function observe(cache: DesktopSelectionCache, cfg: Config, ctx = context(), json = bootstrap()): void {
  cache.observeBootstrap(ctx, json, cfg);
}
function select(cache: DesktopSelectionCache, cfg: Config, ctx = context("selection"), body: unknown = { model: EXTRA, thinking: { type: "effort", effort: "high" } }): Record<string, unknown> | null {
  return cache.completeSelection(cache.prepareSelection(ctx, "PATCH", body, cfg), 400, REFUSAL, cfg);
}
function overlay(cache: DesktopSelectionCache, cfg: Config, ctx = context(), json = bootstrap()): { changed: number; json: Record<string, unknown> } {
  const compatibleCodeSurfaces = cache.observeBootstrap(ctx, json, cfg);
  injectPickerModels(json, chatPickerModels(cfg), undefined, () => ["low", "high"], { codeOnly: true, compatibleCodeSurfaces });
  return { changed: cache.overlayBootstrap(ctx, json, cfg), json };
}
const states = (json: Record<string, unknown>) => json.model_selector_state as Record<string, unknown>[];

test("known extra refusal returns measured state shape; next bootstrap changes only its Code state", () => {
  const cache = new DesktopSelectionCache(); const cfg = config();
  const original = bootstrap(); const frozen = JSON.stringify(original);
  observe(cache, cfg, context(), original);
  const reply = select(cache, cfg);
  assert.deepEqual(reply, { id: "code", model: EXTRA,
    thinking_by_model: [...nativeState().thinking_by_model, { id: EXTRA, thinking: { type: "effort", effort: "high" } }],
    thinking: { type: "effort", effort: "high" } });
  assert.equal(JSON.stringify(original), frozen, "observing/selection never mutates the native bootstrap");
  const { changed, json } = overlay(cache, cfg);
  assert.equal(changed, 1);
  assert.deepEqual(json.account, original.account);
  assert.deepEqual(states(json).find(row => row.id === "code"), reply);
  for (const row of states(json).filter(row => row.id !== "code")) assert.deepEqual(row, states(original).find(other => other.id === row.id));
  assert.equal(JSON.stringify(cache), "{}", "private cache state exposes no raw identities/authentication");
});

test("a selection without thinking does not inherit or invent the native model's effort", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  const reply = select(cache, cfg, context("selection"), { model: EXTRA });
  assert.deepEqual(reply, { id: "code", model: EXTRA, thinking_by_model: nativeState().thinking_by_model });
  assert.equal(Object.hasOwn(reply!, "thinking"), false);
});

test("ccd supports the same measured state shape without rewriting an unselected code state", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  assert.equal(select(cache, cfg, context("selection", "org-one", "synthetic-session-one", "ccd"))?.id, "ccd");
  const out = overlay(cache, cfg);
  assert.equal(out.changed, 1);
  assert.equal(states(out.json).find(row => row.id === "code")!.model, "claude-opus-5");
  assert.equal(states(out.json).find(row => row.id === "ccd")!.model, EXTRA);
});

test("preparing a request never creates a choice before the native response", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  assert.ok(cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg));
  assert.equal(overlay(cache, cfg).changed, 0);
});

test("authentication, throttling, server and unrecognized validation errors remain untouched", () => {
  for (const [status, body] of [[401, REFUSAL], [403, REFUSAL], [429, REFUSAL], [500, REFUSAL], [400, { error: { details: { error_code: "invalid_request" } } }], [400, {}], [400, null], [400, "model_not_selectable"]] as const) {
    const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
    const token = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
    const before = JSON.stringify(body);
    assert.equal(cache.completeSelection(token, status, body, cfg), null);
    assert.equal(JSON.stringify(body), before);
    assert.equal(overlay(cache, cfg).changed, 0);
  }
});

test("native, unknown and configured-but-unselected model requests cannot receive synthetic success", () => {
  for (const model of ["claude-opus-5", "opus", "unconfigured-extra", "gemini-not-selected"]) {
    const cache = new DesktopSelectionCache(); const cfg = config();
    cfg.providers.google!.models!.push({ id: "gemini-not-selected" });
    observe(cache, cfg);
    assert.equal(select(cache, cfg, context("selection"), { model }), null);
  }
});

test("organization and exact native authentication scope cannot leak a choice to another session", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  assert.ok(select(cache, cfg));
  for (const ctx of [context("bootstrap", "org-two"), context("bootstrap", "org-one", "synthetic-session-two")]) {
    const before = bootstrap(); injectPickerModels(before, chatPickerModels(cfg), undefined, undefined, { codeOnly: true, compatibleCodeSurfaces: ["code", "ccd"] });
    const raw = JSON.stringify(before);
    assert.equal(cache.overlayBootstrap(ctx, before, cfg), 0);
    assert.equal(JSON.stringify(before), raw);
  }
  assert.equal(select(cache, cfg, context("selection", "org-two")), null);
  assert.equal(select(cache, cfg, context("selection", "org-one", "synthetic-session-two")), null);
  assert.equal(overlay(cache, cfg).changed, 1);
});

test("unscoped old bootstrap, unsupported surfaces and lookalike authorities stay native", () => {
  for (const path of ["/edge-api/bootstrap", "/edge-api/bootstrap?cache=1", "/api/bootstrap/org-one/current_user_access", "/edge-api/bootstrap/org-one/app_start/", "/edge-api/bootstrap/org%2Done/app_start"]) {
    const cache = new DesktopSelectionCache(); const cfg = config();
    observe(cache, cfg, { ...context(), path });
    assert.equal(select(cache, cfg), null);
  }
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  for (const surface of ["cc", "ccr", "chat", "cowork", "CODE", "code/", "code%3F"]) {
    assert.equal(cache.prepareSelection(context("selection", "org-one", "synthetic-session-one", surface), "PATCH", { model: EXTRA }, cfg), null);
  }
  for (const authority of ["evil.claude.ai", "claude.ai.evil.invalid", "api.anthropic.com", "claude.ai:8443"]) {
    assert.equal(cache.prepareSelection({ ...context("selection"), authority }, "PATCH", { model: EXTRA }, cfg), null);
  }
  assert.equal(cache.prepareSelection(context("selection"), "GET", { model: EXTRA }, cfg), null);
});

test("only native auth headers scope the cache; duplicate/missing/oversized authentication is refused", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  for (const rawHeaders of [[], ["X-Api-Key", "synthetic"], ["Cookie", ""], ["Cookie", "sessionKey=one", "cookie", "sessionKey=two"],
    ["Authorization", "Bearer synthetic", "authorization", "Bearer duplicate"], ["Cookie", "x".repeat(32_769)], ["Cookie", "bad\r\nvalue"], ["Cookie"]]) {
    assert.equal(cache.prepareSelection({ ...context("selection"), rawHeaders }, "PATCH", { model: EXTRA }, cfg), null);
  }
  // Header name/order and explicit HTTPS port carry the same scope, not unrelated headers.
  assert.ok(select(cache, cfg, { ...context("selection"), authority: "claude.ai:443", rawHeaders: ["X-Other", "different", "cookie", "sessionKey=synthetic-session-one"] }));
});

test("native Authorization also scopes a session without retaining the bearer value", () => {
  const cache = new DesktopSelectionCache(); const cfg = config();
  const rawHeaders = ["Authorization", "Bearer synthetic-not-a-real-token"];
  observe(cache, cfg, { ...context(), rawHeaders });
  assert.ok(select(cache, cfg, { ...context("selection"), rawHeaders }));
  assert.equal(cache.overlayBootstrap(context(), bootstrap(), cfg), 0);
});

test("unknown, duplicate or malformed native selector state cannot establish a reply template", () => {
  const badStates: unknown[] = [null, {}, "future", [{ ...nativeState(), model: { id: "claude-opus-5" } }], [nativeState(), nativeState()],
    [{ ...nativeState(), thinking: { type: "adaptive", effort: "high" } }], [{ ...nativeState(), thinking_by_model: [null] }],
    [{ ...nativeState(), thinking_by_model: [nativeState().thinking_by_model[0], nativeState().thinking_by_model[0]] }],
    [{ ...nativeState(), model: EXTRA }], Array.from({ length: 129 }, () => nativeState())];
  for (const state of badStates) {
    const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
    json.model_selector_state = state;
    const raw = JSON.stringify(json); observe(cache, cfg, context(), json);
    assert.equal(select(cache, cfg), null);
    assert.equal(JSON.stringify(json), raw);
  }
});

test("missing/duplicate native Code menu shape cannot establish a template", () => {
  for (const modelConfig of [null, [], [{ id: "code", models: [] }], [{ id: "code", models: [{ id: "future-nonnative" }] }],
    [{ id: "code", models: [null] }], [{ id: "code", models: [{ id: "claude-opus-5" }, { id: "claude-opus-5" }] }],
    [{ id: "code", models: [{ id: "claude-opus-5" }] }, { id: "code", models: [{ id: "claude-opus-5" }] }]]) {
    const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap(); json.model_selector_config = modelConfig;
    observe(cache, cfg, context(), json);
    assert.equal(select(cache, cfg), null);
  }
});

test("bootstrap capabilities are scoped and independent for compatible Code surfaces", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
  states(json)[1]!.thinking = { type: "future-thinking", effort: "high" };
  const before = JSON.stringify(json);
  assert.deepEqual(cache.observeBootstrap(context(), json, cfg), ["ccd"]);
  assert.equal(JSON.stringify(json), before, "capability detection never edits native data");
  assert.equal(select(cache, cfg), null);
  assert.ok(select(cache, cfg, context("selection", "org-one", "synthetic-session-one", "ccd")));
  assert.deepEqual(cache.observeBootstrap({ ...context(), path: "/api/bootstrap/org-one/app_start_v2" }, bootstrap(), cfg), []);
  assert.deepEqual(cache.observeBootstrap({ ...context(), rawHeaders: [] }, bootstrap(), cfg), []);
});

test("additive native metadata and unrelated native model preferences survive selection and refresh", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
  const native = states(json)[1]!;
  native.revision = 2;
  native.optional_metadata = { labels: ["preserve", "native"] };
  native.thinking = { type: "effort", effort: "high", label: "Native high" };
  native.thinking_by_model = [
    { ...nativeState().thinking_by_model[0], new_native_field: { preserved: true } },
    { id: "future-native-model", thinking: { type: "future-native-thinking", budget: 512 }, metadata: "untouched" },
  ];
  assert.deepEqual(cache.observeBootstrap(context(), json, cfg), ["code", "ccd"]);
  const reply = select(cache, cfg)!;
  assert.equal(reply.revision, 2);
  assert.deepEqual(reply.optional_metadata, native.optional_metadata);
  assert.deepEqual((reply.thinking_by_model as unknown[]).slice(0, 2), native.thinking_by_model);
  assert.deepEqual(reply.thinking, { type: "effort", effort: "high" });
  const refreshed = structuredClone(json);
  states(refreshed)[1]!.revision = 3;
  states(refreshed)[1]!.optional_metadata = { labels: ["updated", "native"] };
  (refreshed.model_selector_config as { models: Record<string, unknown>[] }[])[1]!.models.push({ id: "future-native-model", new_native_metadata: { preserve: true } });
  const nativeRows = structuredClone(states(refreshed)[1]!.thinking_by_model);
  const result = overlay(cache, cfg, context(), refreshed);
  assert.equal(result.changed, 1, "unrelated metadata updates do not discard an explicit extra choice");
  const selected = states(result.json)[1]!;
  assert.equal(selected.model, EXTRA);
  assert.equal(selected.revision, 3, "the latest native metadata is preserved");
  assert.deepEqual(selected.optional_metadata, { labels: ["updated", "native"] });
  assert.deepEqual((selected.thinking_by_model as unknown[]).slice(0, 2), nativeRows);
});

test("a row-only active native effort change wins over an extra and invalidates pending replies", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const first = bootstrap();
  delete states(first)[1]!.thinking;
  assert.deepEqual(cache.observeBootstrap(context(), first, cfg), ["code", "ccd"]);
  assert.ok(select(cache, cfg));
  const pending = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const changed = structuredClone(first);
  (states(changed)[1]!.thinking_by_model as { thinking: { effort: string } }[])[0]!.thinking.effort = "low";
  const result = overlay(cache, cfg, context(), changed);
  assert.equal(result.changed, 0);
  assert.equal(states(result.json)[1]!.model, "claude-opus-5");
  assert.equal(cache.completeSelection(pending, 400, REFUSAL, cfg), null);
  assert.ok(select(cache, cfg), "a fresh explicit extra choice is still supported");
});

test("conflicting or unknown active native effort is incompatible while other-model preferences stay opaque", () => {
  for (const [top, active] of [
    [{ type: "effort", effort: "high" }, { type: "effort", effort: "low" }],
    [undefined, { type: "future-effort", budget: 512 }],
  ] as const) {
    const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
    if (top) states(json)[1]!.thinking = top; else delete states(json)[1]!.thinking;
    states(json)[1]!.thinking_by_model = [{ id: "claude-opus-5", thinking: active }];
    const before = JSON.stringify(json);
    assert.deepEqual(cache.observeBootstrap(context(), json, cfg), ["ccd"]);
    assert.equal(select(cache, cfg), null);
    assert.equal(JSON.stringify(json), before);
  }
});

test("retained native selector metadata is bounded by 64 KiB of UTF-8 for bootstrap and native replies", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const oversized = bootstrap();
  states(oversized)[1]!.optional_metadata = "测".repeat(22_000);
  const before = JSON.stringify(oversized);
  assert.deepEqual(cache.observeBootstrap(context(), oversized, cfg), ["ccd"]);
  assert.equal(select(cache, cfg), null);
  assert.equal(JSON.stringify(oversized), before);
  const small = bootstrap(); states(small)[1]!.optional_metadata = "x".repeat(60_000);
  assert.deepEqual(cache.observeBootstrap(context(), small, cfg), ["code", "ccd"]);
  assert.ok(select(cache, cfg));
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: "claude-opus-5" }, cfg);
  const response = states(oversized)[1]!;
  assert.equal(cache.completeSelection(token, 200, response, cfg), null);
  assert.equal(select(cache, cfg), null, "an oversized native success cannot retain a replacement baseline");
  assert.equal(JSON.stringify(oversized), before);
});

test("deeply nested native metadata below the byte cap cannot throw during bootstrap or native success", () => {
  const cache = new DesktopSelectionCache(); const cfg = config();
  const raw = `{"id":"code","model":"claude-opus-5","optional_metadata":${"[".repeat(20_000)}0${"]".repeat(20_000)}}`;
  assert.ok(Buffer.byteLength(raw) < 64 * 1024);
  const native = JSON.parse(raw);
  const json = bootstrap(); states(json)[1] = native;
  assert.deepEqual(cache.observeBootstrap(context(), json, cfg), ["ccd"]);
  assert.equal(select(cache, cfg), null);
  observe(cache, cfg); assert.ok(select(cache, cfg));
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: "claude-opus-5" }, cfg);
  assert.equal(cache.completeSelection(token, 200, native, cfg), null);
  assert.equal(select(cache, cfg), null);
});

test("an incompatible selector clears old choices and pending replies, then recovers without resurrecting them", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  assert.ok(select(cache, cfg));
  const pending = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const changed = bootstrap(); states(changed)[1]!.model = { id: "claude-opus-5" };
  assert.deepEqual(cache.observeBootstrap(context(), changed, cfg), ["ccd"]);
  assert.equal(cache.completeSelection(pending, 400, REFUSAL, cfg), null);
  assert.equal(select(cache, cfg), null);
  assert.deepEqual(cache.observeBootstrap(context(), bootstrap(), cfg), ["code", "ccd"]);
  assert.equal(overlay(cache, cfg).changed, 0);
  assert.ok(select(cache, cfg), "a new explicit selection works when the known shape returns");
});

test("an exact-bound native menu has no extra capacity and clears pending or remembered hidden extras", () => {
  const cache = new DesktopSelectionCache(); const cfg = config();
  const near = bootstrap();
  (near.model_selector_config as { models: Record<string, unknown>[] }[])[1]!.models = Array.from({ length: DESKTOP_PICKER_ROW_LIMIT - 1 }, (_, i) => ({ id: `claude-native-${i}` }));
  assert.deepEqual(cache.observeBootstrap(context(), near, cfg), ["code", "ccd"]);
  assert.ok(select(cache, cfg));
  const pending = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const full = structuredClone(near);
  (full.model_selector_config as { models: Record<string, unknown>[] }[])[1]!.models.push({ id: "claude-native-final" });
  const before = structuredClone((full.model_selector_config as unknown[])[1]);
  assert.deepEqual(cache.observeBootstrap(context(), full, cfg), ["ccd"]);
  assert.equal(cache.completeSelection(pending, 400, REFUSAL, cfg), null);
  assert.equal(select(cache, cfg), null, "an overflow extra cannot receive synthetic acceptance");
  const result = overlay(cache, cfg, context(), full);
  assert.equal(result.changed, 0);
  assert.deepEqual((result.json.model_selector_config as unknown[])[1], before, "all exact-bound native rows remain intact");
  assert.deepEqual(cache.observeBootstrap(context(), near, cfg), ["code", "ccd"]);
  const secondPending = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  cache.observeBootstrap(context(), full, cfg);
  cache.observeBootstrap(context(), near, cfg);
  assert.equal(cache.completeSelection(secondPending, 400, REFUSAL, cfg), null, "capacity recovery cannot resurrect a pre-loss pending choice");
});

test("many configured extras admit only displayed rows and preserve the last available row's overlay", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
  const extras = Array.from({ length: DESKTOP_PICKER_ROW_LIMIT * 2 }, (_, i) => ({ model: `gemini-bounded-${i}`, name: `Fixture ${i}` }));
  cfg.cli.extraModels = extras;
  cfg.providers.google!.models = extras.map(({ model }) => ({ id: model, effortLevels: ["high"] }));
  (json.model_selector_config as { models: Record<string, unknown>[] }[])[1]!.models = Array.from({ length: DESKTOP_PICKER_ROW_LIMIT - 2 }, (_, i) => ({ id: `claude-native-${i}` }));
  assert.deepEqual(cache.observeBootstrap(context(), json, cfg), ["code", "ccd"]);
  assert.ok(select(cache, cfg, context("selection"), { model: extras[1]!.model, thinking: { type: "effort", effort: "high" } }));
  const selected = overlay(cache, cfg, context(), structuredClone(json));
  assert.equal(selected.changed, 1);
  const menu = (selected.json.model_selector_config as { models: { id: string }[] }[])[1]!.models;
  assert.equal(menu.length, DESKTOP_PICKER_ROW_LIMIT);
  assert.equal(menu.at(-1)!.id, extras[1]!.model);
  assert.equal(states(selected.json)[1]!.model, extras[1]!.model);
  assert.equal(select(cache, cfg, context("selection"), { model: extras[2]!.model }), null);
  assert.equal(select(cache, cfg, context("selection"), { model: extras.at(-1)!.model }), null);
});

test("exact-bound native thinking rows allow one bounded selected-extra row without dropping native preferences", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
  const rows = Array.from({ length: DESKTOP_PICKER_ROW_LIMIT }, (_, i) => ({ id: `claude-native-${i}`, thinking: { type: "effort", effort: "high" } }));
  states(json)[1]!.thinking_by_model = rows;
  assert.deepEqual(cache.observeBootstrap(context(), json, cfg), ["code", "ccd"]);
  const reply = select(cache, cfg)!;
  assert.ok(reply);
  assert.equal((reply.thinking_by_model as unknown[]).length, DESKTOP_PICKER_ROW_LIMIT + 1);
  assert.deepEqual((reply.thinking_by_model as unknown[]).slice(0, rows.length), rows);
  const result = overlay(cache, cfg, context(), structuredClone(json));
  assert.equal(result.changed, 1);
  assert.equal(states(result.json)[1]!.model, EXTRA);
  assert.deepEqual((states(result.json)[1]!.thinking_by_model as unknown[]).slice(0, rows.length), rows);
  const oversized = structuredClone(json);
  (states(oversized)[1]!.thinking_by_model as unknown[]).push({ id: "claude-native-over-limit", thinking: { type: "effort", effort: "high" } });
  assert.deepEqual(cache.observeBootstrap(context(), oversized, cfg), ["ccd"], "the native-input cap is unchanged");
});

test("unknown request fields, fast-mode combinations and malformed/unsupported thinking are never emulated", () => {
  for (const body of [null, [], "future", { model: EXTRA, fast_mode: "off" }, { model: EXTRA, future_field: true },
    { model: EXTRA, thinking: null }, { model: EXTRA, thinking: { type: "effort", effort: "max" } },
    { model: EXTRA, thinking: { type: "adaptive", effort: "high" } }, { model: EXTRA, thinking: { type: "effort", effort: "high", budget: 100 } },
    { model: "x".repeat(257) }, { model: `${EXTRA}\n` }]) {
    const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
    assert.equal(select(cache, cfg, context("selection"), body), null);
  }
});

test("a Google model with no declared effort ladder does not borrow another model's ladder", () => {
  const cache = new DesktopSelectionCache(); const cfg = config();
  cfg.providers.google!.models = [{ id: EXTRA }, { id: "other-gemini", effortLevels: ["high"] }];
  observe(cache, cfg);
  assert.equal(select(cache, cfg), null);
  assert.ok(select(cache, cfg, context("selection"), { model: EXTRA }));
});

test("approval revocation invalidates pending and remembered selection, with no reapproval resurrection", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  cfg.security!.approvedOrigins = ["https://api.anthropic.com"];
  assert.equal(cache.completeSelection(token, 400, REFUSAL, cfg), null);
  cfg.security!.approvedOrigins.push("https://generativelanguage.googleapis.com");
  assert.ok(select(cache, cfg));
  cfg.security!.approvedOrigins = ["https://api.anthropic.com"];
  assert.equal(overlay(cache, cfg).changed, 0);
  cfg.security!.approvedOrigins.push("https://generativelanguage.googleapis.com");
  assert.equal(overlay(cache, cfg).changed, 0);
});

test("a config change epoch prevents revoke/reapprove entirely between selection awaits", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  cfg.security!.approvedOrigins = []; cache.clear();
  cfg.security!.approvedOrigins = ["https://api.anthropic.com", "https://generativelanguage.googleapis.com"]; cache.clear();
  observe(cache, cfg);
  assert.equal(cache.completeSelection(token, 400, REFUSAL, cfg), null);
  assert.equal(overlay(cache, cfg).changed, 0);
});

test("a newly loaded Config object invalidates old pending responses even if values match", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const reloaded = structuredClone(cfg);
  assert.equal(cache.completeSelection(token, 400, REFUSAL, reloaded), null);
  assert.equal(overlay(cache, reloaded).changed, 0);
});

test("retargeted, removed, duplicate or unapproved extras cannot replay an old choice", () => {
  for (const mutate of [
    (cfg: Config) => { cfg.cli.extraModels = []; },
    (cfg: Config) => { cfg.cli.extraModels.push({ model: EXTRA, name: "Duplicate" }); },
    (cfg: Config) => { delete cfg.providers.google; },
    (cfg: Config) => { cfg.providers.google!.models![0]!.url = "https://unapproved.invalid"; },
    (cfg: Config) => { cfg.providers.second = { type: "google", auth: "api-key", apiKey: "synthetic", models: [{ id: EXTRA, effortLevels: ["low", "high"] }] };
      cfg.routes[EXTRA] = { provider: "second", model: EXTRA }; },
  ]) {
    const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
    mutate(cfg); assert.equal(overlay(cache, cfg).changed, 0);
  }
});

test("picker disable, leaving personal mode and explicit recovery clear the in-memory overlay", () => {
  for (const mutate of [(cfg: Config) => { cfg.picker!.enabled = false; }, (cfg: Config) => { delete cfg.security; }]) {
    const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
    mutate(cfg); assert.equal(overlay(cache, cfg).changed, 0);
    cfg.security = config().security!; cfg.picker = { enabled: true };
    assert.equal(overlay(cache, cfg).changed, 0);
  }
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  cache.clear(); assert.equal(overlay(cache, cfg).changed, 0);
});

test("native selection success remains untouched and updates the baseline for a later extra", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: "claude-sonnet-5" }, cfg);
  const reply = nativeState("code", "claude-sonnet-5"); const raw = JSON.stringify(reply);
  assert.equal(cache.completeSelection(token, 200, reply, cfg), null);
  assert.equal(JSON.stringify(reply), raw);
  const extraReply = select(cache, cfg);
  assert.deepEqual((extraReply!.thinking_by_model as unknown[])[0], reply.thinking_by_model[0]);
});

test("a successful native selection with additive metadata stays native and preserves its new baseline", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  const reply = { ...nativeState("code", "claude-sonnet-5"), future_optional: { native: true } };
  const before = JSON.stringify(reply);
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: "claude-sonnet-5" }, cfg);
  assert.equal(cache.completeSelection(token, 200, reply, cfg), null);
  assert.equal(JSON.stringify(reply), before);
  const fresh = bootstrap(); states(fresh)[1] = reply;
  assert.equal(overlay(cache, cfg, context(), fresh).changed, 0, "native success always clears the extra choice");
  assert.deepEqual(select(cache, cfg)!.future_optional, reply.future_optional);
});

test("effort-only and fast-mode native successes pass through and clear the remembered extra", () => {
  for (const request of [{ thinking: { type: "effort", effort: "low" } }, { fast_mode: "off" }, { future: "unknown-native-control" }]) {
    const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
    const response = nativeState(); const raw = JSON.stringify(response);
    const token = cache.prepareSelection(context("selection"), "PATCH", request, cfg);
    assert.equal(cache.completeSelection(token, 200, response, cfg), null);
    assert.equal(JSON.stringify(response), raw);
    assert.equal(overlay(cache, cfg).changed, 0);
  }
});

test("an unknown or empty successful native state drops the old template until fresh bootstrap", () => {
  for (const response of [null, { ...nativeState(), thinking: { type: "adaptive" } }, { ...nativeState(), id: "ccd" }, { ...nativeState(), model: EXTRA }]) {
    const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
    const token = cache.prepareSelection(context("selection"), "PATCH", { model: "claude-sonnet-5" }, cfg);
    assert.equal(cache.completeSelection(token, 200, response, cfg), null);
    assert.equal(select(cache, cfg), null);
    assert.equal(overlay(cache, cfg).changed, 0);
  }
});

test("older extra refusal cannot resurrect the choice after a later native selection success", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  const extra = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const native = cache.prepareSelection(context("selection"), "PATCH", { model: "claude-sonnet-5" }, cfg);
  assert.equal(cache.completeSelection(native, 200, nativeState("code", "claude-sonnet-5"), cfg), null);
  assert.equal(cache.completeSelection(extra, 400, REFUSAL, cfg), null);
  const json = bootstrap(); states(json)[1] = nativeState("code", "claude-sonnet-5");
  assert.equal(overlay(cache, cfg, context(), json).changed, 0);
});

test("a native ccd success invalidates an older code extra and clears the linked Code picker overlay", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  const extra = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const native = cache.prepareSelection(context("selection", "org-one", "synthetic-session-one", "ccd"), "PATCH", { model: "claude-opus-5" }, cfg);
  assert.equal(cache.completeSelection(native, 200, nativeState("ccd"), cfg), null);
  assert.equal(cache.completeSelection(extra, 400, REFUSAL, cfg), null);
  assert.equal(overlay(cache, cfg).changed, 0);
});

test("a changed sibling native bootstrap preference clears both linked surfaces", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  const extra = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  const json = bootstrap(); states(json)[2] = nativeState("ccd", "claude-sonnet-5");
  assert.equal(overlay(cache, cfg, context(), json).changed, 0);
  assert.equal(cache.completeSelection(extra, 400, REFUSAL, cfg), null);
});

test("out-of-order extra writes only accept the most recently started request", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg);
  const first = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA, thinking: { type: "effort", effort: "high" } }, cfg);
  const second = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA, thinking: { type: "effort", effort: "low" } }, cfg);
  assert.equal(cache.completeSelection(first, 400, REFUSAL, cfg), null);
  assert.deepEqual(cache.completeSelection(second, 400, REFUSAL, cfg)?.thinking, { type: "effort", effort: "low" });
  assert.deepEqual(states(overlay(cache, cfg).json)[1]!.thinking, { type: "effort", effort: "low" });
});

test("completion tokens are single-use, opaque and local to one cache", () => {
  const cache = new DesktopSelectionCache(); const other = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); observe(other, cfg);
  const token = cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  assert.equal(JSON.stringify(token), "{}");
  assert.equal(other.completeSelection(token, 400, REFUSAL, cfg), null);
  assert.ok(cache.completeSelection(token, 400, REFUSAL, cfg));
  assert.equal(cache.completeSelection(token, 400, REFUSAL, cfg), null);
  assert.equal(cache.completeSelection(Object.freeze({}) as DesktopSelectionToken, 400, REFUSAL, cfg), null);
});

test("idle state and pending requests expire within bounded time", () => {
  let now = 0; const cache = new DesktopSelectionCache({ now: () => now, ttlMs: 100 }); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  now = 100; assert.equal(overlay(cache, cfg).changed, 0);
  const longCache = new DesktopSelectionCache({ now: () => now }); observe(longCache, cfg);
  const token = longCache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg);
  now += 30_000;
  assert.equal(longCache.completeSelection(token, 400, REFUSAL, cfg), null);
});

test("cache capacity evicts old scopes and pending tokens without retaining identities", () => {
  const cache = new DesktopSelectionCache({ maxScopes: 1, maxPending: 1 }); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  observe(cache, cfg, context("bootstrap", "org-two"));
  assert.equal(cache.prepareSelection(context("selection"), "PATCH", { model: EXTRA }, cfg), null);
  const code = cache.prepareSelection(context("selection", "org-two"), "PATCH", { model: EXTRA }, cfg);
  const ccd = cache.prepareSelection(context("selection", "org-two", "synthetic-session-one", "ccd"), "PATCH", { model: EXTRA }, cfg);
  assert.equal(cache.completeSelection(code, 400, REFUSAL, cfg), null);
  assert.ok(cache.completeSelection(ccd, 400, REFUSAL, cfg));
});

test("changed native preference on a fresh bootstrap wins over the local extra overlay", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  const json = bootstrap(); states(json)[1] = nativeState("code", "claude-sonnet-5");
  assert.equal(overlay(cache, cfg, context(), json).changed, 0);
  assert.equal(states(json)[1]!.model, "claude-sonnet-5");
});

test("state overlay never points at a hidden extra or edits a changed/unknown bootstrap shape", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); observe(cache, cfg); assert.ok(select(cache, cfg));
  const noExtra = bootstrap(); const raw = JSON.stringify(noExtra);
  assert.equal(cache.overlayBootstrap(context(), noExtra, cfg), 0);
  assert.equal(JSON.stringify(noExtra), raw);
  const changed = bootstrap(); states(changed)[1]!.thinking = { type: "effort", effort: "low" };
  injectPickerModels(changed, chatPickerModels(cfg), undefined, undefined, { codeOnly: true, compatibleCodeSurfaces: ["code", "ccd"] });
  const changedRaw = JSON.stringify(changed);
  assert.equal(cache.overlayBootstrap(context(), changed, cfg), 0);
  assert.equal(JSON.stringify(changed), changedRaw);
});

test("minimal measured state shapes are supported without fabricated native properties", () => {
  const cache = new DesktopSelectionCache(); const cfg = config(); const json = bootstrap();
  json.model_selector_state = [{ id: "code", model: "claude-opus-5" }];
  observe(cache, cfg, context(), json);
  assert.deepEqual(select(cache, cfg, context("selection"), { model: EXTRA }), { id: "code", model: EXTRA, thinking_by_model: [] });
});
