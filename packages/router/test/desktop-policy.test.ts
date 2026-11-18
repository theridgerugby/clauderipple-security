// These are routing-decision fixtures. They do not represent an observed Desktop bootstrap or
// exercise native Windows trust, a real subscription, or a real Google AI Studio API key.
import { test } from "node:test";
import assert from "node:assert/strict";
import { normalizeConfig, type Config } from "../src/config.ts";
import { personalDesktopProblems, preserveNativeDesktopModel } from "../src/desktop-policy.ts";
import { decide, resolve, type RequestKind } from "../src/routing.ts";
import { bootstrapModels, bootstrapWindows, injectBootstrap } from "../src/bootstrap.ts";
import { effortLevelsForModel } from "../src/admin.ts";
import { chatPickerModels, injectPickerModels } from "../src/picker.ts";

const NATIVE = "claude-opus-5-5";
const GEMINI = "gemini-4-carbon";
const PASS = { route: null, refusal: null };
const textBody = (text = "Synthetic ordinary request") => ({ model: NATIVE, messages: [{ role: "user", content: text }] });
function config(): Config {
  return normalizeConfig({
    autoUpdate: false,
    security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com", "https://claude.ai", "https://generativelanguage.googleapis.com"] },
    picker: { enabled: true },
    providers: { google: { type: "google", auth: "api-key", apiKey: "SYNTHETIC-TEST-KEY", models: [{ id: GEMINI }] } },
    routes: {}, aliases: {}, direct: [],
    cli: { extraModels: [{ model: GEMINI, name: "Synthetic Google extra" }] },
  });
}

test("native preservation is limited to personal mode with the Desktop picker enabled", () => {
  const cfg = config();
  for (const model of [NATIVE, "claude-sonnet-5-5", "claude-haiku-5-5", "claude-fable-5-2", "claude-opus-4-6[1m]",
    "opus", "sonnet", "haiku", "fable", "best", "default", "opusplan", "opus[1m]", "SONNET"]) {
    assert.equal(preserveNativeDesktopModel(cfg, model), true, model);
    const off = structuredClone(cfg); off.picker = { enabled: false };
    assert.equal(preserveNativeDesktopModel(off, model), false, `${model}: picker off`);
    const absent = structuredClone(cfg); delete absent.picker;
    assert.equal(preserveNativeDesktopModel(absent, model), false, `${model}: picker absent`);
    const generic = structuredClone(cfg); delete generic.security;
    assert.equal(preserveNativeDesktopModel(generic, model), false, `${model}: generic mode`);
  }
  for (const model of [GEMINI, `google:${GEMINI}`, "not-claude-model", "vendor:claude-opus-5-5", "", null, undefined, 7, {}, []]) {
    assert.equal(preserveNativeDesktopModel(cfg, model), false);
  }
});

test("the supported effort suffix cannot bypass preservation of a native Claude base", () => {
  const cfg = config();
  cfg.routes[NATIVE] = { provider: "google", model: GEMINI };
  cfg.routes[`${NATIVE}[1m]`] = { provider: "google", model: GEMINI };
  for (const model of [`${NATIVE}@high`, `${NATIVE}[1m]@high`, "opus@low"]) {
    assert.equal(preserveNativeDesktopModel(cfg, model), true, model);
    assert.deepEqual(decide(model, textBody(), cfg, "turn", true), PASS, model);
  }
});

test("old native routes, broad direct rules and external native catalogues cannot take subscription models", () => {
  const changes: [string, (cfg: Config) => void][] = [
    ["explicit route", cfg => { cfg.routes[NATIVE] = { provider: "google", model: GEMINI }; }],
    ["native direct prefix", cfg => { cfg.direct = [{ prefix: "claude-", provider: "google" }]; }],
    ["broad direct prefix", cfg => { cfg.direct = [{ prefix: "cla", provider: "google" }]; }],
    ["provider catalogue", cfg => { cfg.providers.google!.models!.push({ id: NATIVE }); }],
    ["native alias and prompt marker", cfg => { cfg.aliases[NATIVE] = GEMINI; cfg.aliases.extra = GEMINI; }],
  ];
  for (const [label, change] of changes) {
    const cfg = config(); change(cfg);
    const body = textBody("[[ripple: extra]] Synthetic task");
    const beforeConfig = structuredClone(cfg), beforeBody = structuredClone(body);
    assert.deepEqual(decide(NATIVE, body, cfg, "turn", true), PASS, label);
    assert.equal(resolve(NATIVE, body, cfg), null, label);
    assert.deepEqual(cfg, beforeConfig, `${label}: config stays untouched`);
    assert.deepEqual(body, beforeBody, `${label}: native request stays untouched`);
  }
});

test("a user prompt marker cannot redirect a native Desktop request to a valid or ambiguous extra", () => {
  const cfg = config();
  cfg.aliases.extra = GEMINI;
  for (const marker of ["extra", GEMINI, `google:${GEMINI}`, "missing-extra"]) {
    assert.deepEqual(decide(NATIVE, textBody(`[[ripple: ${marker}]] Synthetic request`), cfg, "turn"), PASS, marker);
  }
  cfg.providers.other = { type: "google", auth: "api-key", apiKey: "SECOND-SYNTHETIC-KEY", models: [{ id: GEMINI }] };
  assert.deepEqual(decide(NATIVE, textBody(`[[ripple: ${GEMINI}]] Synthetic request`), cfg, "turn"), PASS,
    "an ambiguous prompt marker must not turn the native request into a routing refusal");
});

test("native classifier and side-request kinds bypass an old classifier override and web-search override", () => {
  const cfg = config();
  cfg.routes[NATIVE] = { provider: "google", model: GEMINI };
  cfg.autoModeClassifier = { provider: "google", model: GEMINI, stage1: { provider: "google", model: GEMINI } };
  cfg.webSearch = { provider: "google", model: GEMINI };
  const body = { ...textBody("[[ripple: extra]] Synthetic security check"), system: "You are a security monitor for autonomous AI coding agents.",
    max_tokens: 64, stop_sequences: ["</block>"] };
  for (const kind of ["auto-mode-classifier", "web-search", "web-fetch", "compaction", "turn"] satisfies RequestKind[]) {
    assert.deepEqual(decide(NATIVE, body, cfg, kind, true), PASS, kind);
  }
});

test("the native preservation guard returns before inspecting prompt contents or route getters", () => {
  const cfg = config();
  Object.defineProperty(cfg, "routes", { get() { throw new Error("route configuration should not be consulted"); } });
  Object.defineProperty(cfg, "autoModeClassifier", { get() { throw new Error("classifier should not be consulted"); } });
  const request = { get messages() { throw new Error("prompt should not be inspected"); }, get system() { throw new Error("system should not be inspected"); } };
  assert.deepEqual(decide(NATIVE, request, cfg, "auto-mode-classifier", true), PASS);
});

test("an enabled Claude account pool cannot replace the app's native subscription credentials", () => {
  const cfg = config();
  cfg.providers.pool = { type: "anthropic", auth: "claude-code", accountPool: true, models: [{ id: NATIVE }] };
  cfg.providers.metered = { type: "anthropic", auth: "api-key", apiKey: "SYNTHETIC-METERED-KEY", models: [{ id: NATIVE }] };
  for (const model of [NATIVE, "claude-sonnet-5-5", "claude-fable-5-2"]) {
    for (const pooled of [false, true]) assert.deepEqual(decide(model, textBody(), cfg, "turn", pooled), PASS);
  }
});

test("a distinct Gemini picker selection still resolves to its own Google provider", () => {
  const cfg = config();
  for (const model of [GEMINI, `${GEMINI}@high`, `google:${GEMINI}`]) {
    const body = { ...textBody(), model }, before = structuredClone(body);
    const result = decide(model, body, cfg, "turn", true);
    assert.equal(result.refusal, null);
    assert.equal(result.route?.provider, "google");
    assert.equal(result.route?.model, GEMINI);
    assert.equal(result.route?.asked, model);
    assert.deepEqual(body, before);
  }
});

test("generic and picker-off users retain their explicit route, prompt marker, classifier and pool behavior", () => {
  for (const mode of ["generic", "picker-off"] as const) {
    const cfg = config();
    if (mode === "generic") delete cfg.security;
    else cfg.picker = { enabled: false };
    cfg.routes[NATIVE] = { provider: "google", model: GEMINI };
    assert.equal(decide(NATIVE, textBody(), cfg, "turn").route?.provider, "google", `${mode}: explicit route`);
    delete cfg.routes[NATIVE];
    cfg.aliases.extra = GEMINI;
    assert.equal(decide(NATIVE, textBody("[[ripple: extra]] Synthetic task"), cfg, "turn").route?.provider, "google", `${mode}: marker`);
    cfg.autoModeClassifier = { provider: "google", model: GEMINI };
    assert.equal(decide(NATIVE, textBody(), cfg, "auto-mode-classifier").route?.provider, "google", `${mode}: classifier`);
    delete cfg.autoModeClassifier;
    cfg.providers.pool = { type: "anthropic", auth: "claude-code", accountPool: true };
    assert.equal(decide(NATIVE, textBody(), cfg, "turn", true).route?.provider, "pool", `${mode}: pool`);
  }
});

test("the activation policy diagnoses existing native takeover without mutating its configuration", () => {
  const cfg = config();
  assert.deepEqual(personalDesktopProblems(cfg), []);
  cfg.cli.models = { main: "", smallFast: "", subagent: "" };
  assert.deepEqual(personalDesktopProblems(cfg), [], "legacy empty slots mean keep native defaults");
  cfg.routes[NATIVE] = { provider: "google", model: GEMINI };
  const before = structuredClone(cfg);
  assert.ok(personalDesktopProblems(cfg).some(problem => problem.includes("preserves native Claude model routes")));
  assert.deepEqual(cfg, before);
  cfg.picker = { enabled: false };
  assert.deepEqual(personalDesktopProblems(cfg), [], "recovery can read a legacy config without its disabled Desktop policy blocking it");
});

test("a legacy native route cannot replace the Desktop worker bootstrap's native context limits", () => {
  const cfg = config();
  cfg.routes[NATIVE] = { provider: "google", model: GEMINI, contextWindow: 999_999 };
  cfg.routes[`${NATIVE}@high`] = { provider: "google", model: GEMINI };
  cfg.cli.autoCompactWindow = 1_000_000;
  const original = { additional_model_options: [{ model: NATIVE, name: "Native unchanged", contextWindow: 200_000 }],
    auto_compact_windows: { [NATIVE]: 200_000, [`${NATIVE}@high`]: 195_000 }, other: { native: true } };
  const out = JSON.parse(injectBootstrap(Buffer.from(JSON.stringify(original)), cfg, []).toString());
  assert.equal(out.auto_compact_windows[NATIVE], 200_000);
  assert.equal(out.auto_compact_windows[`${NATIVE}@high`], 195_000);
  assert.equal(out.auto_compact_windows[GEMINI], 1_000_000);
  assert.deepEqual(out.additional_model_options[0], original.additional_model_options[0]);
  assert.deepEqual(out.other, original.other);
  assert.equal(Object.hasOwn(bootstrapWindows(cfg), NATIVE), false);
  assert.equal(Object.hasOwn(bootstrapWindows(cfg, [{ model: NATIVE, name: "Old entry", contextWindow: 1_000_000 }]), NATIVE), false);
});

test("personal bootstrap never reads unrelated terminal agent definitions", () => {
  const cfg = config();
  const unexpectedRead = new Proxy([] as string[], { get() { throw new Error("global agent directories must not be inspected"); } });
  assert.deepEqual(bootstrapModels(cfg, unexpectedRead).map(entry => entry.model), [GEMINI]);
});

test("personal Google picker advertises only the chosen model's own supported effort levels", () => {
  const cfg = config();
  cfg.providers.google!.models!.push({ id: "gemini-other-fixture", effortLevels: ["high"] });
  const native = { id: NATIVE, name: "Native", thinking: { effort_options: [{ id: "high", recommended: true }] } };
  const menu = { model_selector_config: [{ id: "code", models: [structuredClone(native)] as Record<string, unknown>[] }] };
  assert.deepEqual(effortLevelsForModel(cfg, GEMINI), []);
  injectPickerModels(menu, chatPickerModels(cfg), undefined, id => effortLevelsForModel(cfg, id), { codeOnly: true });
  assert.deepEqual(menu.model_selector_config[0]!.models[0], native);
  assert.equal(Object.hasOwn(menu.model_selector_config[0]!.models[1]!, "thinking"), false);
  cfg.providers.google!.models![0]!.effortLevels = ["low", "high"];
  assert.deepEqual(effortLevelsForModel(cfg, GEMINI), ["low", "high"]);
});

test("personal Desktop menu selection cannot be replaced by prompt markers, legacy classifiers or route fallbacks", () => {
  const cfg = config();
  const alternate = "gemini-other-fixture";
  cfg.providers.other = { type: "google", auth: "api-key", apiKey: "SYNTHETIC-OTHER-KEY", models: [{ id: alternate }] };
  cfg.aliases.other = alternate;
  cfg.autoModeClassifier = { provider: "other", model: alternate };
  for (const marker of [alternate, `other:${alternate}`, "other", "unconfigured-model"]) {
    const body = { model: GEMINI, messages: [{ role: "user", content: `[[ripple: ${marker}]] Synthetic content` }] };
    const before = structuredClone(body);
    for (const kind of ["turn", "auto-mode-classifier", "compaction", "web-fetch"] satisfies RequestKind[]) {
      const result = decide(GEMINI, body, cfg, kind);
      assert.equal(result.route?.provider, "google", `${marker}/${kind}`);
      assert.equal(result.route?.model, GEMINI, `${marker}/${kind}`);
      assert.equal(result.refusal, null);
      assert.deepEqual(body, before);
    }
  }
  cfg.routes[GEMINI] = { provider: "google", model: GEMINI, fallbacks: [{ provider: "google", model: alternate }, { provider: "other", model: alternate }] };
  assert.equal(decide(GEMINI, {}, cfg, "turn").route?.fallbacks, undefined);
  const generic = structuredClone(cfg); delete generic.security;
  assert.deepEqual(decide(GEMINI, {}, generic, "turn").route?.fallbacks, cfg.routes[GEMINI].fallbacks,
    "generic mode keeps its explicit routing behavior");
});
