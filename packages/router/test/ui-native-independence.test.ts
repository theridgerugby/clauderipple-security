// Render the production connection card against in-memory DOM/state fixtures only.
// Diagnostics, timers, native actions, accounts and network are all tripwired off.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../../ui/app.js", import.meta.url), "utf8").replaceAll("\r\n", "\n");
const translations = fs.readFileSync(new URL("../../ui/i18n.js", import.meta.url), "utf8").replaceAll("\r\n", "\n");
function block(from: string, to: string): string {
  const start = source.indexOf(from), end = source.indexOf(to, start);
  assert.ok(start >= 0 && end > start, `missing production UI section ${from}`);
  return source.slice(start, end);
}
const i18nStart = translations.indexOf("const I18N = {");
const i18nEnd = translations.indexOf("/** The languages offered", i18nStart);
assert.ok(i18nStart >= 0 && i18nEnd > i18nStart);
const dictionary = new Function(`${translations.slice(i18nStart, i18nEnd)}; return I18N;`)() as Record<string, Record<string, string>>;

class FixtureNode {
  tag: string;
  attrs: Record<string, string> = {};
  className = "";
  textContent = "";
  hidden = false;
  disabled = false;
  open = false;
  children: FixtureNode[] = [];
  listeners = new Map<string, (() => unknown)[]>();
  constructor(tag: string) { this.tag = tag; }
  setAttribute(key: string, value: unknown): void { this.attrs[key] = String(value); }
  appendChild(node: FixtureNode): FixtureNode { this.children.push(node); return node; }
  replaceChildren(...nodes: FixtureNode[]): void { this.children = nodes; }
  addEventListener(event: string, callback: () => unknown): void { this.listeners.set(event, [...(this.listeners.get(event) ?? []), callback]); }
  descendants(): FixtureNode[] { return [this, ...this.children.flatMap(node => node.descendants())]; }
}
const text = (node: FixtureNode) => node.descendants().map(item => item.textContent).filter(Boolean).join(" ");
const report = (originalIndependent: unknown, knownCouplingsAbsent: unknown = null) => ({ schemaVersion: 1, scope: "installation-local-persisted-state", originalIndependent, knownCouplingsAbsent });
const state = (native?: unknown, mode = "ripple", answering = true) => ({
  doctor: { mode, router: { responding: answering }, desktop: { proxy: "ripple" }, cli: { proxy: "ripple" }, problems: [], ...(native === undefined ? {} : { nativeIndependence: native }) },
  routerAnswering: answering, doctorFailed: false, busy: null, result: null, restartClaude: false, loginItem: null,
});

function harness(language = "en", native = true) {
  const host = new FixtureNode("section"), desktop = new FixtureNode("section");
  const requests: string[] = [];
  const fail = (name: string) => () => { requests.push(name); throw new Error(`unexpected side effect ${name}`); };
  const app = native ? {
    repair: fail("repair"), directOn: fail("directOn"), directOff: fail("directOff"), restartClaude: fail("restartClaude"),
    refresh: fail("refresh"), openLogs: fail("openLogs"), recentLog: fail("recentLog"), enableLoginItem: fail("enableLoginItem"),
  } : null;
  const document = {
    createElement: (tag: string) => new FixtureNode(tag),
    createTextNode: (value: string) => { const node = new FixtureNode("#text"); node.textContent = value; return node; },
  };
  const h = {
    app, document, Node: FixtureNode,
    $: (selector: string) => selector === "#health-connection" ? host : selector === "#health-desktop-section" ? desktop :
      selector === "#conn-native-independence-slot" ? host.descendants().find(node => node.attrs.id === "conn-native-independence-slot") : null,
    $all: () => [],
    t: (key: string, vars?: Record<string, unknown>) => {
      let value = dictionary[language]?.[key] ?? dictionary.en![key] ?? key;
      for (const [name, replacement] of Object.entries(vars ?? {})) value = value.split(`{${name}}`).join(String(replacement));
      return value;
    },
    effect: fail("query-or-timer"),
  };
  const ui = new Function("h", `
    const {document, Node, $, $all, t} = h;
    const APP = h.app, api = h.effect, fetch = h.effect, setTimeout = h.effect, setInterval = h.effect;
    let currentConfig = null, shellState = null, routerDown = false, status = null;
    const showView = h.effect, refreshHealth = h.effect, toast = h.effect;
    const svgIcon = () => new Node("svg");
    ${block("function el(", "// Inside the ClaudeRipple app")}
    ${block("function genericControlsAvailable(", "function selectOption(")}
    ${block("const CONN_ICONS =", "\nif (APP) {")}
    return {
      setConfig: value => { currentConfig = value; applyDesktopUiProfile(); },
      render: value => { shellState = value; renderConnection(); },
      model: value => connectionModel(value),
    };
  `)(h) as { setConfig(value: unknown): void; render(value: unknown): void; model(value: unknown): unknown };
  return { ...ui, host, requests,
    note: () => host.descendants().find(node => node.className.split(" ").includes("conn-native-independence")),
    buttons: () => host.descendants().filter(node => node.tag === "button").map(node => node.textContent),
  };
}

test("a healthy router still shows native proxy coupling separately", () => {
  const view = harness(); view.setConfig({ security: { mode: "personal" } });
  const baseline = state(), coupled = state(report(false, false));
  view.render(baseline); const controls = view.buttons(), model = view.model(baseline);
  view.render(coupled);
  assert.deepEqual(view.model(coupled), model, "router health semantics stay unchanged");
  assert.deepEqual(view.buttons(), controls, "the note adds no native action");
  assert.equal(view.host.className, "conn conn-ok calm");
  const note = view.note(); assert.ok(note);
  assert.match(text(note), /Proxy settings still couple/);
  assert.match(text(note), /Router health does not establish independent operation/);
  assert.equal(note.attrs.role, "status");
  assert.doesNotMatch(note.className, /\b(good|ok|success)\b/);
  assert.deepEqual(view.requests, []);
});

test("clear saved state remains unverified and side effects do not become a traffic claim", () => {
  const view = harness(); view.setConfig({ security: { mode: "personal" } });
  view.render(state(report(null, true)));
  assert.match(text(view.note()!), /No known coupling .* inspected saved state/);
  assert.match(text(view.note()!), /still needs verification/);
  view.render(state(report(null, false), "direct", false));
  assert.match(text(view.note()!), /CA trust, saved restoration or background components remain/);
  assert.match(text(view.note()!), /independence is unverified/);
  assert.doesNotMatch(text(view.note()!), /Proxy settings still couple/);
  assert.deepEqual(view.requests, []);
});

test("missing, malformed and future true reports never render a passed independence status", () => {
  const view = harness(); view.setConfig({ security: { mode: "personal" } });
  for (const value of [undefined, null, {}, [], "private raw error", report(null), report(true, true), report("false", "true"),
    { ...report(false, false), schemaVersion: 2 }, { ...report(null, true), scope: "future-scope" }]) {
    view.render(state(value));
    const note = view.note(); assert.ok(note);
    assert.match(text(note), /independence has not been verified/);
    assert.doesNotMatch(note.className, /\b(good|ok|success)\b/);
  }
  assert.deepEqual(view.requests, []);
});

test("the note appears only after personal configuration loads and disappears in generic mode", () => {
  const view = harness(); view.render(state(report(false, false)));
  assert.equal(view.note(), undefined);
  view.setConfig({ security: { mode: "personal" } });
  assert.ok(view.note(), "the profile arrival redraws the already loaded doctor result");
  view.setConfig({ security: { mode: "generic" } });
  assert.equal(view.note(), undefined);
  view.setConfig(null); assert.equal(view.note(), undefined);
  const browser = harness("en", false); browser.setConfig({ security: { mode: "personal" } }); browser.render(state(report(false, false)));
  assert.equal(browser.note(), undefined);
  assert.deepEqual(view.requests, []); assert.deepEqual(browser.requests, []);
});

test("connection modes keep their original controls and notes never request a diagnostic", () => {
  const view = harness(); view.setConfig({ security: { mode: "personal" } });
  for (const [mode, answering] of [["direct", false], ["ripple", false], ["mixed", true], ["ripple", true]] as const) {
    const baseline = state(undefined, mode, answering), changed = state(report(false, false), mode, answering);
    view.render(baseline); const buttons = view.buttons(), model = view.model(baseline);
    view.render(changed);
    assert.deepEqual(view.buttons(), buttons);
    assert.deepEqual(view.model(changed), model);
    assert.ok(view.note());
  }
  assert.deepEqual(view.requests, [], "no action, log fetch, timer, refresh or network was invoked by rendering");
});

test("profile arrival updates only the note and preserves open diagnostics and control nodes", () => {
  const view = harness(); view.render(state(report(null, false), "direct", false));
  const fold = view.host.descendants().find(node => node.className === "conn-details");
  assert.ok(fold); fold.open = true;
  const buttons = view.host.descendants().filter(node => node.tag === "button");
  view.setConfig({ security: { mode: "personal" } });
  assert.ok(view.note());
  assert.equal(view.host.descendants().find(node => node.className === "conn-details"), fold);
  assert.equal(fold.open, true);
  assert.deepEqual(view.host.descendants().filter(node => node.tag === "button"), buttons);
  view.setConfig({ security: { mode: "generic" } });
  assert.equal(view.note(), undefined);
  assert.equal(view.host.descendants().find(node => node.className === "conn-details"), fold);
  assert.deepEqual(view.requests, []);
});

test("raw findings, paths and injected markup never enter the note", () => {
  const secret = '<img src=x onerror="throw 1"> C:\\private\\account\\secret';
  const value = { ...report(false, false), limitations: [secret], detail: secret };
  Object.defineProperty(value, "findings", { get() { throw new Error("raw findings must not be read by the UI"); } });
  const view = harness(); view.setConfig({ security: { mode: "personal" } }); view.render(state(value));
  assert.ok(view.note());
  assert.ok(!text(view.host).includes(secret));
  assert.equal(view.note()!.descendants().some(node => ["img", "script", "a", "input", "button"].includes(node.tag)), false);
  assert.deepEqual(view.requests, []);
});

test("English and Chinese have fixed text and other locales use the existing English fallback", () => {
  const keys = ["title", "coupled", "savedClear", "effects", "unknown"].map(name => `conn.native.${name}`);
  for (const language of ["en", "zh"]) for (const key of keys) assert.ok(dictionary[language]?.[key], `${language}: ${key}`);
  const chinese = harness("zh"); chinese.setConfig({ security: { mode: "personal" } }); chinese.render(state(report(false, false)));
  assert.match(text(chinese.note()!), /代理设置仍依赖 Ripple/);
  for (const language of ["ko", "ja", "es", "pt"]) {
    const view = harness(language); view.setConfig({ security: { mode: "personal" } }); view.render(state());
    assert.ok(text(view.note()!).includes(dictionary.en!["conn.native.unknown"]!));
    assert.doesNotMatch(text(view.note()!), /conn\.native\./);
  }
});
