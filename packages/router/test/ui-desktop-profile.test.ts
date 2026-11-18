// Execute the production UI profile/navigation and handler guards. All fixtures are in memory;
// no installed Desktop, account, certificate trust store or provider credential is involved.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { desktopUiGuardSource } from "./ui-native-fixture.ts";

const source = fs.readFileSync(new URL("../../ui/app.js", import.meta.url), "utf8").replaceAll("\r\n", "\n");
const html = fs.readFileSync(new URL("../../ui/index.html", import.meta.url), "utf8");
function block(from: string, to: string): string {
  const start = source.indexOf(from), end = source.indexOf(to, start);
  assert.ok(start >= 0 && end > start, `missing UI block: ${from}`);
  return source.slice(start, end);
}
// These source functions are top-level declarations; their closing brace starts a line, while
// nested blocks are indented. One-line declarations are deliberately handled as a whole line.
function declaration(name: string): string {
  const match = new RegExp(`^(?:async )?function ${name}\\(`, "m").exec(source);
  assert.ok(match, `missing UI function: ${name}`);
  const start = match.index, lineEnd = source.indexOf("\n", start);
  if (source.slice(start, lineEnd).trimEnd().endsWith("}")) return source.slice(start, lineEnd);
  const end = source.indexOf("\n}", lineEnd);
  assert.ok(end > start, `missing UI function end: ${name}`);
  return source.slice(start, end + 2);
}

class FixtureNode {
  tag: string;
  id = "";
  attrs: Record<string, string> = {};
  dataset: Record<string, string> = {};
  hidden = false;
  disabled = false;
  checked = false;
  textContent = "";
  className = "";
  children: FixtureNode[] = [];
  parentElement: FixtureNode | null = null;
  listeners = new Map<string, (() => unknown)[]>();
  classes = new Set<string>();
  classList = {
    contains: (name: string) => this.classes.has(name),
    toggle: (name: string, on: boolean) => { if (on) this.classes.add(name); else this.classes.delete(name); },
  };
  constructor(tag: string) { this.tag = tag; }
  setAttribute(key: string, value: unknown): void { this.attrs[key] = String(value); }
  removeAttribute(key: string): void { delete this.attrs[key]; }
  appendChild(node: FixtureNode): FixtureNode { node.parentElement = this; this.children.push(node); return node; }
  append(...nodes: FixtureNode[]): void { nodes.forEach(node => this.appendChild(node)); }
  replaceChildren(...nodes: FixtureNode[]): void { this.children = []; this.append(...nodes); }
  get lastElementChild(): FixtureNode | undefined { return this.children.at(-1); }
  remove(): void { if (this.parentElement) this.parentElement.children = this.parentElement.children.filter(node => node !== this); }
  addEventListener(event: string, callback: () => unknown): void { this.listeners.set(event, [...(this.listeners.get(event) || []), callback]); }
  descendants(): FixtureNode[] { return [this, ...this.children.flatMap(node => node.descendants())]; }
  async click(): Promise<void> { for (const callback of this.listeners.get("click") || []) await callback(); }
}
const documentFixture = {
  createElement: (tag: string) => new FixtureNode(tag),
  createTextNode: (text: string) => { const node = new FixtureNode("#text"); node.textContent = text; return node; },
};
const genericOnly = ["slots", "phone", "mac", "mod"];
const allViews = ["health", "providers", "clients", "logs", "about", ...genericOnly];
type Config = Record<string, unknown> | null;

function navigation(initial: Config = null, down = false) {
  const views = allViews.map(name => { const node = new FixtureNode("section"); node.id = `view-${name}`; return node; });
  const nav = allViews.map(name => { const node = new FixtureNode("button"); node.dataset.view = name; return node; });
  const restricted = [...views, ...nav].filter(node => genericOnly.includes(node.dataset.view || node.id.replace("view-", "")));
  const add = new FixtureNode("button"); add.disabled = true;
  const title = new FixtureNode("span"); title.dataset = { i18n: "nav.clients", personalI18n: "clients.desktop.title" };
  const loads: string[] = [], queued: (() => void)[] = [];
  const location = { hash: "" };
  const h = {
    config: initial,
    $: (selector: string) => selector === "#providers-add" ? add : selector === ".view.active" ? views.find(node => node.classList.contains("active")) : null,
    $all: (selector: string) => {
      if (selector === ".view") return views;
      if (selector === ".nav-btn") return nav;
      if (selector === "[data-generic-only]") return restricted;
      if (selector === "[data-personal-i18n]") return [title];
      throw new Error(`unexpected selector: ${selector}`);
    },
    location, history: { replaceState: (_state: unknown, _title: string, hash: string) => { location.hash = hash; } },
    offline: () => down,
    queueMicrotask: (work: () => void) => { queued.push(work); },
    load: (name: string) => { loads.push(name); },
  };
  const ui = new Function("h", `
    let currentConfig = h.config, phoneGeneration = 0, slotsLoaded = false, providersLoaded = false, clientsLoaded = false;
    const {$, $all, location, history, offline, queueMicrotask} = h;
    const t = key => key, hidePhoneQr = () => {}, applyOffline = () => {};
    const loadPhone = () => h.load("phone"), loadMac = () => h.load("mac"), loadSlots = () => h.load("slots");
    const loadProviders = () => h.load("providers"), openClients = () => h.load("clients");
    const refreshRequests = () => h.load("logs"), loadMod = () => h.load("mod");
    ${block("function genericControlsAvailable(", "function selectOption(")}
    ${declaration("showView")}
    return {showView, applyDesktopUiProfile, setConfig: next => {currentConfig = next; applyDesktopUiProfile();}, pending: () => deferredGenericView};
  `)(h) as { showView(name: string): void; applyDesktopUiProfile(): void; setConfig(config: Config): void; pending(): string | null };
  const flush = () => { while (queued.length) queued.shift()!(); };
  return { ...ui, flush, nav, views, restricted, add, loads, location, title,
    active: () => views.find(node => node.classList.contains("active"))?.id };
}

test("unsupported pages and controls are hidden in initial HTML while Desktop and recovery remain reachable", () => {
  for (const name of genericOnly) {
    const nav = html.match(new RegExp(`<button\\b[^>]*data-view="${name}"[^>]*>`))?.[0];
    const view = html.match(new RegExp(`<section\\b[^>]*id="view-${name}"[^>]*>`))?.[0];
    for (const tag of [nav, view]) { assert.ok(tag); assert.match(tag, /\bdata-generic-only\b/); assert.match(tag, /\bhidden\b/); }
  }
  assert.match(html.match(/<button\b[^>]*id="providers-add"[^>]*>/)![0], /\bdisabled\b/);
  const sectionStack: string[] = [];
  const owners = new Map<string, boolean>();
  for (const token of html.matchAll(/<(\/?)([a-z][\w-]*)\b([^>]*)>/gi)) {
    if (token[2] === "section") {
      if (token[1]) { sectionStack.pop(); continue; }
      sectionStack.push(token[3]!);
    }
    const id = /\bid="([^"]+)"/.exec(token[3]!);
    if (id) owners.set(id[1]!, sectionStack.some(attrs => /\bdata-generic-only\b/.test(attrs)));
  }
  for (const id of ["client-model-slots", "client-auto-classifier", "client-status-mod-toggle", "client-worker-tools-toggle", "client-codex-toggle", "client-claude-code-rows"])
    assert.equal(owners.get(id), true, id);
  for (const id of ["view-health", "view-about", "client-picker-toggle", "client-picker-models", "client-picker-order"])
    assert.equal(owners.get(id), false, id);
});

for (const page of genericOnly) {
  test(`pre-config #${page} cannot start its loader; personal profile keeps Status`, () => {
    const view = navigation();
    view.showView(page); view.flush();
    assert.equal(view.active(), "view-health");
    assert.equal(view.location.hash, "#health");
    assert.equal(view.pending(), page);
    assert.deepEqual(view.loads, []);
    const personal = Object.freeze({security: Object.freeze({mode:"personal"}), routes: Object.freeze({keep: "unchanged"})});
    view.setConfig(personal); view.flush();
    assert.equal(view.active(), "view-health");
    assert.equal(view.pending(), null);
    assert.equal(view.add.disabled, false);
    assert.ok(view.restricted.every(node => node.hidden));
    assert.equal(view.title.textContent, "clients.desktop.title");
    assert.deepEqual(view.loads, []);
    assert.deepEqual(personal.routes, {keep: "unchanged"});
  });

  test(`generic profile resumes the deferred #${page} page after configuration arrives`, () => {
    const view = navigation(); view.showView(page); view.setConfig({}); view.flush();
    assert.equal(view.active(), `view-${page}`);
    assert.deepEqual(view.loads, [page]);
    assert.ok(view.restricted.every(node => !node.hidden));
    assert.equal(view.title.textContent, "nav.clients");
  });
}

test("later deliberate navigation supersedes an unresolved startup deep link", () => {
  const view = navigation(); view.showView("mod"); view.showView("providers"); view.setConfig({}); view.flush();
  assert.equal(view.active(), "view-providers");
  assert.deepEqual(view.loads, ["providers"]);
  assert.equal(view.pending(), null);
});

test("a loaded personal profile retains only supported navigation without rewriting old configuration", () => {
  const saved = {security:{mode:"personal"}, routes:{legacy:{provider:"untouched"}}, cli:{models:{subagent:"legacy-model"}}};
  const before = structuredClone(saved), view = navigation(saved);
  view.applyDesktopUiProfile();
  for (const name of genericOnly) { view.showView(name); view.flush(); assert.equal(view.active(), "view-health"); }
  assert.deepEqual(view.loads, []);
  for (const name of ["health", "providers", "clients", "logs", "about"]) {
    view.showView(name); view.flush(); assert.equal(view.active(), `view-${name}`);
  }
  assert.deepEqual(view.loads, ["providers", "clients", "logs"]);
  assert.deepEqual(saved, before);
});

for (const config of [null, {security:{mode:"personal"}}]) {
  test(`Status and native direct recovery remain available offline with ${config ? "personal" : "unknown"} config`, async () => {
    const view = navigation(config, true); view.showView("mod"); view.applyDesktopUiProfile(); view.flush();
    assert.equal(view.active(), "view-health");
    assert.deepEqual(view.loads, []);
    assert.ok(!view.views.find(node => node.id === "view-health")!.hidden);
    let restores = 0;
    const direct = new Function("APP", `${block("const CONN_ACTIONS =", "const CONN_BUSY =")}; return CONN_ACTIONS["direct-on"].run;`)(
      {directOn: async () => { restores++; return {doctor:{mode:"direct"}}; }},
    ) as () => Promise<unknown>;
    assert.deepEqual(await direct(), {doctor:{mode:"direct"}});
    assert.equal(restores, 1, "recovery uses the native bridge, without requiring a router API");
  });
}

const blockedHandlers = [
  "autoUpdateRow", "toggleAutoUpdate", "priorityRow", "savePriority", "checkForUpdate", "startUpdate",
  "renderModelSlots", "renderAutoClassifier", "saveWebSearch", "saveModelSlots", "saveAutoClassifier",
  "toggleWorkerTools", "toggleStatusMod", "renderCodexClient", "toggleCodex", "showPhoneQr", "loadPhone",
  "loadMac", "macPollSetup", "startMacSetup", "macPut", "loadSlots", "scheduleSlotsSave", "saveSlots",
  "modPatch", "saveMod", "saveCompactAt", "loadMod", "modRefresh",
];
for (const config of [null, {security:{mode:"personal"}, providers:{keep:{type:"custom"}}, routes:{keep:"intact"}}]) {
  test(`unsupported load and save handlers do nothing with ${config ? "personal" : "unknown"} configuration`, async () => {
    const calls: string[] = [], before = structuredClone(config);
    const ui = new Function("config", "calls", `
      let currentConfig = config, classifierSaving = Promise.resolve();
      const t = key => key;
      const tripwire = name => () => {calls.push(name); throw new Error("Unexpected side effect: " + name);};
      const api = tripwire("api"), latestConfig = tripwire("latestConfig"), configRequest = tripwire("configRequest");
      const $ = tripwire("DOM"), $all = tripwire("DOM"), setTimeout = tripwire("timer"), confirm = tripwire("consent");
      ${desktopUiGuardSource(source)}
      ${[...blockedHandlers, "phonePost"].map(declaration).join("\n")}
      return {${[...blockedHandlers, "phonePost"].join(",")}};
    `)(config, calls) as Record<string, (...args: unknown[]) => unknown>;
    for (const name of blockedHandlers) await ui[name]!(true, {});
    await assert.rejects(() => ui.phonePost!("settings", {}) as Promise<unknown>, /desktop.only/);
    assert.deepEqual(calls, [], "no API, config, UI mutation, consent prompt or timer work");
    assert.deepEqual(config, before);
  });
}

test("slot, search, classifier and tool writes recheck a fresh personal configuration before saving", async () => {
  const fresh = {security:{mode:"personal"}, cli:{models:{keep:"native"}}, webSearch:"native"};
  const calls: string[] = [];
  const ui = new Function("fresh", "calls", `
    let currentConfig = {}, classifierSaving = Promise.resolve(), classifierPending = null, classifierSaveGeneration = 0;
    const clone = structuredClone, t = key => key;
    const latestConfig = async () => {calls.push("read"); return fresh;};
    const configRequest = async () => {calls.push("write");};
    const classifierRowValue = () => ({provider:"test",model:"test"}), classifierSettingOf = first => first;
    ${desktopUiGuardSource(source)}
    ${["saveWebSearch", "saveModelSlots", "saveAutoClassifier", "toggleWorkerTools"].map(declaration).join("\n")}
    return {saveWebSearch, saveModelSlots, saveAutoClassifier, toggleWorkerTools};
  `)(fresh, calls) as Record<string, (...args: unknown[]) => Promise<unknown>>;
  await ui.saveWebSearch!('["test","test"]');
  await ui.saveModelSlots!(); await ui.saveAutoClassifier!(); await ui.toggleWorkerTools!(true);
  assert.deepEqual(calls, ["read", "read", "read", "read"]);
  assert.deepEqual(fresh, {security:{mode:"personal"}, cli:{models:{keep:"native"}}, webSearch:"native"});
});

test("personal Desktop rendering keeps picker controls and avoids optional client queries", () => {
  for (const enabled of [false, true]) {
    const group = new FixtureNode("div"); group.appendChild(new FixtureNode("div"));
    const toggle = new FixtureNode("input"), renders: string[] = [];
    new Function("Node", "document", "$", "renders", "enabled", `
      const currentConfig = {security:{mode:"personal"}}, status = {picker:{enabled}, pickerModels:[]};
      const t = key => key, pickerBusy = false, applyDesktopUiProfile = () => {};
      const renderClientPickerModels = () => renders.push("models"), renderClientPickerOrder = () => renders.push("order");
      const pickerBlockedOriginsNote = () => null;
      const unexpected = () => {throw new Error("optional-client work");};
      const renderModelSlots = unexpected, renderAutoClassifier = unexpected, renderCodexClient = unexpected, api = unexpected;
      ${block("function el(", "// Inside the ClaudeRipple app")}
      ${desktopUiGuardSource(source)}
      ${declaration("renderClients")}
      renderClients();
    `)(FixtureNode, documentFixture, (selector: string) => {
      if (selector === "#client-picker-rows") return group;
      assert.equal(selector, "#client-picker-toggle"); return toggle;
    }, renders, enabled);
    assert.deepEqual(renders, ["models", "order"]);
    assert.equal(toggle.checked, enabled); assert.equal(toggle.disabled, false);
  }
});

test("personal Add provider opens the Google key form; generic provider selection remains intact", async () => {
  for (const config of [null, {security:{mode:"personal"}}, {}]) {
    const opened: unknown[] = [], modals: FixtureNode[] = [];
    new Function("Node", "document", "config", "opened", "modals", `
      const currentConfig = config, presets = [], t = key => key;
      const openGoogleProviderForm = options => opened.push({googleKey:options}), openProviderForm = options => opened.push({generic:options});
      const showModal = node => modals.push(node), hint = text => el("p", {text}), chevronIcon = () => el("svg");
      ${block("function el(", "// Inside the ClaudeRipple app")}
      ${desktopUiGuardSource(source)}
      ${declaration("openProviderChooser")}
      openProviderChooser();
    `)(FixtureNode, documentFixture, config, opened, modals);
    if (!config) { assert.deepEqual(opened, []); assert.deepEqual(modals, []); }
    else if (config.security) {
      assert.deepEqual(opened, [{googleKey:{kind:"google"}}]); assert.deepEqual(modals, []);
    } else {
      assert.deepEqual(opened, []); assert.equal(modals.length, 1);
      const claude = modals[0]!.descendants().find(node => node.tag === "button" && node.descendants().some(child => child.textContent === "providers.anthropic"));
      assert.ok(claude); await claude.click();
      assert.deepEqual(opened, [{generic:{kind:"anthropic"}}]);
    }
  }
});

test("personal About is read-only and describes fixed-source updates; unknown mode offers no updater", () => {
  for (const config of [null, {security:{mode:"personal"}}]) {
    const row = new Function("config", `
      const currentConfig = config, status = {version:"fixture"}, t = key => key;
      const cell = (label, control, note) => ({label,control,note});
      ${desktopUiGuardSource(source)}
      ${declaration("versionRow")}
      return versionRow();
    `)(config) as {label: string; control: unknown; note: string; id: string};
    assert.equal(row.control, null);
    assert.equal(row.note, config ? "desktop.personalUpdates" : "common.loading");
    assert.equal(row.id, "health-version-row");
  }
  const translations = fs.readFileSync(new URL("../../ui/i18n.js", import.meta.url), "utf8");
  const dictionaries = new Function(`${translations.slice(0, translations.indexOf("const LANGUAGES"))}; return I18N;`)() as Record<string, Record<string,string>>;
  for (const lang of ["en", "ko", "zh", "ja", "es", "pt"])
    for (const key of ["desktop.only", "desktop.personalUpdates", "picker.reviewPermission"]) assert.ok(dictionaries[lang]?.[key], `${lang}: ${key}`);
});
