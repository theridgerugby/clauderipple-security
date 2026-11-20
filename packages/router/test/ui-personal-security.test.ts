// Execute the real DOM builder and policy-panel handlers with an in-memory DOM/API boundary.
// No browser, actual provider endpoint, installation, or credential is involved.
import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

const source = fs.readFileSync(new URL("../../ui/app.js", import.meta.url), "utf8").replaceAll("\r\n", "\n");
function block(from: string, to: string): string {
  const start = source.indexOf(from), end = source.indexOf(to, start);
  assert.ok(start >= 0 && end > start, `missing UI block: ${from}`);
  return source.slice(start, end);
}

class Node {
  readonly tag: string;
  readonly attrs: Record<string, string> = {};
  readonly children: Node[] = [];
  readonly listeners = new Map<string, (() => unknown)[]>();
  checked = false;
  disabled = false;
  value = "";
  textContent = "";
  className = "";
  constructor(tag: string) { this.tag = tag; }
  setAttribute(name: string, value: unknown): void { this.attrs[name] = String(value); }
  appendChild(child: Node): Node { this.children.push(child); return child; }
  replaceChildren(...children: Node[]): void { this.children.splice(0, this.children.length, ...children); }
  addEventListener(name: string, listener: () => unknown): void { this.listeners.set(name, [...(this.listeners.get(name) ?? []), listener]); }
  async click(): Promise<void> { if (!this.disabled) for (const fn of this.listeners.get("click") ?? []) await fn(); }
  descendants(): Node[] { return [this, ...this.children.flatMap(child => child.descendants())]; }
}

function page(origins: string[] = []) {
  const panel = new Node("section"), errors: string[] = [];
  const posts: Record<string, unknown>[] = [];
  let approved = [...origins], failRead = false, failWrite = false, reads = 0;
  let modal: Node | null = null, refreshes = 0;
  const api = async (route: string, options?: { method?: string; body?: string }) => {
    assert.equal(route, "/api/security-policy");
    if (options?.method === "POST") {
      const request = JSON.parse(options.body!); posts.push(request);
      if (failWrite) throw new Error("policy save failed");
      approved = request.action === "revoke" ? approved.filter(origin => origin !== request.origin) : [...approved, request.origin];
      return {};
    }
    reads++;
    if (failRead) throw new Error("policy unavailable");
    return { mode: "personal", approvedOrigins: [...approved], candidates: ["https://configured-only.invalid"] };
  };
  const document = {
    createElement: (tag: string) => new Node(tag),
    createTextNode: (text: string) => { const node = new Node("#text"); node.textContent = text; return node; },
  };
  const controls = new Function("Node", "document", "$", "api", "toast", "showModal", "closeModal", "refreshHealth", `
    const currentConfig = {security:{mode:"personal"}}, t = key => key;
    ${block("function el(", "// Inside the ClaudeRipple app")}
    ${block("async function openDestinationReview(", "function renderClients(")}
    ${block("async function loadPersonalSecurityPanel(", "async function loadProviders()")}
    return {load: loadPersonalSecurityPanel, review: openDestinationReview};
  `)(Node, document, (selector: string) => {
    assert.equal(selector, "#personal-security-panel"); return panel;
  }, api, (message: string) => errors.push(message), (node: Node) => { modal = node; },
  () => { modal = null; }, () => { refreshes++; }) as {
    load(): Promise<void>; review(origin: string): Promise<void>;
  };
  const node = (match: (node: Node) => boolean): Node => {
    const found = (modal || panel).descendants().find(match); assert.ok(found, "expected panel control"); return found;
  };
  return {
    panel, errors, posts, ...controls, modal: () => modal, refreshes: () => refreshes,
    origin: () => node(item => item.tag === "input" && item.attrs.type === "url"),
    consent: () => node(item => item.tag === "input" && item.attrs.type === "checkbox"),
    approve: () => node(item => item.tag === "button" && item.textContent === "Approve destination"),
    revoke: () => node(item => item.tag === "button" && item.textContent === "Revoke"),
    failRead: () => { failRead = true; }, failWrite: () => { failWrite = true; },
    reads: () => reads,
  };
}

test("personal policy panel never auto-approves a configured destination and requires explicit consent", async () => {
  const view = page(); await view.load();
  assert.equal(view.consent().checked, false);
  assert.equal(view.origin().value, "");
  assert.deepEqual(view.posts, []);
  view.origin().value = "  https://school-fixture.invalid  ";
  await view.approve().click();
  assert.deepEqual(view.posts, []);
  assert.match(view.errors[0]!, /Confirm data-sharing/);
  view.consent().checked = true;
  await view.approve().click();
  assert.deepEqual(view.posts, [{ action: "approve", origin: "https://school-fixture.invalid", acknowledgeDataSharing: true }]);
  assert.equal(view.reads(), 2, "save is followed by an authoritative policy read");
  assert.equal(view.consent().checked, false, "consent never carries over to a different destination");
});

test("personal policy revocation names the exact saved origin regardless of unfinished input", async () => {
  const view = page(["https://saved-fixture.invalid"]); await view.load();
  view.origin().value = "https://uncommitted-fixture.invalid";
  await view.revoke().click();
  assert.deepEqual(view.posts, [{ action: "revoke", origin: "https://saved-fixture.invalid" }]);
  assert.equal(view.panel.descendants().some(node => node.tag === "button" && node.textContent === "Revoke"), false);
});

test("policy read failure leaves no stale mutation controls and write failure restores the current control", async () => {
  const view = page(); await view.load();
  view.consent().checked = true; view.origin().value = "https://new-fixture.invalid";
  view.failWrite(); await view.approve().click();
  assert.equal(view.approve().disabled, false);
  assert.deepEqual(view.errors, ["policy save failed"]);
  assert.equal(view.reads(), 1, "failed mutation is never presented as a successful saved policy");
  view.failRead(); await view.load();
  assert.equal(view.panel.descendants().some(node => node.tag === "button" || node.tag === "input"), false);
  assert.match(view.panel.descendants().map(node => node.textContent).join(" "), /Security policy unavailable/);
});

test("policy destination labels use text nodes through the real DOM builder", async () => {
  const label = '<img src=x onerror="unexpected()">';
  const view = page([label]); await view.load();
  assert.ok(view.panel.descendants().some(node => node.tag === "code" && node.textContent === label));
  assert.equal(view.panel.descendants().some(node => node.tag === "img"), false);
  assert.equal(view.panel.descendants().some(node => Object.keys(node.attrs).some(key => key.startsWith("on"))), false);
});

function googleForm(personal: boolean, existing?: { auth: string }) {
  let form: Node | undefined;
  const requests: Record<string, unknown>[] = [];
  const document = {
    createElement: (tag: string) => new Node(tag),
    createTextNode: (text: string) => { const node = new Node("#text"); node.textContent = text; return node; },
  };
  const build = new Function("Node", "document", "capture", "api", "personal", `
    const currentConfig = { security: personal ? {mode: "personal", approvedOrigins: []} : undefined };
    const t = key => key;
    ${block("function el(", "// Inside the ClaudeRipple app")}
    const selectOption = (value, text) => el("option", { value, text });
    const inputRow = (title, input) => el("div", {}, [el("span", {text:title}), input]);
    const hint = text => el("small", {text});
    const modelsOf = value => value?.models || [];
    const modelChecklist = () => el("div", {class:"model-picker"});
    const pickerModeOn = () => false, providerFormName = name => name;
    const closeModal = () => {}, showModal = value => capture(value);
    ${block("function openGoogleProviderForm(", "function openProviderForm(")}
    return openGoogleProviderForm;
  `)(Node, document, (value: Node) => { form = value; }, async (_url: string, request: { body: string }) => {
    requests.push(JSON.parse(request.body));
    return { ok: false, auth: "missing" };
  }, personal) as (options: unknown) => void;
  build({ ...(existing ? { name: "google", provider: existing } : {}) });
  assert.ok(form);
  return { form, requests };
}

test("personal Google setup exposes only the AI Studio API-key path", async () => {
  const { form, requests } = googleForm(true);
  const nodes = form.descendants();
  assert.ok(nodes.some(node => node.tag === "input" && node.attrs.type === "password"));
  assert.equal(nodes.some(node => node.tag === "option" && node.attrs.value === "antigravity"), false);
  assert.equal(nodes.some(node => node.tag === "button" && node.textContent === "providers.addGoogleAccount"), false);
  assert.equal(requests.length, 0, "opening the form does not grant approval or send credentials");
  await nodes.find(node => node.tag === "button" && node.textContent === "providers.check")!.click();
  assert.equal(requests.length, 1);
  assert.equal(requests[0]!.type, "google");
  assert.equal(requests[0]!.auth, "api-key");
});

test("an old Google subscription setting cannot auto-start subscription probing in personal mode", () => {
  const { form, requests } = googleForm(true, { auth: "antigravity" });
  assert.equal(requests.length, 0);
  assert.equal(form.descendants().some(node => node.textContent === "providers.addGoogleAccount"), false);
});

test("the generic Google form retains its separate subscription choice", () => {
  const { form } = googleForm(false);
  assert.deepEqual(form.descendants().filter(node => node.tag === "option").map(node => node.attrs.value), ["api-key", "antigravity"]);
});

function pickerActivation(accept: boolean) {
  const i18nSource = fs.readFileSync(new URL("../../ui/i18n.js", import.meta.url), "utf8");
  const start = i18nSource.indexOf("const I18N = {"), end = i18nSource.indexOf("\n};", start);
  const dictionary = new Function(`${i18nSource.slice(start, end + 3)}; return I18N.en;`)() as Record<string, string>;
  const confirmations: string[] = [], requests: { url: string; body: unknown }[] = [];
  const message = new Node("div");
  const load = new Function("t", "confirm", "api", "$", `
    let pickerBusy = false;
    const status = {picker:{enabled:false}}, currentConfig = {picker:{enabled:false}};
    const toast = () => {}, refreshHealth = async () => {};
    ${block("function pickerModeOn()", "async function toggleStatusMod(")}
    return { offerPickerOn, togglePicker };
  `)((key: string) => dictionary[key] ?? key, (text: string) => { confirmations.push(text); return accept; },
  async (url: string, request: { body: string }) => { requests.push({ url, body: JSON.parse(request.body) }); return { ok: true }; },
  () => message) as { offerPickerOn(wanted: boolean): Promise<void>; togglePicker(enabled: boolean): Promise<void> };
  return { ...load, confirmations, requests };
}

test("provider-save and direct picker activation use the same full-scope consent", async () => {
  const offered = pickerActivation(true), direct = pickerActivation(true);
  await offered.offerPickerOn(true);
  await direct.togglePicker(true);
  assert.deepEqual(offered.confirmations, direct.confirmations);
  assert.equal(offered.confirmations.length, 1);
  assert.match(offered.confirmations[0]!, /local CA.*current user.*Desktop app's network traffic/s);
  assert.match(offered.confirmations[0]!, /approved HTTPS destinations/);
  assert.match(offered.confirmations[0]!, /proxy stops.*default connection.*direct on.*reopen Desktop/s);
  assert.deepEqual(offered.requests, [{ url: "/api/picker", body: { enabled: true } }]);
});

test("declining a picker offer leaves activation and approvals untouched", async () => {
  const view = pickerActivation(false);
  await view.offerPickerOn(false);
  assert.deepEqual(view.confirmations, []);
  await view.offerPickerOn(true);
  assert.equal(view.confirmations.length, 1);
  assert.deepEqual(view.requests, []);
});

function blockedOriginsNote(picker: unknown): Node | null {
  const document = {
    createElement: (tag: string) => new Node(tag),
    createTextNode: (text: string) => { const node = new Node("#text"); node.textContent = text; return node; },
  };
  return new Function("Node", "document", "picker", `
    const t = key => key;
    ${block("function el(", "// Inside the ClaudeRipple app")}
    ${block("function pickerBlockedOriginsNote(", "function renderClients(")}
    return pickerBlockedOriginsNote(picker);
  `)(Node, document, picker) as Node | null;
}

test("picker blocked-origin note is bounded and offers only explicit reviews of canonical origins", () => {
  const origins = ["https://assets.example", "https://service.example:8443"];
  const node = blockedOriginsNote({ enabled: true, blockedOrigins: [
    ...origins, "https://user:secret@service.example", "https://service.example/path?key=secret",
    "https://service.example/#token", "http://insecure.example", '<img src=x onerror="unexpected()">',
    null, { message: "private exception text" },
  ] });
  assert.ok(node);
  assert.deepEqual(node.descendants().filter(item => item.tag === "code").map(item => item.textContent), origins);
  assert.deepEqual(node.descendants().filter(item => item.tag === "button").map(item => item.textContent), origins.map(() => "picker.reviewPermission"));
  assert.equal(node.tag, "div");
  assert.equal(node.listeners.size, 0, "the note itself does not approve or navigate");
  assert.equal(node.descendants().some(item => item.tag === "a" || item.attrs.href), false);
  assert.equal(blockedOriginsNote({ enabled: false, blockedOrigins: origins }), null);
  assert.equal(blockedOriginsNote({ enabled: true, blockedOrigins: [] }), null);
  assert.equal(blockedOriginsNote({ enabled: true, blockedOrigins: "https://wrong-shape.example" }), null);
  const many = Array.from({ length: 18 }, (_, i) => `https://service-${i}.example`);
  assert.deepEqual(blockedOriginsNote({ enabled: true, blockedOrigins: many })!.descendants()
    .filter(item => item.tag === "code").map(item => item.textContent), many.slice(0, 16));
});

test("reviewing a blocked origin prefills the existing approval form without granting or retrying", async () => {
  const view = page();
  await view.review("https://assets.example");
  assert.ok(view.modal());
  assert.equal(view.origin().value, "https://assets.example");
  assert.equal(view.consent().checked, false);
  assert.deepEqual(view.posts, []);
  assert.equal(view.refreshes(), 0);
  const text = view.modal()!.descendants().map(node => node.textContent).join(" ");
  assert.match(text, /provider requests and Desktop connections/);
  assert.doesNotMatch(text, /assets.only/);
  await view.approve().click();
  assert.deepEqual(view.posts, []);
  view.consent().checked = true;
  view.origin().value = "https://different.example";
  for (const listener of view.origin().listeners.get("input") || []) listener();
  assert.equal(view.consent().checked, false, "editing a prefilled destination requires fresh consent");
  view.consent().checked = true;
  await view.approve().click();
  assert.deepEqual(view.posts, [{ action: "approve", origin: "https://different.example", acknowledgeDataSharing: true }]);
  assert.equal(view.modal(), null);
  assert.equal(view.refreshes(), 1, "only connection status is refreshed; no failed request is replayed");
});

test("origin review refuses credential-bearing and noncanonical URLs before any policy read", async () => {
  const view = page();
  for (const value of ["https://name:secret@assets.example", "http://assets.example", "https://assets.example/path", "https://assets.example/#private", "<img src=x>"]) {
    await view.review(value);
  }
  assert.equal(view.modal(), null);
  assert.equal(view.reads(), 0);
  assert.deepEqual(view.posts, []);
});

test("picker-origin readiness maps to exact-origin review instructions without approving anything", () => {
  const translate = new Function("t", `
    ${block("function readinessProblemText(", "/**\n * The problems the router reports")}
    return readinessProblemText;
  `)((key: string) => key) as (code: string) => string;
  assert.equal(translate("picker-origin"), "health.diagnosticPickerOrigin");
  assert.equal(translate("unknown-diagnostic"), "unknown-diagnostic");
  const translations = fs.readFileSync(new URL("../../ui/i18n.js", import.meta.url), "utf8");
  const entries = [...translations.matchAll(/"health\.diagnosticPickerOrigin": "([^"\n]+)"/g)];
  assert.equal(entries.length, 6, "each supported locale has an explicit diagnostic");
  for (const entry of entries) {
    assert.ok(entry[1]!.includes("https://claude.ai"));
    assert.doesNotMatch(entry[1]!, /\*\.claude\.ai|https:\/\/claude\.ai\//);
  }
});
