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
  const load = new Function("Node", "document", "$", "api", "toast", `
    ${block("function el(", "// Inside the ClaudeRipple app")}
    ${block("async function loadPersonalSecurityPanel()", "async function loadProviders()")}
    return loadPersonalSecurityPanel;
  `)(Node, document, (selector: string) => {
    assert.equal(selector, "#personal-security-panel"); return panel;
  }, api, (message: string) => errors.push(message)) as () => Promise<void>;
  const node = (match: (node: Node) => boolean): Node => {
    const found = panel.descendants().find(match); assert.ok(found, "expected panel control"); return found;
  };
  return {
    panel, errors, posts, load,
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
