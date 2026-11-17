import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { EventEmitter } from "node:events";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import type { Session, WebContents, IpcMainInvokeEvent } from "electron";
import { configurePermissions, DASHBOARD_CSP, externalUrl, isAppUrl, isDashboardUrl, ORIGIN, trustedIpcSender, trustedTopFrame, watchPrivilegedWindow } from "../src/security.ts";

const frame = { processId: 7, routingId: 11, origin: ORIGIN, url: `${ORIGIN}/?lang=en#health`, frames: [] };
const owner = Object.assign(new EventEmitter(), { id: 17, mainFrame: frame }) as unknown as WebContents;
watchPrivilegedWindow(owner);
const event = { sender: owner, senderFrame: frame } as unknown as IpcMainInvokeEvent;

test("privilege belongs to exactly the owned top-level dashboard frame", () => {
  assert.equal(trustedTopFrame(owner.id, frame, owner), true);
  assert.equal(trustedIpcSender(event, owner), true);
  for (const other of [
    null, undefined, { ...frame, processId: 8 }, { ...frame, routingId: 12 },
    { ...frame, origin: "null" }, { ...frame, origin: "https://untrusted.example" },
    { ...frame, url: "ripple://app.evil/" }, { ...frame, url: "ripple://app:80/" },
    { ...frame, url: "ripple://user@app/" }, { ...frame, url: "ripple://app/app.js" },
    { ...frame, url: "about:blank" },
  ]) assert.equal(trustedTopFrame(owner.id, other, owner), false, JSON.stringify(other));
  assert.equal(trustedTopFrame(18, frame, owner), false);
  assert.equal(trustedTopFrame(undefined, frame, owner), false);
  assert.equal(trustedTopFrame(owner.id, frame, null), false);
  const detached = { get mainFrame(): never { throw new Error("frame disposed"); }, id: owner.id };
  assert.equal(trustedTopFrame(owner.id, frame, detached), false);
  assert.equal(trustedIpcSender({ ...event, sender: { id: 18 } as WebContents }, owner), false);
});

test("scheme and document validation do not accept origin-prefix matches", () => {
  assert.equal(isAppUrl(`${ORIGIN}/style.css`), true);
  assert.equal(isDashboardUrl(`${ORIGIN}/index.html?lang=zh#providers`), true);
  assert.equal(isDashboardUrl(`${ORIGIN}/style.css`), false);
  for (const value of ["ripple://app.evil/", "ripple://user@app/", "ripple://app:80/", "https://app/", "invalid"])
    assert.equal(isAppUrl(value), false, value);
});

test("external opener permits only verified HTTPS destinations", () => {
  for (const url of ["https://github.com/PBJ-2/clauderipple/releases", "https://accounts.google.com/test", "https://claude.ai/oauth/authorize", "https://auth.openai.com/oauth/authorize"])
    assert.equal(externalUrl(url), url);
  for (const url of [
    "file:///tmp/fixture", "javascript:alert(1)", "data:text/html,fixture", "http://github.com/",
    "https://github.com.evil.example/", "https://github.com@collector.example/", "https://user@github.com/",
    "https://github.com:8443/", "https://127.0.0.1/", "https://github.com\\@collector.example/",
    " https://github.com/", "https://github.com/\n",
  ]) assert.equal(externalUrl(url), null, url);
});

test("session permissions deny all capabilities except sanitized clipboard writes by the owner", () => {
  let check: Function | undefined, request: Function | undefined, device: Function | undefined, media: Function | undefined;
  let download: Function | undefined;
  const ses = {
    setPermissionCheckHandler: (fn: Function) => { check = fn; },
    setPermissionRequestHandler: (fn: Function) => { request = fn; },
    setDevicePermissionHandler: (fn: Function) => { device = fn; },
    setDisplayMediaRequestHandler: (fn: Function) => { media = fn; },
    on: (name: string, fn: Function) => { assert.equal(name, "will-download"); download = fn; },
  };
  configurePermissions(ses as unknown as Session, () => owner);
  assert.ok(check && request && device && media && download);
  const details = { isMainFrame: true, requestingUrl: frame.url };
  const ask = (contents: WebContents | null, permission: string, data: object) => {
    let result: boolean | undefined;
    request!(contents, permission, (allowed: boolean) => { result = allowed; }, data);
    return result;
  };
  assert.equal(check(owner, "clipboard-sanitized-write", ORIGIN, details), true);
  assert.equal(ask(owner, "clipboard-sanitized-write", details), true);
  for (const permission of ["media", "display-capture", "geolocation", "notifications", "clipboard-read", "clipboard-write", "fileSystem", "hid", "serial", "usb", "unknown"])
    assert.equal(check(owner, permission, ORIGIN, details) || ask(owner, permission, details), false, permission);
  for (const contents of [null, { ...owner, id: 18 } as WebContents]) {
    assert.equal(check(contents, "clipboard-sanitized-write", ORIGIN, details), false);
    assert.equal(ask(contents, "clipboard-sanitized-write", details), false);
  }
  for (const invalid of [{ ...details, isMainFrame: false }, {}, { ...details, requestingUrl: "https://untrusted.example/" }]) {
    assert.equal(check(owner, "clipboard-sanitized-write", ORIGIN, invalid), false);
    assert.equal(ask(owner, "clipboard-sanitized-write", invalid), false);
  }
  assert.equal(check(owner, "clipboard-sanitized-write", "null", details), false);
  assert.equal(device(), false);
  let mediaResult: unknown;
  media({}, (value: unknown) => { mediaResult = value; });
  assert.deepEqual(mediaResult, {});
  let blocked = false;
  download({ preventDefault: () => { blocked = true; } });
  assert.equal(blocked, true);
});

test("the desktop CSP excludes embedded frames, workers, plugin objects and inline execution", () => {
  for (const directive of ["script-src 'self'", "connect-src 'none'", "frame-src 'none'", "frame-ancestors 'none'", "worker-src 'none'", "object-src 'none'", "base-uri 'none'", "form-action 'none'"])
    assert.ok(DASHBOARD_CSP.includes(directive));
  assert.doesNotMatch(DASHBOARD_CSP, /unsafe-inline|unsafe-eval|https?:|\*/);
});

test("real IPC handlers reject foreign windows and same-origin child frames before privileged actions", async () => {
  const source = fs.readFileSync(new URL("../src/main.ts", import.meta.url), "utf8");
  const syntax = ts.createSourceFile("main.ts", source, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TS);
  const selected = syntax.statements.filter(node =>
    (ts.isFunctionDeclaration(node) && ["fromOurPage", "wireBridge"].includes(node.name?.text ?? "")) ||
    (ts.isVariableStatement(node) && node.declarationList.declarations.some(item => item.name.getText(syntax) === "BRIDGE_ACTIONS")));
  assert.equal(selected.length, 3);
  const compiled = ts.transpileModule(selected.map(node => node.getText(syntax)).join("\n") + "\nwireBridge();", {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS },
  }).outputText;
  const handlers = new Map<string, Function>();
  const actions: string[] = [];
  runInNewContext(compiled, {
    ipcMain: { handle: (channel: string, callback: Function) => handlers.set(channel, callback) },
    trustedIpcSender, mainWindow: () => ({ webContents: owner }),
    ADMIN_IPC_CHANNEL: "ripple-app:admin-request", createAdminRequestHandler: () => async () => ({ status: 403 }),
    adminUrl: () => "http://127.0.0.1:1/", home: "/unused-test-home",
    bridgeState: () => ({ test: true }), logTail: () => ["fixture"], act: async (id: string) => { actions.push(id); },
  });
  assert.deepEqual([...handlers.keys()], ["ripple-app:admin-request", "ripple-app:state", "ripple-app:log", "ripple-app:act"]);
  for (const invalid of [
    { ...event, sender: { id: 18 } }, { ...event, senderFrame: null },
    { ...event, senderFrame: { ...frame, routingId: 12 } },
    { ...event, senderFrame: { ...frame, origin: "null" } },
  ]) {
    assert.equal(handlers.get("ripple-app:state")!(invalid), null);
    assert.equal(handlers.get("ripple-app:log")!(invalid).length, 0);
    assert.equal(await handlers.get("ripple-app:act")!(invalid, "repair"), null);
  }
  for (const action of ["arbitrary", "../install", null, {}]) assert.equal(await handlers.get("ripple-app:act")!(event, action), null);
  assert.deepEqual(actions, []);
  assert.deepEqual(handlers.get("ripple-app:state")!(event), { test: true });
  await handlers.get("ripple-app:act")!(event, "refresh");
  assert.deepEqual(actions, ["refresh"]);
  const completion = handlers.get("ripple-app:act")!(event, "refresh");
  owner.emit("frame-created", {} as Electron.Event, { frame: { ...frame, parent: frame, routingId: 99 } } as never);
  assert.equal(await completion, null, "an authorized action cannot return state after its window loses privilege");
  assert.equal(handlers.get("ripple-app:state")!(event), null);
  assert.equal(handlers.get("ripple-app:log")!(event).length, 0);
  assert.equal(await handlers.get("ripple-app:act")!(event, "repair"), null);
  assert.deepEqual(actions, ["refresh", "refresh"], "tainted parent cannot borrow any recovery-action channel");
});
