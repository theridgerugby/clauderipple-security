import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { EventEmitter } from "node:events";
import { runInNewContext } from "node:vm";
import ts from "typescript";
import * as security from "../src/security.ts";

const source = fs.readFileSync(new URL("../src/window.ts", import.meta.url), "utf8");
const compiled = ts.transpileModule(source, {
  compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, esModuleInterop: true },
}).outputText;

function harness() {
  let settings: any;
  let window: FakeWindow;
  let popup: (details: { url: string }) => { action: string };
  const opened: string[] = [], loaded: string[] = [];
  class FakeWindow extends EventEmitter {
    webContents = Object.assign(new EventEmitter(), {
      id: 17, mainFrame: { frames: [], origin: security.ORIGIN, url: `${security.ORIGIN}/`, processId: 7, routingId: 11 },
      setWindowOpenHandler: (handler: typeof popup) => { popup = handler; },
    });
    constructor(options: unknown) { super(); settings = options; window = this; }
    removeMenu() {}
    loadURL(url: string) { loaded.push(url); return Promise.resolve(); }
  }
  const modules: Record<string, object> = {
    electron: { BrowserWindow: FakeWindow, app: {}, nativeTheme: { shouldUseDarkColors: false }, screen: {},
      shell: { openExternal: async (url: string) => { opened.push(url); } } },
    "node:child_process": { execFile: () => assert.fail("OS commands must not run") }, "node:path": path,
    "./security": security, "./protocol": { ORIGIN: security.ORIGIN },
  };
  const exports: { openWindow?: Function } = {};
  runInNewContext(compiled, {
    exports, require: (id: string) => { assert.ok(id in modules, id); return modules[id]; },
    __dirname: "/unused-app/dist", process: { platform: "linux" },
  });
  assert.ok(exports.openWindow);
  exports.openWindow({ lang: "en", savedBounds: () => null, saveBounds() {}, shown() {} });
  return { settings, contents: window!.webContents, opened, loaded, popup: (url: string) => popup!({ url }) };
}

test("the actual dashboard window explicitly enables sandbox and disables renderer Node features", () => {
  const fixture = harness();
  const settings = fixture.settings.webPreferences;
  for (const key of ["sandbox", "contextIsolation", "webSecurity"]) assert.equal(settings[key], true, key);
  for (const key of ["nodeIntegration", "nodeIntegrationInSubFrames", "nodeIntegrationInWorker", "webviewTag", "allowRunningInsecureContent", "experimentalFeatures"])
    assert.equal(settings[key], false, key);
  assert.equal(fixture.loaded[0], `${security.ORIGIN}/?lang=en`);
});

test("popup requests always deny child windows and only open allowed HTTPS hosts externally", () => {
  const fixture = harness();
  assert.equal(fixture.popup("https://github.com/PBJ-2/clauderipple/releases").action, "deny");
  assert.deepEqual(fixture.opened, ["https://github.com/PBJ-2/clauderipple/releases"]);
  for (const url of ["javascript:alert(1)", "file:///tmp/test", "https://untrusted.example/", "ripple://app/api/config", "https://github.com.evil/"])
    assert.equal(fixture.popup(url).action, "deny");
  assert.equal(fixture.opened.length, 1);
});

test("frame navigation, redirects and webviews cannot replace or embed privileged dashboard content", () => {
  const fixture = harness();
  const blocked = (eventName: string, url: string, isMainFrame: boolean) => {
    let prevented = false;
    const event = { url, isMainFrame, preventDefault: () => { prevented = true; } };
    fixture.contents.emit(eventName, event, url);
    return prevented;
  };
  for (const event of ["will-frame-navigate", "will-redirect"]) {
    assert.equal(blocked(event, `${security.ORIGIN}/?lang=zh`, true), false);
    assert.equal(blocked(event, `${security.ORIGIN}/`, false), true);
    for (const url of ["https://untrusted.example/", "ripple://app/app.js", "ripple://app:99/", "file:///tmp/test", "about:blank"])
      assert.equal(blocked(event, url, true), true, `${event} ${url}`);
  }
  assert.equal(blocked("will-navigate", `${security.ORIGIN}/index.html`, true), false);
  assert.equal(blocked("will-navigate", "https://untrusted.example/", true), true);
  assert.equal(blocked("will-attach-webview", `${security.ORIGIN}/`, true), true);
  assert.deepEqual(fixture.opened, []);
});

test("production child-frame policy stays tainted after detach and closes OS-open capability", () => {
  const fixture = harness();
  const contents = fixture.contents;
  assert.equal(security.isPrivilegedWindow(contents as unknown as import("electron").WebContents), true);
  contents.emit("frame-created", {}, { frame: { parent: contents.mainFrame, processId: 7, routingId: 12 } });
  assert.equal(security.isPrivilegedWindow(contents as unknown as import("electron").WebContents), false);
  contents.mainFrame.frames.length = 0;
  fixture.popup("https://github.com/PBJ-2/clauderipple/releases");
  contents.emit("will-navigate", { preventDefault() {} }, "https://github.com/PBJ-2/clauderipple/releases");
  assert.deepEqual(fixture.opened, []);
  security.watchPrivilegedWindow(contents as unknown as import("electron").WebContents);
  assert.equal(security.isPrivilegedWindow(contents as unknown as import("electron").WebContents), false);
});
