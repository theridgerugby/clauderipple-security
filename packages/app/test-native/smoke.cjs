// Exercise the built protocol/IPC/permission policies with Chromium, synthetic credentials and
// a disposable IPv4-loopback TLS router. No user installation, model API, real key or updater.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const http = require("node:http");
const https = require("node:https");
const path = require("node:path");
const { once } = require("node:events");
const { app, BrowserWindow, ipcMain, net, session } = require("electron");
const { registerScheme, handleScheme } = require("../dist/protocol.js");
const { ADMIN_IPC_CHANNEL, createAdminRequestHandler } = require("../dist/admin-ipc.js");
const { configurePermissions, trustedIpcSender, watchPrivilegedWindow, ORIGIN } = require("../dist/security.js");
const { applyWindowsPrivateAcl } = require("../dist/windows-private-acl.js");

assert.ok(!app.commandLine.hasSwitch("no-sandbox"));
assert.ok(!app.commandLine.hasSwitch("disable-setuid-sandbox"));
assert.ok(!process.env.ELECTRON_DISABLE_SANDBOX);
app.enableSandbox();
registerScheme();
app.on("window-all-closed", () => {});
const windows = [];
let server;
let untrustedServer;
const bounds = { show: false, width: 800, height: 600, webPreferences: {
  sandbox: true, contextIsolation: true, nodeIntegration: false, webSecurity: true,
  nodeIntegrationInSubFrames: false, webviewTag: false,
  preload: path.join(__dirname, "preload.cjs"),
} };

async function run() {
  await app.whenReady();
  const home = process.env.RIPPLE_NATIVE_FIXTURE;
  assert.ok(home && path.isAbsolute(home));
  const ui = path.join(home, "ui");
  fs.mkdirSync(ui, { mode: 0o700 });
  const secret = fs.readFileSync(path.join(home, "admin-tls-token"), "utf8").trim();
  const identity = JSON.parse(fs.readFileSync(path.join(home, "admin-tls-identity.json"), "utf8"));
  assert.match(secret, /^[a-f0-9]{64}$/);
  fs.writeFileSync(path.join(ui, "index.html"), '<!doctype html><meta charset="utf-8"><title>Security fixture</title><script src="app.js"></script>');
  fs.writeFileSync(path.join(ui, "app.js"), 'window.fixtureLoaded = true;');
  let received = 0;
  server = https.createServer({ cert: identity.certPem, key: identity.keyPem, minVersion: "TLSv1.2" }, (req, res) => {
    assert.ok(req.url.startsWith("/api/"));
    received++;
    assert.equal(req.headers["x-clauderipple-admin"], secret);
    assert.equal(req.headers["x-clauderipple-instance-id"], "a".repeat(32));
    res.setHeader("content-type", "application/json");
    res.end('{"fixture":true}');
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const tlsPort = server.address().port;
  // The public HTTP endpoint is deliberately untrusted and never sees a capability. It serves
  // only a foreign-page fixture. The main process reads/pins the separate protected TLS endpoint.
  untrustedServer = http.createServer((req, res) => {
    assert.equal(req.headers["x-clauderipple-admin"], undefined);
    assert.ok(!req.url.startsWith("/api/"), "admin requests must never fall back to public HTTP");
    res.setHeader("content-type", "text/html"); res.end("<!doctype html><title>Untrusted fixture</title>");
  });
  untrustedServer.listen(0, "127.0.0.1");
  await once(untrustedServer, "listening");
  const publicPort = untrustedServer.address().port;
  const base = `http://127.0.0.1:${publicPort}/`;
  // The parent created a private directory (including Windows inheritable owner-only DACL).
  const endpointFile = path.join(home, "admin-tls-endpoint.json");
  fs.writeFileSync(endpointFile, JSON.stringify({ version: 1, instanceId: "a".repeat(32), publicPort, tlsPort }), { flag: "wx", mode: 0o600 });
  // Match the production writer's explicit owner as well as its private DACL. A native elevated
  // test account may otherwise create an Administrators-owned file even inside a private parent.
  if (process.platform === "win32") applyWindowsPrivateAcl(endpointFile, false);
  let owner = new BrowserWindow(bounds);
  watchPrivilegedWindow(owner.webContents);
  windows.push(owner);
  configurePermissions(session.defaultSession, () => owner.webContents);
  // Observe the real guard's decisions without replacing its policy. Installing a second
  // onBeforeRequest listener would replace the production listener, so wrap registration
  // temporarily and restore the method immediately after handleScheme registers its guard.
  const guardRequests = [];
  const webRequest = session.defaultSession.webRequest;
  const originalBeforeRequest = webRequest.onBeforeRequest;
  const beforeRequestDescriptor = Object.getOwnPropertyDescriptor(webRequest, "onBeforeRequest");
  let guardRegistrations = 0;
  Object.defineProperty(webRequest, "onBeforeRequest", { configurable: true, writable: true, value: function(filter, listener) {
    guardRegistrations++;
    return originalBeforeRequest.call(this, filter, (details, callback) => listener(details, response => {
      const pathname = new URL(details.url).pathname;
      if (pathname.startsWith("/api/")) {
        const frame = details.frame;
        guardRequests.push({ path: pathname, resourceType: details.resourceType,
          webContentsId: details.webContentsId, processId: frame?.processId,
          routingId: frame?.routingId, frameUrl: frame?.url, cancel: response.cancel === true });
      }
      callback(response);
    }));
  } });
  try { handleScheme(ui); }
  finally {
    if (beforeRequestDescriptor) Object.defineProperty(webRequest, "onBeforeRequest", beforeRequestDescriptor);
    else delete webRequest.onBeforeRequest;
  }
  assert.equal(webRequest.onBeforeRequest, originalBeforeRequest);
  assert.equal(guardRegistrations, 1, "the production protocol must install exactly one request guard");
  ipcMain.handle("ripple-native:probe", event => trustedIpcSender(event, owner.webContents));
  ipcMain.handle(ADMIN_IPC_CHANNEL, createAdminRequestHandler({ ownedContents: () => owner.webContents, admin: () => base, home }));
  await owner.loadURL(`${ORIGIN}/`);
  const isolation = await owner.webContents.executeJavaScript(`({
    sandboxed: rippleNative.sandboxed, isolated: rippleNative.contextIsolated,
    require: typeof require, process: typeof process, loaded: window.fixtureLoaded,
    bridgeNames: Object.keys(rippleNative)
  })`);
  assert.deepEqual(isolation, { sandboxed: true, isolated: true, require: "undefined", process: "undefined", loaded: true,
    bridgeNames: ["sandboxed", "contextIsolated", "probe", "adminRequest"] });
  console.log("PASS native sandbox, context isolation and renderer Node isolation");
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.probe()"), true);
  const response = await owner.webContents.executeJavaScript(`rippleNative.adminRequest({path:'/api/status'}).then(r => ({ status: r.status, text: new TextDecoder().decode(r.body), headers: r.headers }))`);
  assert.equal(response.status, 200);
  assert.deepEqual(JSON.parse(response.text), { fixture: true });
  assert.ok(!JSON.stringify(response).includes(secret));
  assert.equal(received, 1);
  assert.equal(guardRequests.length, 0, "administrative IPC does not traverse the browser protocol");
  assert.equal(await owner.webContents.executeJavaScript(`fetch('/api/status').then(r => r.status).catch(() => 'blocked')`), "blocked");
  assert.equal(received, 1, "even the owned top frame has no browser API fallback");
  console.log("PASS native owned-frame IPC and pinned TLS credential isolation");
  const permission = await owner.webContents.executeJavaScript("navigator.permissions.query({name: 'geolocation'}).then(p => p.state)");
  assert.equal(permission, "denied");
  await owner.webContents.executeJavaScript("const script = document.createElement('script'); script.textContent = 'window.inlineRan = true'; document.body.append(script)");
  assert.equal(await owner.webContents.executeJavaScript("window.inlineRan === true"), false);
  console.log("PASS native permission denial and inline-script CSP");
  // Execute inside Chromium's actual child context. Browser API routing is denied regardless
  // of whether this runtime attributes the request to the child or the parent's frame.
  await owner.webContents.executeJavaScript(`new Promise(resolve => {
    const frame = document.createElement('iframe'); frame.id = 'security-child';
    frame.onload = () => resolve(true); document.body.append(frame);
  })`);
  const children = owner.webContents.mainFrame.frames;
  assert.equal(children.length, 1);
  const childFrame = children[0];
  assert.notEqual(childFrame.routingId, owner.webContents.mainFrame.routingId);
  assert.equal(await childFrame.executeJavaScript("window === window.top"), false);
  const childTraceStart = guardRequests.length;
  const child = await childFrame.executeJavaScript(`fetch('${ORIGIN}/api/status').then(r => r.status).catch(() => 'blocked')`);
  const childRequests = guardRequests.slice(childTraceStart);
  console.log("TRACE native child request", JSON.stringify({ result: child, requests: childRequests }));
  assert.equal(child, "blocked", "a request executed inside the child frame must be denied");
  assert.ok(childRequests.every(request => request.cancel), "requests reaching the guard are denied unconditionally");
  assert.equal(await childFrame.executeJavaScript(`parent.rippleNative.adminRequest({path:'/api/status'}).then(r=>r.status)`), 403,
    "a child borrowing the parent's preload must still be denied");
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.probe()"), false,
    "the same sticky policy closes all privileged IPC channels");
  await owner.webContents.executeJavaScript("document.getElementById('security-child').remove()");
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.adminRequest({path:'/api/status'}).then(r=>r.status)"), 403,
    "detaching the child must not restore privileged IPC");
  await owner.loadURL(`${ORIGIN}/`);
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.adminRequest({path:'/api/status'}).then(r=>r.status)"), 403,
    "ordinary document reload must not reset the tainted WebContents");
  assert.equal(received, 1, "an unowned child frame cannot borrow the capability");
  console.log("PASS native child fetch and borrowed-parent IPC denial, persistent after detach and reload");
  owner.destroy();
  owner = new BrowserWindow(bounds);
  watchPrivilegedWindow(owner.webContents);
  windows.push(owner);
  await owner.loadURL(`${ORIGIN}/`);
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.probe()"), true);
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.adminRequest({path:'/api/status'}).then(r=>r.status)"), 200);
  assert.equal(received, 2, "only a newly created owned window restores the administrative bridge");

  const sameOrigin = new BrowserWindow(bounds);
  windows.push(sameOrigin);
  await sameOrigin.loadURL(`${ORIGIN}/`);
  assert.equal(await sameOrigin.webContents.executeJavaScript("rippleNative.probe()"), false);
  assert.equal(await sameOrigin.webContents.executeJavaScript("rippleNative.adminRequest({path:'/api/status'}).then(r=>r.status)"), 403);
  const sameOriginTraceStart = guardRequests.length;
  assert.equal(await sameOrigin.webContents.executeJavaScript(`fetch('/api/status').then(r => r.status).catch(() => 'blocked')`), "blocked");
  const sameOriginRequests = guardRequests.slice(sameOriginTraceStart);
  assert.ok(sameOriginRequests.every(request => request.cancel));
  assert.equal(received, 2, "a second same-origin window cannot use the owned dashboard's bridge");
  console.log("PASS native same-origin unowned window IPC and API denial");

  const foreign = new BrowserWindow(bounds);
  windows.push(foreign);
  await foreign.loadURL(base);
  assert.equal(await foreign.webContents.executeJavaScript("rippleNative.probe()"), false);
  assert.equal(await foreign.webContents.executeJavaScript("rippleNative.adminRequest({path:'/api/status'}).then(r=>r.status)"), 403);
  const forbidden = await foreign.webContents.executeJavaScript(`fetch('${ORIGIN}/api/status').then(r => r.status).catch(() => 'blocked')`);
  assert.equal(forbidden, "blocked");
  assert.equal(received, 2, "a foreign page cannot use the authenticated bridge");
  try { const browserRequest = await net.fetch(`${ORIGIN}/api/status`); assert.equal(browserRequest.status, 403); }
  catch (error) { assert.match(String(error), /ERR_BLOCKED|Failed to fetch|ERR_FAILED/); }
  assert.equal(received, 2, "browser-initiated requests have no owner frame");
  console.log("PASS native foreign-window and browser-initiated API denial");
  // A process that takes over the exact TLS port with another identity must receive neither the
  // capability nor an HTTP request body. Keep the trusted endpoint/pin unchanged during this test.
  server.closeAllConnections();
  await new Promise(resolve => server.close(resolve));
  const rogue = JSON.parse(fs.readFileSync(path.join(home, "rogue", "admin-tls-identity.json"), "utf8"));
  let rogueRequests = 0;
  server = https.createServer({ cert: rogue.certPem, key: rogue.keyPem, minVersion: "TLSv1.2" }, (_req, res) => { rogueRequests++; res.end("untrusted"); });
  server.listen(tlsPort, "127.0.0.1");
  await once(server, "listening");
  assert.equal(await owner.webContents.executeJavaScript("rippleNative.adminRequest({path:'/api/status'}).then(r => r.status)"), 503);
  assert.equal(rogueRequests, 0, "port takeover cannot receive authenticated HTTP requests");
  console.log(`PASS native Electron ${process.versions.electron}: sandbox, isolation, IPC owner, pinned TLS and port takeover, API credential isolation, foreign-frame denial, CSP and permissions`);
}

run().then(() => finish(0), error => { console.error(error); finish(1); });
function finish(code) {
  for (const window of windows) if (!window.isDestroyed()) window.destroy();
  if (server) { server.closeAllConnections(); server.close(); }
  if (untrustedServer) { untrustedServer.closeAllConnections(); untrustedServer.close(); }
  app.exit(code);
}
