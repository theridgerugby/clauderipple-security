// All reads target injected snapshots or throwaway directories. No real Claude setting,
// certificate store, service manager, account credential, network or inference is accessed.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { auditNativeIndependence, nativeIndependenceSummary, type NativeIndependenceOptions } from "../src/native-independence.ts";

const HOME = path.resolve("synthetic-native-audit-home");
const PROXY = "http://127.0.0.1:18791";
const CA = path.join(HOME, "ca.pem");
const SECRET = "SYNTHETIC-PRIVATE-SENTINEL-NOT-FOR-REPORTS";

function options(overrides: Partial<NativeIndependenceOptions> = {}): NativeIndependenceOptions {
  return {
    home: HOME, proxyUrl: PROXY, platform: "win32",
    supervisor: { registered: false, program: null, args: [], programExists: false, state: "not-loaded", pid: null, current: false, installedHome: null },
    readSettings: () => ({}), readDesktop: () => ({ meta: {}, entry: {} }), readRestoration: () => undefined,
    trustedCa: async () => false,
    readWatchdog: () => { throw new Error("an unregistered service must not inspect a watchdog"); },
    ...overrides,
  };
}

test("a clean persisted snapshot does not claim a live native-client acceptance result", async () => {
  const report = await auditNativeIndependence(options());
  assert.equal(report.knownCouplingsAbsent, true);
  assert.equal(report.originalIndependent, null);
  assert.equal(report.scope, "installation-local-persisted-state");
  assert.ok(Object.values(report.findings).every(value => value.state === "absent"));
  assert.match(nativeIndependenceSummary(report), /live .* has not been verified/);
});

for (const key of ["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"]) {
  test(`shared ${key} targeting this router is a native traffic dependency`, async () => {
    const report = await auditNativeIndependence(options({ readSettings: () => ({ env: { [key]: PROXY, NODE_EXTRA_CA_CERTS: CA, ANTHROPIC_AUTH_TOKEN: SECRET } }) }));
    assert.equal(report.originalIndependent, false);
    assert.equal(report.knownCouplingsAbsent, false);
    assert.equal(report.findings.sharedProxy.state, "present");
    assert.equal(report.findings.sharedProxy.ownership, "this-installation");
    assert.equal(report.findings.sharedCa.state, "present");
    assert.ok(!JSON.stringify(report).includes(SECRET));
    assert.ok(!JSON.stringify(report).includes(HOME));
  });
}

test("a matching endpoint without a CA claim is not asserted to be owned", async () => {
  const report = await auditNativeIndependence(options({ readSettings: () => ({ env: { HTTPS_PROXY: `${PROXY}/` } }) }));
  assert.equal(report.originalIndependent, false);
  assert.equal(report.findings.sharedProxy.ownership, "unverified-or-external");
});

test("external and stale loopback proxies are never claimed as ours", async () => {
  for (const proxy of ["https://foreign.example:8443", "http://127.0.0.1:28791", { token: SECRET }]) {
    const report = await auditNativeIndependence(options({ readSettings: () => ({ env: { HTTPS_PROXY: proxy, NODE_EXTRA_CA_CERTS: CA } }) }));
    assert.equal(report.findings.sharedProxy.state, "unknown");
    assert.equal(report.findings.sharedProxy.ownership, "unverified-or-external");
    assert.equal(report.originalIndependent, null);
    assert.equal(report.findings.sharedCa.state, "present");
    assert.ok(!JSON.stringify(report).includes(SECRET));
  }
});

test("an owned active Desktop proxy prevents a native-independent claim", async () => {
  const report = await auditNativeIndependence(options({ readDesktop: () => ({
    meta: { appliedId: "owned", clauderipple: { ourId: "owned", installationHome: HOME } },
    entry: { egressProxyUrl: PROXY, inferenceGatewayApiKey: SECRET },
  }) }));
  assert.equal(report.originalIndependent, false);
  assert.equal(report.findings.desktopProxy.state, "present");
  assert.equal(report.findings.desktopProxy.ownership, "this-installation");
  assert.ok(!JSON.stringify(report).includes(SECRET));
});

test("a user edit to an owned Desktop entry remains external or unverified", async () => {
  const report = await auditNativeIndependence(options({ readDesktop: () => ({
    meta: { appliedId: "owned", clauderipple: { ourId: "owned", installationHome: HOME } },
    entry: { egressProxyUrl: "https://foreign.example:8443", egressProxyPacUrl: `https://example.invalid/${SECRET}` },
  }) }));
  assert.equal(report.originalIndependent, null);
  assert.equal(report.findings.desktopProxy.state, "unknown");
  assert.equal(report.findings.desktopProxy.ownership, "unverified-or-external");
  assert.equal(report.findings.desktopPac.state, "unknown");
  assert.ok(!JSON.stringify(report).includes(SECRET));
});

test("trust and a deployed watchdog are side effects, without being proof of traffic coupling", async () => {
  const opts = options({ trustedCa: async () => true, readWatchdog: () => "function Get-AdminPort {} # /api/ping $watchdogLog" });
  opts.supervisor = { ...opts.supervisor, installedHome: HOME, registered: true, state: "running", pid: 123, current: true };
  const report = await auditNativeIndependence(opts);
  assert.equal(report.originalIndependent, null);
  assert.equal(report.knownCouplingsAbsent, false);
  assert.equal(report.findings.trustedCa.state, "present");
  assert.equal(report.findings.backgroundService.state, "present");
  assert.equal(report.findings.windowsWatchdog.state, "present");
  assert.match(report.findings.windowsWatchdog.detail, /live execution was not observed/);
});

test("foreign or uninspectable services cannot establish our watchdog's state", async () => {
  for (const change of [
    { registered: true, state: "running" as const, installedHome: path.resolve("other-home"), pid: 44 },
    { lookupError: SECRET },
    { state: "unknown" as const },
  ]) {
    const opts = options(); opts.supervisor = { ...opts.supervisor, ...change };
    const report = await auditNativeIndependence(opts);
    assert.equal(report.findings.backgroundService.state, "unknown");
    assert.equal(report.findings.backgroundService.ownership, "unverified-or-external");
    assert.equal(report.findings.windowsWatchdog.state, "unknown");
    assert.equal(report.knownCouplingsAbsent, null);
    assert.ok(!JSON.stringify(report).includes(SECRET));
  }
});

test("a malformed or unfamiliar owned launcher does not mean the watchdog is absent", async () => {
  const opts = options({ readWatchdog: () => "unrecognized future launcher" });
  opts.supervisor = { ...opts.supervisor, registered: true, installedHome: HOME };
  const report = await auditNativeIndependence(opts);
  assert.equal(report.findings.windowsWatchdog.state, "unknown");
});

test("direct restoration is reported separately from active traffic", async () => {
  const report = await auditNativeIndependence(options({ readRestoration: () => ({ at: "synthetic", cli: { HTTPS_PROXY: PROXY, OTHER: SECRET }, desktop: null }) }));
  assert.equal(report.originalIndependent, null);
  assert.equal(report.knownCouplingsAbsent, false);
  assert.equal(report.findings.savedRestoration.state, "present");
  assert.ok(!JSON.stringify(report).includes(SECRET));
  const empty = await auditNativeIndependence(options({ readRestoration: () => ({ at: "synthetic", cli: {}, desktop: null }) }));
  assert.equal(empty.findings.savedRestoration.state, "absent");
});

test("missing identities, denied trust reads and malformed inputs stay unknown and redacted", async () => {
  const report = await auditNativeIndependence(options({
    readSettings: () => { throw new Error(SECRET); },
    readDesktop: () => { throw new Error(SECRET); },
    readRestoration: () => ({ at: "synthetic", cli: { accidentalSecret: SECRET } }),
    trustedCa: async () => { throw new Error(SECRET); },
  }));
  for (const key of ["sharedProxy", "sharedCa", "desktopProxy", "desktopPac", "savedRestoration", "trustedCa"] as const) assert.equal(report.findings[key].state, "unknown");
  assert.equal(report.knownCouplingsAbsent, null);
  assert.equal(report.originalIndependent, null);
  assert.ok(!JSON.stringify(report).includes(SECRET));
  assert.match(nativeIndependenceSummary(report), /unknown/);
});

function fixture(t: TestContext) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-native-audit-"));
  const home = path.join(root, "home"), settings = path.join(root, "settings.json"), support = path.join(root, "Desktop");
  fs.mkdirSync(home);
  fs.mkdirSync(path.join(support, "configLibrary"), { recursive: true });
  const previous = { CLAUDE_SETTINGS_PATH: process.env.CLAUDE_SETTINGS_PATH, CLAUDE_APP_SUPPORT: process.env.CLAUDE_APP_SUPPORT };
  process.env.CLAUDE_SETTINGS_PATH = settings;
  process.env.CLAUDE_APP_SUPPORT = support;
  t.after(() => {
    for (const [key, value] of Object.entries(previous)) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
    fs.rmSync(root, { recursive: true, force: true });
  });
  const opts = options({ home });
  delete opts.readSettings; delete opts.readDesktop; delete opts.readRestoration; delete opts.readWatchdog;
  return { root, home, settings, support, opts };
}

test("real bounded readers leave all fixture bytes and files unchanged", async t => {
  const f = fixture(t);
  const files = new Map([
    [f.settings, `{"model":"opus","env":{"ANTHROPIC_API_KEY":"${SECRET}"}}\n`],
    [path.join(f.support, "configLibrary", "_meta.json"), '{"appliedId":"native"}\n'],
    [path.join(f.support, "configLibrary", "native.json"), `{"theme":"native","inferenceGatewayApiKey":"${SECRET}"}\n`],
    [path.join(f.home, "direct.json"), '{"at":"synthetic","cli":{},"desktop":null}\n'],
  ]);
  for (const [file, text] of files) fs.writeFileSync(file, text);
  const before = fs.readdirSync(f.root, { recursive: true }).sort();
  const report = await auditNativeIndependence(f.opts);
  assert.equal(report.knownCouplingsAbsent, true);
  assert.deepEqual(fs.readdirSync(f.root, { recursive: true }).sort(), before);
  for (const [file, text] of files) assert.equal(fs.readFileSync(file, "utf8"), text);
  assert.ok(!JSON.stringify(report).includes(SECRET));
});

test("missing local CA never causes an absence claim or an OS trust query", async t => {
  const f = fixture(t); delete f.opts.trustedCa;
  const report = await auditNativeIndependence(f.opts);
  assert.equal(report.findings.trustedCa.state, "unknown");
  assert.equal(report.knownCouplingsAbsent, null);
  assert.deepEqual(fs.readdirSync(f.home), []);
});

test("a malformed or oversized CA is unknown and never passed to OS trust commands", async t => {
  const f = fixture(t); delete f.opts.trustedCa;
  const ca = path.join(f.home, "ca.pem");
  for (const text of [SECRET, " ".repeat(1024 * 1024 + 1)]) {
    fs.writeFileSync(ca, text);
    const report = await auditNativeIndependence(f.opts);
    assert.equal(report.findings.trustedCa.state, "unknown");
    assert.equal(fs.readFileSync(ca, "utf8"), text);
    assert.ok(!JSON.stringify(report).includes(SECRET));
  }
});

test("a settings symlink stays unknown without following or changing its target", async t => {
  const f = fixture(t), target = path.join(f.root, "other.json");
  const text = JSON.stringify({ env: { HTTPS_PROXY: PROXY, ANTHROPIC_API_KEY: SECRET } });
  fs.writeFileSync(target, text);
  try { fs.symlinkSync(target, f.settings); }
  catch (error) {
    if (["EPERM", "ENOSYS", "EACCES"].includes((error as NodeJS.ErrnoException).code ?? "")) { t.skip("filesystem does not permit test symlinks"); return; }
    throw error;
  }
  const report = await auditNativeIndependence(f.opts);
  assert.equal(report.findings.sharedProxy.state, "unknown");
  assert.ok(fs.lstatSync(f.settings).isSymbolicLink());
  assert.equal(fs.readFileSync(target, "utf8"), text);
  assert.ok(!JSON.stringify(report).includes(SECRET));
});

test("multiply-linked restoration snapshots stay unknown and unchanged", async t => {
  const f = fixture(t), saved = path.join(f.home, "direct.json"), alias = path.join(f.root, "other.json");
  const text = JSON.stringify({ at: "synthetic", cli: { HTTPS_PROXY: PROXY, OTHER: SECRET }, desktop: null });
  fs.writeFileSync(saved, text);
  try { fs.linkSync(saved, alias); }
  catch (error) {
    if (["EPERM", "ENOSYS", "EACCES", "ENOTSUP"].includes((error as NodeJS.ErrnoException).code ?? "")) { t.skip("filesystem does not permit test hard links"); return; }
    throw error;
  }
  const report = await auditNativeIndependence(f.opts);
  assert.equal(report.findings.savedRestoration.state, "unknown");
  assert.equal(fs.readFileSync(saved, "utf8"), text);
  assert.equal(fs.readFileSync(alias, "utf8"), text);
  assert.ok(!JSON.stringify(report).includes(SECRET));
});

test("malformed, directory and oversized settings are unknown and left intact", async t => {
  const f = fixture(t);
  for (const text of [`{"env":"${SECRET}"}`, `["${SECRET}"]`, `{${SECRET}`, " ".repeat(1024 * 1024 + 1)]) {
    fs.writeFileSync(f.settings, text);
    const report = await auditNativeIndependence(f.opts);
    assert.equal(report.findings.sharedProxy.state, "unknown");
    assert.equal(fs.readFileSync(f.settings, "utf8"), text);
    assert.ok(!JSON.stringify(report).includes(SECRET));
  }
  fs.unlinkSync(f.settings); fs.mkdirSync(f.settings);
  const report = await auditNativeIndependence(f.opts);
  assert.equal(report.findings.sharedProxy.state, "unknown");
  assert.ok(fs.statSync(f.settings).isDirectory());
});

test("Desktop entry traversal and missing active entries remain unknown", async t => {
  const f = fixture(t), meta = path.join(f.support, "configLibrary", "_meta.json");
  for (const id of ["../outside", "missing", 99]) {
    fs.writeFileSync(meta, JSON.stringify({ appliedId: id }));
    const report = await auditNativeIndependence(f.opts);
    assert.equal(report.findings.desktopProxy.state, "unknown");
    assert.equal(report.findings.desktopPac.state, "unknown");
  }
});
