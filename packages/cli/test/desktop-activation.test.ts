// Activation tests use a throwaway source tree, private config files and injected trust/service
// boundaries. Nothing calls Windows certificate tools, starts a service, or changes real Claude
// settings. The runtime proof is backed by the real local source fingerprint implementation.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createHash, X509Certificate } from "node:crypto";
import { normalizeConfig, type Config } from "../../router/src/config.ts";
import { readPrivateFile } from "../../router/src/private-file.ts";
import { writePrivateFileAtomic, writeSecretJsonAtomic } from "../../router/src/locked-file.ts";
import { createCa, createLeaf } from "../../router/src/x509.ts";
import { personalDesktopProblems } from "../../router/src/desktop-policy.ts";
import { activateDesktopPicker, checkDesktopActivation, commitDesktopPicker, readDesktopActivationState,
  type DesktopActivationOptions, type DesktopActivationState } from "../src/desktop-activation.ts";
import { captureRouterCodeIdentity, type InstallRuntimeDeps, type InstallRuntimeTarget } from "../src/install-runtime.ts";
import { MODEL_SLOT_ENV } from "../src/settings.ts";

const PROXY = "http://127.0.0.1:8791";
const MODEL = "gemini-4-carbon";
const GOOGLE = "https://generativelanguage.googleapis.com";
const ALIAS_MODEL_ENV = ["ANTHROPIC_DEFAULT_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
  "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_FABLE_MODEL"];
function rawConfig(): Record<string, unknown> {
  return {
    autoUpdate: false,
    security: { mode: "personal", approvedOrigins: ["https://api.anthropic.com", "https://claude.ai", GOOGLE] },
    providers: { google: { type: "google", auth: "api-key", apiKey: "SYNTHETIC-TEST-KEY", models: [{ id: MODEL }] } },
    routes: {}, direct: [], aliases: {},
    cli: { extraModels: [{ model: MODEL, name: "Gemini 4 Carbon" }] },
    futureUnrelatedSettings: { keep: ["operator-owned", 7] },
  };
}
function config(): Config { return normalizeConfig(rawConfig() as Partial<Config>); }
function state(caPem = path.resolve("synthetic-ca.pem")): DesktopActivationState {
  return { config: config(), env: { HTTPS_PROXY: PROXY, NODE_EXTRA_CA_CERTS: caPem },
    desktop: { appliedId: null, egressProxyUrl: null, ours: false },
    desktopFingerprint: "synthetic-desktop-snapshot", caFingerprint: "synthetic-ca-fingerprint", direct: false };
}

function fixture(t: TestContext) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "cr-desktop-activation-")));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const repo = path.join(root, "source");
  const write = (relative: string, content: string) => {
    const file = path.join(repo, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, content);
    return file;
  };
  write("package.json", '{"name":"clauderipple","version":"0.12.36"}');
  write("package-lock.json", '{"lockfileVersion":3}');
  const cli = write("packages/cli/src/index.ts", "export const cli = 1;\n");
  const router = write("packages/router/src/index.ts", "export const router = 1;\n");
  const rt = { repo, cli, router };
  const home = path.join(root, "private-data"), file = path.join(home, "config.json"), caPem = path.join(home, "ca.pem");
  writeSecretJsonAtomic(file, rawConfig());
  const target: InstallRuntimeTarget = { version: "0.12.36", node: process.execPath, router,
    codeIdentity: captureRouterCodeIdentity(rt), listen: { host: "127.0.0.1", port: 8791 }, upstream: "api.anthropic.com" };
  const installId = "d".repeat(32);
  const status = () => ({ version: target.version, installId, pid: 4242, listen: { ...target.listen }, upstream: target.upstream,
    runtime: { node: target.node, router, startedAt: "2026-11-18T12:00:00.000Z", codeIdentity: target.codeIdentity } });
  return { root, home, file, caPem, rt, write, target, installId, status };
}

function controlled(t: TestContext, alreadyTrusted = false) {
  const f = fixture(t), calls: string[] = [];
  let current = state(f.caPem), trusted = alreadyTrusted, tick = 0;
  let live: unknown = f.status();
  const runtime: InstallRuntimeDeps = {
    status: async () => { calls.push("status"); return live; },
    installationId: () => f.installId,
    restart: () => { calls.push("restart"); return "failed"; },
    captureIdentity: () => { calls.push("capture"); return captureRouterCodeIdentity(f.rt); },
    now: () => tick,
    sleep: async ms => { tick += ms; },
  };
  const options: DesktopActivationOptions<string> = {
    target: f.target, runtime, proxyUrl: PROXY, caPem: f.caPem,
    readState: () => { calls.push("read-state"); return structuredClone(current); },
    checkDesktop: () => { calls.push("check-desktop"); },
    probe: async () => { calls.push("probe"); return { ok: true, detail: "synthetic data probe", ms: 1 }; },
    trusted: () => { calls.push("trusted"); return trusted; },
    trust: () => { calls.push("trust"); trusted = true; },
    untrust: () => { calls.push("untrust"); const previous = trusted; trusted = false; return previous ? "removed" : "absent"; },
    apply: original => { calls.push("apply"); assert.deepEqual(original, current); return "applied"; },
  };
  return { ...f, calls, options, current: () => current, trustState: () => trusted,
    change: (fn: (value: DesktopActivationState) => void) => { fn(current); },
    setState: (value: DesktopActivationState) => { current = value; },
    setStatus: (value: unknown) => { live = value; }, setTrusted: (value: boolean) => { trusted = value; } };
}

function isolatedStateReader(t: TestContext) {
  const f = fixture(t), keys = ["CLAUDE_SETTINGS_PATH", "CLAUDE_APP_SUPPORT"] as const;
  const previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  t.after(() => { for (const key of keys) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; } });
  process.env.CLAUDE_SETTINGS_PATH = path.join(f.root, "isolated-settings.json");
  process.env.CLAUDE_APP_SUPPORT = path.join(f.root, "isolated-Claude-3p");
  fs.writeFileSync(process.env.CLAUDE_SETTINGS_PATH, JSON.stringify({ env: { HTTPS_PROXY: PROXY, NODE_EXTRA_CA_CERTS: f.caPem, USER_SETTING: "keep" } }));
  const ca = createCa({ cn: "Synthetic Desktop activation CA" });
  fs.writeFileSync(f.caPem, ca.certPem);
  return { ...f, ca, read: () => readDesktopActivationState(f.file, f.home, f.caPem) };
}

test("Desktop preflight accepts an explicit approved Google extra and unchanged native settings", () => {
  const s = state();
  s.env.ANTHROPIC_MODEL = "opus";
  s.env.ANTHROPIC_SMALL_FAST_MODEL = "claude-haiku-5-5";
  s.env.CLAUDE_CODE_SUBAGENT_MODEL = "sonnet[1m]";
  s.env.ANTHROPIC_DEFAULT_OPUS_MODEL = "fable";
  s.env.NO_PROXY = "localhost,127.0.0.1,unrelated.example.invalid";
  assert.doesNotThrow(() => checkDesktopActivation(s, PROXY, s.env.NODE_EXTRA_CA_CERTS!));
  for (const alias of ["fable", "default", "best", "opusplan"]) {
    s.env.ANTHROPIC_MODEL = alias;
    assert.doesNotThrow(() => checkDesktopActivation(s, PROXY, s.env.NODE_EXTRA_CA_CERTS!), alias);
  }
});

test("missing origin, wrong engine settings, direct mode and absent extra refuse before runtime, trust or Desktop writes", async t => {
  const changes: [string, (s: DesktopActivationState) => void][] = [
    ["native origin", s => { s.config.security!.approvedOrigins = s.config.security!.approvedOrigins.filter(origin => origin !== "https://api.anthropic.com"); }],
    ["Desktop origin", s => { s.config.security!.approvedOrigins = s.config.security!.approvedOrigins.filter(origin => origin !== "https://claude.ai"); }],
    ["Google origin", s => { s.config.security!.approvedOrigins = s.config.security!.approvedOrigins.filter(origin => origin !== GOOGLE); }],
    ["no extra", s => { s.config.cli.extraModels = []; }],
    ["missing provider", s => { s.config.providers = {}; }],
    ["proxy mismatch", s => { s.env.HTTPS_PROXY = "http://127.0.0.1:9999"; }],
    ["CA mismatch", s => { s.env.NODE_EXTRA_CA_CERTS += ".different"; }],
    ["direct", s => { s.direct = true; }],
  ];
  for (const [label, change] of changes) {
    const f = controlled(t);
    f.change(change);
    await assert.rejects(activateDesktopPicker(f.options), Error, label);
    assert.deepEqual(f.calls, ["read-state"], label);
    assert.equal(f.trustState(), false);
  }
});

test("Desktop preflight refuses existing authentication, provider, TLS and native-slot overrides", () => {
  const overrides = {
    ANTHROPIC_BASE_URL: "https://other.example.invalid", ANTHROPIC_API_KEY: "synthetic",
    ANTHROPIC_AUTH_TOKEN: "synthetic", CLAUDE_CODE_OAUTH_TOKEN: "synthetic",
    CLAUDE_CODE_USE_BEDROCK: "1", CLAUDE_CODE_USE_VERTEX: "1", CLAUDE_CODE_USE_FOUNDRY: "1",
    NODE_TLS_REJECT_UNAUTHORIZED: "0", NODE_OPTIONS: "--require synthetic.js",
    ...Object.fromEntries(Object.values(MODEL_SLOT_ENV).map(name => [name, MODEL])),
    ...Object.fromEntries(ALIAS_MODEL_ENV.map(name => [name, MODEL])),
  };
  for (const [name, value] of Object.entries(overrides)) {
    const s = state(); s.env[name] = value;
    assert.throws(() => checkDesktopActivation(s, PROXY, s.env.NODE_EXTRA_CA_CERTS!), /override|replaces|startup/, name);
  }
});

test("Desktop preflight refuses NO_PROXY bypass spellings for either intercepted destination", () => {
  for (const key of ["NO_PROXY", "no_proxy"]) {
    for (const value of ["*", "api.anthropic.com", ".anthropic.com", "CLAUDE.AI:443", "localhost, .claude.ai"]) {
      const s = state(); s.env[key] = value;
      assert.throws(() => checkDesktopActivation(s, PROXY, s.env.NODE_EXTRA_CA_CERTS!), /NO_PROXY/, `${key}=${value}`);
    }
  }
});

test("a benign NO_PROXY setting cannot hide an unsafe lower-case no_proxy setting or vice versa", () => {
  for (const blocked of ["NO_PROXY", "no_proxy"]) {
    const s = state();
    s.env.NO_PROXY = "localhost";
    s.env.no_proxy = "127.0.0.1";
    s.env[blocked] = ".anthropic.com";
    assert.throws(() => checkDesktopActivation(s, PROXY, s.env.NODE_EXTRA_CA_CERTS!), /NO_PROXY/);
  }
});

test("Desktop personal policy rejects route/slot/classifier/search takeover and extra intercepted hosts", () => {
  const changes: ((cfg: Config) => void)[] = [
    cfg => { cfg.routes["claude-opus-5-5"] = { provider: "google", model: MODEL }; },
    cfg => { cfg.aliases.opus = MODEL; },
    cfg => { cfg.direct = [{ prefix: "cla", provider: "google" }]; },
    cfg => { cfg.direct = [{ prefix: "claude-opus", provider: "google" }]; },
    cfg => { cfg.providers.google!.models!.push({ id: "claude-sonnet-5-5" }); },
    cfg => { cfg.cli.models = { smallFast: MODEL }; },
    cfg => { cfg.autoModeClassifier = { provider: "google", model: MODEL }; },
    cfg => { cfg.webSearch = { provider: "google", model: MODEL }; },
    cfg => { cfg.picker = { enabled: true, hosts: ["claude.ai", "other.example.invalid"] }; },
  ];
  for (const change of changes) {
    const s = state(); change(s.config);
    assert.throws(() => checkDesktopActivation(s, PROXY, s.env.NODE_EXTRA_CA_CERTS!), /personal Desktop mode/);
    s.config.picker = { ...(s.config.picker ?? {}), enabled: false };
    assert.deepEqual(personalDesktopProblems(s.config), [], "unrelated generic configurations remain out of this Desktop-only policy");
  }
});

test("Desktop activation proves runtime, probes, confirms trust, proves again and only then applies", async t => {
  const f = controlled(t);
  assert.equal(await activateDesktopPicker(f.options), "applied");
  assert.deepEqual(f.calls, ["read-state", "check-desktop", "trusted", "status", "probe", "read-state", "check-desktop",
    "trust", "trusted", "read-state", "check-desktop", "status", "capture", "read-state", "check-desktop", "apply"]);
  assert.equal(f.trustState(), true);
});

test("Desktop conflict and absent authenticated runtime refuse before any trust change", async t => {
  const conflict = controlled(t);
  conflict.options.checkDesktop = () => { conflict.calls.push("check-desktop"); throw new Error("existing corporate proxy"); };
  await assert.rejects(activateDesktopPicker(conflict.options), /corporate proxy/);
  assert.deepEqual(conflict.calls, ["read-state", "check-desktop"]);
  const missing = controlled(t); missing.setStatus(null);
  await assert.rejects(activateDesktopPicker(missing.options), /Secure router identity is unavailable/);
  assert.equal(missing.calls.includes("probe"), false);
  assert.equal(missing.calls.includes("trust"), false);
  assert.equal(missing.calls.includes("apply"), false);
});

test("failed Desktop data probe never changes trust or configuration", async t => {
  const f = controlled(t);
  f.options.probe = async () => { f.calls.push("probe"); return { ok: false, detail: "synthetic failure", ms: 1 }; };
  await assert.rejects(activateDesktopPicker(f.options), /probe failed/);
  assert.equal(f.calls.includes("trust"), false);
  assert.equal(f.calls.includes("untrust"), false);
  assert.equal(f.calls.includes("apply"), false);
});

test("a cancelled certificate prompt stops activation and confirms no new trust remains", async t => {
  const f = controlled(t);
  f.options.trust = () => { f.calls.push("trust-cancelled"); };
  await assert.rejects(activateDesktopPicker(f.options), /CA was not trusted/);
  assert.equal(f.calls.includes("apply"), false);
  assert.equal(f.calls.at(-1), "untrust");
  assert.equal(f.trustState(), false);
});

test("a trust helper that fails after adding the certificate rolls back its partial change", async t => {
  const f = controlled(t);
  f.options.trust = () => { f.calls.push("trust"); f.setTrusted(true); throw new Error("synthetic trust helper error"); };
  await assert.rejects(activateDesktopPicker(f.options), /synthetic trust helper error/);
  assert.equal(f.calls.includes("apply"), false);
  assert.equal(f.calls.at(-1), "untrust");
  assert.equal(f.trustState(), false);
});

test("pre-existing trust removed during a probe is not silently re-added", async t => {
  const f = controlled(t, true);
  f.options.probe = async () => { f.calls.push("probe"); f.setTrusted(false); return { ok: true, detail: "synthetic", ms: 1 }; };
  await assert.rejects(activateDesktopPicker(f.options), /CA was not trusted/);
  assert.equal(f.calls.includes("trust"), false);
  assert.equal(f.calls.includes("untrust"), false);
  assert.equal(f.calls.includes("apply"), false);
});

test("config, Code env, CA, Desktop and direct-state races during probe refuse before trusting", async t => {
  const races: ((s: DesktopActivationState) => void)[] = [
    s => { s.config.cli.extraModels[0]!.name = "Edited concurrently"; },
    s => { s.env.UNRELATED_SETTING = "changed"; },
    s => { s.caFingerprint = "replacement-ca"; },
    s => { s.desktopFingerprint = "replacement-config-library-entry"; },
    s => { s.desktop = { appliedId: "user-config", egressProxyUrl: "http://other.invalid:80", ours: false }; },
    s => { s.direct = true; },
  ];
  for (const race of races) {
    const f = controlled(t);
    f.options.probe = async () => { f.calls.push("probe"); f.change(race); return { ok: true, detail: "synthetic", ms: 1 }; };
    await assert.rejects(activateDesktopPicker(f.options), /changed during activation/);
    assert.equal(f.calls.includes("trust"), false);
    assert.equal(f.calls.includes("apply"), false);
  }
});

test("a post-trust settings race rolls back only the newly added CA", async t => {
  const f = controlled(t);
  f.options.trust = () => { f.calls.push("trust"); f.setTrusted(true); f.change(s => { s.env.NEW_USER_SETTING = "preserve"; }); };
  await assert.rejects(activateDesktopPicker(f.options), /changed during activation/);
  assert.equal(f.trustState(), false);
  assert.equal(f.calls.at(-1), "untrust");
  assert.equal(f.calls.includes("apply"), false);
  assert.equal(f.current().env.NEW_USER_SETTING, "preserve");
});

test("CA or Desktop ownership races prevent unsafe certificate rollback", async t => {
  for (const race of [
    (s: DesktopActivationState) => { s.caFingerprint = "another-CA"; },
    (s: DesktopActivationState) => { s.desktopFingerprint = "another-desktop-config"; },
    (s: DesktopActivationState) => { s.config.picker = { enabled: true }; },
  ]) {
    const f = controlled(t);
    f.options.trust = () => { f.calls.push("trust"); f.setTrusted(true); f.change(race); };
    await assert.rejects(activateDesktopPicker(f.options), /newly requested CA trust could not be safely removed/);
    assert.equal(f.calls.includes("untrust"), false);
    assert.equal(f.calls.includes("apply"), false);
    assert.equal(f.trustState(), true, "leave uncertain shared trust intact with an explicit recovery error");
  }
});

test("replacement process or changed source after trust prevents apply and rolls back newly added trust", async t => {
  for (const race of ["process", "source"]) {
    const f = controlled(t);
    let reads = 0;
    f.options.runtime.status = async () => {
      f.calls.push("status");
      if (++reads === 2) {
        if (race === "process") return { ...f.status(), pid: 9999 };
        f.write("packages/router/src/index.ts", "export const router = 2;\n");
      }
      return f.status();
    };
    await assert.rejects(activateDesktopPicker(f.options), /instance changed|files changed/);
    assert.equal(f.calls.includes("apply"), false);
    assert.equal(f.calls.at(-1), "untrust");
    assert.equal(f.trustState(), false);
  }
});

test("apply failure preserves pre-existing trust, while newly added trust is removed", async t => {
  for (const alreadyTrusted of [false, true]) {
    const f = controlled(t, alreadyTrusted);
    f.options.apply = () => { f.calls.push("apply"); throw new Error("synthetic Desktop write failure"); };
    await assert.rejects(activateDesktopPicker(f.options), /synthetic Desktop write failure/);
    assert.equal(f.calls.includes("trust"), !alreadyTrusted);
    assert.equal(f.calls.includes("untrust"), !alreadyTrusted);
    assert.equal(f.trustState(), alreadyTrusted);
  }
});

test("a failed trust-removal result produces an actionable incomplete-activation error", async t => {
  const f = controlled(t);
  f.options.apply = () => { throw new Error("synthetic apply error"); };
  f.options.untrust = () => { f.calls.push("untrust"); return "failed"; };
  await assert.rejects(activateDesktopPicker(f.options), /could not be safely removed/);
  assert.equal(f.trustState(), true);
});

test("commit enables only picker and retains all raw fields without persisting normalized defaults", t => {
  const f = fixture(t), before = rawConfig();
  const result = commitDesktopPicker(f.file, normalizeConfig(before as Partial<Config>), () => {
    assert.deepEqual(JSON.parse(readPrivateFile(f.file).toString("utf8")), { ...before, picker: { enabled: true } });
    return "Desktop applied";
  });
  assert.equal(result, "Desktop applied");
});

test("failed Desktop commit restores the original raw config and original absence of picker", t => {
  const f = fixture(t), before = rawConfig();
  assert.throws(() => commitDesktopPicker(f.file, normalizeConfig(before as Partial<Config>), () => {
    assert.equal(JSON.parse(readPrivateFile(f.file).toString("utf8")).picker.enabled, true);
    throw new Error("synthetic app write failed");
  }), /synthetic app write failed/);
  assert.deepEqual(JSON.parse(readPrivateFile(f.file).toString("utf8")), before);
});

test("failed Desktop commit preserves prior picker metadata and prior enabled flag", t => {
  for (const enabled of [false, true]) {
    const f = fixture(t), before = { ...rawConfig(), picker: { enabled, hosts: ["claude.ai"], futureValue: "keep" } };
    writeSecretJsonAtomic(f.file, before);
    const storedBefore = fs.readFileSync(f.file);
    assert.throws(() => commitDesktopPicker(f.file, normalizeConfig(before as Partial<Config>), () => { throw new Error("synthetic failure"); }), /synthetic failure/);
    assert.deepEqual(JSON.parse(readPrivateFile(f.file).toString("utf8")), before);
    if (enabled) assert.deepEqual(fs.readFileSync(f.file), storedBefore, "already enabled config is never rewritten on failure");
  }
});

test("a pre-commit config edit refuses before calling Desktop apply and remains intact", t => {
  const f = fixture(t), expected = config();
  const edited = { ...rawConfig(), futureUnrelatedSettings: { edited: "preserve this" } };
  writeSecretJsonAtomic(f.file, edited);
  let applied = false;
  assert.throws(() => commitDesktopPicker(f.file, expected, () => { applied = true; }), /configuration changed/);
  assert.equal(applied, false);
  assert.deepEqual(JSON.parse(readPrivateFile(f.file).toString("utf8")), edited);
});

test("a concurrent noncooperating config writer is preserved when Desktop apply fails", t => {
  const f = fixture(t);
  const edited = { ...rawConfig(), picker: { enabled: true }, futureUnrelatedSettings: { concurrent: "preserve" } };
  assert.throws(() => commitDesktopPicker(f.file, config(), () => {
    // An old/external writer can ignore our advisory lock. Never erase its changes on rollback.
    writeSecretJsonAtomic(f.file, edited);
    throw new Error("synthetic Desktop failure");
  }), /configuration changed or rollback failed.*Existing edits were preserved/);
  assert.deepEqual(JSON.parse(readPrivateFile(f.file).toString("utf8")), edited);
});

test("rollback preserves exact stored bytes when a concurrent raw edit normalizes identically", t => {
  const f = fixture(t);
  const enabled = { ...rawConfig(), picker: { enabled: true } };
  // An explicit default can be an intentional operator choice for a future version. It is a
  // distinct raw edit even though today's normalized configuration is exactly the same.
  const edited = { ...enabled, listen: { ...normalizeConfig(enabled as Partial<Config>).listen } };
  assert.deepEqual(normalizeConfig(edited as Partial<Config>), normalizeConfig(enabled as Partial<Config>));
  assert.notDeepEqual(edited, enabled);
  let concurrentBytes: Buffer | undefined;
  assert.throws(() => commitDesktopPicker(f.file, config(), () => {
    writeSecretJsonAtomic(f.file, edited);
    concurrentBytes = fs.readFileSync(f.file);
    throw new Error("synthetic Desktop apply failure");
  }), /configuration changed or rollback failed.*Existing edits were preserved/);
  assert.ok(concurrentBytes);
  assert.deepEqual(fs.readFileSync(f.file), concurrentBytes, "including encrypted-at-rest bytes, the concurrent writer's file is never rewritten");
  assert.deepEqual(JSON.parse(readPrivateFile(f.file).toString("utf8")), edited);
});

test("commit refuses an invalid private config without echoing its contents or invoking apply", t => {
  const f = fixture(t), secret = "SYNTHETIC-PRIVATE-JSON-PARSER-SENTINEL";
  writePrivateFileAtomic(f.file, `{"secret": ${secret} invalid}`);
  let applied = false, error: unknown;
  try { commitDesktopPicker(f.file, config(), () => { applied = true; }); } catch (caught) { error = caught; }
  assert.equal(applied, false);
  assert.match(String(error), /readable, valid private configuration/);
  assert.ok(!String(error).includes(secret));
});

test("activation refuses a native model remap before touching runtime, trust or Desktop", async t => {
  const f = controlled(t);
  f.change(s => { s.config.routes["claude-opus-5-5"] = { provider: "google", model: MODEL }; });
  await assert.rejects(activateDesktopPicker(f.options), /preserves native Claude model routes/);
  assert.deepEqual(f.calls, ["read-state"]);
  assert.equal(f.trustState(), false);
});

test("real state reader stays within isolated settings, Desktop library and synthetic CA paths", t => {
  const f = isolatedStateReader(t), read = f.read();
  assert.equal(read.env.USER_SETTING, "keep");
  assert.equal(read.env.HTTPS_PROXY, PROXY);
  assert.equal(read.desktop.ours, false);
  assert.equal(read.direct, false);
  assert.ok(read.caFingerprint.length > 0);
  assert.equal(read.config.cli.extraModels[0]?.model, MODEL);
  fs.writeFileSync(path.join(f.home, "direct.json"), "{}");
  assert.equal(f.read().direct, true);
});

test("state fingerprint covers every CA PEM byte, including whitespace outside the certificate", t => {
  const f = isolatedStateReader(t), before = f.read().caFingerprint;
  assert.equal(before, createHash("sha256").update(f.ca.certPem).digest("hex"));
  const changed = `${f.ca.certPem}\n`;
  fs.writeFileSync(f.caPem, changed);
  assert.equal(new X509Certificate(changed).fingerprint256, new X509Certificate(f.ca.certPem).fingerprint256,
    "a certificate-only fingerprint cannot detect a file-byte edit");
  assert.notEqual(f.read().caFingerprint, before);
});

test("state reader refuses CA bundles, appended material and a non-CA certificate", t => {
  const f = isolatedStateReader(t);
  const leaf = createLeaf({ host: "api.anthropic.com", caCertPem: f.ca.certPem, caKeyPem: f.ca.keyPem });
  for (const contents of [`${f.ca.certPem}${f.ca.certPem}`, `${f.ca.certPem}SYNTHETIC-EXTRA-DATA`, leaf.certPem]) {
    fs.writeFileSync(f.caPem, contents);
    assert.throws(f.read, /single CA certificate/);
  }
});
