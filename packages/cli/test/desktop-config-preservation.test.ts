// Real Config Library files, isolated from the user's Desktop and certificate stores.
import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  appProxyFingerprint, applyAppProxy, checkAppProxyActivation, configLibraryDir,
  currentAppProxy, removeAppProxy,
} from "../src/picker.ts";
import { normalizeHome } from "../src/ownership.ts";

function fixture(t: TestContext) {
  const root = fs.realpathSync.native(fs.mkdtempSync(path.join(os.tmpdir(), "cr-desktop-preserve-")));
  const before = process.env.CLAUDE_APP_SUPPORT;
  process.env.CLAUDE_APP_SUPPORT = path.join(root, "desktop");
  const home = path.join(root, "ripple");
  fs.mkdirSync(home);
  const dir = configLibraryDir();
  fs.mkdirSync(dir, { recursive: true });
  const meta = path.join(dir, "_meta.json");
  const original = path.join(dir, "original.json");
  const originalBytes = '{\n  "theme" : "dark", "locale": "zh-CN",\n  "mcpServers": { "local-test": { "command": "fixture-only" } }\n}\n';
  fs.writeFileSync(original, originalBytes);
  fs.writeFileSync(meta, '{ "appliedId": "original", "desktopSetting": {"preserve":true} }\n');
  t.after(() => {
    if (before === undefined) delete process.env.CLAUDE_APP_SUPPORT;
    else process.env.CLAUDE_APP_SUPPORT = before;
    fs.rmSync(root, { recursive: true, force: true });
  });
  const read = (file: string) => JSON.parse(fs.readFileSync(file, "utf8")) as Record<string, unknown>;
  const snapshot = () => Object.fromEntries(fs.readdirSync(dir).sort().map(name => [name, fs.readFileSync(path.join(dir, name), "utf8")]));
  return { root, home, dir, meta, original, originalBytes, read, snapshot, url: "http://127.0.0.1:18791" };
}

for (const kind of ["foreign-proxy", "foreign-pac", "own-pac", "unknown-owner", "other-owner", "different-port"] as const) {
  test(`Desktop activation preflight refuses ${kind} without changing configuration`, t => {
    const f = fixture(t);
    const entry = f.read(f.original);
    const own = !kind.startsWith("foreign");
    fs.writeFileSync(f.original, JSON.stringify({ ...entry,
      ...(kind.endsWith("pac") ? { egressProxyPacUrl: "https://managed.example/proxy.pac" } : {}),
      ...(kind === "foreign-proxy" ? { egressProxyUrl: "http://managed.example:8080" } : {}),
      ...(own ? { egressProxyUrl: kind === "different-port" ? "http://127.0.0.1:28791" : f.url } : {}),
    }));
    if (own) fs.writeFileSync(f.meta, JSON.stringify({ appliedId: "original", clauderipple: {
      ourId: "original", previousAppliedId: null,
      ...(kind === "unknown-owner" ? {} : { installationHome: kind === "other-owner" ? path.join(f.root, "other") : f.home }),
    } }));
    const before = f.snapshot();
    assert.throws(() => checkAppProxyActivation(f.url, f.home), /left unchanged/);
    assert.deepEqual(f.snapshot(), before);
  });
}

test("Desktop activation copies unrelated settings and restores the original immutable entry", t => {
  const f = fixture(t);
  const originalMeta = f.read(f.meta), originalEntry = f.read(f.original);
  const expected = currentAppProxy(), fingerprint = appProxyFingerprint();
  checkAppProxyActivation(f.url, f.home);
  const applied = applyAppProxy(f.url, f.home, expected, {}, fingerprint);
  assert.equal(applied.replaced, "original");
  assert.deepEqual(f.read(path.join(f.dir, `${applied.id}.json`)), { ...originalEntry, egressProxyUrl: f.url });
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
  assert.deepEqual(f.read(f.meta).desktopSetting, originalMeta.desktopSetting);
  assert.equal(currentAppProxy().installationHome, normalizeHome(f.home));
  assert.equal(removeAppProxy(f.url, f.home), true);
  assert.deepEqual(f.read(f.meta), originalMeta);
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
  assert.equal(fs.existsSync(path.join(f.dir, `${applied.id}.json`)), false);
  assert.equal(currentAppProxy().appliedId, "original");
});

test("reapplying an owned Desktop entry keeps subsequent nonproxy settings", t => {
  const f = fixture(t);
  const applied = applyAppProxy(f.url, f.home);
  const ownedFile = path.join(f.dir, `${applied.id}.json`);
  const edited = { ...f.read(ownedFile), locale: "en-CA", userAdded: { nested: [1, 2, 3] } };
  fs.writeFileSync(ownedFile, JSON.stringify(edited));
  const fingerprint = appProxyFingerprint();
  checkAppProxyActivation(f.url, f.home);
  assert.deepEqual(applyAppProxy(f.url, f.home, currentAppProxy(), {}, fingerprint), { id: applied.id, replaced: null });
  assert.deepEqual(f.read(ownedFile), edited);
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

for (const egressProxyUrl of ["http://managed.example:8080", "http://127.0.0.1:18791", "", null]) {
  test(`Desktop writer independently refuses a nonowned proxy value ${JSON.stringify(egressProxyUrl)}`, t => {
    const f = fixture(t);
    fs.writeFileSync(f.original, JSON.stringify({ ...f.read(f.original), egressProxyUrl }));
    const before = f.snapshot();
    assert.throws(() => applyAppProxy(f.url, f.home), /separate proxy configuration/);
    assert.deepEqual(f.snapshot(), before, "the locked writer is safe without a separate preflight call");
  });
}

for (const kind of ["unsafe", "backslash", "missing-entry", "self", "empty", "number", "object"] as const) {
  test(`Desktop restore refuses ${kind} previous entry without modifying configuration`, t => {
    const f = fixture(t);
    const applied = applyAppProxy(f.url, f.home);
    const previousAppliedId = {
      unsafe: "../outside", backslash: "..\\outside", "missing-entry": "no-such-entry",
      self: applied.id, empty: "", number: 42, object: { id: "original" },
    }[kind];
    const meta = f.read(f.meta);
    fs.writeFileSync(f.meta, JSON.stringify({ ...meta, clauderipple: {
      ...(meta.clauderipple as Record<string, unknown>), previousAppliedId,
    } }));
    const outside = path.join(path.dirname(f.dir), "outside.json");
    const sentinel = '{"untouched":"restoration cannot escape the config library"}\n';
    fs.writeFileSync(outside, sentinel);
    const before = f.snapshot();
    assert.throws(() => removeAppProxy(f.url, f.home));
    assert.deepEqual(f.snapshot(), before);
    assert.equal(fs.readFileSync(outside, "utf8"), sentinel);
    assert.equal(currentAppProxy().appliedId, applied.id);
  });
}

test("legacy ownership with an omitted previous entry retains null restoration semantics", t => {
  const f = fixture(t);
  const applied = applyAppProxy(f.url, f.home);
  const meta = f.read(f.meta);
  const marker = meta.clauderipple as Record<string, unknown>;
  delete marker.previousAppliedId;
  delete marker.preservesNativeSettings;
  fs.writeFileSync(path.join(f.dir, `${applied.id}.json`), JSON.stringify({ egressProxyUrl: f.url }));
  fs.writeFileSync(f.meta, JSON.stringify(meta));
  assert.equal(removeAppProxy(f.url, f.home), true);
  assert.equal(currentAppProxy().appliedId, null);
  assert.equal(fs.existsSync(path.join(f.dir, `${applied.id}.json`)), false);
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

test("removing picker preserves edited, added and deleted active native settings in a clean entry", t => {
  const f = fixture(t);
  const applied = applyAppProxy(f.url, f.home);
  const ownedFile = path.join(f.dir, `${applied.id}.json`);
  const edited = { ...f.read(ownedFile), theme: "light", userAdded: { nested: ["new", { kept: true }] },
    mcpServers: { replacement: { command: "edited-fixture", args: ["keep-exactly"] } } };
  delete (edited as Record<string, unknown>).locale;
  fs.writeFileSync(ownedFile, JSON.stringify(edited));
  fs.writeFileSync(f.meta, JSON.stringify({ ...f.read(f.meta), desktopSetting: { preserve: "edited-while-active" } }));
  assert.equal(removeAppProxy(f.url, f.home), true);
  const current = currentAppProxy();
  assert.equal(current.ours, false);
  assert.equal(current.egressProxyUrl, null);
  assert.notEqual(current.appliedId, "original");
  assert.notEqual(current.appliedId, applied.id);
  const wanted = { ...edited }; delete (wanted as Record<string, unknown>).egressProxyUrl;
  assert.deepEqual(f.read(path.join(f.dir, `${current.appliedId}.json`)), wanted);
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
  assert.equal(fs.existsSync(ownedFile), false);
  assert.deepEqual(f.read(f.meta).desktopSetting, { preserve: "edited-while-active" });
  assert.equal(Object.hasOwn(f.read(f.meta), "clauderipple"), false);
});

test("deleting all active native settings is preserved for a modern copied entry", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  fs.writeFileSync(path.join(f.dir, `${applied.id}.json`), JSON.stringify({ egressProxyUrl: f.url }));
  assert.equal(removeAppProxy(f.url, f.home), true);
  const current = currentAppProxy();
  assert.notEqual(current.appliedId, "original");
  assert.deepEqual(f.read(path.join(f.dir, `${current.appliedId}.json`)), {});
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

test("native settings added after activation without a prior entry survive removal", t => {
  const f = fixture(t); fs.writeFileSync(f.meta, JSON.stringify({ desktopSetting: "no-prior-entry" }));
  const applied = applyAppProxy(f.url, f.home);
  fs.writeFileSync(path.join(f.dir, `${applied.id}.json`), JSON.stringify({ egressProxyUrl: f.url, theme: "system", newNative: true }));
  assert.equal(removeAppProxy(f.url, f.home), true);
  assert.deepEqual(f.read(path.join(f.dir, `${currentAppProxy().appliedId}.json`)), { theme: "system", newNative: true });
  assert.equal(f.read(f.meta).desktopSetting, "no-prior-entry");
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

test("legacy nonproxy fields are preserved even without the modern copied-settings marker", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  const meta = f.read(f.meta); delete (meta.clauderipple as Record<string, unknown>).preservesNativeSettings;
  fs.writeFileSync(f.meta, JSON.stringify(meta));
  fs.writeFileSync(path.join(f.dir, `${applied.id}.json`), JSON.stringify({ egressProxyUrl: f.url, theme: "legacy-user-edit" }));
  assert.equal(removeAppProxy(f.url, f.home), true);
  assert.deepEqual(f.read(path.join(f.dir, `${currentAppProxy().appliedId}.json`)), { theme: "legacy-user-edit" });
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

test("an edited inactive original is preserved without guessing a merge into current settings", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  const active = { ...f.read(path.join(f.dir, `${applied.id}.json`)), locale: "en-CA" };
  fs.writeFileSync(path.join(f.dir, `${applied.id}.json`), JSON.stringify(active));
  const inactive = '{ "theme":"inactive-edit", "inactiveOnly":true }\n';
  fs.writeFileSync(f.original, inactive);
  assert.equal(removeAppProxy(f.url, f.home), true);
  const wanted = { ...active }; delete (wanted as Record<string, unknown>).egressProxyUrl;
  assert.deepEqual(f.read(path.join(f.dir, `${currentAppProxy().appliedId}.json`)), wanted);
  assert.equal(fs.readFileSync(f.original, "utf8"), inactive);
});

test("repeated off/on/off uses the preserved native ID without losing settings or accumulating owned copies", t => {
  const f = fixture(t); const first = applyAppProxy(f.url, f.home);
  fs.writeFileSync(path.join(f.dir, `${first.id}.json`), JSON.stringify({ ...f.read(path.join(f.dir, `${first.id}.json`)), theme: "edited" }));
  assert.equal(removeAppProxy(f.url, f.home), true);
  const preserved = currentAppProxy().appliedId!;
  const native = f.read(path.join(f.dir, `${preserved}.json`));
  const after = f.snapshot();
  assert.equal(removeAppProxy(f.url, f.home), false);
  assert.deepEqual(f.snapshot(), after);
  const second = applyAppProxy(f.url, f.home);
  assert.equal(second.replaced, preserved);
  assert.deepEqual(f.read(path.join(f.dir, `${second.id}.json`)), { ...native, egressProxyUrl: f.url });
  assert.equal(removeAppProxy(f.url, f.home), true);
  assert.equal(currentAppProxy().appliedId, preserved);
  assert.deepEqual(f.snapshot(), after);
});

test("foreign proxy or PAC edits during picker use are left untouched", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  const file = path.join(f.dir, `${applied.id}.json`), original = f.read(file);
  fs.writeFileSync(file, JSON.stringify({ ...original, egressProxyPacUrl: "https://managed.invalid/proxy.pac" }));
  const pac = f.snapshot();
  assert.throws(() => removeAppProxy(f.url, f.home), /PAC proxy.*left unchanged/);
  assert.deepEqual(f.snapshot(), pac);
  fs.writeFileSync(file, JSON.stringify({ ...original, egressProxyUrl: "http://managed.invalid:8080" }));
  const foreign = f.snapshot();
  assert.equal(removeAppProxy(f.url, f.home), false);
  assert.deepEqual(f.snapshot(), foreign);
});

for (const timing of ["before", "after"] as const) {
  test(`removal metadata failure ${timing} publication restores owned activation and edited native settings`, t => {
    const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
    fs.writeFileSync(path.join(f.dir, `${applied.id}.json`), JSON.stringify({ ...f.read(path.join(f.dir, `${applied.id}.json`)), theme: "edited" }));
    const before = f.snapshot(); const rename = fs.renameSync; let failures = 0;
    const stub = t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
      if (String(to) === f.meta && failures === 0) {
        failures++; if (timing === "after") rename(from, to);
        throw Object.assign(new Error("simulated removal publish failure"), { code: "EIO" });
      }
      return rename(from, to);
    });
    try { assert.throws(() => removeAppProxy(f.url, f.home), /simulated removal publish failure/); }
    finally { stub.mock.restore(); }
    assert.equal(failures, 1);
    assert.deepEqual(f.read(f.meta), JSON.parse(before["_meta.json"]!));
    assert.equal(fs.readFileSync(path.join(f.dir, `${applied.id}.json`), "utf8"), before[`${applied.id}.json`]);
    assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
    assert.deepEqual(fs.readdirSync(f.dir).sort(), Object.keys(before).sort());
    assert.equal(currentAppProxy().appliedId, applied.id);
  });
}

test("an active native edit concurrent with preservation is retained and removal refuses", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  const owned = path.join(f.dir, `${applied.id}.json`);
  fs.writeFileSync(owned, JSON.stringify({ ...f.read(owned), theme: "first-edit" }));
  const meta = f.read(f.meta); const rename = fs.renameSync; let edited = false;
  const stub = t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
    const out = rename(from, to);
    if (!edited && String(to) !== f.meta && String(to).endsWith(".json")) {
      edited = true; fs.writeFileSync(owned, JSON.stringify({ ...f.read(owned), theme: "concurrent-edit" }));
    }
    return out;
  });
  try { assert.throws(() => removeAppProxy(f.url, f.home), /changed during proxy removal/); }
  finally { stub.mock.restore(); }
  assert.equal(edited, true);
  assert.equal(f.read(owned).theme, "concurrent-edit");
  assert.deepEqual(f.read(f.meta), meta);
  assert.deepEqual(fs.readdirSync(f.dir).sort(), ["_meta.json", "original.json", `${applied.id}.json`].sort());
});

test("active native edit during metadata publication restores the edited active document, not its old clone", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  const owned = path.join(f.dir, `${applied.id}.json`);
  fs.writeFileSync(owned, JSON.stringify({ ...f.read(owned), theme: "first-edit" }));
  const meta = f.read(f.meta); const rename = fs.renameSync; let edited = false;
  const stub = t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
    const out = rename(from, to);
    if (!edited && String(to) === f.meta) { edited = true; fs.writeFileSync(owned, JSON.stringify({ ...f.read(owned), theme: "late-edit" })); }
    return out;
  });
  try { assert.throws(() => removeAppProxy(f.url, f.home), /changed during proxy removal/); }
  finally { stub.mock.restore(); }
  assert.equal(f.read(owned).theme, "late-edit");
  assert.deepEqual(f.read(f.meta), meta);
  assert.equal(currentAppProxy().appliedId, applied.id);
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

test("concurrent metadata edits after removal publication are preserved and never rolled back over", t => {
  const f = fixture(t); const applied = applyAppProxy(f.url, f.home);
  const owned = path.join(f.dir, `${applied.id}.json`);
  fs.writeFileSync(owned, JSON.stringify({ ...f.read(owned), theme: "edited" }));
  const rename = fs.renameSync; let edited = false;
  const stub = t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
    const out = rename(from, to);
    if (!edited && String(to) === f.meta) { edited = true; fs.writeFileSync(f.meta, JSON.stringify({ ...f.read(f.meta), concurrentMetadata: "keep" })); }
    return out;
  });
  try { assert.throws(() => removeAppProxy(f.url, f.home), /could not be fully rolled back/); }
  finally { stub.mock.restore(); }
  assert.equal(f.read(f.meta).concurrentMetadata, "keep");
  assert.equal(f.read(owned).theme, "edited");
  assert.equal(currentAppProxy().ours, false);
  assert.deepEqual(f.read(path.join(f.dir, `${currentAppProxy().appliedId}.json`)), { ...JSON.parse(f.originalBytes), theme: "edited" });
  assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
});

for (const changed of ["entry", "metadata"] as const) {
  test(`Desktop activation fingerprint refuses concurrent unrelated ${changed} edits`, t => {
    const f = fixture(t);
    const expected = currentAppProxy(), fingerprint = appProxyFingerprint();
    if (changed === "entry") fs.writeFileSync(f.original, JSON.stringify({ ...f.read(f.original), theme: "light" }));
    else fs.writeFileSync(f.meta, JSON.stringify({ ...f.read(f.meta), desktopSetting: { preserve: "changed" } }));
    assert.deepEqual(currentAppProxy(), expected, "the old proxy-only snapshot cannot detect this edit");
    assert.notEqual(appProxyFingerprint(), fingerprint);
    const before = f.snapshot();
    assert.throws(() => applyAppProxy(f.url, f.home, expected, {}, fingerprint), /changed during activation/);
    assert.deepEqual(f.snapshot(), before);
  });
}

for (const id of ["../outside", "..\\outside", "/outside", "C:\\outside", "_meta", "with.dot", "with:stream", "x".repeat(129)]) {
  test(`Desktop configuration refuses unsafe entry id ${JSON.stringify(id)}`, t => {
    const f = fixture(t);
    const outside = path.join(path.dirname(f.dir), "outside.json");
    const sentinel = '{"private":"outside entry must stay unread and unchanged"}\n';
    fs.writeFileSync(outside, sentinel);
    fs.writeFileSync(f.meta, JSON.stringify({ appliedId: id }));
    const read = fs.readFileSync;
    const accessed: string[] = [];
    const spy = t.mock.method(fs, "readFileSync", (...args: Parameters<typeof fs.readFileSync>) => {
      if (typeof args[0] === "string") accessed.push(path.resolve(args[0]));
      return Reflect.apply(read, fs, args);
    });
    try {
      assert.throws(() => currentAppProxy(), /could not be read/);
      assert.throws(() => appProxyFingerprint(), /id is invalid/);
      assert.throws(() => checkAppProxyActivation(f.url, f.home));
      assert.throws(() => applyAppProxy(f.url, f.home));
      assert.throws(() => removeAppProxy(f.url, f.home));
      assert.equal(accessed.includes(path.resolve(outside)), false);
    } finally { spy.mock.restore(); }
    assert.equal(fs.readFileSync(outside, "utf8"), sentinel);
    assert.deepEqual(fs.readdirSync(f.dir).sort(), ["_meta.json", "original.json"]);
    assert.deepEqual(f.read(f.meta), { appliedId: id });
  });
}

for (const timing of ["before", "after"] as const) {
  test(`metadata publication failure ${timing} atomic rename rolls back the new Desktop entry`, t => {
    const f = fixture(t);
    const before = f.read(f.meta);
    const rename = fs.renameSync;
    let failures = 0;
    const stub = t.mock.method(fs, "renameSync", (from: fs.PathLike, to: fs.PathLike) => {
      if (String(to) === f.meta && failures === 0) {
        failures++;
        if (timing === "after") rename(from, to);
        throw Object.assign(new Error("simulated metadata publish failure"), { code: "EIO" });
      }
      return rename(from, to);
    });
    try { assert.throws(() => applyAppProxy(f.url, f.home), /simulated metadata publish failure/); }
    finally { stub.mock.restore(); }
    assert.equal(failures, 1);
    assert.deepEqual(f.read(f.meta), before);
    assert.equal(fs.readFileSync(f.original, "utf8"), f.originalBytes);
    assert.deepEqual(fs.readdirSync(f.dir).sort(), ["_meta.json", "original.json"]);
    assert.equal(currentAppProxy().appliedId, "original");
  });
}
