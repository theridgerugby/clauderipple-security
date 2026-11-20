import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileSymlinks } from "../../../test/capabilities.ts";
import { captureRouterCodeIdentity, sameRouterCodeIdentity, verifyAndApplyInstall, type InstallRuntimeDeps, type InstallRuntimeTarget } from "../src/install-runtime.ts";

function fixture(t: TestContext) {
  const repo = fs.mkdtempSync(path.join(os.tmpdir(), "cr-install-code-"));
  t.after(() => fs.rmSync(repo, { recursive: true, force: true }));
  const write = (relative: string, text: string) => {
    const file = path.join(repo, relative);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text);
    return file;
  };
  write("package.json", '{"name":"clauderipple","version":"0.12.36"}');
  write("package-lock.json", '{"lockfileVersion":3}');
  const cli = write("packages/cli/src/index.ts", "export const cli = 1;\n");
  const router = write("packages/router/src/index.ts", "export const router = 1;\n");
  const rt = { repo, cli, router, node: process.execPath };
  const target: InstallRuntimeTarget = { version: "0.12.36", node: rt.node, router, codeIdentity: captureRouterCodeIdentity(rt),
    listen: { host: "127.0.0.1", port: 8791 }, upstream: "api.anthropic.com" };
  const installId = "a".repeat(32);
  const status = () => ({ version: target.version, installId, pid: 42, listen: { ...target.listen }, upstream: target.upstream,
    runtime: { node: rt.node, router, startedAt: "2026-11-17T00:00:00.000Z", codeIdentity: target.codeIdentity } });
  return { repo, write, rt, target, installId, status };
}

test("runtime fingerprint is immutable, location-independent and changes with same-version code", t => {
  const one = fixture(t), two = fixture(t);
  const original = one.target.codeIdentity;
  assert.equal(Object.isFrozen(original), true);
  assert.deepEqual(captureRouterCodeIdentity(one.rt), captureRouterCodeIdentity(two.rt));
  one.write("README.md", "documentation does not execute in the router\n");
  assert.deepEqual(captureRouterCodeIdentity(one.rt), original);
  one.write("packages/router/src/index.ts", "export const router = 2;\n");
  assert.equal(sameRouterCodeIdentity(captureRouterCodeIdentity(one.rt), original), false);
  assert.equal(JSON.parse(fs.readFileSync(path.join(one.repo, "package.json"), "utf8")).version, "0.12.36");
});

test("fingerprint covers imported helpers, frontend runtime and dependency manifest", t => {
  const f = fixture(t);
  let before = captureRouterCodeIdentity(f.rt);
  for (const relative of ["packages/remote/src/shared.ts", "packages/mod/hooks/settings.ts", "packages/ui/app.js", "packages/app/dist/main.js", "package-lock.json"]) {
    f.write(relative, "changed runtime bytes\n");
    const after = captureRouterCodeIdentity(f.rt);
    assert.equal(sameRouterCodeIdentity(before, after), false, relative);
    before = after;
  }
});

test("fingerprint rejects malformed identity, foreign entry layout and hard-linked code", t => {
  const f = fixture(t);
  for (const identity of [null, {}, { schema: 1, sha256: "a" }, { schema: 2, sha256: "a".repeat(64) }]) {
    assert.equal(sameRouterCodeIdentity(identity, f.target.codeIdentity), false);
  }
  assert.throws(() => captureRouterCodeIdentity({ ...f.rt, router: f.rt.cli }), /layout/);
  fs.linkSync(f.rt.router, path.join(f.repo, "linked-router.ts"));
  assert.throws(() => captureRouterCodeIdentity(f.rt), /aliased/);
});

test("fingerprint rejects runtime file symlinks", { skip: !fileSymlinks }, t => {
  const f = fixture(t);
  const target = f.write("fixture.ts", "test\n");
  fs.symlinkSync(target, path.join(f.repo, "packages/router/src/import.ts"), "file");
  assert.throws(() => captureRouterCodeIdentity(f.rt), /alias/);
});

test("fingerprint binds the opened descriptor to the file observed before open, including same-size Windows replacements", t => {
  const f = fixture(t);
  const open = fs.openSync;
  const expectedPath = fs.realpathSync.native(f.rt.router).toLowerCase();
  let swapped = false;
  t.mock.method(fs, "openSync", (file: fs.PathLike, flags: string | number, mode?: fs.Mode) => {
    if (!swapped && typeof file === "string" && fs.realpathSync.native(file).toLowerCase() === expectedPath) {
      swapped = true;
      fs.renameSync(f.rt.router, f.rt.router + ".old");
      fs.writeFileSync(f.rt.router, "export const router = 9;\n");
    }
    return open(file, flags, mode);
  });
  let failure: unknown;
  try { captureRouterCodeIdentity(f.rt); } catch (error) { failure = error; }
  assert.equal(swapped, true, "the fixture must swap the router file before it is opened");
  assert.match(String(failure), /changed/);
});

function controlled(t: TestContext) {
  const f = fixture(t);
  const calls: string[] = [];
  let current: unknown = f.status();
  let tick = 0;
  const deps: InstallRuntimeDeps = {
    status: async () => { calls.push("status"); return current; },
    installationId: () => f.installId,
    restart: () => { calls.push("restart"); return "drained"; },
    captureIdentity: () => { calls.push("capture"); return captureRouterCodeIdentity(f.rt); },
    now: () => tick,
    sleep: async ms => { tick += ms; },
  };
  const options = {
    started: "already-running" as const, target: f.target, deps, readinessMs: 500,
    probe: async () => { calls.push("probe"); return { ok: true, detail: "dummy upstream", ms: 1 }; },
    apply: () => { calls.push("apply"); return "applied"; },
  };
  return { ...f, deps, calls, options, setStatus(value: unknown) { current = value; } };
}

test("settings apply only after authenticated identity, proxy probe and same-instance revalidation", async t => {
  const f = controlled(t);
  assert.equal(await verifyAndApplyInstall(f.options), "applied");
  assert.deepEqual(f.calls, ["status", "probe", "status", "capture", "apply"]);
});

test("failed or foreign supervisor outcomes cannot be rescued by an old working proxy", async t => {
  for (const started of ["failed", "other-installation", "ownership-unknown"] as const) {
    const f = controlled(t);
    await assert.rejects(verifyAndApplyInstall({ ...f.options, started }), /did not start/);
    assert.deepEqual(f.calls, []);
  }
});

test("a legacy HTTP-only router cannot reach restart, proxy probe or client mutation", async t => {
  for (const mode of ["null", "throw"]) {
    const f = controlled(t);
    f.deps.status = async () => { f.calls.push("status"); if (mode === "throw") throw new Error("secure state absent"); return null; };
    await assert.rejects(verifyAndApplyInstall(f.options), /Secure router identity is unavailable/);
    assert.deepEqual(f.calls, ["status"]);
  }
});

test("same-version changed code requires a verified restart before any client settings", async t => {
  const f = controlled(t);
  const old = f.status();
  f.write("packages/router/src/index.ts", "export const router = 2;\n");
  f.target.codeIdentity = captureRouterCodeIdentity(f.rt);
  f.setStatus(old);
  f.deps.restart = () => {
    f.calls.push("restart");
    const fresh = f.status(); fresh.pid = 43; fresh.runtime.startedAt = "2026-11-17T00:00:01.000Z";
    f.setStatus(fresh);
    return "drained";
  };
  assert.equal(await verifyAndApplyInstall(f.options), "applied");
  assert.deepEqual(f.calls, ["status", "restart", "status", "probe", "status", "capture", "apply"]);
});

test("an authenticated pre-fingerprint router can drain, but its successor must carry the current identity", async t => {
  const f = controlled(t), old = f.status();
  f.setStatus({ ...old, runtime: { ...old.runtime, codeIdentity: null } });
  f.deps.restart = () => {
    f.calls.push("restart");
    f.setStatus({ ...f.status(), pid: 43 });
    return "drained";
  };
  assert.equal(await verifyAndApplyInstall(f.options), "applied");
  assert.equal(f.calls.filter(call => call === "restart").length, 1);
});

test("every refused restart preserves client settings", async t => {
  for (const result of ["failed", "other-installation", "ownership-unknown", "identity-unknown"] as const) {
    const f = controlled(t), old = f.status();
    f.setStatus({ ...old, runtime: { ...old.runtime, codeIdentity: null } });
    f.deps.restart = () => { f.calls.push("restart"); return result; };
    await assert.rejects(verifyAndApplyInstall(f.options), /could not be switched/);
    assert.deepEqual(f.calls, ["status", "restart"]);
  }
});

test("a restart receipt cannot certify unchanged code or the same still-running instance", async t => {
  for (const outcome of ["old-code", "same-instance", "changed-installation"]) {
    const f = controlled(t), old = f.status();
    f.setStatus({ ...old, runtime: { ...old.runtime, codeIdentity: null } });
    f.deps.restart = () => {
      f.calls.push("restart");
      if (outcome === "same-instance") f.setStatus(f.status());
      if (outcome === "changed-installation") {
        f.deps.installationId = () => "b".repeat(32);
        f.setStatus({ ...f.status(), installId: "b".repeat(32), pid: 43 });
      }
      return "drained";
    };
    await assert.rejects(verifyAndApplyInstall(f.options), /expected code|newly verified instance/);
    assert.equal(f.calls.includes("probe"), false, outcome);
    assert.equal(f.calls.includes("apply"), false, outcome);
  }
});

test("unverifiable installation and process identity never authorizes a restart", async t => {
  for (const change of [{ installId: "b".repeat(32) }, { pid: null }, { pid: -1 }, { runtime: {} }]) {
    const f = controlled(t);
    f.setStatus({ ...f.status(), ...change });
    await assert.rejects(verifyAndApplyInstall(f.options), /could not be verified/);
    assert.deepEqual(f.calls, ["status"]);
  }
});

test("startup waits are bounded and never fall back to unauthenticated status", async t => {
  const f = controlled(t);
  let reads = 0;
  f.deps.status = async () => { f.calls.push("status"); return ++reads < 2 ? null : f.status(); };
  assert.equal(await verifyAndApplyInstall({ ...f.options, started: "started" }), "applied");
  assert.equal(reads, 3);
  const absent = controlled(t); absent.setStatus(null);
  await assert.rejects(verifyAndApplyInstall({ ...absent.options, started: "started" }), /Secure router identity is unavailable/);
  assert.ok(absent.calls.length <= 4);
  assert.equal(absent.calls.includes("apply"), false);
});

test("failed proxy, racing process, runtime route change or changed source never apply settings", async t => {
  for (const outcome of ["probe", "pid", "start-time", "code", "port", "source-during-final-status"]) {
    const f = controlled(t);
    f.options.probe = async () => {
      f.calls.push("probe");
      const next = f.status();
      if (outcome === "pid") next.pid++;
      if (outcome === "start-time") next.runtime.startedAt = "2026-11-17T00:00:01.000Z";
      if (outcome === "code") next.runtime.codeIdentity = { schema: 1, sha256: "b".repeat(64) };
      if (outcome === "port") next.listen.port++;
      f.setStatus(next);
      if (outcome === "source-during-final-status") f.deps.status = async () => {
        f.calls.push("status"); f.write("packages/router/src/index.ts", "changed after the probe\n"); return next;
      };
      return { ok: outcome !== "probe", detail: "dummy upstream", ms: 1 };
    };
    await assert.rejects(verifyAndApplyInstall(f.options), /probe failed|instance changed|expected code|files changed/, outcome);
    assert.equal(f.calls.includes("apply"), false, outcome);
  }
});
