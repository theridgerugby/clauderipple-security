import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawn } from "node:child_process";
import { once } from "node:events";
import { createInterface } from "node:readline";
import { DEFAULTS, type Config } from "../src/config.ts";
import { syncAgentFiles } from "../src/agents.ts";

function fixture(t: TestContext) {
  const shared = fs.mkdtempSync(path.join(os.tmpdir(), "cr-agent-lock-"));
  t.after(() => fs.rmSync(shared, { recursive: true, force: true }));
  t.mock.method(os, "tmpdir", () => shared);
  const user = typeof process.getuid === "function" ? `uid-${process.getuid()}`
    : crypto.createHash("sha256").update(os.homedir()).digest("hex").slice(0, 16);
  const locks = path.join(shared, `clauderipple-agent-locks-${user}`);
  const dir = path.join(shared, "agents");
  const manifestPath = path.join(shared, "manifest.json");
  const config = (model: string): Config => ({ ...DEFAULTS, providers: {
    p: { type: "anthropic-compatible", url: "http://127.0.0.1:9", models: [{ id: model }] },
  }, routes: {}, aliases: {}, direct: [] });
  const warnings: string[] = [];
  const sync = (model: string) => syncAgentFiles(config(model), dir, { warn: message => { warnings.push(message); } }, { manifestPath });
  return { shared, locks, dir, manifestPath, warnings, sync };
}

test("agent generation owns a private child without requiring ownership of the shared POSIX temp directory", { skip: process.platform === "win32" }, t => {
  const f = fixture(t);
  const before = fs.statSync(f.shared);
  const stat = fs.lstatSync;
  t.mock.method(fs, "lstatSync", (file: fs.PathLike, ...args: unknown[]) => {
    const result = Reflect.apply(stat, fs, [file, ...args]) as fs.Stats;
    if (path.resolve(String(file)) === f.shared) {
      // Ubuntu Actions normally has root-owned /tmp while the runner is unprivileged.
      result.uid = process.getuid!() === 0 ? 1 : 0;
      result.mode = (result.mode & ~0o7777) | 0o1777;
    }
    return result;
  });
  assert.deepEqual(f.sync("model-a"), [path.join(f.dir, "model-a.md")]);
  assert.deepEqual(f.warnings, []);
  const privateDir = fs.statSync(f.locks);
  assert.equal(privateDir.uid, process.getuid!());
  assert.equal(privateDir.mode & 0o777, 0o700);
  const after = fs.statSync(f.shared);
  assert.equal(after.uid, before.uid);
  assert.equal(after.mode, before.mode, "the shared parent is not chmod/chowned");
});

test("a foreign-owned private lock directory still fails closed", { skip: process.platform === "win32" }, t => {
  const f = fixture(t);
  fs.mkdirSync(f.locks, { mode: 0o700 });
  const stat = fs.lstatSync;
  t.mock.method(fs, "lstatSync", (file: fs.PathLike, ...args: unknown[]) => {
    const result = Reflect.apply(stat, fs, [file, ...args]) as fs.Stats;
    if (path.resolve(String(file)) === f.locks) result.uid = process.getuid!() === 0 ? 1 : 0;
    return result;
  });
  assert.deepEqual(f.sync("model-a"), []);
  assert.equal(fs.existsSync(path.join(f.dir, "model-a.md")), false);
  assert.ok(f.warnings.some(message => message.includes("must belong to the current user")));
});

test("a symbolic-link private lock directory is never followed", { skip: process.platform === "win32" }, t => {
  const f = fixture(t);
  const target = path.join(f.shared, "unrelated");
  fs.mkdirSync(target, { mode: 0o700 });
  fs.symlinkSync(target, f.locks);
  assert.deepEqual(f.sync("model-a"), []);
  assert.equal(fs.existsSync(path.join(f.dir, "model-a.md")), false);
  assert.deepEqual(fs.readdirSync(target), []);
  assert.ok(f.warnings.some(message => message.includes("must be a real directory")));
});

test("the deterministic private agent lock excludes another same-user process until release", { timeout: 40_000 }, async t => {
  const f = fixture(t);
  assert.equal(f.sync("first-model").length, 1);
  const key = crypto.createHash("sha256").update(path.resolve(f.dir)).digest("hex").slice(0, 16);
  const lock = path.join(f.locks, `agents-${key}`);
  const release = path.join(f.shared, "release-child");
  const child = spawn(process.execPath, ["--input-type=module", "-e", `
    import fs from 'node:fs';
    import { withFileLock } from ${JSON.stringify(new URL("../src/locked-file.ts", import.meta.url).href)};
    const [lock, release] = process.argv.slice(1);
    withFileLock(lock, () => {
      fs.writeSync(1, 'locked\\n');
      const deadline = Date.now() + 30_000;
      while (!fs.existsSync(release)) {
        if (Date.now() >= deadline) throw new Error('fixture lock release timed out');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 20);
      }
    });
  `, lock, release], { stdio: ["ignore", "pipe", "pipe"] });
  const lines = createInterface({ input: child.stdout });
  let stderr = "";
  child.stderr.setEncoding("utf8"); child.stderr.on("data", chunk => { stderr += chunk; });
  child.on("error", error => { stderr += error.message; });
  const exited = new Promise<number | null>(resolve => { child.once("close", code => { resolve(code); }); });
  t.after(async () => {
    lines.close();
    if (child.exitCode === null && child.signalCode === null) child.kill();
    await exited;
  });
  assert.equal((await once(lines, "line", { signal: AbortSignal.timeout(20_000) }))[0], "locked");
  assert.deepEqual(f.sync("second-model"), [], "a competing process cannot enter the agent mutation");
  assert.ok(f.warnings.some(message => message.includes("already being held")), stderr);
  assert.ok(fs.existsSync(path.join(f.dir, "first-model.md")));
  assert.equal(fs.existsSync(path.join(f.dir, "second-model.md")), false);
  fs.writeFileSync(release, "release");
  assert.equal(await exited, 0, stderr);
  assert.equal(f.sync("second-model").length, 1, "the same lock becomes usable after release");
  assert.ok(fs.existsSync(path.join(f.dir, "second-model.md")));
});
