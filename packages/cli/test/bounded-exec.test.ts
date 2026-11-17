// execBounded: the deadline fires even when the child never lets go of its pipes (#159, #162).
import test from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { execBounded, killProcessTree, type BoundedChild, type BoundedSpawn } from "../src/bounded-exec.ts";

class FakeChild extends EventEmitter {
  pid = 4242;
  stdin = new PassThrough();
  stdout = new PassThrough();
  stderr = new PassThrough();
  killed: string[] = [];
  kill(signal?: NodeJS.Signals | number): boolean { this.killed.push(String(signal)); return true; }
}

function fakeSpawner(): { spawn: BoundedSpawn; children: FakeChild[]; calls: { file: string; args: string[]; detached: unknown }[] } {
  const children: FakeChild[] = [];
  const calls: { file: string; args: string[]; detached: unknown }[] = [];
  return {
    children, calls,
    spawn: (file, args, options) => { calls.push({ file, args, detached: options.detached }); const child = new FakeChild(); children.push(child); return child as unknown as BoundedChild; },
  };
}

test("the deadline fires while the child never closes its stdio, kills the tree and rejects at once", async () => {
  const { spawn, children } = fakeSpawner();
  const killed: BoundedChild[] = [];
  const started = Date.now();
  await assert.rejects(
    execBounded("powershell.exe", ["-Command", "hang"], { timeoutMs: 40, spawn, killTree: child => killed.push(child) }),
    (error: { timedOut?: boolean; code?: unknown }) => error.timedOut === true && error.code === "ETIMEDOUT",
  );
  assert.ok(Date.now() - started < 1000, "no wait for 'close'");
  assert.deepEqual(killed, [children[0]], "the whole tree is killed once");
  assert.equal(children[0]!.stdout.destroyed, true, "the pipes are destroyed so a grandchild holding them cannot keep the loop waiting");
  assert.equal(children[0]!.stderr.destroyed, true);
});

test("on Windows a child that already exited is not killed by PID at the deadline, while its pipes are still let go", async () => {
  for (const platform of ["win32", "darwin"] as const) {
    const { spawn, children } = fakeSpawner();
    const killed: BoundedChild[] = [];
    const result = execBounded("powershell.exe", [], { timeoutMs: 40, platform, spawn, killTree: child => killed.push(child) });
    // PowerShell ended, but something it started still holds stdout: 'close' never comes.
    children[0]!.emit("exit", 0, null);
    await assert.rejects(result, (error: { timedOut?: boolean }) => error.timedOut === true);
    assert.equal(children[0]!.stdout.destroyed, true);
    // Windows can give that PID to an unrelated process; a POSIX group ID is not reused while the group lives.
    assert.equal(killed.length, platform === "win32" ? 0 : 1, platform);
  }
});

test("it settles exactly once: a close after the deadline changes nothing", async () => {
  const { spawn, children } = fakeSpawner();
  let kills = 0;
  const result = execBounded("x", [], { timeoutMs: 20, spawn, killTree: () => { kills++; } });
  await assert.rejects(result);
  children[0]!.emit("close", 0, null);
  children[0]!.emit("error", new Error("late"));
  await new Promise(resolve => setTimeout(resolve, 30));
  assert.equal(kills, 1);
});

test("a child that exits 0 resolves with its stdout and never reaches the kill", async () => {
  const { spawn, children } = fakeSpawner();
  let kills = 0;
  const result = execBounded("x", [], { timeoutMs: 5000, spawn, killTree: () => { kills++; } });
  children[0]!.stdout.write("42\n");
  children[0]!.emit("close", 0, null);
  assert.equal(await result, "42\n");
  await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(kills, 0);
});

test("a non-zero exit rejects with its code and stderr, not as a timeout", async () => {
  const { spawn, children } = fakeSpawner();
  const result = execBounded("x", [], { timeoutMs: 5000, spawn, killTree: () => {} });
  children[0]!.stderr.write("boom");
  children[0]!.emit("close", 3, null);
  await assert.rejects(result, (error: { code?: unknown; timedOut?: boolean; stderr?: string }) => error.code === 3 && !error.timedOut && error.stderr === "boom");
});

test("a spawn error and a thrown spawn both reject", async () => {
  const { spawn, children } = fakeSpawner();
  const result = execBounded("missing", [], { timeoutMs: 5000, spawn });
  children[0]!.emit("error", Object.assign(new Error("spawn missing ENOENT"), { code: "ENOENT" }));
  await assert.rejects(result, /ENOENT/);
  await assert.rejects(execBounded("x", [], { timeoutMs: 5000, spawn: () => { throw new Error("EMFILE"); } }), /EMFILE/);
});

test("output past maxBuffer ends the call and the tree", async () => {
  const { spawn, children } = fakeSpawner();
  let kills = 0;
  const result = execBounded("x", [], { timeoutMs: 5000, maxBuffer: 4, spawn, killTree: () => { kills++; } });
  children[0]!.stdout.write("too much output");
  await assert.rejects(result, /more than 4 bytes/);
  assert.equal(kills, 1);
});

test("on Windows the tree is killed with taskkill /T /F, detached, and not waited for", () => {
  const { spawn, calls } = fakeSpawner();
  const child = new FakeChild();
  killProcessTree(child as unknown as BoundedChild, "win32", spawn);
  assert.deepEqual(calls.map(c => [c.file, c.args.join(" "), c.detached]), [["taskkill", "/PID 4242 /T /F", true]]);
  assert.deepEqual(child.killed, [], "taskkill took the child with it");
});

test("on Windows a taskkill that cannot start falls back to killing the child", () => {
  const child = new FakeChild();
  const killer = new EventEmitter();
  killProcessTree(child as unknown as BoundedChild, "win32", () => killer as unknown as BoundedChild);
  killer.emit("error", new Error("ENOENT"));
  assert.deepEqual(child.killed, ["SIGKILL"]);
});

test("Windows spawns no process group, POSIX does", async () => {
  for (const [platform, detached] of [["win32", false], ["linux", true]] as const) {
    const { spawn, children, calls } = fakeSpawner();
    const result = execBounded("x", [], { timeoutMs: 5000, platform, spawn });
    children[0]!.emit("close", 0, null);
    await result;
    assert.equal(calls[0]!.detached, detached);
  }
});

// The real thing, with a real grandchild that keeps the pipes open after its parent is killed.
test("a real command whose grandchild holds the pipes is cut at the deadline", { skip: process.platform === "win32" }, async () => {
  const script = "require('child_process').spawn(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { stdio: 'inherit' }); setInterval(() => {}, 1000)";
  const started = Date.now();
  await assert.rejects(execBounded(process.execPath, ["-e", script], { timeoutMs: 400 }), (error: { timedOut?: boolean }) => error.timedOut === true);
  assert.ok(Date.now() - started < 2500);
});

test("a real command that finishes is read whole", async () => {
  const out = await execBounded(process.execPath, ["-e", "process.stdout.write('hello')"], { timeoutMs: 10_000 });
  assert.equal(out, "hello");
});

test("bounded stdin is pipe data, never argv, and all pipes close on success", async () => {
  const input = JSON.stringify({ paths: ["C:\\fixture\\quote'; $(not-code)\\secret"] });
  const child = new FakeChild();
  let received = "";
  child.stdin.on("data", chunk => { received += String(chunk); });
  const result = execBounded("trusted.exe", ["fixed-code"], {
    timeoutMs: 5000, input, spawn: (file, args, options) => {
      assert.equal(file, "trusted.exe"); assert.deepEqual(args, ["fixed-code"]);
      assert.deepEqual(options.stdio, ["pipe", "pipe", "pipe"]);
      return child;
    },
  });
  assert.equal(received, input);
  child.stdout.write("ack"); child.emit("close", 0, null);
  assert.equal(await result, "ack");
  for (const stream of [child.stdin, child.stdout, child.stderr]) assert.equal(stream.destroyed, true);
});

test("pre-cancelled or oversized stdin requests do not spawn a helper", async () => {
  const controller = new AbortController(); controller.abort("dummy-private-reason");
  let calls = 0;
  const spawn: BoundedSpawn = () => { calls++; return new FakeChild(); };
  await assert.rejects(execBounded("trusted.exe", [], { timeoutMs: 5000, signal: controller.signal, spawn }),
    (error: Error) => error.name === "AbortError" && !error.message.includes("dummy-private-reason"));
  await assert.rejects(execBounded("trusted.exe", [], { timeoutMs: 5000, input: Buffer.alloc(1024 * 1024 + 1), spawn }), /stdin exceeds/);
  assert.equal(calls, 0);
});

test("cancellation kills the helper tree and closes stdin/stdout/stderr without waiting for close", async () => {
  const controller = new AbortController(), child = new FakeChild();
  let killed = 0;
  const result = execBounded("trusted.exe", [], { timeoutMs: 5000, input: "dummy-data", signal: controller.signal,
    spawn: () => child, killTree: actual => { assert.equal(actual, child); killed++; },
  });
  controller.abort();
  await assert.rejects(result, { name: "AbortError", code: "ABORT_ERR" });
  assert.equal(killed, 1);
  for (const stream of [child.stdin, child.stdout, child.stderr]) assert.equal(stream.destroyed, true);
  child.emit("close", 0, null); child.emit("error", new Error("late helper error"));
  assert.equal(killed, 1);
});

test("an abort after Windows child exit releases pipes without killing a recycled PID", async () => {
  const controller = new AbortController(), child = new FakeChild();
  let killed = 0;
  const result = execBounded("trusted.exe", [], { timeoutMs: 5000, platform: "win32", input: "dummy-data", signal: controller.signal,
    spawn: () => child, killTree: () => { killed++; },
  });
  child.emit("exit", 0, null); controller.abort();
  await assert.rejects(result, { name: "AbortError" });
  assert.equal(killed, 0);
  for (const stream of [child.stdin, child.stdout, child.stderr]) assert.equal(stream.destroyed, true);
});

test("a real helper receives bounded stdin intact", async () => {
  const input = JSON.stringify({ files: ["dummy-one", "dummy-two"] });
  const script = "process.stdin.setEncoding('utf8');let s='';process.stdin.on('data',x=>s+=x);process.stdin.on('end',()=>process.stdout.write(String(JSON.parse(s).files.length)))";
  assert.equal(await execBounded(process.execPath, ["-e", script], { timeoutMs: 10_000, input }), "2");
});
