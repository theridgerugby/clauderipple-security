import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import { spawn } from "node:child_process";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { execBounded, type BoundedChild, type BoundedSpawn } from "../src/bounded-exec.ts";

const require = createRequire(import.meta.url);
const { diagnosticTreeScript, processIsRunning } = require("../test-native/diagnostic-tree.cjs") as {
  diagnosticTreeScript: string; processIsRunning: (pid: number) => boolean;
};

test("the app diagnostic runner is byte-identical to the reviewed CLI process-tree helper", () => {
  assert.equal(fs.readFileSync(new URL("../src/bounded-exec.ts", import.meta.url), "utf8"),
    fs.readFileSync(new URL("../../cli/src/bounded-exec.ts", import.meta.url), "utf8"));
});

test("diagnostic success returns only stdout and keeps stderr out of JSON", async () => {
  const script = "process.stderr.write('synthetic-private-warning');process.stdout.write(JSON.stringify({ok:true}))";
  const stdout = await execBounded(process.execPath, ["-e", script], { timeoutMs: 5000, maxBuffer: 1024 * 1024 });
  assert.deepEqual(JSON.parse(stdout), { ok: true });
});

test("app cancellation refuses Windows taskkill after the direct child exits and releases its held pipes", async () => {
  const child = Object.assign(new EventEmitter(), {
    pid: 4242, stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill: () => true,
  });
  const abort = new AbortController();
  let killed = 0;
  const output = execBounded("owned-diagnostic", [], {
    timeoutMs: 5000, signal: abort.signal, platform: "win32",
    spawn: () => child as BoundedChild, killTree: () => { killed++; },
  });
  child.emit("exit", 0, null);
  abort.abort();
  await assert.rejects(output, { name: "AbortError", code: "ABORT_ERR" });
  assert.equal(killed, 0, "an exited child's PID can have been reassigned to an unrelated process");
  for (const pipe of [child.stdin, child.stdout, child.stderr]) assert.equal(pipe.destroyed, true);
});

test("closing an active diagnostic ends its actual child and grandchild, not just the parent", { timeout: 20000 }, async () => {
  const abort = new AbortController();
  let resolveReady!: (pids: { root: number; descendant: number }) => void;
  const ready = new Promise<{ root: number; descendant: number }>(resolve => { resolveReady = resolve; });
  let buffer = "", ownedRoot = 0;
  const fixtureSpawn: BoundedSpawn = (file, args, options) => {
    if (file === process.execPath) {
      assert.deepEqual(args, ["-e", diagnosticTreeScript]);
    } else {
      assert.equal(process.platform, "win32");
      assert.equal(file, "taskkill");
      assert.deepEqual(args, ["/PID", String(ownedRoot), "/T", "/F"], "cleanup targets only the diagnostic we spawned");
    }
    const child = spawn(file, args, options);
    if (file === process.execPath) {
      ownedRoot = child.pid!;
      child.stdout!.on("data", chunk => {
        buffer += String(chunk);
        if (buffer.includes("\n")) resolveReady(JSON.parse(buffer.split("\n")[0]!));
      });
    }
    return child;
  };
  const output = execBounded(process.execPath, ["-e", diagnosticTreeScript], {
    timeoutMs: 10000, signal: abort.signal, maxBuffer: 1024 * 1024, spawn: fixtureSpawn,
  }).then(() => null, error => error as Error & { code?: string });
  let readinessTimer: NodeJS.Timeout | undefined;
  try {
    const pids = await Promise.race([ready, new Promise<never>((_resolve, reject) => {
      readinessTimer = setTimeout(() => reject(new Error("Diagnostic fixture did not become ready")), 8000);
    })]);
    clearTimeout(readinessTimer);
    assert.equal(pids.root, ownedRoot);
    assert.notEqual(pids.root, pids.descendant);
    assert.equal(processIsRunning(pids.root), true);
    assert.equal(processIsRunning(pids.descendant), true);
    abort.abort();
    assert.equal((await output)?.code, "ABORT_ERR");
    const deadline = Date.now() + 5000;
    while (Object.values(pids).some(processIsRunning) && Date.now() < deadline) {
      await new Promise(resolve => setTimeout(resolve, 25));
    }
    assert.equal(processIsRunning(pids.root), false);
    assert.equal(processIsRunning(pids.descendant), false);
  } finally {
    clearTimeout(readinessTimer);
    abort.abort();
    await output;
  }
});
