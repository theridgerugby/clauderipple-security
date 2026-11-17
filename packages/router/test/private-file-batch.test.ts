import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { syncBuiltinESMExports } from "node:module";
import { readPrivateFilesStrict, type PrivateFileRead } from "../src/private-file.ts";
import { writePrivateFileAtomic } from "../src/locked-file.ts";
import { verifyWindowsPrivateFiles, WINDOWS_PRIVATE_ACL_BATCH_SCRIPT } from "../src/windows-private-acl.ts";

function fixture(t: TestContext): PrivateFileRead[] {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-private-batch-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  return Array.from({ length: 4 }, (_, index) => {
    const file = path.join(home, `dummy-${index}`);
    writePrivateFileAtomic(file, `dummy-value-${index}`);
    return { file, maxBytes: 128 };
  });
}

class FakeChild extends EventEmitter {
  pid = 424242;
  stdin = new PassThrough();
  stdout = new PassThrough();
  stderr = new PassThrough();
  killed = 0;
  kill(): boolean { this.killed++; return true; }
}

async function windowsBatch<T>(t: TestContext, onRun: (child: FakeChild, input: { files: string[] }) => void, action: (children: FakeChild[], kills: string[][]) => Promise<T>): Promise<T> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!;
  const previousRoot = process.env.SystemRoot;
  const children: FakeChild[] = [], kills: string[][] = [];
  const spawned = t.mock.method(childProcess, "spawn", (file: string, args: string[], options: { stdio: unknown }) => {
    const child = new FakeChild();
    if (file === "taskkill") {
      kills.push(args); children.at(-1)?.kill();
      return child;
    }
    assert.equal(file, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_BATCH_SCRIPT]);
    assert.deepEqual(options.stdio, ["pipe", "pipe", "pipe"]);
    children.push(child);
    let input = "";
    child.stdin.on("data", chunk => { input += String(chunk); });
    child.stdin.on("end", () => onRun(child, JSON.parse(input) as { files: string[] }));
    return child;
  });
  const synchronous = t.mock.method(childProcess, "spawnSync", () => { throw new Error("async batches must never invoke synchronous ACL repair"); });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...platform, value: "win32" });
    process.env.SystemRoot = "C:\\Windows";
    return await action(children, kills);
  } finally {
    Object.defineProperty(process, "platform", platform);
    if (previousRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = previousRoot;
    spawned.mock.restore(); synchronous.mock.restore(); syncBuiltinESMExports();
  }
}

function observeDescriptors(t: TestContext, files: PrivateFileRead[]) {
  const names = new Set(files.map(item => item.file)), descriptors: number[] = [];
  const original = fs.openSync;
  t.mock.method(fs, "openSync", (...args: Parameters<typeof fs.openSync>) => {
    const fd = original(...args);
    if (names.has(String(args[0])) && typeof args[1] === "number" && (args[1] & (fs.constants.O_WRONLY | fs.constants.O_RDWR)) === 0) descriptors.push(fd);
    return fd;
  });
  return () => {
    assert.equal(descriptors.length, files.length);
    for (const fd of descriptors) assert.throws(() => fs.fstatSync(fd), { code: "EBADF" });
  };
}

test("Windows batch verifier uses one fixed program, bounded path-only stdin and exact acknowledgement", async () => {
  const files = ["C:\\private\\quote'; $(not-code)\\state", "C:\\private\\second"];
  let calls = 0;
  await verifyWindowsPrivateFiles(files, async (executable, args, options) => {
    calls++;
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_PRIVATE_ACL_BATCH_SCRIPT]);
    assert.deepEqual(JSON.parse(options.input), { files });
    assert.equal(options.timeoutMs, 10_000); assert.equal(options.maxBuffer, 16 * 1024);
    assert.ok(args.every(value => files.every(file => !value.includes(file))));
    return "private-acl-batch-verified";
  }, {}, "C:\\Windows");
  assert.equal(calls, 1);
  assert.doesNotMatch(WINDOWS_PRIVATE_ACL_BATCH_SCRIPT, /SetAccessControl|SetOwner/);
  for (const output of ["", "private-acl-batch-verified\n", "private-acl-verified", "private-acl-batch-ver"]) {
    await assert.rejects(verifyWindowsPrivateFiles(files, async () => output, {}, "C:\\Windows"), /Cannot verify/);
  }
  await assert.rejects(verifyWindowsPrivateFiles(files, async () => { throw new Error("sensitive helper output"); }, {}, "C:\\Windows"),
    error => error instanceof Error && !error.message.includes("sensitive"));
});

test("a four-file strict snapshot verifies once per attempt and never repairs or caches", async t => {
  const files = fixture(t);
  await windowsBatch(t, (child, input) => {
    assert.deepEqual(input.files, files.map(file => file.file));
    child.stdout.write("private-acl-batch-verified"); child.emit("close", 0, null);
  }, async children => {
    for (let iteration = 0; iteration < 2; iteration++) {
      assert.deepEqual((await readPrivateFilesStrict(files)).map(value => value.toString()), files.map((_, index) => `dummy-value-${index}`));
      assert.equal(children.length, iteration + 1);
    }
  });
});

test("a partial batch response returns no bytes and closes every opened descriptor", async t => {
  const files = fixture(t), assertClosed = observeDescriptors(t, files);
  let reads = 0;
  t.mock.method(fs, "readSync", () => { reads++; throw new Error("unverified bytes must not be consumed"); });
  await windowsBatch(t, child => { child.stdout.write("private-acl-batch-ver"); child.emit("close", 0, null); }, async () => {
    await assert.rejects(readPrivateFilesStrict(files), /Cannot verify/);
  });
  assert.equal(reads, 0); assertClosed();
});

test("cancellation kills a hung verifier and closes all pipes and file descriptors without waiting for close", async t => {
  const files = fixture(t), assertClosed = observeDescriptors(t, files), controller = new AbortController();
  let reads = 0;
  t.mock.method(fs, "readSync", () => { reads++; throw new Error("cancelled bytes must not be consumed"); });
  await windowsBatch(t, () => { controller.abort(); }, async (children, kills) => {
    await assert.rejects(readPrivateFilesStrict(files, { signal: controller.signal }), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
    assert.equal(children.length, 1); assert.equal(children[0]!.killed, 1);
    assert.deepEqual(kills, [["/PID", "424242", "/T", "/F"]]);
    for (const stream of [children[0]!.stdin, children[0]!.stdout, children[0]!.stderr]) assert.equal(stream.destroyed, true);
  });
  assert.equal(reads, 0); assertClosed();
});

test("replacing any file during batch verification prevents every credential read", async t => {
  const files = fixture(t), assertClosed = observeDescriptors(t, files);
  let reads = 0;
  t.mock.method(fs, "readSync", () => { reads++; throw new Error("exchanged bytes must not be consumed"); });
  await windowsBatch(t, child => {
    const file = files[0]!.file;
    fs.renameSync(file, file + ".old"); fs.writeFileSync(file, "dummy-replacement", { mode: 0o600 });
    child.stdout.write("private-acl-batch-verified"); child.emit("close", 0, null);
  }, async () => { await assert.rejects(readPrivateFilesStrict(files), /changed while reading or verifying/); });
  assert.equal(reads, 0); assertClosed();
});

test("the final whole-batch identity check catches a previous file changing during a later read", async t => {
  const files = fixture(t), read = fs.readSync;
  let reads = 0;
  t.mock.method(fs, "readSync", (...args: Parameters<typeof fs.readSync>) => {
    const count = read(...args);
    if (count > 0 && ++reads === 4) fs.utimesSync(files[0]!.file, new Date(), new Date(Date.now() + 5000));
    return count;
  });
  await windowsBatch(t, child => { child.stdout.write("private-acl-batch-verified"); child.emit("close", 0, null); }, async () => {
    await assert.rejects(readPrivateFilesStrict(files), /changed while reading or verifying/);
  });
  assert.equal(reads, 4);
});

test("strict batch bounds are checked before opening files", async t => {
  let opens = 0;
  t.mock.method(fs, "openSync", () => { opens++; throw new Error("invalid batches must not open files"); });
  for (const files of [[], Array.from({ length: 17 }, (_, i) => ({ file: String(i), maxBytes: 1 })),
    [{ file: "one", maxBytes: 8 * 1024 * 1024 + 1 }], [{ file: "one", maxBytes: 1 }, { file: "one", maxBytes: 1 }]]) {
    await assert.rejects(readPrivateFilesStrict(files), /batch/);
  }
  assert.equal(opens, 0);
});

test("native Windows verifies all four private files in one uncached process", { skip: process.platform !== "win32" }, async t => {
  const files = fixture(t), spawn = childProcess.spawn;
  let helpers = 0;
  const mocked = t.mock.method(childProcess, "spawn", (...args: Parameters<typeof childProcess.spawn>) => {
    helpers++; return spawn(...args);
  });
  syncBuiltinESMExports();
  try {
    const started = performance.now();
    assert.deepEqual((await readPrivateFilesStrict(files)).map(value => value.toString()), files.map((_, index) => `dummy-value-${index}`));
    assert.equal(helpers, 1);
    t.diagnostic(`native Windows ACL batch: files=4 processes=${helpers} elapsed_ms=${Math.round(performance.now() - started)}`);
  } finally { mocked.mock.restore(); syncBuiltinESMExports(); }
});
