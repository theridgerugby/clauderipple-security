import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import https from "node:https";
import type { IncomingMessage, ServerResponse } from "node:http";
import childProcess from "node:child_process";
import { EventEmitter } from "node:events";
import { PassThrough } from "node:stream";
import { once } from "node:events";
import { syncBuiltinESMExports } from "node:module";
import { ensureAdminToken, ADMIN_TOKEN_HEADER } from "../../router/src/admin-auth.ts";
import { ensureAdminTlsIdentity, writeAdminEndpoint, adminTransportPaths } from "../../router/src/admin-transport-state.ts";
import { writePrivateFileAtomic } from "../../router/src/locked-file.ts";
import { WINDOWS_PRIVATE_ACL_BATCH_SCRIPT } from "../../router/src/windows-private-acl.ts";
import { localControlHome, readLocalControlState, readLocalControlStateAsync } from "../src/local-transport.ts";
import { controlShutdown, waitForHost } from "../src/host-service.ts";

async function fixture(t: TestContext, respond?: (request: IncomingMessage, response: ServerResponse) => void) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-control-deadline-")), home = localControlHome(dir);
  let server: https.Server | undefined;
  let cleaned = false;
  t.after(async () => {
    if (cleaned) return;
    cleaned = true;
    try {
      if (server) {
        server.closeAllConnections();
        await new Promise<void>(resolve => server!.close(() => resolve()));
      }
    } finally { fs.rmSync(dir, { recursive: true, force: true }); }
  });
  const identity = ensureAdminTlsIdentity(home), token = ensureAdminToken(home);
  const requests: string[] = [];
  server = https.createServer({ cert: identity.certPem, key: identity.keyPem }, (request, response) => {
    requests.push(`${request.method} ${request.url}`);
    assert.equal(request.headers[ADMIN_TOKEN_HEADER], token);
    assert.equal(request.headers["x-clauderipple-instance-id"], "b".repeat(32));
    response.setHeader("connection", "close");
    response.setHeader("content-type", "application/json");
    if (respond) respond(request, response);
    else response.end('{"busy":false,"version":"fixture"}');
  });
  server.listen(0, "127.0.0.1"); await once(server, "listening");
  const address = server.address(); assert.ok(address && typeof address !== "string");
  const endpoint = { version: 1 as const, instanceId: "b".repeat(32), publicPort: address.port === 8797 ? 8798 : 8797, tlsPort: address.port };
  writeAdminEndpoint(home, endpoint);
  writePrivateFileAtomic(path.join(dir, "host.json"), JSON.stringify({ port: endpoint.publicPort, token: "p".repeat(43),
    pairingSecurityVersion: 2, adminUrl: "http://127.0.0.1:8792" }));
  return { dir, home, endpoint, server, requests };
}

class FakeChild extends EventEmitter {
  pid = 424242;
  stdin = new PassThrough(); stdout = new PassThrough(); stderr = new PassThrough();
  killed = 0;
  kill(): boolean { this.killed++; return true; }
}

async function verifier<T>(t: TestContext, run: (child: FakeChild, files: string[], index: number) => void, action: (children: FakeChild[], sizes: number[]) => Promise<T>): Promise<T> {
  const platform = Object.getOwnPropertyDescriptor(process, "platform")!, previousRoot = process.env.SystemRoot;
  const children: FakeChild[] = [], sizes: number[] = [];
  const spawned = t.mock.method(childProcess, "spawn", (executable: string, args: string[]) => {
    const child = new FakeChild();
    if (executable === "taskkill") { children.at(-1)?.kill(); return child; }
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.equal(args[4], WINDOWS_PRIVATE_ACL_BATCH_SCRIPT);
    children.push(child);
    let input = "";
    child.stdin.on("data", chunk => { input += String(chunk); });
    child.stdin.on("end", () => {
      const files = (JSON.parse(input) as { files: string[] }).files;
      sizes.push(files.length); run(child, files, sizes.length);
    });
    return child;
  });
  const sync = t.mock.method(childProcess, "spawnSync", () => { throw new Error("lifecycle requests must not perform synchronous permission work"); });
  syncBuiltinESMExports();
  try {
    Object.defineProperty(process, "platform", { ...platform, value: "win32" }); process.env.SystemRoot = "C:\\Windows";
    return await action(children, sizes);
  } finally {
    Object.defineProperty(process, "platform", platform);
    if (previousRoot === undefined) delete process.env.SystemRoot; else process.env.SystemRoot = previousRoot;
    spawned.mock.restore(); sync.mock.restore(); syncBuiltinESMExports();
  }
}
function accept(child: FakeChild): void { child.stdout.write("private-acl-batch-verified"); child.emit("close", 0, null); }

test("slow asynchronous permission validation leaves the complete 500ms network poll budget", async t => {
  const f = await fixture(t);
  const timers: NodeJS.Timeout[] = [];
  t.after(() => { for (const timer of timers) clearTimeout(timer); });
  let heartbeats = 0;
  const heartbeat = setInterval(() => heartbeats++, 25);
  try {
    await verifier(t, child => { timers.push(setTimeout(() => accept(child), 650)); }, async (_children, sizes) => {
      const started = performance.now();
      await waitForHost(f.dir, { timeoutMs: 5000 });
      assert.ok(performance.now() - started >= 600);
      assert.deepEqual(sizes, [4], "one fresh four-file batch is the complete first attempt");
      assert.deepEqual(f.requests, ["GET /api/local/status"]);
      assert.ok(heartbeats > 1, "permission verification must leave the event loop responsive");
    });
  } finally { clearInterval(heartbeat); }
});

test("the whole lifecycle deadline aborts a hung verifier without sending a network request", async t => {
  const f = await fixture(t);
  await verifier(t, () => {}, async (children, sizes) => {
    const started = performance.now();
    await assert.rejects(waitForHost(f.dir, { timeoutMs: 100 }), { name: "TimeoutError", code: "HOST_CONTROL_TIMEOUT" });
    assert.ok(performance.now() - started < 2000);
    assert.deepEqual(sizes, [4]); assert.equal(children[0]!.killed, 1);
    for (const stream of [children[0]!.stdin, children[0]!.stdout, children[0]!.stderr]) assert.equal(stream.destroyed, true);
    assert.deepEqual(f.requests, []);
  });
});

test("shutdown verifies once for status and freshly refuses an exposed ACL before POST", async t => {
  const f = await fixture(t);
  await verifier(t, (child, _files, index) => {
    if (index === 1) accept(child);
    else { child.stderr.write("untrusted diagnostics must not escape"); child.emit("close", 1, null); }
  }, async (_children, sizes) => {
    await assert.rejects(controlShutdown(f.dir), error => error instanceof Error && /Cannot verify/.test(error.message) && !error.message.includes("untrusted"));
    assert.deepEqual(sizes, [4, 4]);
    assert.deepEqual(f.requests, ["GET /api/local/status"]);
  });
});

test("an atomic endpoint replacement after status cannot receive shutdown", async t => {
  let change!: () => void;
  const f = await fixture(t, (_request, response) => { change(); response.end('{"busy":false}'); });
  change = () => {
    // This fixture mutation acts as a new legitimate owner generation between two attempts.
    const file = adminTransportPaths(f.home).endpoint;
    fs.writeFileSync(file, JSON.stringify({ ...f.endpoint, instanceId: "c".repeat(32) }));
  };
  await verifier(t, accept, async (_children, sizes) => {
    await assert.rejects(controlShutdown(f.dir), /instance changed/);
    assert.deepEqual(sizes, [4, 4]);
    assert.deepEqual(f.requests, ["GET /api/local/status"]);
  });
});

test("a refused connection cannot become a stop receipt when final verification exceeds the whole deadline", async t => {
  const f = await fixture(t);
  await new Promise<void>(resolve => f.server.close(() => resolve()));
  // Fake helper streams do not keep Node alive like a real process. Retain one ref while
  // testing the otherwise-unref'd whole-operation deadline with every listener closed.
  const keepAlive = setInterval(() => {}, 1000);
  t.after(() => clearInterval(keepAlive));
  await verifier(t, (child, _files, index) => { if (index === 1) accept(child); }, async (children, sizes) => {
    await assert.rejects(controlShutdown(f.dir, { timeoutMs: 150 }), { name: "AbortError", code: "PRIVATE_STORAGE_ABORTED" });
    assert.deepEqual(sizes, [4, 1], "the refusal branch still performs fresh protected receipt validation");
    assert.equal(children[1]!.killed, 1);
    assert.deepEqual(f.requests, []);
  });
});

test("async state parsing matches existing legacy and v2 configuration rules without applying defaults to disk", async t => {
  const f = await fixture(t), file = path.join(f.dir, "host.json");
  for (const record of [
    { port: f.endpoint.publicPort, token: "legacy-dummy-token-".repeat(3), adminUrl: "http://127.0.0.1:8792" },
    { port: f.endpoint.publicPort, token: "p".repeat(43), pairingSecurityVersion: 2, adminUrl: "http://127.0.0.1:8792" },
  ]) {
    writePrivateFileAtomic(file, JSON.stringify(record));
    const before = fs.readFileSync(file);
    assert.deepEqual(await readLocalControlStateAsync(f.dir), readLocalControlState(f.dir));
    assert.deepEqual(fs.readFileSync(file), before);
  }
  for (const record of [{ pairingSecurityVersion: 3 }, { pairingSecurityVersion: 2, token: "invalid" }]) {
    writePrivateFileAtomic(file, JSON.stringify(record));
    assert.throws(() => readLocalControlState(f.dir), /invalid/);
    await assert.rejects(readLocalControlStateAsync(f.dir), /invalid/);
  }
});
