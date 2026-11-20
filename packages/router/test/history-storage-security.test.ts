import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RequestLog, type RequestRecord } from "../src/requestlog.ts";
import { UsageHistory } from "../src/usage-history.ts";

const row: RequestRecord = {
  id: "dummy", at: "2026-11-16T12:00:00.000Z", ms: 1, status: 200, ok: true,
  kind: "messages", source: "dummy", target: "dummy", provider: "dummy", stream: false,
};

test("history startup refuses aliased active, rotated and aggregate files", { skip: process.platform === "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-history-read-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const unrelated = path.join(home, "unrelated");
  const file = path.join(home, "requests.jsonl");
  const aggregate = path.join(home, "usage-hourly.jsonl");
  fs.writeFileSync(unrelated, JSON.stringify(row) + "\n", { mode: 0o600 });
  fs.symlinkSync(unrelated, file);
  fs.symlinkSync(unrelated, `${file}.1`);
  fs.symlinkSync(unrelated, aggregate);
  const log = new RequestLog(file);
  assert.deepEqual(log.list(10), []);
  assert.equal(log.usage(0, Date.now()).total.count, 0);
  assert.equal(new UsageHistory(aggregate).watermark, null);
  assert.equal(fs.readFileSync(unrelated, "utf8"), JSON.stringify(row) + "\n");
});

test("history startup tightens legacy files without changing shared directory permissions", { skip: process.platform === "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-history-read-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  fs.chmodSync(home, 0o755);
  const file = path.join(home, "requests.jsonl"), aggregate = path.join(home, "usage-hourly.jsonl");
  for (const target of [file, `${file}.1`, aggregate]) {
    fs.writeFileSync(target, target === aggregate ? "" : JSON.stringify(row) + "\n", { mode: 0o644 });
    fs.chmodSync(target, 0o644);
  }
  const log = new RequestLog(file);
  assert.equal(log.list(10).length, 1);
  for (const target of [file, `${file}.1`, aggregate]) assert.equal(fs.statSync(target).mode & 0o777, 0o600);
  assert.equal(fs.statSync(home).mode & 0o777, 0o755);
});
