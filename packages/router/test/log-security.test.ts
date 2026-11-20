import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { Logger } from "../src/log.ts";
import { RequestLog, type RequestRecord } from "../src/requestlog.ts";
import { credentialHeaderValues, redactErrorText, redactHeaders } from "../src/redact.ts";

test("router logs redact recognizable credentials and prevent multiline/control-character forgery", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-log-security-"));
  const file = path.join(home, "router.log");
  const log = new Logger(file, 100_000, 1, false);
  t.after(() => { log.close(); fs.rmSync(home, { recursive: true, force: true }); });
  log.warn('provider failed\nFORGED success\r\n\x1b[2J "apiKey": "dummy-key-to-hide" x-clauderipple-admin=' + "a".repeat(64));
  const data = fs.readFileSync(file, "utf8");
  assert.equal(data.trimEnd().split("\n").length, 1);
  assert.doesNotMatch(data, /dummy-key-to-hide|a{64}|\x1b/);
  assert.match(data, /\[REDACTED\]/);
  if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test("log appends refuse symlinks without touching the unrelated file", { skip: process.platform === "win32" }, t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-log-security-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const target = path.join(home, "unrelated"), file = path.join(home, "router.log");
  fs.writeFileSync(target, "unchanged", { mode: 0o600 });
  fs.symlinkSync(target, file);
  assert.throws(() => new Logger(file, 100_000, 1, false), /regular/);
  assert.equal(fs.readFileSync(target, "utf8"), "unchanged");
});

test("request histories persist privately and scrub credential-shaped notes", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-history-security-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  const file = path.join(home, "requests.jsonl");
  const log = new RequestLog(file);
  const record: RequestRecord = { id: "dummy", at: new Date().toISOString(), ms: 1, status: 401, ok: false,
    kind: "messages", source: "dummy", target: "dummy", provider: "dummy", stream: false,
    note: '{"refresh_token":"dummy-refresh-to-hide"}' };
  log.add(record);
  assert.doesNotMatch(fs.readFileSync(file, "utf8"), /dummy-refresh-to-hide/);
  assert.doesNotMatch(log.list(1)[0]!.note!, /dummy-refresh-to-hide/);
  if (process.platform !== "win32") assert.equal(fs.statSync(file).mode & 0o777, 0o600);
});

test("admin capabilities and quoted JSON credentials join the central redaction boundary", () => {
  const capability = "a".repeat(64);
  assert.deepEqual(credentialHeaderValues([["x-clauderipple-admin", capability]]), [capability]);
  assert.equal(redactHeaders({ "x-clauderipple-admin": capability })["x-clauderipple-admin"], "[REDACTED]");
  for (const field of ["apiKey", "access_token", "refreshToken", "client_secret", "password", "x-clauderipple-admin"]) {
    assert.doesNotMatch(redactErrorText(JSON.stringify({ [field]: "dummy-opaque-sensitive-value" })), /dummy-opaque/);
  }
  assert.doesNotMatch(redactErrorText("upstream echoed AIza" + "x".repeat(35)), /AIza/);
});

test("known credentials are removed before whitespace normalization and diagnostic truncation", () => {
  for (const secret of ["dummy\tprivate  header", "dummy  private\t header", "  dummy \t private  header \t"]) {
    const normalized = secret.replace(/\s+/g, " ").trim();
    assert.equal(redactErrorText(`raw echo: ${secret}; normalized echo: ${normalized}`, [secret]),
      "raw echo: [REDACTED]; normalized echo: [REDACTED]");
    const longSecret = `${secret} ${"opaque-fragment ".repeat(100)}private-ending`;
    for (const echo of [longSecret, longSecret.replace(/\s+/g, " ").trim()]) {
      const diagnostic = redactErrorText(`upstream: ${echo}; harmless trailing context`, [longSecret], 32);
      assert.equal(diagnostic, "upstream: [REDACTED]; harmless trailing context".slice(0, 32));
      assert.doesNotMatch(diagnostic, /dummy|opaque-fragment|private-ending/);
    }
  }
});

test("empty or whitespace-only supplied secrets do not rewrite diagnostics", () => {
  assert.equal(redactErrorText(" normal\t diagnostic  text \n", ["", " ", "\t\n"]), "normal diagnostic text");
  assert.equal(redactErrorText("echo dummy private longer; done", ["dummy  private", "dummy\tprivate  longer"]),
    "echo [REDACTED]; done");
  assert.equal(redactErrorText("echo dummy private longer; done", ["dummy private", "dummy\tprivate  longer"]),
    "echo [REDACTED]; done");
});

test("Google API credential headers join header and opaque-error redaction", () => {
  const key = "dummy-opaque-google-credential";
  const secrets = credentialHeaderValues([["X-Goog-Api-Key", key], ["x-request-id", "safe-id"]]);
  assert.deepEqual(secrets, [key]);
  assert.deepEqual(redactHeaders({ "x-goog-api-key": key, "x-request-id": "safe-id" }),
    { "x-goog-api-key": "[REDACTED]", "x-request-id": "safe-id" });
  assert.equal(redactErrorText(`refused ${key}`, secrets), "refused [REDACTED]");
});
