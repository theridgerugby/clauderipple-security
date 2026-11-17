import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { once } from "node:events";
import { egressFetch, EgressPolicyError, guardEgressFetch, isEgressPolicyError, type EgressFetch } from "../src/egress.ts";
import { fetchWithRetry } from "../src/providers/retry.ts";
import { refreshGoogleGrant } from "../src/providers/google/accounts.ts";
import { refreshChatGptGrant } from "../src/providers/chatgpt/accounts.ts";
import { refreshClaudeOAuth } from "../src/providers/claude-oauth.ts";
import { exchangeGoogleCode } from "../src/providers/google/login.ts";
import { discoverProject, fetchHostCatalogue, fetchUserEmail } from "../src/providers/google/antigravity.ts";
import { fetchClaudeModels } from "../src/providers/anthropic-models.ts";
import { UsageCache } from "../src/providers/usage-cache.ts";
import { anthropicServerToolBackend, webPluginBackend } from "../src/websearch.ts";
import { measureModel } from "../src/capabilities.ts";
import { GoogleAdapter } from "../src/providers/google/index.ts";
import { ChatGptAdapter } from "../src/providers/chatgpt/index.ts";
import { OpenAiCompatibleAdapter } from "../src/providers/openai/index.ts";
import { saveGoogleAccount } from "../src/providers/google/accounts.ts";
import { saveChatGptAccount } from "../src/providers/chatgpt/accounts.ts";
import { Logger } from "../src/log.ts";
import type { AnthropicRequest } from "../src/providers/chatgpt/translate.ts";
import { configurePersonalEgressPolicy, type PersonalSecurityPolicy } from "../src/personal-policy.ts";

const KEY = "synthetic-secret-never-use-for-auth";
const PROMPT = "synthetic-private-prompt-no-user-data";

/** Real HTTP, synthetic data, literal loopback only. No provider or operating-system login. */
async function redirectFixture(t: TestContext) {
  const sourceRequests: { key: string | undefined; authorization: string | undefined; body: string }[] = [];
  const destinationRequests: { body: string }[] = [];
  let destinationOrigin = "";
  const destination = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    destinationRequests.push({ body });
    res.end("redirect should never reach this origin");
  });
  const source = http.createServer(async (req, res) => {
    let body = "";
    for await (const chunk of req) body += chunk;
    sourceRequests.push({ key: req.headers["x-goog-api-key"] as string | undefined, authorization: req.headers.authorization, body });
    const status = Number((req.url ?? "/307").split("/")[1]);
    if (status === 200) {
      res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify({ answer: "normal reply" }));
      return;
    }
    res.writeHead(status, { location: `${destinationOrigin}/sink?echo=${KEY}`, "content-type": "text/plain" });
    res.end(`${KEY} ${PROMPT}`);
  });
  t.after(async () => {
    for (const server of [source, destination]) {
      server.closeAllConnections();
      await new Promise<void>(resolve => server.close(() => resolve()));
    }
  });
  destination.listen(0, "127.0.0.1"); await once(destination, "listening");
  destinationOrigin = `http://127.0.0.1:${(destination.address() as { port: number }).port}`;
  source.listen(0, "127.0.0.1"); await once(source, "listening");
  const sourceOrigin = `http://127.0.0.1:${(source.address() as { port: number }).port}`;
  return { url: (status: number) => `${sourceOrigin}/${status}`, sourceRequests, destinationRequests };
}

function safePolicyError(error: unknown): boolean {
  assert.ok(isEgressPolicyError(error));
  assert.doesNotMatch(error.message, /synthetic|\/sink|127\.0\.0\.1/);
  return true;
}

test("every 300–399 response refuses a second origin and never forwards credentials or prompt", async t => {
  const fixture = await redirectFixture(t);
  for (let status = 300; status < 400; status++) {
    await assert.rejects(egressFetch(fixture.url(status), {
      method: "POST", headers: { "x-goog-api-key": KEY, authorization: `Bearer ${KEY}` }, body: PROMPT,
      // An inner caller cannot opt back into native fetch's implicit redirect behavior.
      redirect: "follow", signal: AbortSignal.timeout(5000),
    }), safePolicyError, `HTTP ${status}`);
  }
  assert.equal(fixture.sourceRequests.length, 100);
  assert.ok(fixture.sourceRequests.every(request => request.key === KEY && request.body === PROMPT));
  assert.deepEqual(fixture.destinationRequests, [], "no request or body reached the redirect destination");
});

test("redirect refusals bypass the whole retry ladder and preserve successful 200 exchanges", async t => {
  const fixture = await redirectFixture(t);
  const messages: string[] = [];
  await assert.rejects(fetchWithRetry(fixture.url(307), {
    method: "POST", headers: { "x-goog-api-key": KEY }, body: PROMPT,
    signal: AbortSignal.timeout(5000),
  }, { attempts: 10, log: message => messages.push(message) }), safePolicyError);
  assert.equal(fixture.sourceRequests.length, 1, "a security refusal is attempted exactly once");
  assert.deepEqual(messages, [], "no network-retry diagnostic masks a policy refusal");
  assert.deepEqual(fixture.destinationRequests, []);
  const response = await fetchWithRetry(fixture.url(200), { method: "POST", body: PROMPT }, { attempts: 10, log: () => {} });
  assert.deepEqual(await response.json(), { answer: "normal reply" });
  assert.equal(fixture.sourceRequests.length, 2);
});

test("injected transports cannot weaken redirect policy and cancellation never awaits hostile body cleanup", async () => {
  let cancelled = false;
  let signal: AbortSignal | null | undefined;
  const transport: EgressFetch = async (_url, init = {}) => {
    assert.equal(init.redirect, "manual");
    signal = init.signal;
    return new Response(new ReadableStream({ cancel() { cancelled = true; return new Promise<void>(() => {}); } }),
      { status: 302, headers: { location: `https://untrusted.invalid/${KEY}` } });
  };
  await assert.rejects(guardEgressFetch(transport)("https://provider.invalid/api", { redirect: "follow" }), safePolicyError);
  assert.equal(cancelled, true);
  assert.equal(signal?.aborted, true);
});

test("invalid targets and a validator rejection fail before a transport sees credentials", async () => {
  let calls = 0;
  const transport: EgressFetch = async () => { calls++; return new Response("unexpected"); };
  for (const url of ["not a URL", "file:///private", `https://name:${KEY}@provider.invalid/`]) {
    await assert.rejects(egressFetch(url, { headers: { authorization: KEY } }, transport), safePolicyError);
  }
  const denied = new EgressPolicyError("destination");
  await assert.rejects(egressFetch("https://provider.invalid/api", {}, transport, () => { throw denied; }), error => error === denied);
  assert.equal(calls, 0);
  assert.equal(isEgressPolicyError(Object.assign(new Error("destination refused"), { code: "ERR_RIPPLE_PERSONAL_POLICY" })), true);
});

test("the registered personal policy validates exact HTTPS origins before any transport and observes revocation", async () => {
  const policy: PersonalSecurityPolicy = { mode: "personal", approvedOrigins: ["https://provider.invalid"] };
  let calls = 0;
  const transport: EgressFetch = async () => { calls++; return Response.json({ ok: true }); };
  configurePersonalEgressPolicy(() => policy);
  try {
    const good = await egressFetch("https://provider.invalid/v1/messages", { method: "POST", body: PROMPT }, transport);
    assert.deepEqual(await good.json(), { ok: true });
    for (const url of ["http://provider.invalid/v1/messages", "https://other.invalid/api", "https://provider.invalid:8443/api", "https://provider.invalid/api#fragment", "https://provider.invalid\\api"]) {
      await assert.rejects(egressFetch(url, { headers: { authorization: KEY }, body: PROMPT }, transport), isEgressPolicyError);
    }
    policy.approvedOrigins = [];
    await assert.rejects(egressFetch("https://provider.invalid/v1/messages", { method: "POST", body: PROMPT }, transport), isEgressPolicyError);
    assert.equal(calls, 1);
  } finally { configurePersonalEgressPolicy(undefined); }
});

const credentialFlows: [string, (transport: EgressFetch) => Promise<unknown>][] = [
  ["Google OAuth code exchange", transport => exchangeGoogleCode({ code: KEY, codeVerifier: KEY, redirectUri: "http://127.0.0.1/callback", fetch: transport })],
  ["Google refresh", transport => refreshGoogleGrant(KEY, { projectId: "fixture" }, transport)],
  ["ChatGPT refresh", transport => refreshChatGptGrant(KEY, { accountId: "fixture" }, transport)],
  ["Claude refresh", transport => refreshClaudeOAuth(KEY, { fetch: transport })],
  ["Google project discovery never falls through to onboarding", transport => discoverProject(KEY, transport)],
  ["Google user identity", transport => fetchUserEmail(KEY, transport)],
  ["Claude model catalogue", transport => fetchClaudeModels("https://provider.invalid", { authorization: `Bearer ${KEY}` }, transport)],
  ["provider usage", transport => new UsageCache({ fetch: transport, label: "fixture" }).windows("test", "https://provider.invalid/usage", { authorization: KEY }, () => [])],
  ["OpenAI hosted search", transport => webPluginBackend({ name: "fixture", url: "https://provider.invalid", headers: { authorization: KEY }, model: "test", fetchImpl: transport as typeof fetch }).search({ query: PROMPT })],
  ["Anthropic hosted search", transport => anthropicServerToolBackend({ name: "fixture", url: "https://provider.invalid", headers: { "x-api-key": KEY }, model: "test", fetchImpl: transport as typeof fetch }).search({ query: PROMPT })],
  ["capability measurement never advances to another candidate", transport => measureModel("test", [{ wire: "chat", url: "https://provider.invalid" }, { wire: "responses", url: "https://another.invalid" }], [], { fetch: transport, headers: { authorization: KEY } })],
];

for (const [name, run] of credentialFlows) {
  test(`${name} preserves terminal policy errors before any retry or fallback`, async t => {
    const fixture = await redirectFixture(t);
    let calls = 0;
    const transport: EgressFetch = async (_url, init = {}) => {
      calls++;
      assert.equal(init.redirect, "manual");
      return fetch(fixture.url(307), { ...init, signal: AbortSignal.timeout(5000) });
    };
    await assert.rejects(run(transport), safePolicyError);
    assert.equal(calls, 1);
    assert.equal(fixture.sourceRequests.length, 1);
    assert.deepEqual(fixture.destinationRequests, []);
  });
}

test("a security refusal from either Google catalogue client family cannot become a static fallback", async () => {
  for (const failedFamily of ["ide", "cli"]) {
    let calls = 0;
    await assert.rejects(fetchHostCatalogue(KEY, "fixture", "https://provider.invalid", async (_url, init = {}) => {
      calls++;
      assert.equal(init.redirect, "manual");
      const agent = new Headers(init.headers).get("user-agent") ?? "";
      const cli = /antigravity\/cli\//i.test(agent);
      if ((failedFamily === "cli") === cli) return new Response(null, { status: 307, headers: { location: "https://another.invalid" } });
      return new Response(JSON.stringify({ models: { "gemini-3.8-flash": { displayName: "test" } } }), { status: 200 });
    }), safePolicyError);
    assert.equal(calls, 2, "only the two planned family requests, no replacement credential/host");
  }
});

const REDIRECT_STATUSES = [300, 301, 302, 303, 304, 305, 306, 307, 308, 399];
const inferenceRequest: AnthropicRequest = { model: "test", stream: true, messages: [{ role: "user", content: PROMPT }] };

/** No listener is needed on the caller side: a terminal policy failure must write no bytes. */
function caller(t: TestContext) {
  const socket = new net.Socket();
  const request = new http.IncomingMessage(socket);
  const response = new http.ServerResponse(request);
  t.after(() => { response.destroy(); request.destroy(); socket.destroy(); });
  return { request, response };
}

for (const family of ["google-key", "openai-chat", "openai-responses", "google-accounts", "chatgpt-accounts"] as const) {
  test(`${family}: generation refuses redirects without credential rotation or writing a fallback response`, async t => {
    const fixture = await redirectFixture(t);
    const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-egress-test-"));
    t.after(() => fs.rmSync(home, { recursive: true, force: true }));
    const log = new Logger(null, 1_000_000, 1, false);
    if (family === "google-accounts") for (let n = 0; n < 2; n++) {
      saveGoogleAccount(home, { accessToken: `${KEY}-${n}`, projectId: `test-project-${n}`, expiresAt: Date.now() + 3_600_000 });
    }
    if (family === "chatgpt-accounts") for (let n = 0; n < 2; n++) {
      saveChatGptAccount(home, { accessToken: `${KEY}-${n}`, accountId: `test-account-${n}`, expiresAt: Date.now() + 3_600_000 });
    }
    let rotations = 0;
    for (const status of REDIRECT_STATUSES) {
      const { request, response } = caller(t);
      const url = fixture.url(status);
      const credential = { headers: { authorization: `Bearer ${KEY}`, "x-goog-api-key": KEY }, next: () => { rotations++; return null; } };
      let run: Promise<unknown>;
      if (family === "google-key") {
        run = new GoogleAdapter("test", { type: "google", auth: "api-key", apiKey: KEY, url }, home, log)
          .handle(request, response, "/v1/messages", inferenceRequest, "gemini-2.5-flash", undefined, credential);
      } else if (family === "openai-chat" || family === "openai-responses") {
        run = new OpenAiCompatibleAdapter("test", { type: "openai-compatible", wire: family === "openai-chat" ? "chat" : "responses", url }, log)
          .handle(request, response, "/v1/messages", inferenceRequest, "test-model", undefined, credential);
      } else if (family === "google-accounts") {
        run = new GoogleAdapter("test", { type: "google", auth: "antigravity", url }, home, log)
          .handle(request, response, "/v1/messages", inferenceRequest, "gemini-2.5-flash", undefined);
      } else {
        run = new ChatGptAdapter("test", { type: "chatgpt", auth: "own", url }, home, log)
          .handle(request, response, "/v1/messages", inferenceRequest, "test-model", undefined);
      }
      await assert.rejects(run, safePolicyError);
      assert.equal(response.headersSent, false);
      assert.equal(response.listenerCount("close"), 0, "the abandoned adapter request releases its close listener");
    }
    assert.equal(rotations, 0, "a redirect is never offered to another API key");
    assert.equal(fixture.sourceRequests.length, REDIRECT_STATUSES.length, "one request per deliberate invocation, no account rotation");
    assert.ok(fixture.sourceRequests.every(item => item.body.includes(PROMPT)));
    assert.ok(fixture.sourceRequests.every(item => item.key?.startsWith(KEY) || item.authorization?.includes(KEY)));
    assert.deepEqual(fixture.destinationRequests, []);
  });
}

test("ChatGPT hosted search, image and usage share the terminal redirect boundary", async t => {
  const fixture = await redirectFixture(t);
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-egress-sidecalls-"));
  t.after(() => fs.rmSync(home, { recursive: true, force: true }));
  saveChatGptAccount(home, { accessToken: KEY, accountId: "test-account", expiresAt: Date.now() + 3_600_000 });
  const adapter = new ChatGptAdapter("test", { type: "chatgpt", auth: "own", url: fixture.url(307) }, home, new Logger(null, 1_000_000, 1, false));
  await assert.rejects(adapter.webSearch("test").search({ query: PROMPT }), safePolicyError);
  await assert.rejects(adapter.generateImage("test", { prompt: PROMPT }), safePolicyError);
  await assert.rejects(adapter.fetchRateLimits(), safePolicyError);
  assert.equal(fixture.sourceRequests.length, 3);
  assert.ok(fixture.sourceRequests.every(item => item.authorization === `Bearer ${KEY}`));
  assert.deepEqual(fixture.destinationRequests, []);
});
