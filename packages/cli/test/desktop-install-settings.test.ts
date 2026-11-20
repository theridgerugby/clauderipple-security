import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { normalizeConfig } from "../../router/src/config.ts";
import { CLI_WINDOW_MAX } from "../../router/src/bootstrap.ts";
import { installModelOptions } from "../src/install-model-options.ts";
import { applyProxyEnv, removeProxyEnv } from "../src/settings.ts";

test("personal install never chooses native slots or a global context override", () => {
  const config = normalizeConfig({ cli: { extraModels: [], models: { main: "external-fixture", smallFast: "another-fixture" } } });
  assert.deepEqual(installModelOptions(config), {});
  for (const cap of ["", "200000", "1000000", "invalid"]) assert.throws(() => installModelOptions(config, cap), /preserves native context/);
  const generic = structuredClone(config); delete generic.security;
  assert.deepEqual(installModelOptions(generic), { models: config.cli.models, maxContextTokens: CLI_WINDOW_MAX });
  assert.equal(installModelOptions(generic, "400000").maxContextTokens, 400000);
});

test("personal install and owned removal preserve native defaults, context, permissions and unrelated settings", t => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-desktop-install-settings-"));
  const before = { home: process.env.CLAUDERIPPLE_HOME, settings: process.env.CLAUDE_SETTINGS_PATH };
  process.env.CLAUDERIPPLE_HOME = home;
  process.env.CLAUDE_SETTINGS_PATH = path.join(home, "synthetic-settings.json");
  t.after(() => {
    if (before.home === undefined) delete process.env.CLAUDERIPPLE_HOME; else process.env.CLAUDERIPPLE_HOME = before.home;
    if (before.settings === undefined) delete process.env.CLAUDE_SETTINGS_PATH; else process.env.CLAUDE_SETTINGS_PATH = before.settings;
    fs.rmSync(home, { recursive: true, force: true });
  });
  const original = { model: "opus", env: { ANTHROPIC_MODEL: "sonnet", ANTHROPIC_SMALL_FAST_MODEL: "haiku", CLAUDE_CODE_SUBAGENT_MODEL: "opus",
    CLAUDE_CODE_MAX_CONTEXT_TOKENS: "200000", UNRELATED: "keep" }, permissions: { allow: ["Read"] }, theme: "dark" };
  fs.writeFileSync(process.env.CLAUDE_SETTINGS_PATH, JSON.stringify(original));
  const proxy = { proxyUrl: "http://127.0.0.1:8790", caPath: path.join(home, "ca.pem"), force: false, home };
  const result = applyProxyEnv({ ...proxy, ...installModelOptions(normalizeConfig({})) });
  assert.equal(result.changed, true);
  assert.deepEqual(result.wroteSlots, []);
  assert.deepEqual(JSON.parse(fs.readFileSync(process.env.CLAUDE_SETTINGS_PATH, "utf8")), {
    ...original, env: { ...original.env, HTTPS_PROXY: proxy.proxyUrl, NODE_EXTRA_CA_CERTS: proxy.caPath },
  });
  removeProxyEnv(proxy);
  assert.deepEqual(JSON.parse(fs.readFileSync(process.env.CLAUDE_SETTINGS_PATH, "utf8")), original);
});
