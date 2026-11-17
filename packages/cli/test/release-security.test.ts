import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";

const root = path.resolve(import.meta.dirname, "../../..");
const release = await import(pathToFileURL(path.join(root, "scripts/release-artifact.mjs")).href) as {
  requiredFiles: string[];
  releaseVersion(root: string, tag?: string): string;
  inspectPackReport(report: unknown, version: string): { filename: string; files: string[] };
};

function packReport(extra: string[] = []) {
  return [{ name: "clauderipple", version: "1.2.3", filename: "clauderipple-1.2.3.tgz", files: [...release.requiredFiles, ...extra].map(file => ({ path: file })) }];
}

test("release inspection requires the actual runtime files and both bundled installers", () => {
  const valid = packReport();
  assert.equal(release.inspectPackReport(valid, "1.2.3").filename, "clauderipple-1.2.3.tgz");
  for (const name of release.requiredFiles) {
    const report = packReport();
    report[0]!.files = report[0]!.files.filter(file => file.path !== name);
    assert.throws(() => release.inspectPackReport(report, "1.2.3"), /missing runtime file/);
  }
});

test("release inspection rejects alternate identity, multiple packages, paths and credential artifacts", () => {
  assert.throws(() => release.inspectPackReport([], "1.2.3"), /exactly one/);
  assert.throws(() => release.inspectPackReport([...packReport(), ...packReport()], "1.2.3"), /exactly one/);
  for (const field of ["name", "version", "filename"] as const) {
    const report = packReport();
    report[0]![field] = "other";
    assert.throws(() => release.inspectPackReport(report, "1.2.3"), /package identity/);
  }
  for (const file of ["../outside", "/outside", "dist\\outside", "dist//outside", "dist/./outside", "dist/line\nfeed", "dist/ui/index.html", "dist/admin-token", "dist/admin-tls-token", "dist/admin-tls-identity.json", "dist/admin-tls-endpoint.json", "dist/admin-runtime.json", ".env", "dist/.env.production", "dist/ca.key", "dist/leaf.key", "dist/credentials.json", ".npmrc", ".git/config"]) {
    assert.throws(() => release.inspectPackReport(packReport([file]), "1.2.3"), /unsafe|duplicate|credential/, file);
  }
  release.inspectPackReport(packReport(["dist/router/src/providers/anthropic-token-file.js"]), "1.2.3");
  for (const name of ["admin-tls-token", "admin-tls-identity.json", "admin-tls-endpoint.json", "host.json", "host-key.json", "local.secret", "expo-push.json", "vapid.json"]) {
    for (const suffix of ["", ".tmp-1234-aabbcc", ".bak", ".old"]) {
      const file = `dist/state/${name}${suffix}`;
      assert.throws(() => release.inspectPackReport(packReport([file]), "1.2.3"), /credential/, file);
    }
  }
  assert.throws(() => release.inspectPackReport(packReport(["dist/local-control-tls/unexpected-state"]), "1.2.3"), /credential/);
});

test("release versions agree across manifests, runtime and the exact tag", t => {
  const temp = fs.mkdtempSync(path.join(os.tmpdir(), "cr-release-version-"));
  t.after(() => fs.rmSync(temp, { recursive: true, force: true }));
  for (const file of ["package.json", "packages/router/package.json", "packages/cli/package.json", "packages/app/package.json"]) {
    fs.mkdirSync(path.dirname(path.join(temp, file)), { recursive: true });
    fs.writeFileSync(path.join(temp, file), JSON.stringify({ version: "1.2.3" }));
  }
  fs.mkdirSync(path.join(temp, "packages/router/src"));
  fs.writeFileSync(path.join(temp, "packages/router/src/version.ts"), 'export const VERSION = "1.2.3";');
  assert.equal(release.releaseVersion(temp, "v1.2.3"), "1.2.3");
  assert.throws(() => release.releaseVersion(temp, "v1.2.4"), /tag differs/);
  fs.writeFileSync(path.join(temp, "packages/app/package.json"), JSON.stringify({ version: "1.2.4" }));
  assert.throws(() => release.releaseVersion(temp, "v1.2.3"), /different versions/);
  for (const version of ["latest", "1.2", "1.2.3\r", "1.2.3\n", "1.2.3-01", "1.2.3+.", "999999999999999999.0.0"]) {
    fs.writeFileSync(path.join(temp, "package.json"), JSON.stringify({ version }));
    assert.throws(() => release.releaseVersion(temp), /invalid release version/);
  }
});

test("every remote workflow action is pinned and untrusted PRs have no privileged trigger", () => {
  for (const name of fs.readdirSync(path.join(root, ".github/workflows"))) {
    if (!/\.ya?ml$/.test(name)) continue;
    const source = fs.readFileSync(path.join(root, ".github/workflows", name), "utf8");
    assert.doesNotMatch(source.replace(/^\s*#.*$/gm, ""), /pull_request_target:|workflow_run:/, name);
    for (const match of source.matchAll(/^\s*(?:-\s*)?uses:\s*(\S+)/gm)) {
      const action = match[1]!;
      if (!action.startsWith("./")) assert.match(action, /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_./-]+@[0-9a-f]{40}$/, `${name}: ${action}`);
    }
    const checkouts = source.match(/uses: actions\/checkout@/g)?.length ?? 0;
    assert.equal(source.match(/persist-credentials: false/g)?.length ?? 0, checkouts, name);
  }
});

test("release permissions are isolated from builds and every supported OS is a mandatory gate", () => {
  const ci = fs.readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8");
  assert.match(ci, /workflow_call:/);
  assert.match(ci, /workflow_dispatch:/);
  assert.match(ci, /os: \[macos-latest, ubuntu-latest, windows-latest\]/);
  assert.doesNotMatch(ci, /continue-on-error/);
  assert.match(ci, /npm ci --ignore-scripts/);
  assert.match(ci, /npm audit --audit-level=low/);
  assert.match(ci, /xvfb-run -a npm run test:native/);
  assert.doesNotMatch(ci, /--no-sandbox/);
  const source = fs.readFileSync(path.join(root, ".github/workflows/publish.yml"), "utf8");
  const start = source.indexOf("\n  publish:");
  const end = source.indexOf("\n  dry-run:");
  assert.ok(start > 0 && end > start);
  const before = source.slice(0, start);
  const publisher = source.slice(start, end).replace(/^\s*#.*$/gm, "");
  assert.doesNotMatch(before, /id-token: write/);
  assert.match(before, /uses: \.\/.github\/workflows\/ci.yml/);
  assert.match(publisher, /id-token: write/);
  assert.doesNotMatch(publisher, /actions\/checkout|npm (?:ci|install|run build)|npm@/);
  assert.match(publisher, /sha256sum --check --strict/);
  assert.match(publisher, /npm publish "\$artifact" .*--ignore-scripts --provenance/);
  assert.doesNotMatch(source.slice(end), /id-token: write/);
});
