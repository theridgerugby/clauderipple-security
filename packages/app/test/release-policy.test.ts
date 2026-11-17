import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";
import {
  releaseTarget, releasePlan, productionConfig, verifyConfiguredSigner, verifyMacSignature,
  verifyWindowsSignature, verifyFuseValues, verifyPackagedApp, inspectArtifacts, expectedArtifacts,
  WINDOWS_SIGNATURE_SCRIPT, RELEASE_FUSES,
} from "../scripts/release-policy.mjs";

const require = createRequire(import.meta.url);
const appDirectory = path.resolve(import.meta.dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(appDirectory, "package.json"), "utf8"));
const macEnv = {
  RIPPLE_MAC_TEAM_ID: "A1B2C3D4E5", RIPPLE_MAC_SIGNING_IDENTITY: "Developer ID Application: Example Fixture (A1B2C3D4E5)",
  APPLE_KEYCHAIN_PROFILE: "fixture-notary-profile",
};
const winEnv = { RIPPLE_WINDOWS_CERT_SHA1: "A".repeat(40), RIPPLE_WINDOWS_TIMESTAMP_URL: "https://timestamp.example.test/rfc3161" };
const macPlan = () => releasePlan("mac", macEnv, "darwin");
const winPlan = () => releasePlan("win", winEnv, "win32");
const ok = { status: 0, stdout: "", stderr: "" };
const macDetails = "Authority=Developer ID Application: Example Fixture (A1B2C3D4E5)\nTeamIdentifier=A1B2C3D4E5\nCodeDirectory v=20500 flags=0x10000(runtime) hashes=123+7 location=embedded\n";

function goodWire() {
  const wire: Record<string, string | number> = { version: "1" };
  const { FuseV1Options } = require("@electron/fuses");
  for (const [name, value] of Object.entries(RELEASE_FUSES)) wire[FuseV1Options[name[0]!.toUpperCase() + name.slice(1)]] = value ? 49 : 48;
  return wire;
}

test("production entry points reject unsupported hosts and CLI override flags", () => {
  assert.equal(releaseTarget(["mac"]), "mac");
  assert.equal(releaseTarget(["win"]), "win");
  for (const args of [[], ["linux"], ["mac", "--config.forceCodeSigning=false"], ["win", "--publish=always"]]) assert.throws(() => releaseTarget(args), /no override/);
  for (const [target, platform] of [["mac", "linux"], ["win", "linux"], ["mac", "win32"], ["win", "darwin"], ["unknown", "darwin"]]) assert.throws(() => releasePlan(target, {}, platform), /matching native/);
  for (const env of [{ GITHUB_EVENT_NAME: "pull_request" }, { GITHUB_EVENT_NAME: "pull_request_target" }, { CSC_FOR_PULL_REQUEST: "true" }, { ELECTRON_DISABLE_SANDBOX: "1" }, { ELECTRON_RUN_AS_NODE: "1" }]) assert.throws(() => releasePlan("mac", { ...macEnv, ...env }, "darwin"), /forbidden|sandbox-enabled/);
});

test("macOS requires an explicit matching Developer ID and a complete unambiguous notarization mode", () => {
  assert.equal(macPlan().team, "A1B2C3D4E5");
  for (const changes of [
    { RIPPLE_MAC_TEAM_ID: "" }, { RIPPLE_MAC_TEAM_ID: "A1B2C3D4E5\n" },
    { RIPPLE_MAC_SIGNING_IDENTITY: "-" }, { RIPPLE_MAC_SIGNING_IDENTITY: "Apple Development: Example (A1B2C3D4E5)" },
    { RIPPLE_MAC_SIGNING_IDENTITY: "Developer ID Application: Wrong Team (Z1Y2X3W4V5)" },
    { APPLE_KEYCHAIN_PROFILE: "" }, { APPLE_ID: "example@example.test" },
    { APPLE_API_KEY_ID: "partial" }, { CSC_LINK: "fixture-certificate.p12" },
    { APPLE_TEAM_ID: "Z1Y2X3W4V5" },
  ]) assert.throws(() => releasePlan("mac", { ...macEnv, ...changes }, "darwin"));
  assert.equal(releasePlan("mac", { ...macEnv, APPLE_KEYCHAIN_PROFILE: "", APPLE_API_KEY: "/fixture/key.p8", APPLE_API_KEY_ID: "fixture", APPLE_API_ISSUER: "fixture" }, "darwin").target, "mac");
  assert.equal(releasePlan("mac", { ...macEnv, APPLE_KEYCHAIN_PROFILE: "", APPLE_ID: "fixture@example.test", APPLE_APP_SPECIFIC_PASSWORD: "fixture-only", APPLE_TEAM_ID: macEnv.RIPPLE_MAC_TEAM_ID }, "darwin").target, "mac");
});

test("Windows requires an explicit signer and timestamp provider without inventing an identity", () => {
  assert.equal(winPlan().thumbprint, "A".repeat(40));
  for (const thumbprint of ["", "0".repeat(39), "G".repeat(40), "A".repeat(40) + "\n"]) assert.throws(() => releasePlan("win", { ...winEnv, RIPPLE_WINDOWS_CERT_SHA1: thumbprint }, "win32"), /thumbprint/);
  for (const url of ["", "http://timestamp.example.test", "https://user:secret@timestamp.example.test", "https://timestamp.example.test/#x", "https://timestamp.example.test:444/", "https://timestamp.example.test/\n"]) assert.throws(() => releasePlan("win", { ...winEnv, RIPPLE_WINDOWS_TIMESTAMP_URL: url }, "win32"), /HTTPS|timestamp/);
  assert.throws(() => releasePlan("win", { ...winEnv, WIN_CSC_LINK: "fixture.pfx" }, "win32"), /password/);
  assert.equal(releasePlan("win", { ...winEnv, WIN_CSC_LINK: "fixture.pfx", WIN_CSC_KEY_PASSWORD: "fixture-only" }, "win32").importedCertificate, true);
});

test("production config forces signatures, notarization, integrity fuses and nonpublishing", () => {
  const weak = structuredClone(manifest);
  weak.build.forceCodeSigning = false;
  weak.build.asar = false;
  weak.build.npmRebuild = true;
  weak.build.nodeGypRebuild = true;
  weak.build.beforePack = "unreviewed-hook.js";
  weak.build.extraResources = [];
  weak.build.mac.notarize = false;
  weak.build.mac.hardenedRuntime = false;
  weak.build.win.signExecutable = false;
  weak.build.win.signAndEditExecutable = false;
  weak.build.win.signtoolOptions = { sign: "untrusted-hook.js", signingHashAlgorithms: ["sha1"] };
  weak.build.win.azureSignOptions = { endpoint: "unconfigured" };
  weak.build.win.signExts = ["!.exe"];
  const hook = () => {};
  for (const plan of [macPlan(), winPlan()]) {
    const config = productionConfig(weak, plan, "/fresh/staging", hook);
    assert.equal(config.forceCodeSigning, true);
    assert.equal(config.asar, true);
    assert.equal(config.npmRebuild, false);
    assert.equal(config.nodeGypRebuild, false);
    assert.equal(config.beforePack, path.join(appDirectory, "scripts/stage-runtime.mjs"));
    assert.deepEqual(config.extraResources, manifest.build.extraResources);
    assert.equal(config.publish, null);
    assert.equal(config.extends, null);
    assert.equal(config.mac.notarize, true);
    assert.equal(config.mac.hardenedRuntime, true);
    assert.equal(config.dmg.sign, true);
    assert.equal(config.win.signExecutable, true);
    assert.equal(config.win.signAndEditExecutable, true);
    assert.equal(config.win.verifyUpdateCodeSignature, true);
    assert.equal(config.win.azureSignOptions, null);
    assert.equal(config.win.signtoolOptions.sign, undefined);
    assert.deepEqual(config.win.signtoolOptions.signingHashAlgorithms, ["sha256"]);
    assert.deepEqual(config.electronFuses, RELEASE_FUSES);
    assert.equal(config.afterSign, hook);
    assert.equal(config.nsis.buildUniversalInstaller, false);
  }
  assert.equal(productionConfig(manifest, winPlan(), "/fresh", hook).win.signtoolOptions.certificateSha1, winEnv.RIPPLE_WINDOWS_CERT_SHA1);
  assert.equal(productionConfig(manifest, macPlan(), "/fresh", hook).mac.identity, "Example Fixture (A1B2C3D4E5)");
});

test("personal source-only checkout blocks native distribution and retains dormant signing checks", () => {
  assert.equal(manifest.build.forceCodeSigning, true);
  assert.equal(manifest.build.win.signExecutable, true);
  for (const name of ["dist", "dist:win", "release", "release:win"]) {
    assert.equal(manifest.scripts[name], "node scripts/block-personal-release.mjs");
  }
  const denied = spawnSync(process.execPath, [path.join(appDirectory, "scripts/block-personal-release.mjs")], {
    encoding: "utf8", timeout: 10_000,
  });
  assert.equal(denied.status, 1);
  assert.match(denied.stderr, /personal security fork is source-only/);
  const source = fs.readFileSync(path.join(appDirectory, "scripts/release.mjs"), "utf8");
  assert.match(source, /publish: "never"/);
  assert.match(source, /verifiedArchitectures\.has\("x64"\)/);
  assert.match(source, /verifiedArchitectures\.has\("arm64"\)/);
  assert.ok(source.indexOf("inspectArtifacts(files") < source.indexOf("fs.renameSync(staging"));
  assert.doesNotMatch(source, /--no-sandbox|ExecutionPolicy|npm publish|gh release/);
});

test("personal source-only package lock excludes the vulnerable unsigned packager chain", () => {
  const root = path.resolve(appDirectory, "../..");
  const rootManifest = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
  const lock = JSON.parse(fs.readFileSync(path.join(root, "package-lock.json"), "utf8"));
  assert.equal(rootManifest.devDependencies["electron-builder"], undefined);
  for (const name of ["electron-builder", "app-builder-lib", "node-gyp", "tinyglobby", "picomatch"]) {
    assert.equal(lock.packages[`node_modules/${name}`], undefined, `${name} must not be in the source-only dependency closure`);
  }
});

test("native signer preflight checks the exact configured identity and cannot be satisfied by another key", () => {
  const exact = (executable: string, args: string[]) => {
    assert.equal(executable, "/usr/bin/security");
    assert.deepEqual(args, ["find-identity", "-v", "-p", "codesigning"]);
    return { ...ok, stdout: `1) ABCDEF "${macEnv.RIPPLE_MAC_SIGNING_IDENTITY}"\n1 valid identities found\n` };
  };
  verifyConfiguredSigner(macPlan(), exact);
  assert.throws(() => verifyConfiguredSigner(macPlan(), () => ({ ...ok, stdout: "1 valid identities found" })), /not available/);
  verifyConfiguredSigner({ ...macPlan(), importedCertificate: true }, () => { throw new Error("No eager certificate import"); });
});

test("macOS verifier requires strict code signing, expected team, Hardened Runtime, staple and Gatekeeper", () => {
  const calls: [string, string[]][] = [];
  verifyMacSignature("/fixture/ClaudeRipple.app", macEnv.RIPPLE_MAC_TEAM_ID, true, (exe: string, args: string[]) => {
    calls.push([exe, args]);
    return args.includes("--display") ? { ...ok, stderr: macDetails } : ok;
  });
  assert.deepEqual(calls, [
    ["/usr/bin/codesign", ["--verify", "--deep", "--strict", "/fixture/ClaudeRipple.app"]],
    ["/usr/bin/codesign", ["--display", "--verbose=4", "/fixture/ClaudeRipple.app"]],
    ["/usr/bin/xcrun", ["stapler", "validate", "/fixture/ClaudeRipple.app"]],
    ["/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=2", "/fixture/ClaudeRipple.app"]],
  ]);
  for (const details of [macDetails.replace("TeamIdentifier=A1B2C3D4E5", "TeamIdentifier=Z1Y2X3W4V5"), macDetails.replace("Authority=Developer ID Application:", "Authority=Self Signed:"), macDetails.replace("(runtime)", "(none)"), macDetails + "Signature=adhoc\n"]) {
    assert.throws(() => verifyMacSignature("/fixture/app", macEnv.RIPPLE_MAC_TEAM_ID, true, () => ({ ...ok, stderr: details })), /authorized|Hardened/);
  }
  for (let failure = 0; failure < 4; failure++) {
    let count = 0;
    assert.throws(() => verifyMacSignature("/fixture/app", macEnv.RIPPLE_MAC_TEAM_ID, true, () => count++ === failure ? { status: 1, stderr: "PRIVATE-NATIVE-OUTPUT" } : { ...ok, stderr: macDetails }), error => /verification failed/.test(String(error)) && !String(error).includes("PRIVATE-NATIVE-OUTPUT"));
  }
});

test("Windows verifier sends paths only on stdin and requires a successful exact acknowledgement", () => {
  const file = "C:\\fixture\\quote' $(not-code).exe";
  const run = (executable: string, args: string[], options: { input: string }) => {
    assert.equal(executable, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
    assert.deepEqual(args, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SIGNATURE_SCRIPT]);
    assert.equal(args.join(" ").includes(file), false);
    assert.deepEqual(JSON.parse(options.input), { mode: "verify", path: file, thumbprint: winEnv.RIPPLE_WINDOWS_CERT_SHA1 });
    return { ...ok, stdout: "release-signature-ok" };
  };
  verifyWindowsSignature(file, winEnv.RIPPLE_WINDOWS_CERT_SHA1, run, "C:\\Windows");
  assert.match(WINDOWS_SIGNATURE_SCRIPT, /Get-AuthenticodeSignature -LiteralPath/);
  assert.match(WINDOWS_SIGNATURE_SCRIPT, /Status -ne 'Valid'/);
  assert.match(WINDOWS_SIGNATURE_SCRIPT, /SignatureType -ne 'Authenticode'/);
  assert.match(WINDOWS_SIGNATURE_SCRIPT, /-CodeSigningCert/);
  assert.match(WINDOWS_SIGNATURE_SCRIPT, /TimeStamperCertificate/);
  assert.match(WINDOWS_SIGNATURE_SCRIPT, /SignerCertificate\.Thumbprint -ne \$request\.thumbprint/);
  assert.doesNotMatch(WINDOWS_SIGNATURE_SCRIPT, /Set-ExecutionPolicy|New-SelfSignedCertificate|Import-Certificate/);
  for (const result of [{ status: 1, stdout: "release-signature-ok" }, { ...ok, stdout: "" }, { ...ok, stdout: "release-signature-ok\nextra" }]) assert.throws(() => verifyWindowsSignature(file, winEnv.RIPPLE_WINDOWS_CERT_SHA1, () => result, "C:\\Windows"));
});

test("packaged fuse verification rejects removed, inherited and weakened fuses", async () => {
  verifyFuseValues(goodWire());
  assert.throws(() => verifyFuseValues({ ...goodWire(), version: "2" }), /wire version/);
  for (const [key, state] of Object.entries(goodWire())) {
    if (key === "version") continue;
    for (const wrong of [state === 48 ? 49 : 48, 114, 144, undefined]) assert.throws(() => verifyFuseValues({ ...goodWire(), [key]: wrong }), /fuse differs/);
  }
  let read = false;
  await verifyPackagedApp("C:\\fixture\\ClaudeRipple.exe", winPlan(), { systemRoot: "C:\\Windows", run: () => ({ ...ok, stdout: "release-signature-ok" }), readFuses: async () => { read = true; return goodWire(); } });
  assert.equal(read, true);
  await assert.rejects(verifyPackagedApp("C:\\fixture\\ClaudeRipple.exe", winPlan(), { systemRoot: "C:\\Windows", run: () => ({ status: 1 }), readFuses: async () => { throw new Error("Must not accept fuses after invalid signature"); } }), /signature verification/);
});

test("artifact receipt rejects missing architectures, stale or escaped files and symlink artifacts", t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-release-artifacts-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const output = path.join(directory, "fresh");
  fs.mkdirSync(output);
  const files = expectedArtifacts("mac", "1.2.3").map((name: string) => { const file = path.join(output, name); fs.writeFileSync(file, "fixture"); return file; });
  assert.deepEqual(inspectArtifacts(files, output, "mac", "1.2.3"), files.map((file: string) => path.basename(file)).sort());
  assert.throws(() => inspectArtifacts(files.slice(1), output, "mac", "1.2.3"), /missing/);
  const outside = path.join(directory, "outside.zip"); fs.writeFileSync(outside, "fixture");
  assert.throws(() => inspectArtifacts([...files, outside], output, "mac", "1.2.3"), /escaped/);
  assert.throws(() => inspectArtifacts([...files, "relative.zip"], output, "mac", "1.2.3"), /escaped/);
  if (process.platform !== "win32") {
    const link = path.join(output, "link.zip"); fs.symlinkSync(outside, link);
    assert.throws(() => inspectArtifacts([...files, link], output, "mac", "1.2.3"), /escaped/);
  }
});

test("the real release command fails before building when authorized credentials are absent", () => {
  const env = { ...process.env };
  for (const key of Object.keys(env)) if (/^(?:RIPPLE_(?:MAC|WINDOWS)_|APPLE_|(?:WIN_)?CSC_)/.test(key)) delete env[key];
  // Exercise missing credentials independently of the earlier PR-event refusal. The
  // production guard remains enabled; its priority is checked separately below.
  delete env.GITHUB_EVENT_NAME;
  const result = spawnSync(process.execPath, [path.join(appDirectory, "scripts/release.mjs"), process.platform === "win32" ? "win" : "mac"], { encoding: "utf8", env, timeout: 10_000 });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /matching native|RIPPLE_MAC_TEAM_ID|RIPPLE_WINDOWS_CERT_SHA1/);
  assert.doesNotMatch(result.stdout, /electron-builder|Verified native/);
});

test("pull-request signing refusal precedes missing credentials on either supported native host", () => {
  for (const event of ["pull_request", "pull_request_target"]) {
    for (const [target, host] of [["mac", "darwin"], ["win", "win32"]]) {
      assert.throws(() => releasePlan(target, { GITHUB_EVENT_NAME: event }, host),
        /^Error: Production signing is forbidden in pull-request jobs$/);
    }
  }
});

test("native macOS rejects an unsigned app before treating it as a signed release", { skip: process.platform !== "darwin" }, t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-unsigned-app-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const app = path.join(directory, "Unsigned.app"); fs.mkdirSync(app);
  assert.throws(() => verifyMacSignature(app, macEnv.RIPPLE_MAC_TEAM_ID, true), /signature verification failed/);
});

test("native Windows rejects an unsigned executable before treating it as a signed release", { skip: process.platform !== "win32" }, t => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-unsigned-exe-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  const file = path.join(directory, "unsigned.exe"); fs.writeFileSync(file, "MZ-unsigned-fixture");
  assert.throws(() => verifyWindowsSignature(file, winEnv.RIPPLE_WINDOWS_CERT_SHA1), /signature verification failed/);
});
