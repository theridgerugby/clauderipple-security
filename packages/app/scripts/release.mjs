// Native production entry point. Requires real credentials supplied by an authorized release
// operator; this program never fabricates identities, changes trust stores, or publishes.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { createRequire } from "node:module";
import {
  ReleaseGateError, releaseTarget, releasePlan, productionConfig, verifyConfiguredSigner,
  verifyPackagedApp, verifyMacSignature, verifyWindowsSignature, inspectArtifacts, RELEASE_FUSES,
} from "./release-policy.mjs";

const require = createRequire(import.meta.url);
const appDirectory = fileURLToPath(new URL("../", import.meta.url));
function prepare() {
  for (const args of [
    ["scripts/sync-private-acl.mjs", "--check"],
    ["scripts/sync-admin-transport.mjs", "--check"],
    ["scripts/make-icons.mts"],
    [require.resolve("typescript/bin/tsc"), "-p", "tsconfig.json"],
  ]) {
    const result = spawnSync(process.execPath, args, { cwd: appDirectory, stdio: "inherit", timeout: 300_000, windowsHide: true });
    if (result.error || result.status !== 0) throw new ReleaseGateError("Desktop release preparation failed");
  }
}

let staging;
try {
  // The preflight deliberately happens before imports that initialize the builder, filesystem
  // changes, icon generation or certificate access. CI's ordinary tests never need release keys.
  const target = releaseTarget(process.argv.slice(2));
  const plan = releasePlan(target);
  verifyConfiguredSigner(plan);
  const manifest = JSON.parse(fs.readFileSync(path.join(appDirectory, "package.json"), "utf8"));
  const { build, Platform, Arch } = require("electron-builder");
  prepare();
  const releaseDirectory = path.join(appDirectory, "release");
  fs.mkdirSync(releaseDirectory, { recursive: true });
  staging = fs.mkdtempSync(path.join(releaseDirectory, `.candidate-${target}-`));
  const verifiedArchitectures = new Set();
  const config = productionConfig(manifest, plan, staging, async context => {
    const arch = Arch[context.arch];
    if (context.electronPlatformName !== plan.host || !["x64", "arm64"].includes(arch)) throw new ReleaseGateError("Unexpected platform or architecture in the signing callback");
    const relative = path.relative(staging, context.appOutDir);
    if (!relative || relative.startsWith("..") || path.isAbsolute(relative)) throw new ReleaseGateError("The signed app escaped the release staging directory");
    const file = path.join(context.appOutDir, target === "mac" ? "ClaudeRipple.app" : "ClaudeRipple.exe");
    await verifyPackagedApp(file, plan);
    verifiedArchitectures.add(arch);
  });
  const platform = target === "mac" ? Platform.MAC : Platform.WINDOWS;
  const targets = new Map([[platform, new Map([[Arch.x64, target === "mac" ? ["dmg", "zip"] : ["nsis", "zip"]], [Arch.arm64, target === "mac" ? ["dmg", "zip"] : ["nsis", "zip"]]])]]);
  const files = await build({ projectDir: appDirectory, targets, config, publish: "never" });
  if (!verifiedArchitectures.has("x64") || !verifiedArchitectures.has("arm64")) throw new ReleaseGateError("Both native app architectures must pass signature and fuse verification");
  const names = inspectArtifacts(files, staging, target, manifest.version);
  for (const name of names) {
    const file = path.join(staging, name);
    if (target === "mac" && name.endsWith(".dmg")) verifyMacSignature(file, plan.team, false);
    if (target === "win" && name.endsWith(".exe")) verifyWindowsSignature(file, plan.thumbprint);
  }
  // This receipt attests only the checks actually run above. It is not a signing certificate,
  // security certification, or substitute for the mandatory native application test matrix.
  const receipt = {
    schema: 1, version: manifest.version, platform: plan.host, architectures: [...verifiedArchitectures].sort(),
    signer: target === "mac" ? { appleTeam: plan.team } : { certificateThumbprint: plan.thumbprint },
    appSignaturesVerified: true, notarizationVerified: target === "mac", electronFuses: RELEASE_FUSES,
    artifacts: names.map(name => ({ name, sha256: createHash("sha256").update(fs.readFileSync(path.join(staging, name))).digest("hex") })),
  };
  fs.writeFileSync(path.join(staging, "release-verification.json"), `${JSON.stringify(receipt, null, 2)}\n`, { flag: "wx" });
  const verified = path.join(releaseDirectory, `verified-${target}-${manifest.version}-${path.basename(staging).split("-").at(-1)}`);
  fs.renameSync(staging, verified);
  staging = undefined;
  console.log(`Verified native release candidates: ${verified}`);
  console.log("No artifacts have been published.");
} catch (error) {
  console.error(error instanceof ReleaseGateError ? error.message : "Native desktop build or verification failed; no release was approved");
  if (staging) console.error("Unverified candidate files remain under release/.candidate-* for local diagnosis; do not distribute them.");
  process.exitCode = 1;
}
