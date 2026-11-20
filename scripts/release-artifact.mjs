// A release is built before this runs. Pack once without lifecycle hooks, inspect that artifact,
// and hand its exact bytes and digest to the separate, minimally privileged publishing job.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { execFileSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const versionPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/;
export const requiredFiles = [
  "package.json", "bin/clauderipple.js", "dist/cli/src/index.js", "dist/router/src/index.js",
  "dist/cli/src/admin-bridge.js", "dist/cli/src/admin-runtime.js", "dist/cli/src/native-ui.js",
  "dist/router/src/admin-transport-client.js", "dist/router/src/admin-transport-state.js",
  "dist/router/src/admin-auth.js", "dist/router/src/private-file.js", "dist/router/src/windows-private-acl.js", "dist/router/src/phone.js",
  "dist/remote/src/main.js", "dist/remote/src/local-control.js", "dist/remote/src/local-transport.js",
  "dist/remote/src/config.js", "dist/remote/src/phone-config-storage.js", "dist/remote/src/phone-auth-migration.js",
  "dist/ui/index.html", "dist/mod/hooks/register.tsx", "dist/app/dist/main.js",
  "dist/app/dist/admin-auth.js", "dist/app/dist/admin-transport-client.js", "dist/app/dist/admin-window.js",
  "dist/app/dist/protocol.js", "dist/app/dist/preload.js", "dist/app/dist/security.js",
  "dist/app/dist/window.js", "dist/app/dist/windows-private-acl.js",
  "dist/installers/install.sh", "dist/installers/install.ps1",
];

export function releaseVersion(sourceRoot = root, tag = "") {
  const manifests = ["package.json", "packages/router/package.json", "packages/cli/package.json", "packages/app/package.json"];
  const versions = manifests.map(file => JSON.parse(fs.readFileSync(path.join(sourceRoot, file), "utf8")).version);
  const version = versions[0];
  const match = typeof version === "string" && version.length <= 200 && version === version.trim() ? versionPattern.exec(version) : null;
  if (!match || match.slice(1, 4).some(part => !Number.isSafeInteger(Number(part))) || match[4]?.split(".").some(part => /^\d+$/.test(part) && part !== "0" && part.startsWith("0"))) throw new Error("invalid release version");
  if (versions.some(value => value !== version)) throw new Error("release manifests have different versions");
  const source = fs.readFileSync(path.join(sourceRoot, "packages/router/src/version.ts"), "utf8");
  if (/^export const VERSION = "([^"]+)";?\s*$/m.exec(source)?.[1] !== version) throw new Error("router source version differs from package version");
  if (tag && tag !== `v${version}`) throw new Error("release tag differs from package version");
  return version;
}

/** Shared by npm inspection and native resource staging. Never copy install state into a release. */
export function assertReleaseArtifactPath(file) {
  if (typeof file !== "string" || /[\\\x00-\x1f\x7f]/.test(file) || file.startsWith("/") || file.split("/").some(part => part === ".." || part === "" || part === ".")) throw new Error("unsafe package path");
  // Source modules named *-token-file.js are expected. Real install credentials are not.
  if (/(^|\/)(?:(?:admin-token|admin-tls-token|admin-tls-identity\.json|admin-tls-endpoint\.json|admin-runtime\.json|host\.json|host-key\.json|local\.secret|expo-push\.json|vapid\.json|ca\.key|leaf\.key|credentials\.json)(?:\.tmp-[^/]+|\.bak|\.old)?|local-control-tls|\.env(?:\..*)?|\.npmrc|\.git)(\/|$)/i.test(file)) throw new Error(`credential or repository metadata in release: ${file}`);
}

export function inspectPackReport(report, version) {
  if (!Array.isArray(report) || report.length !== 1) throw new Error("expected exactly one npm package");
  const packed = report[0];
  if (packed?.name !== "clauderipple" || packed.version !== version || packed.filename !== `clauderipple-${version}.tgz`) throw new Error("unexpected release package identity");
  if (!Array.isArray(packed.files)) throw new Error("npm pack supplied no file list");
  const files = packed.files.map(file => file.path);
  const seen = new Set();
  for (const file of files) {
    assertReleaseArtifactPath(file);
    if (seen.has(file)) throw new Error(`duplicate package path: ${file}`);
    seen.add(file);
  }
  for (const file of requiredFiles) if (!seen.has(file)) throw new Error(`missing runtime file: ${file}`);
  return { filename: packed.filename, files };
}

export function packRelease(destination, { sourceRoot = root, tag = "", run = execFileSync } = {}) {
  const version = releaseVersion(sourceRoot, tag);
  fs.mkdirSync(destination, { recursive: true });
  if (fs.readdirSync(destination).length) throw new Error("release output directory must be empty");
  const npm = process.platform === "win32" ? "npm.cmd" : "npm";
  const report = JSON.parse(run(npm, ["pack", "--json", "--ignore-scripts", "--pack-destination", destination], { cwd: sourceRoot, encoding: "utf8", shell: process.platform === "win32" }));
  const { filename, files } = inspectPackReport(report, version);
  const artifact = path.join(destination, filename);
  if (!fs.lstatSync(artifact).isFile()) throw new Error("release artifact must be a regular file");
  // Read the actual archive without extracting or executing it. npm's JSON and the archive must
  // agree, including both locally bundled installers; the privileged job never repacks it.
  const entries = run("tar", ["-tzf", artifact], { encoding: "utf8" }).trimEnd().split("\n").sort();
  const expected = files.map(file => `package/${file}`).sort();
  if (JSON.stringify(entries) !== JSON.stringify(expected)) throw new Error("tarball entries differ from npm pack report");
  const manifest = JSON.parse(run("tar", ["-xOzf", artifact, "package/package.json"], { encoding: "utf8" }));
  if (manifest.name !== "clauderipple" || manifest.version !== version || manifest.bin?.clauderipple !== "bin/clauderipple.js") throw new Error("tarball manifest is not the intended CLI release");
  for (const name of ["install.sh", "install.ps1"]) {
    const installer = run("tar", ["-xOzf", artifact, `package/dist/installers/${name}`]);
    if (!Buffer.from(installer).equals(fs.readFileSync(path.join(sourceRoot, "scripts", name)))) throw new Error(`bundled ${name} differs from the reviewed source`);
  }
  const sha256 = crypto.createHash("sha256").update(fs.readFileSync(artifact)).digest("hex");
  return { version, sha256, artifact };
}

if (import.meta.main) {
  const destination = process.argv[2];
  if (!destination || !path.isAbsolute(destination)) throw new Error("pass an absolute, empty release output directory");
  const release = packRelease(destination, { tag: process.env.RELEASE_TAG || "" });
  if (process.env.GITHUB_OUTPUT) fs.appendFileSync(process.env.GITHUB_OUTPUT, `version=${release.version}\nsha256=${release.sha256}\n`);
  console.log(`Inspected clauderipple@${release.version}: SHA-256 ${release.sha256}`);
}
