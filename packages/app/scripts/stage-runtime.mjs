// electron-builder's sources run beside app.asar. They therefore need their own complete,
// lockfile-derived production dependency tree; app.asar/node_modules cannot satisfy them.
// This hook only copies already-installed files. It never installs, downloads, or runs hooks.
import fs from "node:fs";
import path from "node:path";
import { createHash, randomBytes } from "node:crypto";
import { createRequire, isBuiltin } from "node:module";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { assertReleaseArtifactPath } from "../../../scripts/release-artifact.mjs";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const MARKER = "native-runtime.json";
const ARCHES = new Set(["x64", "arm64"]);
const PLATFORMS = new Set(["linux", "darwin", "win32"]);
const SOURCE_TREES = ["packages/router/src", "packages/cli/src", "packages/remote/src", "packages/remote/web", "packages/ui", "packages/mod", "packages/app/assets"];
const SOURCE_FILES = ["packages/router/package.json", "packages/cli/package.json", "packages/remote/package.json", "LICENSE", "README.md"];
const EXCLUDED_PARTS = new Set(["node_modules", ".git", "test", "tests", "test-native", "coverage", "preview", "__tests__", "__mocks__"]);
const PRIVATE_NAME = /^(?:\.env(?:\..*)?|admin-(?:tls-token|token|runtime\.json|tls-identity\.json|tls-endpoint\.json)|local\.secret|host\.json|paths\.json|config\.json|[^/]+\.(?:pem|key|p12|pfx))$/i;

const json = file => JSON.parse(fs.readFileSync(file, "utf8"));
const slash = value => value.split(path.sep).join("/");
function inside(root, file) { const rel = path.relative(root, file); return rel === "" || !rel.startsWith(`..${path.sep}`) && rel !== ".." && !path.isAbsolute(rel); }
function regular(file) {
  const info = fs.lstatSync(file);
  if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error(`Runtime input is not a regular independent file: ${file}`);
  return info;
}
function allowed(relative, dependencyAssets) {
  const parts = slash(relative).split("/");
  return !parts.some(part => EXCLUDED_PARTS.has(part) || !dependencyAssets && PRIVATE_NAME.test(part)) &&
    !parts.some((part, index) => part === ".claude-plugin" && parts[index + 1] === "types");
}
/** Dependencies retain legitimate config/certificate assets; install-secret names always fail. */
export function copyRuntimeTree(source, destination, dependencyAssets = false, relative = "") {
  assertReleaseArtifactPath(slash(relative || path.basename(source)));
  const info = fs.lstatSync(source);
  if (info.isSymbolicLink()) throw new Error(`Runtime source cannot be a symbolic link: ${source}`);
  if (info.isDirectory()) {
    fs.mkdirSync(destination, { recursive: true });
    for (const name of fs.readdirSync(source)) {
      const next = path.join(relative, name);
      // Check even an excluded path, so accidentally present real credentials fail loudly.
      assertReleaseArtifactPath(slash(next));
      if (allowed(next, dependencyAssets)) copyRuntimeTree(path.join(source, name), path.join(destination, name), dependencyAssets, next);
    }
  } else {
    regular(source);
    fs.copyFileSync(source, destination, fs.constants.COPYFILE_FICLONE);
    fs.chmodSync(destination, info.mode & 0o777);
  }
}
function allFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    assertReleaseArtifactPath(entry.name);
    const file = path.join(dir, entry.name);
    if (entry.isSymbolicLink()) throw new Error(`Runtime contains a symbolic link: ${file}`);
    if (entry.isDirectory()) out.push(...allFiles(file));
    else { regular(file); out.push(file); }
  }
  return out;
}
function matches(values, wanted) {
  return !values || !values.includes(`!${wanted}`) && (values.every(value => value.startsWith("!")) || values.includes(wanted));
}
function targetPackage(platform, arch) {
  if (!PLATFORMS.has(platform) || !ARCHES.has(arch)) throw new Error("Unsupported native runtime platform or architecture");
  return `@anthropic-ai/claude-agent-sdk-${platform}-${arch}`;
}
function packageName(relative) {
  const tail = relative.slice(relative.lastIndexOf("node_modules/") + "node_modules/".length);
  if (!/^(?:@[a-z0-9_.-]+\/)?[a-z0-9_.-]+$/i.test(tail)) throw new Error(`Invalid production package location: ${relative}`);
  return tail;
}

/** Resolve from the actual staged caller, rejecting fallback to checkout ancestors/global paths. */
function resolveContained(root, caller, specifier) {
  if (isBuiltin(specifier)) return;
  const resolved = createRequire(caller).resolve(specifier);
  const real = fs.realpathSync(resolved);
  if (!inside(root, real)) throw new Error(`Runtime dependency escaped the resource root: ${specifier}`);
  regular(real);
}

function requirePackage(root, caller, name) {
  let directory = path.dirname(caller);
  for (;;) {
    const candidate = path.join(directory, "node_modules", name);
    if (fs.existsSync(candidate)) {
      const real = fs.realpathSync(candidate);
      if (!inside(root, real) || json(path.join(real, "package.json")).name !== name) throw new Error(`Runtime package escaped or changed identity: ${name}`);
      return;
    }
    if (directory === root || !inside(root, directory)) break;
    directory = path.dirname(directory);
  }
  throw new Error(`Runtime required package is missing: ${name}`);
}

function imports(file) {
  const parsed = ts.createSourceFile(file, fs.readFileSync(file, "utf8"), ts.ScriptTarget.Latest, true);
  const found = new Set();
  const visit = node => {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) {
      const typeOnly = ts.isImportDeclaration(node) ? node.importClause?.isTypeOnly : node.isTypeOnly;
      if (!typeOnly) found.add(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && node.arguments.length && ts.isStringLiteral(node.arguments[0])) {
      const callee = node.expression;
      if (callee.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(callee) && callee.text === "require" ||
          ts.isPropertyAccessExpression(callee) && ts.isIdentifier(callee.expression) && callee.expression.text === "require" && callee.name.text === "resolve") {
        found.add(node.arguments[0].text);
      }
    }
    ts.forEachChild(node, visit);
  };
  visit(parsed);
  return found;
}

/** Checks every runtime source import plus each production package's required dependencies/peers. */
export function verifyRuntimeClosure(root) {
  const rootInfo = fs.lstatSync(root);
  if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("Runtime root is not an independent directory");
  // macOS exposes temporary directories through /var -> /private/var. Compare the
  // resolver's canonical files against the same canonical root, while links within
  // that root (and a linked root itself) remain forbidden by the normal file checks.
  root = fs.realpathSync(root);
  for (const file of allFiles(root)) {
    assertReleaseArtifactPath(slash(path.relative(root, file)));
    if (/\.node$/i.test(file)) throw new Error("Native runtime contains an unreviewed ABI addon; rebuilds are disabled and a target-specific verified addon policy is required");
  }
  for (const tree of ["router/src", "cli/src", "remote/src", "remote/web"]) {
    for (const file of allFiles(path.join(root, "packages", tree)).filter(file => /\.[cm]?[jt]s$/.test(file) && !file.endsWith(".d.ts"))) {
      for (const specifier of imports(file)) {
        if (specifier.startsWith(".")) {
          const target = path.resolve(path.dirname(file), specifier);
          if (!inside(root, target)) throw new Error(`Relative runtime import escaped resource root: ${specifier}`);
          regular(target);
        } else resolveContained(root, file, specifier);
      }
    }
  }
  const metadata = json(path.join(root, MARKER));
  const binary = path.join(root, "node_modules", targetPackage(metadata.platform, metadata.arch), metadata.platform === "win32" ? "claude.exe" : "claude");
  const binaryInfo = regular(binary);
  if (!binaryInfo.size || metadata.platform !== "win32" && !(binaryInfo.mode & 0o111)) throw new Error("Target SDK executable is empty or not executable");
  for (const dep of metadata.dependencies) {
    const dir = path.join(root, dep.path);
    const manifest = json(path.join(dir, "package.json"));
    for (const name of Object.keys(manifest.dependencies ?? {})) {
      if (!Object.hasOwn(manifest.optionalDependencies ?? {}, name)) requirePackage(root, path.join(dir, "package.json"), name);
    }
    for (const name of Object.keys(manifest.peerDependencies ?? {})) {
      if (manifest.peerDependenciesMeta?.[name]?.optional !== true) requirePackage(root, path.join(dir, "package.json"), name);
    }
  }
  for (const name of Object.keys(json(path.join(root, "package.json")).dependencies ?? {})) resolveContained(root, path.join(root, "package.json"), name);
  for (const required of ["packages/cli/src/admin-bridge.ts", "packages/remote/src/main.ts", "packages/remote/package.json",
    "packages/remote/web/index.html", "packages/remote/src/chunks.ts", "packages/remote/src/wrap-up.ts", "packages/remote/src/protocol.ts",
    "packages/remote/src/tool-details.ts", "packages/remote/src/e2ee.ts", "packages/ui/index.html", "packages/mod/.claude-plugin/plugin.json",
    "packages/installers/install.sh", "packages/installers/install.ps1", "packages/app/assets/icon.icns", "packages/app/assets/icon.ico"]) {
    regular(path.join(root, required));
  }
  return metadata;
}

/** Materialize an entirely new runtime. Callers must choose a disposable, absent destination. */
export function stageNativeRuntime({ sourceRoot = checkout, output, platform = process.platform, arch = process.arch }) {
  const binaryPackage = targetPackage(platform, arch);
  const source = fs.realpathSync(sourceRoot);
  const target = path.resolve(output);
  if (target === source || inside(target, source) || fs.existsSync(target)) throw new Error("Native runtime destination must be a new isolated directory");
  const lock = json(path.join(source, "package-lock.json"));
  const manifest = json(path.join(source, "package.json"));
  const expectedBinary = lock.packages?.[`node_modules/${binaryPackage}`];
  const binaryName = platform === "win32" ? "claude.exe" : "claude";
  if (!expectedBinary || !fs.existsSync(path.join(source, "node_modules", binaryPackage, binaryName))) {
    throw new Error(`Native ${platform}/${arch} runtime requires the matching locked ${binaryPackage} package; supply it from the reviewed lockfile on the build host. No download or cross-architecture fallback is permitted.`);
  }
  const dependencies = [];
  for (const [relative, entry] of Object.entries(lock.packages ?? {})) {
    if (!/^(?:node_modules\/|packages\/(?:router|cli|remote)\/node_modules\/)/.test(relative) || entry.dev === true || entry.link === true || !matches(entry.os, platform) || !matches(entry.cpu, arch)) continue;
    if (relative.split("/").some(part => part === ".." || part === "." || part.includes("\\"))) throw new Error("Invalid dependency location in lockfile");
    const name = packageName(relative);
    const from = path.join(source, relative);
    if (!inside(source, from)) throw new Error("Dependency source escaped checkout");
    if (!fs.existsSync(from) && entry.optional === true && name !== binaryPackage) continue;
    if (fs.lstatSync(from).isSymbolicLink()) throw new Error(`Production dependency is a symlink: ${name}`);
    const installed = json(path.join(from, "package.json"));
    if (installed.name !== name || installed.version !== entry.version || !matches(installed.os, platform) || !matches(installed.cpu, arch)) throw new Error(`Production dependency differs from reviewed lockfile: ${name}`);
    dependencies.push({ path: relative, name, version: entry.version, integrity: entry.integrity ?? null });
  }
  if (!dependencies.some(item => item.name === binaryPackage)) throw new Error("Target SDK executable is outside the production lockfile closure");
  fs.mkdirSync(target, { recursive: true });
  for (const tree of SOURCE_TREES) copyRuntimeTree(path.join(source, tree), path.join(target, tree));
  for (const file of SOURCE_FILES) { fs.mkdirSync(path.dirname(path.join(target, file)), { recursive: true }); copyRuntimeTree(path.join(source, file), path.join(target, file)); }
  fs.mkdirSync(path.join(target, "packages/installers"), { recursive: true });
  for (const file of ["install.sh", "install.ps1"]) copyRuntimeTree(path.join(source, "scripts", file), path.join(target, "packages/installers", file));
  fs.writeFileSync(path.join(target, "package.json"), JSON.stringify({ name: manifest.name, version: manifest.version, private: true,
    type: "module", engines: manifest.engines, dependencies: manifest.dependencies }, null, 2) + "\n");
  for (const dep of dependencies) {
    const destination = path.join(target, dep.path);
    fs.mkdirSync(path.dirname(destination), { recursive: true });
    copyRuntimeTree(path.join(source, dep.path), destination, true);
  }
  const metadata = { version: 1, platform, arch, packageVersion: manifest.version,
    lockSha256: createHash("sha256").update(fs.readFileSync(path.join(source, "package-lock.json"))).digest("hex"), dependencies };
  fs.writeFileSync(path.join(target, MARKER), JSON.stringify(metadata, null, 2) + "\n");
  verifyRuntimeClosure(target);
  return metadata;
}

function checkedStageParent(root, relative) {
  let current = fs.realpathSync(root);
  for (const part of relative.split("/")) {
    if (!part || part === "." || part === "..") throw new Error("Invalid native staging parent");
    current = path.join(current, part);
    try { fs.mkdirSync(current); } catch (error) { if (error.code !== "EEXIST") throw error; }
    const info = fs.lstatSync(current);
    if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Native staging parent is not an independent directory");
  }
  return current;
}

/** Reserve the exact target through resource copying, not just through this hook's return. */
export function reserveRuntimeStage(sourceRoot, platform, arch) {
  targetPackage(platform, arch);
  const osKey = { darwin: "mac", win32: "win", linux: "linux" }[platform];
  const stageRoot = checkedStageParent(sourceRoot, `packages/app/release-native/runtime/${osKey}`);
  const output = path.join(stageRoot, arch);
  const lock = path.join(stageRoot, `${arch}.stage-lock`);
  const owner = JSON.stringify({ pid: process.pid, nonce: randomBytes(16).toString("hex") });
  let descriptor;
  try { descriptor = fs.openSync(lock, "wx", 0o600); }
  catch (error) {
    if (error.code === "EEXIST") throw new Error(`Native ${platform}/${arch} staging is reserved; another build may be using it. After verifying that no build is running, inspect and remove only ${lock} to recover a crashed build.`);
    throw error;
  }
  fs.writeFileSync(descriptor, owner);
  fs.closeSync(descriptor);
  let released = false;
  const release = () => {
    if (released) return;
    released = true;
    // A replaced parent or lock is not ours to remove.
    try {
      if (fs.realpathSync(stageRoot) !== stageRoot || !regular(lock) || fs.readFileSync(lock, "utf8") !== owner) return;
      fs.unlinkSync(lock);
    } catch { /* An unexpected path stays untouched for operator inspection. */ }
  };
  try {
    if (fs.existsSync(output)) {
      const info = fs.lstatSync(output);
      if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Refusing to replace an unrecognized native runtime staging directory");
      regular(path.join(output, MARKER));
      const marker = json(path.join(output, MARKER));
      if (marker.version !== 1 || marker.platform !== platform || marker.arch !== arch) throw new Error("Refusing to replace a native runtime stage for another target");
      fs.rmSync(output, { recursive: true });
    }
  } catch (error) { release(); throw error; }
  return { output, release };
}

const reservations = new Map();
/** electron-builder's supported beforePack hook, once per target architecture. */
export default async function beforePack(context) {
  const names = { 1: "x64", 3: "arm64" }; // builder-util Arch enum, checked against the installed API in tests.
  const arch = names[context.arch];
  const platform = context.electronPlatformName;
  const key = `${platform}/${arch}`;
  const prior = reservations.get(key);
  if (prior) { verifyRuntimeClosure(prior.output); return; }
  const reserved = reserveRuntimeStage(checkout, platform, arch);
  try { stageNativeRuntime({ output: reserved.output, platform, arch }); }
  catch (error) { reserved.release(); throw error; }
  reservations.set(key, reserved);
  // Keep the reservation while electron-builder copies, signs and creates artifacts. A
  // crashed process leaves a fail-closed lock; no PID-based automatic stale recovery.
  process.once("exit", reserved.release);
}
