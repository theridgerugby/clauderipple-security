// Read-only verification for the owner checkout installed with:
// npm ci --workspace @clauderipple/app --include-workspace-root --ignore-scripts
// Full-workspace development/CI intentionally has a different dependency inventory.
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export const PERSONAL_WORKSPACE = "@clauderipple/app";
export const CORE_RUNTIME_DEPENDENCIES = ["proper-lockfile", "undici"];
const BUILD_DEPENDENCIES = ["@electron/fuses", "@types/node", "@types/proper-lockfile", "typescript"];
const FORBIDDEN = /^(?:@anthropic-ai\/|@cloudflare\/|@modelcontextprotocol\/|@clauderipple\/remote$|@types\/(?:web-push|ws)$|(?:qrcode-generator|tweetnacl|web-push|ws|zod|wrangler|miniflare|workerd|electron-builder|electron-winstaller|app-builder-lib)$)/;
const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const readJson = filename => JSON.parse(fs.readFileSync(filename, "utf8"));

function exactNames(dependencies, expected, label) {
  assert.deepEqual(Object.keys(dependencies ?? {}).sort(), [...expected].sort(), `${label} changed; review the personal dependency boundary`);
}

export function verifyPersonalManifests(root) {
  const manifest = readJson(path.join(root, "package.json"));
  const app = readJson(path.join(root, "packages/app/package.json"));
  const lock = readJson(path.join(root, "package-lock.json"));
  assert.equal(lock.lockfileVersion, 3, "personal install requires the reviewed v3 lockfile");
  exactNames(manifest.dependencies, CORE_RUNTIME_DEPENDENCIES, "root runtime dependencies");
  exactNames(manifest.devDependencies, BUILD_DEPENDENCIES, "root build dependencies");
  exactNames(app.dependencies, [], "dashboard runtime dependencies");
  exactNames(app.devDependencies, ["electron"], "dashboard build dependencies");
  assert.equal(app.name, PERSONAL_WORKSPACE);
  for (const [location, pkg] of [["", manifest], ["packages/app", app]]) {
    assert.ok(lock.packages?.[location], `missing locked workspace: ${location || "root"}`);
    for (const section of ["dependencies", "devDependencies", "optionalDependencies", "peerDependencies"]) {
      assert.deepEqual(lock.packages[location][section] ?? {}, pkg[section] ?? {}, `manifest/lock mismatch: ${location || "root"} ${section}`);
    }
    exactNames(pkg.optionalDependencies, [], `${location || "root"} optional dependencies`);
    exactNames(pkg.peerDependencies, [], `${location || "root"} peer dependencies`);
  }
  return { manifest, app, lock };
}

function resolveLockedDependency(lock, importer, name) {
  let prefix = importer;
  while (true) {
    const candidate = `${prefix ? `${prefix}/` : ""}node_modules/${name}`;
    if (lock.packages[candidate] && !lock.packages[candidate].link) return candidate;
    if (!prefix) return null;
    const parent = prefix.lastIndexOf("/node_modules/");
    prefix = parent < 0 ? "" : prefix.slice(0, parent);
  }
}

// Node's package resolution, over the lockfile only. Optional dependencies may be absent on
// this platform. Required peers and transitive dependencies must be installed, too.
export function dependencyClosure(lock, roots) {
  const allowed = new Map();
  const queue = [...roots];
  while (queue.length) {
    const { importer, name, optional = false } = queue.pop();
    const location = resolveLockedDependency(lock, importer, name);
    if (!location) { assert.ok(optional, `missing locked dependency: ${name} from ${importer || "root"}`); continue; }
    const previous = allowed.get(location);
    if (previous && (!previous.optional || optional)) continue;
    const entry = lock.packages[location];
    allowed.set(location, { name, entry, optional });
    const optionalDependencies = entry.optionalDependencies ?? {};
    for (const dependency of Object.keys(entry.dependencies ?? {})) {
      if (!Object.hasOwn(optionalDependencies, dependency)) queue.push({ importer: location, name: dependency, optional });
    }
    for (const dependency of Object.keys(optionalDependencies)) queue.push({ importer: location, name: dependency, optional: true });
    for (const dependency of Object.keys(entry.peerDependencies ?? {})) {
      queue.push({ importer: location, name: dependency, optional: optional || entry.peerDependenciesMeta?.[dependency]?.optional === true });
    }
  }
  return allowed;
}

function fileBytes(root) {
  let bytes = 0;
  for (const item of fs.readdirSync(root, { withFileTypes: true })) {
    const filename = path.join(root, item.name);
    if (item.isDirectory()) bytes += fileBytes(filename);
    else if (item.isFile()) bytes += fs.statSync(filename).size;
    // npm's command and workspace links are not a second copy of their targets.
  }
  return bytes;
}

export function verifyPersonalInstall(root = checkout) {
  const { manifest, app, lock } = verifyPersonalManifests(root);
  const seeds = (importer, dependencies) => Object.keys(dependencies ?? {}).map(name => ({ importer, name }));
  const core = dependencyClosure(lock, seeds("", manifest.dependencies));
  const allowed = dependencyClosure(lock, [
    ...seeds("", manifest.dependencies), ...seeds("", manifest.devDependencies),
    ...seeds("packages/app", app.devDependencies),
  ]);
  for (const { name } of allowed.values()) assert.ok(!FORBIDDEN.test(name), `Remote or release-tool dependency leaked into personal closure: ${name}`);
  const found = new Set();
  let appLinkFound = false;

  function inspectPackage(dir, name) {
    const relative = path.relative(root, dir).split(path.sep).join("/");
    const stat = fs.lstatSync(dir);
    if (relative === "node_modules/@clauderipple/app") {
      assert.equal(fs.realpathSync(dir), fs.realpathSync(path.join(root, "packages/app")), "dashboard workspace resolves outside this checkout");
      appLinkFound = true;
      return;
    }
    assert.ok(stat.isDirectory() && !stat.isSymbolicLink(), `unexpected linked dependency: ${relative}`);
    assert.ok(!FORBIDDEN.test(name), `Remote or release-tool dependency present in personal install: ${name}`);
    const expected = allowed.get(relative);
    assert.ok(expected, `unexpected package in personal install: ${relative}`);
    const installed = readJson(path.join(dir, "package.json"));
    assert.equal(installed.name, expected.name, `package identity mismatch: ${relative}`);
    assert.equal(installed.version, expected.entry.version, `package version differs from lockfile: ${relative}`);
    found.add(relative);
    const nested = path.join(dir, "node_modules");
    if (fs.existsSync(nested)) inspectModules(nested);
  }

  function inspectModules(dir) {
    assert.ok(fs.lstatSync(dir).isDirectory() && !fs.lstatSync(dir).isSymbolicLink(), `node_modules must be a real directory: ${dir}`);
    for (const item of fs.readdirSync(dir, { withFileTypes: true })) {
      if (item.name.startsWith(".")) continue;
      const candidate = path.join(dir, item.name);
      if (item.name.startsWith("@")) {
        assert.ok(item.isDirectory() && !item.isSymbolicLink(), `invalid dependency scope: ${candidate}`);
        for (const child of fs.readdirSync(candidate)) inspectPackage(path.join(candidate, child), `${item.name}/${child}`);
      } else inspectPackage(candidate, item.name);
    }
  }

  inspectModules(path.join(root, "node_modules"));
  // npm can place nested workspace dependencies here instead of hoisting them.
  const appModules = path.join(root, "packages/app/node_modules");
  if (fs.existsSync(appModules)) inspectModules(appModules);
  assert.ok(appLinkFound, "dashboard workspace was not installed; select --workspace @clauderipple/app --include-workspace-root");
  for (const [location, { optional }] of allowed) assert.ok(optional || found.has(location), `missing required personal dependency: ${location}`);
  const bytes = fileBytes(path.join(root, "node_modules")) + (fs.existsSync(appModules) ? fileBytes(appModules) : 0);
  return { packages: found.size, bytes, coreRuntimePackages: [...core.values()].map(({ name }) => name).sort(),
    electronBinaryInstalled: fs.existsSync(path.join(root, "node_modules/electron/path.txt")),
    note: "Apparent file bytes; does not measure memory, prove downloaded binary integrity, or exercise the owner's Claude Desktop." };
}

if (import.meta.main) {
  try {
    const result = verifyPersonalInstall();
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    console.error(`Personal install verification failed: ${error.message}`);
    process.exitCode = 1;
  }
}
