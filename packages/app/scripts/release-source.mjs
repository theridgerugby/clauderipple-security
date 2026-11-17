// Source traceability for a local signed build. This records a clean Git snapshot; it does
// not assert a review, CI success, hermetic execution, or a SLSA/provenance attestation.
import fs from "node:fs";
import path from "node:path";
import { createHash } from "node:crypto";
import { spawnSync } from "node:child_process";
import { ReleaseGateError } from "./release-policy.mjs";

const MAX_LOCK_BYTES = 16 * 1024 * 1024;
const fail = message => { throw new ReleaseGateError(message); };
// These are build-consumed sources, including stage-runtime's source/resource inputs. Their
// ignored files cannot be accepted merely because a local or nested ignore rule hides them.
// Actual dependency/generated roots are outside these trees or explicitly excluded below.
const SOURCE_INPUTS = [
  "packages/router/src", "packages/cli/src", "packages/remote/src", "packages/remote/web",
  "packages/ui", "packages/mod", "packages/app/assets", "packages/app/src", "packages/app/scripts",
  "packages/router/package.json", "packages/cli/package.json", "packages/remote/package.json",
  "packages/app/package.json", "packages/app/tsconfig.json", "packages/app/build",
  "scripts", "bin", "package.json", "package-lock.json", "tsconfig.json", "tsconfig.build.json", "LICENSE", "README.md",
  ":(exclude)**/node_modules/**", ":(exclude)packages/mod/preview/**", ":(exclude)packages/mod/.claude-plugin/types/**",
  ":(exclude)packages/app/build/icon.png", ":(exclude)packages/app/build/icon.icns", ":(exclude,glob)packages/app/build/*.iconset/**",
];

function git(directory, args, run) {
  const env = { ...process.env };
  // Ambient repository/index/object selectors must not make Git inspect a different source.
  for (const name of Object.keys(env)) if (/^GIT_/i.test(name)) delete env[name];
  Object.assign(env, { GIT_OPTIONAL_LOCKS: "0", GIT_TERMINAL_PROMPT: "0", GIT_NO_REPLACE_OBJECTS: "1" });
  let result;
  try {
    result = run("git", ["--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false", ...args], {
      cwd: directory, env, encoding: "utf8", timeout: 10_000, maxBuffer: 8 * 1024 * 1024,
      windowsHide: true, shell: false, stdio: ["ignore", "pipe", "pipe"],
    });
  } catch { fail("Release source could not be verified with Git"); }
  if (result.error || result.status !== 0 || typeof result.stdout !== "string") {
    fail("Release source could not be verified with Git");
  }
  // Never include command output: dirty paths and local Git configuration are not diagnostics.
  return result.stdout;
}

function head(directory, run) {
  const fields = git(directory, ["log", "-1", "--format=%H%n%T", "--no-show-signature", "--no-patch", "HEAD", "--"], run).trim().split(/\r?\n/);
  if (fields.length !== 2 || !fields.every(value => /^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value)) || fields[0].length !== fields[1].length) {
    fail("Release source has no valid Git commit and tree");
  }
  return { commit: fields[0], tree: fields[1] };
}

function directoryIdentity(directory) {
  const stat = fs.lstatSync(directory, { bigint: true });
  if (!stat.isDirectory() || stat.isSymbolicLink()) fail("Release source must be an existing Git checkout directory");
  // An unavailable file ID cannot establish equality between two paths. A zero device ID
  // can be valid; the per-device directory ID must be present and nonzero.
  if (typeof stat.dev !== "bigint" || typeof stat.ino !== "bigint" || stat.ino <= 0n) {
    fail("Release source requires a stable file-system directory identity");
  }
  return `${stat.dev}:${stat.ino}`;
}

function canonicalDirectory(directory) {
  return path.normalize(fs.realpathSync.native(directory));
}

function lockDigest(directory) {
  const file = path.join(directory, "package-lock.json");
  const before = fs.lstatSync(file, { bigint: true });
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n || before.size > BigInt(MAX_LOCK_BYTES)) {
    fail("Release source requires a bounded regular package lockfile");
  }
  const fd = fs.openSync(file, fs.constants.O_RDONLY | (fs.constants.O_NOFOLLOW ?? 0) | (fs.constants.O_NONBLOCK ?? 0));
  try {
    const same = current => current.isFile() && !current.isSymbolicLink() && current.nlink === 1n &&
      ["dev", "ino", "size", "mtimeNs", "ctimeNs", "mode"].every(key => current[key] === before[key]);
    if (!same(fs.fstatSync(fd, { bigint: true }))) fail("Release lockfile changed while reading it");
    // Do not allow a concurrent writer to turn a stat-bounded read into an unbounded allocation.
    const bytes = Buffer.alloc(Number(before.size) + 1);
    let count = 0;
    while (count < bytes.length) {
      const received = fs.readSync(fd, bytes, count, bytes.length - count, null);
      if (received === 0) break;
      count += received;
    }
    if (count !== Number(before.size) || !same(fs.fstatSync(fd, { bigint: true })) || !same(fs.lstatSync(file, { bigint: true }))) {
      fail("Release lockfile changed while reading it");
    }
    return createHash("sha256").update(bytes.subarray(0, count)).digest("hex");
  } finally { fs.closeSync(fd); }
}

/** Read-only commands only. Generated/installed paths ignored by the repository stay allowed. */
export function captureReleaseSource(checkout, run = spawnSync) {
  try {
    const directory = canonicalDirectory(checkout);
    const identity = directoryIdentity(directory);
    const reported = git(directory, ["rev-parse", "--show-toplevel"], run).trim();
    // Git for Windows and Node can spell the same directory differently, including drive
    // and component case. Case folding would also merge distinct case-sensitive directories.
    // Resolve both paths natively, then require the same actual volume/file identity.
    if (!reported || !path.isAbsolute(reported) || directoryIdentity(canonicalDirectory(reported)) !== identity) {
      fail("Release source must be the Git checkout root");
    }
    const initial = head(directory, run);
    const entries = git(directory, ["ls-files", "-v", "-z"], run).split("\0").filter(Boolean);
    // assume-unchanged/skip-worktree can conceal tracked edits from status. A release checkout
    // must expose every tracked source to Git's ordinary cleanliness check.
    if (entries.some(entry => !entry.startsWith("H ")) || !entries.includes("H package-lock.json")) {
      fail("Release source must track its lockfile without hidden index entries");
    }
    if (git(directory, ["status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignore-submodules=none"], run) !== "") {
      fail("Release source checkout must be clean, including staged and untracked files");
    }
    // status also honors machine-local/global excludes, which are outside the committed tree.
    // Only repository .gitignore rules may hide generated paths from this extra source check.
    if (git(directory, ["ls-files", "--others", "-z", "--exclude-per-directory=.gitignore"], run) !== "") {
      fail("Release source checkout must be clean, including staged and untracked files");
    }
    // An untracked .gitignore can hide itself with '*'; a committed broad 'dist/' rule can
    // also hide new source that stage-runtime would copy. Inspect consumed inputs without
    // any ignore rules, leaving only the explicit non-source exclusions in SOURCE_INPUTS.
    if (git(directory, ["ls-files", "--others", "-z", "--", ...SOURCE_INPUTS], run) !== "") {
      fail("Release build inputs must contain only tracked source and reviewed assets");
    }
    const lockfileSha256 = lockDigest(directory);
    const final = head(directory, run);
    if (final.commit !== initial.commit || final.tree !== initial.tree || directoryIdentity(directory) !== identity) {
      fail("Release source changed while capturing its identity");
    }
    return Object.freeze({ directory, directoryIdentity: identity, ...initial, lockfileSha256 });
  } catch (error) {
    if (error instanceof ReleaseGateError) throw error;
    fail("Release source checkout or lockfile could not be verified");
  }
}

/** Check immediately before receipt promotion. An old signed candidate never approves new source. */
export function assertReleaseSourceUnchanged(checkout, expected, run = spawnSync) {
  const actual = captureReleaseSource(checkout, run);
  for (const key of ["directory", "directoryIdentity", "commit", "tree", "lockfileSha256"]) {
    if (actual[key] !== expected[key]) fail("Release source changed during the build; no release was approved");
  }
}

/** Keep machine-specific paths and any unproven CI/review status out of the published receipt. */
export function releaseSourceReceipt(source) {
  return Object.freeze({ commit: source.commit, tree: source.tree, lockfileSha256: source.lockfileSha256 });
}

/** Production consumes reviewed icon bytes; rendering new tracked assets is a developer step. */
export function prepareReleaseIcons(appDirectory) {
  const assets = path.join(appDirectory, "assets");
  try {
    const source = fs.lstatSync(assets);
    if (!source.isDirectory() || source.isSymbolicLink()) fail("Release requires the reviewed committed icon assets");
  } catch { fail("Release requires the reviewed committed icon assets"); }
  const output = path.join(appDirectory, "build");
  fs.mkdirSync(output, { recursive: true });
  const parent = fs.lstatSync(output);
  if (!parent.isDirectory() || parent.isSymbolicLink()) fail("Release icon output must be an independent build directory");
  for (const name of ["icon.png", "icon.icns"]) {
    const input = path.join(assets, name);
    try {
      const stat = fs.lstatSync(input);
      if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > MAX_LOCK_BYTES) fail("Release requires the reviewed committed icon assets");
    } catch { fail("Release requires the reviewed committed icon assets"); }
    const target = path.join(output, name);
    try {
      const old = fs.lstatSync(target);
      if (!old.isFile() || old.isSymbolicLink() || old.nlink !== 1) fail("Release icon output must be a regular generated file");
    } catch (error) { if (error.code !== "ENOENT") throw error; }
    fs.copyFileSync(input, target);
  }
}
