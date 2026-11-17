import test, { type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync, spawnSync, type SpawnSyncOptionsWithStringEncoding } from "node:child_process";
import { createHash } from "node:crypto";
import {
  captureReleaseSource, assertReleaseSourceUnchanged, releaseSourceReceipt, prepareReleaseIcons,
} from "../scripts/release-source.mjs";

const checkout = path.resolve(import.meta.dirname, "../../..");
const ignored = fs.readFileSync(path.join(checkout, ".gitignore"), "utf8");

function git(directory: string, ...args: string[]): string {
  const env = { ...process.env };
  for (const name of Object.keys(env)) if (/^GIT_/i.test(name)) delete env[name];
  return execFileSync("git", ["-c", `core.hooksPath=${path.join(directory, "disabled-fixture-hooks")}`,
    "-c", "commit.gpgsign=false", "-c", "user.name=Release Fixture", "-c", "user.email=release-fixture@example.invalid",
    ...args], { cwd: directory, env, encoding: "utf8", timeout: 10_000, windowsHide: true, stdio: ["ignore", "pipe", "pipe"] }).trim();
}

function write(directory: string, relative: string, value: string): void {
  const file = path.join(directory, relative);
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, value);
}

function fixture(t: TestContext): string {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-release-source-"));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  git(directory, "init", "--quiet", "--template=");
  write(directory, ".gitignore", ignored);
  write(directory, "package-lock.json", '{"name":"release-fixture","lockfileVersion":3}\n');
  write(directory, "src/main.js", 'console.log("reviewed fixture");\n');
  for (const name of ["icon.png", "icon.icns", "icon.ico"]) write(directory, `packages/app/assets/${name}`, `reviewed-${name}`);
  git(directory, "add", ".gitignore", "package-lock.json", "src/main.js", "packages/app/assets");
  // Commits are confined to disposable fixture repositories, never the shared checkout.
  git(directory, "commit", "--quiet", "-m", "Reviewed fixture source");
  return directory;
}

test("clean source records the exact Git commit/tree and lock digest without a CI or attestation claim", t => {
  const directory = fixture(t);
  const source = captureReleaseSource(directory);
  assert.equal(source.commit, git(directory, "rev-parse", "HEAD"));
  assert.equal(source.tree, git(directory, "rev-parse", "HEAD^{tree}"));
  assert.equal(source.lockfileSha256, createHash("sha256").update(fs.readFileSync(path.join(directory, "package-lock.json"))).digest("hex"));
  assert.deepEqual(Object.keys(releaseSourceReceipt(source)).sort(), ["commit", "lockfileSha256", "tree"]);
  assert.equal(Object.isFrozen(source), true);
  assert.doesNotThrow(() => assertReleaseSourceUnchanged(directory, source));
});

for (const kind of ["tracked", "staged", "untracked"] as const) {
  test(`release rejects ${kind} source dirt before and after a build`, t => {
    const directory = fixture(t);
    const source = captureReleaseSource(directory);
    write(directory, kind === "untracked" ? "src/extra.js" : "src/main.js", "unreviewed fixture change\n");
    if (kind === "staged") git(directory, "add", "src/main.js");
    assert.throws(() => captureReleaseSource(directory), /must be clean/);
    assert.throws(() => assertReleaseSourceUnchanged(directory, source), /must be clean/);
  });
}

for (const kind of ["info/exclude", "core.excludesFile"] as const) {
  test(`machine-local ${kind} cannot hide untracked source from the release snapshot`, t => {
    const directory = fixture(t);
    const source = captureReleaseSource(directory);
    write(directory, "src/unreviewed.ts", "untracked source hidden only on this machine\n");
    const exclude = path.join(directory, ".git", kind === "info/exclude" ? "info/exclude" : "fixture-global-excludes");
    fs.mkdirSync(path.dirname(exclude), { recursive: true });
    fs.writeFileSync(exclude, "src/unreviewed.ts\n");
    if (kind === "core.excludesFile") git(directory, "config", "core.excludesFile", exclude);
    assert.equal(git(directory, "status", "--porcelain", "--untracked-files=all"), "");
    assert.throws(() => captureReleaseSource(directory), /must be clean/);
    assert.throws(() => assertReleaseSourceUnchanged(directory, source), /must be clean/);
  });
}

test("an untracked nested ignore rule cannot conceal build-consumed source", t => {
  const directory = fixture(t);
  write(directory, "packages/router/src/hidden/.gitignore", "*\n");
  write(directory, "packages/router/src/hidden/extra.ts", "unreviewed source\n");
  assert.equal(git(directory, "status", "--porcelain", "--untracked-files=all"), "");
  assert.equal(git(directory, "ls-files", "--others", "-z", "--exclude-per-directory=.gitignore"), "");
  assert.throws(() => captureReleaseSource(directory), /only tracked source/);
});

test("a broad committed dist ignore cannot conceal extra files copied with runtime source", t => {
  const directory = fixture(t);
  write(directory, "packages/router/src/dist/extra.ts", "unreviewed source\n");
  assert.equal(git(directory, "status", "--porcelain", "--untracked-files=all"), "");
  assert.throws(() => captureReleaseSource(directory), /only tracked source/);
});

test("an untracked build ignore cannot conceal auto-discovered installer scripts", t => {
  const directory = fixture(t);
  write(directory, "packages/app/build/.gitignore", "*\n");
  write(directory, "packages/app/build/installer.nsh", "unreviewed installer fixture\n");
  assert.equal(git(directory, "status", "--porcelain", "--untracked-files=all"), "");
  assert.throws(() => captureReleaseSource(directory), /only tracked source/);
});

test("ignored generated outputs and committed icon staging do not dirty the reviewed source", t => {
  const directory = fixture(t);
  const source = captureReleaseSource(directory);
  const app = path.join(directory, "packages/app");
  for (const relative of ["node_modules/fixture/index.js", "dist/cli/index.js", "packages/app/dist/main.js",
    "packages/app/release/.candidate-mac-fixture/app", "packages/app/release-dev/app",
    "packages/app/release-native/runtime/mac/x64/native-runtime.json", "packages/app/build/fixture.iconset/icon.png",
    "packages/mod/.claude-plugin/types/generated.d.ts"]) {
    write(directory, relative, "generated fixture\n");
  }
  prepareReleaseIcons(app);
  for (const name of ["icon.png", "icon.icns"]) {
    assert.equal(fs.readFileSync(path.join(app, "build", name), "utf8"), `reviewed-${name}`);
    assert.equal(fs.readFileSync(path.join(app, "assets", name), "utf8"), `reviewed-${name}`);
  }
  assert.equal(git(directory, "status", "--porcelain"), "");
  assert.doesNotThrow(() => assertReleaseSourceUnchanged(directory, source));
});

test("production icon preparation refuses missing reviewed assets without redrawing source", t => {
  const directory = fixture(t);
  const app = path.join(directory, "packages/app");
  fs.unlinkSync(path.join(app, "assets/icon.icns"));
  const before = fs.readdirSync(path.join(app, "assets")).map(name => [name, fs.readFileSync(path.join(app, "assets", name))]);
  assert.throws(() => prepareReleaseIcons(app), /requires the reviewed committed icon assets/);
  const after = fs.readdirSync(path.join(app, "assets")).map(name => [name, fs.readFileSync(path.join(app, "assets", name))]);
  assert.deepEqual(after, before);
});

test("a clean HEAD movement is rejected even if its tree is unchanged", t => {
  const directory = fixture(t);
  const source = captureReleaseSource(directory);
  git(directory, "commit", "--quiet", "--allow-empty", "-m", "Different source identity");
  const after = captureReleaseSource(directory);
  assert.equal(after.tree, source.tree);
  assert.notEqual(after.commit, source.commit);
  assert.throws(() => assertReleaseSourceUnchanged(directory, source), /changed during the build/);
});

test("a newly committed tree or lockfile cannot inherit the preceding build receipt", t => {
  const directory = fixture(t);
  const source = captureReleaseSource(directory);
  write(directory, "package-lock.json", '{"name":"changed-fixture","lockfileVersion":3}\n');
  git(directory, "add", "package-lock.json");
  git(directory, "commit", "--quiet", "-m", "Changed reviewed tree");
  const after = captureReleaseSource(directory);
  assert.notEqual(after.tree, source.tree);
  assert.notEqual(after.lockfileSha256, source.lockfileSha256);
  assert.throws(() => assertReleaseSourceUnchanged(directory, source), /changed during the build/);
});

test("missing Git, failed or oversized command output and non-Git input fail with safe diagnostics", t => {
  const directory = fixture(t);
  const privateOutput = "PRIVATE-FIXTURE-PATH-OR-CONFIG";
  for (const run of [
    () => ({ status: null, error: Object.assign(new Error(privateOutput), { code: "ENOENT" }), stdout: "", stderr: privateOutput }),
    () => ({ status: 1, stdout: privateOutput, stderr: privateOutput }),
    () => ({ status: null, error: Object.assign(new Error(privateOutput), { code: "ENOBUFS" }), stdout: privateOutput }),
    () => { throw new Error(privateOutput); },
  ]) assert.throws(() => captureReleaseSource(directory, run), error => /could not be verified/.test(String(error)) && !String(error).includes(privateOutput));
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "ripple-nongit-source-"));
  t.after(() => fs.rmSync(outside, { recursive: true, force: true }));
  write(outside, "package-lock.json", "{}\n");
  assert.throws(() => captureReleaseSource(outside), /could not be verified/);
  assert.throws(() => captureReleaseSource(path.join(directory, "src")), /checkout root/);
});

test("moving the checked-out source directory prevents receipt promotion", t => {
  const directory = fixture(t);
  const source = captureReleaseSource(directory);
  const moved = `${directory}-moved`;
  t.after(() => fs.rmSync(moved, { recursive: true, force: true }));
  fs.renameSync(directory, moved);
  assert.throws(() => assertReleaseSourceUnchanged(directory, source), /could not be verified/);
  assert.throws(() => assertReleaseSourceUnchanged(moved, source), /changed during the build/);
});

for (const flag of ["--assume-unchanged", "--skip-worktree"]) {
  test(`hidden index state ${flag} cannot conceal dirty source`, t => {
    const directory = fixture(t);
    git(directory, "update-index", flag, "src/main.js");
    write(directory, "src/main.js", "hidden change\n");
    assert.throws(() => captureReleaseSource(directory), /hidden index entries/);
  });
}

test("Git inspection uses bounded fixed read-only commands without ambient repository selectors", t => {
  const directory = fixture(t);
  const commands: string[][] = [];
  const previous = process.env.GIT_WORK_TREE;
  const previousLower = process.env.git_work_tree;
  process.env.GIT_WORK_TREE = path.join(directory, "wrong-tree");
  process.env.git_work_tree = path.join(directory, "another-wrong-tree");
  try {
    captureReleaseSource(directory, (executable: string, args: string[], options: SpawnSyncOptionsWithStringEncoding) => {
      assert.equal(executable, "git");
      assert.deepEqual(args.slice(0, 5), ["--no-pager", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false"]);
      assert.equal(options.cwd, fs.realpathSync(directory));
      assert.equal(options.shell, false);
      assert.equal(options.timeout, 10_000);
      assert.equal(options.maxBuffer, 8 * 1024 * 1024);
      assert.equal(options.env!.GIT_WORK_TREE, undefined);
      assert.equal(options.env!.git_work_tree, undefined);
      assert.equal(options.env!.GIT_OPTIONAL_LOCKS, "0");
      assert.equal(options.env!.GIT_TERMINAL_PROMPT, "0");
      assert.equal(options.env!.GIT_NO_REPLACE_OBJECTS, "1");
      commands.push(args.slice(5));
      return spawnSync(executable, args, options);
    });
  } finally {
    if (previous === undefined) delete process.env.GIT_WORK_TREE;
    else process.env.GIT_WORK_TREE = previous;
    if (previousLower === undefined) delete process.env.git_work_tree;
    else process.env.git_work_tree = previousLower;
  }
  assert.deepEqual(commands.map(args => args[0]), ["rev-parse", "log", "ls-files", "status", "ls-files", "ls-files", "log"]);
});

test("release captures source before signer access and rechecks before writing or promoting its receipt", () => {
  const source = fs.readFileSync(path.join(checkout, "packages/app/scripts/release.mjs"), "utf8");
  assert.ok(source.indexOf("const source = captureReleaseSource(checkout)") < source.indexOf("verifyConfiguredSigner(plan)"));
  assert.ok(source.indexOf("const source = captureReleaseSource(checkout)") < source.indexOf("require(\"electron-builder\")"));
  assert.ok(source.indexOf("await build(") < source.indexOf("assertReleaseSourceUnchanged(checkout, source)"));
  assert.ok(source.indexOf("assertReleaseSourceUnchanged(checkout, source)") < source.indexOf("fs.writeFileSync(path.join(staging, \"release-verification.json\")"));
  assert.ok(source.indexOf("assertReleaseSourceUnchanged(checkout, source)") < source.indexOf("fs.renameSync(staging, verified)"));
  assert.match(source, /source: releaseSourceReceipt\(source\)/);
  assert.doesNotMatch(source, /make-icons\.mts|ciPassed:|slsa:|attestation:/);
});
