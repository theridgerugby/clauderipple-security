import { test, type TestContext } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { bundledInstaller, dropPowerShellShim, installKind, isNewer, latestVersion, runUpdate } from "../src/update.ts";
import { writePaths } from "../src/registration.ts";
import { runtime } from "../src/runtime.ts";
import { fileSymlinks, posixModes, posixPaths } from "../../../test/capabilities.ts";
import { pathToFileURL } from "node:url";

function fixture(t: TestContext) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "cr-update-"));
  t.after(() => fs.rmSync(root, { recursive: true, force: true }));
  const cli = path.join(root, "dist", "cli", "src", "index.js");
  const installerDir = path.join(root, "dist", "installers");
  fs.mkdirSync(installerDir, { recursive: true });
  // Deliberately inert fixtures. Every child process boundary in this file is mocked.
  fs.writeFileSync(path.join(installerDir, "install.sh"), "# bundled POSIX test fixture\n");
  fs.writeFileSync(path.join(installerDir, "install.ps1"), "# bundled Windows test fixture\r\n");
  return { root, cli, installerDir, rt: { node: process.execPath, env: { UPDATE_TEST_ENV: "retained" }, cli }, target: { kind: "script" as const, prefix: root } };
}

for (const platform of ["darwin", "linux", "win32"] as const) {
  test(`${platform} updates execute a private copy of the installed script without downloading code`, t => {
    const f = fixture(t);
    const source = bundledInstaller(f.cli, platform);
    const original = process.env.CLAUDERIPPLE_INSTALLER;
    process.env.CLAUDERIPPLE_INSTALLER = "https://example.invalid/unreviewed-script";
    t.after(() => { if (original === undefined) delete process.env.CLAUDERIPPLE_INSTALLER; else process.env.CLAUDERIPPLE_INSTALLER = original; });
    let copy: string | undefined;
    const calls: string[] = [];
    const result = runUpdate(f.target, f.rt, "clauderipple@1.2.3", {
      platform, tempDir: f.root,
      run: (program, args, options) => {
        calls.push(program);
        assert.equal(options.env.CLAUDERIPPLE_PREFIX, f.root);
        assert.equal(options.env.CLAUDERIPPLE_PACKAGE, "clauderipple@1.2.3");
        assert.equal(options.env.UPDATE_TEST_ENV, "retained");
        copy = args.at(-1)!;
        assert.notEqual(copy, source, "npm must not replace the script while the shell is still reading it");
        assert.deepEqual(fs.readFileSync(copy), fs.readFileSync(source));
        assert.equal(path.dirname(path.dirname(copy)), f.root);
        if (posixModes) {
          assert.equal(fs.statSync(copy).mode & 0o777, 0o600);
          assert.equal(fs.statSync(path.dirname(copy)).mode & 0o777, 0o700);
        }
        if (platform === "win32") {
          assert.equal(program, "powershell.exe");
          assert.deepEqual(args.slice(0, -1), ["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File"]);
        } else {
          assert.equal(program, "sh");
          assert.equal(args.length, 1);
        }
        return { status: 0 };
      },
    });
    assert.equal(result.ok, true);
    assert.equal(calls.length, 1, "no curl, remote PowerShell expression, or second installer path");
    assert.ok(copy);
    assert.equal(fs.existsSync(path.dirname(copy)), false, "private copy is removed after completion");
    assert.equal(fs.existsSync(source), true, "installed script remains untouched by the updater");
  });
}

test("a missing bundled installer fails closed without a remote fallback", t => {
  const f = fixture(t);
  fs.rmSync(bundledInstaller(f.cli, "linux"));
  const result = runUpdate(f.target, f.rt, "clauderipple@1.2.3", {
    platform: "linux", tempDir: f.root,
    run: () => assert.fail("must not start a downloader or shell"),
  });
  assert.equal(result.ok, false);
  assert.match(result.message, /no usable bundled installer/);
  assert.deepEqual(fs.readdirSync(f.root), ["dist"]);
});

test("an empty or non-regular bundled installer is refused", t => {
  const f = fixture(t);
  const file = bundledInstaller(f.cli, "linux");
  const options = { platform: "linux" as const, tempDir: f.root, run: () => assert.fail("must not start a shell") };
  fs.writeFileSync(file, "");
  assert.equal(runUpdate(f.target, f.rt, "clauderipple@1.2.3", options).ok, false);
  fs.rmSync(file); fs.mkdirSync(file);
  assert.equal(runUpdate(f.target, f.rt, "clauderipple@1.2.3", options).ok, false);
});

test("a bundled installer cannot be a symbolic link", { skip: !fileSymlinks }, t => {
  const f = fixture(t);
  const file = bundledInstaller(f.cli, "linux");
  fs.rmSync(file); fs.symlinkSync(bundledInstaller(f.cli, "win32"), file, "file");
  assert.equal(runUpdate(f.target, f.rt, "clauderipple@1.2.3", { platform: "linux", run: () => assert.fail("must not follow an installer symlink") }).ok, false);
});

test("a bundled installer cannot be hard-linked or unexpectedly large", t => {
  const f = fixture(t);
  const file = bundledInstaller(f.cli, "linux");
  const linked = path.join(f.root, "linked-installer");
  fs.linkSync(file, linked);
  const options = { platform: "linux" as const, tempDir: f.root, run: () => assert.fail("must not execute an aliased or oversized script") };
  assert.equal(runUpdate(f.target, f.rt, "clauderipple@1.2.3", options).ok, false);
  fs.rmSync(linked);
  fs.writeFileSync(file, Buffer.alloc(1024 * 1024 + 1));
  assert.equal(runUpdate(f.target, f.rt, "clauderipple@1.2.3", options).ok, false);
});

test("a failed or interrupted installer cleans up its private copy and reports failure", t => {
  const f = fixture(t);
  for (const exit of [{ status: 7 }, { status: null, signal: "SIGTERM" as const }]) {
    let copy = "";
    const result = runUpdate(f.target, f.rt, "clauderipple@1.2.3", { platform: "linux", tempDir: f.root,
      run: (_program, args) => { copy = args[0]!; return exit; },
    });
    assert.equal(result.ok, false);
    assert.match(result.message, /installer exited/);
    assert.equal(fs.existsSync(path.dirname(copy)), false);
  }
  assert.throws(() => runUpdate(f.target, f.rt, "clauderipple@1.2.3", { platform: "linux", tempDir: f.root,
    run: () => { throw new Error("cannot start fixture shell"); },
  }), /cannot start fixture shell/);
  assert.deepEqual(fs.readdirSync(f.root), ["dist"]);
});

test("updates reject unpinned tags, foreign packages and alternate download sources", t => {
  const f = fixture(t);
  for (const spec of ["", " ", "clauderipple", "clauderipple@latest", "clauderipple@next", "clauderipple@1.2", "other@1.2.3", "https://example.invalid/package.tgz", "file:/tmp/clauderipple.tgz", "clauderipple@1.2.3\n", "clauderipple@1.2.3-..", "clauderipple@1.2.3-01", "clauderipple@1.2.3+.", "clauderipple@999999999999999999.0.0"]) {
    for (const kind of ["script", "npm"] as const) {
      const result = runUpdate({ ...f.target, kind }, f.rt, spec, { run: () => assert.fail("invalid selection must execute nothing") });
      assert.equal(result.ok, false, spec);
      assert.match(result.message, /specific ClaudeRipple version/);
    }
  }
});

test("npm updates use the resolved package pin and run setup only after installation succeeds", t => {
  const f = fixture(t);
  const calls: string[][] = [];
  const result = runUpdate({ kind: "npm", prefix: f.root }, f.rt, "clauderipple@1.2.3-rc.1", {
    npmCli: "/fake/npm-cli.js",
    run: (program, args, options) => {
      assert.equal(program, f.rt.node);
      assert.equal(options.env.UPDATE_TEST_ENV, "retained");
      calls.push(args);
      return { status: 0 };
    },
  });
  assert.equal(result.ok, true);
  assert.deepEqual(calls, [["/fake/npm-cli.js", "install", "--global", "--prefix", f.root, "--registry", "https://registry.npmjs.org", "--ignore-scripts", "--loglevel", "error", "clauderipple@1.2.3-rc.1"], [f.cli, "install"]]);
  let invoked = 0;
  const failed = runUpdate({ kind: "npm", prefix: f.root }, f.rt, "clauderipple@1.2.3", { npmCli: "/fake/npm-cli.js", run: () => { invoked++; return { status: 1 }; } });
  assert.equal(failed.ok, false);
  assert.equal(invoked, 1);
});

test("npm metadata must name an exact version before an update can be selected", async () => {
  for (const version of ["1.2.3", "1.2.3-rc.1", "1.2.3-0.2.alpha-1+build.001"]) {
    assert.equal(await latestVersion(async () => Response.json({ version })), version);
  }
  for (const version of [undefined, null, "latest", "1.2.3\n", "https://example.invalid/script", "1.2", "1.2.3-..", "1.2.3-01", "1.2.3+.", "999999999999999999.0.0"]) {
    await assert.rejects(latestVersion(async () => Response.json({ version })), /valid, pinned version/);
  }
});

test("update discovery stays on the public npm registry without following redirects", async () => {
  await latestVersion(async (url, options) => {
    assert.equal(url, "https://registry.npmjs.org/clauderipple/latest");
    assert.equal(options?.redirect, "error");
    return Response.json({ version: "1.2.3" });
  });
});

test("npm build includes both reviewed installers verbatim", async t => {
  const f = fixture(t);
  const repo = path.resolve(import.meta.dirname, "../../..");
  const output = path.join(f.root, "packaged-dist");
  const build = await import(pathToFileURL(path.join(repo, "scripts/build-npm.mjs")).href) as { bundleInstallers(sourceRoot: string, outputRoot: string): void };
  build.bundleInstallers(repo, output);
  for (const name of ["install.sh", "install.ps1"]) {
    assert.deepEqual(fs.readFileSync(path.join(output, "installers", name)), fs.readFileSync(path.join(repo, "scripts", name)));
  }
});

test("a one-off script prefix is remembered without its original environment", { skip: !posixPaths }, () => {
  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), "cr-prefix-"));
  const repo = path.join(prefix, "lib", "node_modules", "clauderipple");
  const rt = { ...runtime(), packaged: false, repo, cli: path.join(repo, "dist", "cli", "src", "index.js") };
  try {
    fs.writeFileSync(path.join(prefix, "clauderipple-install.json"), JSON.stringify({ kind: "script", prefix }));
    const target = installKind(rt, { platform: "darwin", env: {}, home: path.join(prefix, "unrelated-home") });
    assert.deepEqual(target, { kind: "script", prefix });
    const recorded = JSON.parse(fs.readFileSync(writePaths(rt, path.join(prefix, "state")), "utf8"));
    assert.deepEqual(recorded.install, target);
    fs.rmSync(path.join(prefix, "clauderipple-install.json"));
    assert.deepEqual(installKind(rt, { env: {}, stateHome: path.join(prefix, "state") }), target, "paths.json also retains the install method");
    const calls: string[] = [];
    if (target.kind !== "script") assert.fail("a pinned-Node wrapper must be restored by its bundled installer");
    const bundled = bundledInstaller(rt.cli, "darwin");
    fs.mkdirSync(path.dirname(bundled), { recursive: true }); fs.writeFileSync(bundled, "# inert installer fixture\n");
    runUpdate(target, rt, "clauderipple@1.2.3", { platform: "darwin", tempDir: prefix, run: (program, _args, opts) => {
      calls.push(program);
      assert.equal(opts.env.CLAUDERIPPLE_PREFIX, prefix);
      return { status: 22 };
    } });
    assert.deepEqual(calls, ["sh"], "takes the bundled installer path, never a downloaded script");
  } finally {
    fs.rmSync(prefix, { recursive: true, force: true });
  }
});

test("Windows script updates remove inherited PSModulePath after merging their environment", t => {
  const f = fixture(t);
  const saved = process.env.PSModulePath;
  process.env.PSModulePath = "C:\\Program Files\\PowerShell\\Modules";
  try {
    let called = false;
    const result = runUpdate({ ...f.target, prefix: "C:\\Ripple" }, f.rt, "clauderipple@1.2.3", {
      platform: "win32", tempDir: f.root,
      run: (program, _args, options) => {
        called = true;
        assert.equal(program, "powershell.exe");
        assert.equal(Object.keys(options.env).some(key => key.toLowerCase() === "psmodulepath"), false);
        assert.equal(options.env.CLAUDERIPPLE_PREFIX, "C:\\Ripple");
        assert.equal(options.env.CLAUDERIPPLE_PACKAGE, "clauderipple@1.2.3");
        return { status: 0 };
      },
    });
    assert.equal(called, true);
    assert.equal(result.ok, true);
  } finally {
    if (saved === undefined) delete process.env.PSModulePath;
    else process.env.PSModulePath = saved;
  }
});

test("versions compare by number, not as text", () => {
  assert.equal(isNewer("0.6.0", "0.5.1"), true);
  assert.equal(isNewer("0.10.0", "0.9.9"), true);
  assert.equal(isNewer("0.5.1", "0.5.1"), false);
  assert.equal(isNewer("0.5.0", "0.5.1"), false);
  assert.equal(isNewer("v1.0.0", "0.9.0"), true);
});

// The install scripts and `npm install -g` put the package in the same layout; only the prefix
// says which one did, and each must be updated its own way (update.ts).
test("an install is recognised by where its files are", () => {
  if (posixPaths) {
    const home = "/Users/me";
    const js = (repo: string) => ({ packaged: false, cli: `${repo}/dist/cli/src/index.js`, repo });
    assert.deepEqual(installKind(js("/Users/me/.clauderipple/lib/node_modules/clauderipple"), { platform: "darwin", env: {}, home }), { kind: "script", prefix: "/Users/me/.clauderipple" });
    assert.deepEqual(installKind(js("/opt/homebrew/lib/node_modules/clauderipple"), { platform: "darwin", env: {}, home }), { kind: "npm", prefix: "/opt/homebrew" });
    assert.deepEqual(installKind(js("/srv/cr/lib/node_modules/clauderipple"), { platform: "linux", env: { CLAUDERIPPLE_PREFIX: "/srv/cr" }, home }), { kind: "script", prefix: "/srv/cr" });
    assert.equal(installKind(js("/Users/me/project/node_modules/clauderipple"), { platform: "darwin", env: {}, home }).kind, "unknown");
    assert.equal(installKind({ packaged: false, cli: "/Users/me/src/ClaudeRipple/packages/cli/src/index.ts", repo: "/Users/me/src/ClaudeRipple" }, { platform: "darwin", env: {}, home }).kind, "checkout");
  }
  assert.equal(installKind({ packaged: true, cli: "x", repo: "y" }).kind, "packaged");

  const win = { packaged: false, cli: "C:\\Users\\me\\.clauderipple\\node_modules\\clauderipple\\dist\\cli\\src\\index.js", repo: "C:\\Users\\me\\.clauderipple\\node_modules\\clauderipple" };
  assert.deepEqual(installKind(win, { platform: "win32", env: {}, home: "C:\\Users\\ME" }), { kind: "script", prefix: "C:\\Users\\me\\.clauderipple" });
  assert.equal(installKind({ ...win, repo: "C:\\Users\\me\\AppData\\Roaming\\npm\\node_modules\\clauderipple" }, { platform: "win32", env: {}, home: "C:\\Users\\me" }).kind, "npm");
});

// PowerShell runs npm's clauderipple.ps1 before the .cmd, and its default policy refuses it (#62).
test("install removes npm's PowerShell shim on Windows, and only there", () => {
  const prefix = fs.mkdtempSync(path.join(os.tmpdir(), "cr-shim-"));
  try {
    const ps1 = path.join(prefix, "clauderipple.ps1");
    fs.writeFileSync(path.join(prefix, "clauderipple.cmd"), "");
    fs.writeFileSync(ps1, "");
    assert.equal(dropPowerShellShim({ kind: "npm", prefix }, "darwin"), null);
    assert.equal(dropPowerShellShim({ kind: "checkout" }, "win32"), null);
    assert.equal(fs.existsSync(ps1), true);
    assert.equal(dropPowerShellShim({ kind: "npm", prefix }, "win32"), ps1);
    assert.equal(fs.existsSync(ps1), false);
    assert.equal(fs.existsSync(path.join(prefix, "clauderipple.cmd")), true);
    // With no .cmd beside it, the .ps1 is the only way in and stays.
    fs.rmSync(path.join(prefix, "clauderipple.cmd"));
    fs.writeFileSync(ps1, "");
    assert.equal(dropPowerShellShim({ kind: "script", prefix }, "win32"), null);
    assert.equal(fs.existsSync(ps1), true);
  } finally {
    fs.rmSync(prefix, { recursive: true, force: true });
  }
});
