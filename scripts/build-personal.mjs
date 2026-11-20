// Precompiled personal installation. Build only the Desktop/recovery entrypoint closure and
// the on-demand native UI. No Remote host/web, release staging, downloads or OS installation.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import ts from "typescript";
import { verifyPersonalInstall } from "./check-personal-install.mjs";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
export const PERSONAL_ENTRYPOINTS = [
  "packages/router/src/index.ts", "packages/cli/src/index.ts",
  // These are launched by filename, so a static import closure alone misses them.
  "packages/cli/src/admin-bridge.ts", "packages/cli/src/watchdog-port.ts",
];
export const REQUIRED_PERSONAL_OUTPUTS = [
  "router/src/index.js", "cli/src/index.js", "cli/src/admin-bridge.js", "cli/src/watchdog-port.js",
  "app/dist/main.js", "app/dist/preload.js", "app/package.json", "ui/index.html",
];

function compile(configFile, changes) {
  const base = path.dirname(configFile);
  const source = ts.readConfigFile(configFile, ts.sys.readFile);
  if (source.error) throw new Error(ts.flattenDiagnosticMessageText(source.error.messageText, "\n"));
  const raw = { ...source.config, ...changes,
    compilerOptions: { ...source.config.compilerOptions, ...changes.compilerOptions } };
  const config = ts.parseJsonConfigFileContent(raw, ts.sys, base);
  const program = ts.createProgram(config.fileNames, config.options);
  const diagnostics = [...config.errors, ...ts.getPreEmitDiagnostics(program)];
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => base, getCanonicalFileName: filename => filename, getNewLine: () => "\n",
  }));
  const result = program.emit();
  if (result.emitSkipped || result.diagnostics.length) throw new Error("Personal TypeScript build did not emit a complete runtime");
}

function treeFiles(root) {
  const stat = fs.lstatSync(root);
  if (!stat.isDirectory() || stat.isSymbolicLink()) throw new Error(`Build input/output is not an independent directory: ${root}`);
  const files = [];
  for (const item of fs.readdirSync(root, { withFileTypes: true })) {
    const filename = path.join(root, item.name);
    if (item.isSymbolicLink()) throw new Error(`Build input/output contains a symbolic link: ${filename}`);
    if (item.isDirectory()) files.push(...treeFiles(filename));
    else if (item.isFile()) files.push(filename);
    else throw new Error(`Build input/output is not a regular file: ${filename}`);
  }
  return files;
}

/** Verify emitted imports rather than relying on the checkout's larger development install. */
export function verifyBuiltPersonalRuntime(output) {
  for (const relative of REQUIRED_PERSONAL_OUTPUTS) {
    if (!fs.statSync(path.join(output, relative)).isFile()) throw new Error(`Missing personal runtime output: ${relative}`);
  }
  for (const excluded of ["remote/src/main.js", "remote/web", "mod/.claude-plugin", "installers"]) {
    if (fs.existsSync(path.join(output, excluded))) throw new Error(`Non-personal output leaked into build: ${excluded}`);
  }
  const files = treeFiles(output);
  for (const filename of files) {
    const relative = path.relative(output, filename).split(path.sep).join("/");
    if (!/^(?:cli|router|remote|mod)\//.test(relative) || !filename.endsWith(".js")) continue;
    const source = ts.createSourceFile(filename, fs.readFileSync(filename, "utf8"), ts.ScriptTarget.Latest, true, ts.ScriptKind.JS);
    const specifiers = [];
    function visit(node) {
      if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier && ts.isStringLiteral(node.moduleSpecifier)) specifiers.push(node.moduleSpecifier.text);
      if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || (ts.isIdentifier(node.expression) && node.expression.text === "require")) && node.arguments[0] && ts.isStringLiteral(node.arguments[0])) specifiers.push(node.arguments[0].text);
      ts.forEachChild(node, visit);
    }
    visit(source);
    for (const specifier of specifiers) {
      if (specifier.startsWith("node:")) continue;
      if (specifier.startsWith(".")) {
        const target = path.resolve(path.dirname(filename), specifier);
        if (!target.startsWith(`${path.resolve(output)}${path.sep}`) || !fs.existsSync(target) || !fs.statSync(target).isFile()) throw new Error(`Missing or escaping emitted import: ${relative} -> ${specifier}`);
      } else if (!["proper-lockfile", "undici"].includes(specifier)) {
        throw new Error(`Unexpected personal runtime package: ${relative} -> ${specifier}`);
      }
    }
  }
  return { files: files.length, bytes: files.reduce((sum, filename) => sum + fs.statSync(filename).size, 0) };
}

function copyAssets(source, destination) {
  treeFiles(source); // Reject links rather than following an unexpected checkout asset outside it.
  fs.cpSync(source, destination, { recursive: true, errorOnExist: true, force: false });
}

export function buildPersonal(root = checkout) {
  const report = verifyPersonalInstall(root);
  const app = path.join(root, "packages/app");
  for (const script of ["sync-private-acl.mjs", "sync-admin-transport.mjs", "sync-bounded-exec.mjs"]) {
    execFileSync(process.execPath, [path.join(app, "scripts", script), "--check"], { cwd: app, stdio: "inherit" });
  }
  const stage = fs.mkdtempSync(path.join(root, "personal-build-"));
  const output = path.join(stage, "dist");
  const destination = path.join(root, "dist");
  const previous = path.join(stage, "previous-dist");
  let oldMoved = false;
  try {
    compile(path.join(root, "tsconfig.json"), { include: [], files: PERSONAL_ENTRYPOINTS,
      compilerOptions: { noEmit: false, rootDir: path.join(root, "packages"), outDir: output, declaration: false, sourceMap: false } });
    compile(path.join(app, "tsconfig.json"), { compilerOptions: { noEmit: false, outDir: path.join(output, "app/dist"), declaration: false, sourceMap: false } });
    copyAssets(path.join(root, "packages/ui"), path.join(output, "ui"));
    copyAssets(path.join(app, "assets"), path.join(output, "app/assets"));
    const { version } = JSON.parse(fs.readFileSync(path.join(root, "package.json"), "utf8"));
    fs.writeFileSync(path.join(output, "app/package.json"), JSON.stringify({ private: true, version, type: "commonjs" }, null, 2) + "\n");
    const built = verifyBuiltPersonalRuntime(output);
    if (fs.existsSync(destination)) {
      // Only replace the recognized generated build, never a link or unrelated directory.
      const stat = fs.lstatSync(destination);
      if (!stat.isDirectory() || stat.isSymbolicLink() || !fs.existsSync(path.join(destination, "cli/src/index.js")) || !fs.existsSync(path.join(destination, "router/src/index.js"))) throw new Error("Existing dist is not a recognized generated runtime; it was left unchanged");
      fs.renameSync(destination, previous);
      oldMoved = true;
    }
    try { fs.renameSync(output, destination); }
    catch (error) {
      if (oldMoved) { fs.renameSync(previous, destination); oldMoved = false; }
      throw error;
    }
    // previous-dist was the validated generated build just moved by this invocation.
    if (oldMoved) { fs.rmSync(previous, { recursive: true }); oldMoved = false; }
    return { ...report, buildFiles: built.files, buildBytes: built.bytes };
  } finally {
    // A failed restore must retain the previous build for manual recovery.
    if (!oldMoved) fs.rmSync(stage, { recursive: true, force: true });
  }
}

if (import.meta.main) {
  try {
    const report = buildPersonal();
    console.log(`Personal compiled build verified: ${report.packages} dependency packages; ${report.buildFiles} output files (${report.buildBytes} bytes).`);
    console.log("Entry point: node dist/cli/src/index.js");
  } catch (error) { console.error(error.message); process.exitCode = 1; }
}
