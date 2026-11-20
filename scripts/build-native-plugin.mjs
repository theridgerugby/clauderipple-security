// Build the experimental official-mod proof into a fresh, inert directory.
// Never installs a plugin, changes settings, trusts a CA or starts a service.
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import ts from "typescript";

const checkout = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const builtins = new Set(["node:crypto", "node:https", "node:tls", "node:stream"]);
const sourceAssets = [".claude-plugin/plugin.json", "hooks/hooks.json", "hooks/register.ts"];
const entry = "gemini-native/src/request.js";

function regularFile(root, relative) {
  const base = path.resolve(root);
  const target = path.resolve(base, relative);
  if (!target.startsWith(base + path.sep)) throw new Error("Build file escapes its root");
  const segments = path.relative(base, target).split(path.sep);
  let current = base;
  if (fs.lstatSync(current).isSymbolicLink()) throw new Error("Build root is linked");
  for (const segment of segments) {
    current = path.join(current, segment);
    if (fs.lstatSync(current).isSymbolicLink()) throw new Error("Build input contains a symbolic link");
  }
  const info = fs.lstatSync(target);
  if (!info.isFile() || info.nlink !== 1) throw new Error("Build file is not an independent regular file");
  return target;
}

function imports(filename, text) {
  const source = ts.createSourceFile(filename, text, ts.ScriptTarget.Latest, true, filename.endsWith(".ts") ? ts.ScriptKind.TS : ts.ScriptKind.JS);
  if (source.parseDiagnostics.length) throw new Error("Native plugin source does not parse");
  const specifiers = [];
  function visit(node) {
    if ((ts.isImportDeclaration(node) || ts.isExportDeclaration(node)) && node.moduleSpecifier) {
      if (!ts.isStringLiteral(node.moduleSpecifier)) throw new Error("Non-literal plugin import");
      if (node.isTypeOnly || ts.isImportDeclaration(node) && node.importClause?.isTypeOnly) return;
      specifiers.push(node.moduleSpecifier.text);
    }
    if (ts.isCallExpression(node) && (node.expression.kind === ts.SyntaxKind.ImportKeyword || ts.isIdentifier(node.expression) && node.expression.text === "require")) throw new Error("Dynamic plugin imports are not permitted");
    ts.forEachChild(node, visit);
  }
  visit(source);
  return specifiers;
}

/** This proof has no npm runtime package, network listener or background-worker import. */
export function runtimeClosure(output, initial = entry) {
  const files = new Set();
  const pending = [initial];
  while (pending.length) {
    const relative = pending.pop();
    if (files.has(relative)) continue;
    const filename = regularFile(output, relative);
    if (!filename.endsWith(".js")) throw new Error("Native helper closure must contain compiled JavaScript");
    files.add(relative);
    for (const specifier of imports(filename, fs.readFileSync(filename, "utf8"))) {
      if (builtins.has(specifier)) continue;
      if (!specifier.startsWith(".")) throw new Error("Native helper has an unreviewed runtime dependency");
      const target = path.relative(output, path.resolve(path.dirname(filename), specifier)).split(path.sep).join("/");
      regularFile(output, target);
      pending.push(target);
    }
  }
  return [...files].sort();
}

export function checkNativePlugin(root = checkout) {
  const plugin = path.join(root, "plugins/gemini-native");
  const manifest = JSON.parse(fs.readFileSync(regularFile(plugin, ".claude-plugin/plugin.json"), "utf8"));
  if (manifest.name !== "gemini-native-experimental" || manifest.userConfig?.consent?.default !== false ||
      manifest.engines?.["claude-code"] !== ">=2.1.323" ||
      Object.hasOwn(manifest.userConfig ?? {}, "validated_engine_version") || manifest.userConfig?.api_key?.sensitive !== true ||
      manifest.userConfig?.api_key?.required === true || manifest.userConfig?.api_key?.default !== undefined) throw new Error("Native plugin safety gates are missing");
  const hooks = JSON.parse(fs.readFileSync(regularFile(plugin, "hooks/hooks.json"), "utf8"));
  if (JSON.stringify(hooks) !== JSON.stringify({ modules: ["./register.ts"] })) throw new Error("Native plugin hook entrypoints changed");
  if (imports("register.ts", fs.readFileSync(regularFile(plugin, "hooks/register.ts"), "utf8")).length) throw new Error("Native hook module must not import runtime packages");
  return { plugin, manifest };
}

function compile(root, outDir) {
  const filename = path.join(root, "tsconfig.json");
  const base = ts.readConfigFile(filename, ts.sys.readFile);
  if (base.error) throw new Error("Could not read TypeScript build configuration");
  const raw = { ...base.config, include: [], files: ["packages/gemini-native/src/request.ts"], compilerOptions: {
    ...base.config.compilerOptions, noEmit: false, noEmitOnError: true, rootDir: path.join(root, "packages"), outDir,
    declaration: false, sourceMap: false,
  } };
  const config = ts.parseJsonConfigFileContent(raw, ts.sys, root);
  const program = ts.createProgram(config.fileNames, config.options);
  const diagnostics = [...config.errors, ...ts.getPreEmitDiagnostics(program)];
  if (diagnostics.length) throw new Error(ts.formatDiagnosticsWithColorAndContext(diagnostics, {
    getCurrentDirectory: () => root, getCanonicalFileName: file => file, getNewLine: () => "\n",
  }));
  if (program.emit().emitSkipped) throw new Error("Native helper build failed");
}

export function buildNativePlugin(root = checkout) {
  const { plugin } = checkNativePlugin(root);
  const stage = fs.mkdtempSync(path.join(root, "native-plugin-build-"));
  const emitted = path.join(stage, "compiled");
  const output = path.join(stage, "gemini-native-experimental");
  try {
    compile(root, emitted);
    const closure = runtimeClosure(emitted);
    const files = [];
    const copy = (source, relative) => {
      const destination = path.join(output, relative);
      fs.mkdirSync(path.dirname(destination), { recursive: true });
      fs.copyFileSync(source, destination, fs.constants.COPYFILE_EXCL);
      files.push(relative);
    };
    for (const asset of sourceAssets) copy(regularFile(plugin, asset), asset);
    for (const file of closure) copy(regularFile(emitted, file), `runtime/${file}`);
    copy(regularFile(root, "LICENSE"), "LICENSE");
    copy(regularFile(root, "docs/native-desktop-plugin.md"), "README.md");
    for (const [relative, content] of [
      ["runtime/package.json", '{"private":true,"type":"module"}\n'],
      ["runtime/request.mjs", 'import { main } from "./gemini-native/src/request.js";\nawait main();\n'],
    ]) {
      fs.writeFileSync(path.join(output, relative), content, { flag: "wx" });
      files.push(relative);
    }
    const inventory = files.sort().map(relative => {
      const data = fs.readFileSync(path.join(output, relative));
      return { path: relative, bytes: data.length, sha256: crypto.createHash("sha256").update(data).digest("hex") };
    });
    fs.writeFileSync(path.join(output, "inventory.json"), JSON.stringify({ schemaVersion: 1, experimental: true, runtimePackages: 0, files: inventory }, null, 2) + "\n", { flag: "wx" });
    // Only compiler output created by this build is removed. The independent result is retained.
    fs.rmSync(emitted, { recursive: true });
    return { directory: output, files: inventory.length + 1, bytes: inventory.reduce((sum, item) => sum + item.bytes, fs.statSync(path.join(output, "inventory.json")).size), runtimePackages: 0 };
  } catch (error) {
    // The failed stage was created above and is never an existing user directory.
    fs.rmSync(stage, { recursive: true });
    throw error;
  }
}

if (import.meta.main) {
  try {
    const report = process.argv.includes("--check") ? (checkNativePlugin(), { sourceCheck: "passed", hostValidation: "required" }) : buildNativePlugin();
    console.log(JSON.stringify(report, null, 2));
  } catch (error) { console.error(error instanceof Error ? error.message : "Native plugin build failed"); process.exitCode = 1; }
}
