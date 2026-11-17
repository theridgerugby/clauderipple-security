// Owner-private, non-secret execution descriptor for the mod's native TLS bridge. No program is
// found on PATH; credentials and TLS keys remain private to the native process.
import fs from "node:fs";
import path from "node:path";
import { writePrivateFileAtomic } from "../../router/src/locked-file.ts";
import { readPrivateFile } from "../../router/src/private-file.ts";
import { runtime, type Runtime } from "./runtime.ts";

export const ADMIN_RUNTIME_FILE = "admin-runtime.json";
export type AdminRuntimeDescriptor = {
  version: 1;
  home: string;
  node: string;
  bridge: string;
  env: { ELECTRON_RUN_AS_NODE?: "1" };
};

export function adminBridgePath(rt: Runtime = runtime()): string {
  return path.join(path.dirname(rt.cli), `admin-bridge${path.extname(rt.cli)}`);
}

function absoluteLocalPath(value: unknown): value is string {
  return typeof value === "string" && path.isAbsolute(value) && value.length <= 4096 &&
    !/[\0\r\n]/.test(value) && !/^(?:\\\\|\/\/)/.test(value);
}

export function parseAdminRuntime(value: unknown, home: string): AdminRuntimeDescriptor {
  const row = value as Partial<AdminRuntimeDescriptor> | null;
  if (!row || typeof row !== "object" || Array.isArray(row) || row.version !== 1 ||
      !absoluteLocalPath(row.home) || path.resolve(row.home) !== path.resolve(home) ||
      !absoluteLocalPath(row.node) || !absoluteLocalPath(row.bridge) ||
      !/[\\/]admin-bridge\.(?:js|ts)$/.test(row.bridge) ||
      !row.env || typeof row.env !== "object" || Array.isArray(row.env) ||
      Object.entries(row.env).some(([key, item]) => key !== "ELECTRON_RUN_AS_NODE" || item !== "1")) {
    throw new Error("Invalid native admin runtime; run `clauderipple mod on` with the current installation");
  }
  return { version: 1, home: row.home, node: row.node, bridge: row.bridge, env: { ...row.env } };
}

/** Explicit install/start/mod-on operation only. Does not run the recorded program. */
export function recordAdminRuntime(home: string, rt: Runtime = runtime()): AdminRuntimeDescriptor {
  const descriptor = parseAdminRuntime({
    version: 1, home: path.resolve(home),
    node: fs.realpathSync(rt.node), bridge: fs.realpathSync(adminBridgePath(rt)),
    env: rt.env.ELECTRON_RUN_AS_NODE === "1" ? { ELECTRON_RUN_AS_NODE: "1" } : {},
  }, home);
  for (const file of [descriptor.node, descriptor.bridge]) {
    if (!fs.statSync(file).isFile()) throw new Error("Native admin runtime must name regular files");
  }
  writePrivateFileAtomic(path.join(home, ADMIN_RUNTIME_FILE), JSON.stringify(descriptor) + "\n");
  return descriptor;
}

export function readAdminRuntime(home: string): AdminRuntimeDescriptor {
  return parseAdminRuntime(JSON.parse(readPrivateFile(path.join(home, ADMIN_RUNTIME_FILE), 16 * 1024).toString("utf8")), home);
}
