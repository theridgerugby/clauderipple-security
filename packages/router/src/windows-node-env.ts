// A personal Windows router carries a live Claude login and optionally a university API key.
// Node startup settings can silently disable certificate checks, add trust anchors, preload
// arbitrary code or redirect HTTPS through an ambient proxy. The supervised launcher removes
// these settings before starting Node; this check also refuses unsafe direct launches.
//
// Values are deliberately never included in an error: environment settings can themselves
// contain credentials. This guard cannot undo code that ran via a preload before this module,
// which is why the PowerShell launcher must clear NODE_OPTIONS before spawning Node.

/** Variables to clear before a Windows personal router process is spawned. */
export const PERSONAL_WINDOWS_UNTRUSTED_ENV = Object.freeze([
  "NODE_OPTIONS", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_EXTRA_CA_CERTS",
  "NODE_USE_SYSTEM_CA", "NODE_USE_ENV_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR",
  "OPENSSL_CONF", "SSLKEYLOGFILE", "NODE_DEBUG", "NODE_V8_COVERAGE",
  "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
  "http_proxy", "https_proxy", "all_proxy", "no_proxy",
]);

/** Security-relevant settings only, without ever exposing their potentially sensitive values. */
export function personalWindowsNodeEnvProblems(env: NodeJS.ProcessEnv, execArgv: readonly string[] = []): string[] {
  const problems: string[] = [];
  const set = (name: string): boolean => typeof env[name] === "string" && env[name]!.length > 0;
  if (set("NODE_OPTIONS")) problems.push("NODE_OPTIONS");
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") problems.push("NODE_TLS_REJECT_UNAUTHORIZED");
  if (set("NODE_EXTRA_CA_CERTS")) problems.push("NODE_EXTRA_CA_CERTS");
  if (env.NODE_USE_SYSTEM_CA === "1") problems.push("NODE_USE_SYSTEM_CA");
  if (env.NODE_USE_ENV_PROXY === "1") problems.push("NODE_USE_ENV_PROXY");
  for (const name of ["SSL_CERT_FILE", "SSL_CERT_DIR", "OPENSSL_CONF", "SSLKEYLOGFILE", "NODE_DEBUG", "NODE_V8_COVERAGE"]) {
    if (set(name)) problems.push(name);
  }
  for (const names of [["HTTP_PROXY", "http_proxy"], ["HTTPS_PROXY", "https_proxy"],
    ["ALL_PROXY", "all_proxy"], ["NO_PROXY", "no_proxy"]]) {
    if (names.some(set)) problems.push(names[0]!);
  }
  if (execArgv.length) problems.push("Node startup flags");
  return problems;
}

export function assertPersonalWindowsNodeEnv(
  env: NodeJS.ProcessEnv = process.env, execArgv: readonly string[] = process.execArgv,
): void {
  const problems = personalWindowsNodeEnvProblems(env, execArgv);
  if (problems.length) {
    throw new Error(`Personal Windows runtime refused unsafe startup settings: ${problems.join(", ")}. ` +
      "Use an ordinary clean PowerShell session and the reviewed source installer; clear these settings from the router environment before retrying.");
  }
}
