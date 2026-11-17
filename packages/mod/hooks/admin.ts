// Pure native-bridge boundary. The mods engine has no documented TLS certificate-pinning API;
// it therefore never reads or sends the local administrator capability itself.
export const ADMIN_RUNTIME_FILE = 'admin-runtime.json'
export const ADMIN_BRIDGE_LIMIT = 3 * 1024 * 1024
export const ADMIN_BRIDGE_REMEDIATION = 'Secure ClaudeRipple admin bridge unavailable. Start or upgrade ClaudeRipple and run `clauderipple mod on`; no HTTP fallback was used.'
export type AdminRuntime = { version: 1; home: string; node: string; bridge: string; env: { ELECTRON_RUN_AS_NODE?: '1' } }
export type AdminResponse = { ok: boolean; status: number; headers: Record<string, string>; text: string }
export type NativeResult = { exitCode: number; stdout: string; stderr: string; isStdoutTruncated: boolean; isStderrTruncated: boolean }

function record(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value)
}
function localPath(value: unknown): value is string {
  return typeof value === 'string' && value.length > 1 && value.length <= 4096 &&
    !/[\0\r\n]/.test(value) && !/^(?:\\\\|\/\/)/.test(value) &&
    (/^\//.test(value) || /^[A-Za-z]:[\\/]/.test(value)) &&
    !value.replace(/\\/g, '/').split('/').some(segment => segment === '.' || segment === '..')
}
function pathKey(value: string): string {
  const normal = value.replace(/\\/g, '/').replace(/\/+$/, '')
  return /^[A-Za-z]:\//.test(normal) ? normal.toLowerCase() : normal
}
export function parseAdminRuntime(value: unknown, home: string): AdminRuntime {
  if (!record(value) || value.version !== 1 || !localPath(home) || !localPath(value.home) ||
      pathKey(value.home) !== pathKey(home) || !localPath(value.node) || !localPath(value.bridge) ||
      !/[\\/]admin-bridge\.(?:js|ts)$/.test(value.bridge) || !record(value.env) ||
      Object.entries(value.env).some(([key, item]) => key !== 'ELECTRON_RUN_AS_NODE' || item !== '1')) {
    throw new Error(ADMIN_BRIDGE_REMEDIATION)
  }
  return { version: 1, home: value.home, node: value.node, bridge: value.bridge,
    env: value.env.ELECTRON_RUN_AS_NODE === '1' ? { ELECTRON_RUN_AS_NODE: '1' } : {} }
}

export function adminRequest(url: string, init: { method?: string; headers?: Readonly<Record<string, string>>; body?: unknown } = {}) {
  const match = /^http:\/\/127\.0\.0\.1:([0-9]{1,5})\/api\/[^\s\\#\0]*$/.exec(url)
  if (!match || url.length > 16_384 || Number(match[1]) < 1 || Number(match[1]) > 65535 ||
      (init.method !== undefined && !['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(init.method)) ||
      (init.body !== undefined && typeof init.body !== 'string')) throw new Error(ADMIN_BRIDGE_REMEDIATION)
  const headers: Record<string, string> = {}
  for (const [name, value] of Object.entries(init.headers ?? {})) {
    const key = name.toLowerCase()
    if (!['content-type', 'accept', 'x-clauderipple-install-id'].includes(key) ||
        typeof value !== 'string' || value.length > 4096 || /[\r\n\0]/.test(value)) throw new Error(ADMIN_BRIDGE_REMEDIATION)
    headers[key] = value
  }
  return { kind: 'request' as const, url, method: init.method ?? 'GET', headers,
    ...(typeof init.body === 'string' ? { body: init.body } : {}), timeoutMs: 30_000 }
}

export function nativeCommand(runtime: AdminRuntime, request: ReturnType<typeof adminRequest> | { kind: 'ui'; view: 'mod' }) {
  const stdin = JSON.stringify(request)
  if (stdin.length > ADMIN_BRIDGE_LIMIT) throw new Error(ADMIN_BRIDGE_REMEDIATION)
  return { argv: [runtime.node, runtime.bridge], init: {
    stdin, env: { ...runtime.env, CLAUDERIPPLE_HOME: runtime.home }, timeoutMs: 35_000,
  } }
}

export function nativeResult(result: NativeResult): Record<string, unknown> {
  if (result.exitCode !== 0 || result.isStdoutTruncated || result.isStderrTruncated || result.stdout.length > ADMIN_BRIDGE_LIMIT) {
    throw new Error(ADMIN_BRIDGE_REMEDIATION)
  }
  let value: unknown
  try { value = JSON.parse(result.stdout) } catch { throw new Error(ADMIN_BRIDGE_REMEDIATION) }
  if (!record(value)) throw new Error(ADMIN_BRIDGE_REMEDIATION)
  return value
}
export function adminResponse(result: NativeResult): AdminResponse {
  const value = nativeResult(result)
  if (typeof value.ok !== 'boolean' || !Number.isInteger(value.status) || Number(value.status) < 200 || Number(value.status) > 599 ||
      value.ok !== (Number(value.status) >= 200 && Number(value.status) < 300) || typeof value.text !== 'string' || !record(value.headers) ||
      Object.values(value.headers).some(item => typeof item !== 'string')) throw new Error(ADMIN_BRIDGE_REMEDIATION)
  return { ok: value.ok, status: Number(value.status), headers: value.headers as Record<string, string>, text: value.text }
}
