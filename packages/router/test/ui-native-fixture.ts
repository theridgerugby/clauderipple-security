import assert from "node:assert/strict";

/** Use the production profile predicate in isolated UI sections that do not evaluate navigation. */
export function desktopUiGuardSource(source: string): string {
  const start = source.indexOf("function genericControlsAvailable(");
  const end = source.indexOf("const GENERIC_ONLY_VIEWS =", start);
  assert.ok(start >= 0 && end > start);
  return source.slice(start, end);
}

/** Business-logic fixtures run in the supported native renderer, never a browser dashboard.
 * The real Electron top-frame, IPC and pinned-TLS boundaries have separate integration tests.
 * This window intentionally contains no admin token or credential-reading bridge.
 */
type FixtureResponse = { status?: number; ok?: boolean; headers?: Headers; text(): Promise<string> };
type NativeRequest = { path: string; method?: string; headers?: Record<string, string>; body?: string };
type NativeOptions = Omit<NativeRequest, "path">;

/** Adapt a synthetic backend to the production IPC response shape, without a browser fetch. */
export function nativeAdminBridge(transport: (value: string, options?: NativeOptions) => Promise<FixtureResponse>) {
  return async (request: NativeRequest) => {
    const { path, ...options } = request;
    assertNativeAdminFetch(path, options);
    const response = await transport(path, options);
    return { status: response.status ?? (response.ok === false ? 500 : 200),
      headers: response.headers ? Object.fromEntries(response.headers) : { "content-type": "application/json" },
      body: new TextEncoder().encode(await response.text()) };
  };
}

export function nativeDashboardWindow(transport?: (value: string, options?: NativeOptions) => Promise<FixtureResponse>) {
  const location = new URL("ripple://app/");
  const storage = new Map<string, string>();
  return {
    rippleApp: Object.freeze({ platform: process.platform, ...(transport ? { adminRequest: nativeAdminBridge(transport) } : {}) }),
    location,
    history: {
      replaceState(_state: unknown, _title: string, value: string) {
        const next = new URL(value, location);
        assert.equal(next.protocol, "ripple:");
        assert.equal(next.host, "app");
        location.href = next.href;
      },
    },
    sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => { storage.set(key, value); },
      removeItem: (key: string) => { storage.delete(key); },
    },
  };
}

/** IPC request data contains no browser fetch options, destination origin, or capability. */
export function assertNativeAdminFetch(value: string, options?: RequestInit): void {
  assert.ok(value.startsWith("/api/") && !value.startsWith("//"));
  const url = new URL(value, "ripple://app/");
  assert.equal(url.protocol, "ripple:");
  assert.equal(url.host, "app");
  assert.equal(options?.mode, undefined);
  assert.equal(options?.redirect, undefined);
  for (const key of Object.keys(options ?? {})) assert.ok(["method", "headers", "body"].includes(key), key);
  for (const [name] of new Headers(options?.headers)) assert.ok(["accept", "content-type"].includes(name), name);
  assert.equal(new Headers(options?.headers).has("x-clauderipple-admin"), false);
}
