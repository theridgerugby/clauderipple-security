import assert from "node:assert/strict";

/** Business-logic fixtures run in the supported native renderer, never a browser dashboard.
 * The real Electron top-frame, IPC and pinned-TLS boundaries have separate integration tests.
 * This window intentionally contains no admin token or credential-reading bridge.
 */
export function nativeDashboardWindow() {
  const location = new URL("ripple://app/");
  const storage = new Map<string, string>();
  return {
    rippleApp: Object.freeze({ platform: process.platform }),
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

/** The renderer calls only its same-origin protocol bridge; main supplies TLS credentials. */
export function assertNativeAdminFetch(value: string, options?: RequestInit): void {
  assert.ok(value.startsWith("/api/") && !value.startsWith("//"));
  const url = new URL(value, "ripple://app/");
  assert.equal(url.protocol, "ripple:");
  assert.equal(url.host, "app");
  assert.equal(options?.mode, "same-origin");
  assert.equal(options?.redirect, "error");
  assert.equal(new Headers(options?.headers).has("x-clauderipple-admin"), false);
}
