// This app is only the local Desktop setup/recovery window. These unrelated operations are
// refused before any credential/config read or transport, including while configuration is
// missing. The router independently enforces its personal policy for non-Electron callers.
// Keep an explicit deny policy rather than silently breaking future provider/status routes.
export function personalDesktopAdminRequestAllowed(apiPath: string): boolean {
  const pathname = apiPath.split("?", 1)[0]!;
  if (/^\/api\/(?:update|power|remote|phone|mod|codex|settings-jobs)(?:\/|-|$)/.test(pathname)) return false;
  if (/^\/api\/(?:claude|chatgpt|google)-(?:login|logout|oauth|accounts)(?:\/|$)/.test(pathname)) return false;
  if (/^\/api\/(?:shutdown|compact-pick|agent-title|status-mod)(?:\/|$)/.test(pathname)) return false;
  return true;
}
