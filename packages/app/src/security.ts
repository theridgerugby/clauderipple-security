// Renderer capabilities are limited to the one dashboard document. Keep these checks shared
// by IPC, the local protocol and permission handlers; a same-origin iframe is not the owner.
import type { IpcMainInvokeEvent, Session, WebContents, WebFrameMain } from "electron";

export const SCHEME = "ripple";
export const ORIGIN = `${SCHEME}://app`;

export function isAppUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return url.protocol === `${SCHEME}:` && url.host === "app" && !url.username && !url.password;
  } catch { return false; }
}

export function isDashboardUrl(value: string): boolean {
  if (!isAppUrl(value)) return false;
  const url = new URL(value);
  return url.pathname === "/" || url.pathname === "/index.html";
}

type Frame = Pick<WebFrameMain, "processId" | "routingId" | "origin" | "url">;
type Owner = Pick<WebContents, "id" | "mainFrame">;

export function trustedTopFrame(senderId: number | undefined, frame: Frame | null | undefined, owned: Owner | null): boolean {
  try {
    return !!owned && senderId === owned.id && !!frame &&
      frame.processId === owned.mainFrame.processId && frame.routingId === owned.mainFrame.routingId &&
      frame.origin === ORIGIN && isDashboardUrl(frame.url);
  } catch { return false; }
}

export function trustedIpcSender(event: Pick<IpcMainInvokeEvent, "sender" | "senderFrame">, owned: Owner | null): boolean {
  return trustedTopFrame(event.sender.id, event.senderFrame, owned);
}

// These are the destinations the shipped dashboard links to: updates, mobile apps, and the
// provider sign-in/verification pages. No arbitrary protocol, local-file or userinfo URL may
// reach the OS opener. New providers must add their exact verified HTTPS host explicitly.
const EXTERNAL_HOSTS = new Set([
  "github.com", "apps.apple.com", "play.google.com", "accounts.google.com",
  "console.cloud.google.com", "aistudio.google.com", "claude.ai", "console.anthropic.com",
  "platform.claude.com", "platform.anthropic.com", "auth.anthropic.com", "auth.claude.com",
  "auth.openai.com",
]);

export function externalUrl(value: string): string | null {
  if (/[\x00-\x20\\]/.test(value)) return null;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && !url.username && !url.password && !url.port &&
      EXTERNAL_HOSTS.has(url.hostname) ? url.href : null;
  } catch { return null; }
}

export const DASHBOARD_CSP = [
  "default-src 'self'", "script-src 'self'", "style-src 'self'", "connect-src 'self'",
  "img-src 'self' data:", "object-src 'none'", "frame-src 'none'", "frame-ancestors 'none'",
  "worker-src 'none'", "base-uri 'none'", "form-action 'none'",
].join("; ");

/** Only copying text is needed by the dashboard. Camera, mic, files, devices and all else deny. */
export function configurePermissions(ses: Session, owner: () => WebContents | null): void {
  const isOwner = (contents: WebContents | null): boolean => {
    try { return !!contents && trustedTopFrame(contents.id, contents.mainFrame, owner()); }
    catch { return false; }
  };
  ses.setPermissionCheckHandler((contents, permission, requestingOrigin, details) =>
    permission === "clipboard-sanitized-write" && isOwner(contents) && details.isMainFrame === true &&
    requestingOrigin === ORIGIN && isDashboardUrl(details.requestingUrl ?? ""));
  ses.setPermissionRequestHandler((contents, permission, callback, details) => {
    callback(permission === "clipboard-sanitized-write" && isOwner(contents) &&
      details.isMainFrame === true && isDashboardUrl(details.requestingUrl ?? ""));
  });
  ses.setDevicePermissionHandler(() => false);
  ses.setDisplayMediaRequestHandler((_request, callback) => callback({}));
  ses.on("will-download", event => event.preventDefault());
}
