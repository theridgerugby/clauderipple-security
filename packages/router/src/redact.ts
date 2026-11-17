// Safe excerpts of upstream errors for logs and client-safe translated errors.
//
// An upstream error may reflect the credential it was given. Keys are opaque vendor strings, so
// callers supply their actual outbound credential values; token-shaped fallbacks cover errors from
// a layer whose credentials are not present in config (for example a refreshed OAuth token).

const REDACTED = "[REDACTED]";

/** Values sent under a credential-bearing outbound header name. */
function credentialHeaderName(name: string): boolean {
  return /^(?:authorization|proxy-authorization|cookie|set-cookie|x-api-key|x-goog-api-key|x-clauderipple-admin|api[-_]?key|.*(?:token|secret|password).*)$/i.test(name);
}

export function credentialHeaderValues(headers: Iterable<[string, string]>): string[] {
  const secrets = new Set<string>();
  for (const [rawName, value] of headers) {
    if (!credentialHeaderName(rawName) || !value) continue;
    secrets.add(value);
    // A vendor that echoes the credential echoes the token, not the scheme in front of it.
    const bare = /^(?:Bearer|Basic|Token)\s+(\S+)$/i.exec(value)?.[1];
    if (bare) secrets.add(bare);
  }
  return [...secrets].sort((a, b) => b.length - a.length);
}

/** Header names are diagnostic; their sensitive values must never reach a log line. */
export function redactHeaders(headers: Record<string, string | string[] | undefined>): Record<string, string | string[]> {
  return Object.fromEntries(Object.entries(headers).flatMap(([name, value]) => {
    if (value === undefined) return [];
    return [[name, credentialHeaderName(name) ? REDACTED : value] as const];
  }));
}

/** Return a bounded, one-line diagnostic without credentials. */
export function redactErrorText(value: string, secrets: readonly string[] = [], max = 500): string {
  let text = value;
  const rawSecrets = secrets.filter(secret => secret.trim().length > 0);
  const normalizedSecrets = [...new Set(rawSecrets.map(secret => secret.replace(/\s+/g, " ").trim()))]
    .sort((a, b) => b.length - a.length);
  const knownRepresentations = [...new Set([...rawSecrets, ...normalizedSecrets])]
    .sort((a, b) => b.length - a.length);
  // Preserve opaque credential bytes until replacement. Normalizing first changes embedded tabs
  // or repeated spaces, making an exact known-secret replacement miss the reflected credential.
  // Longest first avoids leaving a suffix exposed when one configured value contains another.
  for (const secret of knownRepresentations) {
    text = text.replaceAll(secret, REDACTED);
  }
  text = text.replace(/\s+/g, " ").trim();
  // Upstreams may normalize a header before echoing it. Cover that representation too, before
  // diagnostic truncation can leave only a prefix that no longer matches the complete secret.
  for (const secret of normalizedSecrets) {
    text = text.replaceAll(secret, REDACTED);
  }
  return text
    // Authorization values in prose or header-shaped JSON.
    .replace(/\b(Bearer)\s+[A-Za-z0-9._~+/=-]{8,}\b/gi, `$1 ${REDACTED}`)
    .replace(/\b(sk-[A-Za-z0-9][A-Za-z0-9._-]{6,})\b/g, REDACTED)
    .replace(/\bAIza[A-Za-z0-9_-]{20,}\b/g, REDACTED)
    // OAuth access/refresh tokens are JWTs, regardless of the header/body formatting.
    .replace(/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*\b/g, REDACTED)
    // Key/value echoes that are not sent as a standard Authorization header.
    .replace(/\b((?:x-clauderipple-admin|api[-_]?key|access[-_]?token|refresh[-_]?token|id[-_]?token|client[-_]?secret|token|secret|password)["']?\s*[:=]\s*["']?)[^\s,"'};]+/gi, `$1${REDACTED}`)
    .slice(0, max);
}
