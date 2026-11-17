// Personal deployments carry credentials and potentially unpublished research. An endpoint
// entered in a provider form is not permission to send data there: approval is a separate,
// exact HTTPS-origin decision. Production CLI/router entry points install the live policy.
// Library callers can still exercise transports with explicit test fixtures.

export type PersonalSecurityPolicy = {
  mode: "personal";
  approvedOrigins: string[];
};

export const PERSONAL_SECURITY_DEFAULTS: PersonalSecurityPolicy = Object.freeze({
  mode: "personal", approvedOrigins: Object.freeze([]) as unknown as string[],
});

export class PersonalPolicyError extends Error {
  readonly code = "ERR_RIPPLE_PERSONAL_POLICY";
  constructor(message = "Sensitive-data policy refused this operation") {
    super(message);
    this.name = "PersonalPolicyError";
  }
}

let policyProvider: (() => PersonalSecurityPolicy | undefined) | undefined;

/** No credentials, files, or network access; the caller owns configuration loading. */
export function configurePersonalEgressPolicy(provider: (() => PersonalSecurityPolicy | undefined) | undefined): void {
  policyProvider = provider;
}

/** Canonical origin only. Paths, credentials, query strings and wildcards are never approvals. */
export function approvedOrigin(value: unknown): string | null {
  if (typeof value !== "string" || value.length > 2048 || /[\s\u0000-\u001f\u007f\\]/.test(value)) return null;
  try {
    const url = new URL(value);
    if (url.protocol !== "https:" || !url.hostname || url.hostname.includes("*") ||
        url.username || url.password || url.search || url.hash || url.pathname !== "/") return null;
    return url.origin;
  } catch { return null; }
}

export function personalPolicyProblems(value: unknown): string[] {
  if (!value || typeof value !== "object" || Array.isArray(value)) return ["security must be a personal policy object"];
  const policy = value as Record<string, unknown>;
  const errors: string[] = [];
  if (policy.mode !== "personal") errors.push('security.mode must be "personal"');
  if (!Array.isArray(policy.approvedOrigins) || policy.approvedOrigins.length > 32 ||
      policy.approvedOrigins.some(origin => approvedOrigin(origin) !== origin)) {
    errors.push("security.approvedOrigins must contain at most 32 exact canonical HTTPS origins");
  } else if (new Set(policy.approvedOrigins).size !== policy.approvedOrigins.length) {
    errors.push("security.approvedOrigins must not contain duplicates");
  }
  return errors;
}

export function personalMode(config: { security?: PersonalSecurityPolicy }): boolean {
  return config.security?.mode === "personal";
}

/** Checked immediately before each outbound attempt, so revocation is effective on retries too. */
export function assertPersonalEgressAllowed(value: string | URL, _init: RequestInit = {}): void {
  if (!policyProvider) return;
  let policy: PersonalSecurityPolicy | undefined;
  try { policy = policyProvider(); } catch { throw new PersonalPolicyError("Security policy is unavailable; outbound request refused"); }
  // A registered production entry point may never silently fall back to unprotected operation.
  if (personalPolicyProblems(policy).length) throw new PersonalPolicyError("Security policy is invalid; outbound request refused");
  assertApprovedDestination(value, policy!);
}

export function assertApprovedDestination(value: string | URL, policy: PersonalSecurityPolicy): void {
  if (personalPolicyProblems(policy).length) throw new PersonalPolicyError("Security policy is invalid; outbound request refused");
  let url: URL;
  try { url = new URL(value); } catch { throw new PersonalPolicyError("Invalid outbound destination"); }
  if (url.protocol !== "https:" || url.username || url.password || url.hash ||
      /[\u0000-\u001f\u007f\\]/.test(String(value))) {
    throw new PersonalPolicyError("Sensitive-data requests require HTTPS without URL credentials or fragments");
  }
  if (!policy.approvedOrigins.includes(url.origin)) {
    throw new PersonalPolicyError(`Destination not approved: ${url.origin}. Approve its exact HTTPS origin in the native Providers privacy panel.`);
  }
}

/** Cross-provider retries can move the whole conversation; personal mode always keeps its owner. */
export function personalFallbacks<T extends { provider: string }>(
  config: { security?: PersonalSecurityPolicy }, primary: { provider: string }, fallbacks: readonly T[] = [],
): T[] {
  return personalMode(config) ? fallbacks.filter(item => item.provider === primary.provider) : [...fallbacks];
}
