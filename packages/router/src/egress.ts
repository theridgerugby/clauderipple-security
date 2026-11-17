// Every provider-bound HTTP exchange goes through this boundary, including OAuth and catalogues.
// A redirect is a destination change, not a transient provider failure: neither credentials nor a
// prompt may follow it, and account/provider retry loops must preserve the terminal policy error.

import { assertPersonalEgressAllowed } from "./personal-policy.ts";

export type EgressFetch = (url: string, init?: RequestInit) => Promise<Response>;
export type EgressTransport = (url: string, init: RequestInit) => Promise<Response>;
export type EgressValidator = (url: URL, init: RequestInit) => void;

/** Keep existing injected transports behind exactly the same policy as the native transport. */
export function guardEgressFetch(transport: EgressTransport = fetch, validate?: EgressValidator): EgressFetch {
  return (url, init) => egressFetch(url, init, transport, validate);
}

export class EgressPolicyError extends Error {
  readonly code = "ERR_RIPPLE_EGRESS_POLICY";
  readonly retryable = false;
  readonly reason: "redirect" | "destination";

  constructor(reason: "redirect" | "destination" = "redirect") {
    super(reason === "redirect"
      ? "Outbound redirect refused by the security policy"
      : "Outbound destination refused by the security policy");
    this.name = "EgressPolicyError";
    this.reason = reason;
  }
}

export function isEgressPolicyError(error: unknown): error is Error & { readonly code: "ERR_RIPPLE_EGRESS_POLICY" | "ERR_RIPPLE_PERSONAL_POLICY" } {
  return error instanceof EgressPolicyError || (error instanceof Error &&
    ["ERR_RIPPLE_EGRESS_POLICY", "ERR_RIPPLE_PERSONAL_POLICY"].includes(String((error as Error & { code?: unknown }).code)));
}

/**
 * `transport` is the existing dependency-injection seam; even an injected implementation receives
 * the enforced redirect policy. `validate` lets an installation apply its destination policy before
 * any network I/O. Never include a rejected URL, Location, response body, or key in the error.
 */
export async function egressFetch(
  input: string | URL,
  init: RequestInit = {},
  transport: EgressTransport = fetch,
  validate?: EgressValidator,
): Promise<Response> {
  let url: URL;
  try { url = new URL(input); } catch { throw new EgressPolicyError("destination"); }
  if (!/^https?:$/.test(url.protocol) || url.username || url.password) throw new EgressPolicyError("destination");
  assertPersonalEgressAllowed(input, init);
  validate?.(url, init);
  const controller = new AbortController();
  const signal = init.signal ? AbortSignal.any([init.signal, controller.signal]) : controller.signal;
  const response = await transport(url.href, { ...init, signal, redirect: "manual" });
  // All 3xx are rejected, including those without Location. They must never be reinterpreted as
  // an ordinary auth/capacity failure that sends this same prompt using another credential.
  if ((response.status >= 300 && response.status < 400) || response.redirected || response.type === "opaqueredirect") {
    const error = new EgressPolicyError();
    // Cancel without waiting on an untrusted streaming body's cancellation promise. Aborting the
    // owned fetch signal closes its transport as well; the caller receives the policy error now.
    void response.body?.cancel().catch(() => {});
    controller.abort(error);
    throw error;
  }
  return response;
}
