// The dashboard can keep or replace a credential without reading it back. The reserved marker is
// meaningful only for the same provider and credential destination that supplied it.

import type { Config, Provider } from "./config.ts";
import { PRESETS } from "./presets.ts";

export const REDACTED_SECRET = "__CLAUDERIPPLE_REDACTED_SECRET__";
type RecordValue = Record<string, unknown>;

function record(value: unknown): value is RecordValue {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

export function isRedactedSecret(value: unknown): boolean {
  return value === REDACTED_SECRET || value === `Bearer ${REDACTED_SECRET}`;
}

function maskHeaders(value: unknown): unknown {
  if (!record(value)) return value;
  return Object.fromEntries(Object.entries(value).map(([name, secret]) => [name,
    typeof secret === "string" && secret.length > 0
      ? /^Bearer\s+/i.test(secret) ? `Bearer ${REDACTED_SECRET}` : REDACTED_SECRET
      : secret,
  ]));
}

function maskProvider(provider: unknown): unknown {
  if (!record(provider)) return provider;
  return {
    ...provider,
    ...(typeof provider.apiKey === "string" && provider.apiKey ? { apiKey: REDACTED_SECRET } : {}),
    ...(provider.headers !== undefined ? { headers: maskHeaders(provider.headers) } : {}),
    ...(Array.isArray(provider.credentials) ? { credentials: provider.credentials.map(credential => record(credential)
      ? { ...credential, headers: maskHeaders(credential.headers) } : credential) } : {}),
  };
}

export function redactConfigSecrets(config: Config): Config {
  return {
    ...config,
    providers: Object.fromEntries(Object.entries(config.providers ?? {}).map(([name, provider]) => [name, maskProvider(provider)])),
  } as Config;
}

function endpoint(provider: RecordValue): string {
  const fallback = provider.type === "google" ? "https://generativelanguage.googleapis.com"
    : provider.type === "anthropic" ? "https://api.anthropic.com" : "";
  return (typeof provider.url === "string" ? provider.url : fallback).replace(/\/+$/, "");
}

function destinationSet(provider: RecordValue): string[] {
  const urls = [endpoint(provider)];
  if (Array.isArray(provider.models)) for (const model of provider.models) {
    if (record(model) && typeof model.url === "string") urls.push(model.url.replace(/\/+$/, ""));
  }
  return [...new Set(urls)].sort();
}

function sameScope(next: RecordValue, previous: RecordValue): boolean {
  const previousDestinations = new Set(destinationSet(previous));
  return next.type === previous.type && next.auth === previous.auth && next.preset === previous.preset &&
    endpoint(next) === endpoint(previous) &&
    destinationSet(next).every(destination => previousDestinations.has(destination));
}

function containsMarker(value: unknown): boolean {
  if (isRedactedSecret(value)) return true;
  if (Array.isArray(value)) return value.some(containsMarker);
  return record(value) && Object.values(value).some(containsMarker);
}

function restoredValue(value: unknown, previous: unknown): unknown {
  if (!isRedactedSecret(value)) return value;
  if (typeof previous !== "string" || !previous || isRedactedSecret(previous)) {
    throw new Error("saved credential unavailable; enter the credential again");
  }
  return previous;
}

function restoreHeaders(next: unknown, previous: unknown): unknown {
  if (!record(next)) return next;
  return Object.fromEntries(Object.entries(next).map(([name, value]) => [name,
    restoredValue(value, record(previous) && Object.hasOwn(previous, name) ? previous[name] : undefined),
  ]));
}

function restoreProvider(next: RecordValue, previous: RecordValue): RecordValue {
  const credentials = Array.isArray(next.credentials) ? next.credentials.map(credential => {
    if (!record(credential)) return credential;
    const old = Array.isArray(previous.credentials)
      ? previous.credentials.find(entry => record(entry) && entry.id === credential.id) : undefined;
    // The UI promotes a single header set to a pool under id "default". New entries may also
    // copy existing vendor headers while replacing the key, within the same destination scope.
    return { ...credential, headers: restoreHeaders(credential.headers, record(old) ? old.headers : previous.headers) };
  }) : undefined;
  // headers mirrors the pool's first entry. When the old first key is removed, resolve its
  // replacement by credential identity rather than accidentally replaying the removed key.
  const primary = credentials?.[0];
  const oldPrimary = Array.isArray(previous.credentials) ? previous.credentials[0] : undefined;
  const primaryChanged = record(primary) && (!record(oldPrimary) || primary.id !== oldPrimary.id);
  const headers = primaryChanged && record(primary.headers)
    ? { ...(record(previous.headers) ? previous.headers : {}), ...primary.headers } : previous.headers;
  return {
    ...next,
    ...(next.apiKey !== undefined ? { apiKey: restoredValue(next.apiKey, previous.apiKey) } : {}),
    ...(next.headers !== undefined ? { headers: restoreHeaders(next.headers, headers) } : {}),
    ...(credentials !== undefined ? { credentials } : {}),
  };
}

/** A literal new value replaces a secret, an omitted field removes it, and the marker keeps it. */
export function restoreConfigSecrets(next: Config, previous: Config): Config {
  if (!record(next.providers)) return next; // validation reports the malformed object
  return {
    ...next,
    providers: Object.fromEntries(Object.entries(next.providers).map(([name, provider]) => {
      if (!record(provider) || !containsMarker(provider)) return [name, provider];
      const old = Object.hasOwn(previous.providers ?? {}, name) ? previous.providers[name] : undefined;
      if (!record(old) || !sameScope(provider, old)) {
        throw new Error(`provider ${name}: endpoint or credential scope changed; enter credentials again`);
      }
      const restored = restoreProvider(provider, old);
      if (containsMarker(restored)) throw new Error(`provider ${name}: credential marker in unsupported field`);
      return [name, restored];
    })),
  } as Config;
}

function sameOrigin(left: string, right: string): boolean {
  try { return new URL(left).origin === new URL(right).origin; } catch { return false; }
}

/** Probes reuse a stored key by provider identity, never by an arbitrary caller-supplied URL. */
export function restoreProbeSecrets(probe: RecordValue, providers: Record<string, Provider>): RecordValue {
  if (!containsMarker(probe)) return probe;
  const name = typeof probe.name === "string" ? probe.name : "";
  const saved: unknown = Object.hasOwn(providers, name) ? providers[name] : undefined;
  if (!record(saved) || probe.type !== saved.type || probe.auth !== saved.auth || endpoint(probe) !== endpoint(saved)) {
    throw new Error("saved provider name and unchanged endpoint are required to reuse a credential");
  }
  if (probe.preset !== undefined && probe.preset !== saved.preset) throw new Error("saved provider preset changed; enter credentials again");
  // Some official presets keep their model catalogue on a different origin. Only the committed
  // preset's exact catalogue URL is allowed in addition to the saved inference origin.
  if (typeof probe.modelsUrl === "string") {
    const preset = typeof saved.preset === "string" ? PRESETS.find(entry => entry.id === saved.preset) : undefined;
    if (!sameOrigin(probe.modelsUrl, endpoint(saved)) && probe.modelsUrl !== preset?.modelsUrl) {
      throw new Error("model catalogue destination changed; enter credentials again");
    }
  }
  const restored = restoreProvider(probe, saved);
  if (containsMarker(restored)) throw new Error("credential marker in unsupported probe field");
  return restored;
}
