/**
 * EXPERIMENTAL, BUFFERED isolation proof. No install/activation side effects.
 * Uses documented Desktop AbovePrompt / turn.step / engine http.fetch hooks.
 * Production registration uses the host's generated official types. The
 * narrow exported contracts below are used by the module-only mock tests.
 *
 * A worker unload removes all hooks. The host may then use native Claude.
 * No whole-worker fail-closed claim is made. Guard/Windows/process support
 * requires a host compatibility check. Engine patches do not need a new pin.
 */
import type { EngineInterface, HookStream, ProcessSpawnChunk, ProcessSpawnRequest, ProcessSpawnResult, Register, Timer, TurnStepChunk, TurnStepResult } from 'claude-code';

export type Options = Readonly<Record<string, unknown>>;
export type Effort = 'low' | 'medium' | 'high';
export type Signature = [string, string];
export interface HttpResponse { status: number; ok: boolean; headers: Record<string, string>; text: string }
export interface HelperPayload {
  protocol: 1; apiKey: string; request: Record<string, unknown>;
  effort?: Effort; thoughtSignatures: Signature[];
}
export interface ProcessResult {
  exitCode: number; stdout: string; stderr: string;
  isStdoutTruncated?: boolean; isStderrTruncated?: boolean;
}
export interface Invocation {
  argv: string[];
  init: { cwd: string; env: Record<string, string>; stdin: string; timeoutMs: number };
}
type Node = unknown;
interface SelectEvent { surface: string; value: string }
interface Elements {
  Box(props: { flexDirection?: string; children: Node[] }): Node;
  Text(props: { children: string }): Node;
  Select(props: {
    key: string; label: string; value: string;
    options: { value: string; label: string }[];
    onSelect(value: string, event: SelectEvent): void;
  }): Node;
}
export interface Host {
  plugin: { root: string };
  session: {
    id(): Promise<string>;
    surfaces(): Promise<readonly string[]>;
    version(): Promise<{ version: string }>;
  };
  ui: { resolve(event: RenderEvent): Elements; invalidate(event: 'ui.render'): void };
  process?: { spawn(request: ProcessSpawnRequest): HookStream<ProcessSpawnChunk, ProcessSpawnResult> };
  clock?: { after(ms: number, callback: () => void): Timer };
}
export interface StepEvent {
  turnId: string; index: number; model: string; messageCount: number;
  agentId?: string; effort?: string | number;
}
export interface StepResult {
  turnId: string; index: number; answer: string; toolUses: readonly unknown[];
  stopReason: string | null; usage: unknown;
}
export interface HttpEvent {
  url: string;
  init?: { method?: string; headers?: Record<string, string>; body?: string | { base64: string } };
}
export interface RenderEvent { component: string; surface: string; props: { hasSurvey?: boolean; isWorking?: boolean } }
type ObserveEvent = { agentId?: string; turnId?: string; sessionId?: string };
type Meta = { origin?: { plugin: string; tier?: string }; signal?: AbortSignal; called?: boolean };
type Next<E, R> = ((event: E) => R) & Meta;
export type StepHook = ($: Host, event: StepEvent, next: Next<StepEvent, AsyncGenerator<unknown, StepResult>>) => AsyncGenerator<unknown, StepResult>;
export type HttpHook = ($: Host, event: HttpEvent, next: Next<HttpEvent, Promise<unknown>>) => Promise<unknown>;
export type RenderHook = ($: Host, event: RenderEvent, next: Next<RenderEvent, Promise<Node>>) => Promise<Node>;
export type ObserveHook = ($: Host, event: ObserveEvent, next: Next<ObserveEvent, Promise<unknown>>) => Promise<unknown>;
type Registration<F> = { catch(handler: F): void };
export interface On {
  (name: 'turn.step', hook: StepHook): Registration<StepHook>;
  (name: 'http.fetch', hook: HttpHook): Registration<HttpHook>;
  (name: 'ui.render', matcher: { component: 'AbovePrompt' }, hook: RenderHook): Registration<RenderHook>;
  (name: 'turn.start' | 'turn.complete' | 'session.end', hook: ObserveHook): Registration<ObserveHook>;
}

const PREFIX = 'clauderipple-gemini-carbon-';
const MODEL = 'gemini-4-carbon';
const INPUT_LIMIT = 8 * 1024 * 1024;
const OUTPUT_LIMIT = 3 * 1024 * 1024;
const SIGNATURE_LIMIT = 512 * 1024;
const REFUSED = 'Gemini could not complete this request. No automatic Claude retry was requested. Select Claude to continue with your subscription.';
const UNVALIDATED = 'Gemini auto-check pending: send an ordinary Claude request once in this session. A trusted Node path and AI Studio key are also required.';
const byteLength = (value: string): number => new TextEncoder().encode(value).length;
const record = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === 'object' && !Array.isArray(value);
const validNodePath = (path: unknown): path is string => typeof path === 'string'
  && /^(?:[a-z]:[\\/]|\/)/i.test(path) && /(?:^|[\\/])node(?:\.exe)?$/i.test(path)
  && !/[\x00-\x1f]/.test(path);

/** Overrides merge with the host environment; they do not make it hermetic.
 * In particular, Windows case-alias handling and loader behavior need native
 * acceptance before a key is used. Never add a shell workaround here. */
export function createHelperInvocation(nodePath: string, pluginRoot: string, payload: HelperPayload): Invocation {
  if (!validNodePath(nodePath) || !pluginRoot || /[\x00-\x1f]/.test(pluginRoot)) throw new Error('Invalid helper configuration');
  const stdin = JSON.stringify(payload);
  if (byteLength(stdin) > INPUT_LIMIT) throw new Error('Helper input limit');
  const env: Record<string, string> = {};
  for (const name of [
    'NODE_OPTIONS', 'NODE_PATH', 'NODE_EXTRA_CA_CERTS', 'NODE_V8_COVERAGE',
    'NODE_DEBUG', 'NODE_DEBUG_NATIVE', 'NODE_REDIRECT_WARNINGS',
    'NODE_TLS_REJECT_UNAUTHORIZED', 'NODE_USE_ENV_PROXY', 'NODE_USE_SYSTEM_CA',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'SSLKEYLOGFILE',
    'OPENSSL_CONF', 'OPENSSL_MODULES', 'LD_PRELOAD', 'LD_LIBRARY_PATH',
    'DYLD_INSERT_LIBRARIES', 'DYLD_LIBRARY_PATH',
    'HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
    'ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN',
    'CLAUDE_CODE_OAUTH_TOKEN_FILE', 'ANTHROPIC_BASE_URL', 'OPENAI_API_KEY',
    'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GOOGLE_APPLICATION_CREDENTIALS',
  ]) { env[name] = ''; env[name.toLowerCase()] = ''; }
  return {
    argv: [nodePath, `${pluginRoot.replace(/[\\/]$/, '')}/runtime/request.mjs`],
    init: { cwd: pluginRoot, env, stdin, timeoutMs: 120_000 },
  };
}

/** A single cancellable child, with no listener or retry. The documented spawn
 * lifetime is bound to this dispatch's next.signal and module unload; return()
 * closes it. A validated host must also honor clock.after, which supplies the
 * total deadline. A policy-refused timer has no acceptance-status API. */
export async function collectHelper(
  $: { process: Pick<EngineInterface['process'], 'spawn'>; clock: Pick<EngineInterface['clock'], 'after'> },
  invocation: Invocation,
  signal: AbortSignal,
): Promise<ProcessResult> {
  if (signal.aborted || typeof $.process?.spawn !== 'function' || typeof $.clock?.after !== 'function') throw new Error('Helper unavailable');
  let child: HookStream<ProcessSpawnChunk, ProcessSpawnResult> | undefined;
  let timer: Timer | undefined;
  let closing: Promise<unknown> | undefined;
  let stopped = false;
  let failed = false;
  let rejectStop: (error: Error) => void = () => {};
  const interruption = new Promise<never>((_, reject) => { rejectStop = reject; });
  void interruption.catch(() => {});
  const close = (): Promise<unknown> => {
    if (!child) return Promise.resolve();
    if (!closing) {
      try { closing = child.return(undefined as never); }
      catch { closing = Promise.reject(new Error('Helper close failed')); }
      void closing.catch(() => {});
    }
    return closing;
  };
  const stop = (): void => {
    stopped = true;
    rejectStop(new Error('Helper interrupted'));
    void close();
  };
  signal.addEventListener('abort', stop, { once: true });
  try {
    timer = $.clock.after(invocation.init.timeoutMs, stop);
    if (signal.aborted || stopped) throw new Error('Helper interrupted');
    child = $.process.spawn({ argv: invocation.argv, cwd: invocation.init.cwd, env: invocation.init.env, input: invocation.init.stdin });
    // Closing a HookStream rejects its result promise. The iterator return
    // value is consumed below; attach a handler to that alternate result view.
    void child.result.catch(() => {});
    const stdout: string[] = [];
    let outBytes = 0;
    let errorBytes = 0;
    let chunks = 0;
    for (;;) {
      const part = await Promise.race([child.next(), interruption]);
      if (signal.aborted || stopped) throw new Error('Helper interrupted');
      if (part.done) {
        if (part.value.code !== 0 || part.value.signal !== null) throw new Error('Helper failed');
        return { exitCode: 0, stdout: stdout.join(''), stderr: '', isStdoutTruncated: false, isStderrTruncated: false };
      }
      if (++chunks > 8192 || typeof part.value.text !== 'string') throw new Error('Helper output limit');
      if (part.value.stream === 'stdout') {
        outBytes += byteLength(part.value.text);
        if (outBytes > OUTPUT_LIMIT) throw new Error('Helper output limit');
        stdout.push(part.value.text);
      } else if (part.value.stream === 'stderr') {
        errorBytes += byteLength(part.value.text);
        if (errorBytes > 64 * 1024) throw new Error('Helper output limit');
      } else throw new Error('Invalid helper stream');
    }
  } catch { failed = true; throw new Error('Gemini helper failed'); }
  finally {
    try {
      const cleanup = close();
      // On interruption the close request is already sent. Never wait past
      // the deadline for an acknowledgement from a broken host/child stream.
      if (!stopped) await Promise.race([cleanup, interruption]);
    } catch { if (!failed) throw new Error('Gemini helper failed'); }
    finally { try { timer?.cancel(); } catch {} signal.removeEventListener('abort', stop); }
  }
}

/** Only a fixed, bounded response crosses back into the harness. */
export function readHelperResult(result: ProcessResult): { response: HttpResponse; thoughtSignatures: Signature[] } {
  if (result.exitCode !== 0 || result.isStdoutTruncated || result.isStderrTruncated
    || typeof result.stdout !== 'string' || result.stdout.length > OUTPUT_LIMIT
    || byteLength(result.stdout) > OUTPUT_LIMIT) throw new Error('Helper failed');
  const parsed: unknown = JSON.parse(result.stdout);
  if (!record(parsed) || parsed.protocol !== 1 || !record(parsed.response) || !Array.isArray(parsed.thoughtSignatures)) throw new Error('Invalid helper response');
  const r = parsed.response;
  if (!Number.isInteger(r.status) || (r.status as number) < 200 || (r.status as number) > 599
    || typeof r.ok !== 'boolean' || r.ok !== ((r.status as number) < 300)
    || !record(r.headers) || typeof r.text !== 'string') throw new Error('Invalid helper response');
  const contentType = r.headers['content-type'];
  if (contentType !== 'application/json' && contentType !== 'text/event-stream') throw new Error('Invalid content type');
  const signatures: Signature[] = [];
  const ids = new Set<string>();
  let size = 0;
  for (const pair of parsed.thoughtSignatures) {
    if (!Array.isArray(pair) || pair.length !== 2 || typeof pair[0] !== 'string' || typeof pair[1] !== 'string'
      || pair[0].length > 256 || pair[1].length > 16_384 || !pair[0] || !pair[1] || ids.has(pair[0])) throw new Error('Invalid signature');
    ids.add(pair[0]);
    size += byteLength(pair[0]) + byteLength(pair[1]);
    if (signatures.length >= 128 || size > SIGNATURE_LIMIT) throw new Error('Signature limit');
    signatures.push([pair[0], pair[1]]);
  }
  return { response: { status: r.status as number, ok: r.ok, headers: { 'content-type': contentType }, text: r.text }, thoughtSignatures: signatures };
}

/** 2.1.323 introduced the AbovePrompt list used by this mod. Later builds
 * prove their own engine transport contract from a successful ordinary native
 * request; release numbers alone never grant Gemini readiness. */
export function supportedVersion(version: string): boolean {
  const parts = /^(\d+)\.(\d+)\.(\d+)$/.exec(version);
  if (!parts) return false;
  const major = Number(parts[1]!);
  const minor = Number(parts[2]!);
  const patch = Number(parts[3]!);
  return Number.isSafeInteger(major) && Number.isSafeInteger(minor) && Number.isSafeInteger(patch)
    && (major > 2 || (major === 2 && (minor > 1 || (minor === 1 && patch >= 323))));
}
/** These contract checks retain no prompt, token, account, response body or
 * model selection. A changed host has to show the same behavior organically. */
function nativeStepShape(event: StepEvent): boolean {
  return typeof event.turnId === 'string' && event.turnId.length > 0
    && Number.isSafeInteger(event.index) && event.index >= 0
    && Number.isSafeInteger(event.messageCount) && event.messageCount >= 0
    && typeof event.model === 'string' && event.model.length > 0 && !event.model.startsWith(PREFIX);
}
function nativeTransportResult(value: unknown): boolean {
  return record(value) && value.isStreaming === true
    && typeof value.status === 'number' && Number.isInteger(value.status)
    && value.status >= 200 && value.status < 300 && record(value.headers);
}
function nativeModelMatches(stepModel: string, httpModel: unknown): boolean {
  if (typeof httpModel !== 'string' || !httpModel || httpModel.startsWith(PREFIX)) return false;
  if (stepModel === httpModel) return true;
  if (stepModel === 'default') return /^claude-(?:opus|sonnet|haiku)-/.test(httpModel);
  return (stepModel === 'opus' || stepModel === 'sonnet' || stepModel === 'haiku')
    && httpModel.startsWith(`claude-${stepModel}-`);
}
function requestBody(event: HttpEvent): Record<string, unknown> | undefined {
  const body = event.init?.body;
  if (typeof body !== 'string' || body.length > INPUT_LIMIT || byteLength(body) > INPUT_LIMIT) return undefined;
  try { const value: unknown = JSON.parse(body); return record(value) ? value : undefined; } catch { return undefined; }
}
function messagesUrl(event: HttpEvent): boolean {
  try {
    const url = new URL(event.url);
    return url.protocol === 'https:' && url.hostname === 'api.anthropic.com'
      && !url.username && !url.password && (!url.port || url.port === '443')
      && url.pathname === '/v1/messages' && event.init?.method?.toUpperCase() === 'POST';
  } catch { return false; }
}
async function* refusal(event: StepEvent): AsyncGenerator<TurnStepChunk, TurnStepResult> {
  yield { kind: 'text', index: 0, text: REFUSED };
  yield { kind: 'stop', stopReason: 'end_turn', usage: null };
  return { turnId: event.turnId, index: event.index, answer: REFUSED, toolUses: [], stopReason: 'end_turn', usage: null };
}

export const register: Register = (on, options = {}): void => {
  // No handlers, child startup, option-key reads, or host calls when off.
  if (options.consent !== true) return;
  let mode: 'claude' | 'gemini' = 'claude';
  let ready = false;
  let working = false;
  let owner = '';
  let epoch = 0;
  let counter = 0;
  let signatures: Signature[] = [];
  let needsKey = false;
  let contractFailed = false;
  let observedVersion = '';
  let stepObserved = false;
  let transportObserved = false;
  let nativeCanaryActive = false;
  let nativeCanaryTransport = false;
  let nativeCanaryModel = '';
  const selectedSteps = new WeakSet<object>();
  const selectedHttp = new WeakSet<object>();
  type Pending = { effort?: Effort; body?: string; result?: Promise<HttpResponse>; responded?: true };
  const active = new Map<string, Pending>();
  const reset = (): void => { mode = 'claude'; ready = false; owner = ''; working = false; signatures = []; needsKey = false; contractFailed = false; observedVersion = ''; stepObserved = false; transportObserved = false; nativeCanaryActive = false; nativeCanaryTransport = false; nativeCanaryModel = ''; active.clear(); epoch++; };
  const invalidate = ($: { ui: Pick<Host['ui'], 'invalidate'> }): void => { try { $.ui.invalidate('ui.render'); } catch { /* UI failure must not enter inference. */ } };

  on('session.end', async ($, e, next) => { reset(); return next(e); });
  on('turn.start', async ($, e, next) => { if (e.agentId === undefined) working = true; return next(e); });
  on('turn.complete', async ($, e, next) => { if (e.agentId === undefined) { working = false; if (mode === 'gemini') invalidate($); } return next(e); });

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (e.surface !== 'desktop' || e.props.hasSurvey) return next(e);
    const underlying = await next(e);
    const id = await $.session.id();
    if (owner && owner !== id) reset();
    owner = id;
    const version = await $.session.version();
    const surfaces = await $.session.surfaces();
    // Invalidate old proof on *any* engine version change; it is renewed by
    // regular Claude activity and never by a generated test or a Google call.
    if (version.version !== observedVersion) {
      observedVersion = version.version;
      ready = false; stepObserved = false; transportObserved = false;
      nativeCanaryActive = false; nativeCanaryTransport = false; nativeCanaryModel = '';
      contractFailed = false; epoch++;
      // Keep a selected Gemini mode selected-but-unavailable until the
      // person explicitly switches to Claude. No implicit quota fallback.
    }
    ready = !contractFailed && stepObserved && transportObserved
      && surfaces.length === 1 && surfaces[0] === 'desktop'
      && supportedVersion(version.version)
      && typeof $.process?.spawn === 'function' && typeof $.clock?.after === 'function' && validNodePath(options.node_path);
    const { Box, Text, Select } = $.ui.resolve(e);
    const currentEpoch = epoch;
    const unavailable = !ready || needsKey;
    const row = working || e.props.isWorking
        ? Text({ children: mode === 'gemini' ? 'Gemini Carbon · experimental buffered request' : 'Claude subscription · unchanged' })
      : unavailable && mode === 'claude'
        ? Text({ children: UNVALIDATED })
        : Select({
          key: 'gemini-native-mode', label: unavailable ? 'Gemini unavailable · choose Claude to continue' : 'Experimental route', value: mode,
          options: [{ value: 'claude', label: 'Claude subscription (unchanged)' }, { value: 'gemini', label: unavailable ? 'Gemini Carbon (unavailable)' : 'Gemini Carbon (buffered)' }],
          onSelect(value, source) {
            if (source.surface !== 'desktop' || currentEpoch !== epoch || working || active.size) return;
            if (value !== 'claude' && value !== 'gemini') return;
            if (value === 'claude') { mode = 'claude'; invalidate($); return; }
            if (!ready || needsKey) return;
            const key = options.api_key;
            if (typeof key !== 'string' || !key) {
              needsKey = true;
              invalidate($);
              return;
            }
            mode = value;
            invalidate($);
          },
        });
    return Box({ flexDirection: 'column', children: [underlying, row] });
  }).catch(async ($, e, next) => { ready = false; return next(e); });

  on('turn.step', async function* ($, e, next) {
    if (mode !== 'gemini' || e.agentId !== undefined) {
      // Passive, free compatibility canary. The host must send an ordinary
      // native Messages request *inside this very main-loop step*. Results
      // from unrelated native background requests cannot satisfy the proof.
      if (mode === 'claude' && e.agentId === undefined && nativeStepShape(e)
        && !next.signal?.aborted && !stepObserved) {
        const canaryEpoch = epoch;
        nativeCanaryActive = true; nativeCanaryTransport = false; nativeCanaryModel = e.model;
        try {
          const result = yield* next(e);
          if (!next.signal?.aborted && epoch === canaryEpoch && nativeCanaryTransport) {
            stepObserved = true; transportObserved = true;
          }
          return result;
        } finally {
          nativeCanaryActive = false; nativeCanaryTransport = false; nativeCanaryModel = '';
        }
      }
      return yield* next(e);
    }
    selectedSteps.add(e);
    if (!ready || next.signal?.aborted) return yield* refusal(e);
    const id = await $.session.id();
    const surfaces = await $.session.surfaces();
    const version = await $.session.version();
    if (id !== owner || version.version !== observedVersion || !supportedVersion(version.version)
      || surfaces.length !== 1 || surfaces[0] !== 'desktop') return yield* refusal(e);
    // A unique marker belongs only to this selected main-loop step. Never set
    // the persistent model, subscription default, environment, or model picker.
    const marker = `${PREFIX}${epoch}-${++counter}`;
    const pending: Pending = {};
    if (e.effort === 'low' || e.effort === 'medium' || e.effort === 'high') pending.effort = e.effort;
    active.set(marker, pending);
    let stream: ReturnType<typeof next> | undefined;
    let failed = false;
    let finished = false;
    const early: TurnStepChunk[] = [];
    try {
      stream = next({ ...e, model: marker });
      for (;;) {
        const part = await stream.next();
        if (part.done) {
          finished = true;
          if (!pending.responded) { ready = false; contractFailed = true; throw new Error('Selected transport was not observed'); }
          return part.value;
        }
        if (!pending.responded) {
          // A host may emit envelope markers before sending HTTP. Do not expose
          // a completion as Gemini unless this step's helper response was used.
          if (part.value.kind !== 'engine' || early.length >= 64) { ready = false; contractFailed = true; throw new Error('Selected transport was not observed'); }
          early.push(part.value);
        } else {
          for (const chunk of early.splice(0)) yield chunk;
          yield part.value;
        }
      }
    } catch (error) { failed = true; throw error; }
    finally {
      active.delete(marker);
      if (stream && !finished) {
        try { await stream.return(undefined as never); }
        catch (error) { if (!failed) throw error; }
      }
    }
  }).catch(async function* ($, e, next) {
    if (selectedSteps.has(e)) return yield* refusal(e);
    // In a catch the official host replays a called next; it does not infer twice.
    return yield* next(e);
  });

  on('http.fetch', async ($, e, next) => {
    if (next.origin?.plugin !== 'engine') return next(e);
    // Passive network contract: one successful, authentic Claude model call
    // with a streamed host response proves this engine still exposes the
    // documented Messages interception shape. The request and its result
    // return untouched. Only two booleans survive; no auth/prompt is stored.
    if (mode === 'claude' && nativeCanaryActive && !transportObserved && !active.size && messagesUrl(e)
      && typeof e.init?.body === 'string' && !e.init.body.includes(PREFIX)) {
      const parsed = requestBody(e);
      // A matching *model* in the active main-step window rejects unrelated
      // providers and most side calls. A true request/turn ID is still absent
      // from the host API, so concurrent native steps remain a documented gap.
      const candidate = nativeModelMatches(nativeCanaryModel, parsed?.model)
        && Array.isArray(parsed?.messages);
      const result = await next(e);
      if (candidate && !next.signal?.aborted && nativeCanaryActive && nativeTransportResult(result)) nativeCanaryTransport = true;
      return result;
    }
    // Native idle requests avoid parsing unless they mention our reserved model
    // namespace. Expired own markers must never be retried against native Claude.
    if (!active.size && (typeof e.init?.body !== 'string' || !e.init.body.includes(PREFIX))) return next(e);
    const body = requestBody(e);
    const marker = body?.model;
    const pending = typeof marker === 'string' ? active.get(marker) : undefined;
    if (typeof marker === 'string' && marker.startsWith(PREFIX) && !pending) {
      selectedHttp.add(e);
      return { deny: REFUSED };
    }
    // No request-level turn/agent provenance is exposed by this API. A body
    // that cannot be classified (malformed, bytes, oversized) could be an
    // unrelated native sidecall; blocking it would violate native independence.
    // Its pass-through is an unresolved Gemini acceptance blocker, not a
    // fail-closed guarantee. Keep activation gated until the host is verified.
    if (!pending || !body) return next(e);
    selectedHttp.add(e);
    if (!messagesUrl(e) || next.signal?.aborted || !ready) return { deny: REFUSED };
    const encoded = e.init?.body as string;
    if (pending.body !== undefined && pending.body !== encoded) return { deny: REFUSED };
    const deliver = async (response: Promise<HttpResponse>) => {
      const value = await response;
      // The provider result is shared, but cancellation belongs to each HTTP
      // dispatch. A later retry must not inherit the first caller's signal.
      return next.signal.aborted || active.get(marker as string) !== pending || !ready
        ? { deny: REFUSED } : { value };
    };
    if (pending.result) return deliver(pending.result);
    pending.body = encoded;
    // The cached promise also suppresses duplicate provider calls on SDK retries.
    pending.result = (async () => {
      const apiKey = options.api_key;
      const nodePath = options.node_path;
      if (typeof apiKey !== 'string' || !apiKey || !validNodePath(nodePath) || !$.process) throw new Error('Gemini unavailable');
      const payload: HelperPayload = { protocol: 1, apiKey, request: { ...body, model: MODEL }, thoughtSignatures: signatures };
      if (pending.effort) payload.effort = pending.effort;
      const invocation = createHelperInvocation(nodePath, $.plugin.root, payload);
      const result = readHelperResult(await collectHelper($, invocation, next.signal));
      if (next.signal?.aborted || active.get(marker as string) !== pending) throw new Error('Gemini cancelled');
      const merged = new Map(signatures);
      for (const [id, signature] of result.thoughtSignatures) { merged.delete(id); merged.set(id, signature); }
      signatures = [...merged];
      let bytes = signatures.reduce((sum, [id, signature]) => sum + byteLength(id) + byteLength(signature), 0);
      while (signatures.length > 128 || bytes > SIGNATURE_LIMIT) {
        const [id, signature] = signatures.shift()!;
        bytes -= byteLength(id) + byteLength(signature);
      }
      pending.responded = true;
      return result.response;
    })();
    return deliver(pending.result);
  }).catch(async ($, e, next) => selectedHttp.has(e) ? { deny: REFUSED } : next(e));
};
