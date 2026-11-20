import assert from 'node:assert/strict';
import test from 'node:test';
import type { HookStream, ProcessSpawnChunk, ProcessSpawnRequest, ProcessSpawnResult } from 'claude-code';
import { handle } from '../../packages/gemini-native/src/request.ts';
import {
  collectHelper, createHelperInvocation, readHelperResult, register, supportedVersion,
  type Host, type HttpEvent, type HttpHook, type ObserveHook, type On, type Options,
  type ProcessResult, type RenderEvent, type RenderHook, type Signature, type StepEvent,
  type StepHook, type StepResult,
} from '../../plugins/gemini-native/hooks/register.ts';

// These are contract mocks. They do not execute an actual Claude engine or
// render Desktop. In particular, guard policy and worker unloading are not
// emulated as a security boundary or reported as native acceptance.
type Hook = HttpHook | StepHook | RenderHook | ObserveHook;
type Tree = { type: string; props: Record<string, unknown> };
const resultOf = (event: StepEvent, answer = 'native'): StepResult => ({
  turnId: event.turnId, index: event.index, answer, toolUses: [], stopReason: 'end_turn', usage: null,
});
const step = (extra: Partial<StepEvent> = {}): StepEvent => ({
  turnId: 'turn-1', index: 0, model: 'claude-native', messageCount: 1, ...extra,
});
const wire = (model: string): HttpEvent => ({
  url: 'https://api.anthropic.com/v1/messages?beta=true',
  init: {
    method: 'POST', headers: { authorization: 'native-secret', 'x-api-key': 'also-native-secret' },
    body: JSON.stringify({ model, messages: [{ role: 'user', content: 'hello' }], tools: [{ name: 'Read', input_schema: { type: 'object' } }], stream: true }),
  },
});
const helperResult = (signatures: Signature[] = []): ProcessResult => ({
  exitCode: 0, stderr: '', isStdoutTruncated: false, isStderrTruncated: false,
  stdout: JSON.stringify({ protocol: 1, response: {
    status: 200, ok: true, headers: { 'content-type': 'application/json' }, text: '{"type":"message"}',
  }, thoughtSignatures: signatures }),
});
async function collect(generator: AsyncGenerator<unknown, StepResult>): Promise<{ chunks: unknown[]; result: StepResult }> {
  const chunks = [];
  for (;;) { const next = await generator.next(); if (next.done) return { chunks, result: next.value }; chunks.push(next.value); }
}
function find(tree: unknown, type: string): Tree | undefined {
  if (!tree || typeof tree !== 'object') return;
  const element = tree as Tree;
  if (element.type === type) return element;
  const children = element.props?.children;
  if (Array.isArray(children)) for (const child of children) { const found = find(child, type); if (found) return found; }
}

function mockChild(factory: () => Promise<ProcessResult>): HookStream<ProcessSpawnChunk, ProcessSpawnResult> {
  let resolveExit: (value: ProcessSpawnResult) => void = () => {};
  let rejectExit: (error: unknown) => void = () => {};
  const result = new Promise<ProcessSpawnResult>((resolve, reject) => { resolveExit = resolve; rejectExit = reject; });
  const stream = (async function* (): AsyncGenerator<ProcessSpawnChunk, ProcessSpawnResult> {
    let ended = false;
    try {
      const value = await factory();
      if (value.stdout) yield { stream: 'stdout', text: value.stdout };
      if (value.stderr) yield { stream: 'stderr', text: value.stderr };
      const exit = { code: value.exitCode, signal: null };
      ended = true; resolveExit(exit);
      return exit;
    } catch (error) { rejectExit(error); throw error; }
    finally { if (!ended) rejectExit(new Error('mock child closed')); }
  })();
  return Object.assign(stream, { result });
}

function harness(extra: Options = {}) {
  const hooks = new Map<string, { handler: Hook; catcher?: Hook }>();
  const on = ((name: string, ...args: unknown[]) => {
    const entry: { handler: Hook; catcher?: Hook } = { handler: args.at(-1) as Hook };
    hooks.set(name, entry);
    return { catch(catcher: Hook) { entry.catcher = catcher; } };
  }) as On;
  const options = { consent: true, node_path: '/trusted/node', api_key: 'google-test-key', ...extra };
  register(on as unknown as Parameters<typeof register>[0], options);
  let version = '2.1.323';
  let surfaces: readonly string[] = ['desktop'];
  let id = 'session-1';
  let invalidations = 0;
  const invocations: ProcessSpawnRequest[] = [];
  const timers: { ms: number; callback(): void; cancelled: boolean }[] = [];
  let run = async (): Promise<ProcessResult> => helperResult();
  const $: Host = {
    plugin: { root: '/owned/plugin' },
    session: { id: async () => id, surfaces: async () => surfaces, version: async () => ({ version }) },
    ui: {
      resolve: () => ({
        Box: props => ({ type: 'Box', props }), Text: props => ({ type: 'Text', props }), Select: props => ({ type: 'Select', props }),
      }),
      invalidate: () => { invalidations++; },
    },
    process: { spawn: request => { invocations.push(request); return mockChild(run); } },
    clock: { after(ms, callback) { const timer = { ms, callback, cancelled: false }; timers.push(timer); return { cancel() { timer.cancelled = true; } }; } },
  };
  async function render(surface = 'desktop', props: RenderEvent['props'] = {}, underlying: unknown = null): Promise<unknown> {
    const entry = hooks.get('ui.render');
    if (!entry) return underlying;
    const event = { surface, component: 'AbovePrompt', props };
    const next = Object.assign(async () => underlying, { called: false });
    try { return await (entry.handler as RenderHook)($, event, next); }
    catch (error) { if (!entry.catcher) throw error; return (entry.catcher as RenderHook)($, event, next); }
  }
  // This is normal Claude user activity simulated by the mock host. It calls
  // the unchanged native core, never a provider probe, account lookup, or helper.
  async function certify(): Promise<void> {
    await render();
    await runStep(step(), async function* event {
      const response = await http(wire(event.model), async () => ({
        status: 200, ok: true, isStreaming: true, headers: { 'content-type': 'text/event-stream' },
      }));
      assert.equal((response as { status: number }).status, 200);
      return resultOf(event);
    });
    await render();
  }
  async function select(value = 'gemini'): Promise<void> {
    if (value === 'gemini') await certify();
    const element = find(await render(), 'Select');
    assert.ok(element, 'mock Desktop selector is available');
    (element.props.onSelect as (value: string, source: { surface: string; value: string }) => void)(value, { surface: 'desktop', value });
  }
  async function http(event: HttpEvent, core: (event: HttpEvent) => Promise<unknown> = async () => ({ native: true }), origin = 'engine'): Promise<unknown> {
    const entry = hooks.get('http.fetch');
    if (!entry) return core(event);
    let called = false;
    let cached: Promise<unknown> | undefined;
    const next = Object.assign((input: HttpEvent) => {
      called = true;
      return cached ??= core(input);
    }, { origin: { plugin: origin, tier: 'core' }, signal: new AbortController().signal });
    Object.defineProperty(next, 'called', { get: () => called });
    try { return await (entry.handler as HttpHook)($, event, next); }
    catch (error) { if (!entry.catcher) throw error; return (entry.catcher as HttpHook)($, event, next); }
  }
  async function runStep(event = step(), core?: (event: StepEvent) => AsyncGenerator<unknown, StepResult>, host = $) {
    const entry = hooks.get('turn.step');
    let coreCalls = 0;
    let received: StepEvent | undefined;
    let replay: AsyncGenerator<unknown, StepResult> | undefined;
    let replayResult: StepResult | undefined;
    const next = Object.assign((input: StepEvent): AsyncGenerator<unknown, StepResult> => {
      if (replayResult) return (async function* () { return replayResult!; })();
      if (replay) return replay;
      coreCalls++;
      received = input;
      replay = (async function* () {
        const selected = core ? core(input) : (async function* () { yield { kind: 'native' }; return resultOf(input); })();
        const result = yield* selected;
        replayResult = result;
        return result;
      })();
      return replay;
    }, { signal: new AbortController().signal });
    Object.defineProperty(next, 'called', { get: () => coreCalls > 0 });
    let output;
    try { output = await collect(entry ? (entry.handler as StepHook)(host, event, next) : next(event)); }
    catch (error) {
      if (!entry?.catcher) throw error;
      output = await collect((entry.catcher as StepHook)(host, event, next));
    }
    return { ...output, coreCalls, received };
  }
  async function observe(name: string, event: Parameters<ObserveHook>[1] = {}): Promise<unknown> {
    const entry = hooks.get(name);
    return entry ? (entry.handler as ObserveHook)($, event, async input => input) : event;
  }
  return {
    $, hooks, options, invocations, timers, render, select, certify, http, runStep, observe,
    setRun(fn: () => Promise<ProcessResult>) { run = fn; },
    setVersion(value: string) { version = value; },
    setSurfaces(value: readonly string[]) { surfaces = value; },
    setId(value: string) { id = value; },
    invalidations: () => invalidations,
  };
}

test('default-off registers nothing and does not access the credential', () => {
  let calls = 0;
  const options = Object.defineProperty({ consent: false }, 'api_key', { get() { throw new Error('credential read'); } });
  register((() => { calls++; throw new Error('registered'); }) as unknown as Parameters<typeof register>[0], options);
  register((() => { calls++; throw new Error('registered'); }) as unknown as Parameters<typeof register>[0], {});
  assert.equal(calls, 0);
});

test('native turn and HTTP paths pass the identical event, with no host/credential access', async () => {
  const h = harness();
  Object.defineProperty(h.options, 'api_key', { get() { throw new Error('credential read'); } });
  const poison = new Proxy({} as Host, { get() { throw new Error('host access'); } });
  const event = step();
  const result = await h.runStep(event, undefined, poison);
  assert.equal(result.received, event);
  assert.equal(result.coreCalls, 1);
  const request = wire('claude-native');
  assert.equal(await h.http(request, async input => input), request);
  assert.equal(h.invocations.length, 0);
});

test('the native Desktop row does not read an API key; terminal UI is unchanged', async () => {
  const h = harness();
  Object.defineProperty(h.options, 'api_key', { get() { throw new Error('credential read'); } });
  const nativeRow = { existing: 'native content' };
  assert.equal(await h.render('terminal', {}, nativeRow), nativeRow);
  const initial = await h.render('desktop', {}, nativeRow) as Tree;
  assert.equal((initial.props.children as unknown[])[0], nativeRow);
  assert.equal(find(initial, 'Select'), undefined, 'unknown host contract is initially inert');
  await h.certify();
  const tree = await h.render('desktop', {}, nativeRow) as Tree;
  assert.equal((tree.props.children as unknown[])[0], nativeRow);
  assert.ok(find(tree, 'Select'));
  assert.equal(h.invocations.length, 0);
});

test('runtime contract, not an exact release pin, admits patch updates after ordinary native activity', async () => {
  assert.equal(supportedVersion('2.1.322'), false);
  for (const version of ['2.1.323', '2.1.324', '2.1.328', '2.1.329', '2.2.0', '3.0.0']) {
    assert.equal(supportedVersion(version), true, version);
    const h = harness(); h.setVersion(version);
    assert.equal(find(await h.render(), 'Select'), undefined, 'no automatic trust before normal traffic');
    await h.certify();
    assert.ok(find(await h.render(), 'Select'), version);
    assert.equal(h.invocations.length, 0, 'native contract proof cannot spawn helper');
  }
  for (const version of ['2.1.322', '2.0.999', '1.9.9', '3.0.0-beta', 'garbage']) {
    const h = harness(); h.setVersion(version); await h.certify();
    assert.equal(find(await h.render(), 'Select'), undefined, version);
  }
  const changed = harness(); changed.setVersion('2.1.329'); await changed.certify();
  delete changed.$.process;
  assert.equal(find(await changed.render(), 'Select'), undefined);
  const noPath = harness({ node_path: 'node' }); await noPath.certify();
  assert.equal(find(await noPath.render(), 'Select'), undefined);
  const multi = harness(); multi.setSurfaces(['terminal', 'desktop']); await multi.certify();
  assert.equal(find(await multi.render(), 'Select'), undefined);
});


test('native proof requires a successful streamed Messages exchange with the expected model/request shape', async () => {
  const h = harness(); await h.render();
  const good = () => ({ status: 200, isStreaming: true, headers: { 'content-type': 'text/event-stream' } });
  // A network call detached from the current turn can never certify the
  // selected main inference path, even when its response is successful.
  await h.http(wire('claude-native'), async () => good());
  assert.equal(find(await h.render(), 'Select'), undefined);
  for (const value of [
    { status: 200, headers: {}, text: 'body only' },
    { status: 429, isStreaming: true, headers: {} },
    { status: 200, isStreaming: false, headers: {} },
    { status: 200, isStreaming: true, headers: 'bad' },
  ]) {
    await h.runStep(step(), async function* () {
      const event = wire('claude-native');
      assert.equal(await h.http(event, async () => value), value, 'native response must be identical');
      return resultOf(step());
    });
    assert.equal(find(await h.render(), 'Select'), undefined);
  }
  await h.runStep(step(), async function* () {
    const unsupported = wire('claude-native');
    unsupported.init!.body = JSON.stringify({ model: 'claude-native', messages: 'future schema' });
    assert.equal(await h.http(unsupported, async () => good()) !== undefined, true);
    return resultOf(step());
  });
  assert.equal(find(await h.render(), 'Select'), undefined);
  const native = wire('claude-native');
  const response = good();
  await h.runStep(step(), async function* () {
    assert.equal(await h.http(native, async input => { assert.equal(input, native); return response; }), response);
    return resultOf(step());
  });
  assert.ok(find(await h.render(), 'Select'), 'the same completed step and native HTTP stream establish the contract');
  assert.equal(h.invocations.length, 0);
});

test('the passive native contract is model-matched and supports standard Claude model aliases', async () => {
  const h = harness(); await h.render();
  await h.runStep(step({ model: 'claude-sonnet-5-5' }), async function* () {
    const foreign = wire('claude-opus-5-5');
    await h.http(foreign, async () => ({ status: 200, isStreaming: true, headers: {} }));
    return resultOf(step());
  });
  assert.equal(find(await h.render(), 'Select'), undefined, 'unrelated Claude model cannot certify a main step');
  await h.runStep(step({ model: 'sonnet' }), async function* () {
    await h.http(wire('claude-sonnet-5-5'), async () => ({ status: 200, isStreaming: true, headers: {} }));
    return resultOf(step());
  });
  assert.ok(find(await h.render(), 'Select'), 'native alias model is accepted by the same behavioral contract');
});

test('a live engine version update requires an automatic fresh canary; selected Gemini cannot silently fall into Claude', async () => {
  const h = harness(); await h.select();
  h.setVersion('2.1.329');
  const old = find(await h.render(), 'Select');
  assert.ok(old);
  assert.match(old.props.label as string, /unavailable/);
  const blocked = await h.runStep(step());
  assert.equal(blocked.coreCalls, 0, 'selected Gemini must never resume native inference on engine change');
  assert.match(blocked.result.answer, /No automatic Claude retry/);
  await h.select('claude');
  assert.equal(find(await h.render(), 'Select'), undefined, 'fresh version has no proven traffic yet');
  const native = step();
  assert.equal((await h.runStep(native)).received, native);
  assert.equal(find(await h.render(), 'Select'), undefined, 'a turn without an observed network stream is insufficient');
  await h.http(wire('claude-native'), async () => ({ status: 200, isStreaming: true, headers: {} }));
  assert.equal(find(await h.render(), 'Select'), undefined, 'an unrelated network call is insufficient');
  await h.certify();
  assert.ok(find(await h.render(), 'Select'), 'same code now admits the updated engine');
  assert.equal(h.invocations.length, 0);
});

test('a normal native error never establishes a transport proof, and a failed transport never changes the original failure', async () => {
  const h = harness(); await h.render();
  const request = wire('claude-native');
  await assert.rejects(h.runStep(step(), async function* () {
    await h.http(request, async () => { throw new Error('native upstream refused'); });
    return resultOf(step());
  }), /native upstream refused/);
  assert.equal(find(await h.render(), 'Select'), undefined);
  assert.equal(h.invocations.length, 0);
});

test('missing key refuses the explicit selection without launching a helper', async () => {
  const h = harness({ api_key: '' });
  await h.select();
  const event = step();
  assert.equal((await h.runStep(event)).received, event);
  assert.equal(h.invocations.length, 0);
  assert.equal(find(await h.render(), 'Select'), undefined);
});

test('selected main request uses only helper stdin, and native requests alongside it stay original', async () => {
  const h = harness(); await h.select();
  const event = step({ effort: 'high' });
  const output = await h.runStep(event, async function* (rewritten) {
    assert.match(rewritten.model, /^clauderipple-gemini-carbon-/);
    assert.notEqual(rewritten, event);
    const native = wire('claude-native');
    assert.equal(await h.http(native, async input => input), native);
    const response = await h.http(wire(rewritten.model)) as { value: unknown };
    assert.ok(response.value);
    yield { kind: 'text', index: 0, text: 'gemini' };
    return resultOf(event, 'gemini');
  });
  assert.equal(output.result.answer, 'gemini');
  assert.equal(output.coreCalls, 1);
  assert.equal(event.model, 'claude-native');
  assert.equal(h.invocations.length, 1);
  const invocation = h.invocations[0]!;
  const payload = JSON.parse(invocation.input!);
  assert.equal(payload.protocol, 1);
  assert.equal(payload.request.model, 'gemini-4-carbon');
  assert.equal(payload.apiKey, 'google-test-key');
  assert.equal(payload.effort, 'high');
  assert.equal(payload.request.tools[0].name, 'Read');
  assert.equal(h.timers[0]!.ms, 120_000);
  assert.equal(h.timers[0]!.cancelled, true);
  assert.equal(invocation.input!.includes('native-secret'), false);
  assert.equal(invocation.input!.includes('api.anthropic.com'), false);
  assert.equal(invocation.argv.join(' ').includes('google-test-key'), false);
  assert.equal(JSON.stringify(invocation.env).includes('google-test-key'), false);
  assert.deepEqual(invocation.argv, ['/trusted/node', '/owned/plugin/runtime/request.mjs']);
});

test('subagents and unrelated plugin HTTP remain native even when Gemini is selected', async () => {
  const h = harness(); await h.select();
  const event = step({ agentId: 'worker-1' });
  assert.equal((await h.runStep(event)).received, event);
  await h.runStep(step(), async function* (rewritten) {
    const request = wire(rewritten.model);
    assert.equal(await h.http(request, async input => input, 'other-plugin'), request);
    return resultOf(rewritten);
  });
  assert.equal(h.invocations.length, 0);
});

test('same selected HTTP body is replayed from one cached helper result, changed body is refused', async () => {
  const h = harness(); await h.select();
  await h.runStep(step(), async function* (rewritten) {
    const request = wire(rewritten.model);
    const [a, b] = await Promise.all([h.http(request), h.http({ ...request })]);
    assert.deepEqual(a, b);
    const changed = { ...request, init: { ...request.init, body: JSON.stringify({ model: rewritten.model, messages: [] }) } };
    assert.ok('deny' in (await h.http(changed) as object));
    return resultOf(rewritten);
  });
  assert.equal(h.invocations.length, 1);
});

test('unknown/expired own markers are denied without native fallback; later steps get distinct markers', async () => {
  const h = harness(); await h.select();
  let first = '';
  await h.runStep(step(), async function* (rewritten) { first = rewritten.model; await h.http(wire(first)); return resultOf(rewritten); });
  const expired = wire(first);
  assert.ok('deny' in (await h.http(expired, async () => { throw new Error('unexpected native fallback'); }) as object));
  assert.ok('deny' in (await h.http(wire('clauderipple-gemini-carbon-never-issued'), async () => { throw new Error('unexpected native fallback'); }) as object));
  await h.runStep(step({ index: 1 }), async function* (rewritten) {
    assert.notEqual(first, rewritten.model);
    assert.ok('deny' in (await h.http(expired, async () => { throw new Error('unexpected native fallback'); }) as object));
    await h.http(wire(rewritten.model)); return resultOf(rewritten);
  });
  assert.equal(h.invocations.length, 2);
});

test('selected unsupported URL and aborted request are refused, without a helper or upstream call', async () => {
  const h = harness(); await h.select();
  await h.runStep(step(), async function* (rewritten) {
    for (const url of ['https://example.com/v1/messages', 'http://api.anthropic.com/v1/messages', 'https://api.anthropic.com/v1/other']) {
      assert.ok('deny' in (await h.http({ ...wire(rewritten.model), url }, async () => { throw new Error('unexpected upstream'); }) as object));
    }
    const hook = h.hooks.get('http.fetch')!.handler as HttpHook;
    const stop = new AbortController(); stop.abort();
    const next = Object.assign(async () => { throw new Error('unexpected upstream'); }, { origin: { plugin: 'engine' }, signal: stop.signal });
    assert.ok('deny' in (await hook(h.$, wire(rewritten.model), next) as object));
    return resultOf(rewritten);
  });
  assert.equal(h.invocations.length, 0);
});

test('helper error and simulated process timeout refuse Gemini without a raw error or Claude retry', async () => {
  for (const reason of ['google-test-key raw prompt secret', 'simulated process timeout']) {
    const h = harness(); await h.select();
    h.setRun(async () => { throw new Error(reason); });
    let upstream = 0;
    const output = await h.runStep(step(), async function* (rewritten) {
      const response = await h.http(wire(rewritten.model), async () => { upstream++; return {}; });
      assert.ok('deny' in (response as object));
      assert.equal(JSON.stringify(response).includes(reason), false);
      throw new Error('native reader sees denial');
    });
    assert.match(output.result.answer, /No automatic Claude retry/);
    assert.equal(output.result.answer.includes(reason), false);
    assert.equal(output.coreCalls, 1);
    assert.equal(upstream, 0);
    assert.equal(h.invocations.length, 1);
    await h.observe('turn.complete'); await h.select('claude');
    const native = step(); assert.equal((await h.runStep(native)).received, native);
    assert.equal(h.invocations.length, 1);
  }
});

test('native error-handler replay does not call the core twice', async () => {
  const h = harness();
  let calls = 0;
  await assert.rejects(h.http(wire('claude-native'), async () => { calls++; throw new Error('native error'); }), /native error/);
  assert.equal(calls, 1);
  const caught = h.hooks.get('turn.step')!.catcher as StepHook;
  const event = step();
  const next = Object.assign(async function* (input: StepEvent) { assert.equal(input, event); return resultOf(input); }, { called: true });
  assert.equal((await collect(caught(h.$, event, next))).result.answer, 'native');
});

test('selected session/surface changes refuse the turn before core inference', async () => {
  for (const change of [(h: ReturnType<typeof harness>) => h.setId('another'), (h: ReturnType<typeof harness>) => h.setSurfaces(['terminal'])]) {
    const h = harness(); await h.select(); change(h);
    const output = await h.runStep();
    assert.equal(output.coreCalls, 0);
    assert.match(output.result.answer, /No automatic Claude retry/);
    assert.equal(h.invocations.length, 0);
  }
});

test('invalidated Gemini remains refused and an explicit switch back to Claude is always available', async () => {
  const h = harness(); await h.select();
  h.setVersion('2.1.324');
  const picker = find(await h.render(), 'Select');
  assert.ok(picker);
  assert.match(picker.props.label as string, /unavailable/);
  const refused = await h.runStep();
  assert.equal(refused.coreCalls, 0);
  assert.match(refused.result.answer, /No automatic Claude retry/);
  await h.select('claude');
  const native = step();
  assert.equal((await h.runStep(native)).received, native);
  assert.equal(h.invocations.length, 0);
});

test('a host completion without the selected HTTP transport is refused, never labelled Gemini', async () => {
  const h = harness(); await h.select();
  const output = await h.runStep(step(), async function* (rewritten) {
    yield { kind: 'engine', ref: 1 };
    yield { kind: 'text', index: 0, text: 'unexpected native completion' };
    return resultOf(rewritten, 'unexpected native completion');
  });
  assert.equal(JSON.stringify(output.chunks).includes('unexpected native completion'), false);
  assert.match(output.result.answer, /No automatic Claude retry/);
  assert.equal(h.invocations.length, 0);
  const unavailable = find(await h.render(), 'Select');
  assert.match(unavailable?.props.label as string, /unavailable/);
  await h.select('claude');
  assert.equal(find(await h.render(), 'Select'), undefined);
});

test('real helper translation and mod contracts agree with a fake Google endpoint; no live host or provider', async () => {
  const h = harness({ api_key: 'synthetic_google_key_123456' });
  await h.select();
  let googleCalls = 0;
  h.setRun(async () => {
    const output = await handle(h.invocations.at(-1)!.input!, async call => {
      googleCalls++;
      assert.equal(call.url, 'https://generativelanguage.googleapis.com/v1beta/models/gemini-4-carbon:generateContent');
      assert.deepEqual(Object.keys(call.headers).sort(), ['accept', 'content-type', 'x-goog-api-key']);
      assert.equal(JSON.stringify(call).includes('native-secret'), false);
      return { status: 200, body: JSON.stringify({ candidates: [{ content: { parts: [{ text: 'buffered Gemini result' }] }, finishReason: 'STOP' }] }) };
    });
    return { ...helperResult(), stdout: JSON.stringify(output) };
  });
  const output = await h.runStep(step(), async function* (rewritten) {
    const http = await h.http(wire(rewritten.model)) as { value: { status: number; headers: Record<string, string>; text: string } };
    assert.equal(http.value.status, 200);
    assert.equal(http.value.headers['content-type'], 'text/event-stream');
    assert.match(http.value.text, /buffered Gemini result/);
    assert.match(http.value.text, /message_stop/);
    yield { kind: 'text', index: 0, text: 'buffered Gemini result' };
    return resultOf(rewritten, 'buffered Gemini result');
  });
  assert.equal(output.result.answer, 'buffered Gemini result');
  assert.equal(googleCalls, 1);
  assert.equal(h.invocations.length, 1);
});

test('cancellation after helper start discards its response without a retry or signature-cache update', async () => {
  const h = harness(); await h.select();
  let finish: (result: ProcessResult) => void = () => { throw new Error('helper not started'); };
  h.setRun(() => new Promise(resolve => { finish = resolve; }));
  await h.runStep(step(), async function* (rewritten) {
    const hook = h.hooks.get('http.fetch')!;
    const request = wire(rewritten.model);
    const abort = new AbortController();
    let upstream = 0;
    const next = Object.assign(async () => { upstream++; return {}; }, { origin: { plugin: 'engine' }, signal: abort.signal });
    const waiting = (hook.handler as HttpHook)(h.$, request, next);
    abort.abort(); finish(helperResult([['cancelled-tool', 'signature']]));
    await assert.rejects(waiting);
    const denied = await (hook.catcher as HttpHook)(h.$, request, next);
    assert.ok('deny' in (denied as object));
    assert.equal(upstream, 0);
    throw new Error('cancelled');
  });
  assert.equal(h.invocations.length, 1);
  h.setRun(async () => helperResult());
  await h.runStep(step({ index: 1 }), async function* (rewritten) { await h.http(wire(rewritten.model)); return resultOf(rewritten); });
  assert.deepEqual(JSON.parse(h.invocations[1]!.input!).thoughtSignatures, []);
});

test('a separately cancelled duplicate dispatch cannot receive the shared successful helper response', async () => {
  const h = harness(); await h.select();
  let finish: (result: ProcessResult) => void = () => { throw new Error('helper not started'); };
  h.setRun(() => new Promise(resolve => { finish = resolve; }));
  let upstream = 0;
  await h.runStep(step(), async function* (rewritten) {
    const hook = h.hooks.get('http.fetch')!.handler as HttpHook;
    const firstAbort = new AbortController();
    const secondAbort = new AbortController();
    const nextFor = (signal: AbortSignal) => Object.assign(async () => { upstream++; return {}; }, { origin: { plugin: 'engine' }, signal });
    const first = hook(h.$, wire(rewritten.model), nextFor(firstAbort.signal));
    const second = hook(h.$, wire(rewritten.model), nextFor(secondAbort.signal));
    secondAbort.abort();
    finish(helperResult());
    const [firstResponse, secondResponse] = await Promise.all([first, second]);
    assert.ok('value' in (firstResponse as object));
    assert.ok('deny' in (secondResponse as object));
    assert.equal('value' in (secondResponse as object), false);
    return resultOf(rewritten);
  });
  assert.equal(h.invocations.length, 1);
  assert.equal(upstream, 0);
});

test('synchronous next failure releases its marker and permits an explicit return to Claude', async () => {
  const h = harness(); await h.select();
  const entry = h.hooks.get('turn.step')!;
  const event = step();
  let calls = 0;
  const next = Object.assign((): AsyncGenerator<unknown, StepResult> => { calls++; throw new Error('synchronous next failure'); }, { called: true });
  await assert.rejects(collect((entry.handler as StepHook)(h.$, event, next)), /synchronous next failure/);
  const refused = await collect((entry.catcher as StepHook)(h.$, event, next));
  assert.match(refused.result.answer, /No automatic Claude retry/);
  assert.equal(calls, 1);
  await h.observe('turn.complete');
  await h.select('claude');
  const native = step({ turnId: 'next-native-turn' });
  assert.equal((await h.runStep(native)).received, native);
  assert.equal(h.invocations.length, 0);
});

test('selected-stream cleanup releases the marker without replacing the original failure', async () => {
  const h = harness(); await h.select();
  const event = step();
  let cleanups = 0;
  const stream: AsyncGenerator<unknown, StepResult> = {
    async next() { throw new Error('original request failure'); },
    async return() { cleanups++; throw new Error('cleanup failure'); },
    async throw(error: unknown) { throw error; },
    [Symbol.asyncIterator]() { return this; },
    async [Symbol.asyncDispose]() { /* Test stream owns no actual resource. */ },
  };
  const next = Object.assign(() => stream, { called: true });
  await assert.rejects(collect((h.hooks.get('turn.step')!.handler as StepHook)(h.$, event, next)), /original request failure/);
  assert.equal(cleanups, 1);
  await h.observe('turn.complete'); await h.select('claude');
  const native = step(); assert.equal((await h.runStep(native)).received, native);
});

test('busy turns prevent selection; session end resets to native and invalidates stale UI callbacks', async () => {
  const h = harness(); await h.certify();
  const old = find(await h.render(), 'Select')!;
  await h.observe('turn.start');
  (old.props.onSelect as (v: string, e: object) => void)('gemini', { surface: 'desktop' });
  const native = step(); assert.equal((await h.runStep(native)).received, native);
  await h.observe('turn.complete'); await h.select();
  await h.observe('session.end');
  (old.props.onSelect as (v: string, e: object) => void)('gemini', { surface: 'desktop' });
  assert.equal((await h.runStep(native)).received, native);
  assert.equal(h.invocations.length, 0);
});

test('thought signatures are merged only in session memory, bounded, and cleared on session end', async () => {
  const h = harness(); await h.select();
  let count = 0;
  h.setRun(async () => helperResult(Array.from({ length: 80 }, (_, n) => [`id-${count}-${n}`, 'signature'] as Signature)));
  for (; count < 3; count++) await h.runStep(step({ index: count }), async function* (rewritten) {
    await h.http(wire(rewritten.model)); return resultOf(rewritten);
  });
  assert.equal(JSON.parse(h.invocations[0]!.input!).thoughtSignatures.length, 0);
  assert.equal(JSON.parse(h.invocations[1]!.input!).thoughtSignatures.length, 80);
  assert.equal(JSON.parse(h.invocations[2]!.input!).thoughtSignatures.length, 128);
  await h.observe('session.end'); h.setId('session-2'); await h.select();
  await h.runStep(step(), async function* (rewritten) { await h.http(wire(rewritten.model)); return resultOf(rewritten); });
  assert.equal(JSON.parse(h.invocations[3]!.input!).thoughtSignatures.length, 0);
});

test('helper invocation has no shell/PATH lookup, bounded input, and explicit best-effort environment overrides', () => {
  const payload = { protocol: 1 as const, apiKey: 'key', request: { model: 'gemini-4-carbon' }, thoughtSignatures: [] };
  const invocation = createHelperInvocation('C:\\Program Files\\nodejs\\node.exe', 'C:\\owned\\plugin', payload);
  assert.equal(invocation.init.env.NODE_OPTIONS, '');
  assert.equal(invocation.init.env.NODE_PATH, '');
  assert.equal(invocation.init.env.HTTPS_PROXY, '');
  assert.equal(invocation.init.env.https_proxy, '');
  assert.equal(invocation.init.env.NODE_TLS_REJECT_UNAUTHORIZED, '');
  assert.equal(invocation.init.env.node_tls_reject_unauthorized, '');
  assert.equal(invocation.init.env.NODE_USE_ENV_PROXY, '');
  assert.equal(invocation.init.env.OPENSSL_CONF, '');
  assert.equal(invocation.init.env.node_options, '');
  for (const name of ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN_FILE', 'ANTHROPIC_BASE_URL', 'OPENAI_API_KEY', 'GEMINI_API_KEY', 'GOOGLE_API_KEY', 'GOOGLE_APPLICATION_CREDENTIALS']) {
    assert.equal(invocation.init.env[name], '');
    assert.equal(invocation.init.env[name.toLowerCase()], '');
  }
  assert.equal(invocation.argv.join(' ').includes(payload.apiKey), false);
  assert.equal(Object.values(invocation.init.env).includes(payload.apiKey), false);
  assert.throws(() => createHelperInvocation('node', '/owned', payload));
  assert.throws(() => createHelperInvocation('/bin/sh', '/owned', payload));
  assert.throws(() => createHelperInvocation('/trusted/node', '/owned', { ...payload, request: { text: 'x'.repeat(8 * 1024 * 1024) } }));
});

function controlledProcess(neverAcknowledgeClose = false) {
  type Item = IteratorResult<ProcessSpawnChunk, ProcessSpawnResult>;
  const queue: Item[] = [];
  let waiting: ((item: Item) => void) | undefined;
  let closeCalls = 0;
  let closed = false;
  let resolveExit: (exit: ProcessSpawnResult) => void = () => {};
  let rejectExit: (error: unknown) => void = () => {};
  const result = new Promise<ProcessSpawnResult>((resolve, reject) => { resolveExit = resolve; rejectExit = reject; });
  const publish = (item: Item): void => { if (waiting) { const resolve = waiting; waiting = undefined; resolve(item); } else queue.push(item); };
  const stream: HookStream<ProcessSpawnChunk, ProcessSpawnResult> = {
    result,
    next: async () => queue.shift() ?? await new Promise<Item>(resolve => { waiting = resolve; }),
    return: async () => {
      closeCalls++; closed = true;
      const exit = { code: null, signal: 'SIGTERM' };
      rejectExit(new Error('mock stream closed'));
      publish({ done: true, value: exit });
      if (neverAcknowledgeClose) return await new Promise<Item>(() => {});
      return { done: true, value: exit };
    },
    async throw(error: unknown) { throw error; },
    [Symbol.asyncIterator]() { return this; },
    async [Symbol.asyncDispose]() { await this.return(undefined as never); },
  };
  return {
    stream,
    chunk(stream: 'stdout' | 'stderr', text: string) { publish({ done: false, value: { stream, text } }); },
    exit(code: number | null, signal: string | null = null) { const exit = { code, signal }; resolveExit(exit); publish({ done: true, value: exit }); },
    closeCalls: () => closeCalls,
    closed: () => closed,
  };
}

function collectorFixture(neverAcknowledgeClose = false) {
  const child = controlledProcess(neverAcknowledgeClose);
  const timers: { ms: number; callback(): void; cancelled: boolean }[] = [];
  const invocations: ProcessSpawnRequest[] = [];
  const host = {
    process: { spawn(request: ProcessSpawnRequest) { invocations.push(request); return child.stream; } },
    clock: { after(ms: number, callback: () => void) { const timer = { ms, callback, cancelled: false }; timers.push(timer); return { cancel() { timer.cancelled = true; } }; } },
  };
  const abort = new AbortController();
  const invocation = createHelperInvocation('/trusted/node', '/owned/plugin', { protocol: 1, apiKey: 'stdin-only-secret', request: { model: 'gemini-4-carbon' }, thoughtSignatures: [] });
  return { child, timers, invocations, host, abort, invocation };
}

test('spawn collector buffers bounded stdout, drops stderr, and closes/cancels after a successful exit', async () => {
  const f = collectorFixture();
  const pending = collectHelper(f.host, f.invocation, f.abort.signal);
  f.child.chunk('stdout', '{"ok":'); f.child.chunk('stderr', 'raw-secret-diagnostic'); f.child.chunk('stdout', 'true}'); f.child.exit(0);
  const result = await pending;
  assert.equal(result.stdout, '{"ok":true}');
  assert.equal(result.stderr, '');
  assert.equal(f.child.closeCalls(), 1);
  assert.equal(f.timers[0]!.ms, 120_000);
  assert.equal(f.timers[0]!.cancelled, true);
  assert.equal(f.invocations[0]!.input, f.invocation.init.stdin);
  assert.equal(JSON.stringify(f.invocations[0]!.argv).includes('stdin-only-secret'), false);
  assert.equal(JSON.stringify(f.invocations[0]!.env).includes('stdin-only-secret'), false);
});

test('spawn collector closes the child immediately on abort, without waiting for a close acknowledgement', async () => {
  const f = collectorFixture(true);
  const pending = collectHelper(f.host, f.invocation, f.abort.signal);
  f.abort.abort();
  assert.equal(f.child.closed(), true);
  await assert.rejects(pending, /Gemini helper failed/);
  assert.equal(f.child.closeCalls(), 1);
  assert.equal(f.timers[0]!.cancelled, true);
});

test('spawn collector deadline closes the child and remains bounded when close acknowledgement stalls', async () => {
  const f = collectorFixture(true);
  const pending = collectHelper(f.host, f.invocation, f.abort.signal);
  f.timers[0]!.callback();
  assert.equal(f.child.closed(), true);
  await assert.rejects(pending, /Gemini helper failed/);
  assert.equal(f.child.closeCalls(), 1);
  assert.equal(f.timers[0]!.cancelled, true);
});

test('spawn collector closes on stdout/stderr overflow and nonzero or signalled exits', async () => {
  for (const failure of ['stdout', 'stderr', 'nonzero', 'signal'] as const) {
    const f = collectorFixture();
    const pending = collectHelper(f.host, f.invocation, f.abort.signal);
    if (failure === 'stdout') f.child.chunk('stdout', 'x'.repeat(3 * 1024 * 1024 + 1));
    else if (failure === 'stderr') f.child.chunk('stderr', 'secret'.repeat(11_000));
    else if (failure === 'nonzero') f.child.exit(1);
    else f.child.exit(null, 'SIGTERM');
    await assert.rejects(pending, /Gemini helper failed/);
    assert.equal(f.child.closeCalls(), 1);
    assert.equal(f.timers[0]!.cancelled, true);
  }
});

test('spawn collector bounds fragmented output chunks and refuses already-aborted work without spawning', async () => {
  const fragmented = collectorFixture();
  const pending = collectHelper(fragmented.host, fragmented.invocation, fragmented.abort.signal);
  for (let n = 0; n < 8193; n++) fragmented.child.chunk('stdout', 'x');
  await assert.rejects(pending, /Gemini helper failed/);
  assert.equal(fragmented.child.closeCalls(), 1);
  const cancelled = collectorFixture(); cancelled.abort.abort();
  await assert.rejects(collectHelper(cancelled.host, cancelled.invocation, cancelled.abort.signal), /Helper unavailable/);
  assert.equal(cancelled.invocations.length, 0);
  assert.equal(cancelled.timers.length, 0);
});

test('spawn collector cancels the timer after synchronous spawn failure', async () => {
  const f = collectorFixture();
  f.host.process.spawn = () => { throw new Error('raw native launch diagnostic'); };
  await assert.rejects(collectHelper(f.host, f.invocation, f.abort.signal), /Gemini helper failed/);
  assert.equal(f.timers[0]!.cancelled, true);
  assert.equal(f.child.closeCalls(), 0);
});

test('unavailable spawn/timer capability never falls back to process.run', async () => {
  const h = harness();
  h.$.process = { run() { throw new Error('run fallback'); } } as unknown as NonNullable<Host['process']>;
  assert.equal(find(await h.render(), 'Select'), undefined);
  const noTimer = harness(); delete noTimer.$.clock;
  assert.equal(find(await noTimer.render(), 'Select'), undefined);
  assert.equal(h.invocations.length, 0);
  assert.equal(noTimer.invocations.length, 0);
});

test('helper response limits, exact protocol, headers, and signature shape are validated', () => {
  assert.deepEqual(readHelperResult(helperResult()).response.headers, { 'content-type': 'application/json' });
  for (const change of [
    { exitCode: 1 }, { isStdoutTruncated: true }, { isStderrTruncated: true }, { stdout: 'not-json secret' },
    { stdout: 'x'.repeat(3 * 1024 * 1024 + 1) },
  ]) assert.throws(() => readHelperResult({ ...helperResult(), ...change }));
  const parsed = JSON.parse(helperResult().stdout);
  for (const value of [
    { ...parsed, protocol: 2 },
    { ...parsed, response: { ...parsed.response, headers: { 'content-type': 'text/html' } } },
    { ...parsed, response: { ...parsed.response, ok: false } },
    { ...parsed, thoughtSignatures: [['duplicate', 'a'], ['duplicate', 'b']] },
    { ...parsed, thoughtSignatures: [['id', 'x'.repeat(16_385)]] },
    { ...parsed, thoughtSignatures: Array.from({ length: 129 }, (_, n) => [`id${n}`, 'a']) },
  ]) assert.throws(() => readHelperResult({ ...helperResult(), stdout: JSON.stringify(value) }));
  const withPrivateHeaders = { ...parsed, response: { ...parsed.response, headers: { 'content-type': 'application/json', 'set-cookie': 'discard' } } };
  assert.deepEqual(readHelperResult({ ...helperResult(), stdout: JSON.stringify(withPrivateHeaders) }).response.headers, { 'content-type': 'application/json' });
});
