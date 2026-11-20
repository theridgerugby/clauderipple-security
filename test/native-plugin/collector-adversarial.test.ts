import assert from 'node:assert/strict';
import test from 'node:test';
import type { HookStream, ProcessSpawnChunk, ProcessSpawnResult } from 'claude-code';
import { collectHelper, createHelperInvocation } from '../../plugins/gemini-native/hooks/register.ts';

// These exercise the production collector with inert host-boundary mocks.
// No real timer, process, provider, filesystem write or Desktop host is used.
type Failure = 'timer-throws' | 'timer-fires-immediately' | 'next-throws'
  | 'return-throws' | 'result-rejects-and-next-throws';
type Host = Parameters<typeof collectHelper>[0];

function fixture(failure: Failure) {
  const invocation = createHelperInvocation('/fixture/node', '/fixture/plugin', {
    protocol: 1,
    apiKey: 'synthetic_google_key_123456',
    request: { model: 'gemini-4-carbon' },
    thoughtSignatures: [],
  });
  const counts = { spawn: 0, close: 0, cancel: 0, next: 0 };
  const exit: ProcessSpawnResult = { code: 0, signal: null };
  const host: Host = {
    process: {
      spawn(request) {
        counts.spawn++;
        assert.deepEqual(request, {
          argv: invocation.argv, cwd: invocation.init.cwd,
          env: invocation.init.env, input: invocation.init.stdin,
        });
        const child: HookStream<ProcessSpawnChunk, ProcessSpawnResult> = {
          // Intentionally leave the rejected alternative result view unhandled
          // here. The collector must observe it, including when next() throws.
          result: failure === 'result-rejects-and-next-throws'
            ? Promise.reject(new Error('raw child result diagnostic'))
            : Promise.resolve(exit),
          next() {
            counts.next++;
            if (failure === 'next-throws' || failure === 'result-rejects-and-next-throws') {
              throw new Error('raw child pull diagnostic');
            }
            return Promise.resolve({ done: true, value: exit });
          },
          return() {
            counts.close++;
            if (failure === 'return-throws') throw new Error('raw child close diagnostic');
            return Promise.resolve({ done: true, value: exit });
          },
          async throw(error: unknown) { throw error; },
          [Symbol.asyncIterator]() { return this; },
          async [Symbol.asyncDispose]() { await this.return(undefined as never); },
        };
        return child;
      },
    },
    clock: {
      after(ms, callback) {
        assert.equal(ms, invocation.init.timeoutMs);
        if (failure === 'timer-throws') throw new Error('raw timer diagnostic');
        if (failure === 'timer-fires-immediately') callback();
        return { cancel() { counts.cancel++; } };
      },
    },
  };
  return { host, invocation, counts };
}

const cases: readonly [Failure, string][] = [
  ['timer-throws', 'synchronous timer failure prevents child creation'],
  ['timer-fires-immediately', 'an already-fired deadline prevents child creation'],
  ['next-throws', 'synchronous child pull failure closes the child and cancels the timer'],
  ['return-throws', 'synchronous child cleanup failure is redacted and cancels the timer'],
  ['result-rejects-and-next-throws', 'a rejected result view is observed when the child pull also fails'],
];

for (const [failure, description] of cases) {
  test(`spawn collector: ${description}`, async () => {
    const f = fixture(failure);
    await assert.rejects(
      collectHelper(f.host, f.invocation, new AbortController().signal),
      (error: unknown) => error instanceof Error && error.message === 'Gemini helper failed',
    );
    const launched = failure.startsWith('timer-') ? 0 : 1;
    assert.deepEqual(f.counts, {
      spawn: launched, close: launched, next: launched,
      cancel: failure === 'timer-throws' ? 0 : 1,
    });
  });
}
