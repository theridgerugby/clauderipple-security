import test from "node:test";
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
import path from "node:path";

const { verifySystemSandboxHelper } = await import(pathToFileURL(path.resolve(import.meta.dirname, "../test-native/linux-sandbox.mjs")).href);
const helper = "/opt/google/chrome/chrome-sandbox";
const file = { uid: 0, nlink: 1, mode: 0o104755, isFile: () => true, isDirectory: () => false, isSymbolicLink: () => false };
const directory = { uid: 0, mode: 0o40755, isDirectory: () => true, isSymbolicLink: () => false };

function fixture(overrides: Record<string, object> = {}, resolved = helper) {
  const inspected: string[] = [];
  return {
    inspected,
    realpathSync: () => resolved,
    lstatSync: (name: string) => {
      inspected.push(name);
      assert.ok([helper, "/opt/google/chrome", "/opt/google", "/opt", "/"].includes(name));
      return { ...(name === helper ? file : directory), ...overrides[name] };
    },
  };
}

test("native Linux accepts only an existing protected system sandbox helper", () => {
  const files = fixture();
  verifySystemSandboxHelper(helper, files);
  assert.deepEqual(files.inspected, [helper, "/opt/google/chrome", "/opt/google", "/opt", "/"]);
});

test("native Linux rejects helper aliases, writable files, wrong ownership and unsafe ancestors", () => {
  assert.throws(() => verifySystemSandboxHelper("relative/chrome-sandbox", fixture()), /absolute/);
  assert.throws(() => verifySystemSandboxHelper(helper, fixture({}, "/different/helper")), /unaliased/);
  for (const change of [{ uid: 1000 }, { nlink: 2 }, { mode: 0o100755 }, { mode: 0o104777 }, { isSymbolicLink: () => true }, { isFile: () => false }]) {
    assert.throws(() => verifySystemSandboxHelper(helper, fixture({ [helper]: change })), /root-owned with mode 4755/);
  }
  for (const parent of ["/opt/google/chrome", "/opt/google", "/opt", "/"]) {
    for (const change of [{ uid: 1000 }, { mode: 0o40777 }, { isSymbolicLink: () => true }, { isDirectory: () => false }]) {
      assert.throws(() => verifySystemSandboxHelper(helper, fixture({ [parent]: change })), /ancestors/);
    }
  }
});

test("native Linux reports only safe helper metadata when a runner prerequisite fails", () => {
  assert.throws(() => verifySystemSandboxHelper(helper, fixture({ [helper]: { uid: 1001, mode: 0o100755 } })), (error: Error) => {
    assert.match(error.message, /"uid":1001/);
    assert.match(error.message, /"mode":"755"/);
    assert.match(error.message, /"links":1/);
    assert.equal(error.message.includes(helper), false);
    return true;
  });
});
