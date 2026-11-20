// A test-only transport for HostServer's post-decryption session protocol. Production phone
// peers arrive through RelayHost's authenticated encryption; this loopback adapter proves no
// relay encryption or server authentication. Public /ws refusal has separate real HTTP tests.
import { once } from "node:events";
import type { TestContext } from "node:test";
import { WebSocketServer } from "ws";
import { FRAME_CAP } from "../src/protocol.ts";
import type { HostServer } from "../src/server.ts";

const fixtures = new WeakMap<HostServer, Promise<string>>();

export function peerFixtureUrl(t: TestContext, host: HostServer): Promise<string> {
  const existing = fixtures.get(host);
  if (existing) return existing;
  const opened = (async () => {
    const adapter = new WebSocketServer({ host: "127.0.0.1", port: 0, maxPayload: FRAME_CAP });
    adapter.on("connection", peer => host.connected(peer));
    t.after(async () => {
      for (const peer of adapter.clients) peer.terminate();
      await new Promise<void>(resolve => adapter.close(() => resolve()));
      fixtures.delete(host);
    });
    await once(adapter, "listening");
    const address = adapter.address();
    if (!address || typeof address === "string") throw new Error("test peer adapter did not bind");
    return `ws://127.0.0.1:${address.port}/post-decryption-fixture`;
  })();
  fixtures.set(host, opened);
  return opened;
}
