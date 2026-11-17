// Browser business-logic fixtures use the production authenticated E2EE channel. This in-process
// transport does not claim to validate a deployed relay's authentication or TLS certificate.
import assert from "node:assert/strict";
import nacl from "tweetnacl";
import { hostAccept, toB64u } from "../src/e2ee.ts";
import type { Channel } from "../src/e2ee.ts";

const hostKey = nacl.box.keyPair();
export const fixtureNacl = nacl;
export function fixtureRelayPairing(origin: string) {
  return { url: origin, server: "server-fixture-0123456789", hpk: toB64u(hostKey.publicKey) };
}

export class FixtureRelaySocket {
  static latest: FixtureRelaySocket | null = null;
  static current(): FixtureRelaySocket | null { return this.latest; }
  static respond: ((op: Record<string, unknown>) => unknown) | null = null;
  readyState = 0;
  binaryType = "arraybuffer";
  /** Captured after decryption by the fixture host. No application message uses plaintext WS. */
  frames: string[] = [];
  url: string;
  private channel: Channel | null = null;
  onopen: (() => void) | null = null;
  onmessage: ((ev: { data: unknown }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  constructor(url: string) { this.url = url; FixtureRelaySocket.latest = this; }
  send(data: string | Uint8Array): void {
    if (typeof data === "string") {
      const accepted = hostAccept(nacl, hostKey, data);
      this.channel = accepted.channel;
      this.onmessage?.({ data: accepted.text });
      return;
    }
    assert.ok(this.channel, "application frames require a completed host-authenticated handshake");
    const plain = this.channel.open(data);
    this.frames.push(plain);
    const msg = JSON.parse(plain) as { t?: string; reqId?: string; op?: Record<string, unknown> };
    if (msg.t !== "req" || !msg.reqId) return;
    const reqId = msg.reqId;
    void Promise.resolve().then(() => FixtureRelaySocket.respond ? FixtureRelaySocket.respond(msg.op ?? {}) : null).then(
      value => this.deliver({ t: "res", reqId, ok: true, data: value }),
      error => this.deliver({ t: "res", reqId, ok: false, error: String(error) }),
    );
  }
  open(): void { this.readyState = 1; this.onopen?.(); this.onmessage?.({ data: '{"relay":"open"}' }); }
  deliver(msg: unknown): void {
    assert.ok(this.channel);
    this.onmessage?.({ data: this.channel.seal(JSON.stringify(msg)).slice().buffer });
  }
  close(): void { this.readyState = 3; this.onclose?.(); }
}
