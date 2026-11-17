import test from "node:test";
import assert from "node:assert/strict";
import nacl from "tweetnacl";
import { normalizeRelay, pairingUrl, relayPairingUrl } from "../src/config.ts";
import { RelayHost } from "../src/relay.ts";
import { toB64u } from "../src/e2ee.ts";
import { relayClientUrl, secureRelayPairing } from "../web/secure.ts";

const hostKey = nacl.box.keyPair();
const hpk = toB64u(hostKey.publicKey);
const server = "server-fixture-0123456789";
const token = "phone-token-canary-01234567890123456789";

test("direct phone pairing never formats an HTTP URL containing a capability", () => {
  assert.throws(() => pairingUrl("127.0.0.1", 8797, token), error => {
    assert.ok(error instanceof Error);
    assert.match(error.message, /Direct HTTP\/LAN phone connections are disabled/);
    assert.ok(!error.message.includes(token));
    return true;
  });
});

test("relay URLs require a credential-free HTTPS origin with no path, query, or fragment", () => {
  for (const url of ["http://127.0.0.1:8797", "http://localhost", "http://[::1]:8797", "http://relay.example", "https://user:secret@relay.example", "https://relay.example/path", "https://relay.example?token=canary", "https://relay.example/#canary", "wss://relay.example"]) {
    assert.throws(() => normalizeRelay(url), /HTTPS/);
    assert.throws(() => relayPairingUrl(url, server, hpk, token), /HTTPS/);
  }
  assert.equal(normalizeRelay("https://relay.example/"), "https://relay.example");
  const url = new URL(relayPairingUrl("https://relay.example", server, hpk, token));
  assert.equal(url.protocol, "https:");
  assert.equal(url.search, "");
  assert.equal(new URLSearchParams(url.hash.slice(1)).get("pair"), token);
});

test("stored relay configuration is revalidated before a host registration socket can receive its secret", () => {
  let sockets = 0;
  for (const relay of ["http://127.0.0.1:8797", "http://relay.example", "https://relay.example?secret=canary"]) {
    assert.throws(() => new RelayHost({ relay, serverId: server, secret: token, hostKey, nacl,
      makeSocket: () => { sockets++; throw new Error("must not open"); },
      onPeer: () => { throw new Error("must not connect"); },
    }), /HTTPS/);
  }
  assert.equal(sockets, 0);
});

test("browser relay destination always uses WSS and must match its authenticated page origin", () => {
  const pairing = { url: "https://relay.example", server, hpk };
  assert.equal(relayClientUrl(pairing), `wss://relay.example/ws/client?server=${server}`);
  assert.deepEqual(secureRelayPairing(pairing, pairing.url), pairing);
  assert.equal(secureRelayPairing(pairing, "https://other.example"), null);
  for (const bad of [{ ...pairing, url: "http://localhost" }, { ...pairing, hpk: "invalid" }, { ...pairing, server: "bad/id" }, { ...pairing, url: "https://relay.example/" }]) {
    assert.equal(secureRelayPairing(bad, bad.url), null);
    assert.throws(() => relayClientUrl(bad), /HTTPS relay pairing/);
  }
});
