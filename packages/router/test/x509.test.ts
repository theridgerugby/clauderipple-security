import { test } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import tls from "node:tls";
import { createCa, createLeaf, subjectDer } from "../src/x509.ts";

const ca = createCa();
const leaf = createLeaf({ host: "api.anthropic.com", caCertPem: ca.certPem, caKeyPem: ca.keyPem });

test("the CA is a v3 self-signed certificate authority", () => {
  const c = new crypto.X509Certificate(ca.certPem);
  assert.equal(c.ca, true);
  assert.equal(c.subject, "CN=ClaudeRipple local CA");
  assert.equal(c.issuer, c.subject);
  assert.ok(c.verify(crypto.createPublicKey(ca.certPem)), "self-signature verifies");
  // RSA on purpose: Node's TLS client rejects EC keys written with explicit curve parameters.
  // The digest is covered by the handshake test below — Node refuses SHA-1 as "ca md too weak".
  assert.equal(crypto.createPublicKey(ca.certPem).asymmetricKeyType, "rsa");
});

test("the leaf chains to the CA and is a serverAuth certificate for its host", () => {
  const l = new crypto.X509Certificate(leaf.certPem);
  assert.equal(l.subject, "CN=api.anthropic.com");
  assert.equal(l.ca, false);
  assert.equal(l.subjectAltName, "DNS:api.anthropic.com");
  assert.ok(l.checkIssued(new crypto.X509Certificate(ca.certPem)), "issued by our CA");
  assert.ok(l.verify(crypto.createPublicKey(ca.certPem)), "signature verifies against the CA key");
  assert.ok(l.checkHost("api.anthropic.com"), "matches its host");
  assert.equal(l.checkHost("evil.example"), undefined, "does not match another host");
});

test("the leaf's issuer is byte-identical to the CA's subject", () => {
  // Re-encoding the name from its string form could pick a different string type and break chain
  // building against a CA we did not issue — including one already trusted in a keychain.
  const caSubject = subjectDer(ca.certPem);
  const leafDer = new crypto.X509Certificate(leaf.certPem).raw;
  assert.ok(leafDer.includes(caSubject), "the CA's exact subject bytes appear in the leaf");
});

test("IPv4 and IPv6 hosts use binary IP SANs, including compressed and mapped forms", () => {
  for (const host of ["127.0.0.1", "::1", "2001:db8:1:2:3:4:5:6", "::ffff:192.0.2.1", "::"]) {
    const issued = createLeaf({ host, caCertPem: ca.certPem, caKeyPem: ca.keyPem });
    const cert = new crypto.X509Certificate(issued.certPem);
    assert.match(cert.subjectAltName!, /^IP Address:/);
    assert.ok(cert.checkIP(host), host);
    assert.equal(cert.checkHost("collector.example"), undefined);
    assert.ok(cert.verify(new crypto.X509Certificate(ca.certPem).publicKey));
  }
  assert.throws(() => createLeaf({ host: "fe80::1%lo", caCertPem: ca.certPem, caKeyPem: ca.keyPem }), /scope identifier/);
});

test("literal loopback TLS hostname validation accepts the new IP SAN", async () => {
  const issued = createLeaf({ host: "127.0.0.1", caCertPem: ca.certPem, caKeyPem: ca.keyPem });
  const server = tls.createServer({ cert: issued.certPem, key: issued.keyPem }, socket => socket.end("ok"));
  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as { port: number };
  try {
    assert.equal(await new Promise<boolean>((resolve, reject) => {
      const socket = tls.connect({ host: "127.0.0.1", port, ca: ca.certPem, rejectUnauthorized: true }, () => {
        resolve(socket.authorized);
        socket.end();
      });
      socket.on("error", reject);
    }), true);
  } finally { server.close(); }
});

test("a real TLS handshake against the leaf is authorized", async () => {
  const server = tls.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (s) => s.end("ok"));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as { port: number };
  try {
    const authorized = await new Promise<boolean>((resolve, reject) => {
      const s = tls.connect({ port, host: "127.0.0.1", servername: "api.anthropic.com", ca: [ca.certPem] }, () => {
        resolve(s.authorized);
        s.end();
      });
      s.on("error", reject);
    });
    assert.equal(authorized, true);
  } finally {
    server.close();
  }
});

test("a leaf for one host is rejected when presented for another", async () => {
  const server = tls.createServer({ cert: leaf.certPem, key: leaf.keyPem }, (s) => s.end("ok"));
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const { port } = server.address() as { port: number };
  try {
    await assert.rejects(
      () =>
        new Promise((resolve, reject) => {
          const s = tls.connect({ port, host: "127.0.0.1", servername: "evil.example", ca: [ca.certPem] }, () => {
            resolve(null);
            s.end();
          });
          s.on("error", reject);
        }),
      /altnames/,
    );
  } finally {
    server.close();
  }
});

test("private keys are written as PKCS#8 PEM, unencrypted", () => {
  for (const pem of [ca.keyPem, leaf.keyPem]) {
    assert.match(pem, /^-----BEGIN PRIVATE KEY-----\n/);
    assert.doesNotMatch(pem, /ENCRYPTED/);
    assert.doesNotThrow(() => crypto.createPrivateKey(pem));
  }
});

test("serial numbers are positive and unique per certificate", () => {
  const a = new crypto.X509Certificate(createLeaf({ host: "a.example", caCertPem: ca.certPem, caKeyPem: ca.keyPem }).certPem);
  const b = new crypto.X509Certificate(createLeaf({ host: "b.example", caCertPem: ca.certPem, caKeyPem: ca.keyPem }).certPem);
  assert.notEqual(a.serialNumber, b.serialNumber);
  for (const c of [a, b]) {
    const topByte = Number.parseInt(c.serialNumber.slice(0, 2), 16);
    assert.ok(topByte <= 0x7f, `serial must stay positive, got ${c.serialNumber}`);
  }
});
