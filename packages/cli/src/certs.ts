// Generate the local CA and the api.anthropic.com leaf certificate. Pure node:crypto (see
// ../../router/src/x509.ts) so this works wherever Node runs, including Windows, which ships no
// openssl. Nothing is installed in any trust store; the CA is handed to Node only, through
// NODE_EXTRA_CA_CERTS (picker mode additionally trusts it in the login keychain).

import fs from "node:fs";
import path from "node:path";
import { createCa, createLeaf } from "../../router/src/x509.ts";
import { assertPrivateTarget, ensurePrivateDirectory, readPrivateFile } from "../../router/src/private-file.ts";
import { withFileLock, writePrivateFileAtomic } from "../../router/src/locked-file.ts";

export type CertPaths = { caPem: string; caKey: string; leafPem: string; leafKey: string };

export function certPaths(home: string): CertPaths {
  return {
    caPem: path.join(home, "ca.pem"),
    caKey: path.join(home, "ca.key"),
    leafPem: path.join(home, "leaf.pem"),
    leafKey: path.join(home, "leaf.key"),
  };
}

export function generateCerts(home: string, upstream = "api.anthropic.com", days = 3650): CertPaths {
  ensurePrivateDirectory(home);
  const p = certPaths(home);
  withFileLock(path.join(home, "certificates"), () => {
    // Refuse unsafe destinations before changing any member of the certificate set.
    for (const file of Object.values(p)) assertPrivateTarget(file);
    const ca = createCa({ days });
    const leaf = createLeaf({ host: upstream, caCertPem: ca.certPem, caKeyPem: ca.keyPem, days: Math.min(days, 825) });
    writePrivateFileAtomic(p.caPem, ca.certPem);
    writePrivateFileAtomic(p.caKey, ca.keyPem);
    writePrivateFileAtomic(p.leafPem, leaf.certPem);
    writePrivateFileAtomic(p.leafKey, leaf.keyPem);
  });
  return p;
}

export function certsExist(home: string): boolean {
  const p = certPaths(home);
  if (![p.caPem, p.caKey, p.leafPem, p.leafKey].every((f) => fs.existsSync(f))) return false;
  // Validate and tighten existing key files too, not only freshly generated certificates.
  for (const file of Object.values(p)) readPrivateFile(file, 64 * 1024);
  return true;
}
