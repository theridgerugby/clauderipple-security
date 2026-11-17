// Release-only policy. No identity is discovered or created, and this module never publishes.
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
export class ReleaseGateError extends Error {}
const fail = message => { throw new ReleaseGateError(message); };
const present = value => typeof value === "string" && value.trim().length > 0;
const clean = value => present(value) && !/[\0-\x1f\x7f]/.test(value);

// These compatibility fuses remain enabled deliberately: CLI/router run as Node and support
// NODE_EXTRA_CA_CERTS. A production check verifies the exact same policy as package.json.
export const RELEASE_FUSES = Object.freeze({
  runAsNode: true,
  enableNodeOptionsEnvironmentVariable: true,
  enableNodeCliInspectArguments: false,
  enableEmbeddedAsarIntegrityValidation: true,
  onlyLoadAppFromAsar: true,
  grantFileProtocolExtraPrivileges: false,
});

export function releaseTarget(args) {
  if (args.length !== 1 || !["mac", "win"].includes(args[0])) fail("Usage: node scripts/release.mjs mac|win (no override flags)");
  return args[0];
}

/** Validate configuration before generating icons, invoking a builder or touching a signer. */
export function releasePlan(target, env = process.env, platform = process.platform) {
  const host = target === "mac" ? "darwin" : target === "win" ? "win32" : null;
  if (!host || platform !== host) fail("Production desktop releases require their matching native macOS or Windows host");
  if (env.GITHUB_EVENT_NAME?.startsWith("pull_request") || present(env.CSC_FOR_PULL_REQUEST)) fail("Production signing is forbidden in pull-request jobs");
  if (env.ELECTRON_DISABLE_SANDBOX || env.ELECTRON_RUN_AS_NODE) fail("Production release commands require a normal sandbox-enabled environment");
  if (target === "mac") {
    const team = env.RIPPLE_MAC_TEAM_ID;
    const identity = env.RIPPLE_MAC_SIGNING_IDENTITY;
    if (team?.length !== 10 || !/^[A-Z0-9]{10}$/.test(team)) fail("Set RIPPLE_MAC_TEAM_ID to the authorized Apple Developer team");
    if (!clean(identity) || !identity.startsWith("Developer ID Application: ") || !identity.endsWith(` (${team})`)) fail("Set RIPPLE_MAC_SIGNING_IDENTITY to the full authorized Developer ID Application identity for that team");
    if (present(env.CSC_LINK) && !present(env.CSC_KEY_PASSWORD)) fail("Imported production signing certificates require CSC_KEY_PASSWORD");
    // Mirror the credential modes supported by the pinned builder. Reject partial/mixed modes
    // so an unrelated inherited environment variable cannot select a different Apple account.
    const modes = [
      ["APPLE_ID", "APPLE_APP_SPECIFIC_PASSWORD", "APPLE_TEAM_ID"],
      ["APPLE_API_KEY", "APPLE_API_KEY_ID", "APPLE_API_ISSUER"],
      ["APPLE_KEYCHAIN_PROFILE"],
    ];
    const selected = modes.filter(keys => keys.some(key => present(env[key])));
    if (selected.length !== 1 || !selected[0].every(key => present(env[key]))) fail("Set exactly one complete Apple notarization credential mode; notarization cannot be skipped");
    if (present(env.APPLE_TEAM_ID) && env.APPLE_TEAM_ID !== team) fail("The notarization Apple team must match RIPPLE_MAC_TEAM_ID");
    if (present(env.APPLE_KEYCHAIN) && !present(env.APPLE_KEYCHAIN_PROFILE)) fail("APPLE_KEYCHAIN requires APPLE_KEYCHAIN_PROFILE");
    return Object.freeze({ target, host, team, identity, importedCertificate: present(env.CSC_LINK) });
  }
  const thumbprint = env.RIPPLE_WINDOWS_CERT_SHA1;
  if (thumbprint?.length !== 40 || !/^[a-fA-F0-9]{40}$/.test(thumbprint)) fail("Set RIPPLE_WINDOWS_CERT_SHA1 to the authorized code-signing certificate thumbprint");
  let timestamp;
  if (!clean(env.RIPPLE_WINDOWS_TIMESTAMP_URL)) fail("Set RIPPLE_WINDOWS_TIMESTAMP_URL to the signing provider's HTTPS RFC3161 endpoint");
  try { timestamp = new URL(env.RIPPLE_WINDOWS_TIMESTAMP_URL); } catch { fail("Set RIPPLE_WINDOWS_TIMESTAMP_URL to the signing provider's HTTPS RFC3161 endpoint"); }
  if (timestamp.protocol !== "https:" || timestamp.username || timestamp.password || timestamp.hash || timestamp.port) fail("The Windows timestamp endpoint must use HTTPS without credentials, a fragment or a nonstandard port");
  const importedCertificate = present(env.WIN_CSC_LINK) || present(env.CSC_LINK);
  if (importedCertificate && !present(env.WIN_CSC_KEY_PASSWORD ?? env.CSC_KEY_PASSWORD)) fail("Imported Windows production signing certificates require a certificate password");
  return Object.freeze({ target, host, thumbprint: thumbprint.toUpperCase(), timestamp: timestamp.href, importedCertificate });
}

/** Strong settings override manifest defaults; publish remains disabled at both API levels. */
export function productionConfig(manifest, plan, output, afterSign) {
  if (manifest.build?.productName !== "ClaudeRipple" || !clean(manifest.version) || !/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(manifest.version)) fail("Unexpected desktop release identity or version");
  return {
    ...manifest.build, extends: null, publish: null,
    forceCodeSigning: true, asar: true, electronFuses: { ...RELEASE_FUSES },
    // The isolated runtime is already supplied by the reviewed lockfile. Its stage gate
    // refuses native addons; no dependency lifecycle/rebuild code runs during packaging.
    npmRebuild: false, nodeGypRebuild: false,
    beforePack: require.resolve("./stage-runtime.mjs"),
    // The pinned builder excludes a matcher's root node_modules. The second explicit
    // mapping is required for source entries outside app.asar to resolve their packages.
    extraResources: [
      { from: "release-native/runtime/${os}/${arch}", to: "clauderipple" },
      { from: "release-native/runtime/${os}/${arch}/node_modules", to: "clauderipple/node_modules" },
    ],
    directories: { ...manifest.build.directories, output },
    afterSign,
    mac: {
      ...manifest.build.mac, target: ["dmg", "zip"],
      artifactName: "${productName}-${version}-${arch}.${ext}",
      identity: plan.target === "mac" ? plan.identity.slice("Developer ID Application: ".length) : undefined,
      hardenedRuntime: true, notarize: true,
    },
    dmg: { ...manifest.build.dmg, sign: true },
    win: {
      ...manifest.build.win, target: ["nsis", "zip"],
      artifactName: "${productName}-${version}-win-${arch}.${ext}",
      signExecutable: true, signAndEditExecutable: true, verifyUpdateCodeSignature: true,
      // No custom hook, Azure account, certificate auto-discovery or exclusion can bypass this.
      azureSignOptions: null, signExts: [".exe"],
      signtoolOptions: {
        ...(plan.target === "win" && !plan.importedCertificate ? { certificateSha1: plan.thumbprint } : {}),
        signingHashAlgorithms: ["sha256"],
        ...(plan.target === "win" ? { rfc3161TimeStampServer: plan.timestamp, timeStampServer: plan.timestamp } : {}),
      },
    },
    nsis: { ...manifest.build.nsis, buildUniversalInstaller: false, artifactName: "${productName}-Setup-${version}-${arch}.${ext}" },
  };
}

function checkedCommand(run, executable, args, input) {
  const result = run(executable, args, { encoding: "utf8", timeout: 60_000, maxBuffer: 1024 * 1024, windowsHide: true, ...(input ? { input } : {}) });
  // Native tool output can contain local signer/account information. Never include it in an error.
  if (result.error || result.status !== 0) fail("Native release signature verification failed");
  return `${result.stdout ?? ""}${result.stderr ?? ""}`;
}

// Fixed PowerShell program, data only on stdin. No execution-policy change or generated script
// file; tests use the same command boundary and native Windows must reject unsigned fixtures.
export const WINDOWS_SIGNATURE_SCRIPT = String.raw`
$ErrorActionPreference = 'Stop'
[Console]::InputEncoding = [System.Text.UTF8Encoding]::new($false)
$request = [Console]::In.ReadToEnd() | ConvertFrom-Json
if ([string]$request.thumbprint -notmatch '^[A-F0-9]{40}$') { throw 'Invalid signing identity' }
if ($request.mode -eq 'identity') {
  $certs = @(Get-ChildItem Cert:\CurrentUser\My, Cert:\LocalMachine\My -CodeSigningCert -ErrorAction Stop | Where-Object { $_.Thumbprint -eq $request.thumbprint -and $_.HasPrivateKey })
  if ($certs.Count -lt 1) { throw 'An explicit available signing key is required' }
  $cert = $certs[0]
  if ($cert.NotBefore -gt [DateTime]::Now -or $cert.NotAfter -lt [DateTime]::Now -or $cert.Subject -eq $cert.Issuer) { throw 'Invalid production certificate' }
  if (-not $cert.Verify()) { throw 'Untrusted production certificate' }
} elseif ($request.mode -eq 'verify') {
  $item = Get-Item -LiteralPath ([string]$request.path) -Force -ErrorAction Stop
  if ($item.PSIsContainer -or ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Unexpected release artifact type' }
  $signature = Get-AuthenticodeSignature -LiteralPath $item.FullName
  if ($signature.Status -ne 'Valid' -or $signature.SignatureType -ne 'Authenticode' -or $null -eq $signature.SignerCertificate -or $null -eq $signature.TimeStamperCertificate) { throw 'Valid timestamped embedded Authenticode signature required' }
  if ($signature.SignerCertificate.Thumbprint -ne $request.thumbprint -or $signature.SignerCertificate.Subject -eq $signature.SignerCertificate.Issuer) { throw 'Unexpected production signer' }
} else { throw 'Unknown verification mode' }
[Console]::Out.Write('release-signature-ok')
`;

function windowsSignature(request, run, systemRoot) {
  if (!systemRoot || !path.win32.isAbsolute(systemRoot)) fail("The native Windows system directory is unavailable");
  const executable = path.win32.join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe");
  const result = checkedCommand(run, executable, ["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", WINDOWS_SIGNATURE_SCRIPT], JSON.stringify(request));
  if (result !== "release-signature-ok") fail("Native Windows signature verifier did not confirm the release");
}

export function verifyConfiguredSigner(plan, run = spawnSync, systemRoot = process.env.SystemRoot) {
  if (plan.importedCertificate) return; // The builder imports it and forceCodeSigning checks the private key.
  if (plan.target === "mac") {
    const output = checkedCommand(run, "/usr/bin/security", ["find-identity", "-v", "-p", "codesigning"]);
    if (!output.split(/\r?\n/).some(line => line.trim().endsWith(`"${plan.identity}"`))) fail("The configured Developer ID signing identity is not available in the native keychain");
  } else windowsSignature({ mode: "identity", thumbprint: plan.thumbprint }, run, systemRoot);
}

export function verifyMacSignature(file, team, isApp, run = spawnSync) {
  checkedCommand(run, "/usr/bin/codesign", ["--verify", "--deep", "--strict", file]);
  const details = checkedCommand(run, "/usr/bin/codesign", ["--display", "--verbose=4", file]);
  const lines = details.split(/\r?\n/);
  if (!lines.includes(`TeamIdentifier=${team}`) || !lines.some(line => line.startsWith("Authority=Developer ID Application: ")) || lines.includes("Signature=adhoc")) fail("The signed artifact is not from the authorized Developer ID team");
  if (isApp) {
    if (!/\bflags=0x[a-fA-F0-9]+\([^)]*\bruntime\b/.test(details)) fail("The signed app is missing Hardened Runtime");
    checkedCommand(run, "/usr/bin/xcrun", ["stapler", "validate", file]);
    checkedCommand(run, "/usr/sbin/spctl", ["--assess", "--type", "execute", "--verbose=2", file]);
  }
}

export function verifyWindowsSignature(file, thumbprint, run = spawnSync, systemRoot = process.env.SystemRoot) {
  windowsSignature({ mode: "verify", path: file, thumbprint }, run, systemRoot);
}

export function verifyFuseValues(wire) {
  if (wire?.version !== "1") fail("Unsupported Electron fuse wire version");
  const { FuseV1Options } = require("@electron/fuses");
  for (const [name, expected] of Object.entries(RELEASE_FUSES)) {
    const key = name[0].toUpperCase() + name.slice(1);
    // The official wire uses ASCII 0/1, not JS booleans. REMOVED/INHERIT also fail closed.
    if (wire[FuseV1Options[key]] !== (expected ? 49 : 48)) fail(`Packaged Electron fuse differs from release policy: ${name}`);
  }
}

export async function verifyPackagedApp(file, plan, { run = spawnSync, systemRoot = process.env.SystemRoot, readFuses } = {}) {
  if (plan.target === "mac") verifyMacSignature(file, plan.team, true, run);
  else verifyWindowsSignature(file, plan.thumbprint, run, systemRoot);
  const read = readFuses ?? require("@electron/fuses").getCurrentFuseWire;
  verifyFuseValues(await read(file));
}

export function expectedArtifacts(target, version) {
  return ["x64", "arm64"].flatMap(arch => target === "mac"
    ? [`ClaudeRipple-${version}-${arch}.dmg`, `ClaudeRipple-${version}-${arch}.zip`]
    : [`ClaudeRipple-Setup-${version}-${arch}.exe`, `ClaudeRipple-${version}-win-${arch}.zip`]);
}

/** The output is new and private to this build, so stale files cannot satisfy a release check. */
export function inspectArtifacts(files, output, target, version) {
  if (!Array.isArray(files) || files.length === 0) fail("The native builder produced no release artifacts");
  const canonicalOutput = fs.realpathSync(output);
  const names = new Set();
  for (const file of files) {
    if (!path.isAbsolute(file) || path.dirname(file) !== output || !fs.lstatSync(file).isFile() || path.dirname(fs.realpathSync(file)) !== canonicalOutput) fail("A release artifact escaped its fresh staging directory");
    names.add(path.basename(file));
  }
  for (const required of expectedArtifacts(target, version)) if (!names.has(required)) fail("A required signed release artifact or architecture is missing");
  return [...names].sort();
}
