# Native validation and signed release handoff

**Windows personal fork status:** Native distribution is disabled in this source-only
branch. `electron-builder` was removed because its dependency graph included an unpatched
high-severity `picomatch` advisory. For the currently supported Windows source install and
real-device trial, follow [personal-windows-install.md](personal-windows-install.md).
The legacy multi-platform release plan below applies only after a separately reviewed,
fully audited packaging toolchain is restored.

These steps are release gates, not a record that they have already succeeded.
See [security-hardening-validation.md](security-hardening-validation.md) for the
commands actually executed and [security-acceptance.md](security-acceptance.md)
for the production decision. Use the same reviewed commit throughout.

## 1. Run the native matrix

The `CI` workflow accepts `workflow_dispatch` and runs on macOS, Windows and
Ubuntu. Its token is read-only; it does not need signing keys or provider accounts.
A maintainer with repository access must push the reviewed branch and start the
workflow, or open a pull request that triggers it. Record the run URL, commit,
runner OS/architecture, Node version and Electron version. A workflow file without
a completed run is not platform-validation evidence.

The mandatory checks include:

```sh
npm ci --ignore-scripts
npm audit --audit-level=low
node node_modules/electron/install.js
npm run typecheck
npm run check:mod
npm test
npm run build
npm run test:native --workspace @clauderipple/app
```

Do not leave `ELECTRON_SKIP_BINARY_DOWNLOAD=1` set for the explicit downloader.
Linux CI runs the last command under `xvfb-run -a`. Native tests use a normal
non-root account and Chromium's sandbox. Missing display/sandbox prerequisites
are failures to resolve, never reasons to pass `--no-sandbox` or omit the test.

The Electron harness uses disposable private state and synthetic credentials. It
checks sandbox/context isolation, IPC ownership, foreign-frame denial, CSP,
permissions, a real TLS-backed API call and a wrong-certificate takeover of the
same local port. Windows-only Node tests exercise real DACL behavior and unsigned
signature rejection. Their skips on Linux do not establish Windows behavior.

Run `claude plugin test packages/mod` in an authorized Claude installation. Check
the helper's stdin bridge, dashboard launch and normal error handling. Then test
actual packaged CLI, tray, router and Remote host operations, including restart,
pairing control and shutdown. The CI matrix covers its runner architectures;
each distributed x64/arm64 package still needs a matching-architecture smoke test.

## 2. Configure the genuine release identity

Use a protected release environment or the authorized operator's native key store.
Never put a private key, PFX password, Apple password or API key in a PR, repository,
chat message or log. The production commands do not manufacture or self-sign a
production identity and do not import an admin TLS CA into an OS trust store.

| Platform | Required configuration |
| --- | --- |
| macOS | `RIPPLE_MAC_TEAM_ID`, full `RIPPLE_MAC_SIGNING_IDENTITY` in the form `Developer ID Application: Legal Name (TEAMID)`, and its authorized available private key |
| macOS notarization | Exactly one complete mode: `APPLE_ID` + `APPLE_APP_SPECIFIC_PASSWORD` + `APPLE_TEAM_ID`; or `APPLE_API_KEY` + `APPLE_API_KEY_ID` + `APPLE_API_ISSUER`; or `APPLE_KEYCHAIN_PROFILE` with optional `APPLE_KEYCHAIN` |
| Windows | `RIPPLE_WINDOWS_CERT_SHA1` identifying the authorized code-signing certificate, its available private key, and `RIPPLE_WINDOWS_TIMESTAMP_URL` pointing to the signing provider's HTTPS RFC3161 service |
| Optional certificate import | The pinned builder's `CSC_LINK`/`CSC_KEY_PASSWORD`, or Windows-specific `WIN_CSC_LINK`/`WIN_CSC_KEY_PASSWORD`, supplied through protected configuration |

The matching native OS is required. Pull-request jobs are refused. Missing,
partial or mixed identity configuration fails before icon generation or building.
An imported certificate must still match the configured identity after signing.

The build host also needs both target SDK payloads from the reviewed lockfile:
`@anthropic-ai/claude-agent-sdk-darwin-{x64,arm64}` on macOS, or
`@anthropic-ai/claude-agent-sdk-win32-{x64,arm64}` on Windows, currently version
`0.3.283`. Provision them through a clean, authorized package-manager process
that verifies the lockfile artifact integrity. The staging hook checks installed
package identity/version, target payload presence and dependency closure; it does
not independently reconstruct npm package file-content integrity. It performs
no downloads or lifecycle installs, and refuses a missing target instead of using
the build host's executable for a different architecture.

## 3. Build and verify without publishing

On an authorized macOS host:

```sh
npm run release --workspace @clauderipple/app
```

On an authorized Windows host:

```sh
npm run release:win --workspace @clauderipple/app
```

The command builds both x64 and arm64 in a new `release/.candidate-*` directory.
Before packaging, a reviewed hook stages complete CLI/router/Remote sources,
web/shared assets, UI/mod assets, installers and the locked production dependency
and peer closure under `release-native/runtime/{mac,win}/{x64,arm64}`. Runtime
sources beside `app.asar` have a separate self-contained `node_modules` tree;
the two required resource mappings account for the builder's default filtering.
Package-manager/native rebuild hooks are disabled. An unreviewed `.node` addon,
credential-bearing resource, incomplete dependency or target mismatch blocks the
build. These resource checks do not substitute for executing the resulting app.

It requires code signing and verifies the actual packaged executable's fuses.
macOS checks the Developer ID team, Hardened Runtime, notarization ticket and
Gatekeeper assessment. Windows checks a valid embedded, timestamped Authenticode
signature with the configured certificate thumbprint. Installer signatures are
checked after building.

Only successful candidates move to `packages/app/release/verified-*`. Each has
`release-verification.json` with the checked signer, architectures, fuse policy
and artifact SHA-256 digests. Before accessing the signing key or starting the
build, the command requires a clean Git checkout and records its commit, tree
and `package-lock.json` SHA-256. It requires the same clean checkout again before
promoting the receipt; staged, tracked or untracked source changes block release.
Ignored build/staging output stays allowed. Production consumes the committed
icon assets instead of redrawing tracked files. The source fields identify the
local build inputs; they do not assert review approval, CI success, hermetic
execution or a SLSA/provenance attestation. Associate the exact commit with the
completed CI run and artifact-acceptance evidence separately.
Failed `.candidate-*` files remain local diagnostic
material and must not be distributed. These commands never publish a release.

Development commands `dist` and `dist:win` deliberately produce unsigned unpacked
builds in `release-dev`; they cannot substitute for a verified release candidate.

A per-target `<arch>.stage-lock` stays reserved for the whole builder process,
including copying and signing. Normal exit releases only its own nonce-matched
reservation. A crash leaves a lock for inspection. Before removing one, verify
that no build is using that exact target; remove only the displayed lock after
review. An incomplete or unrecognized staging directory also needs inspection
before cleaning only that target. PID reuse or elapsed time never authorizes
automatic recovery, and another target's directory is never deleted.

## 4. Verify the exact distribution artifacts

On disposable machines for each supported architecture, download the intended
artifact, compare its digest with the retained receipt, and independently inspect
the extracted app or installed executable's signer. Confirm OS trust decisions
without changing trust policy to accept the package. Exercise installation,
update, normal operation and rollback of those exact bytes. Retain the logs and
the artifact digest with the review decision.

RunAsNode and NODE_OPTIONS-related fuses remain enabled for the current packaged
CLI/router and custom-CA architecture. The release verifier enforces this explicit
policy; it does not claim these features were disabled. Any stricter fuse policy
needs a tested architectural migration first.

## 5. Upgrade and transport recovery

Upgrade the router, CLI, app and mod as one reviewed unit. HTTP administration and
browser capability links no longer work. `clauderipple ui` needs an existing native
installation; its error points to `clauderipple tray --install` when unavailable.
Do not re-enable an old HTTP control endpoint to make mixed versions interoperate.

Remote HTTP/LAN direct phone connections and HTTP-local relay exceptions are
retired. Configure an HTTPS relay. The updated host rotates its old phone token
once on startup and records `pairingSecurityVersion: 2` in the same atomic write.
Show a fresh relay pairing QR and pair each phone again. Old direct tokens must
fail even inside an otherwise valid encrypted relay session. Keep old outbox data
for explicit recovery; do not automatically resend it to a different identity.
The legacy `--new-token` flag is rejected before any config or service action.
Rotate an already migrated token through the running host's authenticated Phone
settings, which compare the expected token before persisting the replacement.

If transport identity files have been exposed, stop the corresponding service and
all its clients before the operator replaces its token and TLS identity together.
Preserve evidence in an owner-private location and restart only updated code.
Router state and Remote's `local-control-tls` state are separate installations.
Deleting only an endpoint descriptor does not rotate a private key or capability.
Expired coherent identity bundles renew at server startup; corrupted or exposed
state fails closed and needs an explicit operator recovery decision.

This process does not revoke provider accounts, rotate the separate interception
CA, configure protected branches or set up npm trusted publishing. Those operations
have their own authority and recovery requirements.
