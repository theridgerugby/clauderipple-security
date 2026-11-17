# Security hardening

This change hardens local administration, private file storage, the desktop
boundary, installation/update handling and the release workflow. It does not
redesign model routing, the native Claude subscription path, or the Google Gemini
adapter. Normal provider calls still use the credentials the operator chose.

Status: **not approved for a production rollout**. See
[security-acceptance.md](security-acceptance.md) for the remaining gates and
[security-hardening-validation.md](security-hardening-validation.md) for evidence.
This source-level hardening contribution is not a Google security certification
or an independent penetration-test report.

## Authenticated local administration

The configured HTTP loopback port is now an installation-discovery identifier.
Only credential-free `/api/ping` liveness requests remain on that listener;
administrative HTTP requests receive 410. A separate IPv4-loopback TLS listener
handles protected requests. The client authenticates its certificate before
sending a capability or request body. It checks a dedicated per-installation CA,
certificate expiry, the `127.0.0.1` IP SAN and the exact leaf certificate. It does
not use the system/interception CA, a proxy, redirects, pooled TLS sessions or a
plaintext fallback. This dedicated admin CA is never imported into a trust store.

Private state lives under `CLAUDERIPPLE_HOME`:

- `admin-tls-token`: 32 random bytes encoded as hex.
- `admin-tls-identity.json`: an atomically written CA certificate, leaf certificate
  and leaf private key. The CA private key is not persisted.
- `admin-tls-endpoint.json`: public/TLS ports and a random server-instance ID.

Protected API requests and `/readyz` require both `x-clauderipple-admin` and the
current `x-clauderipple-instance-id`. A stale endpoint fails even when the same
installation key is still valid. Host, Origin and duplicate-header checks apply
to reads and writes. TLS has connection, header, idle and request-size bounds;
the shared client limits requests to 32 MiB and responses to 64 MiB, including
chunked responses. Cancellation closes the underlying socket.

The new token namespace deliberately never reads the old `admin-token`: an old
HTTP client cannot expose the current capability to a replacement port listener.
New transport files reject exposed permissions, links, foreign owners, malformed
content and mismatched certificate/key pairs. Windows verifies the existing DACL
on every transport-state read without repairing it first. Exposed identity state
requires an explicit rotation, not silently reusing a potentially leaked key.
Expiry renewal happens only at server startup under the installation lock.

All CLI, desktop and Remote-to-router calls use the same pinned-TLS implementation.
The Electron copy is parity-checked against its canonical source. The desktop main
process attaches credentials after frame/origin validation; the renderer and
preload never receive them. Each installation has a distinct private Electron
profile derived from its home path, including when a profile base is overridden.

The Claude mod calls a bundled native helper with bounded JSON on stdin. Its
owner-protected `admin-runtime.json` descriptor contains fixed absolute executable
and helper paths, not credentials. The helper reads the TLS state itself and caps
mod response output at 3 MiB. No capability appears in process arguments, model
prompts or the descriptor. `clauderipple ui` and the mod opener launch an existing
native app, with no browser or network-download fallback. The web dashboard clears
legacy fragment/session credentials and refuses browser admin fetches.

Remote's host-control API uses its own `local-control-tls` private state directory
and the same certificate, instance and capability checks. Its old HTTP `/local/*`
endpoints return 410. The old `local.secret` is never the new TLS capability.
Its last protected endpoint remains as discovery after a clean shutdown; it is
not proof of liveness. Shutdown operations bind to the captured server generation
and refuse to send an old stop request to a replacement instance.

Remote phone access now requires an authenticated HTTPS relay and the existing
end-to-end host-key handshake. Public HTTP WebSocket upgrades and direct HTTP/LAN
pairing links are refused. The browser refuses legacy direct pairings before it
creates a socket. An actual updated host startup rotates old phone capabilities
once, saving the replacement token and `pairingSecurityVersion: 2` atomically.
Existing phones need to pair again. Read-only status/configuration queries do not
rotate credentials. This closes reuse of tokens previously sent in cleartext;
it does not erase old URLs from browsers. The relay cryptographic protocol is
unchanged. Public HTTP health remains credential-free.

Administrative JSON parsing has byte, depth and object-count limits. Provider
catalog/error bodies are bounded; measurement work has admission limits, explicit
busy responses and bounded retention. Existing scripts must use the new native
client. A raw `curl /api/image` instruction is replaced by `clauderipple image`,
so generated model prompts never contain a credential.

## Saved provider credentials

Configuration reads and revision-conflict snapshots mask `apiKey`, provider
headers and credential-pool headers. A reserved placeholder lets the UI keep a
credential without reading it back. Preservation is scoped to the same named
provider and unchanged credential destinations. Changing the provider identity
or expanding its destinations requires explicitly re-entering credentials.
Deleting a credential remains possible. Do not place secrets in endpoint URLs,
query parameters or labels: these arbitrary fields are not a secret store.

Saved-key probes name the provider and keep its destination. Google environment
API keys are limited to the exact official HTTPS API origin. Credential-bearing
probe and measurement redirects are rejected, and tested probe errors redact
reflected credentials before truncation. A Grok session probe uses its official origin or the exact
saved named endpoint with unchanged credential source.

Configuration revision checking, masked-secret restoration, validation and the
final write now happen inside the same cross-process lock. Background measurements
and catalog updates use the same read-modify-write boundary.

## Private storage and diagnostics

Owned credential files and TLS private keys use unpredictable exclusive temporary
files, a checked destination, flush and atomic rename. Reads use a checked file
descriptor and reject symbolic links, hard links, non-regular files and foreign
POSIX owners. Legacy owner-created provider files are tightened before reading;
failure to apply permissions stops the read. Newly introduced transport identity
files instead reject an existing exposed mode. Private directory creation rejects
directory aliases. Storage path ancestors must be trusted.

Windows applies and verifies explicit ACLs. Every credential temporary file gets
an explicit owner and DACL while it is empty, including inside a private parent.
The writer binds pathname ACL checks and each publication retry to its exclusively
opened file descriptor's identity. Generic locks, JSON writes and log appends
preserve the existing parent directory's permissions. Explicit installation-owned
private directories, such as certificate storage, use the stricter directory policy.
Preserved generic parents must be trusted; descriptor checks do not turn a
hostile-writable parent into a safe credential directory.
Windows behavior still requires native validation. New transport reads do not
depend on file timestamps to infer that an existing DACL remains private.

Credential-shaped log fields and known outbound secrets are redacted. Plain log
lines are bounded and flattened to prevent multiline/control-character forgery.
Active and rotated request history uses private, bounded reads. Durable hourly
accounting uses checked descriptors without silently truncating old totals; its
long-term retention and memory/disk budgets remain a separate operational task.
Opt-in debug dumps use private atomic files but can still contain sensitive prompt
content. Pattern redaction does not prove that arbitrary text contains no secrets.

## Desktop boundary

Electron is pinned to 45.3.3. The main process verifies the owning window, main
frame, page URL and true origin for IPC and the API protocol bridge. API protocol
requests additionally require Electron's browser-supplied initiator origin. Node
integration is disabled in renderers, subframes and workers; context isolation and
the sandbox are enabled. Navigation, redirects, new windows and webviews are
restricted. CSP excludes embedded frames, workers, inline scripts and plugin
objects; permissions are denied by default except the owned dashboard's text copy.

The Windows ACL and local TLS implementations each have one canonical source and
a generated, byte-for-byte parity-tested Electron copy. Native security tests use
a real Electron process, disposable credentials and an actual port-takeover
fixture. They fail when the environment cannot start the sandbox. A test that has
only run under Node is not reported as a successful native Electron execution.

## Update boundary

Automatic installation is disabled unless `autoUpdate` is explicitly `true`.
Existing explicit opt-ins remain enabled. Updates accept only an exact
`clauderipple@<version>` package specification. Script installations execute a
private copy of the installer bundled with the installed package under
`dist/installers`; they do not fetch executable scripts from mutable GitHub
`main`. Missing, aliased, oversized or replaced bundled installers fail closed. The old remote
installer override is not used.

Update package installs use the public npm registry, exact versions and disabled
lifecycle scripts. The pinned Electron downloader is invoked explicitly. POSIX
wrapper/profile generation quotes paths as data. Windows stages and validates a
replacement Node runtime, retains the old runtime until npm and the wrapper have
succeeded, and rolls back pre-commit failures. This is not transactional rollback
of every file in an in-place npm package update.

This does not redesign first-install bootstrap instructions. Future npm packages,
registry metadata, Node downloads and Electron distribution still carry their
normal upstream supply-chain trust. An exact version is not an independent code
audit or a verified signature.

## Release boundary

Native packages stage a self-contained CLI/router/Remote runtime outside
`app.asar`, including web assets, installers and the production dependency/peer
graph from the lockfile. The reviewed builder hook requires the actual target SDK
payload, rejects credential-state paths and dependency fallback outside the
resource root, and holds a per-target reservation through packaging. Tests use
the pinned builder's real resource copier and run the copied CLI/Remote help in
an isolated directory. This establishes resource closure on the test host, not
native application or signature acceptance. Installed package name/version and
recorded lockfile integrity are checked; source artifact integrity remains the
responsibility of the clean, verified installation step.

The proposed CI requires tests, type checking, build, full dependency audit and
native Electron checks on Linux, Windows and macOS. Actions are pinned to commit
hashes. Pull-request code uses read-only repository permissions and no release secrets.

Release verification precedes a read-only packaging job. It packs once without
lifecycle scripts, inspects the actual archive, compares bundled installers with
source and records SHA-256. A separate OIDC publisher consumes the immutable
artifact ID, checks its digest and package identity, and publishes those bytes
without checkout, install, rebuild or lifecycle scripts. Provenance is requested.
Protected tags, trusted-publisher configuration and post-publication verification
still require maintainer control; workflow source alone does not establish an
achieved SLSA level.

Production desktop release commands require a matching native Windows/macOS host
and an explicitly authorized signing identity. macOS builds require Developer ID,
Hardened Runtime, notarization, a valid stapled ticket and Gatekeeper verification.
Windows requires the configured certificate thumbprint, a valid embedded
Authenticode signature and a timestamp. Both architectures must pass actual
packaged-app fuse/signature checks. The checks cover produced installers as well.
Each build uses a fresh candidate directory and records artifact SHA-256 digests;
only successful candidates move to a `verified-*` directory. No release command
publishes automatically. Development builds are explicitly unsigned and go to
`release-dev`. See [native-release-validation.md](native-release-validation.md)
for the maintainer-owned execution steps and evidence requirements.

## Remaining trust boundaries

- Malware running as the current OS user can read private files or tamper with
  the program. Pinned local TLS prevents a different process without the protected
  key from impersonating the server; it does not isolate malware that already has
  the user's file access. A process can still occupy a port or kill a server and
  cause denial of service.
- Legacy tokens or URLs previously exposed to a browser cannot be retroactively
  erased from external logs or extensions. The new token namespace prevents their
  reuse for this TLS transport. Upgrade the router, app, CLI and mod together;
  old clients intentionally fail instead of downgrading the connection.
- OS credential-vault/DPAPI encryption is not implemented. Secrets are plaintext
  behind filesystem permissions; disk encryption remains an operating-system task.
  Model-interception CA/key protection is improved, but native trust-store scope,
  uninstall, recovery and revocation remain unvalidated. That existing CA/leaf
  group is not a crash-atomic multi-file transaction. The separate admin TLS
  identity uses a single atomic bundle and does not participate in this trust flow.
- Electron 45 native compatibility and genuine signed release binaries still need
  successful native execution. Implementing a mandatory verification gate does
  not supply a signing identity or produce a verified release by itself.
  RunAsNode and NODE_OPTIONS-related fuses remain enabled because the packaged
  router and custom-CA architecture depend on them. They need architectural work
  before a stricter desktop policy can require them disabled.
- The proprietary Claude mod engine is unavailable in ordinary Node CI. Its
  syntax/pure helpers are tested there; engine integration tests must also run in
  Claude. The updated mod delegates local administration to the native TLS helper;
  its actual stdin/process integration still requires an engine run.
- Optional Remote transport, account sharing and certificate interception retain
  their existing architecture. This patch is not an audit of every release binary
  or a guarantee about future upstream changes.

## Validation

Automated tests use synthetic credentials, isolated temporary directories and
local mock providers. Update/process tests mock installer boundaries. No live
provider keys, account login, certificate import or real auto-update is required.

Run before merging:

```sh
npm ci --ignore-scripts
npm run typecheck
npm run check:mod
npm test
npm run build
npm run build -w packages/app
npm ls --all
npm audit --ignore-scripts --audit-level=low
npm audit --omit=dev --ignore-scripts
node node_modules/electron/install.js
npm run test:native --workspace @clauderipple/app
```

Also run `claude plugin test packages/mod` on a supported Claude installation.
Perform Windows/macOS desktop smoke tests for dashboard loads and protected API
calls, provider editing and key-pool changes, tray power/update actions, CLI
repair/shutdown, and simultaneous Opus-subscription/Gemini-API sessions. Until
those native checks pass, treat the change as a draft rather than a validated
desktop release.
